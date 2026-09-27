"""Unit tests for the report generator and Ollama fallback safety.

These tests never require a live Ollama server. All network access is mocked
via monkeypatch / unittest.mock so the safety guarantees (no crash, template
fallback) can be verified deterministically.
"""

import json
from unittest import mock

from cybertriage import detector, parser, report, sample_data


def _brute_force_report() -> dict:
    """Build a report from the bundled brute-force sample."""
    df = parser.parse_log_text(sample_data.load_sample("brute_force"))
    detection = detector.detect(df)
    return report.build_report(df, detection)


def test_build_report_has_required_keys():
    report_obj = _brute_force_report()
    for key in (
        "incident_type",
        "severity",
        "summary",
        "evidence",
        "recommended_steps",
    ):
        assert key in report_obj
    assert isinstance(report_obj["evidence"], dict)
    assert isinstance(report_obj["recommended_steps"], list)


def test_render_text_report_includes_headings():
    text = report.render_text_report(_brute_force_report())
    for heading in (
        "Incident Type",
        "Severity",
        "Summary",
        "Evidence",
        "Recommended Next Steps",
    ):
        assert heading in text


def test_ollama_available_returns_false_on_exception():
    with mock.patch(
        "urllib.request.urlopen", side_effect=OSError("connection refused")
    ):
        # Must not raise, must return False.
        assert report.ollama_available("llama3", "http://localhost:11434") is False


def test_generate_llm_explanation_returns_none_when_unavailable():
    with mock.patch.object(report, "ollama_available", return_value=False):
        result = report.generate_llm_explanation(_brute_force_report())
    assert result is None


def test_generate_llm_explanation_returns_parsed_text_when_mocked():
    report_obj = _brute_force_report()
    fake_response_body = json.dumps(
        {"response": "  This is a mocked LLM explanation.  "}
    ).encode("utf-8")

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return fake_response_body

    with mock.patch.object(report, "ollama_available", return_value=True), \
            mock.patch("urllib.request.urlopen", return_value=_FakeResp()):
        result = report.generate_llm_explanation(report_obj)

    assert result == "This is a mocked LLM explanation."


def test_build_llm_prompt_includes_evidence_and_guardrails():
    report_obj = _brute_force_report()
    prompt = report.build_llm_prompt(report_obj)

    # Guardrail instruction must be present.
    assert "Do not invent" in prompt
    # Every evidence field key must appear in the prompt.
    for key in report_obj["evidence"]:
        assert key in prompt
    # The top offender's IP (a key fact) must be carried into the prompt.
    assert report_obj["top_offender"]["source_ip"] in prompt


def test_get_ollama_host_env_override(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://example.local:1234/")
    # Trailing slash should be stripped.
    assert report.get_ollama_host() == "http://example.local:1234"


def test_get_ollama_host_default(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    assert report.get_ollama_host() == report.DEFAULT_OLLAMA_HOST


def test_get_ollama_model_env_override(monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "mistral")
    assert report.get_ollama_model() == "mistral"


def test_get_ollama_model_default(monkeypatch):
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    assert report.get_ollama_model() == report.DEFAULT_OLLAMA_MODEL


def test_generate_llm_explanation_does_not_raise_on_request_error():
    report_obj = _brute_force_report()
    with mock.patch.object(report, "ollama_available", return_value=True), \
            mock.patch(
                "urllib.request.urlopen", side_effect=OSError("boom")
            ):
        # Network error during generation must degrade to None, not crash.
        assert report.generate_llm_explanation(report_obj) is None


def test_validator_accepts_grounded_explanation():
    report_obj = _brute_force_report()
    text = "Repeated failed logins from 192.168.1.45 were observed; 18 failures were recorded."
    assert report.validate_llm_explanation(text, report_obj) is True


def test_validator_rejects_invented_ip():
    report_obj = _brute_force_report()
    text = "The activity came from 8.8.8.8."
    assert report.validate_llm_explanation(text, report_obj) is False


def test_validator_rejects_invented_count():
    report_obj = _brute_force_report()
    text = "The source made 999 failed attempts."
    assert report.validate_llm_explanation(text, report_obj) is False


def test_validator_rejects_unsupported_compromise_claim():
    report_obj = _brute_force_report()
    text = "The system was compromised by 192.168.1.45 after 18 failures."
    assert report.validate_llm_explanation(text, report_obj) is False
