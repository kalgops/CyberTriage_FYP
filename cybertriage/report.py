"""Incident report generator.

Produces a structured, plain-English triage report grounded strictly in the
parsed evidence. A safe template-based generator is always available. An
optional local-LLM (Ollama) path can rephrase the summary, but it is never
required and falls back to the template if unavailable.

The report explicitly avoids inventing facts: every figure shown is derived
from the detection summary.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional

import pandas as pd

from . import classifier

# Default local Ollama settings (overridable via environment variables).
DEFAULT_OLLAMA_HOST = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "llama3"

# Static recommended steps used for brute-force / suspicious findings.
_BRUTE_FORCE_STEPS = [
    "Check whether any login attempt from the same IP address succeeded.",
    "Review authentication logs for similar activity from nearby IP ranges.",
    "Consider blocking or rate-limiting the source IP if the activity is "
    "confirmed as malicious.",
    "Review SSH hardening controls such as disabling root login, limiting "
    "password authentication, and enforcing strong authentication.",
]

_NORMAL_STEPS = [
    "No immediate action required; activity appears consistent with normal use.",
    "Continue routine monitoring of authentication logs.",
    "Periodically review SSH hardening controls as good practice.",
]

_INSUFFICIENT_STEPS = [
    "Verify that the input contains valid Linux SSH (sshd) authentication "
    "log lines.",
    "Confirm the log format matches the expected syslog structure.",
    "Collect a larger sample of logs and re-run the triage.",
]


def _format_usernames(usernames: List[str]) -> str:
    """Join usernames for display, or a placeholder if none were observed."""
    return ", ".join(usernames) if usernames else "none observed"


def _time_window(first_seen: Optional[str], last_seen: Optional[str]) -> str:
    """Render a human-readable time window from two timestamp strings."""
    if first_seen and last_seen:
        return f"{first_seen} to {last_seen}"
    if first_seen:
        return first_seen
    return "unknown"


def build_summary(incident_type: str, detection: Dict[str, object]) -> str:
    """Construct a fact-grounded plain-English summary.

    Args:
        incident_type: One of the classifier labels.
        detection: Output of :func:`cybertriage.detector.detect`.

    Returns:
        A short summary paragraph that references only observed evidence.
    """
    top = detection.get("top_offender") if detection else None

    if incident_type == classifier.BRUTE_FORCE and top:
        multi_user = (
            " Several usernames were targeted, which may indicate an automated "
            "brute-force attempt."
            if top["username_count"] >= 2
            else " A single username was repeatedly targeted."
        )
        return (
            "The system detected repeated failed SSH login attempts from one "
            f"source IP address ({top['source_ip']}).{multi_user}"
        )

    if incident_type == classifier.SUSPICIOUS and top:
        return (
            "The system detected a small number of failed SSH login attempts "
            f"from {top['source_ip']}. This is below the brute-force threshold "
            "but may warrant a quick review."
        )

    if incident_type == classifier.NORMAL:
        return (
            "No source IP exceeded the suspicious-activity thresholds. The "
            "observed authentication activity appears consistent with normal "
            "use."
        )

    return (
        "The provided input did not contain enough recognisable SSH "
        "authentication events to perform a confident triage."
    )


def recommended_steps(incident_type: str) -> List[str]:
    """Return the recommended next investigation steps for an incident type."""
    if incident_type in (classifier.BRUTE_FORCE, classifier.SUSPICIOUS):
        return list(_BRUTE_FORCE_STEPS)
    if incident_type == classifier.NORMAL:
        return list(_NORMAL_STEPS)
    return list(_INSUFFICIENT_STEPS)


def build_report(df: pd.DataFrame, detection: Dict[str, object]) -> Dict[str, object]:
    """Build a structured report object from evidence.

    Args:
        df: Parsed log DataFrame.
        detection: Output of :func:`cybertriage.detector.detect`.

    Returns:
        A dict with keys: ``incident_type``, ``severity``, ``summary``,
        ``evidence`` (dict), ``recommended_steps`` (list), and ``top_offender``.
    """
    incident_type = classifier.classify(df, detection)
    top = detection.get("top_offender") if detection else None

    if incident_type in (classifier.BRUTE_FORCE, classifier.SUSPICIOUS) and top:
        severity = top["severity"]
        evidence = {
            "Source IP": top["source_ip"],
            "Failed login count": top["failed_count"],
            "Targeted usernames": _format_usernames(top["unique_usernames"]),
            "Time window": _time_window(top["first_seen"], top["last_seen"]),
        }
    elif incident_type == classifier.NORMAL:
        severity = "Low"
        evidence = {
            "Total events analysed": detection.get("total_events", 0),
            "Total failed logins": detection.get("total_failed", 0),
            "Flagged source IPs": 0,
        }
    else:  # INSUFFICIENT
        severity = "Informational"
        evidence = {
            "Total events analysed": detection.get("total_events", 0) if detection else 0,
            "Recognisable SSH events": 0,
        }

    return {
        "incident_type": incident_type,
        "severity": severity,
        "summary": build_summary(incident_type, detection),
        "evidence": evidence,
        "recommended_steps": recommended_steps(incident_type),
        "top_offender": top,
    }


def render_text_report(report: Dict[str, object]) -> str:
    """Render a report dict as a plain-text triage report.

    Args:
        report: Output of :func:`build_report`.

    Returns:
        A formatted multi-line string in the required report format.
    """
    lines: List[str] = []
    lines.append(f"Incident Type: {report['incident_type']}")
    lines.append(f"Severity: {report['severity']}")
    lines.append("")
    lines.append("Summary:")
    lines.append(report["summary"])
    lines.append("")
    lines.append("Evidence:")
    for key, value in report["evidence"].items():
        lines.append(f"* {key}: {value}")
    lines.append("")
    lines.append("Recommended Next Steps:")
    for idx, step in enumerate(report["recommended_steps"], start=1):
        lines.append(f"{idx}. {step}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Optional local-LLM (Ollama) explanation. Never required.
# ---------------------------------------------------------------------------

def get_ollama_host() -> str:
    """Return the Ollama base URL.

    Reads the ``OLLAMA_HOST`` environment variable, falling back to
    :data:`DEFAULT_OLLAMA_HOST`. A trailing slash is stripped for safe URL
    joining.
    """
    host = os.environ.get("OLLAMA_HOST", "").strip() or DEFAULT_OLLAMA_HOST
    return host.rstrip("/")


def get_ollama_model() -> str:
    """Return the Ollama model name.

    Reads the ``OLLAMA_MODEL`` environment variable, falling back to
    :data:`DEFAULT_OLLAMA_MODEL`.
    """
    return os.environ.get("OLLAMA_MODEL", "").strip() or DEFAULT_OLLAMA_MODEL


def build_llm_prompt(report: Dict[str, object]) -> str:
    """Build the grounded LLM prompt from a report's evidence.

    The prompt includes every evidence field and explicitly instructs the model
    not to invent unsupported facts. Exposed as a function so it can be unit
    tested without a live server.

    Args:
        report: Output of :func:`build_report`.

    Returns:
        The full prompt string.
    """
    evidence_lines = "\n".join(
        f"- {k}: {v}" for k, v in report["evidence"].items()
    )
    return (
        "You are a defensive cybersecurity assistant helping a junior "
        "analyst understand an SSH log triage result. Using ONLY the "
        "evidence below, write a short, clear, plain-English explanation. "
        "Do not invent any facts, IPs, counts, or usernames that are not "
        "listed.\n\n"
        f"Incident type: {report['incident_type']}\n"
        f"Severity: {report['severity']}\n"
        f"Evidence:\n{evidence_lines}\n"
    )


_UNSUPPORTED_HIGH_RISK_CLAIMS = {
    "malware", "ransomware", "data breach", "account compromised",
    "system compromised", "successful access", "credentials stolen",
    "privilege escalation", "data exfiltration", "compromised",
}


def validate_llm_explanation(text: object, report: Dict[str, object]) -> bool:
    """Reject generated wording that introduces unsupported factual claims.

    This is deliberately conservative. It is not a semantic proof of factual
    consistency, but it enforces three useful invariants before generated text
    can replace the deterministic template: non-empty bounded text, no new IP
    address, and no new numeric fact. High-risk compromise claims are rejected
    because the current SSH evidence cannot establish them.
    """
    if not isinstance(text, str) or not text.strip() or len(text) > 2000:
        return False

    evidence_text = " ".join(str(value) for value in report.get("evidence", {}).values())
    allowed_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9A-Fa-f:]{2,}\b", evidence_text))
    generated_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9A-Fa-f:]{2,}\b", text))
    if not generated_ips.issubset(allowed_ips):
        return False

    allowed_numbers = set(re.findall(r"\d+", evidence_text))
    generated_numbers = set(re.findall(r"\d+", text))
    if not generated_numbers.issubset(allowed_numbers):
        return False

    lowered = text.lower()
    if any(claim in lowered for claim in _UNSUPPORTED_HIGH_RISK_CLAIMS):
        return False
    return True


def ollama_available(
    model: Optional[str] = None, host: Optional[str] = None
) -> bool:
    """Return True if a local Ollama server appears to be reachable.

    This performs a best-effort check and never raises. The prototype works
    fully without Ollama.

    Args:
        model: Unused for the reachability check; accepted for API symmetry.
        host: Optional Ollama base URL. Defaults to :func:`get_ollama_host`.
    """
    base = (host or get_ollama_host()).rstrip("/")
    try:
        import urllib.request

        with urllib.request.urlopen(f"{base}/api/tags", timeout=1):
            return True
    except Exception:
        return False


def generate_llm_explanation(
    report: Dict[str, object],
    model: Optional[str] = None,
    host: Optional[str] = None,
) -> Optional[str]:
    """Optionally rephrase the report summary using a local Ollama model.

    The model is given ONLY the already-computed evidence and is instructed not
    to invent facts. Returns ``None`` on any failure so callers can fall back to
    the deterministic template.

    Args:
        report: Output of :func:`build_report`.
        model: Local Ollama model name. Defaults to :func:`get_ollama_model`.
        host: Ollama base URL. Defaults to :func:`get_ollama_host`.

    Returns:
        A rephrased explanation string, or ``None`` if generation is
        unavailable or fails.
    """
    base = (host or get_ollama_host()).rstrip("/")
    model_name = model or get_ollama_model()

    if not ollama_available(model_name, base):
        return None

    try:
        import json
        import urllib.request

        prompt = build_llm_prompt(report)

        payload = json.dumps(
            {"model": model_name, "prompt": prompt, "stream": False}
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{base}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data.get("response", "")
            return text.strip() if validate_llm_explanation(text, report) else None
    except Exception:
        return None
