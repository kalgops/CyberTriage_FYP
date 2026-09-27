"""Local image/audio ingestion with explicit provenance and human review.

Model outputs are untrusted drafts, never authoritative security evidence.
Dependencies and weights are optional; importing the baseline needs neither.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from functools import lru_cache
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import json
import time
import urllib.request

from . import detector, parser, report

MODEL_ROOT = Path(__file__).resolve().parents[1] / "models"
MAX_UPLOAD_BYTES = 20 * 1024 * 1024


@dataclass
class Extraction:
    domain: str
    model: str
    source_sha256: str
    text: str
    elapsed_seconds: float
    segments: list[dict]


def validate_upload(data: bytes) -> None:
    if not data:
        raise ValueError("The uploaded file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("Maximum upload size is 20 MiB.")


@lru_cache(maxsize=1)
def ocr_reader():
    import easyocr
    return easyocr.Reader(
        ["en"], gpu=False, model_storage_directory=str(MODEL_ROOT / "easyocr"),
        download_enabled=False, verbose=False,
    )


@lru_cache(maxsize=1)
def speech_model():
    from faster_whisper import WhisperModel
    return WhisperModel(
        str(MODEL_ROOT / "whisper-base-en"), device="cpu", compute_type="int8",
        local_files_only=True,
    )


def extract_image(data: bytes, reader=None) -> Extraction:
    """Read lines without silently repairing IP addresses or punctuation."""
    validate_upload(data)
    from PIL import Image
    import numpy as np
    started = time.perf_counter()
    with Image.open(BytesIO(data)) as image:
        if image.width * image.height > 16_000_000:
            raise ValueError("Image exceeds the 16 megapixel limit.")
        pixels = np.array(image.convert("RGB"))
    rows = (reader or ocr_reader()).readtext(pixels, detail=1, paragraph=False)
    # Preserve raw boxes, but reconstruct log rows from geometry: CRAFT may
    # return a line as multiple fragments. No character correction is applied.
    segments = [
        {"box": [[float(x), float(y)] for x, y in box],
         "text": str(text), "confidence": float(confidence)}
        for box, text, confidence in rows
    ]
    return Extraction("image", "EasyOCR: CRAFT + english_g2",
                      sha256(data).hexdigest(), reconstruct_lines(segments),
                      time.perf_counter() - started, segments)


def reconstruct_lines(segments: list[dict]) -> str:
    lines = []
    for segment in sorted(segments, key=lambda s: sum(p[1] for p in s["box"]) / 4):
        ys = [p[1] for p in segment["box"]]
        centre = sum(ys) / len(ys)
        height = max(ys) - min(ys)
        if lines and abs(centre - lines[-1][0]) <= max(3, min(height, lines[-1][1]) * .5):
            lines[-1][2].append(segment)
        else:
            lines.append((centre, height, [segment]))
    return "\n".join(" ".join(s["text"] for s in sorted(parts, key=lambda s: min(p[0] for p in s["box"])))
                     for _, _, parts in lines)


def extract_audio(data: bytes, model=None) -> Extraction:
    """Transcribe an analyst note (not an authentication log)."""
    validate_upload(data)
    from faster_whisper.audio import decode_audio
    started = time.perf_counter()
    # Decode first and reject long audio before expensive model inference.
    samples = decode_audio(BytesIO(data), sampling_rate=16000)
    if len(samples) > 120 * 16000:
        raise ValueError("Audio must be at most 120 seconds.")
    segments, _ = (model or speech_model()).transcribe(
        samples, language="en", beam_size=5, condition_on_previous_text=False,
        vad_filter=True,
    )
    result = [{"start": float(s.start), "end": float(s.end),
               "text": s.text.strip(), "avg_logprob": float(s.avg_logprob)}
              for s in segments]
    return Extraction("audio", "Whisper base.en (CTranslate2 int8)",
                      sha256(data).hexdigest(), " ".join(s["text"] for s in result),
                      time.perf_counter() - started, result)


def build_case(log_text: str, analyst_note: str = "", *, reviewed: bool = False) -> dict:
    if not reviewed:
        raise ValueError("Review and confirm extracted text before analysis.")
    if not log_text.strip():
        raise ValueError("Reviewed SSH logs are required.")
    frame = parser.parse_log_text(log_text)
    detection = detector.detect(frame)
    return {"report": report.build_report(frame, detection), "detection": detection,
            "analyst_note_unverified": analyst_note[:4000],
            "reviewed_log_sha256": sha256(log_text.encode()).hexdigest(),
            "parsed_records": frame.to_dict(orient="records")}


def explain_case(case: dict, model: str = "llama3:latest") -> dict:
    """No network other than local Ollama; failures retain deterministic output.

Analyst notes are shown separately in the case record. They are intentionally
excluded from the factual summary prompt, preventing their promotion to facts.
"""
    started = time.perf_counter()
    baseline = case["report"]["summary"]
    payload = {"model": model, "prompt": report.build_llm_prompt(case["report"]),
               "stream": False, "options": {"temperature": 0, "seed": 3070,
                                            "num_predict": 180}}
    try:
        request = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=120) as response:
            output = json.load(response)
        candidate = output.get("response", "")
        accepted = report.validate_llm_explanation(candidate, case["report"])
        return {"status": "accepted" if accepted else "rejected_fallback",
                "model": output.get("model", model), "candidate": candidate,
                "text": candidate.strip() if accepted else baseline,
                "elapsed_seconds": time.perf_counter() - started}
    except Exception as exc:
        return {"status": "unavailable_fallback", "model": model, "text": baseline,
                "error_type": type(exc).__name__,
                "elapsed_seconds": time.perf_counter() - started}


def extraction_record(extraction: Extraction, reviewed_text: str) -> dict:
    record = asdict(extraction)
    record["reviewed_text"] = reviewed_text
    record["human_edited"] = reviewed_text != extraction.text
    return record
