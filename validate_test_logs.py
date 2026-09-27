"""Check documented fixtures separately from the historical Pytest suite."""
import json
from pathlib import Path
from cybertriage import classifier, detector, parser

root = Path(__file__).resolve().parent / "test_logs"
cases = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
for case in cases:
    frame = parser.parse_log_file(str(root / case["file"]))
    detection = detector.detect(frame)
    actual = (classifier.classify(frame, detection), detection["overall_severity"])
    expected = (case["expected_class"], case["expected_severity"])
    assert actual == expected, (case["file"], actual, expected)
    if case["file"].startswith("14_"):
        assert len(frame) == 3 and (frame.event_type == "unknown").all()
    if case["file"].startswith("15_"):
        top = detection["top_offender"]
        assert (top["first_seen"], top["last_seen"]) == ("Jun 10 10:01:00", "Jun 10 10:10:00")
    print(f"PASS {case['file']}: {actual[0]} / {actual[1]}")
print(f"{len(cases)}/{len(cases)} curated fixtures passed (separate from Pytest).")
