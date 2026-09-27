"""Exercise the real PDF backend rather than mocking its return type."""
from cybertriage import detector, parser, pdf_generator, report, sample_data


def test_pdf_export_returns_downloadable_pdf_bytes():
    frame = parser.parse_log_text(sample_data.load_sample('brute_force'))
    detection = detector.detect(frame)
    evidence_report = report.build_report(frame, detection)
    result = pdf_generator.generate_pdf_report(evidence_report, detection, frame)
    assert isinstance(result, bytes)
    assert result.startswith(b'%PDF-')
    assert result.rstrip().endswith(b'%%EOF')
    assert len(result) > 1000
