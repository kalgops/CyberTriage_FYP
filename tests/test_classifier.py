"""Unit tests for the incident classifier."""

from cybertriage import classifier, detector, parser, sample_data


def _classify_sample(name: str) -> str:
    df = parser.parse_log_text(sample_data.load_sample(name))
    detection = detector.detect(df)
    return classifier.classify(df, detection)


def test_classifier_brute_force_sample():
    assert _classify_sample("brute_force") == classifier.BRUTE_FORCE


def test_classifier_mixed_sample_is_brute_force():
    assert _classify_sample("mixed") == classifier.BRUTE_FORCE


def test_classifier_normal_sample_is_normal():
    assert _classify_sample("normal") == classifier.NORMAL


def test_classifier_empty_input_is_insufficient():
    df = parser.parse_log_text("")
    detection = detector.detect(df)
    assert classifier.classify(df, detection) == classifier.INSUFFICIENT


def test_classifier_unparseable_input_is_insufficient():
    df = parser.parse_log_text("this is not an ssh log\nneither is this")
    detection = detector.detect(df)
    assert classifier.classify(df, detection) == classifier.INSUFFICIENT


def test_classifier_low_volume_is_suspicious():
    # 3 failed attempts from one IP, single user -> Low -> Suspicious Login Pattern.
    lines = [
        "Jun 10 10:00:01 server sshd[1]: Failed password for root from 10.2.2.2 port 1001 ssh2",
        "Jun 10 10:00:05 server sshd[2]: Failed password for root from 10.2.2.2 port 1002 ssh2",
        "Jun 10 10:00:09 server sshd[3]: Failed password for root from 10.2.2.2 port 1003 ssh2",
    ]
    df = parser.parse_log_text("\n".join(lines))
    detection = detector.detect(df)
    assert classifier.classify(df, detection) == classifier.SUSPICIOUS
