"""Unit tests for the brute-force detector."""

from cybertriage import detector, parser, sample_data


def test_detector_flags_brute_force_sample():
    df = parser.parse_log_text(sample_data.load_sample("brute_force"))
    result = detector.detect(df)
    assert result["overall_severity"] == "High"
    assert result["top_offender"] is not None
    assert result["top_offender"]["source_ip"] == "192.168.1.45"
    assert result["top_offender"]["flagged"] is True
    assert result["top_offender"]["failed_count"] >= 15


def test_detector_does_not_flag_normal_sample_as_high():
    df = parser.parse_log_text(sample_data.load_sample("normal"))
    result = detector.detect(df)
    assert result["overall_severity"] != "High"
    assert result["flagged_ips"] == []


def test_detector_identifies_suspicious_ip_in_mixed_sample():
    df = parser.parse_log_text(sample_data.load_sample("mixed"))
    result = detector.detect(df)
    assert result["top_offender"] is not None
    assert result["top_offender"]["source_ip"] == "172.16.0.99"
    assert result["top_offender"]["flagged"] is True


def test_detector_counts_unique_usernames():
    df = parser.parse_log_text(sample_data.load_sample("brute_force"))
    result = detector.detect(df)
    top = result["top_offender"]
    assert "root" in top["unique_usernames"]
    assert "admin" in top["unique_usernames"]
    assert top["username_count"] >= 4


def test_detector_tracks_time_window():
    df = parser.parse_log_text(sample_data.load_sample("brute_force"))
    top = detector.detect(df)["top_offender"]
    assert top["first_seen"] == "Jun 10 10:01:22"
    assert top["last_seen"] == "Jun 10 10:03:31"


def test_detector_multi_user_escalates_severity():
    # 3 failed attempts (base Low) across 3 users should escalate to Medium.
    lines = [
        "Jun 10 10:00:01 server sshd[1]: Failed password for root from 10.1.1.1 port 1001 ssh2",
        "Jun 10 10:00:02 server sshd[2]: Failed password for admin from 10.1.1.1 port 1002 ssh2",
        "Jun 10 10:00:03 server sshd[3]: Failed password for test from 10.1.1.1 port 1003 ssh2",
    ]
    df = parser.parse_log_text("\n".join(lines))
    top = detector.detect(df)["top_offender"]
    assert top["severity"] == "Medium"


def test_detector_empty_input():
    df = parser.parse_log_text("")
    result = detector.detect(df)
    assert result["overall_severity"] == "None"
    assert result["top_offender"] is None


def _severity_for(count, users=("root",)):
    lines = [
        f"Jun 10 10:00:{i:02d} server sshd[{i}]: Failed password for {users[i % len(users)]} from 10.9.9.9 port {3000+i} ssh2"
        for i in range(count)
    ]
    return detector.detect(parser.parse_log_text("\n".join(lines)))["top_offender"]


def test_threshold_boundary_two_not_flagged():
    assert _severity_for(2)["flagged"] is False


def test_threshold_boundary_three_low():
    assert _severity_for(3)["severity"] == "Low"


def test_threshold_boundary_four_low():
    assert _severity_for(4)["severity"] == "Low"


def test_threshold_boundary_five_medium():
    assert _severity_for(5)["severity"] == "Medium"


def test_threshold_boundary_nine_medium():
    assert _severity_for(9)["severity"] == "Medium"


def test_threshold_boundary_ten_high():
    assert _severity_for(10)["severity"] == "High"


def test_multi_user_escalation_at_boundary():
    assert _severity_for(3, ("root", "admin"))["severity"] == "Medium"


def test_success_after_failures_is_counted_separately():
    text = "\n".join([
        "Jun 10 10:00:01 server sshd[1]: Failed password for root from 10.1.1.8 port 1001 ssh2",
        "Jun 10 10:00:02 server sshd[2]: Failed password for root from 10.1.1.8 port 1002 ssh2",
        "Jun 10 10:00:03 server sshd[3]: Accepted password for root from 10.1.1.8 port 1003 ssh2",
    ])
    result = detector.detect(parser.parse_log_text(text))
    assert result["total_failed"] == 2
    assert result["flagged_ips"] == []


def test_out_of_order_timestamps_are_sorted():
    lines = [
        "Jun 10 10:10:00 server sshd[1]: Failed password for root from 10.1.1.9 port 1001 ssh2",
        "Jun 10 10:01:00 server sshd[2]: Failed password for root from 10.1.1.9 port 1002 ssh2",
        "Jun 10 10:05:00 server sshd[3]: Failed password for root from 10.1.1.9 port 1003 ssh2",
    ]
    top = detector.detect(parser.parse_log_text("\n".join(lines)))["top_offender"]
    assert top["first_seen"] == "Jun 10 10:01:00"
    assert top["last_seen"] == "Jun 10 10:10:00"
