"""Unit tests for the SSH log parser."""

from cybertriage import parser

FAILED = "Jun 10 10:01:22 server sshd[1122]: Failed password for root from 192.168.1.45 port 53422 ssh2"
INVALID = "Jun 10 10:01:35 server sshd[1125]: Failed password for invalid user admin from 192.168.1.45 port 53425 ssh2"
ACCEPTED = "Jun 10 10:03:00 server sshd[1130]: Accepted password for kalyan from 192.168.1.20 port 50122 ssh2"


def test_parser_extracts_ip():
    parsed = parser.parse_line(FAILED)
    assert parsed is not None
    assert parsed["source_ip"] == "192.168.1.45"


def test_parser_extracts_username():
    parsed = parser.parse_line(ACCEPTED)
    assert parsed["username"] == "kalyan"


def test_parser_identifies_failed_login():
    parsed = parser.parse_line(FAILED)
    assert parsed["event_type"] == "failed_login"
    assert parsed["username"] == "root"


def test_parser_identifies_successful_login():
    parsed = parser.parse_line(ACCEPTED)
    assert parsed["event_type"] == "successful_login"


def test_parser_identifies_invalid_user():
    parsed = parser.parse_line(INVALID)
    assert parsed["event_type"] == "invalid_user"
    assert parsed["username"] == "admin"
    assert parsed["source_ip"] == "192.168.1.45"


def test_parser_extracts_timestamp_and_port():
    parsed = parser.parse_line(FAILED)
    assert parsed["timestamp"] == "Jun 10 10:01:22"
    assert parsed["port"] == "53422"


def test_parser_handles_unknown_line():
    parsed = parser.parse_line("Jun 10 10:05:00 server sshd[9999]: Connection closed by 10.0.0.1")
    assert parsed["event_type"] == "unknown"


def test_parse_log_text_returns_dataframe():
    df = parser.parse_log_text("\n".join([FAILED, INVALID, ACCEPTED]))
    assert list(df.columns) == parser.COLUMNS
    assert len(df) == 3


def test_parse_log_text_skips_blank_lines():
    df = parser.parse_log_text(f"\n\n{FAILED}\n\n")
    assert len(df) == 1


def test_parse_empty_text_returns_empty_dataframe():
    df = parser.parse_log_text("")
    assert df.empty
    assert list(df.columns) == parser.COLUMNS


def test_parser_accepts_ipv6():
    line = "Jun 10 10:03:00 server sshd[12]: Failed password for root from 2001:db8::5 port 50122 ssh2"
    assert parser.parse_line(line)["source_ip"] == "2001:db8::5"


def test_parser_accepts_publickey_success():
    line = "Jun 10 10:03:00 server sshd[13]: Accepted publickey for deploy from 10.0.0.5 port 50122 ssh2"
    parsed = parser.parse_line(line)
    assert parsed["event_type"] == "successful_login"
    assert parsed["username"] == "deploy"


def test_parser_rejects_invalid_ipv4():
    line = "Jun 10 10:03:00 server sshd[14]: Failed password for root from 999.1.1.1 port 50122 ssh2"
    assert parser.parse_line(line)["event_type"] == "unknown"


def test_parser_rejects_malformed_port():
    line = "Jun 10 10:03:00 server sshd[15]: Failed password for root from 10.0.0.5 port bad ssh2"
    parsed = parser.parse_line(line)
    assert parsed["port"] is None


def test_parser_handles_large_input():
    text = "\n".join([FAILED] * 5000)
    assert len(parser.parse_log_text(text)) == 5000
