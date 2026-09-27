"""SSH authentication log parser.

Parses common Linux SSH (sshd) authentication log lines into structured
records and returns them as a Pandas DataFrame.

Supported event types:
    - failed_login      : "Failed password for <user> ..."
    - invalid_user      : "Failed password for invalid user <user> ..."
    - successful_login  : "Accepted password for <user> ..."
    - unknown           : line did not match any known pattern

This module performs read-only parsing of synthetic logs. It contains no
offensive capability.
"""

from __future__ import annotations

import re
from typing import List, Optional, TypedDict

import pandas as pd

# Columns produced by the parser, in a stable order.
COLUMNS = [
    "timestamp",
    "event_type",
    "username",
    "source_ip",
    "port",
    "raw",
]

# Syslog timestamp prefix, e.g. "Jun 10 10:01:22 server sshd[1122]:"
_PREFIX = r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"

# IPv4 or IPv6 token. Validation is performed with ipaddress after matching.
_IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
_PORT = r"(?:\s+port\s+(?P<port>\d+))?"

# Order matters: "invalid user" must be tested before the generic failed match.
_PATTERNS = [
    (
        "invalid_user",
        re.compile(
            _PREFIX
            + r"Failed password for invalid user (?P<user>\S+) from "
            + _IP
            + _PORT
        ),
    ),
    (
        "failed_login",
        re.compile(
            _PREFIX + r"Failed password for (?P<user>\S+) from " + _IP + _PORT
        ),
    ),
    (
        "successful_login",
        re.compile(
            _PREFIX + r"Accepted password for (?P<user>\S+) from " + _IP + _PORT
        ),
    ),
    (
        "successful_login",
        re.compile(
            _PREFIX + r"Accepted publickey for (?P<user>\S+) from " + _IP + _PORT
        ),
    ),
]


class ParsedLine(TypedDict):
    """Structured representation of a single SSH log line."""

    timestamp: Optional[str]
    event_type: str
    username: Optional[str]
    source_ip: Optional[str]
    port: Optional[str]
    raw: str


def parse_line(line: str) -> Optional[ParsedLine]:
    """Parse a single SSH log line.

    Args:
        line: A raw log line.

    Returns:
        A ParsedLine dict, or ``None`` if the line is blank.
        Lines that do not match any known pattern are returned with
        ``event_type == "unknown"`` and ``None`` fields where unavailable.
    """
    raw = line.rstrip("\n")
    if not raw.strip():
        return None

    for event_type, pattern in _PATTERNS:
        match = pattern.search(raw)
        if match:
            groups = match.groupdict()
            try:
                import ipaddress

                ipaddress.ip_address(groups.get("ip"))
            except ValueError:
                continue
            return ParsedLine(
                timestamp=groups.get("timestamp"),
                event_type=event_type,
                username=groups.get("user"),
                source_ip=groups.get("ip"),
                port=groups.get("port"),
                raw=raw,
            )

    # Did not match a known pattern. Still try to surface a timestamp if present.
    ts_match = re.match(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", raw
    )
    return ParsedLine(
        timestamp=ts_match.group("timestamp") if ts_match else None,
        event_type="unknown",
        username=None,
        source_ip=None,
        port=None,
        raw=raw,
    )


def parse_log_text(text: str) -> pd.DataFrame:
    """Parse a block of SSH log text into a DataFrame.

    Args:
        text: Multi-line string containing SSH log lines.

    Returns:
        A Pandas DataFrame with columns defined in ``COLUMNS``. Blank lines are
        skipped. If no parseable lines are found an empty DataFrame (with the
        correct columns) is returned.
    """
    records: List[ParsedLine] = []
    for line in (text or "").splitlines():
        parsed = parse_line(line)
        if parsed is not None:
            records.append(parsed)

    if not records:
        return pd.DataFrame(columns=COLUMNS)

    df = pd.DataFrame(records, columns=COLUMNS)
    return df


def parse_log_file(path: str) -> pd.DataFrame:
    """Parse an SSH log file from disk.

    Args:
        path: Path to a ``.log`` or ``.txt`` file.

    Returns:
        A Pandas DataFrame as produced by :func:`parse_log_text`.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return parse_log_text(handle.read())
