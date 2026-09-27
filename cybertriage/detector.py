"""Brute-force detection logic.

Groups failed SSH login events by source IP and applies deterministic,
evidence-based threshold rules to flag suspicious activity. No machine learning
or external calls are involved; detection is fully reproducible.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, TypedDict

import pandas as pd

# Threshold rules for failed-attempt counts.
LOW_THRESHOLD = 3   # 3-4 failed attempts  -> Low
MEDIUM_THRESHOLD = 5  # 5-9 failed attempts -> Medium
HIGH_THRESHOLD = 10  # 10+ failed attempts -> High

# Event types treated as failed authentication attempts.
FAILED_EVENT_TYPES = {"failed_login", "invalid_user"}

SEVERITY_ORDER = {"None": 0, "Low": 1, "Medium": 2, "High": 3}


class IPSummary(TypedDict):
    """Aggregated detection summary for a single source IP."""

    source_ip: str
    failed_count: int
    unique_usernames: List[str]
    username_count: int
    first_seen: Optional[str]
    last_seen: Optional[str]
    severity: str
    flagged: bool
    verdict: str


def _base_severity(failed_count: int) -> str:
    """Map a failed-attempt count to a base severity label."""
    if failed_count >= HIGH_THRESHOLD:
        return "High"
    if failed_count >= MEDIUM_THRESHOLD:
        return "Medium"
    if failed_count >= LOW_THRESHOLD:
        return "Low"
    return "None"


def _escalate(severity: str) -> str:
    """Raise a severity by one level (capped at High)."""
    order = ["None", "Low", "Medium", "High"]
    idx = order.index(severity)
    return order[min(idx + 1, len(order) - 1)]


def analyse_ip(group: pd.DataFrame, source_ip: str) -> IPSummary:
    """Build a detection summary for a single source IP.

    Args:
        group: DataFrame rows belonging to one source IP (failed events only).
        source_ip: The IP address being summarised.

    Returns:
        An :class:`IPSummary` describing the activity from this IP.
    """
    failed_count = int(len(group))

    usernames = [u for u in group["username"].dropna().tolist() if u]
    unique_usernames = sorted(set(usernames))
    username_count = len(unique_usernames)

    timestamps = [t for t in group["timestamp"].dropna().tolist() if t]
    timestamps.sort(
        key=lambda value: datetime.strptime(f"2026 {value}", "%Y %b %d %H:%M:%S")
    )
    first_seen = timestamps[0] if timestamps else None
    last_seen = timestamps[-1] if timestamps else None

    severity = _base_severity(failed_count)

    # Escalate when the same IP targets multiple usernames and has already met
    # at least the low threshold (spraying behaviour).
    if username_count >= 2 and severity != "None":
        severity = _escalate(severity)

    flagged = failed_count >= LOW_THRESHOLD
    verdict = (
        "Possible SSH Brute Force Attempt"
        if flagged
        else "Normal / No Significant Suspicious Activity"
    )

    return IPSummary(
        source_ip=source_ip,
        failed_count=failed_count,
        unique_usernames=unique_usernames,
        username_count=username_count,
        first_seen=first_seen,
        last_seen=last_seen,
        severity=severity,
        flagged=flagged,
        verdict=verdict,
    )


def detect(df: pd.DataFrame) -> Dict[str, object]:
    """Run brute-force detection over parsed log records.

    Args:
        df: DataFrame produced by :func:`cybertriage.parser.parse_log_text`.

    Returns:
        A dict containing:
            - ``ip_summaries``: list of :class:`IPSummary`, sorted by severity
              then failed count (most suspicious first).
            - ``flagged_ips``: subset of summaries that met a threshold.
            - ``top_offender``: the single most suspicious IPSummary or ``None``.
            - ``overall_severity``: highest severity across all IPs.
            - ``total_failed``: total failed events analysed.
            - ``total_events``: total parsed events.
    """
    total_events = int(len(df)) if df is not None else 0

    if df is None or df.empty or "event_type" not in df.columns:
        return {
            "ip_summaries": [],
            "flagged_ips": [],
            "top_offender": None,
            "overall_severity": "None",
            "total_failed": 0,
            "total_events": total_events,
        }

    failed = df[df["event_type"].isin(FAILED_EVENT_TYPES)].copy()
    failed = failed[failed["source_ip"].notna()]

    summaries: List[IPSummary] = []
    for source_ip, group in failed.groupby("source_ip", sort=False):
        summaries.append(analyse_ip(group, str(source_ip)))

    summaries.sort(
        key=lambda s: (SEVERITY_ORDER[s["severity"]], s["failed_count"]),
        reverse=True,
    )

    flagged = [s for s in summaries if s["flagged"]]
    top_offender = summaries[0] if summaries else None
    overall_severity = (
        max((s["severity"] for s in summaries), key=lambda v: SEVERITY_ORDER[v])
        if summaries
        else "None"
    )

    return {
        "ip_summaries": summaries,
        "flagged_ips": flagged,
        "top_offender": top_offender,
        "overall_severity": overall_severity,
        "total_failed": int(len(failed)),
        "total_events": total_events,
    }
