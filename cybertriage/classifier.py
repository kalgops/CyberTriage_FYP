"""Deterministic, evidence-based incident classifier.

Maps detection output to one of four incident categories. The classifier never
invents facts; it relies only on the parsed evidence and detection summary.
"""

from __future__ import annotations

from typing import Dict

import pandas as pd

# Canonical incident labels.
BRUTE_FORCE = "Possible SSH Brute Force Attempt"
SUSPICIOUS = "Suspicious Login Pattern"
NORMAL = "Normal Activity"
INSUFFICIENT = "Parsing Error / Insufficient Evidence"


def classify(df: pd.DataFrame, detection: Dict[str, object]) -> str:
    """Classify the incident type from parsed logs and detection results.

    Decision logic (deterministic):
        1. No parseable events at all          -> Parsing Error / Insufficient Evidence
        2. Any IP flagged at Medium/High        -> Possible SSH Brute Force Attempt
        3. Any IP flagged at Low                -> Suspicious Login Pattern
        4. Otherwise                            -> Normal Activity

    Args:
        df: Parsed log DataFrame.
        detection: Output of :func:`cybertriage.detector.detect`.

    Returns:
        One of the four canonical incident label strings.
    """
    # No usable evidence: empty input or nothing recognisable was parsed.
    if df is None or df.empty:
        return INSUFFICIENT

    recognised = df[df["event_type"] != "unknown"]
    if recognised.empty:
        return INSUFFICIENT

    flagged_ips = detection.get("flagged_ips", []) if detection else []
    overall_severity = detection.get("overall_severity", "None") if detection else "None"

    if flagged_ips:
        if overall_severity in ("Medium", "High"):
            return BRUTE_FORCE
        return SUSPICIOUS

    return NORMAL
