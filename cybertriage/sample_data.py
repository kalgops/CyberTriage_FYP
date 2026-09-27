"""Access to bundled synthetic sample logs.

Provides helper functions to load the three synthetic sample logs shipped with
the prototype. All sample data uses private, non-routable IP ranges and is
entirely synthetic. No real systems or credentials are referenced.
"""

from __future__ import annotations

import os
from typing import Dict

# Directory containing the bundled sample logs (../sample_logs).
_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DIR = os.path.normpath(os.path.join(_PACKAGE_DIR, "..", "sample_logs"))

SAMPLE_FILES: Dict[str, str] = {
    "normal": "normal_auth.log",
    "brute_force": "brute_force_auth.log",
    "mixed": "mixed_auth.log",
}

# Friendly display labels for the dashboard.
SAMPLE_LABELS: Dict[str, str] = {
    "normal": "Normal logins (low risk)",
    "brute_force": "SSH brute-force (high severity)",
    "mixed": "Mixed activity (one suspicious IP)",
}


def sample_path(name: str) -> str:
    """Return the absolute path to a named sample log.

    Args:
        name: One of ``"normal"``, ``"brute_force"``, ``"mixed"``.

    Returns:
        Absolute filesystem path to the sample log file.

    Raises:
        KeyError: If ``name`` is not a known sample.
    """
    return os.path.join(SAMPLE_DIR, SAMPLE_FILES[name])


def load_sample(name: str) -> str:
    """Load a named sample log's raw text.

    Args:
        name: One of ``"normal"``, ``"brute_force"``, ``"mixed"``.

    Returns:
        The raw text content of the sample log.
    """
    with open(sample_path(name), "r", encoding="utf-8") as handle:
        return handle.read()
