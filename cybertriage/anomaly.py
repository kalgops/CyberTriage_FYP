"""Isolation Forest anomaly baseline for aggregated SSH behaviour.

The model is deliberately separate from the deterministic detector. It is
trained only on labelled normal reference observations and refuses to predict
when fewer than ``MIN_TRAINING_ROWS`` are available.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, Iterable, List, Optional

import numpy as np
import pandas as pd

from .detector import FAILED_EVENT_TYPES

FEATURE_COLUMNS = [
    "failed_count",
    "successful_count",
    "unique_usernames",
    "events_per_minute",
    "duration_minutes",
    "failure_ratio",
]
MIN_TRAINING_ROWS = 20


def _minutes(values: Iterable[str]) -> float:
    parsed = sorted(
        datetime.strptime(f"2026 {v}", "%Y %b %d %H:%M:%S")
        for v in values if isinstance(v, str)
    )
    if len(parsed) < 2:
        return 1.0 / 60.0
    return max((parsed[-1] - parsed[0]).total_seconds() / 60.0, 1.0 / 60.0)


def aggregate_features(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate parsed events into one feature row per source IP."""
    columns = ["source_ip", *FEATURE_COLUMNS]
    if df is None or df.empty or "source_ip" not in df:
        return pd.DataFrame(columns=columns)

    usable = df[df["source_ip"].notna()].copy()
    rows: List[Dict[str, object]] = []
    for source_ip, group in usable.groupby("source_ip", sort=False):
        failed = int(group["event_type"].isin(FAILED_EVENT_TYPES).sum())
        successes = int((group["event_type"] == "successful_login").sum())
        total_auth = failed + successes
        usernames = int(group["username"].dropna().nunique())
        duration = _minutes(group["timestamp"].dropna().tolist())
        rows.append(
            {
                "source_ip": str(source_ip),
                "failed_count": failed,
                "successful_count": successes,
                "unique_usernames": usernames,
                "events_per_minute": total_auth / duration,
                "duration_minutes": duration,
                "failure_ratio": failed / total_auth if total_auth else 0.0,
            }
        )
    return pd.DataFrame(rows, columns=columns)


class IsolationForestBaseline:
    """Small reproducible wrapper around scikit-learn IsolationForest."""

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.training_rows = 0

    def fit(self, normal_features: pd.DataFrame) -> "IsolationForestBaseline":
        if normal_features is None or len(normal_features) < MIN_TRAINING_ROWS:
            raise ValueError(
                f"Isolation Forest requires at least {MIN_TRAINING_ROWS} normal "
                "training observations; no prediction was forced."
            )
        from sklearn.ensemble import IsolationForest

        x = normal_features[FEATURE_COLUMNS].astype(float).replace([np.inf, -np.inf], 0).fillna(0)
        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self.model.fit(x)
        self.training_rows = len(x)
        return self

    def predict(self, features: pd.DataFrame) -> pd.DataFrame:
        if self.model is None:
            return pd.DataFrame(
                [{"status": "insufficient_training_data", "is_anomaly": None,
                  "anomaly_score": None, "training_rows": self.training_rows}]
            )
        if features is None or features.empty:
            return pd.DataFrame(columns=["source_ip", "anomaly_score", "is_anomaly", "status", "training_rows"])
        x = features[FEATURE_COLUMNS].astype(float).replace([np.inf, -np.inf], 0).fillna(0)
        result = features.copy()
        result["anomaly_score"] = -self.model.score_samples(x)
        result["is_anomaly"] = self.model.predict(x) == -1
        result["status"] = "ok"
        result["training_rows"] = self.training_rows
        return result


def compare_with_rules(features: pd.DataFrame, rule_detection: Dict[str, object], model: Optional[IsolationForestBaseline]) -> pd.DataFrame:
    """Return aligned per-IP rule and model decisions for the interface."""
    rule_map = {row["source_ip"]: bool(row["flagged"]) for row in rule_detection.get("ip_summaries", [])}
    if model is None or model.model is None:
        out = features.copy()
        out["rule_flagged"] = out["source_ip"].map(rule_map).fillna(False)
        out["isolation_forest_anomaly"] = None
        out["anomaly_score"] = None
        out["model_status"] = "model_not_loaded" if model is None else "insufficient_training_data"
        if model is not None:
            out["training_rows"] = model.training_rows
        return out
    predicted = model.predict(features).rename(columns={"is_anomaly": "isolation_forest_anomaly", "status": "model_status"})
    predicted["rule_flagged"] = predicted["source_ip"].map(rule_map).fillna(False)
    return predicted
