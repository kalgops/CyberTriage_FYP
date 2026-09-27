"""Tests for feature aggregation and Isolation Forest safety."""

import pandas as pd
import pytest

from cybertriage import anomaly, parser
from cybertriage.synthetic_dataset import generate_scenarios


def _training_features():
    frames = [
        anomaly.aggregate_features(parser.parse_log_text(s.log_text))
        for s in generate_scenarios()
        if s.split == "train_normal"
    ]
    return pd.concat(frames, ignore_index=True)


def test_feature_columns_and_values():
    scenario = next(s for s in generate_scenarios() if s.category == "concentrated_brute_force")
    frame = anomaly.aggregate_features(parser.parse_log_text(scenario.log_text))
    assert list(frame.columns) == ["source_ip", *anomaly.FEATURE_COLUMNS]
    assert frame.iloc[0]["failed_count"] >= 12
    assert frame.iloc[0]["failure_ratio"] == 1.0


def test_successful_automation_has_zero_failure_ratio():
    scenario = next(s for s in generate_scenarios() if s.category == "legitimate_automation")
    row = anomaly.aggregate_features(parser.parse_log_text(scenario.log_text)).iloc[0]
    assert row["successful_count"] >= 12
    assert row["failure_ratio"] == 0.0


def test_model_refuses_insufficient_training_data():
    with pytest.raises(ValueError, match="at least"):
        anomaly.IsolationForestBaseline().fit(_training_features().head(3))


def test_model_trains_on_normal_reference_rows():
    model = anomaly.IsolationForestBaseline(random_state=3070).fit(_training_features())
    assert model.training_rows == 24


def test_untrained_model_returns_explicit_status():
    result = anomaly.IsolationForestBaseline().predict(_training_features().head(1))
    assert result.iloc[0]["status"] == "insufficient_training_data"
    assert result.iloc[0]["is_anomaly"] is None


def test_model_prediction_is_reproducible():
    training = _training_features()
    test = training.head(5)
    a = anomaly.IsolationForestBaseline(random_state=3070).fit(training).predict(test)
    b = anomaly.IsolationForestBaseline(random_state=3070).fit(training).predict(test)
    assert a["is_anomaly"].tolist() == b["is_anomaly"].tolist()
    assert a["anomaly_score"].tolist() == pytest.approx(b["anomaly_score"].tolist())
