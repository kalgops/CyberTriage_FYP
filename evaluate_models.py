"""Run the reproducible threshold-vs-Isolation-Forest evaluation."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

# Keep Matplotlib's cache inside the submission folder for reproducibility and
# to avoid depending on a writable user profile.
os.environ.setdefault("MPLCONFIGDIR", str(Path(__file__).parent / ".matplotlib"))

import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from cybertriage import anomaly, detector, parser
from cybertriage.synthetic_dataset import generate_scenarios


def _observation(scenario):
    parsed = parser.parse_log_text(scenario.log_text)
    features = anomaly.aggregate_features(parsed)
    if features.empty:
        # Preserve malformed scenarios as zero-evidence observations.
        features = pd.DataFrame([{"source_ip": "none", **{c: 0.0 for c in anomaly.FEATURE_COLUMNS}}])
    # Scenario generator uses one source per scenario; use its leading row.
    row = features.sort_values("failed_count", ascending=False).iloc[0].to_dict()
    rule = detector.detect(parsed)
    row.update({
        "scenario_id": scenario.scenario_id,
        "category": scenario.category,
        "label": scenario.label,
        "split": scenario.split,
        "rule_prediction": int(bool(rule["flagged_ips"])),
    })
    return row


def _metrics(name, truth, prediction):
    precision, recall, f1, _ = precision_recall_fscore_support(truth, prediction, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(truth, prediction, labels=[0, 1]).ravel()
    return {
        "model": name,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "true_negative": int(tn), "false_positive": int(fp),
        "false_negative": int(fn), "true_positive": int(tp),
        "test_scenarios": len(truth),
    }


def run(output_dir: Path, seed: int = 3070):
    output_dir.mkdir(parents=True, exist_ok=True)
    scenarios = generate_scenarios(seed=seed)
    frame = pd.DataFrame([_observation(s) for s in scenarios])
    training = frame[frame["split"] == "train_normal"]
    test = frame[frame["split"] == "test"].copy()

    model = anomaly.IsolationForestBaseline(contamination=0.1, random_state=seed)
    model.fit(training)
    predicted = model.predict(test)
    test["isolation_forest_prediction"] = predicted["is_anomaly"].astype(int).to_numpy()
    test["anomaly_score"] = predicted["anomaly_score"].to_numpy()

    metrics = pd.DataFrame([
        _metrics("Threshold baseline", test["label"], test["rule_prediction"]),
        _metrics("Isolation Forest", test["label"], test["isolation_forest_prediction"]),
    ])
    per_category = (
        test.groupby("category")
        .apply(lambda g: pd.Series({
            "scenarios": len(g),
            "positives": int(g["label"].sum()),
            "threshold_correct": int((g["label"] == g["rule_prediction"]).sum()),
            "isolation_forest_correct": int((g["label"] == g["isolation_forest_prediction"]).sum()),
        }), include_groups=False)
        .reset_index()
    )

    test.to_csv(output_dir / "scenario_results.csv", index=False)
    metrics.to_csv(output_dir / "model_metrics.csv", index=False)
    per_category.to_csv(output_dir / "per_category_results.csv", index=False)

    chart = metrics.set_index("model")[["precision", "recall", "f1", "false_positive_rate"]]
    ax = chart.plot(kind="bar", figsize=(9, 5), color=["#2E75B6", "#70AD47", "#ED7D31", "#A5A5A5"])
    ax.set_ylim(0, 1.05); ax.set_ylabel("Score"); ax.set_title("Threshold baseline vs Isolation Forest")
    ax.grid(axis="y", alpha=.25); ax.legend(loc="lower right"); plt.xticks(rotation=0); plt.tight_layout()
    plt.savefig(output_dir / "model_comparison.png", dpi=180)
    plt.close()
    print(f"Training normal observations: {len(training)}")
    print(f"Held-out scenarios: {len(test)}")
    print(metrics.to_string(index=False))
    return metrics, test, per_category


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", type=Path, default=Path("evaluation_results"))
    ap.add_argument("--seed", type=int, default=3070)
    args = ap.parse_args()
    run(args.output_dir, args.seed)
