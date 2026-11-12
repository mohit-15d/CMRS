"""CMRS paper experiment - anomaly detector evaluation (Section 4.5).

Runs Isolation Forest, One-Class SVM, Local Outlier Factor and the paper's
fixed-rule baseline on the synthetic session dataset and reports every metric
computed from the ACTUAL binary predictions.  No metric is forced, rounded
toward, or tuned to match any pre-existing manuscript value.

Protocol
--------
* primary run: dataset seed 42 (read from the CSV produced by
  generate_synthetic_sessions.py), model seed 42
* stability: seeds 0..9; per seed the dataset is regenerated with the same
  generator and the model is given the same seed where supported
* preprocessing (identical pipeline for all three ML models):
    1. np.log1p on the skewed count/volume features
       (failed_login_count, evidence_access_volume, case_access_pattern,
       evidence_access_frequency); the binary off-hours flag stays 0/1
    2. StandardScaler fitted on the whole unlabelled matrix
  true_label never enters the pipeline
* the categorical metadata column `role` is NOT used as a model input (it is
  not behavioural and is not correlated with the injected anomalies here)
* contamination / nu = 0.10 for all three unsupervised models (the known
  100/1000 ratio); the number of predicted anomalies is reported exactly as
  measured and never adjusted

Run:
    python evaluate_detectors.py --seed 42 --dataset output/synthetic_sessions.csv --out output
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_synthetic_sessions import (FEATURES, PRIMARY_SEED,  # noqa: E402
                                         RULE_FAILED_LOGINS, RULE_OFF_HOURS,
                                         RULE_VOLUME_MB, generate, summarize)

# Skewed features that get np.log1p; unusual_access_time is binary and stays as is.
LOG_FEATURES = ["failed_login_count", "evidence_access_volume",
                "case_access_pattern", "evidence_access_frequency"]
METHODS = ["Isolation Forest", "One-Class SVM", "LOF", "Rule-based"]
METRIC_NAMES = ["precision", "recall", "f1", "accuracy", "roc_auc"]
STABILITY_SEEDS = list(range(10))
CONTAMINATION = 0.10


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest().upper()


def preprocess(df: pd.DataFrame) -> np.ndarray:
    """np.log1p on skewed features, then StandardScaler (no label leakage)."""
    x = df[FEATURES].astype(float).copy()
    for col in LOG_FEATURES:
        x[col] = np.log1p(x[col])
    return StandardScaler().fit_transform(x)


def _as_binary(raw: np.ndarray) -> np.ndarray:
    """sklearn -1 (anomaly) -> 1, 1 (inlier) -> 0."""
    return (np.asarray(raw).reshape(-1) == -1).astype(int)


# --------------------------------------------------------------------------
# Detectors (exactly the four methods specified in the experiment protocol)
# --------------------------------------------------------------------------
def detect_isolation_forest(X: np.ndarray, seed: int) -> dict:
    model = IsolationForest(n_estimators=200, contamination=CONTAMINATION,
                            random_state=seed)
    model.fit(X)
    return {
        "pred": _as_binary(model.predict(X)),
        "score": -model.decision_function(X),
        "params": {"n_estimators": 200, "contamination": CONTAMINATION,
                   "random_state": seed},
        "score_note": "continuous anomaly score = -decision_function (higher = more anomalous)",
    }


def detect_one_class_svm(X: np.ndarray, seed: int) -> dict:
    model = OneClassSVM(kernel="rbf", nu=CONTAMINATION)
    model.fit(X)
    return {
        "pred": _as_binary(model.predict(X)),
        "score": -model.decision_function(X),
        "params": {"kernel": "rbf", "nu": CONTAMINATION, "gamma": "scale (sklearn default)",
                   "random_state": None},
        "score_note": ("continuous anomaly score = -decision_function; sklearn's OneClassSVM "
                       "exposes no random_state (deterministic libsvm solver), so none is set"),
    }


def detect_lof(X: np.ndarray, seed: int) -> dict:
    model = LocalOutlierFactor(n_neighbors=20, novelty=False,
                               contamination=CONTAMINATION)
    raw_pred = model.fit_predict(X)  # -1 = anomaly, 1 = normal
    return {
        "pred": _as_binary(raw_pred),
        "score": -model.negative_outlier_factor_,
        "params": {"n_neighbors": 20, "novelty": False, "contamination": CONTAMINATION,
                   "random_state": None},
        "score_note": ("continuous anomaly score = -negative_outlier_factor_ "
                       "(higher = more anomalous); LOF has no random_state (deterministic)"),
    }


def detect_rule(df: pd.DataFrame) -> dict:
    """The paper's fixed rule, thresholds unchanged."""
    pred = (
        (df["unusual_access_time"] == RULE_OFF_HOURS)
        | (df["evidence_access_volume"] > RULE_VOLUME_MB)
        | (df["failed_login_count"] >= RULE_FAILED_LOGINS)
    ).to_numpy().astype(int)
    return {
        "pred": pred,
        "score": None,
        "params": {"off_hours": "unusual_access_time == 1",
                   "volume_mb": f"evidence_access_volume > {RULE_VOLUME_MB}",
                   "failed_logins": f"failed_login_count >= {RULE_FAILED_LOGINS}"},
        "score_note": ("binary rule only - no continuous score exists, so ROC-AUC is reported "
                       "as null; a rule ROC-AUC would not be comparable with the continuous detectors"),
    }


# --------------------------------------------------------------------------
# Metrics (computed from binary predictions, never from scores alone)
# --------------------------------------------------------------------------
def metrics_from_predictions(y_true: np.ndarray, pred: np.ndarray,
                             score: np.ndarray | None = None) -> dict:
    cm = confusion_matrix(y_true, pred, labels=[0, 1])
    tn, fp, fn, tp = (int(v) for v in cm.ravel())
    out = {
        "precision": round(float(precision_score(y_true, pred, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, pred, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, pred, zero_division=0)), 6),
        "accuracy": round(float(accuracy_score(y_true, pred)), 6),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "predicted_anomalies": int(pred.sum()),
        "roc_auc": None,
    }
    if score is not None:
        out["roc_auc"] = round(float(roc_auc_score(y_true, score)), 6)
    return out


DETECTORS = {
    "Isolation Forest": ("ml", detect_isolation_forest),
    "One-Class SVM": ("ml", detect_one_class_svm),
    "LOF": ("ml", detect_lof),
    "Rule-based": ("rule", detect_rule),
}


def run_all(df: pd.DataFrame, seed: int) -> dict:
    """Run all four detectors; returns per-method pred/score/metrics."""
    X = preprocess(df)
    y = df["true_label"].to_numpy()
    results = {}
    for name, (kind, fn) in DETECTORS.items():
        r = fn(X, seed) if kind == "ml" else fn(df)
        r["metrics"] = metrics_from_predictions(y, r["pred"], r["score"])
        results[name] = r
    return results


def stability_study(seeds: list[int]) -> dict:
    """Seed = 0..9; dataset regenerated per seed, model seeded identically."""
    collected = {m: {k: [] for k in METRIC_NAMES} for m in METHODS}
    for seed in seeds:
        df = generate(seed)
        results = run_all(df, seed)
        for m in METHODS:
            for k in METRIC_NAMES:
                v = results[m]["metrics"][k]
                if v is not None:
                    collected[m][k].append(float(v))
    out = {}
    for m in METHODS:
        out[m] = {}
        for k in METRIC_NAMES:
            vals = collected[m][k]
            if not vals:
                out[m][k] = None
            else:
                std = float(np.std(vals, ddof=1)) if len(vals) > 1 else 0.0
                out[m][k] = {"mean": round(float(np.mean(vals)), 6),
                             "std": round(std, 6),
                             "n": len(vals)}
    return out


# --------------------------------------------------------------------------
# Output artefacts
# --------------------------------------------------------------------------
def public_results(results: dict) -> dict:
    """JSON-serialisable view of a run (predictions/scores dropped)."""
    return {
        name: {"params": r["params"], "score_note": r["score_note"], "metrics": r["metrics"]}
        for name, r in results.items()
    }


def table_rows(primary: dict) -> list[dict]:
    rows = []
    for m in METHODS:
        mt = primary[m]["metrics"]
        rows.append({"Method": m,
                     "Precision": f"{mt['precision']:.3f}",
                     "Recall": f"{mt['recall']:.3f}",
                     "F1-score": f"{mt['f1']:.3f}"})
    return rows


def write_table3(out_dir: Path, rows: list[dict]) -> None:
    df = pd.DataFrame(rows, columns=["Method", "Precision", "Recall", "F1-score"])
    df.to_csv(out_dir / "table3.csv", index=False, encoding="utf-8", lineterminator="\n")
    md = ["Table 3. Anomaly detection: Isolation Forest vs. three baseline methods (synthetic data).", "",
          "| Method | Precision | Recall | F1-score |", "|---|---:|---:|---:|"]
    for r in rows:
        md.append(f"| {r['Method']} | {r['Precision']} | {r['Recall']} | {r['F1-score']} |")
    md += ["", "Values are measured from the primary run (dataset seed 42, model seed 42),",
           "formatted to three decimals; full-precision values are in metrics.json."]
    (out_dir / "table3.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def write_confusion(out_dir: Path, primary: dict) -> None:
    doc = {}
    for m in METHODS:
        mt = primary[m]["metrics"]
        doc[m] = {"tp": mt["tp"], "tn": mt["tn"], "fp": mt["fp"], "fn": mt["fn"],
                  "matrix_rows_true_0_1": [[mt["tn"], mt["fp"]], [mt["fn"], mt["tp"]]],
                  "predicted_anomalies": mt["predicted_anomalies"]}
    (out_dir / "confusion_matrices.json").write_text(
        json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def fmt_stability(stability: dict) -> list[str]:
    lines = ["10-SEED RESULTS (seeds 0-9; dataset regenerated per seed; mean +/- sample std)", ""]
    header = f"{'Method':<18}{'Precision':>18}{'Recall':>18}{'F1':>18}{'Accuracy':>18}{'ROC-AUC':>18}"
    lines += [header, "-" * len(header)]
    for m in METHODS:
        cells = []
        for k in METRIC_NAMES:
            s = stability[m][k]
            cells.append("n/a" if s is None else f"{s['mean']:.4f} +/- {s['std']:.4f}")
        lines.append(f"{m:<18}" + "".join(f"{c:>18}" for c in cells))
    lines += ["", "ROC-AUC for the rule-based baseline is n/a: the rule produces a binary",
              "decision only, so no comparable continuous score exists."]
    return lines


def fmt_method_block(method: str, r: dict) -> list[str]:
    mt = r["metrics"]
    lines = [
        f"{method}",
        f"  parameters            : {json.dumps(r['params'])}",
        f"  score                 : {r['score_note']}",
        f"  predicted anomalies   : {mt['predicted_anomalies']}",
        f"  precision / recall/F1 : {mt['precision']:.6f} / {mt['recall']:.6f} / {mt['f1']:.6f}",
        f"  accuracy              : {mt['accuracy']:.6f}",
        "  roc_auc               : " + ("n/a" if mt["roc_auc"] is None else f"{mt['roc_auc']:.6f}"),
        f"  confusion (tn, fp, fn, tp): ({mt['tn']}, {mt['fp']}, {mt['fn']}, {mt['tp']})",
    ]
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate anomaly detectors on the CMRS synthetic dataset.")
    parser.add_argument("--seed", type=int, default=PRIMARY_SEED, help="model seed (default 42)")
    parser.add_argument("--dataset", type=Path,
                        default=Path(__file__).resolve().parent / "output" / "synthetic_sessions.csv")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "output")
    parser.add_argument("--skip-stability", action="store_true")
    args = parser.parse_args()

    log: list[str] = []

    def say(text: str = "") -> None:
        print(text)
        log.append(text)

    df = pd.read_csv(args.dataset)
    ds_stats = summarize(df)
    ds_sha = sha256_file(args.dataset)

    say("=" * 78)
    say("CMRS Section 4.5 - anomaly detection experiment")
    say("=" * 78)
    say(f"dataset file      : {args.dataset}")
    say(f"dataset sha256    : {ds_sha}")
    say(f"model seed        : {args.seed}")
    say(f"python/sklearn    : {platform.python_version()} / sklearn {sklearn.__version__}")
    say("")
    say("DATASET VERIFICATION")
    for k, v in ds_stats.items():
        say(f"  {k}: {v}")
    say("")

    primary = run_all(df, args.seed)
    say(f"PRIMARY RESULTS (model seed {args.seed}; metrics from binary predictions)")
    say("")
    for m in METHODS:
        say("\n".join(fmt_method_block(m, primary[m])))
        say("")

    rows = table_rows(primary)
    say("TABLE 3 (measured)")
    for r in rows:
        say(f"  {r['Method']:<18} precision={r['Precision']}  recall={r['Recall']}  f1={r['F1-score']}")
    say("")

    stability = {}
    if not args.skip_stability:
        stability = stability_study(STABILITY_SEEDS)
        for line in fmt_stability(stability):
            say(line)
        say("")

    metrics_doc = {
        "experiment": "CMRS Section 4.5 - anomaly detection on synthetic user sessions",
        "critical_note": ("All values below are measured from the actual binary predictions of the "
                          "listed detectors. No value was forced, adjusted, or targeted."),
        "protocol": {
            "primary_model_seed": args.seed,
            "dataset_generator_seed": PRIMARY_SEED,
            "stability_seeds": STABILITY_SEEDS,
            "contamination_nu": CONTAMINATION,
            "rule_thresholds": {"off_hours": "unusual_access_time == 1",
                                "volume_mb": f"evidence_access_volume > {RULE_VOLUME_MB}",
                                "failed_logins": f"failed_login_count >= {RULE_FAILED_LOGINS}"},
            "preprocessing": {
                "log1p_features": LOG_FEATURES,
                "binary_feature_untouched": ["unusual_access_time"],
                "scaler": "StandardScaler fitted on the full unlabelled feature matrix",
                "true_label_used_in_pipeline": False,
                "categorical_role_used_as_feature": False,
            },
            "prediction_mapping": "sklearn -1 -> 1 (anomaly), 1 -> 0 (normal)",
            "predicted_anomaly_counts_adjusted": False,
        },
        "environment": {"python": platform.python_version(), "numpy": np.__version__,
                        "pandas": pd.__version__, "scikit_learn": sklearn.__version__},
        "dataset": {**ds_stats, "file": args.dataset.name, "sha256": ds_sha,
                    "generator": "generate_synthetic_sessions.py"},
        "primary_results": public_results(primary),
        "stability_results": stability,
    }

    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(metrics_doc, indent=2) + "\n", encoding="utf-8")
    write_table3(out, rows)
    write_confusion(out, primary)

    from datetime import datetime
    header = [f"CMRS experiment log - generated {datetime.now().isoformat(timespec='seconds')}"]
    (out / "experiment_log.txt").write_text("\n".join(header + log) + "\n", encoding="utf-8")
    print(f"\nartefacts written to: {out}")


if __name__ == "__main__":
    main()


