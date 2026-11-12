"""CMRS Part A: Held-out 80/20 stratified split validation on seed-42 dataset.

Protocol:
- Uses ONLY the existing original dataset: experiments/output/synthetic_sessions.csv
- Stratified 80/20 split (random_state=42):
    - Train split: 800 records (720 normal, 80 anomalous)
    - Test split : 200 records (180 normal, 20 anomalous)
- Fits preprocessing (np.log1p + StandardScaler) and all unsupervised models
  ONLY on the 720 normal training records (y_train == 0).
- Evaluates on the 200 held-out test records without test-label tuning.
- Evaluates Isolation Forest with both contamination=0.10 (original param)
  and contamination="auto" (normal-only / live backend param), plus
  One-Class SVM (nu=0.10), LOF (novelty=True, contamination=0.10), and the
  fixed Rule-based baseline.
"""
from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

ROOT_EXP_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_EXP_DIR))

from generate_synthetic_sessions import (  # noqa: E402
    FEATURES,
    PRIMARY_SEED,
    RULE_FAILED_LOGINS,
    RULE_OFF_HOURS,
    RULE_VOLUME_MB,
)

SPLIT_SEED = 42
TEST_SIZE = 0.20
LOG_FEATURES = [
    "failed_login_count",
    "evidence_access_volume",
    "case_access_pattern",
    "evidence_access_frequency",
]
EXPECTED_DATASET_SHA256 = "BAB4140BF159919243E2E50833F7F674F3B3F8F721A7029D2122230D7EB2BAC0"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest().upper()


def _log_transform(df: pd.DataFrame) -> pd.DataFrame:
    x = df[FEATURES].astype(float).copy()
    for col in LOG_FEATURES:
        x[col] = np.log1p(x[col])
    return x


def _as_binary(raw: np.ndarray) -> np.ndarray:
    """Map sklearn {-1: anomaly, 1: inlier} -> {1: anomaly, 0: normal}."""
    return (np.asarray(raw).reshape(-1) == -1).astype(int)


def compute_metrics(
    y_true: np.ndarray, pred: np.ndarray, score: np.ndarray | None = None
) -> dict:
    cm = confusion_matrix(y_true, pred, labels=[0, 1])
    tn, fp, fn, tp = (int(v) for v in cm.ravel())
    out = {
        "accuracy": round(float(accuracy_score(y_true, pred)), 6),
        "precision": round(float(precision_score(y_true, pred, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, pred, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, pred, zero_division=0)), 6),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "predicted_anomalies": int(pred.sum()),
        "roc_auc": None,
        "score_direction_check": None,
    }
    if score is not None:
        mean_norm = float(np.mean(score[y_true == 0]))
        mean_anom = float(np.mean(score[y_true == 1]))
        out["roc_auc"] = round(float(roc_auc_score(y_true, score)), 6)
        out["score_direction_check"] = {
            "higher_is_more_anomalous": bool(mean_anom > mean_norm),
            "mean_score_normal": round(mean_norm, 6),
            "mean_score_anomaly": round(mean_anom, 6),
        }
    return out


def main() -> None:
    out_dir = Path(__file__).resolve().parent
    dataset_path = ROOT_EXP_DIR / "output" / "synthetic_sessions.csv"
    orig_metrics_path = ROOT_EXP_DIR / "output" / "metrics.json"

    ds_sha = sha256_file(dataset_path)
    assert ds_sha == EXPECTED_DATASET_SHA256, f"Dataset SHA-256 mismatch: {ds_sha}"

    df = pd.read_csv(dataset_path)
    assert len(df) == 1000, f"Expected 1000 rows, got {len(df)}"

    train_df, test_df = train_test_split(
        df, test_size=TEST_SIZE, stratify=df["true_label"], random_state=SPLIT_SEED
    )
    train_normal_df = train_df[train_df["true_label"] == 0].copy()

    assert len(train_df) == 800
    assert int((train_df["true_label"] == 0).sum()) == 720
    assert int((train_df["true_label"] == 1).sum()) == 80
    assert len(test_df) == 200
    assert int((test_df["true_label"] == 0).sum()) == 180
    assert int((test_df["true_label"] == 1).sum()) == 20
    assert len(train_normal_df) == 720

    # Fit preprocessing ONLY on the 720 normal training records
    scaler = StandardScaler()
    X_train_normal = scaler.fit_transform(_log_transform(train_normal_df))
    X_test = scaler.transform(_log_transform(test_df))
    y_test = test_df["true_label"].to_numpy()

    models = {
        "Isolation Forest (contamination=0.10)": {
            "kind": "ml",
            "model": IsolationForest(
                n_estimators=200, contamination=0.10, random_state=PRIMARY_SEED
            ),
            "params": {"n_estimators": 200, "contamination": 0.10, "random_state": PRIMARY_SEED},
            "score_note": "-decision_function(X_test) (higher = more anomalous)",
        },
        "Isolation Forest (contamination='auto')": {
            "kind": "ml",
            "model": IsolationForest(
                n_estimators=200, contamination="auto", random_state=PRIMARY_SEED
            ),
            "params": {"n_estimators": 200, "contamination": "auto", "random_state": PRIMARY_SEED},
            "score_note": "-decision_function(X_test) (higher = more anomalous)",
        },
        "One-Class SVM (nu=0.10)": {
            "kind": "ml",
            "model": OneClassSVM(kernel="rbf", nu=0.10),
            "params": {"kernel": "rbf", "nu": 0.10, "gamma": "scale"},
            "score_note": "-decision_function(X_test) (higher = more anomalous)",
        },
        "LOF (novelty=True, contamination=0.10)": {
            "kind": "ml",
            "model": LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=0.10),
            "params": {"n_neighbors": 20, "novelty": True, "contamination": 0.10},
            "score_note": "-decision_function(X_test) (higher = more anomalous)",
        },
        "Rule-based (fixed)": {
            "kind": "rule",
            "params": {
                "off_hours": f"unusual_access_time == {RULE_OFF_HOURS}",
                "volume_mb": f"evidence_access_volume > {RULE_VOLUME_MB}",
                "failed_logins": f"failed_login_count >= {RULE_FAILED_LOGINS}",
            },
            "score_note": "binary rule only - no continuous score (roc_auc = null)",
        },
    }

    results = {}
    cm_doc = {}
    for name, spec in models.items():
        if spec["kind"] == "ml":
            mdl = spec["model"]
            mdl.fit(X_train_normal)
            pred = _as_binary(mdl.predict(X_test))
            score = -mdl.decision_function(X_test)
        else:
            pred = (
                (test_df["unusual_access_time"] == RULE_OFF_HOURS)
                | (test_df["evidence_access_volume"] > RULE_VOLUME_MB)
                | (test_df["failed_login_count"] >= RULE_FAILED_LOGINS)
            ).to_numpy().astype(int)
            score = None

        mt = compute_metrics(y_test, pred, score)
        results[name] = {
            "params": spec["params"],
            "score_note": spec["score_note"],
            "metrics": mt,
        }
        cm_doc[name] = {
            "tp": mt["tp"],
            "tn": mt["tn"],
            "fp": mt["fp"],
            "fn": mt["fn"],
            "matrix_rows_true_0_1": [[mt["tn"], mt["fp"]], [mt["fn"], mt["tp"]]],
            "predicted_anomalies": mt["predicted_anomalies"],
        }

    split_manifest = {
        "source_dataset": "experiments/output/synthetic_sessions.csv",
        "source_sha256": ds_sha,
        "split_method": "sklearn.model_selection.train_test_split (stratified 80/20)",
        "split_random_state": SPLIT_SEED,
        "test_size_ratio": TEST_SIZE,
        "train_total": int(len(train_df)),
        "train_normal_used_for_fitting": int(len(train_normal_df)),
        "train_anomalous_excluded_from_unsupervised_fit": int((train_df["true_label"] == 1).sum()),
        "test_total": int(len(test_df)),
        "test_normal": int((test_df["true_label"] == 0).sum()),
        "test_anomalous": int((test_df["true_label"] == 1).sum()),
        "recall_resolution_per_sample": 0.05,
        "train_session_ids": train_df["session_id"].tolist(),
        "test_session_ids": test_df["session_id"].tolist(),
    }

    orig_metrics = json.loads(orig_metrics_path.read_text(encoding="utf-8"))

    metrics_doc = {
        "experiment": "CMRS Part A: Stratified 80/20 Held-Out Validation (Normal-Only Fitting)",
        "source_dataset": {
            "file": "experiments/output/synthetic_sessions.csv",
            "sha256": ds_sha,
            "seed": PRIMARY_SEED,
            "total_rows": 1000,
        },
        "protocol": {
            "split_random_state": SPLIT_SEED,
            "train_fit_rows": 720,
            "train_fit_class": "normal_only (true_label == 0)",
            "test_rows": 200,
            "test_class_distribution": {"normal": 180, "anomalous": 20},
            "recall_granularity_note": "20 anomalous test samples -> 1 sample = 5 percentage points (0.05) recall",
            "feature_count": len(FEATURES),
            "features": FEATURES,
            "excluded_columns": ["session_id", "user_id", "role", "true_label"],
            "preprocessing": "np.log1p on skewed features + StandardScaler fitted ONLY on 720 normal training records",
            "test_labels_used_in_tuning": False,
        },
        "environment": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "heldout_split_results": results,
        "original_same_session_reference": orig_metrics.get("primary_results", {}),
    }

    (out_dir / "split_manifest.json").write_text(
        json.dumps(split_manifest, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "heldout_split_metrics.json").write_text(
        json.dumps(metrics_doc, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "heldout_split_confusion_matrices.json").write_text(
        json.dumps(cm_doc, indent=2) + "\n", encoding="utf-8"
    )

    print("=" * 78)
    print("CMRS Held-Out 80/20 Split Validation (Normal-Only Fitting: 720 Train -> 200 Test)")
    print("=" * 78)
    for name, res in results.items():
        mt = res["metrics"]
        auc = "n/a" if mt["roc_auc"] is None else f"{mt['roc_auc']:.6f}"
        print(
            f"{name:<40} | Acc={mt['accuracy']:.4f} Prec={mt['precision']:.4f} "
            f"Rec={mt['recall']:.4f} F1={mt['f1']:.4f} AUC={auc} "
            f"(tn={mt['tn']} fp={mt['fp']} fn={mt['fn']} tp={mt['tp']})"
        )


if __name__ == "__main__":
    main()
