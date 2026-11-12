# CMRS anomaly-detection experiment (paper Section 4.5)

Reproducible experiment that produces the anomaly-detection numbers reported in
Table 3 of the CMRS paper. Everything here is **measured from actual model
predictions** — no metric is forced, rounded toward, or tuned to match any
previously reported value.

This folder is self-contained. It does not import, modify, or run CMRS
application code, the API, the database, or any pipeline.

## How to run

```bash
cd experiments

# 1. Dataset (fixed seed 42 -> byte-identical CSV)
python generate_synthetic_sessions.py --seed 42 --out output/synthetic_sessions.csv

# 2. Evaluation: primary same-session run (seed 42) + 10-seed stability study (seeds 0-9)
python evaluate_detectors.py --seed 42 --dataset output/synthetic_sessions.csv --out output
```

Environment: Python 3.13.1, scikit-learn 1.9.0, pandas 3.0.5, numpy 2.5.2.

## Dataset design (1,000 sessions: 900 normal + 100 anomalous)

Six behavioural features (`unusual_access_time`, `failed_login_count`,
`evidence_access_volume`, `case_access_pattern`, `login_frequency`,
`evidence_access_frequency`) plus metadata (`session_id`, `user_id`, `role`,
`true_label`). Normal and anomalous behaviour **deliberately overlap**.

*(Note: The live CMRS backend service includes a seventh feature,
`transfer_frequency`, which is not part of this Section 4.5 synthetic dataset.)*

| Block | n | Behaviour |
|---|---:|---|
| normal | 900 | log-normal volumes; 8.4% off-hours; 4.8% above 55 MB (legitimate batch exports); 3.7% with >= 2 failed logins; 2.7% with cross-case access |
| A1 bulk download | 15 | 260–900 MB (single strong indicator) |
| A2 failed logins | 10 | 6–15 failures (single strong indicator) |
| A3 cross-case | 10 | 4–10 cross-case accesses (single strong indicator) |
| B1 combined weak | 15 | off-hours + 60–130 MB + 2–3 failures + 1–2 cross-case |
| B2 below-threshold combination | 15 | every indicator stays under the rule thresholds; only the joint pattern is unusual (half of the block has a dormant-account profile) |
| B3 combined weak | 10 | off-hours + 2–4 failures + 35–55 MB |
| C1 moderate volume | 10 | only 56–140 MB (overlaps the normal batch-export tail) |
| C2 moderate failures | 8 | only 2–4 failed logins |
| C3 off-hours only | 7 | only off-hours, everything else ordinary |

Measured composition: 16.22% of normal sessions and 87% of anomalous sessions
trip the paper's fixed rule, so the rule baseline has a realistic false-alarm
floor and no detector enjoys perfect separation.

## Documented decisions (same-session methodology)

* `unusual_access_time` is a **binary** off-hours flag, so the paper's rule
  ("access outside 06:00–22:00") and `unusual_access_time == 1` are the same
  condition.
* `role` (admin / investigator / viewer) is realistic metadata and stays
  categorical. It is **not** a model input: it is not behavioural, and by
  construction it does not encode the injected anomalies.
* Preprocessing, identical for all three ML models: `np.log1p` on the skewed
  count/volume features (`failed_login_count`, `evidence_access_volume`,
  `case_access_pattern`, `evidence_access_frequency`); the binary flag is left
  at 0/1; `StandardScaler` fitted on the full unlabelled matrix. `true_label`
  never enters the pipeline.
* `contamination` / `nu` = 0.10 for all three unsupervised models, matching the
  dataset's 100/1000 anomaly rate. Predicted anomaly counts are reported as
  measured and never adjusted.
* Isolation Forest uses `random_state = seed`; `OneClassSVM` and
  `LocalOutlierFactor` (`novelty=False`, `fit_predict`) expose no `random_state`
  (deterministic solvers), so none is set there.
* Stability study: seeds 0–9, dataset regenerated per seed with the same
  generator (generator seed == model seed). The primary run uses the saved
  seed-42 dataset and reports the 10-seed stability separately; no seed is
  selected for a better score.

## Measured results (primary same-session run: dataset seed 42, model seed 42)

| Method | Precision | Recall | F1-score | Accuracy | ROC-AUC | Predicted anomalies |
|---|---:|---:|---:|---:|---:|---:|
| Isolation Forest | 0.710 | 0.710 | 0.710 | 0.942 | 0.950 | 100 |
| One-Class SVM | 0.500 | 0.500 | 0.500 | 0.900 | 0.883 | 100 |
| LOF | 0.290 | 0.290 | 0.290 | 0.858 | 0.772 | 100 |
| Rule-based | 0.373 | 0.870 | 0.523 | 0.841 | n/a (binary rule) | 233 |

10-seed means (mean +/- sample std): Isolation Forest F1 `0.688 +/- 0.028`,
One-Class SVM `0.492 +/- 0.032`, LOF `0.325 +/- 0.034`, rule baseline
`0.546 +/- 0.026`.

## Reproducibility

* DATASET_REPRODUCIBILITY: **PASS** — generator run twice produces identical
  bytes; SHA-256:
  `BAB4140BF159919243E2E50833F7F674F3B3F8F721A7029D2122230D7EB2BAC0`
* PRIMARY_RUN_REPRODUCIBILITY: **PASS** — evaluator run twice produces identical
  `metrics.json`, `table3.csv`, and `confusion_matrices.json`.

## Files

| File | Content |
|---|---|
| `generate_synthetic_sessions.py` | dataset generator (fixed seed, byte-identical output) |
| `evaluate_detectors.py` | four detectors, metrics from binary predictions, stability study, artefact writer |
| `output/synthetic_sessions.csv` | the 1,000-session dataset (seed 42) |
| `output/metrics.json` | all measured metrics, protocol, environment, dataset stats |
| `output/table3.csv`, `output/table3.md` | Table 3 with measured values (3 decimals) |
| `output/confusion_matrices.json` | TP/TN/FP/FN per detector |
| `output/experiment_log.txt` | full run log |

## Limitations

* **Synthetic dataset:** The 1,000 sessions are synthetically generated rather than
  real-world labelled forensic activity logs. The experiment demonstrates
  comparative feasibility on synthetic overlapping distributions, not a
  real-world production accuracy estimate.
* **Same-session evaluation:** In the primary seed-42 run, each unsupervised
  model and the `StandardScaler` are fitted and evaluated on the same 1,000
  sessions without a separate held-out test split (and `LocalOutlierFactor`
  uses `novelty=False`).
