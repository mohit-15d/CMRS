"""CMRS paper experiment - synthetic session dataset generator.

Generates the 1,000-session behaviour dataset used in Section 4.5 of the CMRS
paper (900 normal sessions, 100 anomalous sessions) with the six behavioural
features plus session metadata.  The normal and anomalous distributions
deliberately OVERLAP: normal sessions occasionally show single suspicious
traits (off-hours work, large downloads, failed logins, rare cross-case
access) and anomalies include combined-weak-indicator and moderate-indicator
cases that sit inside the normal tail.  There is no perfect separation.

Deterministic: a fixed seed always produces a byte-identical CSV.

Run:
    python generate_synthetic_sessions.py --seed 42 --out output/synthetic_sessions.csv
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------
# Feature contract (must match the paper and the evaluation script)
# --------------------------------------------------------------------------
FEATURES = [
    "unusual_access_time",        # binary off-hours flag (1 = outside 06:00-22:00)
    "failed_login_count",         # failed logins during the session
    "evidence_access_volume",     # MB of evidence accessed/downloaded in the session
    "case_access_pattern",        # accesses to cases the user is not assigned to
    "login_frequency",            # logins during the last 30 days
    "evidence_access_frequency",  # evidence items accessed in the session
]
METADATA = ["user_id", "role"]     # kept OUT of the model feature matrix
COLUMNS = ["session_id", *FEATURES, "user_id", "role", "true_label"]

ROLES = ("admin", "investigator", "viewer")
NORMAL, ANOMALY = 0, 1
N_NORMAL = 900
N_ANOMALY = 100
PRIMARY_SEED = 42

# Rule thresholds from the paper (used only by the rule baseline, never here)
RULE_OFF_HOURS = 1
RULE_VOLUME_MB = 55.0
RULE_FAILED_LOGINS = 2


def _normals(rng: np.random.Generator, n: int) -> dict:
    """900 normal sessions with realistic, occasionally suspicious behaviour."""
    role = rng.choice(ROLES, size=n, p=(0.15, 0.70, 0.15))

    # Login frequency: admins/investigators use the system more than viewers.
    base = rng.normal(22.0, 6.0, size=n)
    shift = np.where(role == "viewer", -6.0, np.where(role == "admin", 4.0, 0.0))
    login_frequency = np.clip(np.round(base + shift), 4, 48).astype(int)

    # Off-hours work is uncommon but genuinely happens (~8% of normal sessions).
    unusual_access_time = (rng.random(n) < 0.08).astype(int)

    # Evidence volume: log-normal body plus occasional legitimate batch exports
    # (multi-file exports legitimately reach tens of MB).
    volume = rng.lognormal(mean=2.2, sigma=0.9, size=n)
    batch_export = rng.random(n) < 0.04
    volume = np.where(batch_export, rng.uniform(40.0, 95.0, size=n), volume)
    volume = np.clip(volume, 0.5, 220.0)

    # Failed logins: mostly zero; a few honest mistypes (some reach >= 2).
    roll = rng.random(n)
    failed = np.zeros(n, dtype=int)
    failed[(roll >= 0.00) & (roll < 0.09)] = 1
    failed[(roll >= 0.09) & (roll < 0.11)] = 2
    failed[(roll >= 0.11) & (roll < 0.12)] = 3

    # Cross-case access is rare but not impossible for normal sessions.
    roll = rng.random(n)
    case_access = np.zeros(n, dtype=int)
    case_access[(roll >= 0.975) & (roll < 0.995)] = 1
    case_access[roll >= 0.995] = 2

    # Evidence items accessed per session; a few busy days go higher.
    eaf = rng.integers(1, 7, size=n)
    busy = rng.random(n) < 0.05
    eaf = np.where(busy, rng.integers(8, 13, size=n), eaf)

    return {
        "unusual_access_time": unusual_access_time,
        "failed_login_count": failed,
        "evidence_access_volume": np.round(volume, 2),
        "case_access_pattern": case_access,
        "login_frequency": login_frequency,
        "evidence_access_frequency": eaf.astype(int),
        "role": role,
    }


def _group(rng: np.random.Generator, m: int, **cols) -> dict:
    """Build one anomaly archetype block (role metadata included)."""
    block = {c: np.asarray(v) for c, v in cols.items()}
    block["role"] = rng.choice(ROLES, size=m, p=(0.15, 0.70, 0.15))
    return block


def _anomalies(rng: np.random.Generator) -> dict:
    """100 anomalous sessions in three families (single strong / combined weak /
    moderate-overlapping), so that no trivial separation exists."""
    groups = {}

    # --- Family A: single strong indicator ---------------------------------
    # A1 (15) bulk download far above any normal session.
    m = 15
    groups["A1_bulk_download"] = _group(
        rng, m,
        unusual_access_time=(rng.random(m) < 0.40).astype(int),
        failed_login_count=rng.integers(0, 2, size=m),
        evidence_access_volume=np.round(rng.uniform(260.0, 900.0, size=m), 2),
        case_access_pattern=np.zeros(m, dtype=int),
        login_frequency=np.clip(np.round(rng.normal(20.0, 6.0, size=m)), 4, 48).astype(int),
        evidence_access_frequency=rng.integers(3, 11, size=m),
    )

    # A2 (10) many failed logins, little else unusual.
    m = 10
    groups["A2_failed_logins"] = _group(
        rng, m,
        unusual_access_time=(rng.random(m) < 0.30).astype(int),
        failed_login_count=rng.integers(6, 16, size=m),
        evidence_access_volume=np.round(rng.uniform(6.0, 30.0, size=m), 2),
        case_access_pattern=np.zeros(m, dtype=int),
        login_frequency=np.clip(np.round(rng.normal(24.0, 6.0, size=m)), 4, 48).astype(int),
        evidence_access_frequency=rng.integers(1, 6, size=m),
    )

    # A3 (10) repeated cross-case access, otherwise ordinary.
    m = 10
    groups["A3_cross_case"] = _group(
        rng, m,
        unusual_access_time=(rng.random(m) < 0.30).astype(int),
        failed_login_count=rng.integers(0, 3, size=m),
        evidence_access_volume=np.round(rng.uniform(18.0, 60.0, size=m), 2),
        case_access_pattern=rng.integers(4, 11, size=m),
        login_frequency=np.clip(np.round(rng.normal(22.0, 6.0, size=m)), 4, 48).astype(int),
        evidence_access_frequency=rng.integers(2, 8, size=m),
    )

    # --- Family B: several weak indicators combined ------------------------
    # B1 (15) off-hours + above-threshold volume + failed logins + cross-case.
    m = 15
    groups["B1_offhours_volume_failed_crosscase"] = _group(
        rng, m,
        unusual_access_time=np.ones(m, dtype=int),
        failed_login_count=rng.integers(2, 4, size=m),
        evidence_access_volume=np.round(rng.uniform(60.0, 130.0, size=m), 2),
        case_access_pattern=rng.integers(1, 3, size=m),
        login_frequency=np.clip(np.round(rng.normal(24.0, 7.0, size=m)), 4, 48).astype(int),
        evidence_access_frequency=rng.integers(3, 10, size=m),
    )

    # B2 (15) every indicator stays BELOW the rule thresholds, so only the
    # joint pattern is unusual; half the block has a dormant-account profile.
    m = 15
    login_freq = np.where(
        rng.random(m) < 0.5,
        np.round(rng.uniform(2.0, 8.0, size=m)),
        np.clip(np.round(rng.normal(22.0, 6.0, size=m)), 4, 48),
    )
    groups["B2_below_threshold_combination"] = _group(
        rng, m,
        unusual_access_time=np.zeros(m, dtype=int),
        failed_login_count=rng.integers(1, 3, size=m),
        evidence_access_volume=np.round(rng.uniform(45.0, 54.0, size=m), 2),
        case_access_pattern=np.ones(m, dtype=int),
        login_frequency=login_freq.astype(int),
        evidence_access_frequency=rng.integers(2, 7, size=m),
    )

    # B3 (10) off-hours + moderate failed logins + mid-size volume.
    m = 10
    groups["B3_offhours_failed_moderate"] = _group(
        rng, m,
        unusual_access_time=np.ones(m, dtype=int),
        failed_login_count=rng.integers(2, 5, size=m),
        evidence_access_volume=np.round(rng.uniform(35.0, 55.0, size=m), 2),
        case_access_pattern=rng.integers(0, 2, size=m),
        login_frequency=np.clip(np.round(rng.normal(20.0, 6.0, size=m)), 4, 48).astype(int),
        evidence_access_frequency=rng.integers(2, 7, size=m),
    )

    # --- Family C: moderate indicator overlapping the normal tail ----------
    # C1 (10) download just above the rule threshold.
    m = 10
    groups["C1_moderate_volume"] = _group(
        rng, m,
        unusual_access_time=np.zeros(m, dtype=int),
        failed_login_count=rng.integers(0, 2, size=m),
        evidence_access_volume=np.round(rng.uniform(56.0, 140.0, size=m), 2),
        case_access_pattern=(rng.random(m) < 0.2).astype(int),
        login_frequency=np.clip(np.round(rng.normal(21.0, 6.0, size=m)), 4, 48).astype(int),
        evidence_access_frequency=rng.integers(2, 8, size=m),
    )

    # C2 (8) two to four failed logins only.
    m = 8
    groups["C2_moderate_failed_logins"] = _group(
        rng, m,
        unusual_access_time=np.zeros(m, dtype=int),
        failed_login_count=rng.integers(2, 5, size=m),
        evidence_access_volume=np.round(rng.uniform(6.0, 30.0, size=m), 2),
        case_access_pattern=np.zeros(m, dtype=int),
        login_frequency=np.clip(np.round(rng.normal(22.0, 6.0, size=m)), 4, 48).astype(int),
        evidence_access_frequency=rng.integers(1, 6, size=m),
    )

    # C3 (7) off-hours only, everything else within normal ranges.
    m = 7
    groups["C3_moderate_off_hours"] = _group(
        rng, m,
        unusual_access_time=np.ones(m, dtype=int),
        failed_login_count=np.zeros(m, dtype=int),
        evidence_access_volume=np.round(rng.uniform(20.0, 45.0, size=m), 2),
        case_access_pattern=np.zeros(m, dtype=int),
        login_frequency=np.clip(np.round(rng.normal(18.0, 6.0, size=m)), 4, 48).astype(int),
        evidence_access_frequency=rng.integers(1, 5, size=m),
    )

    total = sum(len(g["unusual_access_time"]) for g in groups.values())
    assert total == N_ANOMALY, f"anomaly blocks sum to {total}, expected {N_ANOMALY}"
    return groups


def generate(seed: int = PRIMARY_SEED) -> pd.DataFrame:
    """Return the full 1,000-session dataset for the given seed."""
    rng = np.random.default_rng(seed)
    normal = _normals(rng, N_NORMAL)
    anomaly_blocks = list(_anomalies(rng).values())

    blocks = [normal, *anomaly_blocks]
    data = {
        c: np.concatenate([b[c] for b in blocks])
        for c in [*FEATURES, "role"]
    }
    labels = np.concatenate([
        np.full(N_NORMAL, NORMAL, dtype=int),
        np.full(N_ANOMALY, ANOMALY, dtype=int),
    ])

    order = rng.permutation(N_NORMAL + N_ANOMALY)
    df = pd.DataFrame({c: data[c][order] for c in [*FEATURES, "role"]})
    df["true_label"] = labels[order]
    df["session_id"] = [f"S{i:04d}" for i in range(1, len(df) + 1)]
    df["user_id"] = [f"U{u:03d}" for u in rng.integers(1, 151, size=len(df))]

    for c in FEATURES:
        if c != "evidence_access_volume":
            df[c] = df[c].astype(int)
    df["evidence_access_volume"] = df["evidence_access_volume"].astype(float).round(2)
    return df[COLUMNS]


def summarize(df: pd.DataFrame) -> dict:
    """Verification statistics required by the experiment protocol."""
    normal = df[df["true_label"] == NORMAL]
    anom = df[df["true_label"] == ANOMALY]
    rule = (
        (df["unusual_access_time"] == RULE_OFF_HOURS)
        | (df["evidence_access_volume"] > RULE_VOLUME_MB)
        | (df["failed_login_count"] >= RULE_FAILED_LOGINS)
    )
    return {
        "rows": int(len(df)),
        "normal": int(len(normal)),
        "anomaly": int(len(anom)),
        "nan_cells": int(df.isna().sum().sum()),
        "duplicate_session_ids": int(df["session_id"].duplicated().sum()),
        "normal_off_hours_pct": round(100 * float(normal["unusual_access_time"].mean()), 2),
        "normal_download_gt55mb_pct": round(100 * float((normal["evidence_access_volume"] > RULE_VOLUME_MB).mean()), 2),
        "normal_failed_logins_ge2_pct": round(100 * float((normal["failed_login_count"] >= RULE_FAILED_LOGINS).mean()), 2),
        "normal_cross_case_pct": round(100 * float((normal["case_access_pattern"] > 0).mean()), 2),
        "anomaly_off_hours_pct": round(100 * float(anom["unusual_access_time"].mean()), 2),
        "anomaly_download_gt55mb_pct": round(100 * float((anom["evidence_access_volume"] > RULE_VOLUME_MB).mean()), 2),
        "anomaly_failed_logins_ge2_pct": round(100 * float((anom["failed_login_count"] >= RULE_FAILED_LOGINS).mean()), 2),
        "anomaly_cross_case_pct": round(100 * float((anom["case_access_pattern"] > 0).mean()), 2),
        "normal_flagged_by_rule_pct": round(100 * float(rule[df["true_label"] == NORMAL].mean()), 2),
        "anomaly_flagged_by_rule_pct": round(100 * float(rule[df["true_label"] == ANOMALY].mean()), 2),
    }


def write_csv(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False, encoding="utf-8", lineterminator="\n", float_format="%.2f")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the CMRS synthetic session dataset.")
    parser.add_argument("--seed", type=int, default=PRIMARY_SEED, help="random seed (default 42)")
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "output" / "synthetic_sessions.csv")
    args = parser.parse_args()

    df = generate(args.seed)
    write_csv(df, args.out)
    stats = summarize(df)
    print(f"dataset written to: {args.out}")
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
