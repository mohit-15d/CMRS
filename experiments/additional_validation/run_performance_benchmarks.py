"""CMRS Part B: Repeated performance & cryptographic timing benchmarks.

Protocol:
- 5 warm-up iterations + 30 measured repetitions per operation using time.perf_counter_ns().
- Reports mean, median, std (sample), P95, min, max in milliseconds (ms).
- Uses temporary synthetic byte payloads and an ephemeral AES-256 key.
- Calls actual CMRS security implementations:
    - app.security.encryption.{encrypt_evidence, decrypt_evidence, generate_example_key}
    - app.security.audit_ledger.{_canonical_payload, calculate_record_hash, GENESIS_HASH}
    - app.models.audit_log.AuditLog
- Clearly separates:
    A. Cryptographic microbenchmarks (SHA-256, AES-256-GCM encrypt, AES-256-GCM decrypt)
    B. In-memory end-to-end evidence processing (hash -> encrypt -> decrypt -> re-hash -> compare)
    C. In-memory chained-hash ledger benchmarks (1,000 synthetic records derived from seed-42 CSV)
    D. Database-backed measurements (explicitly NOT executed; PostgreSQL I/O excluded)
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter_ns

import cryptography
import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

# Provide ephemeral non-production settings before importing app modules
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
import secrets  # noqa: E402

os.environ.setdefault("JWT_SECRET", "benchmark_ephemeral_jwt_secret_not_for_prod")
os.environ["ENCRYPTION_KEY"] = secrets.token_hex(32)

from app.models.audit_log import AuditLog  # noqa: E402
from app.security.audit_ledger import (  # noqa: E402
    GENESIS_HASH,
    _canonical_payload,
    calculate_record_hash,
)
from app.security.encryption import decrypt_evidence, encrypt_evidence  # noqa: E402

WARMUP_ITERS = 5
MEASURED_REPS = 30
PAYLOAD_SIZES = {
    "1 KB": 1024,
    "1 MB": 1024 * 1024,
    "10 MB": 10 * 1024 * 1024,
    "25 MB": 25 * 1024 * 1024,
}


def get_system_info() -> dict:
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    mem = MEMORYSTATUSEX()
    mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem))
    return {
        "os": platform.platform(),
        "cpu": platform.processor(),
        "logical_cores": os.cpu_count(),
        "ram_total_gb": round(mem.ullTotalPhys / (1024**3), 2),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "numpy": np.__version__,
        "pandas": pd.__version__,
    }


def bench_stats(fn) -> dict:
    for _ in range(WARMUP_ITERS):
        fn()
    samples_ms = []
    for _ in range(MEASURED_REPS):
        t0 = perf_counter_ns()
        fn()
        t1 = perf_counter_ns()
        samples_ms.append((t1 - t0) / 1_000_000.0)
    arr = np.asarray(samples_ms, dtype=float)
    return {
        "warmup_iterations": WARMUP_ITERS,
        "measured_repetitions": MEASURED_REPS,
        "unit": "ms",
        "mean_ms": round(float(np.mean(arr)), 4),
        "median_ms": round(float(np.median(arr)), 4),
        "std_ms": round(float(np.std(arr, ddof=1)), 4),
        "p95_ms": round(float(np.percentile(arr, 95)), 4),
        "min_ms": round(float(np.min(arr)), 4),
        "max_ms": round(float(np.max(arr)), 4),
    }


def build_synthetic_ledger_records(csv_path: Path) -> list[AuditLog]:
    """Build 1,000 in-memory AuditLog records derived from synthetic_sessions.csv."""
    df = pd.read_csv(csv_path)
    records: list[AuditLog] = []
    prev_hash = GENESIS_HASH
    base_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    for idx, row in df.iterrows():
        rec_id = uuid.uuid5(uuid.NAMESPACE_DNS, f"cmrs-bench-{row['session_id']}")
        actor_id = uuid.uuid5(uuid.NAMESPACE_DNS, f"cmrs-user-{row['user_id']}")
        created_at = base_time
        details = {
            "session_id": str(row["session_id"]),
            "evidence_access_volume": float(row["evidence_access_volume"]),
            "failed_login_count": int(row["failed_login_count"]),
        }
        curr_hash = hashlib.sha256(
            _canonical_payload(
                record_id=rec_id,
                created_at=created_at,
                actor_id=actor_id,
                action="EVIDENCE_ACCESSED",
                resource_type="evidence",
                resource_id=str(row["session_id"]),
                result="success",
                details=details,
                previous_hash=prev_hash,
            )
        ).hexdigest()
        records.append(
            AuditLog(
                id=rec_id,
                actor_id=actor_id,
                action="EVIDENCE_ACCESSED",
                resource_type="evidence",
                resource_id=str(row["session_id"]),
                result="success",
                details=details,
                created_at=created_at,
                updated_at=created_at,
                previous_hash=prev_hash,
                current_hash=curr_hash,
            )
        )
        prev_hash = curr_hash
    return records


def main() -> None:
    out_dir = Path(__file__).resolve().parent
    csv_path = REPO_ROOT / "experiments" / "output" / "synthetic_sessions.csv"
    rng = np.random.default_rng(42)

    crypto_micro = {}
    in_memory_e2e = {}

    for label, size_bytes in PAYLOAD_SIZES.items():
        payload = rng.bytes(size_bytes)
        encrypted_sample = encrypt_evidence(payload)

        def op_sha256(buf=payload):
            return hashlib.sha256(buf).hexdigest()

        def op_encrypt(buf=payload):
            return encrypt_evidence(buf)

        def op_decrypt(ct=encrypted_sample):
            return decrypt_evidence(ct)

        def op_e2e(buf=payload):
            h1 = hashlib.sha256(buf).hexdigest()
            ct = encrypt_evidence(buf)
            pt = decrypt_evidence(ct)
            h2 = hashlib.sha256(pt).hexdigest()
            assert h1 == h2
            return h2

        crypto_micro[label] = {
            "payload_bytes": size_bytes,
            "sha256_hash": bench_stats(op_sha256),
            "aes_256_gcm_encrypt": bench_stats(op_encrypt),
            "aes_256_gcm_decrypt": bench_stats(op_decrypt),
        }
        in_memory_e2e[label] = {
            "payload_bytes": size_bytes,
            "combined_hash_encrypt_decrypt_verify": bench_stats(op_e2e),
        }

    # C. In-memory chained-hash ledger benchmarks (1,000 records from seed-42 CSV)
    ledger_records = build_synthetic_ledger_records(csv_path)
    sample_rec = ledger_records[0]

    def op_ledger_single_append_crypto():
        return hashlib.sha256(
            _canonical_payload(
                record_id=sample_rec.id,
                created_at=sample_rec.created_at,
                actor_id=sample_rec.actor_id,
                action=sample_rec.action,
                resource_type=sample_rec.resource_type,
                resource_id=sample_rec.resource_id,
                result=sample_rec.result,
                details=sample_rec.details,
                previous_hash=sample_rec.previous_hash,
            )
        ).hexdigest()

    def op_ledger_full_1000_chain_verify():
        expected_prev = GENESIS_HASH
        for rec in ledger_records:
            assert rec.previous_hash == expected_prev
            assert calculate_record_hash(rec) == rec.current_hash
            expected_prev = rec.current_hash
        return True

    ledger_bench = {
        "record_count": len(ledger_records),
        "single_record_hash_calculation": bench_stats(op_ledger_single_append_crypto),
        "full_1000_record_chain_verification": bench_stats(op_ledger_full_1000_chain_verify),
    }

    report = {
        "experiment": "CMRS Part B: Repeated Cryptographic & Ledger Performance Benchmarks",
        "system_info": get_system_info(),
        "protocol": {
            "timer": "time.perf_counter_ns()",
            "warmup_iterations": WARMUP_ITERS,
            "measured_repetitions": MEASURED_REPS,
            "ephemeral_key_used": True,
            "real_evidence_used": False,
        },
        "A_cryptographic_microbenchmarks": crypto_micro,
        "B_in_memory_end_to_end_processing": in_memory_e2e,
        "C_in_memory_chained_hash_ledger": ledger_bench,
        "D_database_backed_measurements": {
            "executed": False,
            "reason": (
                "No separate controlled PostgreSQL benchmark database is available in the "
                "sandboxed environment; development database was not accessed or modified. "
                "In-memory benchmarks (A-C) measure pure CPU/cryptographic overhead only and "
                "do NOT represent PostgreSQL transaction, pg_advisory_xact_lock, or disk I/O latency."
            ),
        },
    }

    (out_dir / "benchmark_results.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )

    print("=" * 78)
    print("CMRS Performance Benchmarks (5 warm-up, 30 measured reps, time.perf_counter_ns)")
    print("=" * 78)
    for label in PAYLOAD_SIZES:
        s = crypto_micro[label]["sha256_hash"]
        e = crypto_micro[label]["aes_256_gcm_encrypt"]
        d = crypto_micro[label]["aes_256_gcm_decrypt"]
        c = in_memory_e2e[label]["combined_hash_encrypt_decrypt_verify"]
        print(f"\nPayload: {label}")
        print(f"  SHA-256  : mean={s['mean_ms']:.4f}ms median={s['median_ms']:.4f}ms p95={s['p95_ms']:.4f}ms")
        print(f"  AES-Enc  : mean={e['mean_ms']:.4f}ms median={e['median_ms']:.4f}ms p95={e['p95_ms']:.4f}ms")
        print(f"  AES-Dec  : mean={d['mean_ms']:.4f}ms median={d['median_ms']:.4f}ms p95={d['p95_ms']:.4f}ms")
        print(f"  E2E Mem  : mean={c['mean_ms']:.4f}ms median={c['median_ms']:.4f}ms p95={c['p95_ms']:.4f}ms")

    la = ledger_bench["single_record_hash_calculation"]
    lv = ledger_bench["full_1000_record_chain_verification"]
    print("\nChained-Hash Ledger (in-memory, 1,000 records):")
    print(f"  Single record hash : mean={la['mean_ms']:.4f}ms median={la['median_ms']:.4f}ms p95={la['p95_ms']:.4f}ms")
    print(f"  1,000-rec verify   : mean={lv['mean_ms']:.4f}ms median={lv['median_ms']:.4f}ms p95={lv['p95_ms']:.4f}ms")


if __name__ == "__main__":
    main()
