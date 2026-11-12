# CMRS Additional Research Validation

Isolated validation folder addressing reviewer requests without modifying **any** original experiment files or the original seed-42 dataset (`experiments/output/synthetic_sessions.csv`, SHA-256 `BAB4140BF159919243E2E50833F7F674F3B3F8F721A7029D2122230D7EB2BAC0`):

1. **Part A — Stratified 80/20 Held-Out Split Validation (`run_heldout_split_validation.py`):**
   - Splits the 1,000 sessions (`random_state=42`) into 800 training (`720` normal, `80` anomalous) and 200 held-out test (`180` normal, `20` anomalous).
   - Fits preprocessing (`np.log1p` + `StandardScaler`) and all unsupervised detectors **only** on the `720` normal training records.
   - Evaluates Isolation Forest (`contamination=0.10` and `contamination="auto"`), One-Class SVM (`nu=0.10`), LOF (`novelty=True`, `contamination=0.10`), and the fixed Rule-based baseline on the 200 held-out test samples.
2. **Part B — Repeated Performance Benchmarks (`run_performance_benchmarks.py`):**
   - `5` warm-up iterations + `30` measured repetitions using `time.perf_counter_ns()`.
   - Measures SHA-256 hashing, AES-256-GCM encryption/decryption, combined in-memory evidence processing (1 KB, 1 MB, 10 MB, 25 MB), and in-memory chained-hash ledger append/verification (1,000 records derived from `synthetic_sessions.csv`).
   - Uses temporary synthetic byte payloads and an ephemeral encryption key. Database-backed PostgreSQL measurements are explicitly excluded.
3. **Part C — Standalone Ledger Integrity & HMAC Checkpoint Verification (`run_ledger_tamper_validation.py`):**
   - Newly implemented standalone verification script (not the lost original paper script) using CMRS's canonical SHA-256 ledger helpers in-memory.
   - Tests 20 valid baseline chains, 200 tampered chains across 5 attack modes (`details_modified`, `action_modified`, `timestamp_modified`, `previous_hash_broken`, `record_deleted`), and ephemeral-key HMAC-SHA256 checkpoint verification (`ledger_tamper_results.json`).
   - *Note: Production `backend/app/security/audit_ledger.py` uses unkeyed SHA-256 hash chaining without HMAC checkpoints.*

## Reproduction

```bash
python experiments/additional_validation/run_heldout_split_validation.py
python experiments/additional_validation/run_performance_benchmarks.py
python experiments/additional_validation/run_ledger_tamper_validation.py
```

## Limitations
- Both 80/20 splits originate from the synthetic seed-42 dataset, not real-world forensic logs.
- The 200-row test split has 20 anomalous samples (each sample shifts recall by 5 percentage points).
- In-memory benchmarks measure pure CPU/cryptographic overhead and do not include PostgreSQL transaction, `pg_advisory_xact_lock`, or disk I/O latency.
- `run_ledger_tamper_validation.py` is a newly written standalone verification script rather than the lost original draft file.
