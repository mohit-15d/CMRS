"""CMRS Standalone Ledger Integrity & HMAC Checkpoint Verification.

Newly implemented standalone verification script (not the lost original paper
script). Uses CMRS's actual canonical SHA-256 ledger helpers in-memory without
touching PostgreSQL or any original experiment files.

Tests:
1. 200 independent tampered chains (40 each across 5 attack modes):
   - details_modified: alters a field inside `details`
   - action_modified: alters `action` / `result`
   - timestamp_modified: alters `created_at`
   - previous_hash_broken: alters `previous_hash` link
   - record_deleted: drops an interior record from the chain
2. Prototype HMAC-SHA256 checkpoint verification (using an ephemeral test key):
   - Valid checkpoint verification
   - Tampered checkpoint tag detection
   - Chain truncation detection against checkpointed tip hash
   (Note: production `backend/app/security/audit_ledger.py` uses unkeyed
   SHA-256 chaining without HMAC checkpoints.)

Run:
    python experiments/additional_validation/run_ledger_tamper_validation.py
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import secrets
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

os.environ.setdefault("JWT_SECRET", "standalone_ledger_test_ephemeral_jwt_secret")

from app.models.audit_log import AuditLog  # noqa: E402
from app.security.audit_ledger import (  # noqa: E402
    GENESIS_HASH,
    _canonical_payload,
    calculate_record_hash,
)

NUM_CHAINS_PER_MODE = 40
CHAIN_LENGTH = 20
TAMPER_MODES = (
    "details_modified",
    "action_modified",
    "timestamp_modified",
    "previous_hash_broken",
    "record_deleted",
)


def build_valid_chain(length: int, seed_tag: str) -> list[AuditLog]:
    records: list[AuditLog] = []
    prev_hash = GENESIS_HASH
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    for i in range(length):
        rec_id = uuid.uuid5(uuid.NAMESPACE_DNS, f"{seed_tag}-{i}")
        actor_id = uuid.uuid5(uuid.NAMESPACE_DNS, f"actor-{i % 5}")
        created_at = base_time + timedelta(seconds=i * 15)
        details = {"seq": i, "seed_tag": seed_tag, "evidence": f"EV-{i:03d}"}
        curr_hash = hashlib.sha256(
            _canonical_payload(
                record_id=rec_id,
                created_at=created_at,
                actor_id=actor_id,
                action="EVIDENCE_ACCESSED",
                resource_type="evidence",
                resource_id=f"EV-{i:03d}",
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
                resource_id=f"EV-{i:03d}",
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


def verify_in_memory_chain(records: list[AuditLog]) -> tuple[bool, str | None]:
    expected_prev = GENESIS_HASH
    for rec in records:
        if rec.previous_hash != expected_prev:
            return False, f"Broken link at record {rec.id}"
        if calculate_record_hash(rec) != rec.current_hash:
            return False, f"Invalid hash at record {rec.id}"
        expected_prev = rec.current_hash
    return True, None


def tamper_chain(records: list[AuditLog], mode: str, idx: int) -> list[AuditLog]:
    mutated = copy.deepcopy(records)
    target_pos = (idx % (len(mutated) - 2)) + 1  # interior record
    rec = mutated[target_pos]
    if mode == "details_modified":
        rec.details = {**(rec.details or {}), "tampered": True}
    elif mode == "action_modified":
        rec.action = "CUSTODY_TRANSFER"
    elif mode == "timestamp_modified":
        rec.created_at = rec.created_at + timedelta(seconds=1)
    elif mode == "previous_hash_broken":
        rec.previous_hash = "0" * 64
    elif mode == "record_deleted":
        mutated.pop(target_pos)
    else:
        raise ValueError(f"Unknown tamper mode: {mode}")
    return mutated


def sign_hmac_checkpoint(hmac_key: bytes, tip_hash: str, length: int) -> str:
    msg = f"{length}:{tip_hash}".encode("utf-8")
    return hmac.new(hmac_key, msg, hashlib.sha256).hexdigest()


def verify_hmac_checkpoint(
    hmac_key: bytes, records: list[AuditLog], expected_len: int, signature: str
) -> bool:
    if len(records) != expected_len or not records:
        return False
    expected_sig = sign_hmac_checkpoint(hmac_key, records[-1].current_hash, len(records))
    return hmac.compare_digest(expected_sig, signature)


def main() -> None:
    out_dir = Path(__file__).resolve().parent

    # 1. Valid chain baseline
    valid_passed = 0
    for i in range(20):
        chain = build_valid_chain(CHAIN_LENGTH, f"valid-{i}")
        ok, _ = verify_in_memory_chain(chain)
        if ok:
            valid_passed += 1
    assert valid_passed == 20

    # 2. 200 tampered chains (40 per mode x 5 modes)
    mode_results = {}
    total_tampered = 0
    total_detected = 0
    for mode in TAMPER_MODES:
        detected = 0
        for i in range(NUM_CHAINS_PER_MODE):
            base = build_valid_chain(CHAIN_LENGTH, f"{mode}-{i}")
            bad = tamper_chain(base, mode, i)
            ok, _ = verify_in_memory_chain(bad)
            if not ok:
                detected += 1
        mode_results[mode] = {
            "tested": NUM_CHAINS_PER_MODE,
            "detected": detected,
            "detection_rate": round(detected / NUM_CHAINS_PER_MODE, 6),
        }
        total_tampered += NUM_CHAINS_PER_MODE
        total_detected += detected

    assert total_tampered == 200
    assert total_detected == 200

    # 3. Ephemeral HMAC-SHA256 checkpoint tests
    ephemeral_hmac_key = secrets.token_bytes(32)
    ckpt_chain = build_valid_chain(CHAIN_LENGTH, "hmac-ckpt")
    ckpt_sig = sign_hmac_checkpoint(
        ephemeral_hmac_key, ckpt_chain[-1].current_hash, len(ckpt_chain)
    )
    hmac_valid_ok = verify_hmac_checkpoint(
        ephemeral_hmac_key, ckpt_chain, len(ckpt_chain), ckpt_sig
    )
    bad_sig = ("f" if ckpt_sig[0] != "f" else "0") + ckpt_sig[1:]
    hmac_forged_rejected = not verify_hmac_checkpoint(
        ephemeral_hmac_key, ckpt_chain, len(ckpt_chain), bad_sig
    )
    truncated_chain = ckpt_chain[:-1]
    hmac_truncation_rejected = not verify_hmac_checkpoint(
        ephemeral_hmac_key, truncated_chain, len(ckpt_chain), ckpt_sig
    )
    assert hmac_valid_ok and hmac_forged_rejected and hmac_truncation_rejected

    results = {
        "experiment": "CMRS Standalone Chained-Hash Ledger Tamper & HMAC Checkpoint Verification",
        "notice": (
            "Newly implemented standalone verification script using CMRS canonical SHA-256 "
            "ledger helpers in-memory. Production backend/app/security/audit_ledger.py uses "
            "unkeyed SHA-256 chaining without HMAC checkpoints."
        ),
        "valid_baseline": {"tested": 20, "passed": valid_passed},
        "tampered_chain_tests": {
            "total_tested": total_tampered,
            "total_detected": total_detected,
            "overall_detection_rate": round(total_detected / total_tampered, 6),
            "by_mode": mode_results,
        },
        "hmac_checkpoint_prototype_tests": {
            "ephemeral_key_used": True,
            "valid_checkpoint_accepted": hmac_valid_ok,
            "forged_signature_rejected": hmac_forged_rejected,
            "truncated_chain_rejected": hmac_truncation_rejected,
        },
    }

    (out_dir / "ledger_tamper_results.json").write_text(
        json.dumps(results, indent=2) + "\n", encoding="utf-8"
    )

    print("=" * 78)
    print("CMRS Standalone Ledger Integrity & HMAC Checkpoint Verification")
    print("=" * 78)
    print(f"Valid baseline chains   : {valid_passed}/20 passed")
    print(f"Tampered chains detected: {total_detected}/{total_tampered} (100.0%)")
    for mode, stats in mode_results.items():
        print(f"  - {mode:<22}: {stats['detected']}/{stats['tested']} detected")
    print("HMAC checkpoint tests   : valid=True, forged_rejected=True, truncation_rejected=True")


if __name__ == "__main__":
    main()
