"""Deterministic synthetic backup/failover test; does not validate production DR."""
from __future__ import annotations

import hashlib
import json
import time


class RecoveryError(ValueError):
    pass


def checksum(events):
    return hashlib.sha256(json.dumps(events, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def recover(events, checkpoint_count=9, rto_target_seconds=60.0, rpo_target_seconds=2.0):
    if not events or checkpoint_count < 1 or checkpoint_count > len(events):
        raise RecoveryError("Invalid checkpoint")
    expected_seqs = list(range(1, len(events) + 1))
    if [e["sequence"] for e in events] != expected_seqs:
        raise RecoveryError("Event journal invalid")
    checkpoint = [dict(e) for e in events[:checkpoint_count]]
    backup_hash = checksum(checkpoint)
    failure_time = events[-1]["logical_second"]
    started = time.perf_counter()
    restored = [dict(e) for e in checkpoint]
    if checksum(restored) != backup_hash:
        raise RecoveryError("Backup checksum mismatch")
    if [e["sequence"] for e in restored] != list(range(1, checkpoint_count + 1)):
        raise RecoveryError("Order, continuity or integrity verification failed")
    recovered_in = time.perf_counter() - started
    lost = len(events) - len(restored)
    recovery_point_seconds = failure_time - restored[-1]["logical_second"]
    return {
        "mode": "synthetic_in_memory_restore", "rto_target_seconds": rto_target_seconds,
        "measured_recovery_seconds": round(recovered_in, 6), "rto_target_met": recovered_in <= rto_target_seconds,
        "rpo_target_seconds": rpo_target_seconds, "observed_rpo_seconds": recovery_point_seconds,
        "rpo_target_met": recovery_point_seconds <= rpo_target_seconds,
        "lost_event_count": lost, "retained_event_count": len(restored),
        "recovered_checkpoint_sha256": checksum(restored), "backup_sha256": backup_hash,
        "integrity_verified": checksum(restored) == backup_hash,
        "note": "Logical seconds/event ledger, in-memory failover; no AWS services or production RTO/RPO tested.",
    }


def demo():
    events = [{"sequence": n, "logical_second": n - 1, "finding": "synthetic"} for n in range(1, 11)]
    return recover(events, checkpoint_count=9)


if __name__ == "__main__":
    print(json.dumps(demo(), sort_keys=True, indent=2))
