"""APAT: Action Provenance Audit Trail.

SHA-256 chained append-only audit log. Each entry contains 15 fields
including hash of previous entry, making the log tamper-evident.
"""

from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class AuditEntry:
    entry_id: int
    timestamp: str
    scenario_id: str
    step: int
    action_type: str
    action_args: dict
    scp_passed: bool
    violations: list[str]         # violation IDs
    scp_feedback_summary: str
    rate_rho: float
    rate_tier: str
    rate_factors: dict
    executed: bool
    revision_round: int
    checker_decision: str         # "n/a" | "approved" | "rejected" | "auto"
    prev_hash: str
    entry_hash: str


class AuditTrail:
    """SHA-256 chained audit log."""

    def __init__(self, log_dir: str = "results/audit_logs", scenario_id: str = "default"):
        self.entries: list[AuditEntry] = []
        self.scenario_id = scenario_id
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._prev_hash = "0" * 64  # genesis

    def _hash_entry(self, entry_dict: dict) -> str:
        payload = json.dumps(entry_dict, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def record(self, step: int, action_type: str, action_args: dict,
               scp_passed: bool, violations: list[str],
               scp_feedback: str, rate_rho: float, rate_tier: str,
               rate_factors: dict, executed: bool, revision_round: int = 0,
               checker_decision: str = "n/a") -> str:
        entry_id = len(self.entries) + 1
        entry_data = dict(
            entry_id=entry_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            scenario_id=self.scenario_id,
            step=step,
            action_type=action_type,
            action_args=action_args,
            scp_passed=scp_passed,
            violations=violations,
            scp_feedback_summary=scp_feedback[:200],
            rate_rho=round(rate_rho, 4),
            rate_tier=rate_tier,
            rate_factors={k: round(v, 3) for k, v in rate_factors.items()},
            executed=executed,
            revision_round=revision_round,
            checker_decision=checker_decision,
            prev_hash=self._prev_hash,
        )
        entry_hash = self._hash_entry(entry_data)
        entry_data["entry_hash"] = entry_hash
        entry = AuditEntry(**entry_data)
        self.entries.append(entry)
        self._prev_hash = entry_hash
        return entry_hash

    def save(self, filename: str | None = None):
        if filename is None:
            filename = f"apat_{self.scenario_id}_{int(time.time())}.json"
        path = self.log_dir / filename
        data = [asdict(e) for e in self.entries]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return str(path)

    def verify_chain(self) -> bool:
        """Verify hash chain integrity (tamper-evidence)."""
        prev = "0" * 64
        for e in self.entries:
            # Recompute hash from the entry minus entry_hash
            entry_dict = asdict(e)
            stored_hash = entry_dict.pop("entry_hash")
            recomputed = self._hash_entry(entry_dict)
            if recomputed != stored_hash:
                return False
            if e.prev_hash != prev:
                return False
            prev = stored_hash
        return True
