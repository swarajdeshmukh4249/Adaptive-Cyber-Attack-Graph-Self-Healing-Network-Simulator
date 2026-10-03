"""Tamper-evident audit log (Section 7): SHA-256 hash chain with light proof-of-work."""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from typing import List, Optional

DIFFICULTY = 3  # leading hex zeros required in each block hash


class AuditChain:
    def __init__(self) -> None:
        self.blocks: List[dict] = []
        self._pristine: List[dict] = []
        self._append("GENESIS", {"message": "Audit ledger initialised"}, tick=0)

    @staticmethod
    def _hash(block: dict) -> str:
        body = {k: block[k] for k in ("index", "timestamp", "tick", "event", "data", "prev_hash", "nonce")}
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

    def _append(self, event: str, data: dict, tick: int) -> dict:
        block = {
            "index": len(self.blocks),
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tick": tick,
            "event": event,
            "data": data,
            "prev_hash": self.blocks[-1]["hash"] if self.blocks else "0" * 64,
            "nonce": 0,
        }
        target = "0" * DIFFICULTY
        while True:
            h = self._hash(block)
            if h.startswith(target):
                break
            block["nonce"] += 1
        block["hash"] = h
        self.blocks.append(block)
        self._pristine.append(copy.deepcopy(block))
        return block

    def add(self, event: str, data: dict, tick: int) -> dict:
        return self._append(event, data, tick)

    def verify(self) -> dict:
        """Recompute every hash and link; report the first broken block, if any."""
        for i, b in enumerate(self.blocks):
            if self._hash(b) != b["hash"] or not b["hash"].startswith("0" * DIFFICULTY):
                return {"valid": False, "broken_at": i, "reason": "hash mismatch (data altered)"}
            if i and b["prev_hash"] != self.blocks[i - 1]["hash"]:
                return {"valid": False, "broken_at": i, "reason": "broken link to previous block"}
        return {"valid": True, "broken_at": None, "reason": "all hashes and links verified"}

    def tamper(self, index: Optional[int] = None) -> dict:
        """Demo: an insider edits a past record without re-mining the chain."""
        if len(self.blocks) < 2:
            return {"ok": False}
        i = index if index is not None and 0 < index < len(self.blocks) else max(1, len(self.blocks) // 2)
        self.blocks[i]["data"] = dict(self.blocks[i]["data"], tampered=True, note="record silently edited")
        return {"ok": True, "index": i}

    def repair(self) -> None:
        """Restore from the replicated (peer) copy."""
        self.blocks = copy.deepcopy(self._pristine)

    def to_dict(self, last: int = 14) -> dict:
        return {
            "length": len(self.blocks),
            "difficulty": DIFFICULTY,
            "blocks": self.blocks[-last:],
            "verify": self.verify(),
        }
