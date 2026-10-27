"""EvidenceStore: append-only JSONL evidence log + auth-zone log reader.

Appends one JSON line per probe to ``out/evidence.jsonl``. Also reads the
test-zone server's query log (``queries.jsonl``) and indexes it by nonce so
the classifier can check whether a nonce was seen -- the proof of recursion.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .prober import ProbeResult


class EvidenceStore:
    """Append-only JSONL evidence store with an auth-zone log index."""

    def __init__(self, path: str | Path = "out/evidence.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, result: ProbeResult) -> None:
        """Append one JSON line for a probe result."""
        line = {
            "target_id": result.target_id,
            "probe_type": result.probe_type,
            "qname": result.qname,
            "qtype": result.qtype,
            "flags": result.flags,
            "rcode": result.rcode,
            "answer": result.answer,
            "response_time_ms": result.response_time_ms,
            "transport": result.transport,
            "error": result.error,
            "nonce": result.nonce,
            "via_forwarder": result.via_forwarder,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")

    def read_auth_log(self, log_path: str | Path) -> dict[str, list[dict]]:
        """Read the test-zone queries.jsonl and index entries by nonce."""
        index: dict[str, list[dict]] = {}
        path = Path(log_path)
        if not path.exists():
            return index
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                nonce = entry.get("nonce")
                if nonce:
                    index.setdefault(nonce, []).append(entry)
        return index

    def find_nonce(self, log_path: str | Path, nonce: str) -> Optional[dict]:
        """Return the first auth-log entry for ``nonce``, or None."""
        index = self.read_auth_log(log_path)
        entries = index.get(nonce, [])
        return entries[0] if entries else None
