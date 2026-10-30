from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable, Optional

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
            "attempts": result.attempts,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")

    def append_raw(self, entry: dict) -> None:
        """Append an already-structured record (e.g. the canary self-check).

        Unlike :meth:`append`, this is not tied to a per-target probe; the
        classifier ignores records whose ``target_id`` is not a scan target.
        """
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

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

    def wait_for_nonces(
        self,
        log_path: str | Path,
        expected: set[str],
        timeout_seconds: float,
        interval: float = 0.5,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> dict[str, list[dict]]:
        """Poll the auth-zone log until every expected nonce appears.

        Returns the indexed log (whether or not all nonces arrived) once all
        are present or ``timeout_seconds`` elapses. Prevents the fixed-sleep
        race where slow recursion leaves a nonce unseen at classify time.
        """
        deadline = clock() + max(0.0, timeout_seconds)
        index = self.read_auth_log(log_path)
        missing = expected - set(index)
        while missing and clock() < deadline:
            sleep(min(interval, max(0.0, deadline - clock())))
            index = self.read_auth_log(log_path)
            missing = expected - set(index)
        return index

    def find_nonce(self, log_path: str | Path, nonce: str) -> Optional[dict]:
        """Return the first auth-log entry for ``nonce``, or None."""
        index = self.read_auth_log(log_path)
        entries = index.get(nonce, [])
        return entries[0] if entries else None
