from __future__ import annotations

import signal
from dataclasses import dataclass, field
from pathlib import Path

from .config import ScopeConfig, Target


class SafetyError(Exception):
    """Raised by SafetyGate when a safety rule is violated."""


@dataclass
class SafetyGate:
    scope: ScopeConfig
    kill_file: Path = Path("KILL")
    max_total_queries: int | None = None
    max_queries_per_target: int | None = None

    def __post_init__(self) -> None:
        self._signals_received = False
        self._queries_sent = 0
        self._queries_per_target: dict[str, int] = {}
        self._old_handlers: dict[int, object] = {}

    def check_authorisation(self) -> None:
        """Refuse to run if the authorisation block is missing or incomplete."""
        auth = self.scope.authorisation
        if not auth or not auth.is_complete():
            raise SafetyError(
                "authorisation block is missing or incomplete; refusing to run"
            )

    def enforce_max_20(self, targets: list[Target]) -> None:
        """Abort if more than 20 targets are requested."""
        if len(targets) > 20:
            raise SafetyError(
                f"refusing to scan {len(targets)} targets; maximum is 20"
            )

    def check_scope(self, ip: str) -> None:
        """Refuse any IP not listed in scope.yaml."""
        if self.scope.by_ip(ip) is None:
            raise SafetyError(
                f"IP {ip} is not in scope.yaml; refusing to probe"
            )

    def record_query(self, target_id: str | None = None) -> None:
        """Count one query toward the global and (optionally) per-target caps."""
        self._queries_sent += 1
        if target_id is not None:
            self._queries_per_target[target_id] = (
                self._queries_per_target.get(target_id, 0) + 1
            )

    def per_target_exceeded(self, target_id: str) -> bool:
        """True once target_id has used its configured query budget."""
        if self.max_queries_per_target is None:
            return False
        return (
            self._queries_per_target.get(target_id, 0)
            >= self.max_queries_per_target
        )

    def kill_switch(self) -> bool:
        """Return True when the run must stop cleanly.

        Triggered by: the ./KILL file existing, a SIGINT having been received,
        or max_total_queries being reached.
        """
        if self.kill_file.exists():
            return True
        if self._signals_received:
            return True
        if (
            self.max_total_queries is not None
            and self._queries_sent >= self.max_total_queries
        ):
            return True
        return False

    def install_signal_handlers(self) -> None:
        self._old_handlers[signal.SIGINT] = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._on_signal)

    def restore_signal_handlers(self) -> None:
        for sig, handler in self._old_handlers.items():
            signal.signal(sig, handler)
        self._old_handlers.clear()

    def _on_signal(self, signum, frame) -> None:
        self._signals_received = True
