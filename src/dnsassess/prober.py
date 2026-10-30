from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Optional

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from .config import RateConfig, ScopeConfig, Target
from .ratelimit import RateLimiter

_FLAG_NAMES = ("QR", "AA", "TC", "RD", "RA")
_FLAG_BITS = {
    "QR": dns.flags.QR,
    "AA": dns.flags.AA,
    "TC": dns.flags.TC,
    "RD": dns.flags.RD,
    "RA": dns.flags.RA,
}


@dataclass
class ProbeResult:
    """Result of a single DNS probe."""

    target_id: str
    probe_type: str  # "A" or "B"
    qname: str
    qtype: str
    flags: dict[str, bool]
    rcode: str
    answer: list[str]
    response_time_ms: float
    transport: str  # "udp", "tcp", or "none"
    error: Optional[str] = None
    nonce: Optional[str] = None
    via_forwarder: bool = False
    attempts: int = 1  # UDP attempts used (1 + retries on timeout)


class Prober:
    """Sends nonce-based recursion probes to authorised targets.

    Each probe is sent over UDP with up to ``udp_retries`` extra attempts on
    timeout. Retries reuse the same qname and nonce so the auth-zone log
    still correlates, wait on the rate limiter, and count toward the
    per-target and total query caps enforced by the CLI.
    """

    def __init__(
        self,
        scope: ScopeConfig,
        rate: RateConfig,
        limiter: RateLimiter,
        timeout_seconds: float | None = None,
        edns_payload: int | None = None,
        udp_retries: int | None = None,
    ) -> None:
        self.scope = scope
        self.rate = rate
        self.limiter = limiter
        self.timeout = (
            timeout_seconds if timeout_seconds is not None else rate.timeout_seconds
        )
        self.edns_payload = (
            edns_payload if edns_payload is not None else rate.edns_payload
        )
        self.udp_retries = (
            udp_retries if udp_retries is not None else rate.udp_retries
        )
        self._nonce_index: dict[str, int] = {}

    # -- nonce ---------------------------------------------------------
    def make_nonce(self, seed: str, target_id: str, index: int) -> str:
        """12-char lowercase hex, reproducible from (seed, target_id, index)."""
        digest = hashlib.sha256(
            f"{seed}:{target_id}:{index}".encode()
        ).hexdigest()
        return digest[:12]

    def next_nonce(self, seed: str, target_id: str) -> str:
        """Return the next nonce for ``target_id`` and advance its counter."""
        index = self._nonce_index.get(target_id, 0)
        self._nonce_index[target_id] = index + 1
        return self.make_nonce(seed, target_id, index)

    # -- low-level send ------------------------------------------------
    @staticmethod
    def _flags_dict(msg: dns.message.Message) -> dict[str, bool]:
        return {name: bool(msg.flags & bit) for name, bit in _FLAG_BITS.items()}

    def _send(
        self,
        target: Target,
        qname: str,
        rdtype: dns.rdatatype.RdataType,
        rd: bool,
        nonce: Optional[str] = None,
    ) -> ProbeResult:
        """Send one query: UDP with timeout retries, TCP fallback only on TC."""
        qname_text = str(qname)
        query = dns.message.make_query(qname_text, rdtype)
        query.use_edns(edns=0, ednsflags=0, payload=self.edns_payload)

        response: Optional[dns.message.Message] = None
        error: Optional[str] = None
        transport = "udp"
        attempts = 0
        max_attempts = 1 + max(0, self.udp_retries)

        for attempt in range(max_attempts):
            attempts = attempt + 1
            if attempt > 0:
                # Each retry is a real query: wait on the limiter and reset
                # the latency timer for the final attempt.
                self.limiter.wait(target.id)
            start = time.monotonic()
            try:
                response = dns.query.udp(
                    query, target.ip, port=53, timeout=self.timeout
                )
                error = None
                break
            except dns.exception.Timeout:
                error = "timeout"
            except OSError as exc:
                error = str(exc)
                break

        if response is None:
            return ProbeResult(
                target_id=target.id,
                probe_type=dns.rdatatype.to_text(rdtype),
                qname=qname_text,
                qtype=dns.rdatatype.to_text(rdtype),
                flags={},
                rcode="timeout" if error == "timeout" else "error",
                answer=[],
                response_time_ms=(time.monotonic() - start) * 1000,
                transport="udp",
                error=(
                    f"timeout after {attempts} attempt(s)"
                    if error == "timeout"
                    else error
                ),
                nonce=nonce,
                attempts=attempts,
            )

        if bool(response.flags & dns.flags.TC):
            self.limiter.wait(target.id)
            transport = "tcp"
            start = time.monotonic()  # exclude the limiter wait from latency
            try:
                response = dns.query.tcp(
                    query, target.ip, port=53, timeout=self.timeout
                )
            except (dns.exception.Timeout, OSError) as exc:
                # Never treat the truncated UDP reply's fields as a TCP
                # result when the TCP retry also fails.
                return ProbeResult(
                    target_id=target.id,
                    probe_type=dns.rdatatype.to_text(rdtype),
                    qname=qname_text,
                    qtype=dns.rdatatype.to_text(rdtype),
                    flags={},
                    rcode="error",
                    answer=[],
                    response_time_ms=(time.monotonic() - start) * 1000,
                    transport="tcp",
                    error=str(exc),
                    nonce=nonce,
                    attempts=attempts,
                )

        return ProbeResult(
            target_id=target.id,
            probe_type=dns.rdatatype.to_text(rdtype),
            qname=qname_text,
            qtype=dns.rdatatype.to_text(rdtype),
            flags=self._flags_dict(response),
            rcode=dns.rcode.to_text(response.rcode()),
            answer=[rr.to_text() for rr in response.answer],
            response_time_ms=(time.monotonic() - start) * 1000,
            transport=transport,
            nonce=nonce,
            attempts=attempts,
        )

    # -- public probes -------------------------------------------------
    def skipped(
        self,
        target: Target,
        probe_type: str,
        reason: str,
        nonce: Optional[str] = None,
    ) -> ProbeResult:
        """Build a no-send probe result with a documented skip reason."""
        return ProbeResult(
            target_id=target.id,
            probe_type=probe_type,
            qname="",
            qtype="A" if probe_type == "A" else "SOA",
            flags={},
            rcode="skipped",
            answer=[],
            response_time_ms=0.0,
            transport="none",
            error=reason,
            nonce=nonce,
            attempts=0,
        )

    def probe_A(self, target: Target, seed: str, nonce: str) -> ProbeResult:
        """Recursion probe: A query for <nonce>.test_zone, RD=1."""
        self.limiter.wait(target.id)
        qname = f"{nonce}.{self.scope.test_zone}"
        return self._send(target, qname, dns.rdatatype.A, rd=True, nonce=nonce)

    def probe_B(self, target: Target) -> ProbeResult:
        """Zone probe: SOA query for target's serves_zone, RD=0."""
        if not target.serves_zone:
            return self.skipped(
                target, "B", "no serves_zone configured"
            )
        self.limiter.wait(target.id)
        return self._send(target, target.serves_zone, dns.rdatatype.SOA, rd=False)
