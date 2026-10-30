"""Canary attribution self-check, run before every scan.

The scan's core proof is canary evidence: a nonce appearing in the team-owned
test-zone server's query log. This module validates that whole pipeline before
any target is probed, with one clearly-labelled control query:

1. The probe client sends a ``selfcheck-*`` control name directly to the
   canary server (our own ``test_zone_ip``, never a target).
2. The canary log is polled for that control name.
3. Attribution is asserted: the canary must have recorded the control query
   from the probe client's actual source IP.

If any step fails, the scan refuses to run — name/nonce correlation is not
trustworthy when the canary's logging or the log reader is broken. The control
query counts toward the run's global query budget.
"""
from __future__ import annotations

import hashlib
import socket
import time
from dataclasses import asdict, dataclass
from typing import Callable, Optional

import dns.message
import dns.rcode

from .ratelimit import RateLimiter

# Label prefix distinguishes control names from probe nonces (12-hex); the
# authzone server logs each query's first label, so this is queryable.
CONTROL_PREFIX = "selfcheck"


@dataclass
class SelfCheckResult:
    """Outcome of the canary attribution self-check."""

    status: str  # "verified" | "timeout" | "src_ip_mismatch" | "error"
    control_qname: str
    client_ip: Optional[str]
    observed_src_ip: Optional[str]
    rcode: Optional[str] = None
    response_time_ms: float = 0.0
    attempts: int = 1
    log_poll_seconds: float = 0.0
    error: Optional[str] = None

    def as_dict(self) -> dict:
        """Plain dict for run metadata and evidence records."""
        return asdict(self)


def _predict_client_ip(zone_ip: str) -> Optional[str]:
    """Return the source IP a UDP packet to zone_ip would leave from."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((zone_ip, 53))
            return sock.getsockname()[0]
    except OSError:
        return None


def run_canary_selfcheck(
    zone_ip: str,
    zone: str,
    *,
    seed: str = "",
    timeout: float = 3.0,
    log_wait: float = 6.0,
    limiter: Optional[RateLimiter] = None,
    send_query: Optional[Callable[..., dns.message.Message]] = None,
    read_log: Optional[Callable[[], dict[str, list[dict]]]] = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> SelfCheckResult:
    """Send one control query to the canary server and verify the log.

    ``send_query`` and ``read_log`` are injectable so tests exercise the flow
    without Docker; production callers pass nothing and use dnspython plus an
    ``EvidenceStore.read_auth_log`` closure.
    """
    zone_name = zone.rstrip(".")
    label = CONTROL_PREFIX + "-" + hashlib.sha256(
        f"{seed}:{zone_name}:canary-control".encode()
    ).hexdigest()[:8]
    qname = f"{label}.{zone_name}."

    result = SelfCheckResult(
        status="error",
        control_qname=qname,
        client_ip=_predict_client_ip(zone_ip),
        observed_src_ip=None,
    )
    if read_log is None:
        result.error = "no canary-log reader wired up"
        return result

    send = send_query or (
        lambda query, ip, port=53, timeout=None: dns.query.udp(
            query, ip, port=port, timeout=timeout
        )
    )

    query = dns.message.make_query(qname, "A")
    if limiter is not None:
        limiter.wait("canary-selfcheck")
    start = clock()
    try:
        response = send(query, zone_ip, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - report any send failure verbatim
        result.error = f"{type(exc).__name__}: {exc}"
        return result
    result.response_time_ms = round((clock() - start) * 1000, 3)
    result.rcode = dns.rcode.to_text(response.rcode())
    if response.rcode() != dns.rcode.NOERROR:
        result.error = f"canary answered {result.rcode} for the control query"
        return result

    # Poll the canary log for the control-name entry.
    poll_start = clock()
    deadline = poll_start + max(0.0, log_wait)
    entries = read_log().get(label, [])
    while not entries and clock() < deadline:
        sleep(min(0.5, max(0.0, deadline - clock())))
        entries = read_log().get(label, [])
    result.log_poll_seconds = round(clock() - poll_start, 3)

    if not entries:
        result.status = "timeout"
        result.error = (
            "control entry not found in the canary log within "
            f"{log_wait:g}s; canary logging is not trustworthy"
        )
        return result

    result.observed_src_ip = entries[0].get("src_ip")
    if result.client_ip is None:
        result.error = "could not determine the probe client's source IP"
        return result
    if result.observed_src_ip != result.client_ip:
        result.status = "src_ip_mismatch"
        result.error = (
            f"canary attributed the control query to {result.observed_src_ip!r}, "
            f"expected the probe client's {result.client_ip!r}"
        )
        return result
    result.status = "verified"
    return result
