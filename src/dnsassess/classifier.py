"""Classifier: label each target as Recursive, Authoritative-only, Refused,
or Inconclusive using the nonce-based recursion proof (build prompt §6).

Rules are applied in order; the first matching rule decides the label. The
key idea is to *prove* recursion via the nonce appearing in our own
auth-zone log, not to infer it from flags like RA.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .prober import ProbeResult


@dataclass
class Classification:
    """Result of classifying a single target."""

    label: str
    reason: str
    evidence_ids: list[str] = field(default_factory=list)
    via_forwarder: bool = False
    nonce_seen: bool = False
    probe_a: Optional[ProbeResult] = None
    probe_b: Optional[ProbeResult] = None
    raw: dict = field(default_factory=dict)


def _has_response(result: ProbeResult) -> bool:
    """True if the probe got an actual DNS reply (not timeout/error/skip)."""
    return result.transport in ("udp", "tcp") and result.error is None


def _is_refused(result: ProbeResult) -> bool:
    """True if the probe got a REFUSED reply."""
    return _has_response(result) and result.rcode == "REFUSED"


def _no_recursion_evidence(result: ProbeResult, nonce_seen: bool) -> bool:
    """True if Probe A shows no evidence of recursion.

    Covers: REFUSED, no response (timeout/error/skipped), or NXDOMAIN
    without nonce evidence.
    """
    if result.rcode == "REFUSED":
        return True
    if not _has_response(result):
        return True
    if result.rcode == "NXDOMAIN" and not nonce_seen:
        return True
    return False


def classify(
    probe_a: ProbeResult,
    probe_b: ProbeResult,
    auth_entries: list[dict],
    target_ip: str,
) -> Classification:
    """Apply the 7 classification rules in order.

    Args:
        probe_a: Recursion probe result (A query, RD=1).
        probe_b: Zone probe result (SOA query, RD=0) or skipped.
        auth_entries: Auth-zone log entries matching probe_a's nonce.
        target_ip: The target's IP, used to detect forwarders.

    Returns:
        A Classification with label, reason, and supporting evidence.
    """
    evidence_ids: list[str] = []
    if probe_a.nonce:
        evidence_ids.append(f"{probe_a.target_id}:{probe_a.nonce}:A")
    if probe_b.nonce:
        evidence_ids.append(f"{probe_b.target_id}:{probe_b.nonce}:B")

    raw = {
        "a": _summary(probe_a),
        "b": _summary(probe_b),
    }

    # Rule 1: No response after retries -> Inconclusive (timeout)
    if not _has_response(probe_a):
        return Classification(
            label="Inconclusive",
            reason="timeout",
            evidence_ids=evidence_ids,
            probe_a=probe_a,
            probe_b=probe_b,
            nonce_seen=False,
            raw=raw,
        )

    # Rule 2: SERVFAIL/bad reply -> Inconclusive (servfail/bad_reply)
    if probe_a.rcode == "SERVFAIL" or probe_a.rcode not in (
        "NOERROR",
        "NXDOMAIN",
        "REFUSED",
    ):
        return Classification(
            label="Inconclusive",
            reason="servfail" if probe_a.rcode == "SERVFAIL" else "bad_reply",
            evidence_ids=evidence_ids,
            probe_a=probe_a,
            probe_b=probe_b,
            nonce_seen=False,
            raw=raw,
        )

    # Check the auth log for probe_a's nonce (proof of recursion).
    nonce_seen = False
    via_forwarder = False
    if probe_a.nonce:
        for entry in auth_entries:
            if entry.get("nonce") == probe_a.nonce:
                nonce_seen = True
                if entry.get("src_ip") != target_ip:
                    via_forwarder = True
                break

    # Rule 3: NOERROR + expected A + nonce in auth log -> Recursive.
    if probe_a.rcode == "NOERROR" and probe_a.answer and nonce_seen:
        return Classification(
            label="Recursive",
            reason="nonce_seen_in_auth_log",
            evidence_ids=evidence_ids,
            via_forwarder=via_forwarder,
            probe_a=probe_a,
            probe_b=probe_b,
            nonce_seen=True,
            raw=raw,
        )

    # Rule 4: Answer but no nonce in log -> Inconclusive
    # (answer_without_upstream_evidence).
    if probe_a.rcode == "NOERROR" and probe_a.answer and not nonce_seen:
        return Classification(
            label="Inconclusive",
            reason="answer_without_upstream_evidence",
            evidence_ids=evidence_ids,
            probe_a=probe_a,
            probe_b=probe_b,
            nonce_seen=False,
            raw=raw,
        )

    # Rule 5: Probe A REFUSED and Probe B REFUSED (or no answer) -> Refused.
    probe_b_no_answer = not _has_response(probe_b) or _is_refused(probe_b)
    if _is_refused(probe_a) and probe_b_no_answer:
        return Classification(
            label="Refused",
            reason="both_probes_refused",
            evidence_ids=evidence_ids,
            probe_a=probe_a,
            probe_b=probe_b,
            nonce_seen=False,
            raw=raw,
        )

    # Rule 6: Probe B AA=1 and Probe A refused/no answer/NXDOMAIN without
    # nonce -> Authoritative-only.
    probe_b_aa = _has_response(probe_b) and probe_b.flags.get("AA", False)
    if probe_b_aa and _no_recursion_evidence(probe_a, nonce_seen):
        return Classification(
            label="Authoritative-only",
            reason="zone_answer_without_recursion",
            evidence_ids=evidence_ids,
            probe_a=probe_a,
            probe_b=probe_b,
            nonce_seen=nonce_seen,
            raw=raw,
        )

    # Rule 7: Else -> Inconclusive (conflicting_evidence).
    return Classification(
        label="Inconclusive",
        reason="conflicting_evidence",
        evidence_ids=evidence_ids,
        probe_a=probe_a,
        probe_b=probe_b,
        nonce_seen=nonce_seen,
        raw=raw,
    )


def _summary(result: ProbeResult) -> dict:
    return {
        "qname": result.qname,
        "qtype": result.qtype,
        "rcode": result.rcode,
        "flags": result.flags,
        "transport": result.transport,
        "error": result.error,
        "response_time_ms": result.response_time_ms,
    }
