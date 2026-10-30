"""Canary attribution self-check: send, poll, and attribute the control query."""
from __future__ import annotations

import dns.message
import dns.rcode
import pytest

from dnsassess.selfcheck import CONTROL_PREFIX, SelfCheckResult, run_canary_selfcheck

ZONE = "probe.lab.test"
ZONE_IP = "172.28.0.10"
CLIENT_IP = "172.28.0.2"


def _declined(query, ip, port=53, timeout=None):
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.REFUSED)
    return response


def _answered(query, ip, port=53, timeout=None):
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NOERROR)
    return response


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _run(monkeypatch, *, sent=None, log_by_label=None, log_wait=2.0):
    """Drive the self-check with an injectable sender and canned log."""
    monkeypatch.setattr(
        "dnsassess.selfcheck._predict_client_ip", lambda _ip: CLIENT_IP
    )
    sender = sent if sent is not None else (
        lambda query, ip, port=53, timeout=None: _answered(query, ip, port, timeout)
    )

    def read_log():
        return log_by_label or {}

    clock = FakeClock()
    checks: list[SelfCheckResult] = []

    def record(result):
        checks.append(result)
        return result

    # Wrap run_canary_selfcheck by capturing the result it returns.
    result = run_canary_selfcheck(
        ZONE_IP,
        ZONE,
        seed="unit",
        timeout=1.0,
        log_wait=log_wait,
        send_query=sender,
        read_log=read_log,
        clock=clock,
        sleep=clock.sleep,
    )
    record(result)
    assert checks  # the flow always produces exactly one result to inspect
    return checks[-1]


def test_control_qname_is_labelled_and_distinct_from_nonces(monkeypatch):
    import hashlib
    result = _run(monkeypatch, log_by_label={})
    # Control names carry the selfcheck- prefix so they can never collide with
    # the 12-hex probe nonces, and they stay inside the canary's zone.
    assert result.control_qname.startswith("selfcheck-")
    assert result.control_qname.endswith("." + ZONE + ".")
    assert hashlib.sha256(b"unit:probe.lab.test:canary-control").hexdigest()[:8] in result.control_qname


def test_verified_when_control_entry_attributed_to_client(monkeypatch):
    import hashlib
    label = CONTROL_PREFIX + "-" + hashlib.sha256(
        b"unit:probe.lab.test:canary-control"
    ).hexdigest()[:8]

    def good_send(query, ip, port=53, timeout=None):
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NOERROR)
        return response

    captured = {}

    def sender(query, ip, port=53, timeout=None):
        captured["qname"] = str(query.question[0].name)
        return good_send(query, ip, port, timeout)

    result = _run(
        monkeypatch,
        sent=sender,
        log_by_label={label: [{"src_ip": CLIENT_IP}]},
    )
    assert result.status == "verified"
    assert result.observed_src_ip == CLIENT_IP
    assert captured["qname"].startswith("selfcheck-")
    assert result.rcode == "NOERROR"


def test_timeout_when_canary_log_never_records(monkeypatch):
    result = _run(monkeypatch, log_by_label={}, log_wait=2.0)
    assert result.status == "timeout"
    assert "canary logging" in result.error


def test_src_ip_mismatch_reported(monkeypatch):
    import hashlib
    label = CONTROL_PREFIX + "-" + hashlib.sha256(
        b"unit:probe.lab.test:canary-control"
    ).hexdigest()[:8]
    result = _run(monkeypatch, log_by_label={label: [{"src_ip": "10.9.9.9"}]})
    assert result.status == "src_ip_mismatch"
    assert "10.9.9.9" in result.error


def test_send_failure_is_reported_not_raised(monkeypatch):
    def broken_send(query, ip, port=53, timeout=None):
        raise OSError("network unreachable")

    result = _run(monkeypatch, sent=broken_send)
    assert result.status == "error"
    assert result.error and "OSError" in result.error


def test_refused_control_answer_is_an_error(monkeypatch):
    result = _run(monkeypatch, sent=_declined)
    assert result.status == "error"
    assert result.rcode == "REFUSED"
