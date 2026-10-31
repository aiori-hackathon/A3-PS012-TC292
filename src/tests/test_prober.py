"""UDP retry, TCP fallback and skip-result behaviour of the Prober."""
from __future__ import annotations

import dns.exception
import dns.flags
import dns.message
import dns.rrset

from dnsassess.config import Authorisation, RateConfig, ScopeConfig, Target
from dnsassess.prober import Prober
from dnsassess.ratelimit import RateLimiter


class FakeClock:
    """Monotonic-enough clock controlling limiter waits in tests."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        """Simulate a blocking sleep by advancing the fake clock."""
        self.now += seconds


def _prober(udp_retries: int = 2, timeout: float = 2.0) -> tuple[Prober, FakeClock]:
    scope = ScopeConfig(
        authorisation=Authorisation(
            owner="Team Binary Beans lab",
            authorised_by="Prof (Dr) Rupayan Das",
            authorised_on="2026-10-16",
            statement="All listed servers are lab containers owned by the team.",
        ),
        test_zone="probe.lab.test",
        test_zone_ip="172.28.0.10",
        targets=[Target(id="t01", name="bind-open", ip="172.28.0.101")],
    )
    rate = RateConfig(
        global_qps=100.0,
        per_target_qps=100.0,
        max_queries_per_target=10,
        timeout_seconds=timeout,
        max_total_queries=80,
        edns_payload=1232,
        udp_retries=udp_retries,
    )
    clock = FakeClock()
    limiter = RateLimiter(rate=rate, clock=clock, sleep=lambda s: None)
    prober = Prober(scope=scope, rate=rate, limiter=limiter, timeout_seconds=timeout)
    return prober, clock


def _response_for(query: dns.message.Message) -> dns.message.Message:
    response = dns.message.make_response(query)
    response.flags |= dns.flags.QR
    qname = response.question[0].name
    response.answer.append(
        dns.rrset.from_text(qname, 0, "IN", "A", "192.0.2.1")
    )
    return response


def test_udp_retry_succeeds_on_second_attempt(monkeypatch):
    prober, _ = _prober(udp_retries=2)
    calls = []

    def fake_udp(query, ip, port=53, timeout=None):
        calls.append(query)
        if len(calls) == 1:
            raise dns.exception.Timeout()
        return _response_for(query)

    monkeypatch.setattr("dns.query.udp", fake_udp)

    result = prober.probe_A(prober.scope.targets[0], "seed", "nonce1")

    assert len(calls) == 2
    assert result.rcode == "NOERROR"
    assert result.answer, "expected the answer to survive the retry"
    assert result.error is None
    assert result.attempts == 2


def test_udp_retry_exhausts_and_records_attempt_count(monkeypatch):
    prober, _ = _prober(udp_retries=1)
    calls = []

    def fake_udp(query, ip, port=53, timeout=None):
        calls.append(query)
        raise dns.exception.Timeout()

    monkeypatch.setattr("dns.query.udp", fake_udp)

    result = prober.probe_A(prober.scope.targets[0], "seed", "nonce1")

    assert len(calls) == 2, "1 initial attempt + 1 retry expected"
    assert result.rcode == "timeout"
    assert result.attempts == 2
    assert result.error == "timeout after 2 attempt(s)"
    assert "nonce1" == result.nonce, "nonce must survive retries"


def test_zero_retries_sends_single_attempt(monkeypatch):
    prober, _ = _prober(udp_retries=0)
    calls = []

    def fake_udp(query, ip, port=53, timeout=None):
        calls.append(query)
        raise dns.exception.Timeout()

    monkeypatch.setattr("dns.query.udp", fake_udp)

    result = prober.probe_A(prober.scope.targets[0], "seed", "nonce1")

    assert len(calls) == 1
    assert result.attempts == 1
    assert result.error == "timeout after 1 attempt(s)"


def test_tcp_fallback_failure_does_not_inherit_udp_fields(monkeypatch):
    """Regression: a failed TCP retry must not report the UDP reply as TCP."""
    prober, _ = _prober(udp_retries=0)

    def fake_udp(query, ip, port=53, timeout=None):
        response = _response_for(query)
        response.flags |= dns.flags.TC  # truncated
        return response

    def fake_tcp(query, ip, port=53, timeout=None):
        raise dns.exception.Timeout()

    monkeypatch.setattr("dns.query.udp", fake_udp)
    monkeypatch.setattr("dns.query.tcp", fake_tcp)

    result = prober.probe_A(prober.scope.targets[0], "seed", "nonce1")

    assert result.transport == "tcp"
    assert result.rcode == "error", "must not report the UDP reply's rcode"
    assert result.flags == {}, "must not inherit the UDP reply's flags"
    assert result.error != ""


def test_tcp_fallback_recovers_truncated_answer(monkeypatch):
    prober, _ = _prober(udp_retries=0)

    def fake_udp(query, ip, port=53, timeout=None):
        response = _response_for(query)
        response.flags |= dns.flags.TC
        return response

    def fake_tcp(query, ip, port=53, timeout=None):
        return _response_for(query)

    monkeypatch.setattr("dns.query.udp", fake_udp)
    monkeypatch.setattr("dns.query.tcp", fake_tcp)

    result = prober.probe_A(prober.scope.targets[0], "seed", "nonce1")

    assert result.transport == "tcp"
    assert result.rcode == "NOERROR"
    assert result.answer


def test_tcp_fallback_latency_excludes_limiter_wait(monkeypatch):
    """Regression: t16 measured ~1027 ms because the TC-to-TCP fallback timer
    started before the 1 qps per-target limiter wait, so the reported server
    latency included ~1 s of regulatory wait instead of the ~10 ms TCP reply.
    """
    import dnsassess.prober as prober_mod

    scope = ScopeConfig(
        authorisation=Authorisation(
            owner="Team Binary Beans lab",
            authorised_by="Prof (Dr) Rupayan Das",
            authorised_on="2026-10-16",
            statement="All listed servers are lab containers owned by the team.",
        ),
        test_zone="probe.lab.test",
        test_zone_ip="172.28.0.10",
        targets=[Target(id="t16", name="tcp-truncate", ip="172.28.0.116")],
    )
    rate = RateConfig(
        global_qps=100.0,
        per_target_qps=1.0,  # forces a real ~1 s gap between the two legs
        max_queries_per_target=3,
        timeout_seconds=2.0,
        max_total_queries=80,
        edns_payload=1232,
        udp_retries=0,
    )
    clock = FakeClock()
    limiter = RateLimiter(rate=rate, clock=clock, sleep=clock.sleep)
    prober_node = Prober(scope=scope, rate=rate, limiter=limiter, timeout_seconds=2.0)

    # Route the prober's latency timer through the same fake clock, so the
    # limiter's pause shows up as elapsed time instead of a real full second.
    monkeypatch.setattr(prober_mod.time, "monotonic", lambda: clock.now)

    def fake_udp(query, ip, port=53, timeout=None):
        response = _response_for(query)
        response.flags |= dns.flags.TC  # truncated -> TCP fallback
        return response  # answers instantly on the fake clock

    def fake_tcp(query, ip, port=53, timeout=None):
        clock.sleep(0.150)  # server answers over TCP after 150 ms
        return _response_for(query)

    monkeypatch.setattr("dns.query.udp", fake_udp)
    monkeypatch.setattr("dns.query.tcp", fake_tcp)

    result = prober_node.probe_A(prober_node.scope.targets[0], "seed", "nonce1")

    assert result.transport == "tcp"
    assert result.rcode == "NOERROR"
    assert result.attempts == 1, "a TC reply is a valid response, not a retry"
    # The limiter adds ~1.01 s of regulatory wait before the TCP leg; the
    # measured server latency must only be the ~150 ms TCP round-trip.
    assert result.response_time_ms < 300, (
        f"TCP latency {result.response_time_ms:.0f} ms includes the limiter "
        "wait; the timer must reset after the rate-limiter pause"
    )


def test_no_serves_zone_returns_skipped_documented():
    prober, _ = _prober()
    skipped = prober.probe_B(prober.scope.targets[0])

    assert skipped.rcode == "skipped"
    assert skipped.transport == "none"
    assert skipped.attempts == 0
    assert "serves_zone" in (skipped.error or "")


def test_rd_bit_is_honoured_per_probe(monkeypatch):
    """Probe A is sent with RD=1 and probe B (zone SOA probe) with RD=0."""
    prober, _ = _prober()
    sent = []

    def fake_udp(query, ip, port=53, timeout=None):
        sent.append(query)
        return _response_for(query)

    monkeypatch.setattr("dns.query.udp", fake_udp)
    target = Target(
        id="t07", name="nsd-auth", ip="172.28.0.107", serves_zone="owned.t07.lab.test"
    )
    prober.probe_A(target, "seed", "abc123abc123")
    prober.probe_B(target)

    assert bool(sent[0].flags & dns.flags.RD) is True
    assert bool(sent[1].flags & dns.flags.RD) is False
