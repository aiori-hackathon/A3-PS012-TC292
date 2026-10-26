"""Nonce tests: unique, lowercase hex, reproducible from seed."""
from dnsassess.config import Authorisation, RateConfig, ScopeConfig, Target
from dnsassess.prober import Prober
from dnsassess.ratelimit import RateLimiter


def _prober() -> Prober:
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
        global_qps=5.0,
        per_target_qps=1.0,
        max_queries_per_target=3,
        timeout_seconds=2.0,
        max_total_queries=80,
        edns_payload=1232,
    )
    return Prober(scope=scope, rate=rate, limiter=RateLimiter(rate=rate))


def test_nonce_is_twelve_char_lowercase_hex():
    p = _prober()
    nonce = p.make_nonce("seed1", "t01", 0)
    assert len(nonce) == 12
    assert all(c in "0123456789abcdef" for c in nonce)


def test_nonce_reproducible_from_seed():
    p = _prober()
    assert p.make_nonce("seed1", "t01", 0) == p.make_nonce("seed1", "t01", 0)


def test_nonce_unique_per_index():
    p = _prober()
    assert p.make_nonce("seed1", "t01", 0) != p.make_nonce("seed1", "t01", 1)


def test_nonce_unique_per_target():
    p = _prober()
    assert p.make_nonce("seed1", "t01", 0) != p.make_nonce("seed1", "t02", 0)


def test_next_nonce_advances_per_target():
    p = _prober()
    first = p.next_nonce("seed1", "t01")
    second = p.next_nonce("seed1", "t01")
    assert first != second
