from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
T02 = ROOT / "lab" / "targets" / "t02"


def test_t02_bind_config_has_no_authoritative_zone():
    config = (T02 / "named.conf").read_text(encoding="utf-8")

    assert "allow-recursion { 127.0.0.1; };" in config
    assert 'zone "owned.t02.lab.test"' not in config


def test_t02_fixture_does_not_host_a_zone():
    fixture = (T02 / "bind_closed.py").read_text(encoding="utf-8")

    assert "owned.t02.lab.test" not in fixture
    assert "response.set_rcode(dns.rcode.REFUSED)" in fixture
