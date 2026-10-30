from pathlib import Path

from dnsassess.config import Authorisation, RateConfig, ScopeConfig, Target
from dnsassess.safety import SafetyGate, SafetyError


def _scope(targets: list[Target]) -> ScopeConfig:
    return ScopeConfig(
        authorisation=Authorisation(
            owner="Team Binary Beans lab",
            authorised_by="Prof (Dr) Rupayan Das",
            authorised_on="2026-10-16",
            statement="All listed servers are lab containers owned by the team.",
        ),
        test_zone="probe.lab.test",
        test_zone_ip="172.28.0.10",
        targets=targets,
    )


def test_check_scope_refuses_out_of_scope_ip(tmp_path: Path):
    gate = SafetyGate(
        scope=_scope([Target(id="t01", name="n", ip="172.28.0.101")]),
        kill_file=tmp_path / "KILL",
    )
    gate.check_authorisation()
    gate.enforce_max_20(gate.scope.targets)
    try:
        gate.check_scope("10.0.0.99")
        raise AssertionError("expected SafetyError for out-of-scope IP")
    except SafetyError:
        pass


def test_check_scope_allows_in_scope_ip():
    gate = SafetyGate(
        scope=_scope([Target(id="t01", name="n", ip="172.28.0.101")]),
        kill_file=Path("/nonexistent/KILL"),
    )
    gate.check_scope("172.28.0.101")  # must not raise


def test_enforce_max_20_aborts_at_21_targets():
    targets = [
        Target(id=f"t{i}", name=f"n{i}", ip=f"172.28.0.{100 + i}") for i in range(21)
    ]
    gate = SafetyGate(scope=_scope([]), kill_file=Path("/nonexistent/KILL"))
    try:
        gate.enforce_max_20(targets)
        raise AssertionError("expected SafetyError for 21 targets")
    except SafetyError as exc:
        assert "20" in str(exc)


def test_missing_authorisation_aborts():
    scope = ScopeConfig(
        authorisation=None, test_zone="z", test_zone_ip="1.2.3.4", targets=[]
    )
    gate = SafetyGate(scope=scope, kill_file=Path("/nonexistent/KILL"))
    try:
        gate.check_authorisation()
        raise AssertionError("expected SafetyError for missing authorisation")
    except SafetyError:
        pass


def test_incomplete_authorisation_aborts():
    scope = ScopeConfig(
        authorisation=Authorisation(owner="", authorised_by="b", authorised_on="d", statement="s"),
        test_zone="z",
        test_zone_ip="1.2.3.4",
        targets=[],
    )
    gate = SafetyGate(scope=scope, kill_file=Path("/nonexistent/KILL"))
    try:
        gate.check_authorisation()
        raise AssertionError("expected SafetyError for incomplete authorisation")
    except SafetyError:
        pass


def test_kill_switch_file(tmp_path: Path):
    kill_file = tmp_path / "KILL"
    gate = SafetyGate(scope=_scope([]), kill_file=kill_file)
    assert not gate.kill_switch()
    kill_file.write_text("stop")
    assert gate.kill_switch()


def test_per_target_query_cap_trips_and_isolates_targets():
    gate = SafetyGate(
        scope=_scope([]),
        kill_file=Path("/nonexistent/KILL"),
        max_queries_per_target=2,
    )
    gate.record_query("t01")
    assert not gate.per_target_exceeded("t01")
    gate.record_query("t01")
    assert gate.per_target_exceeded("t01")
    assert not gate.per_target_exceeded("t02"), "cap must be per target"


def test_per_target_cap_disabled_when_unset():
    gate = SafetyGate(scope=_scope([]), kill_file=Path("/nonexistent/KILL"))
    for _ in range(5):
        gate.record_query("t01")
    assert not gate.per_target_exceeded("t01")


def test_max_total_queries_trips_kill_switch():
    gate = SafetyGate(
        scope=_scope([]),
        kill_file=Path("/nonexistent/KILL"),
        max_total_queries=2,
    )
    gate.record_query("t01")
    assert not gate.kill_switch()
    gate.record_query("t02")
    assert gate.kill_switch(), "total query budget must stop the run"
