from pathlib import Path
import json
from argparse import Namespace

from dnsassess import cli
from dnsassess.prober import ProbeResult


def _sent_result(target_id: str) -> ProbeResult:
    return ProbeResult(
        target_id=target_id,
        probe_type="A",
        qname="x.probe.lab.test",
        qtype="A",
        flags={},
        rcode="NOERROR",
        answer=["x.probe.lab.test. 0 IN A 192.0.2.1"],
        response_time_ms=1.0,
        transport="udp",
        nonce="nonce1",
    )


def _skipped_result(target_id: str, reason: str) -> ProbeResult:
    return ProbeResult(
        target_id=target_id,
        probe_type="A",
        qname="",
        qtype="A",
        flags={},
        rcode="skipped",
        answer=[],
        response_time_ms=0.0,
        transport="none",
        error=reason,
        nonce="nonce1",
        attempts=0,
    )


def test_find_ground_truth_in_package_root_mount(tmp_path, monkeypatch):
    package_root = tmp_path / "app"
    package_root.mkdir()
    (package_root / "ground_truth.yaml").write_text("targets: []\n", encoding="utf-8")
    package_dir = package_root / "dnsassess"
    package_root.mkdir(exist_ok=True)
    package_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(cli, "__file__", str(package_dir / "cli.py"))
    monkeypatch.chdir(tmp_path)

    assert cli._find_ground_truth(tmp_path / "out") == package_root / "ground_truth.yaml"


def test_guarded_probe_sends_within_budget(tmp_path):
    from dnsassess.cli import _guarded_probe
    from dnsassess.evidence import EvidenceStore
    from dnsassess.safety import SafetyGate
    from dnsassess.config import Authorisation, ScopeConfig

    scope = ScopeConfig(
        authorisation=Authorisation(
            owner="o", authorised_by="b", authorised_on="d", statement="s"
        ),
        test_zone="probe.lab.test",
        test_zone_ip="172.28.0.10",
        targets=[],
    )
    gate = SafetyGate(
        scope=scope,
        kill_file=tmp_path / "KILL",
        max_queries_per_target=1,
    )
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    sent = []

    first = _guarded_probe(
        gate,
        store,
        "t01",
        lambda reason: reason,
        lambda: (_sent_result("t01"), sent.append("query"))[0],
    )
    assert first.rcode == "NOERROR"
    assert first.attempts == 1
    assert len(sent) == 1

    second = _guarded_probe(
        gate,
        store,
        "t01",
        lambda reason: _skipped_result("t01", reason),
        lambda: (_sent_result("t01"), sent.append("query"))[0],
    )
    assert second.rcode == "skipped"
    assert "per-target query cap" in (second.error or "")
    assert len(sent) == 1, "no second query may be sent beyond the cap"


def test_guarded_probe_respects_kill_switch(tmp_path):
    from dnsassess.cli import _guarded_probe
    from dnsassess.evidence import EvidenceStore
    from dnsassess.safety import SafetyGate
    from dnsassess.config import Authorisation, ScopeConfig

    scope = ScopeConfig(
        authorisation=Authorisation(
            owner="o", authorised_by="b", authorised_on="d", statement="s"
        ),
        test_zone="probe.lab.test",
        test_zone_ip="172.28.0.10",
        targets=[],
    )
    kill_file = tmp_path / "KILL"
    kill_file.write_text("stop", encoding="utf-8")
    gate = SafetyGate(scope=scope, kill_file=kill_file)
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    sent = []

    result = _guarded_probe(
        gate,
        store,
        "t01",
        lambda reason: _skipped_result("t01", reason),
        lambda: (_sent_result("t01"), sent.append("query"))[0],
    )

    assert result.rcode == "skipped"
    assert "kill switch" in (result.error or "")
    assert sent == [], "nothing may be sent while the kill switch is active"


def test_stability_verifier_rejects_different_labels(tmp_path, monkeypatch):
    results = iter(
        [
            {"t01": "Recursive"},
            {"t01": "Inconclusive"},
            {"t01": "Recursive"},
        ]
    )

    def fake_scan(args):
        args_path = Path(args.out)
        args_path.mkdir(parents=True)
        (args_path / "results.json").write_text(
            json.dumps({"predictions": next(results)}), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(cli, "_cmd_scan", fake_scan)
    args = Namespace(
        out=str(tmp_path / "stability"),
        runs=3,
        scope="scope.yaml",
        rate="rate.yaml",
        seed="same",
        auth_log="auth.jsonl",
    )

    assert cli._cmd_verify_stability(args) == 1
