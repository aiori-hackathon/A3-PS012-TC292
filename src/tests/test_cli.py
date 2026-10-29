from pathlib import Path
import json
from argparse import Namespace

from dnsassess import cli


def test_find_ground_truth_in_package_root_mount(tmp_path, monkeypatch):
    package_root = tmp_path / "app"
    package_root.mkdir()
    (package_root / "ground_truth.yaml").write_text("targets: []\n", encoding="utf-8")
    package_dir = package_root / "dnsassess"
    package_dir.mkdir()
    monkeypatch.setattr(cli, "__file__", str(package_dir / "cli.py"))
    monkeypatch.chdir(tmp_path)

    assert cli._find_ground_truth(tmp_path / "out") == package_root / "ground_truth.yaml"


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
