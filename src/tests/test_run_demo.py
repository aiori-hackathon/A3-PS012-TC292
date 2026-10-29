from pathlib import Path
import subprocess

from run_demo import ROOT, run_demo


def test_demo_runs_all_steps_in_order():
    calls = []

    def fake_run(command, cwd, check):
        calls.append((command, cwd, check))
        return subprocess.CompletedProcess(command, 0)

    assert run_demo(fake_run) == 0
    assert len(calls) == 4
    assert calls[0][0][:3] == ["docker", "compose", "up"]
    assert "--wait" in calls[0][0]
    assert calls[1][0][1:5] == ["exec", "lab-client", "python3", "-m"]
    assert calls[1][0][5:7] == ["dnsassess.cli", "scan"]
    assert calls[2][0][-2:] == ["--out", "/app/out"]
    assert calls[3][0][5:7] == ["dnsassess.cli", "report"]
    assert all(check is False for _, _, check in calls)
    assert calls[0][1] == ROOT / "lab"


def test_demo_stops_at_first_failed_step():
    calls = []

    def fake_run(command, cwd, check):
        calls.append(command)
        return subprocess.CompletedProcess(command, 23 if len(calls) == 2 else 0)

    assert run_demo(fake_run) == 23
    assert len(calls) == 2


def test_demo_reports_missing_docker():
    def missing_docker(*args, **kwargs):
        raise FileNotFoundError("docker")

    assert run_demo(missing_docker) == 1
