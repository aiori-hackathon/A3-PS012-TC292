from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent
LAB = ROOT / "lab"


def run_demo(
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    """Run the Docker lab, scan, comparison, and report in sequence."""
    steps = [
        (
            "start and wait for the Docker lab",
            [
                "docker",
                "compose",
                "up",
                "-d",
                "--build",
                "--remove-orphans",
                "--wait",
                "--wait-timeout",
                "180",
            ],
            LAB,
        ),
        (
            "scan authorized lab targets",
            [
                "docker",
                "exec",
                "lab-client",
                "python3",
                "-m",
                "dnsassess.cli",
                "scan",
                "--scope",
                "/app/config/scope.yaml",
                "--rate",
                "/app/config/rate.yaml",
                "--out",
                "/app/out",
                "--seed",
                "demo",
                "--auth-log",
                "/var/log/authzone/queries.jsonl",
            ],
            ROOT,
        ),
        (
            "compare results with ground truth",
            [
                "docker",
                "exec",
                "lab-client",
                "python3",
                "-m",
                "dnsassess.cli",
                "compare",
                "--out",
                "/app/out",
            ],
            ROOT,
        ),
        (
            "generate JSON, CSV, and HTML reports",
            [
                "docker",
                "exec",
                "lab-client",
                "python3",
                "-m",
                "dnsassess.cli",
                "report",
                "--out",
                "/app/out",
                "--scope",
                "/app/config/scope.yaml",
                "--rate",
                "/app/config/rate.yaml",
            ],
            ROOT,
        ),
    ]

    for description, command, cwd in steps:
        print(f"\n==> {description}", flush=True)
        try:
            result = run(command, cwd=cwd, check=False)
        except OSError as exc:
            print(f"demo failed while trying to {description}: {exc}", file=sys.stderr)
            return 1
        if result.returncode != 0:
            print(
                f"demo failed while trying to {description} "
                f"(exit code {result.returncode})",
                file=sys.stderr,
            )
            return result.returncode

    print(f"\nDemo complete. HTML report: {ROOT / 'out' / 'report.html'}")
    return 0


if __name__ == "__main__":
    sys.exit(run_demo())
