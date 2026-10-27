from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from dnsassess.comparator import LAB_CAUSES as CAUSES
from dnsassess.comparator import compare

LABELS = ["Recursive", "Authoritative-only", "Refused", "Inconclusive"]


def _lab_reachable() -> bool:
    """True if we can reach a lab target on port 53."""
    try:
        result = subprocess.run(
            [
                "docker",
                "exec",
                "lab-client",
                "python3",
                "-c",
                "import socket; s=socket.socket(); s.settimeout(2); "
                "s.connect(('172.28.0.101', 53)); s.close()",
            ],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@pytest.mark.lab
def test_lab_accuracy_at_least_90(tmp_path):
    """Run scan against lab, compare to ground truth, assert >= 90% accuracy."""
    if not _lab_reachable():
        pytest.skip("Docker lab not reachable from this host")

    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Run the scan from the dedicated client container.
    scan_cmd = [
        "docker",
        "exec",
        "lab-client",
        "python3",
        "-c",
        (
            "import sys; sys.path.insert(0, '/app'); "
            "from dnsassess.cli import main; "
            f"sys.exit(main(['scan', '--scope', '/app/config/scope.yaml', "
            f"'--rate', '/app/config/rate.yaml', '--out', '/app/out', "
            f"'--seed', 'integration', "
            f"'--auth-log', '/var/log/authzone/queries.jsonl']))"
        ),
    ]
    result = subprocess.run(scan_cmd, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, f"scan failed: {result.stderr}"

    # Load predictions from results.json written inside the container.
    results_path = Path("/app/out/results.json")
    if not results_path.exists():
        # Fallback: copy from container
        subprocess.run(
            ["docker", "cp", "lab-client:/app/out/results.json", str(tmp_path / "results.json")],
            check=True,
        )
        results_path = tmp_path / "results.json"

    report = json.loads(results_path.read_text(encoding="utf-8"))
    predictions = report.get("predictions", {})

    # Load ground truth.
    gt_path = Path("/app/ground_truth.yaml")
    if not gt_path.exists():
        subprocess.run(
            ["docker", "cp", "lab-client:/app/ground_truth.yaml", str(tmp_path / "ground_truth.yaml")],
            check=True,
        )
        gt_path = tmp_path / "ground_truth.yaml"

    with gt_path.open("r", encoding="utf-8") as fh:
        gt_data = yaml.safe_load(fh) or {}
    ground_truth = {t["id"]: t["expected_label"] for t in gt_data.get("targets", [])}

    comparison = compare(predictions, ground_truth, CAUSES)

    # Assert accuracy >= 90%.
    assert comparison.accuracy >= 0.90, (
        f"Accuracy {comparison.accuracy:.1%} below 90% threshold "
        f"({comparison.correct}/{comparison.total})"
    )

    # Assert every mismatch has a documented root cause.
    for m in comparison.mismatches:
        assert m.cause != "other", (
            f"{m.target_id}: mismatch undocumented (cause='other'): "
            f"truth={m.truth} predicted={m.predicted}"
        )
        assert m.explanation, f"{m.target_id}: mismatch missing explanation"

    # Print summary for visibility.
    print(f"\nLab accuracy: {comparison.accuracy:.1%} ({comparison.correct}/{comparison.total})")
    for label in LABELS:
        print(
            f"  {label:20s} precision={comparison.precision[label]:.2f} "
            f"recall={comparison.recall[label]:.2f}"
        )
    if comparison.mismatches:
        print("Mismatches:")
        for m in comparison.mismatches:
            print(f"  {m.target_id}: {m.truth} -> {m.predicted} ({m.cause}): {m.explanation}")
