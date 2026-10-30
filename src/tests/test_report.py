import csv
import json
from datetime import datetime, timedelta, timezone

from dnsassess.comparator import compare
from dnsassess.report import build_run_metadata, generate_reports


def test_reports_include_metadata_and_target_data(tmp_path):
    scope = tmp_path / "scope.yaml"
    rate = tmp_path / "rate.yaml"
    scope.write_text("targets: []\n", encoding="utf-8")
    rate.write_text("global_qps: 5\n", encoding="utf-8")
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(seconds=2)
    metadata = build_run_metadata(scope, rate, "test-seed", start, end)
    data = {
        "run_metadata": metadata,
        "results": [
            {
                "target_id": "t01",
                "name": "resolver",
                "ip": "192.0.2.1",
                "label": "Recursive",
                "reason": "nonce_seen",
                "via_forwarder": False,
                "probe_a": {"response_time_ms": 12.5},
            },
            {
                "target_id": "t02",
                "name": "auth",
                "ip": "192.0.2.2",
                "label": "Authoritative-only",
                "probe_a": {"response_time_ms": 8.9148960000216},
            },
            {
                "target_id": "t03",
                "name": "refused",
                "ip": "192.0.2.3",
                "label": "Refused",
                "probe_a": {"response_time_ms": 9.0},
            },
            {
                "target_id": "t04",
                "name": "unknown",
                "ip": "192.0.2.4",
                "label": "Inconclusive",
                "probe_a": {},
            },
        ],
        "predictions": {
            "t01": "Recursive",
            "t02": "Authoritative-only",
            "t03": "Refused",
            "t04": "Inconclusive",
        },
    }

    comparison = compare(
        data["predictions"],
        {target_id: label for target_id, label in data["predictions"].items()},
    )
    paths = generate_reports(
        tmp_path / "out", data, scope, rate, "wrong-seed", comparison
    )

    json_report = json.loads(paths["results_json"].read_text(encoding="utf-8"))
    assert json_report["run_metadata"] == metadata
    with paths["results_csv"].open(encoding="utf-8", newline="") as stream:
        row = next(csv.DictReader(stream))
    assert row["id"] == "t01"
    assert row["run_seed"] == "test-seed"
    assert row["run_config_hash"] == metadata["config_hash"]
    assert row["run_start_time"] == start.isoformat()
    assert row["run_end_time"] == end.isoformat()
    html = paths["report_html"].read_text(encoding="utf-8")
    assert "test-seed" in html
    assert metadata["config_hash"] in html
    assert start.isoformat() in html and end.isoformat() in html
    assert "Confusion matrix" in html
    assert "t01 (resolver)" in html
    assert 'class="badge b-rec"' in html
    assert 'class="badge b-auth"' in html
    assert 'class="badge b-ref"' in html
    assert 'class="badge b-inc"' in html
    assert "8.91" in html
    assert "8.9148960000216" not in html


def test_run_metadata_hashes_both_config_files(tmp_path):
    scope = tmp_path / "scope.yaml"
    rate = tmp_path / "rate.yaml"
    scope.write_bytes(b"scope")
    rate.write_bytes(b"rate")

    metadata = build_run_metadata(
        scope,
        rate,
        "seed",
        datetime.now(timezone.utc),
        datetime.now(timezone.utc),
    )

    assert metadata["config_hash"]
    assert len(metadata["config_hash"]) == 64
