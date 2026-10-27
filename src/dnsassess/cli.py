"""Command-line interface: scan, compare, report, demo.

scan: loads scope/rate config, runs SafetyGate, probes each authorised
target, classifies via the nonce-based recursion proof, and writes
evidence + results to out/.

compare: compares predicted labels against lab/ground_truth.yaml to build
a confusion matrix and error analysis (Phase 3-4).

report: writes JSON, CSV and HTML reports (Phase 4).

demo: lab-up -> scan -> compare -> report (Phase 5).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import yaml

from .classifier import classify
from .comparator import compare, LABELS
from .config import ConfigError, load_rate, load_scope
from .evidence import EvidenceStore
from .prober import Prober
from .ratelimit import RateLimiter
from .safety import SafetyGate, SafetyError


DEFAULT_OUT = "out"
DEFAULT_AUTH_LOG = "lab/authzone/logs/queries.jsonl"


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        scope = load_scope(args.scope)
        rate = load_rate(args.rate)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1

    gate = SafetyGate(scope=scope)
    try:
        gate.check_authorisation()
        gate.enforce_max_20(scope.targets)
    except SafetyError as exc:
        print(f"safety error: {exc}", file=sys.stderr)
        return 1

    limiter = RateLimiter(rate=rate)
    prober = Prober(scope=scope, rate=rate, limiter=limiter)
    store = EvidenceStore(Path(args.out) / "evidence.jsonl")

    # Read the auth-zone log to index nonces (proof of recursion).
    auth_index: dict[str, list[dict]] = {}
    if Path(args.auth_log).exists():
        auth_index = EvidenceStore().read_auth_log(args.auth_log)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Phase 1: probe every target (probe_A + probe_B), storing raw results.
    probe_results: list[dict] = []
    for target in scope.targets:
        # Safety: refuse out-of-scope targets.
        try:
            gate.check_scope(target.ip)
        except SafetyError as exc:
            print(f"safety error: {exc}", file=sys.stderr)
            return 1

        # Kill switch checked before every query.
        gate.record_query()
        if gate.kill_switch():
            print("kill switch triggered; stopping cleanly.", file=sys.stderr)
            break

        nonce = prober.next_nonce(args.seed, target.id)
        probe_a = prober.probe_A(target, args.seed, nonce)
        probe_b = prober.probe_B(target)

        probe_results.append(
            {
                "target": target,
                "nonce": nonce,
                "probe_a": probe_a,
                "probe_b": probe_b,
            }
        )
        store.append(probe_a)
        store.append(probe_b)

    # Phase 2: read the auth-zone log (after probing, so recursive queries
    # have arrived). Wait briefly for upstream resolvers to forward queries.
    time.sleep(2.0)
    auth_index: dict[str, list[dict]] = {}
    if Path(args.auth_log).exists():
        auth_index = EvidenceStore().read_auth_log(args.auth_log)

    # Phase 3: classify each target using probe results + auth log.
    predictions: dict[str, str] = {}
    results: list[dict] = []

    for pr in probe_results:
        target = pr["target"]
        nonce = pr["nonce"]
        probe_a = pr["probe_a"]
        probe_b = pr["probe_b"]

        entries = auth_index.get(nonce, [])
        classification = classify(probe_a, probe_b, entries, target.ip)

        predictions[target.id] = classification.label
        results.append(
            {
                "target_id": target.id,
                "name": target.name,
                "ip": target.ip,
                "serves_zone": target.serves_zone,
                "label": classification.label,
                "reason": classification.reason,
                "via_forwarder": classification.via_forwarder,
                "nonce_seen": classification.nonce_seen,
                "evidence_ids": classification.evidence_ids,
                "probe_a": classification.raw.get("a", {}),
                "probe_b": classification.raw.get("b", {}),
            }
        )

    # Write results.json
    results_path = out_dir / "results.json"
    report = {
        "results": results,
        "predictions": predictions,
    }
    results_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"scan complete: {len(results)} targets -> {results_path}")
    for r in results:
        print(f"  {r['target_id']} ({r['ip']}): {r['label']} ({r['reason']})")
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    # Load predictions from previous scan output.
    results_path = Path(args.out) / "results.json"
    if not results_path.exists():
        print(f"no results found at {results_path}; run `scan` first.", file=sys.stderr)
        return 1
    report = json.loads(results_path.read_text(encoding="utf-8"))
    predictions = report.get("predictions", {})

    # Load ground truth.
    gt_path = Path("lab/ground_truth.yaml")
    if not gt_path.exists():
        gt_path = Path(args.out) / "ground_truth.yaml"
    with gt_path.open("r", encoding="utf-8") as fh:
        gt_data = yaml.safe_load(fh) or {}
    ground_truth = {t["id"]: t["expected_label"] for t in gt_data.get("targets", [])}

    comparison = compare(predictions, ground_truth)
    print(f"accuracy: {comparison.accuracy:.1%}  ({comparison.correct}/{comparison.total})")
    for label in LABELS:
        print(
            f"  {label:20s} precision={comparison.precision[label]:.2f} "
            f"recall={comparison.recall[label]:.2f}"
        )
    if comparison.mismatches:
        print("mismatches:")
        for m in comparison.mismatches:
            print(
                f"  {m.target_id}: truth={m.truth} predicted={m.predicted} "
                f"cause={m.cause} ({m.explanation})"
            )
    else:
        print("no mismatches")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    print("report: not yet implemented (Phase 4).")
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    print("demo: not yet implemented (Phase 5).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dnsassess")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="run authorised probes")
    p_scan.add_argument("--scope", required=True, help="path to scope.yaml")
    p_scan.add_argument("--rate", required=True, help="path to rate.yaml")
    p_scan.add_argument("--out", default=DEFAULT_OUT, help="output directory")
    p_scan.add_argument(
        "--seed", default="default", help="seed for nonce generation"
    )
    p_scan.add_argument(
        "--auth-log",
        default=DEFAULT_AUTH_LOG,
        help="path to auth-zone queries.jsonl",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_compare = sub.add_parser("compare", help="compare results to ground truth")
    p_compare.add_argument("--out", default=DEFAULT_OUT, help="output directory")
    p_compare.set_defaults(func=_cmd_compare)

    p_report = sub.add_parser("report", help="write JSON/CSV/HTML reports")
    p_report.add_argument("--out", default=DEFAULT_OUT, help="output directory")
    p_report.set_defaults(func=_cmd_report)

    sub.add_parser("demo", help="full lab-up -> scan -> compare -> report").set_defaults(
        func=_cmd_demo
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
