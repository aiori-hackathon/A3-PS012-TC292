from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .classifier import classify
from .comparator import LAB_CAUSES, LABELS, compare
from .config import ConfigError, load_rate, load_scope
from .evidence import EvidenceStore
from .prober import Prober
from .ratelimit import RateLimiter
from .safety import SafetyGate, SafetyError
from .selfcheck import SelfCheckResult, run_canary_selfcheck
from .report import build_run_metadata, generate_reports


DEFAULT_OUT = "out"
DEFAULT_AUTH_LOG = "lab/authzone/logs/queries.jsonl"


def _guarded_probe(
    gate: SafetyGate,
    store: EvidenceStore,
    target_id: str,
    make_skipped,  # (reason: str) -> ProbeResult
    send,  # () -> ProbeResult
):
    """Send one probe under the safety gates, or record it as skipped.

    The kill-switch and per-target caps are checked before every query, so
    a probe is only ever sent inside its remaining budget.
    """
    if gate.kill_switch():
        reason = "kill switch triggered"
    elif gate.per_target_exceeded(target_id):
        reason = "per-target query cap reached"
    else:
        gate.record_query(target_id)
        result = send()
        store.append(result)
        return result
    result = make_skipped(reason)
    store.append(result)
    return result


def _cmd_scan(args: argparse.Namespace) -> int:
    start_time = datetime.now(timezone.utc)
    try:
        scope = load_scope(args.scope)
        rate = load_rate(args.rate)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1

    gate = SafetyGate(
        scope=scope,
        max_total_queries=rate.max_total_queries,
        max_queries_per_target=rate.max_queries_per_target,
    )
    try:
        gate.check_authorisation()
        gate.enforce_max_20(scope.targets)
    except SafetyError as exc:
        print(f"safety error: {exc}", file=sys.stderr)
        return 1

    limiter = RateLimiter(rate=rate)
    prober = Prober(scope=scope, rate=rate, limiter=limiter)
    store = EvidenceStore(Path(args.out) / "evidence.jsonl")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Phase 0: canary attribution self-check — one control query to our own
    # canary server proves it receives, logs, and that the log reader can
    # attribute entries to this client. The scan refuses to run otherwise.
    # The control query counts toward the global query budget.
    gate.record_query()
    check: SelfCheckResult | None = None
    if args.skip_selfcheck:
        print("canary self-check skipped (--skip-selfcheck)", file=sys.stderr)
    else:
        check = run_canary_selfcheck(
            zone_ip=scope.test_zone_ip,
            zone=scope.test_zone,
            seed=args.seed,
            timeout=rate.timeout_seconds,
            log_wait=args.log_wait,
            limiter=limiter,
            read_log=lambda: store.read_auth_log(args.auth_log),
        )
        store.append_raw({"record": "canary_selfcheck", **check.as_dict()})
        if check.status != "verified":
            print(
                f"canary self-check {check.status}: {check.error or ''}; "
                "refusing to scan — nonce/log correlation is not trustworthy.",
                file=sys.stderr,
            )
            return 1
        print(
            f"canary self-check {check.status}: {check.control_qname} "
            f"attributed to src_ip {check.observed_src_ip} "
            f"({check.response_time_ms:.1f} ms)"
        )

    # Phase 1: probe every target (probe_A + probe_B), storing raw results.
    probe_results: list[dict] = []
    for target in scope.targets:
        # Safety: refuse out-of-scope targets.
        try:
            gate.check_scope(target.ip)
        except SafetyError as exc:
            print(f"safety error: {exc}", file=sys.stderr)
            return 1

        nonce = prober.next_nonce(args.seed, target.id)

        probe_a = _guarded_probe(
            gate,
            store,
            target.id,
            lambda reason, t=target, n=nonce: prober.skipped(t, "A", reason, nonce=n),
            lambda t=target, n=nonce: prober.probe_A(t, args.seed, n),
        )
        probe_b = _guarded_probe(
            gate,
            store,
            target.id,
            lambda reason, t=target: prober.skipped(t, "B", reason),
            lambda t=target: prober.probe_B(t),
        )

        probe_results.append(
            {
                "target": target,
                "nonce": nonce,
                "probe_a": probe_a,
                "probe_b": probe_b,
            }
        )
        if gate.kill_switch():
            print("kill switch triggered; stopping cleanly.", file=sys.stderr)
            break

    # Phase 2: read the auth-zone log so recursive queries have arrived.
    # Poll until every answer that could prove recursion has a log entry,
    # instead of a fixed sleep that races against slow resolvers.
    expected_nonces = {
        pr["nonce"]
        for pr in probe_results
        if pr["probe_a"].nonce
        and pr["probe_a"].error is None
        and pr["probe_a"].transport in ("udp", "tcp")
    }
    auth_index = store.wait_for_nonces(
        args.auth_log, expected_nonces, timeout_seconds=args.log_wait
    )

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
    run_metadata = build_run_metadata(
        args.scope,
        args.rate,
        args.seed,
        start_time,
        datetime.now(timezone.utc),
    )
    report = {
        "run_metadata": run_metadata,
        "results": results,
        "predictions": predictions,
    }
    if check is not None:
        run_metadata["canary_selfcheck"] = check.as_dict()
    results_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"scan complete: {len(results)} targets -> {results_path}")
    for r in results:
        print(f"  {r['target_id']} ({r['ip']}): {r['label']} ({r['reason']})")
    return 0


def _find_ground_truth(out_dir: Path) -> Path | None:
    package_root = Path(__file__).resolve().parents[1]
    candidates = (
        Path("lab/ground_truth.yaml"),
        out_dir / "ground_truth.yaml",
        package_root / "ground_truth.yaml",
        package_root / "lab" / "ground_truth.yaml",
    )
    return next((path for path in candidates if path.exists()), None)


def _cmd_compare(args: argparse.Namespace) -> int:
    # Load predictions from previous scan output.
    results_path = Path(args.out) / "results.json"
    if not results_path.exists():
        print(f"no results found at {results_path}; run `scan` first.", file=sys.stderr)
        return 1
    report = json.loads(results_path.read_text(encoding="utf-8"))
    predictions = report.get("predictions", {})

    gt_path = _find_ground_truth(Path(args.out))
    if gt_path is None:
        print("ground_truth.yaml not found", file=sys.stderr)
        return 1
    with gt_path.open("r", encoding="utf-8") as fh:
        gt_data = yaml.safe_load(fh) or {}
    ground_truth = {t["id"]: t["expected_label"] for t in gt_data.get("targets", [])}

    comparison = compare(predictions, ground_truth, LAB_CAUSES)
    labels = list(comparison.confusion_matrix)
    column_width = max(18, *(len(label) for label in labels))
    print("\nconfusion matrix (rows=truth, columns=predicted):")
    print(f"{'truth / predicted':>{column_width}} " + " ".join(
        f"{label:>{column_width}}" for label in labels
    ))
    for truth, row in comparison.confusion_matrix.items():
        print(
            f"{truth:>{column_width}} "
            + " ".join(f"{row[label]:>{column_width}}" for label in labels)
        )
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
    results_path = Path(args.out) / "results.json"
    if not results_path.exists():
        print(f"no results found at {results_path}; run `scan` first.", file=sys.stderr)
        return 1
    report = json.loads(results_path.read_text(encoding="utf-8"))
    results_report = {
        "run_metadata": report.get("run_metadata", {}),
        "results": report.get("results", []),
        "predictions": report.get("predictions", {}),
    }

    # find paths for config hash
    scope_path = Path(args.scope) if getattr(args, "scope", None) else Path("config/scope.yaml")
    rate_path = Path(args.rate) if getattr(args, "rate", None) else Path("config/rate.yaml")
    if not scope_path.exists():
        scope_path = Path(__file__).resolve().parents[1] / "config" / "scope.yaml"
    if not rate_path.exists():
        rate_path = Path(__file__).resolve().parents[1] / "config" / "rate.yaml"

    seed = report.get("run_metadata", {}).get("seed", getattr(args, "seed", "default"))

    # Load the comparison when ground truth is available.
    comparison = None
    gt_path = _find_ground_truth(Path(args.out))
    if gt_path is not None:
        with gt_path.open("r", encoding="utf-8") as fh:
            gt_data = yaml.safe_load(fh) or {}
        ground_truth = {t["id"]: t["expected_label"] for t in gt_data.get("targets", [])}
        predictions = results_report.get("predictions", {})
        comparison = compare(predictions, ground_truth, LAB_CAUSES)
    else:
        print("ground_truth.yaml not found; generating reports without comparison.", file=sys.stderr)

    paths = generate_reports(
        args.out,
        results_report,
        scope_path=scope_path,
        rate_path=rate_path,
        seed=seed,
        comparison=comparison,
    )
    print(f"reports written: {paths['results_json']}, {paths['results_csv']}, {paths['report_html']}")
    if comparison is not None:
        print(f"accuracy: {comparison.accuracy:.1%} ({comparison.correct}/{comparison.total})")
    return 0


def _cmd_verify_stability(args: argparse.Namespace) -> int:
    if args.runs < 2:
        print("stability verification requires at least two runs", file=sys.stderr)
        return 2
    out_dir = Path(args.out)
    predictions: list[dict[str, str]] = []
    for run_number in range(1, args.runs + 1):
        run_out = out_dir / f"run{run_number}"
        scan_args = argparse.Namespace(
            scope=args.scope,
            rate=args.rate,
            out=str(run_out),
            seed=args.seed,
            auth_log=args.auth_log,
        )
        status = _cmd_scan(scan_args)
        if status != 0:
            return status
        report_path = run_out / "results.json"
        predictions.append(
            json.loads(report_path.read_text(encoding="utf-8")).get("predictions", {})
        )

    target_ids = sorted(set().union(*(run.keys() for run in predictions)))
    mismatches = [
        target_id
        for target_id in target_ids
        if len({run.get(target_id) for run in predictions}) != 1
    ]
    if mismatches:
        print(
            f"label stability failed: {len(target_ids) - len(mismatches)}/"
            f"{len(target_ids)} targets agree across {args.runs} runs",
            file=sys.stderr,
        )
        for target_id in mismatches:
            labels = ", ".join(str(run.get(target_id, "missing")) for run in predictions)
            print(f"  {target_id}: {labels}", file=sys.stderr)
        return 1

    print(f"label stability passed: all {len(target_ids)} targets agree across {args.runs} runs")
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    import subprocess

    try:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / "run_demo.py")],
            check=False,
        )
    except OSError as exc:
        print(f"demo could not start: {exc}", file=sys.stderr)
        return 1
    return result.returncode


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
    p_scan.add_argument(
        "--log-wait",
        type=float,
        default=6.0,
        help="seconds to poll the auth-zone log for nonce evidence",
    )
    p_scan.add_argument(
        "--skip-selfcheck",
        action="store_true",
        help="skip the canary attribution self-check (not recommended)",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_compare = sub.add_parser("compare", help="compare results to ground truth")
    p_compare.add_argument("--out", default=DEFAULT_OUT, help="output directory")
    p_compare.set_defaults(func=_cmd_compare)

    p_report = sub.add_parser("report", help="write JSON/CSV/HTML reports")
    p_report.add_argument("--out", default=DEFAULT_OUT, help="output directory")
    p_report.add_argument("--scope", help="path to scope.yaml")
    p_report.add_argument("--rate", help="path to rate.yaml")
    p_report.add_argument("--seed", default="default")
    p_report.set_defaults(func=_cmd_report)

    p_stability = sub.add_parser(
        "verify-stability", help="repeat scans and require identical labels"
    )
    p_stability.add_argument("--scope", required=True, help="path to scope.yaml")
    p_stability.add_argument("--rate", required=True, help="path to rate.yaml")
    p_stability.add_argument("--out", default="out/stability", help="output directory")
    p_stability.add_argument("--seed", default="stability")
    p_stability.add_argument("--auth-log", default=DEFAULT_AUTH_LOG)
    p_stability.add_argument("--runs", type=int, default=3)
    p_stability.set_defaults(func=_cmd_verify_stability)

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
