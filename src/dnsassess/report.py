"""Report generation for JSON, CSV and HTML outputs.

Phase 4: writes results.json, results.csv, report.html with run metadata,
confusion matrix, error analysis and remediation advice.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import config_hash as hash_config_files

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except Exception:  # pragma: no cover
    Environment = None  # type: ignore
    FileSystemLoader = None  # type: ignore
    select_autoescape = None  # type: ignore


try:
    from importlib import metadata
    __version__ = metadata.version("dnsassess")
except Exception:
    __version__ = "0.0.0"


def build_run_metadata(
    scope_path: Path | str | None,
    rate_path: Path | str | None,
    seed: str,
    start_time: datetime,
    end_time: datetime,
) -> dict[str, Any]:
    """Build metadata shared by scan and report outputs."""
    scope_path_p = Path(scope_path) if scope_path else None
    rate_path_p = Path(rate_path) if rate_path else None
    config_hash = ""
    if scope_path_p and rate_path_p and scope_path_p.exists() and rate_path_p.exists():
        config_hash = hash_config_files(scope_path_p, rate_path_p)

    return {
        "tool_version": __version__,
        "seed": seed,
        "config_hash": config_hash,
        "scope_path": str(scope_path_p) if scope_path_p else None,
        "rate_path": str(rate_path_p) if rate_path_p else None,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
    }


def generate_reports(
    out_dir: Path | str,
    results_report: dict[str, Any],
    scope_path: Path | str | None = None,
    rate_path: Path | str | None = None,
    seed: str = "default",
    comparison: Any | None = None,
) -> dict[str, Path]:
    """Generate JSON, CSV and HTML reports in out_dir."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    results = results_report.get("results", [])
    predictions = results_report.get("predictions", {})
    run_meta = dict(results_report.get("run_metadata") or {})
    if not run_meta:
        now = datetime.now(timezone.utc)
        run_meta = build_run_metadata(scope_path, rate_path, seed, now, now)
    else:
        run_meta.setdefault("seed", seed)
        run_meta.setdefault("tool_version", __version__)
        run_meta.setdefault("scope_path", str(scope_path) if scope_path else None)
        run_meta.setdefault("rate_path", str(rate_path) if rate_path else None)

    # results.json (full evidence per target) - include run metadata
    results_json_path = out_dir / "results.json"
    full_report = {
        "run_metadata": run_meta,
        "results": results,
        "predictions": predictions,
    }
    results_json_path.write_text(json.dumps(full_report, indent=2) + "\n", encoding="utf-8")

    # results.csv
    csv_path = out_dir / "results.csv"
    metadata_fields = {
        "run_tool_version": run_meta.get("tool_version", ""),
        "run_seed": run_meta.get("seed", ""),
        "run_config_hash": run_meta.get("config_hash", ""),
        "run_scope_path": run_meta.get("scope_path", ""),
        "run_rate_path": run_meta.get("rate_path", ""),
        "run_start_time": run_meta.get("start_time", ""),
        "run_end_time": run_meta.get("end_time", ""),
    }
    fieldnames = [
        "id", "name", "ip", "label", "reason", "via_forwarder", "latency_ms",
        *metadata_fields,
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for r in results:
            pa = r.get("probe_a") or {}
            latency_ms = pa.get("response_time_ms")
            w.writerow(
                {
                    "id": r.get("target_id"),
                    "name": r.get("name"),
                    "ip": r.get("ip"),
                    "label": r.get("label"),
                    "reason": r.get("reason"),
                    "via_forwarder": r.get("via_forwarder"),
                    "latency_ms": latency_ms,
                    **metadata_fields,
                }
            )

    # HTML report
    html_path = out_dir / "report.html"
    _write_html(html_path, full_report, comparison, run_meta)

    return {
        "results_json": results_json_path,
        "results_csv": csv_path,
        "report_html": html_path,
    }


def _write_html(
    html_path: Path,
    full_report: dict[str, Any],
    comparison: Any | None,
    run_meta: dict[str, Any],
) -> None:
    results = full_report.get("results", [])
    # counts
    counts: dict[str, int] = {}
    for r in results:
        lbl = r.get("label", "Unknown")
        counts[lbl] = counts.get(lbl, 0) + 1

    # try to use template
    template_path = Path(__file__).resolve().parent / "templates" / "report.html.j2"
    if Environment and template_path.exists():
        env = Environment(
            loader=FileSystemLoader(str(template_path.parent)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        tmpl = env.get_template(template_path.name)
        html = tmpl.render(
            results=results,
            counts=counts,
            comparison=comparison,
            run_meta=run_meta,
        )
        html_path.write_text(html, encoding="utf-8")
        return

    # fallback minimal HTML
    html_lines = []
    html_lines.append("<html><head><meta charset='utf-8'><title>DNSAssess Report</title></head><body>")
    html_lines.append("<h1>DNS Resolver Exposure Assessment Report</h1>")
    html_lines.append(
        "<p>"
        f"Tool: {run_meta.get('tool_version')} | Seed: {run_meta.get('seed')} | "
        f"Config hash: {run_meta.get('config_hash')} | "
        f"Start: {run_meta.get('start_time')} | End: {run_meta.get('end_time')}"
        "</p>"
    )
    html_lines.append("<h2>Summary</h2><ul>")
    for k in ["Recursive", "Authoritative-only", "Refused", "Inconclusive"]:
        html_lines.append(f"<li>{k}: {counts.get(k,0)}</li>")
    html_lines.append("</ul>")
    html_lines.append("<h2>Per-target results</h2><table border='1' cellpadding='4'>")
    html_lines.append("<tr><th>ID</th><th>Name</th><th>IP</th><th>Label</th><th>Reason</th><th>via_forwarder</th><th>latency_ms</th></tr>")
    for r in results:
        lbl = r.get("label","")
        color = {
            "Recursive": "#d4edda",
            "Authoritative-only": "#dbeafe",
            "Refused": "#fef3c7",
            "Inconclusive": "#f8d7da",
        }.get(lbl, "#e2e3e5")
        pa = r.get("probe_a") or {}
        latency_ms = pa.get("response_time_ms")
        latency_text = f"{latency_ms:.2f}" if isinstance(latency_ms, (int, float)) else ""
        html_lines.append(
            f"<tr style='background:{color}'><td>{r.get('target_id')}</td><td>{r.get('name')}</td><td>{r.get('ip')}</td><td>{lbl}</td><td>{r.get('reason')}</td><td>{r.get('via_forwarder')}</td><td>{latency_text}</td></tr>"
        )
    html_lines.append("</table>")
    if comparison is not None:
        html_lines.append("<h2>Confusion Matrix</h2>")
        html_lines.append(f"<p>Accuracy: {getattr(comparison,'accuracy',0):.1%} ({getattr(comparison,'correct',0)}/{getattr(comparison,'total',0)})</p>")
        labels = list(comparison.confusion_matrix)
        html_lines.append("<table border='1' cellpadding='4'><tr><th>Truth / Predicted</th>")
        html_lines.extend(f"<th>{label}</th>" for label in labels)
        html_lines.append("</tr>")
        for truth, row in comparison.confusion_matrix.items():
            html_lines.append(f"<tr><th>{truth}</th>")
            html_lines.extend(f"<td>{row.get(label, 0)}</td>" for label in labels)
            html_lines.append("</tr>")
        html_lines.append("</table>")
        if getattr(comparison,'mismatches',None):
            html_lines.append("<h3>Error Analysis</h3><ul>")
            for m in comparison.mismatches:
                html_lines.append(f"<li>{m.target_id}: truth={m.truth} pred={m.predicted} cause={m.cause} - {m.explanation}</li>")
            html_lines.append("</ul>")
    html_lines.append("<h2>Remediation</h2>")
    recursive_results = [r for r in results if r.get("label") == "Recursive"]
    if recursive_results:
        for result in recursive_results:
            html_lines.append(
                f"<p><strong>{result.get('target_id')} ({result.get('name')}):</strong> "
                "Restrict recursion to intended clients with an access control list "
                "(RFC 5358 / BCP 140). Block outside access to recursive service.</p>"
            )
    else:
        html_lines.append("<p>No Recursive targets were identified.</p>")
    html_lines.append("</body></html>")
    html_path.write_text("\n".join(html_lines), encoding="utf-8")
