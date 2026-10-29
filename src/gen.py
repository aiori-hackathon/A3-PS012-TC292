from pathlib import Path
import json
import yaml
import csv
from datetime import datetime, timezone
from dnsassess.comparator import compare, LAB_CAUSES

base = Path("/app")
outd = base / "out"
outd.mkdir(parents=True, exist_ok=True)
data = json.loads((outd / "results.json").read_text())
res = {"results": data.get("results", []), "predictions": data.get("predictions", {})}
gt_data = yaml.safe_load((base / "ground_truth.yaml").read_text())
gtmap = {t["id"]: t["expected_label"] for t in gt_data.get("targets", [])}
comp = compare(res["predictions"], gtmap, LAB_CAUSES)

run_meta = {"tool_version": "0.0.0", "seed": "default", "config_hash": "", "scope_path": str(base / "config" / "scope.yaml"), "rate_path": str(base / "config" / "rate.yaml"), "start_time": datetime.now(timezone.utc).isoformat(), "end_time": datetime.now(timezone.utc).isoformat()}
full = {"run_metadata": run_meta, "results": res["results"], "predictions": res["predictions"]}
(outd / "results.json").write_text(json.dumps(full, indent=2) + "\n")

with (outd / "results.csv").open("w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=["id", "name", "ip", "label", "reason", "via_forwarder", "latency_ms"])
    w.writeheader()
    for r in res["results"]:
        pa = r.get("probe_a") or {}
        w.writerow({"id": r.get("target_id"), "name": r.get("name"), "ip": r.get("ip"), "label": r.get("label"), "reason": r.get("reason"), "via_forwarder": r.get("via_forwarder"), "latency_ms": pa.get("response_time_ms")})

html = []
html.append('<html><head><meta charset="utf-8"><title>DNSAssess Report</title></head><body>')
html.append('<h1>DNS Resolver Exposure Assessment Report</h1>')
html.append('<p>Accuracy: {:.1%} ({}/{})</p>'.format(comp.accuracy, comp.correct, comp.total))
html.append('<h2>Summary</h2><ul>')
counts = {}
for r in res["results"]:
    counts[r.get("label")] = counts.get(r.get("label"), 0) + 1
for k in ["Recursive", "Authoritative-only", "Refused", "Inconclusive"]:
    html.append('<li>' + k + ': ' + str(counts.get(k, 0)) + '</li>')
html.append('</ul>')
html.append('<h2>Per-target results</h2><table border="1" cellpadding="4"><tr><th>ID</th><th>Name</th><th>IP</th><th>Label</th><th>Reason</th><th>via_forwarder</th><th>latency_ms</th></tr>')
for r in res["results"]:
    lbl = r.get("label", "")
    color = "#d4edda" if lbl == "Recursive" else "#f8d7da" if lbl == "Inconclusive" else "#e2e3e5"
    pa = r.get("probe_a") or {}
    html.append('<tr style="background:' + color + '"><td>' + str(r.get("target_id")) + '</td><td>' + str(r.get("name")) + '</td><td>' + str(r.get("ip")) + '</td><td>' + str(lbl) + '</td><td>' + str(r.get("reason")) + '</td><td>' + str(r.get("via_forwarder")) + '</td><td>' + str(pa.get("response_time_ms")) + '</td></tr>')
html.append('</table>')
if comp.mismatches:
    html.append('<h2>Error Analysis</h2><ul>')
    for m in comp.mismatches:
        html.append('<li>' + m.target_id + ': truth=' + m.truth + ' predicted=' + m.predicted + ' cause=' + m.cause + ' - ' + m.explanation + '</li>')
    html.append('</ul>')
html.append('<h2>Remediation</h2><div style="border:1px solid #ccc;padding:1em;background:#fff3cd;"><strong>For Recursive targets:</strong> Restrict recursion to intended clients with an access control list (RFC 5358 / BCP 140). Block outside access to recursive service.</div>')
html.append('</body></html>')
(outd / "report.html").write_text('\n'.join(html))
print("done")
