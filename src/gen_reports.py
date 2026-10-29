import json
from pathlib import Path
from dnsassess import report
from dnsassess.comparator import compare, LAB_CAUSES
import yaml

base = Path("/app")
if not base.exists():
    base = Path(__file__).resolve().parent
out = base / "out"
data = json.loads((out / "results.json").read_text())
res = {"results": data.get("results", []), "predictions": data.get("predictions", {})}
if (base / "ground_truth.yaml").exists():
    gt_data = yaml.safe_load((base / "ground_truth.yaml").read_text())
else:
    gt_data = yaml.safe_load((base / "lab" / "ground_truth.yaml").read_text())
gt = {t["id"]: t["expected_label"] for t in gt_data.get("targets", [])}
comp = compare(res["predictions"], gt, LAB_CAUSES)
paths = report.generate_reports(out, res, scope_path=base / "config" / "scope.yaml", rate_path=base / "config" / "rate.yaml", seed="default", comparison=comp)
print(paths)
