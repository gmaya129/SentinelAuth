import csv
from typing import Dict, Any, List
from utils import safe_json

def write_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(safe_json(data))

def write_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        with open(path, "w", newline="", encoding="utf-8") as f:
            f.write("")
        return

    # flatten shallow dicts only (keep nested as JSON strings)
    fieldnames = sorted({k for r in rows for k in r.keys()})
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            out = {}
            for k, v in r.items():
                if isinstance(v, (dict, list)):
                    out[k] = safe_json(v)
                else:
                    out[k] = v
            w.writerow(out)
