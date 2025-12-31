from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from dateutil import parser as dtparser

from parsers import Event
from utils import uniq_count

@dataclass(frozen=True)
class Row:
    entity_type: str       # "ip" or "user"
    entity: str            # the IP or username
    bucket_start: str      # ISO time bucket start
    features: Dict[str, float]
    context: Dict[str, Any]  # for explainability / reporting

def _bucket_start(ts_iso: Optional[str], bucket_minutes: int) -> Optional[str]:
    if not ts_iso:
        return None
    try:
        dt = dtparser.parse(ts_iso)
        # Floor to bucket_minutes
        minute = (dt.minute // bucket_minutes) * bucket_minutes
        bucketed = dt.replace(minute=minute, second=0, microsecond=0)
        return bucketed.isoformat()
    except Exception:
        return None

def build_bucket_rows(events: List[Event], bucket_minutes: int) -> List[Row]:
    # Aggregate stats per (bucket, ip) and (bucket, user)
    ip_ag = defaultdict(lambda: {"total": 0, "fails": 0, "success": 0, "users": [], "sample": None})
    user_ag = defaultdict(lambda: {"total": 0, "fails": 0, "success": 0, "ips": [], "sample": None})

    for ev in events:
        b = _bucket_start(ev.ts_iso, bucket_minutes)
        if not b:
            continue

        if ev.ip:
            key = (b, ev.ip)
            s = ip_ag[key]
            s["total"] += 1
            if ev.action == "fail":
                s["fails"] += 1
            elif ev.action == "success":
                s["success"] += 1
            if ev.user:
                s["users"].append(ev.user)
            if s["sample"] is None and ev.action in ("fail", "success"):
                s["sample"] = ev.message

        if ev.user:
            key = (b, ev.user)
            s = user_ag[key]
            s["total"] += 1
            if ev.action == "fail":
                s["fails"] += 1
            elif ev.action == "success":
                s["success"] += 1
            if ev.ip:
                s["ips"].append(ev.ip)
            if s["sample"] is None and ev.action in ("fail", "success"):
                s["sample"] = ev.message

    rows: List[Row] = []

    for (b, ip), s in ip_ag.items():
        total = float(s["total"])
        fails = float(s["fails"])
        succ = float(s["success"])
        distinct_users = float(uniq_count(s["users"]))
        fail_rate = (fails / total) if total else 0.0

        rows.append(Row(
            entity_type="ip",
            entity=ip,
            bucket_start=b,
            features={
                "total": total,
                "fails": fails,
                "success": succ,
                "distinct_counterpart": distinct_users,  # users targeted
                "fail_rate": fail_rate,
            },
            context={
                "sample_line": s["sample"],
                "distinct_users": int(distinct_users),
            }
        ))

    for (b, user), s in user_ag.items():
        total = float(s["total"])
        fails = float(s["fails"])
        succ = float(s["success"])
        distinct_ips = float(uniq_count(s["ips"]))
        fail_rate = (fails / total) if total else 0.0

        rows.append(Row(
            entity_type="user",
            entity=user,
            bucket_start=b,
            features={
                "total": total,
                "fails": fails,
                "success": succ,
                "distinct_counterpart": distinct_ips,  # IPs hitting user
                "fail_rate": fail_rate,
            },
            context={
                "sample_line": s["sample"],
                "distinct_ips": int(distinct_ips),
            }
        ))

    return rows

def rows_to_matrix(rows: List[Row]) -> Tuple[List[str], List[List[float]]]:
    # stable feature order
    feat_order = ["total", "fails", "success", "distinct_counterpart", "fail_rate"]
    keys = [f"{r.entity_type}:{r.entity}@{r.bucket_start}" for r in rows]
    X = [[float(r.features.get(f, 0.0)) for f in feat_order] for r in rows]
    return keys, X
