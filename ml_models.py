from dataclasses import dataclass
from typing import Dict, Any, List, Tuple
import joblib

from sklearn.ensemble import IsolationForest

from feature_engineering import Row, rows_to_matrix
from utils import pct

@dataclass(frozen=True)
class ModelBundle:
    model: Any
    feature_order: List[str]

FEATURE_ORDER = ["total", "fails", "success", "distinct_counterpart", "fail_rate"]

def train_model(rows: List[Row], contamination: float) -> ModelBundle:
    keys, X = rows_to_matrix(rows)
    model = IsolationForest(
        n_estimators=250,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X)
    return ModelBundle(model=model, feature_order=list(FEATURE_ORDER))

def save_bundle(bundle: ModelBundle, path: str) -> None:
    joblib.dump({"model": bundle.model, "feature_order": bundle.feature_order}, path)

def load_bundle(path: str) -> ModelBundle:
    d = joblib.load(path)
    return ModelBundle(model=d["model"], feature_order=d["feature_order"])

def score_rows(bundle: ModelBundle, rows: List[Row]) -> List[Dict[str, Any]]:
    keys, X = rows_to_matrix(rows)
    # decision_function: higher = more normal
    scores = bundle.model.decision_function(X)
    preds = bundle.model.predict(X)  # -1 anomaly, 1 normal

    results = []
    for k, s, p, r in zip(keys, scores, preds, rows):
        results.append({
            "key": k,
            "entity_type": r.entity_type,
            "entity": r.entity,
            "bucket_start": r.bucket_start,
            "score": float(s),
            "is_anomaly": (int(p) == -1),
            "features": r.features,
            "context": r.context,
        })

    # sort anomalies first (most suspicious = lowest score)
    results.sort(key=lambda x: x["score"])
    return results

def explain_anomaly(scored_row: Dict[str, Any], baseline_stats: Dict[str, Dict[str, float]]) -> Dict[str, Any]:
    """
    baseline_stats: by entity_type -> { feature_mean_* and feature_std_* ... } (simple stats)
    We’ll provide human explanation: fail_rate, distinct counterpart count, fails spikes.
    """
    et = scored_row["entity_type"]
    feats = scored_row["features"]
    base = baseline_stats.get(et, {})

    def z(feature: str) -> float:
        mu = base.get(f"mean_{feature}", 0.0)
        sd = base.get(f"std_{feature}", 0.0)
        return ((feats.get(feature, 0.0) - mu) / sd) if sd else 0.0

    # The “why”
    reasons = []
    fr = feats.get("fail_rate", 0.0)
    fails = feats.get("fails", 0.0)
    distinct = feats.get("distinct_counterpart", 0.0)
    total = feats.get("total", 0.0)

    if fr >= 0.8 and total >= 5:
        reasons.append(f"Very high fail rate ({pct(fails, total):.1f}%).")
    if distinct >= 5:
        if et == "ip":
            reasons.append(f"Targeted many usernames in this hour (distinct users: {int(distinct)}).")
        else:
            reasons.append(f"Access attempts from many IPs in this hour (distinct IPs: {int(distinct)}).")
    if z("fails") >= 3.0:
        reasons.append("Failure count is a strong outlier vs baseline (z-score ≥ 3).")
    if z("distinct_counterpart") >= 3.0:
        reasons.append("Distinct counterpart count is a strong outlier vs baseline (z-score ≥ 3).")
    if not reasons:
        reasons.append("Behavior deviates from baseline feature distribution (model outlier).")

    return {
        "reasons": reasons,
        "z_scores": {
            "fails": z("fails"),
            "distinct_counterpart": z("distinct_counterpart"),
            "fail_rate": z("fail_rate"),
            "total": z("total"),
        }
    }

def compute_baseline_stats(rows: List[Row]) -> Dict[str, Dict[str, float]]:
    # simple mean/std per entity_type for explainability
    import math
    by_type = {"ip": [], "user": []}
    for r in rows:
        by_type[r.entity_type].append(r.features)

    out: Dict[str, Dict[str, float]] = {}
    for et, feats_list in by_type.items():
        if not feats_list:
            out[et] = {}
            continue

        stats: Dict[str, float] = {}
        for f in FEATURE_ORDER:
            xs = [float(d.get(f, 0.0)) for d in feats_list]
            mean = sum(xs) / len(xs)
            var = sum((x - mean) ** 2 for x in xs) / max(1, len(xs) - 1)
            sd = math.sqrt(var) if var > 0 else 0.0
            stats[f"mean_{f}"] = mean
            stats[f"std_{f}"] = sd
        out[et] = stats
    return out
