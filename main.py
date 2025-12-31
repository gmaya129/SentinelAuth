import argparse
from typing import List, Dict, Any

from config import Config
from parsers import iter_events, Event
from rules import detect_rule_alerts
from feature_engineering import build_bucket_rows
from ml_models import (
    train_model,
    save_bundle,
    load_bundle,
    score_rows,
    compute_baseline_stats,
    explain_anomaly,
)
from reporting import write_json, write_csv


# ---------- helpers ----------

def read_events(path: str, cfg: Config) -> List[Event]:
    """
    Safely read and parse all log lines into Event objects.
    """
    return list(iter_events(path, max_len=cfg.max_line_length))


# ---------- TRAIN MODE ----------

def run_train(train_log: str, model_out: str, cfg: Config) -> Dict[str, Any]:
    """
    Train an unsupervised ML baseline from historical logs.
    """
    events = read_events(train_log, cfg)

    # Build hourly feature rows (IP + user)
    rows = build_bucket_rows(events, bucket_minutes=cfg.bucket_minutes)

    if len(rows) < cfg.min_rows_for_ml:
        raise SystemExit(
            f"Not enough data to train ML model "
            f"(have {len(rows)}, need {cfg.min_rows_for_ml})"
        )

    # Train IsolationForest
    bundle = train_model(rows, contamination=cfg.contamination)
    save_bundle(bundle, model_out)

    # Compute baseline stats (used later for explanations)
    baseline_stats = compute_baseline_stats(rows)

    return {
        "mode": "train",
        "log_file": train_log,
        "model_path": model_out,
        "total_events": len(events),
        "feature_rows": len(rows),
        "baseline_stats": baseline_stats,
    }


# ---------- DETECT MODE ----------

def run_detect(detect_log: str, model_in: str, cfg: Config) -> Dict[str, Any]:
    """
    Detect brute-force attacks + ML anomalies using a trained baseline.
    """
    events = read_events(detect_log, cfg)

    # --- Rule-based detection ---
    rule_alerts = detect_rule_alerts(
        events,
        window_seconds=cfg.rule_window_seconds,
        brute_force_threshold=cfg.brute_force_threshold,
        spray_user_threshold=cfg.spray_user_threshold,
        distributed_ip_threshold=cfg.distributed_ip_threshold,
    )

    # --- ML detection ---
    rows = build_bucket_rows(events, bucket_minutes=cfg.bucket_minutes)

    ml_results = []
    anomalies = []
    ml_used = False

    if cfg.use_ml and len(rows) >= cfg.min_rows_for_ml:
        bundle = load_bundle(model_in)
        scored = score_rows(bundle, rows)

        baseline_stats = compute_baseline_stats(rows)

        for s in scored:
            if s["is_anomaly"]:
                explanation = explain_anomaly(s, baseline_stats)
                anomalies.append({**s, "explanation": explanation})

        # Keep report readable
        anomalies = anomalies[:50]
        ml_used = True

    return {
        "mode": "detect",
        "log_file": detect_log,
        "total_events": len(events),
        "rules": {
            "alert_count": len(rule_alerts),
            "alerts": rule_alerts,
        },
        "ml": {
            "enabled": cfg.use_ml,
            "used": ml_used,
            "model_path": model_in if cfg.use_ml else None,
            "bucket_minutes": cfg.bucket_minutes,
            "feature_rows": len(rows),
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
        },
    }


# ---------- CLI ----------

def main():
    parser = argparse.ArgumentParser(
        description="SentinelAuth — Hybrid Log Intrusion Detector (Rules + ML)"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ---- train ----
    train_cmd = sub.add_parser("train", help="Train ML baseline from historical logs")
    train_cmd.add_argument("--log", required=True, help="Baseline log file")
    train_cmd.add_argument(
        "--model-out", default="baseline_model.joblib", help="Output model file"
    )
    train_cmd.add_argument(
        "--bucket-minutes", type=int, default=60, help="Time bucket size (minutes)"
    )
    train_cmd.add_argument(
        "--contamination", type=float, default=0.02, help="Expected anomaly fraction"
    )

    # ---- detect ----
    detect_cmd = sub.add_parser("detect", help="Detect attacks using trained model")
    detect_cmd.add_argument("--log", required=True, help="Log file to analyze")
    detect_cmd.add_argument(
        "--model-in", default="baseline_model.joblib", help="Baseline model file"
    )
    detect_cmd.add_argument("--prefix", default="report", help="Output file prefix")
    detect_cmd.add_argument(
        "--no-ml", action="store_true", help="Disable ML anomaly detection"
    )

    args = parser.parse_args()

    if args.command == "train":
        cfg = Config(
            bucket_minutes=args.bucket_minutes,
            contamination=args.contamination,
        )
        result = run_train(args.log, args.model_out, cfg)
        write_json("training_summary.json", result)
        print("Training complete.")
        print("Saved model and training_summary.json")

    elif args.command == "detect":
        cfg = Config(
            output_prefix=args.prefix,
            use_ml=not args.no_ml,
        )
        result = run_detect(args.log, args.model_in, cfg)

        write_json(f"{cfg.output_prefix}.json", result)
        write_csv(f"{cfg.output_prefix}_rule_alerts.csv", result["rules"]["alerts"])
        write_csv(f"{cfg.output_prefix}_ml_anomalies.csv", result["ml"]["anomalies"])

        print("Detection complete.")
        print(f"Wrote {cfg.output_prefix}.json")
        print(f"Wrote {cfg.output_prefix}_rule_alerts.csv")
        print(f"Wrote {cfg.output_prefix}_ml_anomalies.csv")


if __name__ == "__main__":
    main()
