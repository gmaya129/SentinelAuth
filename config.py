from dataclasses import dataclass

@dataclass(frozen=True)
class Config:
    # safety
    max_line_length: int = 10_000

    # time bucketing
    bucket_minutes: int = 60  # hourly features

    # rules (sliding windows)
    rule_window_seconds: int = 10 * 60
    brute_force_threshold: int = 8
    spray_user_threshold: int = 6         # many usernames from one IP in window
    distributed_ip_threshold: int = 6     # many IPs against one user in window

    # ML
    use_ml: bool = True
    contamination: float = 0.02
    min_rows_for_ml: int = 10  # minimum bucketed entity-rows to train / detect

    # output
    output_prefix: str = "report"
