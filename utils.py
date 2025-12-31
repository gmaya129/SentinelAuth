import json
import re
from typing import Any, Iterable

# Remove control characters that can break logs or terminals
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")

def sanitize_text(s: str) -> str:
    return CONTROL_CHARS.sub("", s)

def clamp_line(line: str, max_len: int) -> str:
    if len(line) > max_len:
        return line[:max_len] + "…[TRUNCATED]"
    return line

def safe_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str)

def uniq_count(values: Iterable[Any]) -> int:
    return len(set(v for v in values if v is not None))

def pct(n: float, d: float) -> float:
    return (n / d) * 100.0 if d else 0.0
