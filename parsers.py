from dataclasses import dataclass
from typing import Iterator, Optional
import re
from dateutil import parser as dtparser

from utils import sanitize_text, clamp_line

@dataclass(frozen=True)
class Event:
    ts_iso: Optional[str]   # parsed ISO timestamp (best effort)
    action: str             # "fail" | "success" | "other"
    user: Optional[str]
    ip: Optional[str]
    service: Optional[str]
    message: str            # sanitized line

# Common sshd patterns
SSH_FAIL_RE = re.compile(
    r"(Failed password)\s+for\s+(invalid user\s+)?(?P<user>[^\s]+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE
)
SSH_OK_RE = re.compile(
    r"(Accepted password|Accepted publickey)\s+for\s+(?P<user>[^\s]+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE
)

# Syslog timestamp at start: "Dec 26 12:34:56 ..."
SYSLOG_TS_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+")
SERVICE_RE = re.compile(r"\b(sshd|sudo|login|su|pam_unix)\b", re.IGNORECASE)

def _parse_ts(line: str) -> Optional[str]:
    m = SYSLOG_TS_RE.match(line)
    if not m:
        return None
    raw = m.group("ts")
    try:
        # dtparser will assume current year if missing; good enough for bucket baselines
        return dtparser.parse(raw).isoformat()
    except Exception:
        return None

def _service(line: str) -> Optional[str]:
    m = SERVICE_RE.search(line)
    return m.group(1).lower() if m else None

def parse_line(line: str, max_len: int) -> Event:
    line = clamp_line(line.rstrip("\n"), max_len)
    line = sanitize_text(line)

    ts_iso = _parse_ts(line)
    service = _service(line)

    m = SSH_FAIL_RE.search(line)
    if m:
        return Event(ts_iso=ts_iso, action="fail", user=m.group("user"), ip=m.group("ip"), service=service, message=line)

    m = SSH_OK_RE.search(line)
    if m:
        return Event(ts_iso=ts_iso, action="success", user=m.group("user"), ip=m.group("ip"), service=service, message=line)

    return Event(ts_iso=ts_iso, action="other", user=None, ip=None, service=service, message=line)

def iter_events(path: str, max_len: int) -> Iterator[Event]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield parse_line(line, max_len=max_len)
