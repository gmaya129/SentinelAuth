from collections import defaultdict, deque
from typing import Dict, Any, List, Optional
from dateutil import parser as dtparser

from parsers import Event

def _dt(ts_iso: Optional[str]):
    if not ts_iso:
        return None
    try:
        return dtparser.parse(ts_iso)
    except Exception:
        return None

def detect_rule_alerts(
    events: List[Event],
    window_seconds: int,
    brute_force_threshold: int,
    spray_user_threshold: int,
    distributed_ip_threshold: int
) -> List[Dict[str, Any]]:
    fail_events = [e for e in events if e.action == "fail" and (e.ip or e.user)]
    have_time = any(e.ts_iso for e in fail_events)

    ip_fails = defaultdict(deque)            # ip -> deque(time or index)
    ip_users = defaultdict(deque)           # ip -> deque((time/index, user))
    user_fails = defaultdict(deque)         # user -> deque(time or index)
    user_ips = defaultdict(deque)           # user -> deque((time/index, ip))

    def prune_time(dq: deque, now):
        while dq and (now - dq[0]).total_seconds() > window_seconds:
            dq.popleft()

    def prune_pairs(dq: deque, now):
        while dq and (now - dq[0][0]).total_seconds() > window_seconds:
            dq.popleft()

    alerts: List[Dict[str, Any]] = []

    for idx, ev in enumerate(fail_events):
        now = _dt(ev.ts_iso) if have_time else None
        ip = ev.ip
        user = ev.user

        # Per-IP windows
        if ip:
            if have_time and now:
                prune_time(ip_fails[ip], now)
                ip_fails[ip].append(now)
                prune_pairs(ip_users[ip], now)
                ip_users[ip].append((now, user))
            else:
                ip_fails[ip].append(idx)
                while ip_fails[ip] and (idx - ip_fails[ip][0]) > brute_force_threshold * 5:
                    ip_fails[ip].popleft()
                ip_users[ip].append((idx, user))
                while ip_users[ip] and (idx - ip_users[ip][0][0]) > brute_force_threshold * 5:
                    ip_users[ip].popleft()

            if len(ip_fails[ip]) >= brute_force_threshold:
                alerts.append({
                    "type": "rule_bruteforce_ip",
                    "ip": ip,
                    "count": len(ip_fails[ip]),
                    "window_seconds": window_seconds if have_time else None,
                    "sample_line": ev.message,
                })

            distinct_users = {u for _, u in ip_users[ip] if u}
            if len(distinct_users) >= spray_user_threshold:
                alerts.append({
                    "type": "rule_password_spray_ip",
                    "ip": ip,
                    "distinct_users_in_window": len(distinct_users),
                    "users": sorted(list(distinct_users))[:50],
                    "window_seconds": window_seconds if have_time else None,
                    "sample_line": ev.message,
                })

        # Per-user windows
        if user:
            if have_time and now:
                prune_time(user_fails[user], now)
                user_fails[user].append(now)
                prune_pairs(user_ips[user], now)
                user_ips[user].append((now, ip))
            else:
                user_fails[user].append(idx)
                while user_fails[user] and (idx - user_fails[user][0]) > brute_force_threshold * 5:
                    user_fails[user].popleft()
                user_ips[user].append((idx, ip))
                while user_ips[user] and (idx - user_ips[user][0][0]) > brute_force_threshold * 5:
                    user_ips[user].popleft()

            if len(user_fails[user]) >= brute_force_threshold:
                alerts.append({
                    "type": "rule_bruteforce_user",
                    "user": user,
                    "count": len(user_fails[user]),
                    "window_seconds": window_seconds if have_time else None,
                    "sample_line": ev.message,
                })

            distinct_ips = {i for _, i in user_ips[user] if i}
            if len(distinct_ips) >= distributed_ip_threshold:
                alerts.append({
                    "type": "rule_distributed_attack_user",
                    "user": user,
                    "distinct_ips_in_window": len(distinct_ips),
                    "ips": sorted(list(distinct_ips))[:50],
                    "window_seconds": window_seconds if have_time else None,
                    "sample_line": ev.message,
                })

    # De-dupe by signature to reduce spam
    seen = set()
    out = []
    for a in alerts:
        sig = (a.get("type"), a.get("ip"), a.get("user"))
        if sig in seen:
            continue
        seen.add(sig)
        out.append(a)
    return out
