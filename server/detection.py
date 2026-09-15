import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .config import RULES_PATH, BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW, ALERT_COOLDOWN
from .db import query

_last_alert = {}

def now():
    return datetime.now(timezone.utc)

def load_rules():
    try:
        return json.loads(Path(RULES_PATH).read_text())
    except Exception:
        return []

def matches(event, conditions):
    for key, expected in conditions.items():
        actual = str(event.get(key) or "").lower()
        vals = expected if isinstance(expected, list) else [expected]
        ok = False
        for value in vals:
            value = str(value)
            if value.lower().startswith("regex:"):
                ok |= bool(re.search(value[6:], actual, re.I))
            else:
                ok |= value.lower() in actual
        if not ok:
            return False
    return True

def detect(event):
    # Baseline telemetry is deliberately excluded from security detections.
    if event.get("event_type") in {"system_metrics", "process_inventory", "network_inventory"}:
        return []

    matched = []

    for rule in load_rules():
        if not rule.get("enabled", True):
            continue

        if not matches(event, rule.get("conditions", {})):
            continue

        # Prevent the same rule from generating an alert for every
        # repeated telemetry event during the configured cooldown.
        rule_id = rule.get("id")
        cooldown_key = f"rule:{rule_id}"

        if (
            cooldown_key in _last_alert
            and (now() - _last_alert[cooldown_key]).total_seconds() < ALERT_COOLDOWN
        ):
            continue

        _last_alert[cooldown_key] = now()
        matched.append(rule)

    return matched

def failed_login_correlation(event):
    if event.get("event_type") != "login_failed" or not event.get("src_ip"):
        return None
    cutoff = (now() - timedelta(seconds=BRUTE_FORCE_WINDOW)).isoformat()
    rows = query("SELECT timestamp FROM events WHERE event_type='login_failed' AND src_ip=? AND timestamp>=?",
                 (event["src_ip"], cutoff))
    count = len(rows)
    if count < BRUTE_FORCE_THRESHOLD:
        return None
    key = event["src_ip"]
    if key in _last_alert and (now() - _last_alert[key]).total_seconds() < ALERT_COOLDOWN:
        return None
    _last_alert[key] = now()
    return {
        "id": "CORR-001",
        "title": f"Brute-force authentication detected from {event['src_ip']}",
        "description": f"{count} failed authentication attempts from {event['src_ip']} within {BRUTE_FORCE_WINDOW//60} minutes.",
        "severity": "critical" if count >= 12 else "high",
        "risk": min(98, 65 + count * 4),
        "tactic": "Credential Access",
        "technique": "T1110 Brute Force",
    }

def ioc_matches(event):
    haystack = " ".join(str(event.get(k) or "") for k in
                         ["message", "src_ip", "dst_ip", "process", "command", "user"]).lower()
    return [ioc for ioc in query("SELECT * FROM iocs") if ioc["value"].lower() in haystack]
