from pathlib import Path
from datetime import datetime, timezone
import json
import re

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
STATE_FILE = DATA / "command_guard.json"
EVENT_FILE = DATA / "command_guard_events.jsonl"
ALLOWLIST_FILE = DATA / "command_guard_allowlist.json"

DEFAULT_STATE = {
    "enabled": True,
    "mode": "block",
    "updated_at": None
}

# Intentionally conservative: these target clearly destructive
# administrative commands rather than ordinary sudo usage.
PATTERNS = [
    (r'\bsudo\s+rm\s+-[^\n]*\brm\b', "Destructive sudo removal command"),
    (r'\brm\s+-[^\n]*(?:/|--no-preserve-root)', "Destructive filesystem removal command"),
    (r'\bsudo\s+mkfs(?:\.[A-Za-z0-9_-]+)?\b', "Filesystem formatting command"),
    (r'\bmkfs(?:\.[A-Za-z0-9_-]+)?\b', "Filesystem formatting command"),
    (r'\bdd\s+if=[^\s]+\s+of=/dev/', "Direct disk overwrite command"),
    (r'\bsudo\s+dd\s+.*\bof=/dev/', "Privileged disk overwrite command"),
    (r'\bwipefs\b', "Filesystem signature destruction command"),
    (r'\bsudo\s+(shutdown|reboot|poweroff|halt)\b', "System shutdown command"),
    (r'(^|[;&|]\s*)\:\(\)\s*\{\s*\:\s*\|\s*\:\s*&', "Fork bomb pattern"),
    (r'\bsudo\s+chmod\s+(?:-[Rr]\s+)?[0-7]*7[0-7]*\s+/', "Dangerous recursive permission change"),
    (r'\bsudo\s+chown\s+(?:-[Rr]\s+)?[^ ]+\s+/', "Dangerous recursive ownership change"),
]

def _ensure_state():
    DATA.mkdir(exist_ok=True)
    if not STATE_FILE.exists():
        STATE_FILE.write_text(json.dumps(DEFAULT_STATE, indent=2))

def get_state():
    _ensure_state()
    try:
        data = json.loads(STATE_FILE.read_text())
        return {
            "enabled": bool(data.get("enabled", True)),
            "mode": "block",
            "updated_at": data.get("updated_at")
        }
    except Exception:
        return dict(DEFAULT_STATE)

def set_enabled(enabled: bool):
    state = get_state()
    state["enabled"] = bool(enabled)
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    STATE_FILE.write_text(json.dumps(state, indent=2))
    return state


def allowed_commands():
    DATA.mkdir(exist_ok=True)

    if not ALLOWLIST_FILE.exists():
        ALLOWLIST_FILE.write_text("[]")

    try:
        data = json.loads(ALLOWLIST_FILE.read_text())
        if not isinstance(data, list):
            return []
        return [str(x) for x in data]
    except Exception:
        return []


def allow_command(command: str):
    command = (command or "").strip()

    if not command:
        return {"status": "error", "reason": "Empty command"}

    commands = allowed_commands()

    if command not in commands:
        commands.append(command)
        ALLOWLIST_FILE.write_text(
            json.dumps(commands, indent=2)
        )

    return {
        "status": "allowed",
        "command": command,
        "allowlist": commands
    }


def remove_allowed_command(command: str):
    command = (command or "").strip()
    commands = allowed_commands()

    if command in commands:
        commands.remove(command)
        ALLOWLIST_FILE.write_text(
            json.dumps(commands, indent=2)
        )

    return {
        "status": "removed",
        "command": command,
        "allowlist": commands
    }


def is_command_allowed(command: str):
    command = (command or "").strip()
    return command in allowed_commands()

def check_command(command: str):
    command = (command or "").strip()
    state = get_state()

    if not command:
        return {
            "suspicious": False,
            "blocked": False,
            "reason": None,
            "command": command
        }

    # Explicit SOC analyst allowlist takes precedence.
    if is_command_allowed(command):
        return {
            "suspicious": True,
            "blocked": False,
            "allowed": True,
            "reason": "Explicitly allowed by SOC analyst",
            "command": command
        }

    for pattern, reason in PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return {
                "suspicious": True,
                "blocked": bool(state["enabled"]),
                "allowed": False,
                "reason": reason,
                "command": command
            }

    return {
        "suspicious": False,
        "blocked": False,
        "allowed": False,
        "reason": None,
        "command": command
    }

def record_event(command: str, blocked: bool, reason: str):
    DATA.mkdir(exist_ok=True)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "blocked": bool(blocked),
        "reason": reason,
        "severity": "high",
        "technique": "T1059 Command and Scripting Interpreter",
        "source": "command_guard"
    }

    with EVENT_FILE.open("a") as f:
        f.write(json.dumps(event) + "\n")

    return event

def recent_events(limit=50):
    if not EVENT_FILE.exists():
        return []

    lines = EVENT_FILE.read_text().splitlines()[-max(1, int(limit)):]
    result = []

    for line in reversed(lines):
        try:
            result.append(json.loads(line))
        except Exception:
            continue

    return result
