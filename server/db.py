import sqlite3
from pathlib import Path
from .config import DB_PATH

def conn():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = conn()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS agents(
      id TEXT PRIMARY KEY, hostname TEXT, os TEXT, agent_version TEXT,
      first_seen TEXT, last_seen TEXT, status TEXT DEFAULT 'online'
    );
    CREATE TABLE IF NOT EXISTS events(
      id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, timestamp TEXT,
      event_type TEXT, severity TEXT, message TEXT, user TEXT,
      src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
      protocol TEXT, process TEXT, command TEXT, source TEXT, raw TEXT
    );
    CREATE TABLE IF NOT EXISTS metrics(
      id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, timestamp TEXT,
      cpu REAL, memory REAL, disk REAL, processes INTEGER
    );
    CREATE TABLE IF NOT EXISTS alerts(
      id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, agent_id TEXT,
      created_at TEXT, title TEXT, description TEXT, severity TEXT,
      risk INTEGER, status TEXT DEFAULT 'new', rule_id TEXT,
      tactic TEXT, technique TEXT
    );
    CREATE TABLE IF NOT EXISTS incidents(
      id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, updated_at TEXT,
      title TEXT, severity TEXT, risk INTEGER, status TEXT DEFAULT 'open',
      summary TEXT, owner TEXT
    );
    CREATE TABLE IF NOT EXISTS incident_alerts(
      incident_id INTEGER, alert_id INTEGER,
      PRIMARY KEY(incident_id, alert_id)
    );
    CREATE TABLE IF NOT EXISTS iocs(
      id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, value TEXT,
      severity TEXT DEFAULT 'high', description TEXT
    );
    CREATE TABLE IF NOT EXISTS rules(
      id TEXT PRIMARY KEY, title TEXT, description TEXT,
      severity TEXT, risk INTEGER, enabled INTEGER DEFAULT 1,
      tactic TEXT, technique TEXT, conditions TEXT
    );
    CREATE TABLE IF NOT EXISTS ip_bans(
      ip TEXT PRIMARY KEY, blocked_at TEXT, reason TEXT, active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS audit_logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
      actor TEXT, action TEXT, target TEXT, details TEXT
    );
    """)
    c.commit()
    c.close()

def execute(sql, params=(), fetch=False):
    c = conn()
    cur = c.execute(sql, params)
    rows = cur.fetchall() if fetch else None
    c.commit()
    c.close()
    return rows

def scalar(sql, params=()):
    rows = execute(sql, params, True)
    return rows[0][0] if rows else None

def query(sql, params=()):
    return execute(sql, params, True)
