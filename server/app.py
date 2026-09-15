from server.models import IOCIn
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timezone
from pathlib import Path
import asyncio
import json

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uvicorn

from .config import *
from .db import execute, scalar, init_db, query
from .collector import LocalCollector
from .detection import detect, failed_login_correlation
from .command_guard import get_state as command_guard_state, set_enabled as command_guard_set_enabled, check_command as command_guard_check, record_event as command_guard_record, recent_events as command_guard_events
from server.command_guard import allow_command as command_guard_allow
from server.command_guard import remove_allowed_command as command_guard_remove_allowed
from server.command_guard import allowed_commands as command_guard_allowed


import re
BASE_DIR = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = BASE_DIR / "dashboard"

app = FastAPI(title="SentinelSOC")
app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")


def now():
    return datetime.now(timezone.utc).isoformat()


class IncidentIn(BaseModel):
    title: str
    severity: str = "high"
    risk: int = 70
    summary: str = ""
    owner: str = "SOC Analyst"
    alert_id: int | None = None


class Broadcast:
    def __init__(self):
        self.clients = set()

    async def send(self, data):
        dead = []

        for ws in self.clients:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.clients.discard(ws)


broadcast = Broadcast()

# Created during FastAPI startup, after ingest_event has been defined.
collector = None


@app.on_event("startup")
async def startup():
    global collector

    init_db()

    # Load the current rules from rules/rules.json into the database.
    try:
        rules_path = BASE_DIR / "rules" / "rules.json"

        if rules_path.exists():
            rules = json.loads(
                rules_path.read_text(
                    encoding="utf-8"
                )
            )

            for r in rules:
                execute(
                    """
                    INSERT OR REPLACE INTO rules(
                        id,
                        title,
                        description,
                        severity,
                        risk,
                        enabled,
                        tactic,
                        technique,
                        conditions
                    )
                    VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        r["id"],
                        r["title"],
                        r.get("description", ""),
                        r.get("severity", "medium"),
                        r.get("risk", 50),
                        1 if r.get("enabled", True) else 0,
                        r.get("tactic", ""),
                        r.get("technique", ""),
                        json.dumps(
                            r.get("conditions", {})
                        ),
                    ),
                )

    except Exception as e:
        print("Rule loading error:", e)

    # Start the agentless local collector.
    collector = LocalCollector(ingest_event)
    asyncio.create_task(collector.start())


@app.on_event("shutdown")
async def shutdown():
    global collector

    if collector is not None:
        collector.running = False


async def ingest_event(event):
    """
    Store real telemetry, run detection,
    create alerts, and broadcast the result.
    """

    timestamp = event.get("timestamp") or now()

    # ---------------------------------------------------------
    # 1. Store telemetry event
    # ---------------------------------------------------------

    event_id = scalar(
        """
        INSERT INTO events(
            timestamp,
            event_type,
            severity,
            source,
            message,
            user,
            src_ip,
            dst_ip,
            dst_port,
            process,
            raw
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?)
        RETURNING id
        """,
        (
            timestamp,
            event.get("event_type", "unknown"),
            event.get("severity", "low"),
            event.get("source", "collector"),
            event.get("message", ""),
            event.get("user"),
            event.get("src_ip"),
            event.get("dst_ip"),
            event.get("dst_port"),
            event.get("process"),
            json.dumps(event.get("raw", {})),
        ),
    )

    alerts = []

    # ---------------------------------------------------------
    # 2. Rule-based detection
    #
    # detect() returns a LIST of matching rules.
    # ---------------------------------------------------------

    detected_rules = detect(event)

    for rule in detected_rules:

        alert_id = scalar(
            """
            INSERT INTO alerts(
                event_id,
                created_at,
                title,
                description,
                severity,
                risk,
                status,
                rule_id,
                tactic,
                technique
            )
            VALUES(?,?,?,?,?,?,?,?,?,?)
            RETURNING id
            """,
            (
                event_id,
                now(),
                rule["title"],
                rule.get("description", ""),
                rule.get("severity", "medium"),
                rule.get("risk", 50),
                "new",
                rule.get("id"),
                rule.get("tactic", ""),
                rule.get("technique", ""),
            ),
        )

        detected = dict(rule)

        # Database alert ID
        detected["id"] = alert_id

        # Original telemetry event
        detected["event_id"] = event_id

        # Preserve the detection rule ID.
        # Example: NET-002
        detected["rule_id"] = rule.get("id")

        alerts.append(detected)

        await broadcast.send(
            {
                "type": "alert",
                "data": detected,
            }
        )

    # ---------------------------------------------------------
    # 3. Correlation detection
    #
    # Five failed SSH authentication attempts from one IP
    # within the configured time window -> CORR-001
    # ---------------------------------------------------------

    correlation = failed_login_correlation(event)

    if correlation:

        correlation_rule_id = correlation.get(
            "id",
            "CORR-001"
        )

        correlation_alert = scalar(
            """
            INSERT INTO alerts(
                event_id,
                created_at,
                title,
                description,
                severity,
                risk,
                status,
                rule_id,
                tactic,
                technique
            )
            VALUES(?,?,?,?,?,?,?,?,?,?)
            RETURNING id
            """,
            (
                None,
                now(),
                correlation["title"],
                correlation.get("description", ""),
                correlation.get("severity", "high"),
                correlation.get("risk", 85),
                "new",
                correlation_rule_id,
                correlation.get(
                    "tactic",
                    "Credential Access"
                ),
                correlation.get(
                    "technique",
                    "T1110 Brute Force"
                ),
            ),
        )

        correlation["rule_id"] = correlation_rule_id
        correlation["id"] = correlation_alert
        correlation["event_id"] = None

        alerts.append(correlation)

        await broadcast.send(
            {
                "type": "alert",
                "data": correlation,
            }
        )

    # ---------------------------------------------------------
    # 4. Broadcast telemetry event
    # ---------------------------------------------------------

    await broadcast.send(
        {
            "type": "event",
            "data": {
                **event,
                "id": event_id,
                "timestamp": timestamp,
            },
            "alerts": alerts,
        }
    )


# ============================================================
# Dashboard files
# ============================================================

@app.get("/")
def index():
    return FileResponse(
        DASHBOARD_DIR / "index.html"
    )


@app.get("/app.js")
def app_js():
    return FileResponse(
        DASHBOARD_DIR / "app.js"
    )


@app.get("/style.css")
def style_css():
    return FileResponse(
        DASHBOARD_DIR / "style.css"
    )


# ============================================================
# Dashboard overview
# ============================================================

@app.get("/api/v2/dashboard")
def dashboard():

    total_events = scalar(
        """
        SELECT COUNT(*)
        FROM events
        WHERE event_type NOT IN (
            'system_metrics',
            'process_inventory',
            'network_inventory'
        )
        """
    ) or 0

    total_alerts = scalar(
        "SELECT COUNT(*) FROM alerts"
    ) or 0

    active_alerts = scalar(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE status != 'resolved'
        """
    ) or 0

    critical = scalar(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE severity='critical'
        AND status != 'resolved'
        """
    ) or 0

    high = scalar(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE severity='high'
        AND status != 'resolved'
        """
    ) or 0

    resolved = scalar(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE status='resolved'
        """
    ) or 0

    unique_ips = scalar(
        """
        SELECT COUNT(DISTINCT src_ip)
        FROM events
        WHERE src_ip IS NOT NULL
        """
    ) or 0

    intel = scalar(
        """
        SELECT COUNT(*)
        FROM threat_intel
        """
    ) or 0

    top_vectors_rows = execute(
        """
        SELECT
            COALESCE(NULLIF(technique, ''), 'Unclassified') AS vector,
            COUNT(*) AS count
        FROM alerts
        GROUP BY COALESCE(NULLIF(technique, ''), 'Unclassified')
        ORDER BY count DESC
        LIMIT 8
        """,
        fetch=True,
    )

    top_vectors = [
        {
            "vector": row[0],
            "count": row[1],
        }
        for row in top_vectors_rows
    ]

    score = max(
        0,
        min(
            100,
            100 - (critical * 15) - (high * 7)
        ),
    )

    return {
        "security_score": score,
        "active_alerts": active_alerts,
        "total_alerts": total_alerts,
        "live_events": total_events,
        "unique_ips": unique_ips,
        "critical": critical,
        "high": high,
        "resolved": resolved,
        "threat_intel": intel,
        "top_vectors": top_vectors,
    }


# ============================================================
# Events
# ============================================================

@app.get("/api/v2/events")
def events(
    limit: int = 100,
    q: str = "",
    src_ip: str = "",
    threat_type: str = "",
):

    sql = """
        SELECT
            id,
            timestamp,
            event_type,
            severity,
            source,
            message,
            user,
            src_ip,
            dst_ip,
            dst_port,
            process,
            raw
        FROM events
        WHERE 1=1
    """

    params = []

    if q:

        sql += """
            AND (
                message LIKE ?
                OR event_type LIKE ?
                OR src_ip LIKE ?
                OR user LIKE ?
            )
        """

        like = f"%{q}%"

        params.extend(
            [
                like,
                like,
                like,
                like,
            ]
        )

    if src_ip:
        sql += " AND src_ip=?"
        params.append(src_ip)

    if threat_type:

        sql += """
            AND (
                event_type=?
                OR event_type LIKE ?
            )
        """

        params.extend(
            [
                threat_type,
                f"%{threat_type}%",
            ]
        )

    sql += """
        ORDER BY timestamp DESC
        LIMIT ?
    """

    params.append(limit)

    rows = execute(
        sql,
        params,
        fetch=True,
    )

    return [
        {
            "id": r[0],
            "timestamp": r[1],
            "event_type": r[2],
            "severity": r[3],
            "source": r[4],
            "message": r[5],
            "user": r[6],
            "src_ip": r[7],
            "dst_ip": r[8],
            "dst_port": r[9],
            "process": r[10],
            "raw": r[11],
        }
        for r in rows
    ]


# ============================================================
# Alerts
# ============================================================

@app.get("/api/v2/alerts")
def alerts(limit: int = 150):

    rows = execute(
        """
        SELECT
            id,
            event_id,
            created_at,
            title,
            description,
            severity,
            risk,
            status,
            rule_id,
            tactic,
            technique
        FROM alerts
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (limit,),
        fetch=True,
    )

    return [
        {
            "id": r[0],
            "event_id": r[1],
            "created_at": r[2],
            "title": r[3],
            "description": r[4],
            "severity": r[5],
            "risk": r[6],
            "status": r[7],
            "rule_id": r[8],
            "tactic": r[9],
            "technique": r[10],
        }
        for r in rows
    ]


@app.patch("/api/v2/alerts/{alert_id}")
def update_alert(
    alert_id: int,
    status: str,
):

    if status not in (
        "new",
        "acknowledged",
        "resolved",
    ):
        raise HTTPException(
            400,
            "Invalid status",
        )

    execute(
        """
        UPDATE alerts
        SET status=?
        WHERE id=?
        """,
        (
            status,
            alert_id,
        ),
    )

    execute(
        """
        INSERT INTO audit_logs(
            timestamp,
            actor,
            action,
            target,
            details
        )
        VALUES(?,?,?,?,?)
        """,
        (
            now(),
            "dashboard",
            f"alert_{status}",
            str(alert_id),
            f"Alert #{alert_id} changed to {status}",
        ),
    )

    return {
        "ok": True
    }


# ============================================================
# Event trend
# ============================================================

@app.get("/api/v2/trend")
def trend():

    rows = execute(
        """
        SELECT
            substr(timestamp,1,16) AS bucket,
            COUNT(*) AS count
        FROM events
        GROUP BY bucket
        ORDER BY bucket DESC
        LIMIT 24
        """,
        fetch=True,
    )

    rows.reverse()

    return [
        {
            "bucket": r[0],
            "count": r[1],
        }
        for r in rows
    ]


# ============================================================
# Incidents
# ============================================================

@app.post("/api/v2/incidents")
def create_incident(i: IncidentIn):

    created = now()

    execute(
        """
        INSERT INTO incidents(
            created_at,
            updated_at,
            title,
            severity,
            risk,
            status,
            summary,
            owner
        )
        VALUES(?,?,?,?,?,?,?,?)
        """,
        (
            created,
            created,
            i.title,
            i.severity,
            i.risk,
            "open",
            i.summary,
            i.owner,
        ),
    )

    # Do not use last_insert_rowid() here because db.py
    # opens a new SQLite connection for each operation.
    incident_id = scalar(
        """
        SELECT id
        FROM incidents
        WHERE created_at=?
        AND title=?
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            created,
            i.title,
        ),
    )

    if incident_id is None:
        raise HTTPException(
            500,
            "Incident was created but ID could not be retrieved",
        )

    if i.alert_id is not None:

        execute(
            """
            INSERT OR IGNORE INTO incident_alerts(
                incident_id,
                alert_id
            )
            VALUES(?,?)
            """,
            (
                incident_id,
                i.alert_id,
            ),
        )

    execute(
        """
        INSERT INTO audit_logs(
            timestamp,
            actor,
            action,
            target,
            details
        )
        VALUES(?,?,?,?,?)
        """,
        (
            now(),
            "dashboard",
            "incident_created",
            str(incident_id),
            (
                f"Created from alert #{i.alert_id}"
                if i.alert_id is not None
                else "Manual incident creation"
            ),
        ),
    )

    return {
        "incident_id": incident_id
    }



@app.get("/api/v2/alerts/{alert_id}/investigation")
def alert_investigation(alert_id: int):
    alert_rows = execute(
        "SELECT * FROM alerts WHERE id=?",
        (alert_id,),
        fetch=True,
    )

    if not alert_rows:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = dict(alert_rows[0])

    source_ip = None

    # Correlation alerts may not have event_id, so recover the
    # source IP from the alert text when necessary.
    text = " ".join(
        str(alert.get(k) or "")
        for k in ["title", "description"]
    )

    m = re.search(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        text
    )

    if m:
        source_ip = m.group(0)

    if alert.get("event_id"):
        event_rows = execute(
            "SELECT * FROM events WHERE id=?",
            (alert["event_id"],),
            fetch=True,
        )

        if event_rows:
            event = dict(event_rows[0])
            source_ip = source_ip or event.get("src_ip")

    timeline = []

    if source_ip:
        # Search real telemetry around the alert.
        # This intentionally excludes background inventory events.
        rows = execute(
            """
            SELECT *
            FROM events
            WHERE src_ip=?
              AND event_type NOT IN (
                  'system_metrics',
                  'network_inventory',
                  'process_inventory'
              )
            ORDER BY timestamp ASC
            LIMIT 100
            """,
            (source_ip,),
            fetch=True,
        )

        for row in rows:
            e = dict(row)
            timeline.append(e)

    # Investigation indicators based only on collected telemetry.
    types = {
        str(x.get("event_type") or "").lower()
        for x in timeline
    }

    users = sorted({
        str(x.get("user"))
        for x in timeline
        if x.get("user")
    })

    return {
        "alert": alert,
        "source_ip": source_ip,
        "users": users,
        "timeline": timeline,
        "indicators": {
            "failed_logins": sum(
                1 for x in timeline
                if x.get("event_type") == "login_failed"
            ),
            "successful_login": "login_success" in types,
            "privilege_change": "privilege_change" in types,
            "network_connection": "network_connection" in types,
            "account_change": "account_change" in types,
        },
    }


@app.get("/api/v2/incidents/{incident_id}/investigation")
def incident_investigation(incident_id: int):
    incident_rows = execute(
        "SELECT * FROM incidents WHERE id=?",
        (incident_id,),
        fetch=True,
    )

    if not incident_rows:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = dict(incident_rows[0])

    links = execute(
        """
        SELECT alert_id
        FROM incident_alerts
        WHERE incident_id=?
        """,
        (incident_id,),
        fetch=True,
    )

    alert_ids = [
        int(dict(x)["alert_id"])
        for x in links
        if dict(x).get("alert_id") is not None
    ]

    alerts = []

    if alert_ids:
        placeholders = ",".join("?" for _ in alert_ids)

        alert_rows = execute(
            f"""
            SELECT *
            FROM alerts
            WHERE id IN ({placeholders})
            ORDER BY created_at ASC
            """,
            tuple(alert_ids),
            fetch=True,
        )

        alerts = [dict(x) for x in alert_rows]

    # Collect source IPs from linked alerts.
    source_ips = set()

    for alert in alerts:
        text = " ".join(
            str(alert.get(k) or "")
            for k in ["title", "description"]
        )

        for m in re.finditer(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            text
        ):
            source_ips.add(m.group(0))

    timeline = []

    if source_ips:
        placeholders = ",".join("?" for _ in source_ips)

        rows = execute(
            f"""
            SELECT *
            FROM events
            WHERE src_ip IN ({placeholders})
              AND event_type NOT IN (
                  'system_metrics',
                  'network_inventory',
                  'process_inventory'
              )
            ORDER BY timestamp ASC
            LIMIT 250
            """,
            tuple(source_ips),
            fetch=True,
        )

        timeline = [dict(x) for x in rows]

    types = {
        str(x.get("event_type") or "").lower()
        for x in timeline
    }

    return {
        "incident": incident,
        "alerts": alerts,
        "source_ips": sorted(source_ips),
        "timeline": timeline,
        "indicators": {
            "failed_logins": sum(
                1 for x in timeline
                if x.get("event_type") == "login_failed"
            ),
            "successful_login": "login_success" in types,
            "privilege_change": "privilege_change" in types,
            "network_connection": "network_connection" in types,
            "account_change": "account_change" in types,
        },
    }


@app.get("/api/v2/incidents")
def get_incidents():

    rows = execute(
        """
        SELECT
            id,
            created_at,
            updated_at,
            title,
            severity,
            risk,
            status,
            summary,
            owner
        FROM incidents
        ORDER BY updated_at DESC
        """,
        fetch=True,
    )

    return [
        {
            "id": r[0],
            "created_at": r[1],
            "updated_at": r[2],
            "title": r[3],
            "severity": r[4],
            "risk": r[5],
            "status": r[6],
            "summary": r[7],
            "owner": r[8],
        }
        for r in rows
    ]


@app.patch("/api/v2/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    status: str,
):

    allowed = (
        "open",
        "investigating",
        "contained",
        "closed",
    )

    if status not in allowed:
        raise HTTPException(
            400,
            "Invalid incident status",
        )

    existing = execute(
        """
        SELECT status
        FROM incidents
        WHERE id=?
        """,
        (
            incident_id,
        ),
        fetch=True,
    )

    if not existing:
        raise HTTPException(
            404,
            "Incident not found",
        )

    old_status = existing[0][0]

    execute(
        """
        UPDATE incidents
        SET status=?,
            updated_at=?
        WHERE id=?
        """,
        (
            status,
            now(),
            incident_id,
        ),
    )

    execute(
        """
        INSERT INTO audit_logs(
            timestamp,
            actor,
            action,
            target,
            details
        )
        VALUES(?,?,?,?,?)
        """,
        (
            now(),
            "dashboard",
            "incident_status_changed",
            str(incident_id),
            f"{old_status} -> {status}",
        ),
    )

    return {
        "ok": True,
        "incident_id": incident_id,
        "status": status,
    }


# ============================================================
# Threat intelligence correlation
# ============================================================


@app.get("/api/v2/iocs")
def get_iocs():
    rows = query("""
        SELECT id, kind, value, severity, description
        FROM iocs
        ORDER BY id DESC
    """)
    return [dict(row) for row in rows]


@app.post("/api/v2/iocs")
def create_ioc(ioc: IOCIn):
    execute("""
        INSERT INTO iocs(kind, value, severity, description)
        VALUES(?, ?, ?, ?)
    """, (
        ioc.kind,
        ioc.value,
        ioc.severity,
        ioc.description
    ))

    row = query("""
        SELECT id, kind, value, severity, description
        FROM iocs
        WHERE kind=? AND value=?
        ORDER BY id DESC
        LIMIT 1
    """, (ioc.kind, ioc.value))

    return row[0] if row else {"status": "created"}


@app.delete("/api/v2/iocs/{ioc_id}")
def delete_ioc(ioc_id: int):
    existing = query(
        "SELECT id FROM iocs WHERE id=?",
        (ioc_id,)
    )

    if not existing:
        raise HTTPException(status_code=404, detail="IOC not found")

    execute(
        "DELETE FROM iocs WHERE id=?",
        (ioc_id,)
    )

    return {"status": "deleted", "id": ioc_id}


@app.get("/api/v2/threat-intel/correlation")
def threat_correlation():

    rows = execute(
        """
        SELECT
            src_ip,
            COUNT(*) AS events,
            GROUP_CONCAT(
                DISTINCT dst_port
            ) AS ports,
            GROUP_CONCAT(
                DISTINCT raw
            ) AS raws
        FROM events
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY events DESC
        LIMIT 50
        """,
        fetch=True,
    )

    output = []

    for r in rows:

        ports = []

        if r[2]:

            try:
                ports = [
                    int(x)
                    for x in r[2].split(",")
                    if x
                ]

            except Exception:
                ports = []

        user_agents = []

        if r[3]:

            for raw in r[3].split("},{"):

                if "User-Agent" in raw:
                    user_agents.append(
                        raw[:120]
                    )

        output.append(
            {
                "source_ip": r[0],
                "events": r[1],
                "destination_ports": ports,
                "user_agents": user_agents,
            }
        )

    return output


# ============================================================
# IP management
# ============================================================

@app.get("/api/v2/ip-management")
def ip_management():

    rows = execute(
        """
        SELECT
            ip,
            reason,
            blocked_at
        FROM blocked_ips
        ORDER BY blocked_at DESC
        """,
        fetch=True,
    )

    return [
        {
            "ip": r[0],
            "reason": r[1],
            "blocked_at": r[2],
        }
        for r in rows
    ]


@app.post("/api/v2/ip-management/{ip}/block")
def block_ip(
    ip: str,
    payload: dict,
):

    reason = payload.get(
        "reason",
        "Manual SOC analyst block",
    )

    execute(
        """
        INSERT OR REPLACE INTO blocked_ips(
            ip,
            reason,
            blocked_at
        )
        VALUES(?,?,?)
        """,
        (
            ip,
            reason,
            now(),
        ),
    )

    execute(
        """
        INSERT INTO audit_logs(
            timestamp,
            actor,
            action,
            target,
            details
        )
        VALUES(?,?,?,?,?)
        """,
        (
            now(),
            "dashboard",
            "ip_blocked",
            ip,
            reason,
        ),
    )

    return {
        "ok": True
    }


@app.post("/api/v2/ip-management/{ip}/unblock")
def unblock_ip(ip: str):

    execute(
        """
        DELETE FROM blocked_ips
        WHERE ip=?
        """,
        (
            ip,
        ),
    )

    execute(
        """
        INSERT INTO audit_logs(
            timestamp,
            actor,
            action,
            target,
            details
        )
        VALUES(?,?,?,?,?)
        """,
        (
            now(),
            "dashboard",
            "ip_unblocked",
            ip,
            "Manual SOC analyst unblock",
        ),
    )

    return {
        "ok": True
    }


# ============================================================
# Assets
# ============================================================

@app.get("/api/v2/assets")
def assets():

    rows = execute(
        """
        SELECT
            a.id,
            a.hostname,
            a.os,
            a.status,
            a.collection,

            (
                SELECT COUNT(*)
                FROM events e
                WHERE e.source = 'local_monitor'
            ) AS event_count,

            (
                SELECT COUNT(*)
                FROM alerts al
                WHERE al.status NOT IN ('closed', 'resolved')
            ) AS alert_count,

            (
                SELECT COALESCE(MAX(al.risk), 0)
                FROM alerts al
                WHERE al.status NOT IN ('closed', 'resolved')
            ) AS risk,

            (
                SELECT MAX(e.timestamp)
                FROM events e
                WHERE e.source = 'local_monitor'
            ) AS last_seen

        FROM assets a
        ORDER BY a.hostname
        """,
        fetch=True,
    )

    return [
        {
            "id": r[0],
            "hostname": r[1],
            "os": r[2],
            "status": r[3],
            "collection": r[4],
            "event_count": r[5] or 0,
            "alert_count": r[6] or 0,
            "risk": r[7] or 0,
            "last_seen": r[8],
        }
        for r in rows
    ]


# ============================================================
# WebSocket
# ============================================================

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
):

    await websocket.accept()

    broadcast.clients.add(websocket)

    try:

        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        broadcast.clients.discard(websocket)

    except Exception:
        broadcast.clients.discard(websocket)


# ============================================================
# Direct execution
# ============================================================

if __name__ == "__main__":

    uvicorn.run(
        "server.app:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )


# ============================================================
# COMMAND GUARD / HOST PROTECTION
# ============================================================

@app.get("/api/v2/command-guard")
def get_command_guard():
    return {
        "status": command_guard_state(),
        "events": command_guard_events(50)
    }


@app.patch("/api/v2/command-guard")
def update_command_guard(payload: dict):
    enabled = bool(payload.get("enabled", True))
    state = command_guard_set_enabled(enabled)

    execute("""
        INSERT INTO audit_logs(timestamp, actor, action, target, details)
        VALUES(?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat(),
        "dashboard",
        "command_guard_changed",
        "command_guard",
        "enabled=" + str(enabled)
    ))

    return {"status": state}


@app.post("/api/v2/command-guard/check")
def check_command_guard(payload: dict):
    command = str(payload.get("command", ""))
    result = command_guard_check(command)

    if result["suspicious"]:
        event = command_guard_record(
            command,
            result["blocked"],
            result["reason"]
        )
        result["event"] = event

    return result


@app.get("/api/v2/command-guard/events")
def get_command_guard_events(limit: int = 50):
    return command_guard_events(limit)


@app.get("/api/v2/command-guard/allowlist")
def get_command_guard_allowlist():
    return command_guard_allowed()


@app.post("/api/v2/command-guard/allow")
def allow_command_guard_command(payload: dict):
    command = str(payload.get("command", "")).strip()

    if not command:
        raise HTTPException(status_code=400, detail="Command is required")

    result = command_guard_allow(command)

    execute("""
        INSERT INTO audit_logs(timestamp, actor, action, target, details)
        VALUES(?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat(),
        "dashboard",
        "command_allowed",
        command,
        "Command explicitly allowed by SOC analyst"
    ))

    return result


@app.delete("/api/v2/command-guard/allow")
def remove_command_guard_allow(payload: dict):
    command = str(payload.get("command", "")).strip()

    if not command:
        raise HTTPException(status_code=400, detail="Command is required")

    result = command_guard_remove_allowed(command)

    execute("""
        INSERT INTO audit_logs(timestamp, actor, action, target, details)
        VALUES(?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat(),
        "dashboard",
        "command_allow_removed",
        command,
        "Command removed from Command Guard allowlist"
    ))

    return result
