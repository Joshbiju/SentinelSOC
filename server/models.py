from pydantic import BaseModel, Field
from typing import Any, Optional

class EventIn(BaseModel):
    timestamp: str
    event_type: str = "system"
    severity: str = "info"
    message: str = ""
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    process: Optional[str] = None
    command: Optional[str] = None
    source: str = "local_monitor"
    raw: dict[str, Any] = Field(default_factory=dict)

class IncidentIn(BaseModel):
    title: str
    severity: str = "high"
    risk: int = 70
    summary: str = ""
    owner: str = "SOC Analyst"
    alert_id: Optional[int] = None

class IOCIn(BaseModel):
    kind: str
    value: str
    severity: str = "high"
    description: str = ""


class IPBlockIn(BaseModel):
    reason: str = "Manual SOC analyst block"
