"""
API Schemas - Defines what data looks like in API requests/responses.

Pydantic models validate data automatically:
- Wrong type? Error!
- Missing field? Error!
- Extra field? Ignored!

This prevents bad data from entering our system.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ─── Event Schemas ─────────────────────────────────────

class EventResponse(BaseModel):
    """How a security event looks in API response."""
    id: str
    event_type: str
    severity: str
    title: str
    description: Optional[str] = None
    source: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    file_path: Optional[str] = None
    threat_score: float = 0.0
    created_at: datetime

    class Config:
        from_attributes = True


# ─── Alert Schemas ─────────────────────────────────────

class AlertResponse(BaseModel):
    """How an alert looks in API response."""
    id: str
    event_id: str
    severity: str
    title: str
    description: Optional[str] = None
    status: str = "new"
    threat_score: float = 0.0
    action_taken: Optional[str] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    """Data needed to update an alert status."""
    status: str = Field(
        description="new, investigating, resolved, false_positive"
    )
    action_taken: Optional[str] = None


# ─── System Metrics Schema ─────────────────────────────

class MetricResponse(BaseModel):
    """How system metrics look in API response."""
    id: str
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_bytes_sent: int
    network_bytes_recv: int
    active_processes: int
    created_at: datetime

    class Config:
        from_attributes = True


# ─── Dashboard Schema ──────────────────────────────────

class DashboardStats(BaseModel):
    """Summary stats for dashboard."""
    total_events: int = 0
    total_alerts: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    system_status: str = "healthy"


# ─── General Response ──────────────────────────────────

class MessageResponse(BaseModel):
    """Simple message response."""
    message: str
    status: str = "success"