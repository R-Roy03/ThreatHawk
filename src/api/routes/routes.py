"""
API Routes - All endpoints for ThreatHawk.

These are the URLs that frontend/dashboard will call
to get data from our agent.
"""

from fastapi import APIRouter, HTTPException
from sqlalchemy import select, func, desc

from src.database.connection import db_manager
from src.database.models import SecurityEvent, Alert, SystemMetric
from src.api.schemas.schemas import (
    EventResponse,
    AlertResponse,
    AlertUpdate,
    DashboardStats,
    MessageResponse,
)
from src.utils.logger import get_logger
from src.utils.helpers import now_utc

logger = get_logger(__name__)

router = APIRouter()


# ─── Dashboard ─────────────────────────────────────────

@router.get("/dashboard", response_model=DashboardStats)
async def get_dashboard():
    """Get summary stats for dashboard."""
    session = await db_manager.get_session()

    try:
        # Count total events
        total_events = await session.scalar(
            select(func.count(SecurityEvent.id))
        )

        # Count total alerts
        total_alerts = await session.scalar(
            select(func.count(Alert.id))
        )

        # Count by severity
        critical = await session.scalar(
            select(func.count(Alert.id)).where(Alert.severity == "critical")
        )
        high = await session.scalar(
            select(func.count(Alert.id)).where(Alert.severity == "high")
        )
        medium = await session.scalar(
            select(func.count(Alert.id)).where(Alert.severity == "medium")
        )

        # Determine system status
        if critical > 0:
            status = "critical"
        elif high > 0:
            status = "warning"
        else:
            status = "healthy"

        return DashboardStats(
            total_events=total_events or 0,
            total_alerts=total_alerts or 0,
            critical_alerts=critical or 0,
            high_alerts=high or 0,
            medium_alerts=medium or 0,
            system_status=status,
        )
    finally:
        await session.close()


# ─── Events ───────────────────────────────────────────

@router.get("/events", response_model=list[EventResponse])
async def get_events(limit: int = 50):
    """Get recent security events."""
    session = await db_manager.get_session()

    try:
        result = await session.execute(
            select(SecurityEvent)
            .order_by(desc(SecurityEvent.created_at))
            .limit(limit)
        )
        events = result.scalars().all()
        return events
    finally:
        await session.close()


@router.get("/events/{event_id}", response_model=EventResponse)
async def get_event(event_id: str):
    """Get a single event by ID."""
    session = await db_manager.get_session()

    try:
        result = await session.execute(
            select(SecurityEvent).where(SecurityEvent.id == event_id)
        )
        event = result.scalar_one_or_none()

        if not event:
            raise HTTPException(status_code=404, detail="Event not found")

        return event
    finally:
        await session.close()


# ─── Alerts ───────────────────────────────────────────

@router.get("/alerts", response_model=list[AlertResponse])
async def get_alerts(status: str = None, limit: int = 50):
    """Get alerts. Filter by status if provided."""
    session = await db_manager.get_session()

    try:
        query = select(Alert).order_by(desc(Alert.created_at)).limit(limit)

        if status:
            query = query.where(Alert.status == status)

        result = await session.execute(query)
        alerts = result.scalars().all()
        return alerts
    finally:
        await session.close()


@router.put("/alerts/{alert_id}", response_model=MessageResponse)
async def update_alert(alert_id: str, data: AlertUpdate):
    """Update alert status (investigate, resolve, etc)."""
    session = await db_manager.get_session()

    try:
        result = await session.execute(
            select(Alert).where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()

        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        alert.status = data.status
        if data.action_taken:
            alert.action_taken = data.action_taken
        if data.status == "resolved":
            alert.resolved_at = now_utc()

        await session.commit()

        return MessageResponse(
            message=f"Alert updated to '{data.status}'",
            status="success",
        )
    finally:
        await session.close()


# ─── Scan ─────────────────────────────────────────────

@router.post("/scan", response_model=MessageResponse)
async def trigger_scan():
    """Manually trigger a security scan."""
    from src.core.engine import SentinelEngine

    engine = SentinelEngine()
    events = await engine.run_single_scan()

    return MessageResponse(
        message=f"Scan complete. Found {len(events)} events.",
        status="success",
    )