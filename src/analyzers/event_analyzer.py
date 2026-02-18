"""
Event Analyzer - Analyzes collected events and creates alerts.

This is the DECISION MAKER:
1. Takes raw events from collectors
2. Scores them using threat_scorer
3. Decides if alert should be created
4. Saves everything to database

Think of it as a Security Analyst working 24/7!
"""

from sqlalchemy import select

from src.analyzers.threat_scorer import (
    calculate_threat_score,
    get_severity_from_score,
)
from src.database.connection import db_manager
from src.database.models import SecurityEvent, Alert
from src.utils.logger import get_logger
from src.utils.helpers import generate_id, now_utc

logger = get_logger(__name__)

# Minimum score to create an alert
ALERT_THRESHOLD = 0.5


async def analyze_event(event: dict) -> dict | None:
    """
    Analyze a single event and decide if it's a threat.

    Steps:
    1. Calculate threat score
    2. Determine severity
    3. Save event to database
    4. Create alert if score is high enough

    Returns the alert dict if created, None otherwise.
    """
    # Step 1: Calculate threat score
    score = calculate_threat_score(event)
    severity = get_severity_from_score(score)

    # Update event with calculated values
    event["threat_score"] = score
    event["severity"] = severity

    logger.info(
        f"Event analyzed: {event.get('title', 'Unknown')} "
        f"| Score: {score} | Severity: {severity}"
    )

    # Step 2: Save event to database
    await _save_event(event)

    # Step 3: Create alert if score is high enough
    if score >= ALERT_THRESHOLD:
        alert = await _create_alert(event)
        return alert

    return None


async def analyze_batch(events: list[dict]) -> list[dict]:
    """
    Analyze multiple events at once.

    Returns list of alerts created.
    """
    alerts = []

    for event in events:
        alert = await analyze_event(event)
        if alert:
            alerts.append(alert)

    if alerts:
        logger.warning(f"Created {len(alerts)} alerts from {len(events)} events")

    return alerts


async def _save_event(event: dict) -> None:
    """Save a security event to database."""
    try:
        session = await db_manager.get_session()

        db_event = SecurityEvent(
            id=event.get("id", generate_id()),
            event_type=event.get("event_type", "unknown"),
            severity=event.get("severity", "low"),
            title=event.get("title", "Unknown Event"),
            description=event.get("description"),
            source=event.get("source", "unknown"),
            source_ip=event.get("source_ip"),
            destination_ip=event.get("destination_ip"),
            process_name=event.get("process_name"),
            process_id=event.get("process_id"),
            file_path=event.get("file_path"),
            threat_score=event.get("threat_score", 0.0),
            raw_data=event.get("raw_data"),
        )

        session.add(db_event)
        await session.commit()
        await session.close()

    except Exception as e:
        logger.error(f"Failed to save event: {e}")


async def _create_alert(event: dict) -> dict:
    """Create an alert from a high-score event."""
    alert_data = {
        "id": generate_id(),
        "event_id": event.get("id", ""),
        "severity": event.get("severity", "medium"),
        "title": event.get("title", "Security Alert"),
        "description": event.get("description"),
        "status": "new",
        "threat_score": event.get("threat_score", 0.0),
        "created_at": now_utc().isoformat(),
    }

    try:
        session = await db_manager.get_session()

        db_alert = Alert(
            id=alert_data["id"],
            event_id=alert_data["event_id"],
            severity=alert_data["severity"],
            title=alert_data["title"],
            description=alert_data["description"],
            status=alert_data["status"],
            threat_score=alert_data["threat_score"],
        )

        session.add(db_alert)
        await session.commit()
        await session.close()

        logger.warning(
            f"ALERT CREATED: {alert_data['title']} "
            f"[{alert_data['severity'].upper()}]"
        )

    except Exception as e:
        logger.error(f"Failed to create alert: {e}")

    return alert_data