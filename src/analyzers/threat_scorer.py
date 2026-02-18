"""
Threat Scorer - Calculates how dangerous an event is.

Every event gets a score from 0.0 to 1.0:
- 0.0 to 0.3 = Low (probably safe)
- 0.3 to 0.5 = Medium (keep an eye)
- 0.5 to 0.7 = High (investigate!)
- 0.7 to 1.0 = Critical (take action NOW!)

This is the BRAIN that decides threat level.
"""

from src.core.constants import EventType, Severity
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Base scores for each event type
EVENT_BASE_SCORES = {
    EventType.SUSPICIOUS_PROCESS.value: 0.8,
    EventType.NETWORK_ANOMALY.value: 0.6,
    EventType.FILE_CHANGE.value: 0.5,
    EventType.HIGH_RESOURCE.value: 0.3,
    EventType.PORT_SCAN.value: 0.7,
    EventType.BRUTE_FORCE.value: 0.8,
    EventType.USB_DEVICE.value: 0.4,
}


def calculate_threat_score(event: dict) -> float:
    """
    Calculate final threat score for an event.

    Combines base score with additional factors
    to give accurate threat level.
    """
    # Start with base score for this event type
    event_type = event.get("event_type", "")
    score = EVENT_BASE_SCORES.get(event_type, 0.3)

    # Factor 1: If event already has a score, average it
    existing_score = event.get("threat_score", 0.0)
    if existing_score > 0:
        score = (score + existing_score) / 2

    # Factor 2: Boost score for critical keywords
    title = event.get("title", "").lower()
    description = event.get("description", "").lower()
    text = title + " " + description

    critical_keywords = [
        "mimikatz", "keylogger", "malware",
        "backdoor", "trojan", "ransomware",
    ]

    for keyword in critical_keywords:
        if keyword in text:
            score = min(score + 0.15, 1.0)
            break

    # Factor 3: Multiple connections = more suspicious
    raw_data = event.get("raw_data", {})
    if isinstance(raw_data, dict):
        total_connections = raw_data.get("total_connections", 0)
        if total_connections > 50:
            score = min(score + 0.1, 1.0)

    # Keep score between 0 and 1
    score = max(0.0, min(1.0, round(score, 2)))

    return score


def get_severity_from_score(score: float) -> str:
    """
    Convert numeric score to severity label.

    0.0 - 0.3 = LOW
    0.3 - 0.5 = MEDIUM
    0.5 - 0.7 = HIGH
    0.7 - 1.0 = CRITICAL
    """
    if score >= 0.7:
        return Severity.CRITICAL.value
    elif score >= 0.5:
        return Severity.HIGH.value
    elif score >= 0.3:
        return Severity.MEDIUM.value
    else:
        return Severity.LOW.value