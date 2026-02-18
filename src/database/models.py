"""
Database models for SentinelEye Agent.

Each class = one database table.
SQLAlchemy automatically creates tables from these models.
"""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    DateTime,
    Float,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import Mapped, mapped_column

from src.database.connection import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid4())


class SecurityEvent(Base):
    """
    Every suspicious activity gets stored here.
    This is the main data table of our agent.
    """

    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_id
    )
    event_type: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(50))
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)
    raw_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now
    )

    def __repr__(self):
        return f"<Event({self.event_type}, {self.severity})>"


class Alert(Base):
    """
    Alerts generated when a threat is confirmed.
    Events become Alerts after analysis.
    """

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_id
    )
    event_id: Mapped[str] = mapped_column(String(36))
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="new")
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)
    action_taken: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self):
        return f"<Alert({self.title}, {self.status})>"


class SystemMetric(Base):
    """
    System health data - CPU, memory, disk usage.
    Used for anomaly detection baseline.
    """

    __tablename__ = "system_metrics"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_id
    )
    cpu_percent: Mapped[float] = mapped_column(Float)
    memory_percent: Mapped[float] = mapped_column(Float)
    disk_percent: Mapped[float] = mapped_column(Float)
    network_bytes_sent: Mapped[int] = mapped_column(Integer, default=0)
    network_bytes_recv: Mapped[int] = mapped_column(Integer, default=0)
    active_processes: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now
    )

    def __repr__(self):
        return f"<Metric(cpu={self.cpu_percent}%, mem={self.memory_percent}%)>"