"""
TimeCodeSecurity (TCS) Delivery Audit Models & Schema.

Defines the persisted DeliveryAuditLog entity and Pydantic DTOs for Phase 15D.
Audit records are application-level append-only records.

Invariants:
- Strictly persists delivery telemetry without sensitive payload or secret exposure.
- Never persists target_ip, webhook secrets, authorization headers, request bodies, or response bodies.
- error_message is strictly bounded to <= 512 characters.
- All timestamps represent explicit UTC time.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, validator

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
)

try:
    from app import Base
except ImportError:
    from sqlalchemy.orm import declarative_base
    Base = declarative_base()


MAX_AUDIT_ERROR_LENGTH: int = 512


class DeliveryAuditLog(Base):
    """
    SQLAlchemy model representing a permanent delivery audit record.
    Application-level append-only: no update or delete operations are permitted.
    """
    __tablename__ = "delivery_audit_logs"

    id = Column(String(36), primary_key=True, index=True)
    organization_id = Column(Integer, nullable=False, index=True)
    event_id = Column(String(64), nullable=False, index=True)
    scan_id = Column(String(64), nullable=True, index=True)
    idempotency_key = Column(String(64), nullable=False, index=True)
    channel = Column(String(32), nullable=False)
    status = Column(String(64), nullable=False, index=True)
    status_code = Column(Integer, nullable=True)
    attempts = Column(Integer, nullable=False, default=1)
    duration_ms = Column(Float, nullable=False, default=0.0)
    error_message = Column(String(MAX_AUDIT_ERROR_LENGTH), nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    __table_args__ = (
        Index("ix_delivery_audit_org_created_id", "organization_id", "created_at", "id"),
        Index("ix_delivery_audit_org_idempotency", "organization_id", "idempotency_key"),
        Index("ix_delivery_audit_org_status", "organization_id", "status"),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes model attributes into a safe public dictionary."""
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "event_id": self.event_id,
            "scan_id": self.scan_id,
            "idempotency_key": self.idempotency_key,
            "channel": self.channel,
            "status": self.status,
            "status_code": self.status_code,
            "attempts": self.attempts,
            "duration_ms": self.duration_ms,
            "error_message": self.error_message,
            "created_at": (
                self.created_at.replace(tzinfo=datetime.timezone.utc).isoformat()
                if self.created_at and self.created_at.tzinfo is None
                else self.created_at.isoformat() if self.created_at else None
            ),
        }


class DeliveryAuditLogCreate(BaseModel):
    """Internal DTO for creating a delivery audit log."""
    id: Optional[str] = None
    organization_id: int
    event_id: str
    scan_id: Optional[str] = None
    idempotency_key: str
    channel: str = "WEBHOOK"
    status: str
    status_code: Optional[int] = None
    attempts: int = 1
    duration_ms: float = 0.0
    error_message: Optional[str] = None
    created_at: Optional[datetime.datetime] = None

    @validator("organization_id")
    def validate_org_id(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("organization_id must be a positive integer.")
        return v

    @validator("error_message")
    def truncate_error(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v) > MAX_AUDIT_ERROR_LENGTH:
            return v[:MAX_AUDIT_ERROR_LENGTH]
        return v


class DeliveryAuditLogRead(BaseModel):
    """
    Safe public representation of a delivery audit log.
    Strictly excludes target_ip, secrets, request payloads, response bodies, and auth headers.
    """
    id: str
    organization_id: int
    event_id: str
    scan_id: Optional[str] = None
    idempotency_key: str
    channel: str
    status: str
    status_code: Optional[int] = None
    attempts: int
    duration_ms: float
    error_message: Optional[str] = None
    created_at: str

    class Config:
        from_attributes = True
        orm_mode = True


class DeliveryStatsResponse(BaseModel):
    """Summary statistics for webhook delivery telemetry."""
    organization_id: int
    total_deliveries: int
    success_count: int
    failure_count: int
    average_duration_ms: float
