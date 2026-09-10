"""
TimeCodeSecurity (TCS) Notification Data Models & Schema.

Defines the persisted Notification entity, Pydantic DTOs,
recipient ownership scopes, and validation invariants for Phase 15B.

Invariants:
- Recipient ownership is strictly USER or ORGANIZATION.
- scope_target is deterministic: user_id for USER scope, 0 for ORGANIZATION scope.
- Database unique constraint on (organization_id, scope_target, dedupe_key, type).
- Event ID is an audit provenance string (VARCHAR(64)), NOT a database foreign key.
- Read-state invariant: is_read == False => read_at is None; is_read == True => read_at is not None.
- String bounds: title <= 255, message <= 2000, link <= 512.
- Zero raw secrets in title/message.
- Links must be relative internal URLs starting with '/' (no '//', no external schemes).
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional, Union

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    event,
)
from pydantic import BaseModel, Field, validator

try:
    from app import Base
except ImportError:
    from sqlalchemy.orm import declarative_base
    Base = declarative_base()


class RecipientScope(str, Enum):
    """Defines the recipient boundary for notifications."""
    USER = "USER"
    ORGANIZATION = "ORGANIZATION"


class NotificationSeverity(str, Enum):
    """Severity classification matching TCS domain levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Regular expression patterns for defensive raw secret rejection
_SECRET_PATTERNS = [
    re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),  # AWS Access Key
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b"),  # Stripe Key
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36,}\b|\bgithub_pat_[0-9a-zA-Z_]{80,}\b"),  # GitHub Token
    re.compile(r"\bsk-[a-zA-Z0-9_-]{20,}\b"),  # OpenAI Key
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),  # Private Key
    re.compile(r"(?i)\b(?:bearer\s+[a-zA-Z0-9\._\-]{20,}|password\s*=\s*['\"][^'\"]{6,}['\"])"),  # Generic auth/pwd
]


def validate_no_secrets(content: str, field_name: str = "content") -> None:
    """
    Validates that text does not contain known high-risk raw secret patterns.
    Raises ValueError if a secret is detected.
    """
    if not content or not isinstance(content, str):
        return
    for pattern in _SECRET_PATTERNS:
        if pattern.search(content):
            raise ValueError(
                f"Security policy violation: Raw secret or sensitive token pattern detected in {field_name}. "
                "Mask credentials before creating notifications."
            )


def validate_relative_link(link: Optional[str]) -> Optional[str]:
    """
    Validates that a link is a safe relative internal dashboard URL.
    - Must start with '/'
    - Must NOT start with '//' (protocol-relative)
    - Must NOT contain scheme prefixes (http:, https:, javascript:, data:, etc.)
    - Must NOT contain whitespace or control characters
    - Must be <= 512 characters
    """
    if link is None:
        return None
    if not isinstance(link, str):
        raise ValueError("Notification link must be a string or None.")

    trimmed = link.strip()
    if not trimmed:
        return None

    if len(trimmed) > 512:
        raise ValueError(f"Notification link exceeds 512 characters limit ({len(trimmed)} chars).")

    if re.search(r"[\s\x00-\x1f\x7f]", trimmed):
        raise ValueError("Notification link must not contain whitespace or control characters.")

    if not trimmed.startswith("/"):
        raise ValueError(f"Notification link must be a relative internal URL starting with '/': '{link}'.")

    if trimmed.startswith("//"):
        raise ValueError("Notification link must not start with '//' (protocol-relative URL forbidden).")

    lower = trimmed.lower()
    dangerous_keywords = ("javascript:", "data:", "vbscript:", "file:", "http:", "https:", "ftp:")
    for kw in dangerous_keywords:
        if kw in lower:
            raise ValueError(f"Notification link contains forbidden scheme or keyword '{kw}'.")

    return trimmed


class Notification(Base):
    """
    SQLAlchemy model representing a mutable, persisted user/tenant notification.
    """
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    organization_id = Column(Integer, ForeignKey("organization.id"), nullable=False, index=True)
    recipient_scope = Column(String(16), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    scope_target = Column(Integer, nullable=False, default=0, index=True)

    # Audit provenance: correlates with SecurityDomainEvent, but NOT a database FK
    event_id = Column(String(64), nullable=False, index=True)
    scan_id = Column(String(64), nullable=False, index=True)
    dedupe_key = Column(String(64), nullable=False, index=True)

    type = Column(String(32), nullable=False, index=True)
    severity = Column(String(16), nullable=False, default="INFO")
    title = Column(String(255), nullable=False)
    message = Column(String(2000), nullable=False)
    link = Column(String(512), nullable=True)

    is_read = Column(Boolean, nullable=False, default=False, index=True)
    read_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "scope_target",
            "dedupe_key",
            "type",
            name="uq_notification_dedupe",
        ),
        Index("ix_notifications_tenant_lookup", "organization_id", "recipient_scope", "user_id"),
        Index("ix_notifications_unread", "organization_id", "is_read"),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Deterministic serialization to a Python dictionary."""
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "recipient_scope": str(self.recipient_scope),
            "user_id": self.user_id,
            "scope_target": self.scope_target,
            "event_id": self.event_id,
            "scan_id": self.scan_id,
            "dedupe_key": self.dedupe_key,
            "type": self.type,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "link": self.link,
            "is_read": bool(self.is_read),
            "read_at": self.read_at.isoformat() if self.read_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


@event.listens_for(Notification, "before_insert")
@event.listens_for(Notification, "before_update")
def _enforce_notification_scope_invariants(mapper, connection, target: Notification) -> None:
    """
    Model-level invariant enforcement:
    - Guarantees scope_target is derived strictly from recipient_scope and user_id.
    - Overwrites any caller-provided scope_target.
    - Enforces that USER scope has positive user_id, and ORGANIZATION scope has user_id=None.
    """
    scope = target.recipient_scope.value if isinstance(target.recipient_scope, Enum) else str(target.recipient_scope)
    if scope == RecipientScope.USER.value:
        if target.user_id is None or target.user_id <= 0:
            raise ValueError("Model invariant violation: user_id must be a positive integer when recipient_scope is USER.")
        target.scope_target = target.user_id
    elif scope == RecipientScope.ORGANIZATION.value:
        if target.user_id is not None:
            raise ValueError("Model invariant violation: user_id must be None when recipient_scope is ORGANIZATION.")
        target.scope_target = 0
    else:
        raise ValueError(f"Model invariant violation: Unsupported recipient_scope '{target.recipient_scope}'.")


class NotificationCreate(BaseModel):
    """
    Validated DTO for creating a new notification.
    Enforces ownership invariants, string bounds, and defensive sanitization.
    """
    organization_id: int
    recipient_scope: RecipientScope
    user_id: Optional[int] = None
    event_id: str
    scan_id: str
    dedupe_key: str
    type: str
    severity: Union[NotificationSeverity, str] = NotificationSeverity.INFO
    title: str
    message: str
    link: Optional[str] = None

    # Internal derived target (computed automatically; not user-controlled)
    scope_target: int = 0

    class Config:
        use_enum_values = True

    @validator("organization_id")
    def validate_org_id(cls, v: int) -> int:
        if not isinstance(v, int) or v <= 0:
            raise ValueError("organization_id must be a positive integer.")
        return v

    @validator("title")
    def validate_title_content(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("title cannot be empty.")
        if len(v) > 255:
            raise ValueError(f"title exceeds 255 characters limit ({len(v)} chars).")
        validate_no_secrets(v, "title")
        return v.strip()

    @validator("message")
    def validate_message_content(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("message cannot be empty.")
        if len(v) > 2000:
            raise ValueError(f"message exceeds 2000 characters limit ({len(v)} chars).")
        validate_no_secrets(v, "message")
        return v.strip()

    @validator("link")
    def validate_link_content(cls, v: Optional[str]) -> Optional[str]:
        return validate_relative_link(v)

    @validator("event_id")
    def validate_event_id(cls, v: str) -> str:
        if not v or not v.strip() or len(v) > 64:
            raise ValueError("event_id must be non-empty and at most 64 characters.")
        return v.strip()

    @validator("scan_id")
    def validate_scan_id(cls, v: str) -> str:
        if not v or not v.strip() or len(v) > 64:
            raise ValueError("scan_id must be non-empty and at most 64 characters.")
        return v.strip()

    @validator("dedupe_key")
    def validate_dedupe_key(cls, v: str) -> str:
        if not v or not v.strip() or len(v) > 64:
            raise ValueError("dedupe_key must be non-empty and at most 64 characters.")
        return v.strip()

    @validator("type")
    def validate_type(cls, v: str) -> str:
        if not v or not v.strip() or len(v) > 32:
            raise ValueError("type must be non-empty and at most 32 characters.")
        return v.strip()

    @validator("severity")
    def validate_severity(cls, v: Any) -> str:
        val = v.value if isinstance(v, Enum) else str(v)
        val = val.upper()
        if val not in [s.value for s in NotificationSeverity]:
            raise ValueError(f"Invalid severity '{v}'. Must be one of: {[s.value for s in NotificationSeverity]}")
        return val

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        # Enforce and derive scope_target internally
        if self.recipient_scope == RecipientScope.USER or self.recipient_scope == RecipientScope.USER.value:
            if self.user_id is None or not isinstance(self.user_id, int) or self.user_id <= 0:
                raise ValueError("user_id must be a positive integer when recipient_scope is USER.")
            object.__setattr__(self, "scope_target", self.user_id)
        elif self.recipient_scope == RecipientScope.ORGANIZATION or self.recipient_scope == RecipientScope.ORGANIZATION.value:
            if self.user_id is not None:
                raise ValueError("user_id must be None when recipient_scope is ORGANIZATION.")
            object.__setattr__(self, "scope_target", 0)
        else:
            raise ValueError(f"Unsupported recipient_scope '{self.recipient_scope}'.")


class NotificationRead(BaseModel):
    """DTO for viewing notification details."""
    id: int
    organization_id: int
    recipient_scope: str
    user_id: Optional[int]
    scope_target: int
    event_id: str
    scan_id: str
    dedupe_key: str
    type: str
    severity: str
    title: str
    message: str
    link: Optional[str]
    is_read: bool
    read_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "recipient_scope": self.recipient_scope,
            "user_id": self.user_id,
            "scope_target": self.scope_target,
            "event_id": self.event_id,
            "scan_id": self.scan_id,
            "dedupe_key": self.dedupe_key,
            "type": self.type,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "link": self.link,
            "is_read": self.is_read,
            "read_at": self.read_at.isoformat() if self.read_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
