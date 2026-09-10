"""
TimeCodeSecurity (TCS) Notification & Delivery REST API Routes.

Exposes authenticated multi-tenant endpoints for:
- Listing in-app notifications
- Querying unread counts
- Marking notifications as read/unread
- Marking all notifications as read
- Querying delivery audit logs (Admin only)

Invariants:
- All routes require authentication via JWT Bearer token or API key.
- Strict multi-tenant isolation: queries are bounded by user's organization_id.
- Cross-tenant access returns HTTP 404 to prevent resource enumeration.
- Delivery audit inspection is strictly restricted to users with org_role == 'admin' (HTTP 403 otherwise).
- Deterministic pagination: ORDER BY created_at DESC, id DESC.
- UTC ISO-8601 serialized timestamps.
- Zero raw secrets, payload bodies, or target IPs exposed in public responses.
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from delivery_models import DeliveryAuditLogRead
from sqlite_delivery_repository import SqliteDeliveryRepository
from sqlite_notification_repository import SqliteNotificationRepository

logger = logging.getLogger("tcs.notification_routes")

router = APIRouter(prefix="/api/notifications", tags=["Notifications"])


# ---------------------------------------------------------------------------
# DTOs
# ---------------------------------------------------------------------------

class NotificationReadResponse(BaseModel):
    id: int
    organization_id: int
    user_id: Optional[int] = None
    recipient_scope: str
    event_id: str
    scan_id: Optional[str] = None
    channel: str
    severity: str
    title: str
    message: str
    link: Optional[str] = None
    is_read: bool
    read_at: Optional[str] = None
    created_at: str

    class Config:
        from_attributes = True
        orm_mode = True


class NotificationListResponse(BaseModel):
    items: List[NotificationReadResponse]
    total: int
    limit: int
    offset: int


class UnreadCountResponse(BaseModel):
    unread_count: int


class MarkReadRequest(BaseModel):
    is_read: bool = True


class MarkAllReadResponse(BaseModel):
    marked_count: int
    updated_at: str


class DeliveryAuditListResponse(BaseModel):
    items: List[DeliveryAuditLogRead]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Dependencies & Helpers
# ---------------------------------------------------------------------------

def get_db_session():
    """Provides a transactional database session from application infrastructure."""
    from app import SessionLocal
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_authenticated_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db_session),
) -> Any:
    """
    Authenticates requests via Bearer JWT or TCS API key.
    Enforces authentication failure semantics (HTTP 401).
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")

    token = authorization.split(" ")[1]
    from app import User, SECRET_KEY
    import jwt

    if token.startswith("tcs_"):
        user = db.query(User).filter(User.api_key == token).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid API Key")
        return user

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email = payload.get("sub")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    if not email:
        raise HTTPException(status_code=401, detail="Invalid token subject")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def get_effective_org_id(user: Any) -> int:
    """Resolves the user's organization ID, defaulting to user ID for individual accounts."""
    org_id = getattr(user, "org_id", None)
    if org_id is not None and isinstance(org_id, int) and org_id > 0:
        return org_id
    # Fallback to user ID if no explicit organization is configured
    return int(user.id)


def serialize_notification(n: Any) -> NotificationReadResponse:
    """Serializes a Notification SQLAlchemy entity into safe DTO."""
    created_at_str = (
        n.created_at.replace(tzinfo=datetime.timezone.utc).isoformat()
        if n.created_at and n.created_at.tzinfo is None
        else n.created_at.isoformat() if n.created_at else None
    )
    read_at_str = (
        n.read_at.replace(tzinfo=datetime.timezone.utc).isoformat()
        if n.read_at and n.read_at.tzinfo is None
        else n.read_at.isoformat() if n.read_at else None
    )
    return NotificationReadResponse(
        id=n.id,
        organization_id=n.organization_id,
        user_id=n.user_id,
        recipient_scope=n.recipient_scope,
        event_id=n.event_id,
        scan_id=n.scan_id,
        channel=getattr(n, "channel", "IN_APP"),
        severity=getattr(n, "severity", "INFO"),
        title=n.title,
        message=n.message,
        link=n.link,
        is_read=bool(n.is_read),
        read_at=read_at_str,
        created_at=created_at_str,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=NotificationListResponse)
def list_notifications(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    unread_only: bool = Query(False),
    channel: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    user: Any = Depends(get_authenticated_user),
    db: Session = Depends(get_db_session),
):
    """
    Lists in-app notifications for the authenticated user and organization.
    Ordered deterministically by created_at DESC, id DESC.
    """
    try:
        if not isinstance(limit, int):
            limit = getattr(limit, "default", 50)
        if not isinstance(offset, int):
            offset = getattr(offset, "default", 0)
        if not isinstance(channel, str):
            channel = None
        if not isinstance(severity, str):
            severity = None

        org_id = get_effective_org_id(user)
        repo = SqliteNotificationRepository(session=db)
        items = repo.list_notifications(
            organization_id=org_id,
            user_id=user.id,
            unread_only=unread_only,
            limit=limit,
            offset=offset,
        )

        if channel:
            items = [i for i in items if getattr(i, "channel", None) == channel]
        if severity:
            items = [i for i in items if getattr(i, "severity", None) == severity]

        # Total count matching tenant and recipient scope
        total = repo.count_unread(organization_id=org_id, user_id=user.id) if unread_only else len(items)

        return NotificationListResponse(
            items=[serialize_notification(i) for i in items],
            total=total,
            limit=limit,
            offset=offset,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Error listing notifications: %s", exc)
        raise HTTPException(status_code=500, detail="Internal database operation failed")


@router.get("/unread-count", response_model=UnreadCountResponse)
def get_unread_count(
    user: Any = Depends(get_authenticated_user),
    db: Session = Depends(get_db_session),
):
    """Returns the total number of unread notifications visible to the authenticated user."""
    try:
        org_id = get_effective_org_id(user)
        repo = SqliteNotificationRepository(session=db)
        count = repo.count_unread(organization_id=org_id, user_id=user.id)
        return UnreadCountResponse(unread_count=count)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Error fetching unread count: %s", exc)
        raise HTTPException(status_code=500, detail="Internal database operation failed")


@router.patch("/{id}/read", response_model=NotificationReadResponse)
def mark_notification_read(
    id: int,
    payload: MarkReadRequest = MarkReadRequest(),
    user: Any = Depends(get_authenticated_user),
    db: Session = Depends(get_db_session),
):
    """
    Marks a single notification as read or unread.
    Enforces strict tenant isolation; cross-tenant requests return HTTP 404.
    """
    try:
        org_id = get_effective_org_id(user)
        repo = SqliteNotificationRepository(session=db)
        notif = repo.get_by_id(notification_id=id, organization_id=org_id, user_id=user.id)
        if notif is None:
            # Prevent ID enumeration across tenants: return 404
            raise HTTPException(status_code=404, detail="Notification not found")

        now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        if payload.is_read:
            repo.mark_read(
                notification_id=id,
                organization_id=org_id,
                user_id=user.id,
                read_at=now_utc,
            )
        else:
            notif.is_read = False
            notif.read_at = None
            db.commit()

        db.refresh(notif)
        return serialize_notification(notif)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Error marking notification read status: %s", exc)
        raise HTTPException(status_code=500, detail="Internal database operation failed")


@router.post("/mark-all-read", response_model=MarkAllReadResponse)
def mark_all_notifications_read(
    user: Any = Depends(get_authenticated_user),
    db: Session = Depends(get_db_session),
):
    """Marks all visible unread notifications in the tenant as read."""
    try:
        org_id = get_effective_org_id(user)
        repo = SqliteNotificationRepository(session=db)
        now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        marked_count = repo.mark_all_read(
            organization_id=org_id,
            user_id=user.id,
            read_at=now_utc,
        )
        return MarkAllReadResponse(
            marked_count=marked_count,
            updated_at=now_utc.replace(tzinfo=datetime.timezone.utc).isoformat(),
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Error marking all notifications read: %s", exc)
        raise HTTPException(status_code=500, detail="Internal database operation failed")


@router.get("/deliveries", response_model=DeliveryAuditListResponse)
def list_delivery_audits(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None),
    user: Any = Depends(get_authenticated_user),
    db: Session = Depends(get_db_session),
):
    """
    Lists webhook delivery audit logs for the authenticated organization.
    RESTRICTED: Only users with org_role == 'admin' may access this endpoint.
    Non-admin users receive HTTP 403 Forbidden.
    """
    try:
        org_role = getattr(user, "org_role", "member")
        if org_role != "admin":
            raise HTTPException(
                status_code=403,
                detail="Administrator privileges required to view delivery audit records",
            )

        if not isinstance(limit, int):
            limit = getattr(limit, "default", 50)
        if not isinstance(offset, int):
            offset = getattr(offset, "default", 0)
        if not isinstance(status, str):
            status = None

        org_id = get_effective_org_id(user)
        repo = SqliteDeliveryRepository(session=db)
        items, total = repo.list(
            organization_id=org_id,
            status=status,
            limit=limit,
            offset=offset,
        )

        read_items = [
            DeliveryAuditLogRead(
                id=i.id,
                organization_id=i.organization_id,
                event_id=i.event_id,
                scan_id=i.scan_id,
                idempotency_key=i.idempotency_key,
                channel=i.channel,
                status=i.status,
                status_code=i.status_code,
                attempts=i.attempts,
                duration_ms=i.duration_ms,
                error_message=i.error_message,
                created_at=(
                    i.created_at.replace(tzinfo=datetime.timezone.utc).isoformat()
                    if i.created_at and i.created_at.tzinfo is None
                    else i.created_at.isoformat() if i.created_at else ""
                ),
            )
            for i in items
        ]

        return DeliveryAuditListResponse(
            items=read_items,
            total=total,
            limit=limit,
            offset=offset,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Error listing delivery audit records: %s", exc)
        raise HTTPException(status_code=500, detail="Internal database operation failed")
