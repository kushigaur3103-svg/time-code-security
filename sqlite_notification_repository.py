"""
TimeCodeSecurity (TCS) SQLite/SQLAlchemy Notification Repository.

Concrete implementation of NotificationRepository using SQLAlchemy and SQLite.
Enforces multi-tenant isolation, SQLite pragmas (WAL mode, busy timeout, foreign keys),
authoritative database unique constraints, and atomic state transitions.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from enum import Enum
from typing import Any, Generator, List, Optional, Union

from sqlalchemy import and_, event, func, or_
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from notification_models import (
    Base,
    Notification,
    NotificationCreate,
    RecipientScope,
)
from notification_repository import NotificationRepository


def configure_sqlite_pragmas(target_engine: Engine) -> None:
    """
    Configures critical SQLite pragmas:
    - PRAGMA foreign_keys=ON: Relational integrity.
    - PRAGMA busy_timeout=5000: Prevents 'database is locked' errors during concurrency.
    - PRAGMA journal_mode=WAL: Concurrency optimization (readers do not block writers).
    """
    if target_engine is not None and target_engine.dialect.name == "sqlite":
        @event.listens_for(target_engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA busy_timeout=5000")
                try:
                    cursor.execute("PRAGMA journal_mode=WAL")
                except Exception:
                    pass  # In-memory SQLite safely degrades without error
            except Exception:
                pass
            finally:
                cursor.close()


class SqliteNotificationRepository(NotificationRepository):
    """
    SQLAlchemy-backed repository implementation for SQLite.
    Supports dependency-injected sessions, sessionmakers, or custom engines.
    """

    def __init__(
        self,
        session: Optional[Session] = None,
        session_factory: Optional[sessionmaker] = None,
        engine: Optional[Engine] = None,
    ) -> None:
        self._session = session
        self._engine = engine
        self._session_factory = session_factory

        if self._engine is not None:
            configure_sqlite_pragmas(self._engine)
            if self._session_factory is None and self._session is None:
                self._session_factory = sessionmaker(
                    autocommit=False,
                    autoflush=False,
                    bind=self._engine,
                    expire_on_commit=False,
                )

        if self._session is None and self._session_factory is None:
            # Fallback to existing application infrastructure
            try:
                from app import SessionLocal, engine as app_engine
                self._engine = app_engine
                self._session_factory = SessionLocal
                if self._engine is not None:
                    configure_sqlite_pragmas(self._engine)
            except Exception:
                pass

    @contextmanager
    def _session_scope(self) -> Generator[Session, None, None]:
        """Provides a transactional session scope."""
        if self._session is not None:
            yield self._session
        elif self._session_factory is not None:
            session = self._session_factory()
            try:
                yield session
            finally:
                session.close()
        else:
            raise RuntimeError(
                "No SQLAlchemy session, session_factory, or engine configured for SqliteNotificationRepository."
            )

    def init_db(self) -> None:
        """Initializes tables in the bound engine if available."""
        if self._engine is not None:
            Base.metadata.create_all(bind=self._engine)
        elif self._session is not None:
            bind = self._session.get_bind()
            if bind is not None:
                Base.metadata.create_all(bind=bind)

    def _find_existing(
        self,
        session: Session,
        org_id: int,
        scope_target: int,
        dedupe_key: str,
        notif_type: str,
    ) -> Optional[Notification]:
        """Lookup existing record by dedupe identity."""
        return session.query(Notification).filter(
            Notification.organization_id == org_id,
            Notification.scope_target == scope_target,
            Notification.dedupe_key == dedupe_key,
            Notification.type == notif_type,
        ).first()

    def create(self, payload: Union[NotificationCreate, dict]) -> Notification:
        """
        Idempotently creates a notification record.
        On concurrent conflict (IntegrityError), rolls back and returns the winning record.
        """
        if isinstance(payload, dict):
            payload = NotificationCreate(**payload)
        elif not isinstance(payload, NotificationCreate):
            raise TypeError("payload must be a NotificationCreate instance or dictionary.")

        scope_target = payload.scope_target
        org_id = payload.organization_id
        dedupe_key = payload.dedupe_key
        notif_type = payload.type

        with self._session_scope() as session:
            # 1. Optional application-level check optimization
            existing = self._find_existing(
                session, org_id, scope_target, dedupe_key, notif_type
            )
            if existing is not None:
                return existing

            # 2. Construct record
            record = Notification(
                organization_id=org_id,
                recipient_scope=payload.recipient_scope.value if isinstance(payload.recipient_scope, Enum) else str(payload.recipient_scope),
                user_id=payload.user_id,
                scope_target=scope_target,
                event_id=payload.event_id,
                scan_id=payload.scan_id,
                dedupe_key=dedupe_key,
                type=notif_type,
                severity=payload.severity.value if isinstance(payload.severity, Enum) else str(payload.severity),
                title=payload.title,
                message=payload.message,
                link=payload.link,
                is_read=False,
                read_at=None,
                created_at=datetime.utcnow(),
            )

            # 3. Attempt insert/commit with race-safe rollback
            try:
                session.add(record)
                session.commit()
                session.refresh(record)
                return record
            except IntegrityError:
                session.rollback()
                winning = session.query(Notification).filter(
                    Notification.organization_id == org_id,
                    Notification.scope_target == scope_target,
                    Notification.dedupe_key == dedupe_key,
                    Notification.type == notif_type,
                ).first()
                if winning is not None:
                    return winning
                raise
            except Exception:
                session.rollback()
                raise

    def get_by_id(
        self,
        notification_id: int,
        organization_id: int,
        user_id: Optional[int] = None,
    ) -> Optional[Notification]:
        """Fetch notification by ID enforcing tenant and user isolation."""
        if organization_id is None or not isinstance(organization_id, int) or organization_id <= 0:
            raise ValueError("organization_id must be a positive integer.")
        if user_id is not None and (not isinstance(user_id, int) or user_id <= 0):
            raise ValueError("user_id must be a positive integer or None.")

        with self._session_scope() as session:
            query = session.query(Notification).filter(
                Notification.id == notification_id,
                Notification.organization_id == organization_id,
            )
            if user_id is not None:
                query = query.filter(
                    or_(
                        and_(
                            Notification.recipient_scope == RecipientScope.USER.value,
                            Notification.user_id == user_id,
                        ),
                        Notification.recipient_scope == RecipientScope.ORGANIZATION.value,
                    )
                )
            else:
                query = query.filter(
                    Notification.recipient_scope == RecipientScope.ORGANIZATION.value
                )
            return query.first()

    def list_notifications(
        self,
        organization_id: int,
        user_id: Optional[int] = None,
        recipient_scope: Optional[Union[RecipientScope, str]] = None,
        unread_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Notification]:
        """List notifications ordered by created_at DESC with tenant isolation."""
        if organization_id is None or not isinstance(organization_id, int) or organization_id <= 0:
            raise ValueError("organization_id must be a positive integer.")
        if user_id is not None and (not isinstance(user_id, int) or user_id <= 0):
            raise ValueError("user_id must be a positive integer or None.")
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative integers.")

        with self._session_scope() as session:
            query = session.query(Notification).filter(
                Notification.organization_id == organization_id
            )

            if unread_only:
                query = query.filter(Notification.is_read == False)

            if recipient_scope is not None:
                scope_val = recipient_scope.value if isinstance(recipient_scope, Enum) else str(recipient_scope)
                if scope_val not in [s.value for s in RecipientScope]:
                    raise ValueError(f"Invalid recipient_scope '{recipient_scope}'.")
                query = query.filter(Notification.recipient_scope == scope_val)
                if scope_val == RecipientScope.USER.value and user_id is not None:
                    query = query.filter(Notification.user_id == user_id)
            else:
                if user_id is not None:
                    query = query.filter(
                        or_(
                            and_(
                                Notification.recipient_scope == RecipientScope.USER.value,
                                Notification.user_id == user_id,
                            ),
                            Notification.recipient_scope == RecipientScope.ORGANIZATION.value,
                        )
                    )
                else:
                    query = query.filter(
                        Notification.recipient_scope == RecipientScope.ORGANIZATION.value
                    )

            query = query.order_by(Notification.created_at.desc(), Notification.id.desc())
            if offset:
                query = query.offset(offset)
            if limit:
                query = query.limit(limit)

            return query.all()

    def count_unread(
        self,
        organization_id: int,
        user_id: Optional[int] = None,
        recipient_scope: Optional[Union[RecipientScope, str]] = None,
    ) -> int:
        """Count unread notifications matching tenant/recipient scope."""
        if organization_id is None or not isinstance(organization_id, int) or organization_id <= 0:
            raise ValueError("organization_id must be a positive integer.")
        if user_id is not None and (not isinstance(user_id, int) or user_id <= 0):
            raise ValueError("user_id must be a positive integer or None.")

        with self._session_scope() as session:
            query = session.query(func.count(Notification.id)).filter(
                Notification.organization_id == organization_id,
                Notification.is_read == False,
            )
            if recipient_scope is not None:
                scope_val = recipient_scope.value if isinstance(recipient_scope, Enum) else str(recipient_scope)
                if scope_val not in [s.value for s in RecipientScope]:
                    raise ValueError(f"Invalid recipient_scope '{recipient_scope}'.")
                query = query.filter(Notification.recipient_scope == scope_val)
                if scope_val == RecipientScope.USER.value and user_id is not None:
                    query = query.filter(Notification.user_id == user_id)
            else:
                if user_id is not None:
                    query = query.filter(
                        or_(
                            and_(
                                Notification.recipient_scope == RecipientScope.USER.value,
                                Notification.user_id == user_id,
                            ),
                            Notification.recipient_scope == RecipientScope.ORGANIZATION.value,
                        )
                    )
                else:
                    query = query.filter(
                        Notification.recipient_scope == RecipientScope.ORGANIZATION.value
                    )
            return query.scalar() or 0

    def mark_read(
        self,
        notification_id: int,
        organization_id: int,
        user_id: Optional[int] = None,
        read_at: Optional[datetime] = None,
    ) -> bool:
        """Marks a single notification as read, enforcing invariant and tenant boundary."""
        if organization_id is None or not isinstance(organization_id, int) or organization_id <= 0:
            raise ValueError("organization_id must be a positive integer.")

        with self._session_scope() as session:
            query = session.query(Notification).filter(
                Notification.id == notification_id,
                Notification.organization_id == organization_id,
            )
            if user_id is not None:
                query = query.filter(
                    or_(
                        and_(
                            Notification.recipient_scope == RecipientScope.USER.value,
                            Notification.user_id == user_id,
                        ),
                        Notification.recipient_scope == RecipientScope.ORGANIZATION.value,
                    )
                )
            else:
                query = query.filter(
                    Notification.recipient_scope == RecipientScope.ORGANIZATION.value
                )

            record = query.first()
            if record is None:
                return False

            if record.is_read:
                return True

            ts = read_at or datetime.utcnow()
            try:
                record.is_read = True
                record.read_at = ts
                session.commit()
                return True
            except Exception:
                session.rollback()
                raise

    def mark_all_read(
        self,
        organization_id: int,
        user_id: Optional[int] = None,
        read_at: Optional[datetime] = None,
    ) -> int:
        """Marks all unread notifications matching scope as read."""
        if organization_id is None or not isinstance(organization_id, int) or organization_id <= 0:
            raise ValueError("organization_id must be a positive integer.")

        ts = read_at or datetime.utcnow()

        with self._session_scope() as session:
            query = session.query(Notification).filter(
                Notification.organization_id == organization_id,
                Notification.is_read == False,
            )
            if user_id is not None:
                query = query.filter(
                    or_(
                        and_(
                            Notification.recipient_scope == RecipientScope.USER.value,
                            Notification.user_id == user_id,
                        ),
                        Notification.recipient_scope == RecipientScope.ORGANIZATION.value,
                    )
                )
            else:
                query = query.filter(
                    Notification.recipient_scope == RecipientScope.ORGANIZATION.value
                )

            try:
                unread_records = query.all()
                count = len(unread_records)
                if count > 0:
                    for rec in unread_records:
                        rec.is_read = True
                        rec.read_at = ts
                    session.commit()
                return count
            except Exception:
                session.rollback()
                raise

    def exists_by_dedupe_key(
        self,
        dedupe_key: str,
        organization_id: int,
        user_id: Optional[int] = None,
        type: Optional[str] = None,
    ) -> bool:
        """Check whether a notification with this dedupe identity already exists."""
        if organization_id is None or not isinstance(organization_id, int) or organization_id <= 0:
            raise ValueError("organization_id must be a positive integer.")
        if not dedupe_key or not isinstance(dedupe_key, str):
            raise ValueError("dedupe_key must be a non-empty string.")

        scope_target = user_id if user_id is not None else 0

        with self._session_scope() as session:
            query = session.query(Notification.id).filter(
                Notification.organization_id == organization_id,
                Notification.scope_target == scope_target,
                Notification.dedupe_key == dedupe_key,
            )
            if type is not None:
                query = query.filter(Notification.type == type)
            return query.first() is not None
