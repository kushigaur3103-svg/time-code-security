"""
TimeCodeSecurity (TCS) SQLite/SQLAlchemy Delivery Repository.

Concrete implementation of DeliveryRepository using SQLAlchemy and SQLite/PostgreSQL.
Enforces multi-tenant isolation, deterministic ordering, and append-only audit retention.

Invariants:
- All operations require organization_id.
- Pagination strictly orders by created_at DESC, id DESC.
- Limit is bounded between 1 and 100; offset is >= 0.
- Append-only: strictly no update or delete methods exist.
"""

from __future__ import annotations

import datetime
import uuid
from contextlib import contextmanager
from typing import Any, Generator, List, Optional, Tuple, Union

from sqlalchemy import and_, event, func
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from delivery_models import (
    Base,
    DeliveryAuditLog,
    DeliveryAuditLogCreate,
    DeliveryStatsResponse,
    MAX_AUDIT_ERROR_LENGTH,
)
from delivery_repository import DeliveryRepository


def configure_sqlite_pragmas(target_engine: Engine) -> None:
    """
    Configures critical SQLite pragmas:
    - PRAGMA foreign_keys=ON: Relational integrity.
    - PRAGMA busy_timeout=5000: Prevents 'database is locked' errors during concurrency.
    - PRAGMA journal_mode=WAL: Concurrency optimization.
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
                    pass
            except Exception:
                pass
            finally:
                cursor.close()


class SqliteDeliveryRepository(DeliveryRepository):
    """
    SQLAlchemy-backed append-only repository for delivery audit logs.
    Supports dependency-injected sessions, sessionmakers, or engines.
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
        """Provides a safe transactional session scope."""
        if self._session is not None:
            yield self._session
        elif self._session_factory is not None:
            session = self._session_factory()
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()
        else:
            raise RuntimeError(
                "No SQLAlchemy session, session_factory, or engine configured for SqliteDeliveryRepository."
            )

    def init_db(self) -> None:
        """Initializes tables in the bound engine or session bind."""
        if self._engine is not None:
            Base.metadata.create_all(bind=self._engine)
        elif self._session is not None:
            bind = self._session.get_bind()
            if bind is not None:
                Base.metadata.create_all(bind=bind)

    def create(self, record: Union[DeliveryAuditLogCreate, Any, dict]) -> DeliveryAuditLog:
        """
        Appends a new delivery audit record.
        Strictly append-only; handles DeliveryResult, DeliveryAuditLogCreate, or dict.
        """
        if isinstance(record, dict):
            delivery_id = record.get("id") or f"deliv_{uuid.uuid4().hex}"
            org_id = int(record["organization_id"])
            event_id = str(record["event_id"])
            scan_id = record.get("scan_id")
            idempotency_key = str(record["idempotency_key"])
            channel = str(record.get("channel", "WEBHOOK"))
            status = record["status"]
            status_code = record.get("status_code")
            attempts = int(record.get("attempts", 1))
            duration_ms = float(record.get("duration_ms", 0.0))
            error_message = record.get("error_message")
            created_at = record.get("created_at")
        else:
            delivery_id = getattr(record, "id", None) or f"deliv_{uuid.uuid4().hex}"
            org_id = int(getattr(record, "organization_id"))
            event_id = str(getattr(record, "event_id"))
            scan_id = getattr(record, "scan_id", None)
            idempotency_key = str(getattr(record, "idempotency_key"))
            channel = str(getattr(record, "channel", "WEBHOOK"))
            status = getattr(record, "status")
            status_code = getattr(record, "status_code", None)
            attempts = int(getattr(record, "attempts", 1))
            duration_ms = float(getattr(record, "duration_ms", 0.0))
            error_message = getattr(record, "error_message", None)
            created_at = getattr(record, "created_at", None)

        if hasattr(status, "value"):
            status_str = status.value
        else:
            status_str = str(status)

        if error_message and len(error_message) > MAX_AUDIT_ERROR_LENGTH:
            error_message = error_message[:MAX_AUDIT_ERROR_LENGTH]

        if created_at is None:
            created_at = datetime.datetime.now(datetime.timezone.utc)
        elif created_at.tzinfo is not None:
            created_at = created_at.astimezone(datetime.timezone.utc).replace(tzinfo=None)

        audit_entry = DeliveryAuditLog(
            id=delivery_id,
            organization_id=org_id,
            event_id=event_id,
            scan_id=scan_id,
            idempotency_key=idempotency_key,
            channel=channel,
            status=status_str,
            status_code=status_code,
            attempts=attempts,
            duration_ms=duration_ms,
            error_message=error_message,
            created_at=created_at,
        )

        with self._session_scope() as session:
            session.add(audit_entry)
            session.flush()
            return audit_entry

    def get_by_id(
        self,
        delivery_id: str,
        organization_id: int,
    ) -> Optional[DeliveryAuditLog]:
        """
        Retrieves a delivery audit log enforcing organization scoping.
        Returns None if not found or unauthorized.
        """
        with self._session_scope() as session:
            return (
                session.query(DeliveryAuditLog)
                .filter(
                    DeliveryAuditLog.id == delivery_id,
                    DeliveryAuditLog.organization_id == organization_id,
                )
                .first()
            )

    def list(
        self,
        organization_id: int,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[DeliveryAuditLog], int]:
        """
        Lists delivery audit logs with deterministic ordering:
        ORDER BY created_at DESC, id DESC.
        """
        clamped_limit = max(1, min(100, int(limit)))
        clamped_offset = max(0, int(offset))

        with self._session_scope() as session:
            query = session.query(DeliveryAuditLog).filter(
                DeliveryAuditLog.organization_id == organization_id
            )
            if status:
                query = query.filter(DeliveryAuditLog.status == status)

            total_count = query.count()
            items = (
                query.order_by(
                    DeliveryAuditLog.created_at.desc(),
                    DeliveryAuditLog.id.desc(),
                )
                .offset(clamped_offset)
                .limit(clamped_limit)
                .all()
            )
            return items, total_count

    def get_stats(
        self,
        organization_id: int,
        since: Optional[datetime.datetime] = None,
    ) -> DeliveryStatsResponse:
        """
        Computes delivery metrics for an organization.
        """
        with self._session_scope() as session:
            query = session.query(DeliveryAuditLog).filter(
                DeliveryAuditLog.organization_id == organization_id
            )
            if since:
                if since.tzinfo is not None:
                    since_utc = since.astimezone(datetime.timezone.utc).replace(tzinfo=None)
                else:
                    since_utc = since
                query = query.filter(DeliveryAuditLog.created_at >= since_utc)

            total = query.count()
            success_count = query.filter(DeliveryAuditLog.status == "SUCCESS").count()
            failure_count = total - success_count

            avg_dur = (
                session.query(func.avg(DeliveryAuditLog.duration_ms))
                .filter(DeliveryAuditLog.organization_id == organization_id)
                .scalar()
                or 0.0
            )

            return DeliveryStatsResponse(
                organization_id=organization_id,
                total_deliveries=total,
                success_count=success_count,
                failure_count=failure_count,
                average_duration_ms=float(avg_dur),
            )
