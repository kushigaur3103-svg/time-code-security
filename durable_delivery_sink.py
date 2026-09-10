"""
TimeCodeSecurity (TCS) Durable Delivery Result Sink.

Bridges Phase 15C webhook execution to persistent relational storage (delivery_audit_logs)
while preserving live diagnostic telemetry in InMemoryDeliveryResultSink.

Invariants:
- Thread-safe for concurrent worker threads.
- Obtains a fresh independent SQLAlchemy session for each persistence operation.
- Never shares sessions across workers or with FastAPI/scanner threads.
- Audit persistence failure is decoupled from webhook delivery:
  - Errors are logged with bounded diagnostic text.
  - In-memory result is safely retained.
  - Webhook is NEVER retried due to an audit write failure.
  - Original DeliveryResult status is NEVER mutated.
  - Worker threads NEVER terminate due to audit database failure.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, List, Optional

from sqlalchemy.orm import Session, sessionmaker

from delivery_models import DeliveryAuditLog
from sqlite_delivery_repository import SqliteDeliveryRepository
from webhook_adapter import DeliveryResult, InMemoryDeliveryResultSink

logger = logging.getLogger("tcs.durable_delivery_sink")


class DurableDeliveryResultSink:
    """
    Composite sink that records results to in-memory telemetry and
    persistently writes audit records to the database.
    """

    def __init__(
        self,
        session_factory: Optional[Callable[[], Session]] = None,
        memory_sink: Optional[InMemoryDeliveryResultSink] = None,
        repository_factory: Optional[Callable[[Session], SqliteDeliveryRepository]] = None,
    ) -> None:
        self._session_factory = session_factory
        self._memory_sink = memory_sink or InMemoryDeliveryResultSink()
        self._repository_factory = repository_factory or (lambda s: SqliteDeliveryRepository(session=s))
        self._db_lock = threading.Lock()

    @property
    def memory_sink(self) -> InMemoryDeliveryResultSink:
        return self._memory_sink

    def record(self, result: DeliveryResult) -> None:
        """
        Records the delivery result into memory and persists to the database.
        Failures in database persistence are isolated and do NOT alter delivery status.
        """
        # 1. Non-failing in-memory record
        try:
            self._memory_sink.record(result)
        except Exception as exc:
            logger.error("Failed to record delivery result in memory sink: %s", str(exc)[:200])

        # 2. Synchronous worker-local DB persistence with independent session
        if self._session_factory is not None:
            session: Optional[Session] = None
            try:
                with self._db_lock:
                    session = self._session_factory()
                    repo = self._repository_factory(session)
                    repo.create(result)
                    session.commit()
            except Exception as exc:
                if session is not None:
                    try:
                        session.rollback()
                    except Exception:
                        pass
                logger.error(
                    "Failed to persist delivery audit log for event_id=%s idempotency_key=%s: %s",
                    result.event_id,
                    result.idempotency_key,
                    str(exc)[:200],
                )
                # Webhook delivery is NOT retried.
                # DeliveryResult is NOT mutated.
                # Worker thread does NOT terminate.
            finally:
                if session is not None:
                    try:
                        session.close()
                    except Exception:
                        pass

    def get_recent(self) -> List[DeliveryResult]:
        """Delegates to internal memory sink for live telemetry."""
        return self._memory_sink.get_recent()

    def clear(self) -> None:
        """Delegates to internal memory sink."""
        self._memory_sink.clear()
