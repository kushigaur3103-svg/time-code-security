"""
TimeCodeSecurity (TCS) In-App Notification Delivery Adapter.

Consumes NotificationIntent objects produced by NotificationPolicy,
translates them to NotificationCreate DTOs, and persists them via
NotificationRepository.

Invariants:
- Consumes already-created NotificationIntent objects only.
- Adapters MUST NOT re-evaluate notification policy.
- Every NotificationIntent is attempted independently and sequentially.
- No fake transaction-wide rollback: successful intents remain committed.
- If any intent fails, an AggregatePersistenceError is raised after all intents
  have been attempted, propagating failure to the EventBus boundary without
  affecting scanner execution.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from notification_models import Notification, NotificationCreate, RecipientScope
from notification_policy import NotificationIntent
from notification_repository import NotificationRepository

logger = logging.getLogger("tcs.in_app_adapter")


class AggregatePersistenceError(Exception):
    """
    Raised when one or more NotificationIntent objects fail persistence.
    Contains the full list of failed intents and their associated exceptions.
    """

    def __init__(
        self,
        message: str,
        failures: List[Tuple[NotificationIntent, Exception]],
        persisted: List[Notification]
    ) -> None:
        super().__init__(message)
        self.failures = failures
        self.persisted = persisted

    def __repr__(self) -> str:
        return f"AggregatePersistenceError({len(self.failures)} failure(s), {len(self.persisted)} persisted)"


class InAppNotificationAdapter:
    """
    Synchronous adapter that persists In-App NotificationIntents via NotificationRepository.
    """

    def __init__(self, repository: NotificationRepository) -> None:
        if not isinstance(repository, NotificationRepository):
            raise TypeError(f"Expected NotificationRepository, got {type(repository).__name__}")
        self._repository = repository

    def handle_intent(self, intent: NotificationIntent) -> Notification:
        """
        Persists a single NotificationIntent.
        Raises exception immediately if this individual intent fails.
        """
        if not isinstance(intent, NotificationIntent):
            raise TypeError(f"Expected NotificationIntent, got {type(intent).__name__}")

        dto = NotificationCreate(
            organization_id=intent.organization_id,
            recipient_scope=intent.recipient_scope,
            user_id=intent.user_id,
            event_id=intent.event_id,
            scan_id=intent.scan_id,
            dedupe_key=intent.dedupe_key,
            type=intent.notification_type,
            severity=intent.severity,
            title=intent.title,
            message=intent.message,
            link=intent.link,
        )
        return self._repository.create(dto)

    def handle_intents(self, intents: Sequence[NotificationIntent]) -> List[Notification]:
        """
        Processes a sequence of NotificationIntents independently.
        All intents are attempted. Successful intents remain persisted.
        If any intent fails, an AggregatePersistenceError is raised after all
        intents have been attempted.
        """
        persisted: List[Notification] = []
        failures: List[Tuple[NotificationIntent, Exception]] = []

        for intent in intents:
            if intent.channel != "IN_APP":
                continue
            try:
                notif = self.handle_intent(intent)
                persisted.append(notif)
            except Exception as exc:
                logger.error(
                    "Failed to persist in-app notification intent %s for org %s: %s",
                    intent.intent_id,
                    intent.organization_id,
                    exc,
                )
                failures.append((intent, exc))

        if failures:
            raise AggregatePersistenceError(
                f"In-app persistence failed for {len(failures)} of {len(intents)} intent(s).",
                failures=failures,
                persisted=persisted,
            )

        return persisted
