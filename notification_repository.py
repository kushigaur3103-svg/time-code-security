"""
TimeCodeSecurity (TCS) Notification Repository Interface.

Defines the abstract multi-tenant contract for notification persistence,
querying, deduplication, and read-state management.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional, Union

from notification_models import Notification, NotificationCreate, RecipientScope


class NotificationRepository(ABC):
    """
    Abstract interface for notification storage.
    Enforces tenant isolation across all query and mutation methods.
    """

    @abstractmethod
    def create(self, payload: Union[NotificationCreate, dict]) -> Notification:
        """
        Idempotently creates a notification record.
        If a notification with identical dedupe identity
        (organization_id, scope_target, dedupe_key, type) already exists,
        returns the existing record without duplicate row insertion.
        """
        pass

    @abstractmethod
    def get_by_id(
        self,
        notification_id: int,
        organization_id: int,
        user_id: Optional[int] = None,
    ) -> Optional[Notification]:
        """
        Retrieves a notification by ID enforcing strict tenant and user boundary.
        - Requires organization_id.
        - If user_id is provided, returns the notification if it is USER-scoped
          for that user OR if it is ORGANIZATION-scoped.
        - If user_id is None, returns the notification only if it is ORGANIZATION-scoped.
        - Returns None if not found or unauthorized.
        """
        pass

    @abstractmethod
    def list_notifications(
        self,
        organization_id: int,
        user_id: Optional[int] = None,
        recipient_scope: Optional[Union[RecipientScope, str]] = None,
        unread_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Notification]:
        """
        Lists notifications ordered chronologically by created_at DESC.
        - Requires organization_id.
        - Respects user/organization boundaries and unread filtering.
        """
        pass

    @abstractmethod
    def count_unread(
        self,
        organization_id: int,
        user_id: Optional[int] = None,
        recipient_scope: Optional[Union[RecipientScope, str]] = None,
    ) -> int:
        """
        Counts unread notifications matching the requested tenant and recipient scope.
        """
        pass

    @abstractmethod
    def mark_read(
        self,
        notification_id: int,
        organization_id: int,
        user_id: Optional[int] = None,
        read_at: Optional[datetime] = None,
    ) -> bool:
        """
        Marks a single notification as read, enforcing:
        is_read = True and read_at is set atomically.
        Returns True if updated (or already read), False if not found/unauthorized.
        """
        pass

    @abstractmethod
    def mark_all_read(
        self,
        organization_id: int,
        user_id: Optional[int] = None,
        read_at: Optional[datetime] = None,
    ) -> int:
        """
        Marks all unread notifications matching the tenant/user scope as read in a single atomic transaction.
        Returns the count of updated records.
        """
        pass

    @abstractmethod
    def exists_by_dedupe_key(
        self,
        dedupe_key: str,
        organization_id: int,
        user_id: Optional[int] = None,
        type: Optional[str] = None,
    ) -> bool:
        """
        Checks whether a notification matching the semantic dedupe identity already exists.
        """
        pass
