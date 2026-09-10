"""
TimeCodeSecurity (TCS) Delivery Repository Interface.

Defines the abstract multi-tenant contract for delivery audit log persistence,
querying, and telemetry.

Invariants:
- Strictly append-only: no update or delete operations exist.
- All query operations require strict organization_id scoping.
- Deterministic pagination strictly orders by created_at DESC, id DESC.
- Bounded limits (1..100) and validated offsets (>= 0).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, List, Optional, Tuple, Union

from delivery_models import (
    DeliveryAuditLog,
    DeliveryAuditLogCreate,
    DeliveryStatsResponse,
)


class DeliveryRepository(ABC):
    """
    Abstract append-only interface for delivery audit storage.
    Enforces tenant isolation and immutable audit retention.
    """

    @abstractmethod
    def create(self, record: Union[DeliveryAuditLogCreate, Any, dict]) -> DeliveryAuditLog:
        """
        Appends a new delivery audit record.
        Strictly append-only; existing records cannot be modified.
        """
        pass

    @abstractmethod
    def get_by_id(
        self,
        delivery_id: str,
        organization_id: int,
    ) -> Optional[DeliveryAuditLog]:
        """
        Retrieves a single delivery audit record enforcing organization scope.
        Returns None if not found or if belonging to another organization.
        """
        pass

    @abstractmethod
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
        Enforces organization boundary, limit (1..100), and offset (>= 0).
        Returns a tuple of (items, total_count).
        """
        pass

    @abstractmethod
    def get_stats(
        self,
        organization_id: int,
        since: Optional[datetime] = None,
    ) -> DeliveryStatsResponse:
        """
        Computes delivery statistics for an organization since an optional timestamp.
        """
        pass
