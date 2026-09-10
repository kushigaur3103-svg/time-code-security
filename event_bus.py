"""
TimeCodeSecurity (TCS) In-Memory Synchronous Event Bus.

Provides deterministic, insertion-ordered FIFO event dispatch with
strict subscriber failure isolation.

Invariants:
- Synchronous and deterministic FIFO invocation ordering.
- Subscriber failure isolation: exceptions in one subscriber never abort
  dispatch to subsequent subscribers or bubble up to fail security scans.
- Catches standard Exception (never BaseException).
- Structured DispatchResult captures execution telemetry and error states.
- Zero network, database, or notification delivery dependencies.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Optional, List, Tuple, Any

from event_taxonomy import SecurityDomainEvent, EventType

logger = logging.getLogger("tcs.event_bus")


@dataclass(frozen=True)
class SubscriptionHandle:
    """Opaque handle representing an active subscription."""
    id: str
    event_type: Optional[EventType]
    name: str


@dataclass(frozen=True)
class DispatchResult:
    """Result telemetry for a single subscriber dispatch attempt."""
    handle_id: str
    subscriber_name: str
    event_type: EventType
    status: str  # "SUCCESS" or "FAILED"
    error: Optional[str] = None
    duration_ms: float = 0.0


class InMemoryEventBus:
    """
    Synchronous in-memory event dispatcher.
    Preserves strict insertion-ordered (FIFO) subscriber execution.
    """

    def __init__(self) -> None:
        self._subscribers: List[Tuple[SubscriptionHandle, Callable[[SecurityDomainEvent], None]]] = []

    def subscribe(
        self,
        handler: Callable[[SecurityDomainEvent], None],
        event_type: Optional[EventType] = None,
        name: Optional[str] = None
    ) -> SubscriptionHandle:
        """
        Registers a subscriber handler with optional event-type filtering.
        Subscribers are invoked in exact FIFO registration order.
        """
        if not callable(handler):
            raise TypeError("Subscriber handler must be a callable.")

        if event_type is not None and not isinstance(event_type, EventType):
            if isinstance(event_type, str):
                event_type = EventType(event_type)
            else:
                raise ValueError(f"Invalid event_type filter: {event_type}")

        subscriber_name = name or getattr(handler, "__name__", "anonymous_subscriber")
        handle = SubscriptionHandle(
            id=f"sub_{uuid.uuid4().hex[:12]}",
            event_type=event_type,
            name=subscriber_name
        )
        self._subscribers.append((handle, handler))
        return handle

    def unsubscribe(self, handle: SubscriptionHandle) -> bool:
        """
        Safely removes a subscriber by its handle.
        Returns True if removed, False if not found.
        """
        initial_len = len(self._subscribers)
        self._subscribers = [
            (h, fn) for (h, fn) in self._subscribers if h.id != handle.id
        ]
        return len(self._subscribers) < initial_len

    def publish(self, event: SecurityDomainEvent) -> List[DispatchResult]:
        """
        Dispatches an event synchronously to all matching subscribers in FIFO order.
        Isolates all subscriber errors and returns structured dispatch results.
        """
        if not isinstance(event, SecurityDomainEvent):
            raise TypeError(f"Expected SecurityDomainEvent instance, got {type(event).__name__}")

        dispatch_results: List[DispatchResult] = []

        for handle, handler in list(self._subscribers):
            # Check event-type filter
            if handle.event_type is not None and handle.event_type != event.event_type:
                continue

            t0 = time.perf_counter()
            try:
                handler(event)
                duration_ms = round((time.perf_counter() - t0) * 1000.0, 3)
                dispatch_results.append(
                    DispatchResult(
                        handle_id=handle.id,
                        subscriber_name=handle.name,
                        event_type=event.event_type,
                        status="SUCCESS",
                        duration_ms=duration_ms
                    )
                )
            except Exception as exc:
                duration_ms = round((time.perf_counter() - t0) * 1000.0, 3)
                error_summary = f"{type(exc).__name__}: {str(exc)}"
                logger.error(
                    "Subscriber '%s' failed processing event %s [%s]: %s",
                    handle.name, event.event_id, event.event_type.value, error_summary
                )
                dispatch_results.append(
                    DispatchResult(
                        handle_id=handle.id,
                        subscriber_name=handle.name,
                        event_type=event.event_type,
                        status="FAILED",
                        error=error_summary,
                        duration_ms=duration_ms
                    )
                )

        return dispatch_results

    def clear(self) -> None:
        """Removes all registered subscribers."""
        self._subscribers.clear()

    def subscriber_count(self, event_type: Optional[EventType] = None) -> int:
        """Returns the count of registered subscribers matching event_type filter."""
        if event_type is None:
            return len(self._subscribers)
        return sum(
            1 for (h, _) in self._subscribers
            if h.event_type is None or h.event_type == event_type
        )
