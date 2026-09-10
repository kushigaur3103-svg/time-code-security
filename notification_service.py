"""
TimeCodeSecurity (TCS) Notification Orchestration Service.

Orchestrates:
- Phase 15A EventPublisher & InMemoryEventBus
- Phase 15C NotificationPolicy, InAppNotificationAdapter & WebhookDeliveryAdapter
- Phase 15D DurableDeliveryResultSink & delivery audit logs

Invariants:
- notification_service.py is orchestration ONLY.
- Never defines a new event schema.
- Never duplicates EventPublisher logic.
- Never bypasses EventBus.
- Never modifies input ScanResult.
- Strictly adheres to the Data Safety Rule: NEVER puts webhook secrets, credentials,
  or user.webhook_url into SecurityDomainEvent metadata.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from event_bus import DispatchResult, InMemoryEventBus
from event_publisher import EventPublisher
from event_taxonomy import SecurityDomainEvent
from in_app_adapter import InAppNotificationAdapter
from notification_policy import NotificationIntent, NotificationPolicy, PolicyConfig
from sqlite_delivery_repository import SqliteDeliveryRepository
from sqlite_notification_repository import SqliteNotificationRepository
from webhook_adapter import (
    InMemoryDeliveryResultSink,
    WebhookDeliveryAdapter,
    WebhookDeliveryService,
    WebhookDestinationConfig,
)
from durable_delivery_sink import DurableDeliveryResultSink

logger = logging.getLogger("tcs.notification_service")


class NotificationService:
    """
    Central orchestration boundary for security notifications.
    Binds EventBus to NotificationPolicy and delivery adapters.
    """

    def __init__(
        self,
        bus: Optional[InMemoryEventBus] = None,
        event_publisher: Optional[EventPublisher] = None,
        in_app_adapter: Optional[InAppNotificationAdapter] = None,
        webhook_adapter: Optional[WebhookDeliveryAdapter] = None,
        webhook_service: Optional[WebhookDeliveryService] = None,
        durable_sink: Optional[DurableDeliveryResultSink] = None,
        session_factory: Optional[Callable[[], Any]] = None,
    ) -> None:
        self.bus = bus or InMemoryEventBus()
        self.event_publisher = event_publisher or EventPublisher(bus=self.bus)

        # 1. Setup durable delivery sink
        if durable_sink is not None:
            self.durable_sink = durable_sink
        else:
            self.durable_sink = DurableDeliveryResultSink(
                session_factory=session_factory,
                memory_sink=InMemoryDeliveryResultSink(),
            )

        # 2. Setup webhook service and adapter
        self.webhook_service = webhook_service or WebhookDeliveryService(
            max_workers=4,
            max_queue_size=100,
            result_sink=self.durable_sink,
        )
        self.webhook_adapter = webhook_adapter or WebhookDeliveryAdapter(service=self.webhook_service)

        # 3. Setup in-app adapter
        if in_app_adapter is not None:
            self.in_app_adapter = in_app_adapter
        else:
            repo = SqliteNotificationRepository(session_factory=session_factory)
            self.in_app_adapter = InAppNotificationAdapter(repository=repo)

        # 4. Destination registry by organization ID
        self._destinations: Dict[int, WebhookDestinationConfig] = {}
        self._policy_configs: Dict[int, PolicyConfig] = {}

        # 5. Subscribe orchestration handler to EventBus
        self.bus.subscribe(
            handler=self.handle_domain_event,
            event_type=None,
            name="NotificationServiceOrchestrator",
        )

    # Destination Registry Contract & Limitation:
    # "Phase 15D supports runtime/in-memory webhook destination registration.
    # Durable webhook destination configuration management is deferred to a
    # future phase."
    # The registry:
    # - remains organization-scoped (Dict[int, WebhookDestinationConfig])
    # - enforces destination.organization_id == intent.organization_id
    # - never receives webhook URL through SecurityDomainEvent metadata
    # - never exposes webhook secrets
    # - remains the only destination lookup mechanism used by webhook delivery

    def register_destination(self, destination: WebhookDestinationConfig) -> None:
        """
        Registers an organization-scoped webhook destination in the runtime in-memory registry.
        Phase 15D limitation: runtime/in-memory only. Durable config is deferred.
        """
        self._destinations[destination.organization_id] = destination

    def register_policy_config(self, config: PolicyConfig) -> None:
        """Registers a tenant notification policy configuration."""
        self._policy_configs[config.organization_id] = config

    def handle_domain_event(self, event: SecurityDomainEvent) -> None:
        """
        Synchronous EventBus subscriber callback.
        Evaluates policy and dispatches intents to adapters with error isolation.
        """
        org_id_raw = event.metadata.get("organization_id") if event.metadata else None
        if org_id_raw is None:
            logger.warning("Event %s discarded: missing mandatory organization_id in metadata", event.event_id)
            return
        try:
            org_id = int(org_id_raw)
        except (ValueError, TypeError):
            logger.error("Event %s discarded: invalid organization_id '%s'", event.event_id, org_id_raw)
            return

        policy_config = self._policy_configs.get(
            org_id,
            PolicyConfig(
                organization_id=org_id,
                min_severity_in_app="LOW",
                min_severity_webhook="HIGH",
            ),
        )

        try:
            intents = NotificationPolicy.evaluate(event, policy_config)
        except Exception as exc:
            logger.error("Notification policy evaluation failed for event %s: %s", event.event_id, exc)
            return

        for intent in intents:
            try:
                if intent.channel == "IN_APP":
                    self.in_app_adapter.handle_intent(intent)
                elif intent.channel == "WEBHOOK":
                    destination = self._destinations.get(intent.organization_id)
                    if destination:
                        if destination.organization_id != intent.organization_id:
                            logger.error(
                                "Tenant boundary violation: destination org %s != intent org %s",
                                destination.organization_id,
                                intent.organization_id,
                            )
                            continue
                        self.webhook_adapter.dispatch_intent(intent, destination)
            except Exception as exc:
                logger.error(
                    "Error dispatching intent %s on channel %s: %s",
                    intent.intent_id,
                    intent.channel,
                    exc,
                )

    def publish_scan_events(
        self,
        scan_result: Mapping[str, Any],
        repository: str,
        scan_id: str,
        metadata: Optional[Mapping[str, Any]] = None,
        policy_thresholds: Optional[Mapping[str, Any]] = None,
    ) -> List[Tuple[SecurityDomainEvent, List[DispatchResult]]]:
        """
        Delegates scan result event publication to the Phase 15A EventPublisher.
        Ensures strict data minimization: no raw webhook secrets in metadata.
        """
        clean_metadata = dict(metadata) if metadata else {}
        # Enforce Data Safety Rule: Strip any accidental webhook credentials/URLs from event metadata
        clean_metadata.pop("webhook_url", None)
        clean_metadata.pop("secret", None)
        clean_metadata.pop("api_key", None)

        return self.event_publisher.publish_scan_events(
            scan_result=scan_result,
            repository=repository,
            scan_id=scan_id,
            metadata=clean_metadata,
            policy_thresholds=policy_thresholds,
        )

    def shutdown(self, max_wait_seconds: float = 3.0) -> None:
        """Shuts down the webhook delivery service workers monotonically."""
        self.webhook_service.shutdown(max_wait_seconds=max_wait_seconds)
