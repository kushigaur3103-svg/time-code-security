"""
TimeCodeSecurity (TCS) Webhook Delivery Adapter & Queue Infrastructure.

Defines:
- WebhookDestinationConfig: Immutable tenant destination configuration.
- DeliveryResult: Immutable outcome telemetry with ownership attribution.
- InMemoryDeliveryResultSink: Thread-safe, bounded result sink (deque maxlen=1000).
- WebhookDeliveryService: Bounded work queue (maxsize=100), fixed worker pool (N=4),
  and idempotent shutdown sequence.
- WebhookDeliveryAdapter: Consumes NotificationIntents, validates multi-tenant
  destination invariants, and submits delivery tasks.
"""

from __future__ import annotations

import collections
import hashlib
import logging
import queue
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from notification_policy import NotificationIntent
from webhook_client import (
    MAX_ERROR_MESSAGE_LENGTH,
    DeliveryStatus,
    WebhookAuthConfig,
    WebhookClient,
)
from webhook_formatters import (
    MAX_WEBHOOK_PAYLOAD_BYTES,
    PayloadTooLargeError,
    format_webhook_payload,
)

logger = logging.getLogger("tcs.webhook_adapter")

DEFAULT_SHUTDOWN_TIMEOUT_SECONDS: float = 3.0


class TenantBoundaryViolationError(Exception):
    """Raised when destination organization does not match intent organization."""
    pass


class DeliveryAdmissionError(Exception):
    """Raised when a delivery task fails admission to the delivery queue."""
    pass


@dataclass(frozen=True)
class WebhookDestinationConfig:
    """
    Tenant-configured webhook endpoint configuration.
    Injected into adapter; workers do not dynamically choose arbitrary destinations.
    """
    destination_id: str
    organization_id: int
    url: str
    auth_config: WebhookAuthConfig = field(default_factory=WebhookAuthConfig)
    format: str = "GENERIC"  # "GENERIC" | "SLACK" | "DISCORD"

    def __post_init__(self) -> None:
        if not isinstance(self.organization_id, int) or self.organization_id <= 0:
            raise ValueError("organization_id must be a positive integer.")
        if not self.url or not isinstance(self.url, str):
            raise ValueError("url must be a non-empty string.")


@dataclass(frozen=True)
class DeliveryResult:
    """
    Immutable structured delivery outcome.
    target_ip is retained strictly for internal diagnostics and is NEVER
    exposed in user-facing notifications or external webhook payloads.
    """
    success: bool
    status: DeliveryStatus
    status_code: Optional[int]
    error_message: Optional[str]
    duration_ms: float
    attempts: int
    idempotency_key: str
    organization_id: int
    event_id: str
    scan_id: Optional[str]
    channel: str
    target_ip: Optional[str] = None

    def __post_init__(self) -> None:
        if self.error_message and len(self.error_message) > MAX_ERROR_MESSAGE_LENGTH:
            object.__setattr__(self, "error_message", self.error_message[:MAX_ERROR_MESSAGE_LENGTH])


@dataclass(frozen=True)
class WebhookDeliveryTask:
    """Task item enqueued into the bounded worker queue."""
    intent: NotificationIntent
    destination: WebhookDestinationConfig
    idempotency_key: str
    payload_bytes: bytes


def canonicalize_endpoint(url: str) -> str:
    """
    Normalizes ONLY scheme, hostname, and default port.
    Preserves EXACT path representation (including trailing slashes and repeated slashes)
    and exact query string ordering.
    """
    parsed = urllib.parse.urlsplit(url.strip())
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    if hostname.endswith("."):
        hostname = hostname[:-1]

    port = parsed.port
    port_str = f":{port}" if port is not None and port != 443 else ""
    path = parsed.path
    query_str = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{hostname}{port_str}{path}{query_str}"


def compute_idempotency_key(organization_id: int, canonical_endpoint: str, dedupe_key: str) -> str:
    """
    Computes deterministic SHA-256 idempotency key:
    SHA256(str(organization_id) + ":" + canonical_endpoint + ":" + dedupe_key)
    """
    raw = f"{organization_id}:{canonical_endpoint}:{dedupe_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class InMemoryDeliveryResultSink:
    """
    Thread-safe, bounded in-memory delivery result sink.
    Retains up to 1000 recent results in a circular deque.
    Structured logging strictly avoids secrets, payload bodies, and auth headers.
    """

    def __init__(self, maxlen: int = 1000) -> None:
        self._results: collections.deque[DeliveryResult] = collections.deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def record(self, result: DeliveryResult) -> None:
        with self._lock:
            self._results.append(result)

        # Structured logging without secrets or payloads
        logger.info(
            "Webhook delivery completed: status=%s success=%s attempts=%d duration_ms=%.1f org_id=%d event_id=%s idempotency_key=%s",
            result.status.value,
            result.success,
            result.attempts,
            result.duration_ms,
            result.organization_id,
            result.event_id,
            result.idempotency_key,
        )

    def get_recent(self) -> List[DeliveryResult]:
        with self._lock:
            return list(self._results)

    def clear(self) -> None:
        with self._lock:
            self._results.clear()


class WebhookDeliveryService:
    """
    Bounded queue delivery service with fixed worker threads.
    Enforces non-blocking enqueue (put_nowait), admission rejection telemetry,
    and idempotent atomic shutdown.
    """

    def __init__(
        self,
        max_workers: int = 4,
        max_queue_size: int = 100,
        result_sink: Optional[InMemoryDeliveryResultSink] = None,
        webhook_client: Optional[WebhookClient] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._queue: queue.Queue[Optional[WebhookDeliveryTask]] = queue.Queue(maxsize=max_queue_size)
        self._max_queue_size = max_queue_size
        self._sink = result_sink or InMemoryDeliveryResultSink()
        self._client = webhook_client or WebhookClient(clock=clock)
        self._clock = clock
        self._shutdown_event = threading.Event()
        self._shutdown_initiated = False
        self._accepting_submissions = True
        self._lock = threading.Lock()
        self._workers: List[threading.Thread] = []

        for i in range(max_workers):
            t = threading.Thread(
                target=self._worker_loop,
                name=f"tcs-webhook-worker-{i}",
                daemon=True,
            )
            t.start()
            self._workers.append(t)

    @property
    def sink(self) -> InMemoryDeliveryResultSink:
        return self._sink

    def enqueue(self, task: WebhookDeliveryTask) -> bool:
        """
        Non-blocking task admission.
        Uses put_nowait(). Never blocks caller thread.
        Returns True on successful queue admission.
        Returns False on QUEUE_OVERFLOW or SHUTDOWN_ABORTED after recording failure in sink.
        """
        with self._lock:
            if not self._accepting_submissions or self._shutdown_event.is_set():
                self._sink.record(
                    DeliveryResult(
                        success=False,
                        status=DeliveryStatus.SHUTDOWN_ABORTED,
                        status_code=None,
                        error_message="Submission rejected: delivery service is shutting down",
                        duration_ms=0.0,
                        attempts=0,
                        idempotency_key=task.idempotency_key,
                        organization_id=task.intent.organization_id,
                        event_id=task.intent.event_id,
                        scan_id=task.intent.scan_id,
                        channel="WEBHOOK",
                        target_ip=None,
                    )
                )
                return False

            try:
                self._queue.put_nowait(task)
                return True
            except queue.Full:
                self._sink.record(
                    DeliveryResult(
                        success=False,
                        status=DeliveryStatus.QUEUE_OVERFLOW,
                        status_code=None,
                        error_message=f"Webhook delivery queue full (capacity {self._max_queue_size})",
                        duration_ms=0.0,
                        attempts=0,
                        idempotency_key=task.idempotency_key,
                        organization_id=task.intent.organization_id,
                        event_id=task.intent.event_id,
                        scan_id=task.intent.scan_id,
                        channel="WEBHOOK",
                        target_ip=None,
                    )
                )
                return False

    def shutdown(self, max_wait_seconds: float = DEFAULT_SHUTDOWN_TIMEOUT_SECONDS) -> None:
        """
        Idempotent shutdown sequence:
        1. Stop accepting submissions under lock.
        2. Drain all pending tasks from queue and mark SHUTDOWN_ABORTED exactly once.
        3. Signal workers and post sentinels.
        4. Allow in-flight work to complete within monotonic deadline.
        5. Join workers.
        """
        already_initiated = False
        with self._lock:
            if self._shutdown_initiated:
                already_initiated = True
            else:
                self._shutdown_initiated = True
                self._accepting_submissions = False

        if already_initiated:
            # Idempotent: wait for workers without duplicating aborts
            deadline = self._clock() + max_wait_seconds
            for worker in self._workers:
                rem = max(0.0, deadline - self._clock())
                worker.join(timeout=rem)
            return

        # Drain unstarted queue items
        while True:
            try:
                item = self._queue.get_nowait()
                if item is not None:
                    self._sink.record(
                        DeliveryResult(
                            success=False,
                            status=DeliveryStatus.SHUTDOWN_ABORTED,
                            status_code=None,
                            error_message="Aborted due to service shutdown before execution",
                            duration_ms=0.0,
                            attempts=0,
                            idempotency_key=item.idempotency_key,
                            organization_id=item.intent.organization_id,
                            event_id=item.intent.event_id,
                            scan_id=item.intent.scan_id,
                            channel="WEBHOOK",
                            target_ip=None,
                        )
                    )
                self._queue.task_done()
            except queue.Empty:
                break

        # Signal workers
        self._shutdown_event.set()
        for _ in self._workers:
            try:
                self._queue.put_nowait(None)  # Sentinel
            except queue.Full:
                pass

        # Join workers monotonically
        deadline = self._clock() + max_wait_seconds
        for worker in self._workers:
            rem = max(0.0, deadline - self._clock())
            worker.join(timeout=rem)

    def _worker_loop(self) -> None:
        """Background worker thread consumption loop."""
        while True:
            try:
                task = self._queue.get(timeout=0.2)
            except queue.Empty:
                if self._shutdown_event.is_set():
                    break
                continue

            if task is None:  # Sentinel
                self._queue.task_done()
                break

            try:
                self._execute_delivery(task)
            except Exception as exc:
                logger.error("Unhandled exception in webhook delivery worker: %s", exc)
                self._sink.record(
                    DeliveryResult(
                        success=False,
                        status=DeliveryStatus.INTERNAL_ERROR,
                        status_code=None,
                        error_message=f"Internal worker exception: {exc}"[:MAX_ERROR_MESSAGE_LENGTH],
                        duration_ms=0.0,
                        attempts=0,
                        idempotency_key=task.idempotency_key,
                        organization_id=task.intent.organization_id,
                        event_id=task.intent.event_id,
                        scan_id=task.intent.scan_id,
                        channel="WEBHOOK",
                        target_ip=None,
                    )
                )
            finally:
                self._queue.task_done()

    def _execute_delivery(self, task: WebhookDeliveryTask) -> None:
        """Executes delivery for a single task."""
        client_res = self._client.send(
            url=task.destination.url,
            payload_bytes=task.payload_bytes,
            auth_config=task.destination.auth_config,
            idempotency_key=task.idempotency_key,
        )

        res = DeliveryResult(
            success=client_res.success,
            status=client_res.status,
            status_code=client_res.status_code,
            error_message=client_res.error_message,
            duration_ms=client_res.duration_ms,
            attempts=client_res.attempts,
            idempotency_key=task.idempotency_key,
            organization_id=task.intent.organization_id,
            event_id=task.intent.event_id,
            scan_id=task.intent.scan_id,
            channel="WEBHOOK",
            target_ip=client_res.target_ip,
        )
        self._sink.record(res)


class WebhookDeliveryAdapter:
    """
    Webhook Delivery Adapter.
    Consumes NotificationIntents, validates multi-tenant destination boundaries,
    formats payloads (with byte-size limit check), and submits tasks to the service.
    """

    def __init__(self, service: WebhookDeliveryService) -> None:
        if not isinstance(service, WebhookDeliveryService):
            raise TypeError(f"Expected WebhookDeliveryService, got {type(service).__name__}")
        self._service = service

    def deliver(
        self,
        intent: NotificationIntent,
        destination: WebhookDestinationConfig
    ) -> str:
        """
        Dispatches a NotificationIntent to a WebhookDestinationConfig.
        Enforces tenant boundary, pre-network payload byte limit, and queue admission.
        Returns the computed idempotency_key on success.
        Raises:
        - TenantBoundaryViolationError: If destination.organization_id != intent.organization_id.
        - PayloadTooLargeError: If serialized payload exceeds 65536 bytes.
        - DeliveryAdmissionError: If queue is full or service is shutting down.
        """
        if not isinstance(intent, NotificationIntent):
            raise TypeError(f"Expected NotificationIntent, got {type(intent).__name__}")
        if not isinstance(destination, WebhookDestinationConfig):
            raise TypeError(f"Expected WebhookDestinationConfig, got {type(destination).__name__}")

        # 1. Hard Multi-Tenant Destination Invariant Check
        if destination.organization_id != intent.organization_id:
            msg = (
                f"Cross-tenant delivery rejected: destination org {destination.organization_id} "
                f"!= intent org {intent.organization_id}"
            )
            # Record security failure in sink
            self._service.sink.record(
                DeliveryResult(
                    success=False,
                    status=DeliveryStatus.SSRF_BLOCKED,
                    status_code=None,
                    error_message=msg[:MAX_ERROR_MESSAGE_LENGTH],
                    duration_ms=0.0,
                    attempts=0,
                    idempotency_key="",
                    organization_id=intent.organization_id,
                    event_id=intent.event_id,
                    scan_id=intent.scan_id,
                    channel="WEBHOOK",
                    target_ip=None,
                )
            )
            raise TenantBoundaryViolationError(msg)

        # 2. Canonicalize Endpoint and Compute Idempotency Key
        canonical_url = canonicalize_endpoint(destination.url)
        idempotency_key = compute_idempotency_key(
            intent.organization_id,
            canonical_url,
            intent.dedupe_key
        )

        # 3. Payload Serialization & Pre-Network Byte-Size Limit Check
        try:
            payload_bytes = format_webhook_payload(intent, destination.format)
        except PayloadTooLargeError as exc:
            self._service.sink.record(
                DeliveryResult(
                    success=False,
                    status=DeliveryStatus.PAYLOAD_TOO_LARGE,
                    status_code=None,
                    error_message=str(exc)[:MAX_ERROR_MESSAGE_LENGTH],
                    duration_ms=0.0,
                    attempts=0,
                    idempotency_key=idempotency_key,
                    organization_id=intent.organization_id,
                    event_id=intent.event_id,
                    scan_id=intent.scan_id,
                    channel="WEBHOOK",
                    target_ip=None,
                )
            )
            raise

        # 4. Construct Task
        task = WebhookDeliveryTask(
            intent=intent,
            destination=destination,
            idempotency_key=idempotency_key,
            payload_bytes=payload_bytes,
        )

        # 5. Non-Blocking Admission to Queue
        admitted = self._service.enqueue(task)
        if not admitted:
            raise DeliveryAdmissionError(
                f"Webhook task admission failed for intent {intent.intent_id} (queue full or shutting down)"
            )

        return idempotency_key
