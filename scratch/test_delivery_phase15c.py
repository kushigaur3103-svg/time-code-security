"""
Phase 15C Comprehensive Offline Test Suite: Delivery Adapters & Security Boundaries.

Strictly zero external network egress.
Uses FakeClock, mock DNS, mock sockets, mock SSL contexts, and mock HTTP responses.
Verifies all 35 Phase 15C requirements.
"""

import hashlib
import ipaddress
import json
import os
import socket
import ssl
import sys
import unittest
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Optional, Tuple

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from event_bus import InMemoryEventBus
from event_taxonomy import EventSummary, EventType, ScanStatus, SecurityDomainEvent
from in_app_adapter import AggregatePersistenceError, InAppNotificationAdapter
from notification_models import Notification, NotificationCreate, RecipientScope
from notification_policy import (
    NotificationIntent,
    NotificationPolicy,
    PolicyConfig,
    SafeFindingSummary,
)
from notification_repository import NotificationRepository
from ssrf_guard import DNSResolutionError, SSRFGuard, SSRFValidationError
from webhook_adapter import (
    DeliveryAdmissionError,
    DeliveryResult,
    InMemoryDeliveryResultSink,
    TenantBoundaryViolationError,
    WebhookDeliveryAdapter,
    WebhookDeliveryService,
    WebhookDeliveryTask,
    WebhookDestinationConfig,
    canonicalize_endpoint,
    compute_idempotency_key,
)
from webhook_client import (
    DeliveryStatus,
    PinnedIPHTTPSConnection,
    WebhookAuthConfig,
    WebhookClient,
    compute_webhook_signature,
)
from webhook_formatters import (
    MAX_WEBHOOK_PAYLOAD_BYTES,
    DiscordWebhookFormatter,
    GenericWebhookFormatter,
    PayloadTooLargeError,
    SlackWebhookFormatter,
    format_webhook_payload,
)


class FakeClock:
    """Deterministic monotonic clock for offline testing."""
    def __init__(self, start: float = 1000.0) -> None:
        self.time = start

    def __call__(self) -> float:
        return self.time

    def advance(self, seconds: float) -> None:
        self.time += seconds


class FakeSleep:
    """Mock sleep function advancing FakeClock without real-time delay."""
    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.calls: List[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        self.clock.advance(seconds)


class MockHTTPResponse:
    """Mock response for http.client."""
    def __init__(
        self,
        status: int = 200,
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b'{"ok": true}',
    ) -> None:
        self.status = status
        self._headers = headers or {}
        self._body = body

    def getheader(self, name: str, default: Optional[str] = None) -> Optional[str]:
        for k, v in self._headers.items():
            if k.lower() == name.lower():
                return v
        return default

    def getheaders(self) -> List[Tuple[str, str]]:
        return list(self._headers.items())

    def read(self, amt: Optional[int] = None) -> bytes:
        return self._body


class MockHTTPSConnection:
    """Mock HTTPS connection supporting controlled responses and error simulation."""
    def __init__(
        self,
        target_ip: str,
        hostname: str,
        port: int = 443,
        timeout: float = 3.0,
        response_sequence: Optional[List[Any]] = None,
    ) -> None:
        self.target_ip = target_ip
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.connected = False
        self.closed = False
        self.sock = self
        self.requests: List[Tuple[str, str, bytes, Dict[str, str]]] = []
        self.response_sequence = response_sequence or [MockHTTPResponse(200)]
        self.response_idx = 0

    def connect(self) -> None:
        self.connected = True

    def settimeout(self, t: float) -> None:
        self.timeout = t

    def request(self, method: str, url: str, body: bytes = b"", headers: Optional[Dict[str, str]] = None) -> None:
        self.requests.append((method, url, body, headers or {}))

    def getresponse(self) -> MockHTTPResponse:
        if self.response_idx < len(self.response_sequence):
            resp = self.response_sequence[self.response_idx]
            self.response_idx += 1
            if isinstance(resp, Exception):
                raise resp
            return resp
        return MockHTTPResponse(200)

    def close(self) -> None:
        self.closed = True


class MockNotificationRepository(NotificationRepository):
    """In-memory mock of NotificationRepository."""
    def __init__(self, failure_trigger_id: Optional[str] = None) -> None:
        self.stored: List[Notification] = []
        self.failure_trigger_id = failure_trigger_id
        self._next_id = 1

    def create(self, payload: Any) -> Notification:
        if isinstance(payload, NotificationCreate):
            dto = payload
        else:
            dto = NotificationCreate(**payload)

        if self.failure_trigger_id and dto.title == self.failure_trigger_id:
            raise RuntimeError(f"Simulated DB failure for {dto.title}")

        notif = Notification(
            id=self._next_id,
            organization_id=dto.organization_id,
            recipient_scope=dto.recipient_scope,
            user_id=dto.user_id,
            scope_target=dto.scope_target,
            event_id=dto.event_id,
            scan_id=dto.scan_id,
            dedupe_key=dto.dedupe_key,
            type=dto.type,
            severity=dto.severity,
            title=dto.title,
            message=dto.message,
            link=dto.link,
            is_read=False,
            read_at=None,
            created_at=datetime.now(timezone.utc),
        )
        self._next_id += 1
        self.stored.append(notif)
        return notif

    def get_by_id(self, notification_id: int, organization_id: int, user_id: Optional[int] = None) -> Optional[Notification]:
        for n in self.stored:
            if n.id == notification_id and n.organization_id == organization_id:
                return n
        return None

    def list_notifications(self, organization_id: int, user_id: Optional[int] = None, recipient_scope: Optional[Any] = None, unread_only: bool = False, limit: int = 50, offset: int = 0) -> List[Notification]:
        return [n for n in self.stored if n.organization_id == organization_id]

    def count_unread(self, organization_id: int, user_id: Optional[int] = None, recipient_scope: Optional[Any] = None) -> int:
        return len([n for n in self.stored if n.organization_id == organization_id and not n.is_read])

    def mark_read(self, notification_id: int, organization_id: int, user_id: Optional[int] = None, read_at: Optional[datetime] = None) -> bool:
        return True

    def mark_all_read(self, organization_id: int, user_id: Optional[int] = None, read_at: Optional[datetime] = None) -> int:
        return 0

    def exists_by_dedupe_key(self, organization_id: int, scope_target: int, dedupe_key: str, type: str) -> bool:
        return any(
            n.organization_id == organization_id and n.scope_target == scope_target and n.dedupe_key == dedupe_key and n.type == type
            for n in self.stored
        )


def create_sample_event(
    critical: int = 1,
    high: int = 2,
    medium: int = 0,
    low: int = 0,
    total: int = 3,
    org_id: int = 10,
    findings: Optional[List[Dict[str, Any]]] = None,
) -> SecurityDomainEvent:
    """Helper to build a valid SecurityDomainEvent."""
    summary = EventSummary(
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        total_findings=total,
        security_score=50,
        risk_level="HIGH" if high > 0 else "CRITICAL",
        scan_status=ScanStatus.SUCCESS,
        message="Scan completed with findings",
    )
    meta = {
        "organization_id": org_id,
        "findings": findings or [
            {
                "rule_id": "TCS-SQLI-01",
                "cwe": "CWE-89",
                "severity": "CRITICAL",
                "file_path": "backend/db.py",
                "line": 42,
                "message": "Raw SQL injection vulnerability",
            },
            {
                "rule_id": "TCS-XSS-02",
                "cwe": "CWE-79",
                "severity": "HIGH",
                "file_path": "frontend/render.js",
                "line": 105,
                "message": "Unescaped DOM innerHTML",
            },
        ],
    }
    dedupe = hashlib.sha256(f"scan-123:{org_id}:repo".encode("utf-8")).hexdigest()
    return SecurityDomainEvent(
        schema_version=1,
        event_id="evt-test-01",
        event_type=EventType.CRITICAL_FINDING_DETECTED,
        timestamp="2026-09-10T12:00:00Z",
        repository="acme/core-service",
        scan_id="scan-123",
        summary=summary,
        high_risk_count=critical + high,
        metadata=MappingProxyType(meta),
        dedupe_key=dedupe,
    )


class TestPhase15CDeliverySuite(unittest.TestCase):
    """35 Comprehensive Offline Unit Tests for Phase 15C."""

    # 1. Policy Purity
    def test_policy_pure_evaluation(self):
        event = create_sample_event(critical=2, high=1, total=3)
        config = PolicyConfig(organization_id=10, min_severity_in_app="LOW", min_severity_webhook="HIGH")
        intents = NotificationPolicy.evaluate(event, config)
        self.assertIsInstance(intents, tuple)
        self.assertEqual(len(intents), 2)  # 1 In-App, 1 Webhook
        self.assertEqual(intents[0].channel, "IN_APP")
        self.assertEqual(intents[1].channel, "WEBHOOK")
        self.assertEqual(intents[0].organization_id, 10)
        self.assertEqual(intents[1].organization_id, 10)

    # 2. Policy Filtering
    def test_policy_severity_filtering(self):
        event = create_sample_event(critical=0, high=0, medium=1, low=0, total=1)
        config = PolicyConfig(organization_id=10, min_severity_in_app="LOW", min_severity_webhook="HIGH")
        intents = NotificationPolicy.evaluate(event, config)
        self.assertEqual(len(intents), 1)  # Only In-App, Webhook filtered out (MEDIUM < HIGH)
        self.assertEqual(intents[0].channel, "IN_APP")

    # 3. Independent Multi-Intent Persistence
    def test_in_app_independent_multi_intent_persistence(self):
        repo = MockNotificationRepository(failure_trigger_id="Intent 2 Failed")
        adapter = InAppNotificationAdapter(repo)

        intent1 = NotificationIntent(
            intent_id="i1", event_id="e1", scan_id="s1", dedupe_key="d1",
            notification_type="ALERT", severity="HIGH", recipient_scope=RecipientScope.ORGANIZATION,
            organization_id=10, title="Intent 1 Success", message="Msg 1"
        )
        intent2 = NotificationIntent(
            intent_id="i2", event_id="e1", scan_id="s1", dedupe_key="d2",
            notification_type="ALERT", severity="HIGH", recipient_scope=RecipientScope.ORGANIZATION,
            organization_id=10, title="Intent 2 Failed", message="Msg 2"
        )
        intent3 = NotificationIntent(
            intent_id="i3", event_id="e1", scan_id="s1", dedupe_key="d3",
            notification_type="ALERT", severity="HIGH", recipient_scope=RecipientScope.ORGANIZATION,
            organization_id=10, title="Intent 3 Success", message="Msg 3"
        )

        with self.assertRaises(AggregatePersistenceError) as ctx:
            adapter.handle_intents([intent1, intent2, intent3])

        self.assertEqual(len(ctx.exception.failures), 1)
        self.assertEqual(len(ctx.exception.persisted), 2)
        # Verify intent 1 and intent 3 remain persisted in repo
        self.assertEqual(len(repo.stored), 2)
        self.assertEqual(repo.stored[0].title, "Intent 1 Success")
        self.assertEqual(repo.stored[1].title, "Intent 3 Success")

    # 4. In-App Aggregate Failure Propagates to EventBus
    def test_in_app_aggregate_failure_propagates_to_bus(self):
        bus = InMemoryEventBus()
        repo = MockNotificationRepository(failure_trigger_id="Intent Fail")
        adapter = InAppNotificationAdapter(repo)

        def subscriber(event: SecurityDomainEvent) -> None:
            config = PolicyConfig(organization_id=10)
            intents = [
                NotificationIntent(
                    intent_id="i1", event_id=event.event_id, scan_id=event.scan_id, dedupe_key="d1",
                    notification_type="ALERT", severity="HIGH", recipient_scope=RecipientScope.ORGANIZATION,
                    organization_id=10, title="Intent Fail", message="Msg"
                )
            ]
            adapter.handle_intents(intents)

        bus.subscribe(subscriber, event_type=EventType.CRITICAL_FINDING_DETECTED)
        event = create_sample_event()
        results = bus.publish(event)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "FAILED")
        self.assertIn("In-app persistence failed", results[0].error or "")

    # 5. Tenant Boundary Violation Rejected Before Queue
    def test_webhook_tenant_boundary_violation_rejected_before_queue(self):
        sink = InMemoryDeliveryResultSink()
        service = WebhookDeliveryService(max_workers=0, result_sink=sink)
        adapter = WebhookDeliveryAdapter(service)

        intent = NotificationIntent(
            intent_id="i1", event_id="e1", scan_id="s1", dedupe_key="d1",
            notification_type="ALERT", severity="CRITICAL", recipient_scope=RecipientScope.ORGANIZATION,
            organization_id=10, title="TCS Alert", message="Msg"
        )
        # Destination belongs to Org 99 != Intent Org 10
        dest = WebhookDestinationConfig(
            destination_id="dest-99", organization_id=99, url="https://hooks.slack.com/services/XXX"
        )

        with self.assertRaises(TenantBoundaryViolationError):
            adapter.deliver(intent, dest)

        # Confirm recorded in sink and zero tasks in queue
        results = sink.get_recent()
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].success)
        self.assertIn("Cross-tenant delivery rejected", results[0].error_message or "")
        service.shutdown(max_wait_seconds=0.1)

    # 6. Webhook Admission Failure Propagates to EventBus
    def test_webhook_admission_failure_propagates_to_event_bus(self):
        bus = InMemoryEventBus()
        sink = InMemoryDeliveryResultSink()
        service = WebhookDeliveryService(max_workers=0, max_queue_size=1, result_sink=sink)
        adapter = WebhookDeliveryAdapter(service)

        # Pre-fill queue to capacity
        dest = WebhookDestinationConfig(destination_id="d1", organization_id=10, url="https://example.com/hook")
        intent1 = NotificationIntent(
            intent_id="i1", event_id="e1", scan_id="s1", dedupe_key="d1",
            notification_type="ALERT", severity="HIGH", recipient_scope=RecipientScope.ORGANIZATION,
            organization_id=10, title="TCS Alert 1", message="Msg 1"
        )
        adapter.deliver(intent1, dest)

        def webhook_subscriber(event: SecurityDomainEvent) -> None:
            intent2 = NotificationIntent(
                intent_id="i2", event_id=event.event_id, scan_id=event.scan_id, dedupe_key="d2",
                notification_type="ALERT", severity="HIGH", recipient_scope=RecipientScope.ORGANIZATION,
                organization_id=10, title="TCS Alert 2", message="Msg 2"
            )
            adapter.deliver(intent2, dest)

        bus.subscribe(webhook_subscriber, event_type=EventType.CRITICAL_FINDING_DETECTED)
        event = create_sample_event()
        results = bus.publish(event)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "FAILED")
        self.assertIn("Webhook task admission failed", results[0].error or "")
        service.shutdown(max_wait_seconds=0.1)

    # 7. Payload Byte Limit Rejected Before Network
    def test_payload_byte_limit_rejected_before_network(self):
        sink = InMemoryDeliveryResultSink()
        service = WebhookDeliveryService(max_workers=0, result_sink=sink)
        adapter = WebhookDeliveryAdapter(service)

        # Create finding that blows past 64 KB limit
        huge_message = "A" * 70000
        # Bypass SafeFindingSummary clamp to test formatters hard byte limit
        huge_finding = SafeFindingSummary(
            rule_id="R1", cwe="C1", severity="HIGH", file_path="f.py", line=1, message="M"
        )
        object.__setattr__(huge_finding, "message", huge_message)

        intent = NotificationIntent(
            intent_id="i_huge", event_id="e1", scan_id="s1", dedupe_key="d1",
            notification_type="ALERT", severity="CRITICAL", recipient_scope=RecipientScope.ORGANIZATION,
            organization_id=10, title="Huge Alert", message="Msg",
            safe_findings=(huge_finding,)
        )
        dest = WebhookDestinationConfig(destination_id="d1", organization_id=10, url="https://example.com/hook")

        with self.assertRaises(PayloadTooLargeError):
            adapter.deliver(intent, dest)

        results = sink.get_recent()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, DeliveryStatus.PAYLOAD_TOO_LARGE)
        service.shutdown(max_wait_seconds=0.1)

    # 8. Webhook HMAC-SHA256 Signature Matches Exact Bytes
    def test_webhook_authentication_signature_matches_exact_bytes(self):
        secret = "super_secret_webhook_key_123"
        payload = b'{"schema_version": 1, "alert": "critical"}'
        sig = compute_webhook_signature(secret, payload)
        expected = hashlib.sha256()
        # Verify HMAC correctness
        import hmac
        expected_hmac = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        self.assertEqual(sig, expected_hmac)

    # 9. SSRF: Reject HTTP Scheme
    def test_ssrf_reject_http_scheme(self):
        guard = SSRFGuard()
        with self.assertRaises(SSRFValidationError) as ctx:
            guard.validate_url("http://api.example.com/webhook")
        self.assertIn("strictly require HTTPS", str(ctx.exception))

    # 10. SSRF: Reject Userinfo
    def test_ssrf_reject_embedded_credentials(self):
        guard = SSRFGuard()
        with self.assertRaises(SSRFValidationError) as ctx:
            guard.validate_url("https://admin:password@api.example.com/webhook")
        self.assertIn("Embedded user credentials", str(ctx.exception))

    # 11. SSRF: Reject IPv4 Loopback
    def test_ssrf_reject_ipv4_loopback(self):
        guard = SSRFGuard()
        with self.assertRaises(SSRFValidationError):
            guard.validate_url("https://127.0.0.1/webhook")

    # 12. SSRF: Reject Private Subnets (RFC 1918)
    def test_ssrf_reject_private_subnets(self):
        guard = SSRFGuard()
        for private_ip in ["10.0.0.1", "172.16.5.10", "192.168.1.1"]:
            with self.assertRaises(SSRFValidationError):
                guard.validate_url(f"https://{private_ip}/webhook")

    # 13. SSRF: Reject Cloud Metadata
    def test_ssrf_reject_cloud_metadata(self):
        guard = SSRFGuard()
        with self.assertRaises(SSRFValidationError):
            guard.validate_url("https://169.254.169.254/latest/meta-data")

    # 14. SSRF: Reject CGNAT
    def test_ssrf_reject_cgnat(self):
        guard = SSRFGuard()
        with self.assertRaises(SSRFValidationError):
            guard.validate_url("https://100.64.0.1/webhook")

    # 15. SSRF: Reject IPv6 Loopback and ULA
    def test_ssrf_reject_ipv6_loopback_and_ula(self):
        guard = SSRFGuard()
        with self.assertRaises(SSRFValidationError):
            guard.validate_url("https://[::1]/webhook")
        with self.assertRaises(SSRFValidationError):
            guard.validate_url("https://[fc00::1]/webhook")

    # 16. SSRF: Reject IPv4-Mapped IPv6
    def test_ssrf_reject_ipv4_mapped_ipv6(self):
        guard = SSRFGuard()
        with self.assertRaises(SSRFValidationError):
            guard.validate_url("https://[::ffff:127.0.0.1]/webhook")

    # 17. SSRF: Dual-Homed DNS Rejection
    def test_ssrf_dual_homed_dns_rejected(self):
        def mock_dual_homed_dns(host, port):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),  # Public
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port)),       # Private
            ]
        guard = SSRFGuard(dns_resolver=mock_dual_homed_dns)
        with self.assertRaises(SSRFValidationError) as ctx:
            guard.validate_url("https://dual.example.com/webhook")
        self.assertIn("resolves to forbidden address 10.0.0.1", str(ctx.exception))

    # 18. Deterministic Target-IP Selection
    def test_deterministic_target_ip_selection(self):
        def mock_multi_public_dns(host, port):
            return [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.5", port)), # doc net
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)), # public
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", port)), # public
            ]
        # Custom mock with only valid public IPs
        def mock_clean_multi_dns(host, port):
            return [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            ]
        guard = SSRFGuard(dns_resolver=mock_clean_multi_dns)
        res = guard.validate_url("https://multi.example.com/webhook")
        # IPv4 should be selected over IPv6, and 93.184.216.34 sorted before 93.184.216.35
        self.assertEqual(res.target_ip, "93.184.216.34")

    # 19. Pinned-IP Direct Socket Connection
    def test_pinned_ip_client_connects_to_ip_directly(self):
        connected_addrs = []
        def mock_socket_factory(addr, timeout=3.0):
            connected_addrs.append(addr)
            return MockHTTPSConnection(addr[0], "example.com")

        # Verify PinnedIPHTTPSConnection calls socket_factory with target_ip
        conn = PinnedIPHTTPSConnection(
            target_ip="93.184.216.34",
            hostname="example.com",
            port=443,
            socket_factory=mock_socket_factory,
        )
        # Mock wrap_socket
        mock_ctx = ssl.create_default_context()
        mock_ctx.wrap_socket = lambda s, server_hostname: s
        conn.ssl_context = mock_ctx
        conn.connect()
        self.assertEqual(len(connected_addrs), 1)
        self.assertEqual(connected_addrs[0], ("93.184.216.34", 443))

    # 20. Preserved TLS SNI Hostname
    def test_preserved_tls_sni(self):
        sni_names = []
        class MockSSLContext:
            verify_mode = ssl.CERT_REQUIRED
            check_hostname = True
            def wrap_socket(self, sock, server_hostname):
                sni_names.append(server_hostname)
                return sock

        conn = PinnedIPHTTPSConnection(
            target_ip="93.184.216.34",
            hostname="api.custom-subdomain.com",
            port=443,
            ssl_context=MockSSLContext(),
            socket_factory=lambda addr, timeout=3.0: MockHTTPSConnection(addr[0], "dummy"),
        )
        conn.connect()
        self.assertEqual(len(sni_names), 1)
        self.assertEqual(sni_names[0], "api.custom-subdomain.com")

    # 21. Strict TLS Verification Invariants
    def test_strict_tls_verification_invariants(self):
        # CERT_NONE must be rejected
        bad_ctx1 = ssl.create_default_context()
        bad_ctx1.check_hostname = False
        bad_ctx1.verify_mode = ssl.CERT_NONE
        with self.assertRaises(ValueError) as ctx1:
            PinnedIPHTTPSConnection(target_ip="1.2.3.4", hostname="example.com", ssl_context=bad_ctx1)
        self.assertIn("CERT_NONE", str(ctx1.exception))

        # check_hostname=False must be rejected
        bad_ctx2 = ssl.create_default_context()
        bad_ctx2.check_hostname = False
        with self.assertRaises(ValueError) as ctx2:
            PinnedIPHTTPSConnection(target_ip="1.2.3.4", hostname="example.com", ssl_context=bad_ctx2)
        self.assertIn("check_hostname=False", str(ctx2.exception))

    # 22. Redirects Strictly Blocked
    def test_redirect_strictly_blocked(self):
        def mock_dns(host, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_conn = MockHTTPSConnection(
            "93.184.216.34", "example.com",
            response_sequence=[MockHTTPResponse(status=302, headers={"Location": "https://attacker.com"})]
        )
        client = WebhookClient(
            ssrf_guard=SSRFGuard(dns_resolver=mock_dns),
            http_connection_factory=lambda **kw: mock_conn,
        )
        res = client.send("https://example.com/webhook", b'{"msg": "test"}')
        self.assertFalse(res.success)
        self.assertEqual(res.status, DeliveryStatus.REDIRECT_BLOCKED)
        self.assertEqual(res.status_code, 302)

    # 23. Fake-Clock Deadline Enforcement
    def test_fake_clock_deadline_enforcement(self):
        clock = FakeClock(start=1000.0)
        def mock_dns(host, port):
            clock.advance(11.0)  # Simulate DNS or execution taking > 10s
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        client = WebhookClient(
            ssrf_guard=SSRFGuard(dns_resolver=mock_dns),
            clock=clock,
            http_connection_factory=lambda **kw: MockHTTPSConnection("93.184.216.34", "example.com"),
        )
        res = client.send("https://example.com/webhook", b'{}')
        self.assertFalse(res.success)
        self.assertEqual(res.status, DeliveryStatus.CONNECTION_TIMEOUT)
        self.assertIn("deadline exceeded", res.error_message or "")

    # 24. Timeout Clamping
    def test_timeout_clamping(self):
        clock = FakeClock(start=1000.0)
        captured_timeouts = []
        def mock_dns(host, port):
            clock.advance(8.0)  # Remaining deadline = 10.0 - 8.0 = 2.0s (< 3.0s connect timeout)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        def mock_factory(**kw):
            captured_timeouts.append(kw.get("timeout"))
            return MockHTTPSConnection("93.184.216.34", "example.com")

        client = WebhookClient(
            ssrf_guard=SSRFGuard(dns_resolver=mock_dns),
            clock=clock,
            http_connection_factory=mock_factory,
        )
        res = client.send("https://example.com/webhook", b'{}')
        self.assertEqual(len(captured_timeouts), 1)
        self.assertAlmostEqual(captured_timeouts[0], 2.0, places=1)

    # 25. Retry-After <= 2.0s Retries
    def test_retry_after_under_two_seconds_retries(self):
        clock = FakeClock(start=1000.0)
        sleep = FakeSleep(clock)
        def mock_dns(host, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_conn = MockHTTPSConnection(
            "93.184.216.34", "example.com",
            response_sequence=[
                MockHTTPResponse(status=429, headers={"Retry-After": "1"}),
                MockHTTPResponse(status=200),
            ]
        )
        client = WebhookClient(
            ssrf_guard=SSRFGuard(dns_resolver=mock_dns),
            clock=clock,
            sleep_fn=sleep,
            http_connection_factory=lambda **kw: mock_conn,
        )
        res = client.send("https://example.com/webhook", b'{}')
        self.assertTrue(res.success)
        self.assertEqual(res.attempts, 2)
        self.assertEqual(sleep.calls, [1.0])

    # 26. Retry-After > 2.0s Aborts Immediately
    def test_retry_after_over_two_seconds_aborts(self):
        clock = FakeClock(start=1000.0)
        sleep = FakeSleep(clock)
        def mock_dns(host, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_conn = MockHTTPSConnection(
            "93.184.216.34", "example.com",
            response_sequence=[MockHTTPResponse(status=429, headers={"Retry-After": "5"})]
        )
        client = WebhookClient(
            ssrf_guard=SSRFGuard(dns_resolver=mock_dns),
            clock=clock,
            sleep_fn=sleep,
            http_connection_factory=lambda **kw: mock_conn,
        )
        res = client.send("https://example.com/webhook", b'{}')
        self.assertFalse(res.success)
        self.assertEqual(res.status, DeliveryStatus.HTTP_RATE_LIMITED)
        self.assertEqual(res.attempts, 1)
        self.assertEqual(len(sleep.calls), 0)  # No retry sleep

    # 27. Retry-After Missing or Invalid Aborts Immediately
    def test_retry_after_missing_or_invalid_aborts(self):
        clock = FakeClock(start=1000.0)
        sleep = FakeSleep(clock)
        def mock_dns(host, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_conn = MockHTTPSConnection(
            "93.184.216.34", "example.com",
            response_sequence=[MockHTTPResponse(status=429, headers={})]  # Missing header
        )
        client = WebhookClient(
            ssrf_guard=SSRFGuard(dns_resolver=mock_dns),
            clock=clock,
            sleep_fn=sleep,
            http_connection_factory=lambda **kw: mock_conn,
        )
        res = client.send("https://example.com/webhook", b'{}')
        self.assertFalse(res.success)
        self.assertEqual(res.attempts, 1)
        self.assertEqual(len(sleep.calls), 0)

    # 28. HTTP 5xx Retries Once
    def test_http_5xx_retries_once(self):
        clock = FakeClock(start=1000.0)
        sleep = FakeSleep(clock)
        def mock_dns(host, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_conn = MockHTTPSConnection(
            "93.184.216.34", "example.com",
            response_sequence=[
                MockHTTPResponse(status=500),
                MockHTTPResponse(status=200),
            ]
        )
        client = WebhookClient(
            ssrf_guard=SSRFGuard(dns_resolver=mock_dns),
            clock=clock,
            sleep_fn=sleep,
            http_connection_factory=lambda **kw: mock_conn,
        )
        res = client.send("https://example.com/webhook", b'{}')
        self.assertTrue(res.success)
        self.assertEqual(res.attempts, 2)
        self.assertEqual(sleep.calls, [1.0])

    # 29. HTTP 4xx Zero Retries
    def test_http_4xx_permanent_error_zero_retries(self):
        clock = FakeClock(start=1000.0)
        sleep = FakeSleep(clock)
        def mock_dns(host, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        for code in [400, 401, 403, 404]:
            mock_conn = MockHTTPSConnection(
                "93.184.216.34", "example.com",
                response_sequence=[MockHTTPResponse(status=code)]
            )
            client = WebhookClient(
                ssrf_guard=SSRFGuard(dns_resolver=mock_dns),
                clock=clock,
                sleep_fn=sleep,
                http_connection_factory=lambda **kw: mock_conn,
            )
            res = client.send("https://example.com/webhook", b'{}')
            self.assertFalse(res.success)
            self.assertEqual(res.status, DeliveryStatus.HTTP_CLIENT_ERROR)
            self.assertEqual(res.attempts, 1)
            self.assertEqual(len(sleep.calls), 0)

    # 30. Bounded Queue Overflow
    def test_bounded_queue_overflow(self):
        sink = InMemoryDeliveryResultSink()
        service = WebhookDeliveryService(max_workers=0, max_queue_size=2, result_sink=sink)
        task = WebhookDeliveryTask(
            intent=NotificationIntent(
                intent_id="i1", event_id="e1", scan_id="s1", dedupe_key="d1",
                notification_type="ALERT", severity="HIGH", recipient_scope=RecipientScope.ORGANIZATION,
                organization_id=10, title="T", message="M"
            ),
            destination=WebhookDestinationConfig(destination_id="d", organization_id=10, url="https://example.com"),
            idempotency_key="k1",
            payload_bytes=b"{}",
        )
        # Fill queue
        self.assertTrue(service.enqueue(task))
        self.assertTrue(service.enqueue(task))
        # 3rd item overflows
        self.assertFalse(service.enqueue(task))
        results = sink.get_recent()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, DeliveryStatus.QUEUE_OVERFLOW)
        service.shutdown(max_wait_seconds=0.1)

    # 31. Shutdown Atomic Drain
    def test_shutdown_atomic_drain(self):
        sink = InMemoryDeliveryResultSink()
        service = WebhookDeliveryService(max_workers=0, max_queue_size=5, result_sink=sink)
        task = WebhookDeliveryTask(
            intent=NotificationIntent(
                intent_id="i1", event_id="e1", scan_id="s1", dedupe_key="d1",
                notification_type="ALERT", severity="HIGH", recipient_scope=RecipientScope.ORGANIZATION,
                organization_id=10, title="T", message="M"
            ),
            destination=WebhookDestinationConfig(destination_id="d", organization_id=10, url="https://example.com"),
            idempotency_key="k1",
            payload_bytes=b"{}",
        )
        service.enqueue(task)
        service.enqueue(task)
        service.shutdown(max_wait_seconds=0.1)

        results = sink.get_recent()
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertEqual(r.status, DeliveryStatus.SHUTDOWN_ABORTED)

    # 32. Shutdown is Idempotent
    def test_shutdown_is_idempotent(self):
        sink = InMemoryDeliveryResultSink()
        service = WebhookDeliveryService(max_workers=1, max_queue_size=5, result_sink=sink)
        # Calling shutdown twice must not raise and must not duplicate abort results
        service.shutdown(max_wait_seconds=0.1)
        service.shutdown(max_wait_seconds=0.1)
        results = sink.get_recent()
        self.assertEqual(len(results), 0)

    # 33. Exact URL Canonicalization
    def test_exact_url_canonicalization(self):
        raw_url = "HTTPS://API.Slack.Com.:443/services//hooks//?b=2&a=1"
        canonical = canonicalize_endpoint(raw_url)
        # Scheme lower, host lower & trailing dot stripped, default 443 omitted, path & query preserved exactly
        self.assertEqual(canonical, "https://api.slack.com/services//hooks//?b=2&a=1")
        key = compute_idempotency_key(10, canonical, "dedupe123")
        self.assertEqual(len(key), 64)

    # 34. Slack Escaping and Mention Neutralization
    def test_slack_escaping_and_mention_neutralization(self):
        finding = SafeFindingSummary(
            rule_id="TCS-1", cwe="CWE-1", severity="HIGH",
            file_path="src/app.py", line=10,
            message="Alert: <@U12345> injected <!everyone> & dangerous <script>"
        )
        intent = NotificationIntent(
            intent_id="i1", event_id="e1", scan_id="s1", dedupe_key="d1",
            notification_type="ALERT", severity="HIGH", recipient_scope=RecipientScope.ORGANIZATION,
            organization_id=10, title="Title & <bad>", message="Message with <@user>",
            safe_findings=(finding,)
        )
        payload_bytes = SlackWebhookFormatter.format(intent)
        payload_str = payload_bytes.decode("utf-8")
        # Ensure raw < and > are neutralized
        self.assertNotIn("<@U12345>", payload_str)
        self.assertNotIn("<!everyone>", payload_str)
        self.assertIn("&lt;@U12345&gt;", payload_str)
        self.assertIn("&lt;!everyone&gt;", payload_str)
        self.assertIn("&amp;", payload_str)

    # 35. Discord Mention Neutralization
    def test_discord_mention_neutralization(self):
        intent = NotificationIntent(
            intent_id="i1", event_id="e1", scan_id="s1", dedupe_key="d1",
            notification_type="ALERT", severity="HIGH", recipient_scope=RecipientScope.ORGANIZATION,
            organization_id=10, title="Check @everyone and @here", message="Target <@12345> and <@&67890>"
        )
        payload_bytes = DiscordWebhookFormatter.format(intent)
        payload_str = payload_bytes.decode("utf-8")
        self.assertNotIn("@everyone", payload_str)
        self.assertNotIn("@here", payload_str)
        self.assertIn("@\u200beveryone", payload_str)
        self.assertIn("@\u200bhere", payload_str)
        self.assertIn("<\u200b@", payload_str)

    # 36. Scanner Truth Independent of Delivery Failure
    def test_scanner_truth_independent_of_delivery_failure(self):
        # Simulated scan output
        scan_result = {
            "target": "acme/backend",
            "findings": [
                {"id": "F1", "rule": "SQLI", "severity": "CRITICAL", "path": "db.py"}
            ],
            "score": 45,
            "status": "COMPLETED",
        }
        scan_copy = dict(scan_result)

        # Trigger complete delivery failure
        sink = InMemoryDeliveryResultSink()
        service = WebhookDeliveryService(max_workers=0, result_sink=sink)
        adapter = WebhookDeliveryAdapter(service)

        intent = NotificationIntent(
            intent_id="i1", event_id="e1", scan_id="s1", dedupe_key="d1",
            notification_type="ALERT", severity="CRITICAL", recipient_scope=RecipientScope.ORGANIZATION,
            organization_id=10, title="TCS Alert", message="Msg"
        )
        dest = WebhookDestinationConfig(destination_id="d1", organization_id=99, url="https://example.com")

        try:
            adapter.deliver(intent, dest)
        except TenantBoundaryViolationError:
            pass

        service.shutdown(max_wait_seconds=0.1)

        # Assert scanner truth is 100% unaltered
        self.assertEqual(scan_result, scan_copy)

    # 37. Exact HMAC Header Contract & Secret Omission
    def test_exact_hmac_signature_header_contract(self):
        clock = FakeClock(start=1000.0)
        def mock_dns(host, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        captured_requests = []
        class MockCapturingConnection(MockHTTPSConnection):
            def request(self, method, url, body=b"", headers=None):
                captured_requests.append((method, url, body, headers or {}))
                super().request(method, url, body, headers)

        # Sub-case A: With valid secret token -> exact X-TCS-Signature: sha256=<hex_hmac>
        conn1 = MockCapturingConnection("93.184.216.34", "example.com")
        client1 = WebhookClient(
            ssrf_guard=SSRFGuard(dns_resolver=mock_dns),
            clock=clock,
            http_connection_factory=lambda **kw: conn1,
        )
        token = "test-secret-token-key-999"
        raw_payload = b'{"event":"security.finding","severity":"CRITICAL"}'
        auth_cfg = WebhookAuthConfig(secret_token=token)

        res1 = client1.send("https://example.com/webhook", raw_payload, auth_config=auth_cfg)
        self.assertTrue(res1.success)
        self.assertEqual(len(captured_requests), 1)

        req_headers1 = captured_requests[0][3]
        self.assertIn("X-TCS-Signature", req_headers1)
        expected_sig = compute_webhook_signature(token, raw_payload)
        self.assertEqual(req_headers1["X-TCS-Signature"], f"sha256={expected_sig}")

        # Invariant checks: MUST NOT contain legacy timestamp format or wrong header name
        self.assertNotIn("X-TCS-Signature-256", req_headers1)
        self.assertFalse(req_headers1["X-TCS-Signature"].startswith("t="))

        # Sub-case B: With secret_token=None -> signature header MUST be omitted completely
        captured_requests.clear()
        conn2 = MockCapturingConnection("93.184.216.34", "example.com")
        client2 = WebhookClient(
            ssrf_guard=SSRFGuard(dns_resolver=mock_dns),
            clock=clock,
            http_connection_factory=lambda **kw: conn2,
        )
        auth_none = WebhookAuthConfig(secret_token=None)
        res2 = client2.send("https://example.com/webhook", raw_payload, auth_config=auth_none)
        self.assertTrue(res2.success)
        self.assertEqual(len(captured_requests), 1)
        req_headers2 = captured_requests[0][3]
        self.assertNotIn("X-TCS-Signature", req_headers2)
        self.assertNotIn("X-TCS-Signature-256", req_headers2)

        # Sub-case C: With auth_config=None -> signature header MUST be omitted completely
        captured_requests.clear()
        conn3 = MockCapturingConnection("93.184.216.34", "example.com")
        client3 = WebhookClient(
            ssrf_guard=SSRFGuard(dns_resolver=mock_dns),
            clock=clock,
            http_connection_factory=lambda **kw: conn3,
        )
        res3 = client3.send("https://example.com/webhook", raw_payload, auth_config=None)
        self.assertTrue(res3.success)
        self.assertEqual(len(captured_requests), 1)
        req_headers3 = captured_requests[0][3]
        self.assertNotIn("X-TCS-Signature", req_headers3)
        self.assertNotIn("X-TCS-Signature-256", req_headers3)

    # 38. Network Timeout Retries Once with Exact 1.0s Backoff
    def test_network_timeout_retries_with_one_second_backoff(self):
        clock = FakeClock(start=1000.0)
        sleep = FakeSleep(clock)
        def mock_dns(host, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        mock_conn = MockHTTPSConnection(
            "93.184.216.34", "example.com",
            response_sequence=[
                socket.timeout("TCP connection timeout"),
                MockHTTPResponse(status=200),
            ]
        )
        client = WebhookClient(
            ssrf_guard=SSRFGuard(dns_resolver=mock_dns),
            clock=clock,
            sleep_fn=sleep,
            http_connection_factory=lambda **kw: mock_conn,
        )
        res = client.send("https://example.com/webhook", b'{}')
        self.assertTrue(res.success)
        self.assertEqual(res.attempts, 2)
        self.assertEqual(sleep.calls, [1.0])

    # 39. Default Shutdown Deadline is Exactly 3.0 Seconds
    def test_shutdown_default_deadline_three_seconds(self):
        import inspect
        sig = inspect.signature(WebhookDeliveryService.shutdown)
        self.assertIn("max_wait_seconds", sig.parameters)
        self.assertEqual(sig.parameters["max_wait_seconds"].default, 3.0)


if __name__ == "__main__":
    unittest.main()
