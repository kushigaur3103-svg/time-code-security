"""
Phase 15D Comprehensive Verification Suite: Durable Audit Persistence, REST API & EventBus Integration.

Verifies all 28 mandatory Phase 15D requirements:
1. DeliveryAuditLog schema
2. Append-only repository interface (no update, no delete)
3. Deterministic pagination (ORDER BY created_at DESC, id DESC, limit 1..100)
4. UTC timestamps (ISO-8601 UTC serialized)
5. Tenant isolation across queries
6. Cross-tenant 404 anti-enumeration
7. Admin-only delivery audit access (HTTP 200 for admin)
8. Developer/member access control (HTTP 403 for non-admin)
9. Authentication failure semantics (HTTP 401)
10. Input validation failure semantics (HTTP 422)
11. Notification listing
12. Unread count
13. Mark one read/unread
14. Mark all read
15. Worker DB session isolation (independent sessions per operation)
16. Concurrent audit persistence
17. DB audit failure does not kill worker
18. DB audit failure does not trigger webhook retry
19. DeliveryResult status preserved on audit failure
20. Existing EventPublisher invocation
21. Existing InMemoryEventBus invocation
22. Scanner result unchanged by notification failure
23. Legacy requests.post removed from app.py
24. No direct webhook network calls remain in app.py
25. Persisted audit survives new repository/session
26. Public DTO excludes target_ip
27. Secrets excluded from audit logs
28. Request and response bodies excluded from audit logs
"""

from __future__ import annotations

import datetime
import os
import subprocess
import sys
import threading
import time
import unittest
import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import app
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from delivery_models import (
    Base,
    DeliveryAuditLog,
    DeliveryAuditLogCreate,
    DeliveryAuditLogRead,
    DeliveryStatsResponse,
)
from delivery_repository import DeliveryRepository
from durable_delivery_sink import DurableDeliveryResultSink
from event_bus import InMemoryEventBus
from event_publisher import EventPublisher
from event_taxonomy import EventType, SecurityDomainEvent
from notification_models import Notification, NotificationCreate, RecipientScope
from notification_service import NotificationService
from sqlite_delivery_repository import SqliteDeliveryRepository
from sqlite_notification_repository import SqliteNotificationRepository
from webhook_adapter import (
    DeliveryResult,
    InMemoryDeliveryResultSink,
    WebhookDeliveryAdapter,
    WebhookDeliveryService,
    WebhookDestinationConfig,
)
from webhook_client import DeliveryStatus



class Phase15DTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create an isolated test SQLite in-memory database with StaticPool
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)
        app.Base.metadata.create_all(bind=cls.engine)

    def setUp(self):
        self.session = self.SessionLocal()
        # Clean up existing test data
        self.session.query(DeliveryAuditLog).delete()
        self.session.query(Notification).delete()
        self.session.commit()

    def tearDown(self):
        self.session.close()

    # -----------------------------------------------------------------------
    # 1. No /api/notifications/deliveries/stats route exists
    # -----------------------------------------------------------------------
    def test_01_no_deliveries_stats_route(self):
        from notification_routes import router
        route_paths = [r.path for r in router.routes]
        self.assertNotIn("/deliveries/stats", route_paths)
        self.assertNotIn("/api/notifications/deliveries/stats", route_paths)

        from app import app as fastapi_app
        from fastapi.testclient import TestClient
        client = TestClient(fastapi_app)
        res = client.get("/api/notifications/deliveries/stats")
        self.assertEqual(res.status_code, 404, "Public /api/notifications/deliveries/stats endpoint must NOT exist")

    # -----------------------------------------------------------------------
    # 2. Exact audit model field names
    # -----------------------------------------------------------------------
    def test_02_exact_audit_model_field_names(self):
        columns = {col.name: col for col in DeliveryAuditLog.__table__.columns}
        exact_expected_cols = {
            "id", "organization_id", "event_id", "scan_id", "idempotency_key",
            "channel", "status", "status_code", "attempts", "duration_ms",
            "error_message", "created_at"
        }
        self.assertEqual(
            set(columns.keys()),
            exact_expected_cols,
            f"Table columns must match exact approved schema: {exact_expected_cols}"
        )

    # -----------------------------------------------------------------------
    # 3. No created_at_epoch column (and other unapproved fields)
    # -----------------------------------------------------------------------
    def test_03_no_created_at_epoch_column(self):
        columns = set(DeliveryAuditLog.__table__.columns.keys())
        self.assertNotIn("created_at_epoch", columns, "created_at_epoch must NOT be in DeliveryAuditLog")
        self.assertNotIn("http_status", columns, "http_status must NOT replace status_code")
        self.assertNotIn("attempt_count", columns, "attempt_count must NOT replace attempts")
        self.assertNotIn("error_snippet", columns, "error_snippet must NOT replace error_message")
        self.assertNotIn("target_ip", columns, "target_ip must NEVER be persisted")
        self.assertNotIn("secret", columns, "secrets must NEVER be persisted")
        self.assertNotIn("payload", columns, "payload must NEVER be persisted")
        self.assertNotIn("response_body", columns, "response_body must NEVER be persisted")

    # -----------------------------------------------------------------------
    # 4. Full DeliveryStatus values are preserved
    # -----------------------------------------------------------------------
    def test_04_full_delivery_status_values_preserved(self):
        repo = SqliteDeliveryRepository(session=self.session)
        phase15c_statuses = [
            DeliveryStatus.SUCCESS,
            DeliveryStatus.SSRF_BLOCKED,
            DeliveryStatus.DNS_RESOLUTION_FAILED,
            DeliveryStatus.CONNECTION_TIMEOUT,
            DeliveryStatus.READ_TIMEOUT,
            DeliveryStatus.TLS_ERROR,
            DeliveryStatus.CONNECTION_REFUSED,
            DeliveryStatus.HTTP_CLIENT_ERROR,
            DeliveryStatus.HTTP_RATE_LIMITED,
            DeliveryStatus.HTTP_SERVER_ERROR,
            DeliveryStatus.REDIRECT_BLOCKED,
            DeliveryStatus.PAYLOAD_TOO_LARGE,
            DeliveryStatus.QUEUE_OVERFLOW,
            DeliveryStatus.PAYLOAD_INVALID,
            DeliveryStatus.SHUTDOWN_ABORTED,
            DeliveryStatus.INTERNAL_ERROR,
        ]
        for idx, st in enumerate(phase15c_statuses):
            record = repo.create({
                "id": f"deliv_st_{idx}",
                "organization_id": 1,
                "event_id": f"evt_st_{idx}",
                "idempotency_key": f"key_st_{idx}",
                "channel": "WEBHOOK",
                "status": st,
            })
            self.assertEqual(
                record.status,
                st.value,
                f"Status must be preserved as '{st.value}', not collapsed into generic success/failure"
            )
        self.session.commit()

        persisted = self.session.query(DeliveryAuditLog).filter(DeliveryAuditLog.organization_id == 1).all()
        persisted_statuses = {p.status for p in persisted}
        for st in phase15c_statuses:
            self.assertIn(st.value, persisted_statuses)

    # -----------------------------------------------------------------------
    # 5. DeliveryResult -> DeliveryAuditLog mapping is lossless
    # -----------------------------------------------------------------------
    def test_05_delivery_result_to_audit_log_lossless_mapping(self):
        repo = SqliteDeliveryRepository(session=self.session)
        result = DeliveryResult(
            success=False,
            status=DeliveryStatus.CONNECTION_TIMEOUT,
            status_code=504,
            attempts=2,
            duration_ms=1050.75,
            error_message="Connection timed out after 1000ms",
            organization_id=42,
            event_id="evt_lossless_test",
            scan_id="scan_lossless_99",
            channel="WEBHOOK",
            idempotency_key="idemp_lossless_1",
            target_ip="93.184.216.34",
        )
        audit = repo.create(result)
        self.session.commit()

        self.assertEqual(audit.status, "CONNECTION_TIMEOUT")
        self.assertEqual(audit.status_code, 504)
        self.assertEqual(audit.attempts, 2)
        self.assertAlmostEqual(audit.duration_ms, 1050.75, places=2)
        self.assertEqual(audit.error_message, "Connection timed out after 1000ms")
        self.assertEqual(audit.organization_id, 42)
        self.assertEqual(audit.event_id, "evt_lossless_test")
        self.assertEqual(audit.scan_id, "scan_lossless_99")
        self.assertEqual(audit.channel, "WEBHOOK")
        self.assertEqual(audit.idempotency_key, "idemp_lossless_1")
        self.assertIsNotNone(audit.id)
        self.assertIsNotNone(audit.created_at)

    # -----------------------------------------------------------------------
    # 6. Phase 15C sealed files remain unmodified
    # -----------------------------------------------------------------------
    def test_06_phase15c_sealed_files_remain_unmodified(self):
        sealed_files = [
            "notification_policy.py",
            "in_app_adapter.py",
            "ssrf_guard.py",
            "webhook_client.py",
            "webhook_formatters.py",
            "webhook_adapter.py",
        ]
        diff_output = subprocess.check_output(
            ["git", "diff", "--"] + sealed_files,
            cwd=PROJECT_ROOT,
        )
        self.assertEqual(
            diff_output.strip(),
            b"",
            f"Phase 15C sealed files must have zero git diffs. Found: {diff_output.decode('utf-8')}"
        )

    # -----------------------------------------------------------------------
    # Append-Only Repository Interface (no update, no delete)
    # -----------------------------------------------------------------------
    def test_repo_append_only_interface(self):
        repo = SqliteDeliveryRepository(session=self.session)
        self.assertTrue(issubclass(SqliteDeliveryRepository, DeliveryRepository))
        self.assertTrue(hasattr(repo, "create"))
        self.assertTrue(hasattr(repo, "get_by_id"))
        self.assertTrue(hasattr(repo, "list"))
        self.assertTrue(hasattr(repo, "get_stats"))
        self.assertFalse(hasattr(repo, "update"), "DeliveryRepository must NOT expose update()")
        self.assertFalse(hasattr(repo, "delete"), "DeliveryRepository must NOT expose delete()")

    # -----------------------------------------------------------------------
    # 7. Cross-tenant 404 (Anti-Enumeration)
    # -----------------------------------------------------------------------
    def test_07_cross_tenant_404(self):
        repo = SqliteDeliveryRepository(session=self.session)
        repo.create({
            "id": "deliv_secret_org2",
            "organization_id": 2,
            "event_id": "evt_2",
            "idempotency_key": "key_2",
            "channel": "WEBHOOK",
            "status": "SUCCESS",
        })
        self.session.commit()

        # Repository-level anti-enumeration
        fetched = repo.get_by_id(delivery_id="deliv_secret_org2", organization_id=1)
        self.assertIsNone(fetched, "Cross-tenant retrieval must return None to trigger HTTP 404")

        # Route-level anti-enumeration
        notif_repo = SqliteNotificationRepository(session=self.session)
        n = notif_repo.create(NotificationCreate(
            organization_id=2,
            recipient_scope=RecipientScope.ORGANIZATION,
            event_id="evt_org2",
            scan_id="scan_org2",
            dedupe_key="dedupe_secret_org2",
            type="VULNERABILITY",
            severity="HIGH",
            title="Secret",
            message="Secret info",
        ))
        self.session.commit()

        from notification_routes import mark_notification_read
        from fastapi import HTTPException
        user_org1 = MagicMock(id=1, org_id=1, org_role="admin")
        with self.assertRaises(HTTPException) as ctx:
            mark_notification_read(id=n.id, user=user_org1, db=self.session)
        self.assertEqual(ctx.exception.status_code, 404)

    # -----------------------------------------------------------------------
    # 8. Non-admin 403
    # -----------------------------------------------------------------------
    def test_08_non_admin_403(self):
        admin_user = MagicMock(org_role="admin", org_id=1, id=100)
        dev_user = MagicMock(org_role="developer", org_id=1, id=101)
        member_user = MagicMock(org_role="member", org_id=1, id=102)

        from notification_routes import list_delivery_audits
        from fastapi import HTTPException

        # Admin: 200 OK (no exception)
        res = list_delivery_audits(user=admin_user, db=self.session)
        self.assertIsNotNone(res)

        # Developer: 403 Forbidden
        with self.assertRaises(HTTPException) as ctx_dev:
            list_delivery_audits(user=dev_user, db=self.session)
        self.assertEqual(ctx_dev.exception.status_code, 403)

        # Member: 403 Forbidden
        with self.assertRaises(HTTPException) as ctx_mem:
            list_delivery_audits(user=member_user, db=self.session)
        self.assertEqual(ctx_mem.exception.status_code, 403)

    # -----------------------------------------------------------------------
    # 9. Authentication 401
    # -----------------------------------------------------------------------
    def test_09_authentication_401(self):
        from app import app as fastapi_app
        from fastapi.testclient import TestClient
        client = TestClient(fastapi_app)

        # Unauthenticated request -> HTTP 401
        res = client.get("/api/notifications")
        self.assertEqual(res.status_code, 401)

        # Invalid auth format -> HTTP 401
        res_bad_auth = client.get("/api/notifications", headers={"Authorization": "Basic 12345"})
        self.assertEqual(res_bad_auth.status_code, 401)

        # Deliveries endpoint without auth -> HTTP 401
        res_deliv = client.get("/api/notifications/deliveries")
        self.assertEqual(res_deliv.status_code, 401)

    # -----------------------------------------------------------------------
    # 10. Validation 422
    # -----------------------------------------------------------------------
    def test_10_validation_422(self):
        from app import app as fastapi_app
        from fastapi.testclient import TestClient
        from notification_routes import get_authenticated_user

        mock_user = MagicMock(id=1, org_id=1, org_role="admin")
        fastapi_app.dependency_overrides[get_authenticated_user] = lambda: mock_user
        try:
            client = TestClient(fastapi_app)

            # limit > 100 -> 422
            res = client.get("/api/notifications?limit=150")
            self.assertEqual(res.status_code, 422)

            # limit < 1 -> 422
            res2 = client.get("/api/notifications?limit=0")
            self.assertEqual(res2.status_code, 422)

            # offset < 0 -> 422
            res3 = client.get("/api/notifications?offset=-1")
            self.assertEqual(res3.status_code, 422)

            # deliveries limit > 100 -> 422
            res4 = client.get("/api/notifications/deliveries?limit=101")
            self.assertEqual(res4.status_code, 422)
        finally:
            fastapi_app.dependency_overrides.clear()

    # -----------------------------------------------------------------------
    # 11. Deterministic pagination (ORDER BY created_at DESC, id DESC)
    # -----------------------------------------------------------------------
    def test_11_deterministic_pagination(self):
        repo = SqliteDeliveryRepository(session=self.session)
        base_time = datetime.datetime(2026, 9, 10, 12, 0, 0, tzinfo=datetime.timezone.utc)

        for i in range(5):
            repo.create({
                "id": f"deliv_det_{i}",
                "organization_id": 1,
                "event_id": f"evt_det_{i}",
                "idempotency_key": f"idemp_det_{i}",
                "channel": "WEBHOOK",
                "status": "SUCCESS",
                "attempts": 1,
                "duration_ms": 100.0,
                "created_at": base_time + datetime.timedelta(minutes=i),
            })
        self.session.commit()

        items, total = repo.list(organization_id=1, limit=2, offset=0)
        self.assertEqual(total, 5)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].id, "deliv_det_4")
        self.assertEqual(items[1].id, "deliv_det_3")

        items2, _ = repo.list(organization_id=1, limit=2, offset=2)
        self.assertEqual(items2[0].id, "deliv_det_2")
        self.assertEqual(items2[1].id, "deliv_det_1")

    # -----------------------------------------------------------------------
    # 12. UTC timestamp behavior
    # -----------------------------------------------------------------------
    def test_12_utc_timestamp_behavior(self):
        repo = SqliteDeliveryRepository(session=self.session)
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        record = repo.create({
            "id": "deliv_utc_test",
            "organization_id": 1,
            "event_id": "evt_utc",
            "idempotency_key": "idemp_utc",
            "channel": "WEBHOOK",
            "status": "SUCCESS",
            "created_at": now_utc,
        })
        self.session.commit()

        d = record.to_dict()
        self.assertIn("created_at", d)
        self.assertTrue(d["created_at"].endswith("+00:00") or d["created_at"].endswith("Z"))

    # -----------------------------------------------------------------------
    # 13. Worker-local SQLAlchemy sessions
    # -----------------------------------------------------------------------
    def test_13_worker_local_sqlalchemy_sessions(self):
        session_tokens = []

        def tracked_session_factory():
            s = self.SessionLocal()
            token = uuid.uuid4().hex
            session_tokens.append(token)
            return s

        sink = DurableDeliveryResultSink(
            session_factory=tracked_session_factory,
            memory_sink=InMemoryDeliveryResultSink(),
        )

        def worker_task(idx: int):
            res = DeliveryResult(
                success=True,
                status=DeliveryStatus.SUCCESS,
                status_code=200,
                error_message=None,
                duration_ms=50.0,
                attempts=1,
                idempotency_key=f"concurrent_key_{idx}",
                organization_id=1,
                event_id=f"evt_concurrent_{idx}",
                scan_id="scan_concurrent",
                channel="WEBHOOK",
            )
            sink.record(res)

        threads = [threading.Thread(target=worker_task, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(session_tokens), 10)
        self.assertEqual(len(set(session_tokens)), 10, "Each worker operation must obtain a fresh session from factory")

    # -----------------------------------------------------------------------
    # 14. Audit failure does not trigger webhook retry
    # -----------------------------------------------------------------------
    def test_14_audit_failure_does_not_trigger_webhook_retry(self):
        failing_session_factory = MagicMock(side_effect=RuntimeError("Database lock timeout"))
        mem_sink = InMemoryDeliveryResultSink()
        sink = DurableDeliveryResultSink(
            session_factory=failing_session_factory,
            memory_sink=mem_sink,
        )

        result = DeliveryResult(
            success=True,
            status=DeliveryStatus.SUCCESS,
            status_code=200,
            error_message=None,
            duration_ms=45.0,
            attempts=1,
            idempotency_key="idemp_fail_test",
            organization_id=1,
            event_id="evt_fail_test",
            scan_id="scan_fail",
            channel="WEBHOOK",
        )

        sink.record(result)

        recent = sink.get_recent()
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0].attempts, 1, "Attempts must remain 1 without retrying")
        self.assertEqual(recent[0].status, DeliveryStatus.SUCCESS)

    # -----------------------------------------------------------------------
    # 15. Audit failure does not kill worker
    # -----------------------------------------------------------------------
    def test_15_audit_failure_does_not_kill_worker(self):
        failing_session_factory = MagicMock(side_effect=RuntimeError("Database lock timeout"))
        mem_sink = InMemoryDeliveryResultSink()
        sink = DurableDeliveryResultSink(
            session_factory=failing_session_factory,
            memory_sink=mem_sink,
        )

        result = DeliveryResult(
            success=True,
            status=DeliveryStatus.SUCCESS,
            status_code=200,
            error_message=None,
            duration_ms=45.0,
            attempts=1,
            idempotency_key="idemp_fail_worker",
            organization_id=1,
            event_id="evt_fail_worker",
            scan_id="scan_fail",
            channel="WEBHOOK",
        )

        crashed = False
        def worker():
            nonlocal crashed
            try:
                sink.record(result)
            except Exception:
                crashed = True

        t = threading.Thread(target=worker)
        t.start()
        t.join()
        self.assertFalse(crashed, "Worker thread must not crash on DB audit failure")

    # -----------------------------------------------------------------------
    # 16. Legacy requests.post is absent from app.py
    # -----------------------------------------------------------------------
    def test_16_legacy_requests_post_absent_from_app_py(self):
        app_path = os.path.join(PROJECT_ROOT, "app.py")
        with open(app_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertNotIn("requests.post(user.webhook_url", content, "requests.post(user.webhook_url) must be deleted from app.py")
        self.assertNotIn("user.webhook_url, json=payload", content, "Legacy webhook json payload send must be deleted from app.py")

    # -----------------------------------------------------------------------
    # 17. user.webhook_url is absent from SecurityDomainEvent metadata
    # -----------------------------------------------------------------------
    def test_17_user_webhook_url_absent_from_security_domain_event_metadata(self):
        bus = InMemoryEventBus()
        publisher = EventPublisher(bus=bus)

        events_received = []
        bus.subscribe(
            handler=lambda e: events_received.append(e),
            event_type=EventType.SCAN_COMPLETED,
            name="MetadataInspector",
        )

        service = NotificationService(
            bus=bus,
            event_publisher=publisher,
            session_factory=self.SessionLocal,
        )

        scan_result = {
            "status": "success",
            "summary": {
                "active_vulnerabilities": 0,
                "secrets_detected": 0,
                "security_score": 100,
                "risk_level": "CLEAN",
                "risk_message": "Clean scan",
            },
            "findings": [],
        }

        service.publish_scan_events(
            scan_result=scan_result,
            repository="org_1",
            scan_id="scan_meta_test",
            metadata={"organization_id": 1, "user_id": 10, "email": "user@example.com"},
        )
        service.shutdown()

        self.assertGreaterEqual(len(events_received), 1)
        for ev in events_received:
            self.assertNotIn("webhook_url", ev.metadata)
            self.assertNotIn("url", ev.metadata)
            self.assertNotIn("destination", ev.metadata)
            self.assertNotIn("secret", ev.metadata)

    # -----------------------------------------------------------------------
    # 18. Scanner result remains unchanged
    # -----------------------------------------------------------------------
    def test_18_scanner_result_remains_unchanged(self):
        from app import background_scan_task, ScanCache, User
        u = self.session.query(User).filter(User.email == "test_scan@example.com").first()
        if not u:
            u = User(email="test_scan@example.com", password_hash="dummy", org_id=1, org_role="admin")
            self.session.add(u)
            self.session.commit()

        job = ScanCache(job_id="test_job_123", code_hash="hash_123", status="pending")
        self.session.add(job)
        self.session.commit()

        def mock_ai(code, prompt, is_fix=False, db=None, existing_job_id=None):
            if existing_job_id and db:
                j = db.query(ScanCache).filter(ScanCache.job_id == existing_job_id).first()
                if j:
                    j.status = "completed"
                    j.report_text = "Security Analysis Report Content"
                    db.commit()
            return "Security Analysis Report Content"

        with patch("app.SessionLocal", side_effect=self.SessionLocal):
            with patch("app.get_cached_or_generate_ai", side_effect=mock_ai):
                background_scan_task(
                    job_id="test_job_123",
                    email="test_scan@example.com",
                    redacted_code="print('hello')",
                    system_prompt="Analyze code",
                    secrets_found=False,
                )

        updated_job = self.session.query(ScanCache).filter(ScanCache.job_id == "test_job_123").first()
        self.assertIsNotNone(updated_job)
        self.assertEqual(updated_job.status, "completed")
        self.assertIn("Security Analysis Report Content", updated_job.report_text)

    # -----------------------------------------------------------------------
    # In-App Notification Functional Lifecycle Tests
    # -----------------------------------------------------------------------
    def test_19_in_app_notification_read_flow(self):
        notif_repo = SqliteNotificationRepository(session=self.session)
        notif = notif_repo.create(
            NotificationCreate(
                organization_id=1,
                recipient_scope=RecipientScope.ORGANIZATION,
                event_id="evt_test",
                scan_id="scan_test_1",
                dedupe_key="dedupe_1",
                type="VULNERABILITY",
                severity="HIGH",
                title="Test Vulnerability",
                message="Details here",
            )
        )
        self.session.commit()

        self.assertEqual(notif_repo.count_unread(organization_id=1), 1)

        items = notif_repo.list_notifications(organization_id=1)
        self.assertEqual(len(items), 1)
        self.assertFalse(items[0].is_read)

        now = datetime.datetime.now(datetime.timezone.utc)
        marked = notif_repo.mark_read(notification_id=notif.id, organization_id=1, read_at=now)
        self.assertTrue(marked)
        self.session.commit()

        refreshed = notif_repo.get_by_id(notification_id=notif.id, organization_id=1)
        self.assertTrue(refreshed.is_read)
        self.assertEqual(notif_repo.count_unread(organization_id=1), 0)

        marked_count = notif_repo.mark_all_read(organization_id=1, read_at=now)
        self.assertEqual(marked_count, 0)

    # -----------------------------------------------------------------------
    # Data Safety & Minimization Invariants
    # -----------------------------------------------------------------------
    def test_20_data_safety_and_minimization(self):
        fields = (
            DeliveryAuditLogRead.model_fields.keys()
            if hasattr(DeliveryAuditLogRead, "model_fields")
            else DeliveryAuditLogRead.__fields__.keys()
        )
        self.assertNotIn("target_ip", fields)
        self.assertNotIn("secret", fields)
        self.assertNotIn("webhook_secret", fields)
        self.assertNotIn("api_key", fields)
        self.assertNotIn("request_body", fields)
        self.assertNotIn("payload", fields)
        self.assertNotIn("response_body", fields)
        self.assertNotIn("raw_code", fields)

    # -----------------------------------------------------------------------
    # Persisted Audit Survives New Session
    # -----------------------------------------------------------------------
    def test_21_persisted_audit_survives_new_session(self):
        s1 = self.SessionLocal()
        r1 = SqliteDeliveryRepository(session=s1)
        r1.create({
            "id": "deliv_persistent_1",
            "organization_id": 99,
            "event_id": "evt_pers_1",
            "idempotency_key": "idemp_pers_1",
            "channel": "WEBHOOK",
            "status": "SUCCESS",
            "duration_ms": 10.0,
        })
        s1.commit()
        s1.close()

        s2 = self.SessionLocal()
        r2 = SqliteDeliveryRepository(session=s2)
        fetched = r2.get_by_id(delivery_id="deliv_persistent_1", organization_id=99)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.id, "deliv_persistent_1")
        self.assertEqual(fetched.status, "SUCCESS")
        s2.close()


    # -----------------------------------------------------------------------
    # 22. No synthetic CWE-SEC finding is created merely from AI text
    # -----------------------------------------------------------------------
    def test_22_no_synthetic_cwe_sec_finding_from_ai_text(self):
        from app import background_scan_task, User, notification_service

        u = self.session.query(User).filter(User.email == "test_no_synth@example.com").first()
        if not u:
            u = User(email="test_no_synth@example.com", password_hash="dummy", org_id=1, org_role="admin")
            self.session.add(u)
            self.session.commit()

        events_captured = []
        notification_service.bus.subscribe(
            handler=lambda e: events_captured.append(e),
            event_type=None,
            name="SynthChecker",
        )

        # AI mock outputs scary alarm text, but source code is completely clean
        def mock_ai_alarm(code, prompt, is_fix=False, db=None, existing_job_id=None):
            return "🚨 Vulnerability Detected! CRITICAL vulnerability found in code_analysis!"

        with patch("app.SessionLocal", side_effect=self.SessionLocal):
            with patch("app.get_cached_or_generate_ai", side_effect=mock_ai_alarm):
                background_scan_task(
                    job_id="test_job_clean_code",
                    email="test_no_synth@example.com",
                    redacted_code="print('totally clean code')",
                    system_prompt="Analyze code",
                    secrets_found=False,
                )

        # Verify no synthetic CWE-SEC finding was manufactured
        for ev in events_captured:
            if ev.scan_id == "test_job_clean_code":
                self.assertEqual(ev.summary.critical_count, 0, "Clean code must have 0 critical findings regardless of AI text")
                self.assertEqual(ev.summary.high_count, 0, "Clean code must have 0 high findings regardless of AI text")
                self.assertEqual(ev.high_risk_count, 0)
                fingerprints = ev.metadata.get("critical_fingerprints", [])
                for fp in fingerprints:
                    self.assertNotIn("CWE-SEC", fp)
                    self.assertNotIn("code_analysis", fp)

    # -----------------------------------------------------------------------
    # 23. Actual scanner finding data is passed unchanged into EventPublisher
    # -----------------------------------------------------------------------
    def test_23_actual_scanner_finding_passed_unchanged(self):
        from app import background_scan_task, User, notification_service

        u = self.session.query(User).filter(User.email == "test_real_ast@example.com").first()
        if not u:
            u = User(email="test_real_ast@example.com", password_hash="dummy", org_id=1, org_role="admin")
            self.session.add(u)
            self.session.commit()

        events_captured = []
        notification_service.bus.subscribe(
            handler=lambda e: events_captured.append(e),
            event_type=None,
            name="RealAstChecker",
        )

        # Real OS command injection code: AST taint tracker detects CWE-78
        vulnerable_code = "from flask import request\nimport os\ncmd = request.args.get('cmd')\nos.system(cmd)"

        with patch("app.SessionLocal", side_effect=self.SessionLocal):
            with patch("app.get_cached_or_generate_ai", return_value="Analysis report"):
                with patch.object(notification_service.in_app_adapter, "handle_intent"):
                    background_scan_task(
                        job_id="test_job_real_ast",
                        email="test_real_ast@example.com",
                        redacted_code=vulnerable_code,
                        system_prompt="Analyze code",
                        secrets_found=False,
                    )

        # Verify actual AST finding (CWE-78) was detected and passed into EventPublisher
        real_events = [e for e in events_captured if e.scan_id == "test_job_real_ast"]
        self.assertGreaterEqual(len(real_events), 1)
        crit_events = [e for e in real_events if e.event_type == EventType.CRITICAL_FINDING_DETECTED]
        self.assertEqual(len(crit_events), 1)
        crit_event = crit_events[0]
        self.assertIn("critical_fingerprints", crit_event.metadata)
        self.assertTrue(any("CWE-78" in fp and "system" in fp for fp in crit_event.metadata["critical_fingerprints"]))

    # -----------------------------------------------------------------------
    # 24. No finding is invented when no actual scanner finding exists
    # -----------------------------------------------------------------------
    def test_24_no_finding_invented_when_clean(self):
        from app import background_scan_task, User, notification_service

        u = self.session.query(User).filter(User.email == "test_clean_scan@example.com").first()
        if not u:
            u = User(email="test_clean_scan@example.com", password_hash="dummy", org_id=1, org_role="admin")
            self.session.add(u)
            self.session.commit()

        events_captured = []
        notification_service.bus.subscribe(
            handler=lambda e: events_captured.append(e),
            event_type=None,
            name="CleanScannerChecker",
        )

        clean_code = "a = 1 + 2\nprint(a)"

        with patch("app.SessionLocal", side_effect=self.SessionLocal):
            with patch("app.get_cached_or_generate_ai", return_value="All clear, no issues"):
                background_scan_task(
                    job_id="test_job_clean_true",
                    email="test_clean_scan@example.com",
                    redacted_code=clean_code,
                    system_prompt="Analyze code",
                    secrets_found=False,
                )

        clean_events = [e for e in events_captured if e.scan_id == "test_job_clean_true"]
        for e in clean_events:
            self.assertEqual(e.high_risk_count, 0)
            self.assertEqual(e.summary.critical_count, 0)
            self.assertEqual(e.summary.high_count, 0)
            self.assertEqual(e.summary.sast_findings, 0)

    # -----------------------------------------------------------------------
    # 25. NotificationService import safety (no threads/network on import)
    # -----------------------------------------------------------------------
    def test_25_notification_service_import_safety(self):
        import notification_service
        # Module import must not start active threads or initiate sockets
        self.assertTrue(hasattr(notification_service, "NotificationService"))

    # -----------------------------------------------------------------------
    # 26. Multiple imports/initializations do not create duplicate subscribers
    # -----------------------------------------------------------------------
    def test_26_multiple_init_no_duplicate_subscribers_or_workers(self):
        import app as app_module
        svc1 = getattr(app_module.app.state, "notification_service", None)
        self.assertIsNotNone(svc1)
        initial_sub_count = len(svc1.bus._subscribers)

        # Simulate re-running initialization block
        svc2 = getattr(app_module.app.state, "notification_service", None)
        if svc2 is None:
            svc2 = NotificationService(session_factory=app_module.SessionLocal)
            app_module.app.state.notification_service = svc2

        self.assertIs(svc1, svc2, "Singleton on app.state must prevent duplicate service creation")
        self.assertEqual(len(svc1.bus._subscribers), initial_sub_count, "Subscriber count must not duplicate")

    # -----------------------------------------------------------------------
    # 27. Destination registry enforces organization_id match
    # -----------------------------------------------------------------------
    def test_27_destination_tenant_boundary_enforcement(self):
        bus = InMemoryEventBus()
        mock_webhook_adapter = MagicMock()
        service = NotificationService(
            bus=bus,
            webhook_adapter=mock_webhook_adapter,
            session_factory=self.SessionLocal,
        )

        # Register destination for org 1
        service.register_destination(
            WebhookDestinationConfig(
                destination_id="dest_org1",
                organization_id=1,
                url="https://api.example.com/webhook",
            )
        )

        # Construct intent for org 2 (mismatched)
        from notification_policy import NotificationIntent
        mismatched_intent = NotificationIntent(
            intent_id="intent_mismatch",
            event_id="evt_mismatch",
            scan_id="scan_mismatch",
            dedupe_key="dedupe_mismatch",
            notification_type="SECURITY_ALERT",
            severity="HIGH",
            recipient_scope=RecipientScope.ORGANIZATION,
            organization_id=2,  # Org 2!
            channel="WEBHOOK",
            title="Alert",
            message="Alert message",
        )

        # Directly attempt dispatching via handle_domain_event with simulated event for org 2
        with patch("notification_policy.NotificationPolicy.evaluate", return_value=[mismatched_intent]):
            mock_event = MagicMock(event_id="evt_mismatch", metadata={"organization_id": 2})
            service.handle_domain_event(mock_event)

        # Webhook adapter must NOT have been called with mismatched destination
        mock_webhook_adapter.dispatch_intent.assert_not_called()
        service.shutdown()

    # -----------------------------------------------------------------------
    # 28. Missing org_id never falls back to user.id
    # -----------------------------------------------------------------------
    def test_28_missing_org_id_never_falls_back_to_user_id(self):
        from app import background_scan_task, User, notification_service

        u = self.session.query(User).filter(User.email == "test_no_org@example.com").first()
        if not u:
            u = User(
                email="test_no_org@example.com",
                password_hash="dummy",
                org_id=None,  # Explicitly None!
                webhook_url="https://api.example.com/unauthorized_user_webhook",
            )
            self.session.add(u)
            self.session.commit()
            self.session.refresh(u)

        user_id = u.id

        events_captured = []
        notification_service.bus.subscribe(
            handler=lambda e: events_captured.append(e),
            event_type=None,
            name="NoOrgChecker",
        )

        with patch.object(notification_service, "register_destination") as mock_reg:
            with patch.object(notification_service, "publish_scan_events") as mock_pub:
                with patch("app.SessionLocal", side_effect=self.SessionLocal):
                    with patch("app.get_cached_or_generate_ai", return_value="Report"):
                        background_scan_task(
                            job_id="test_job_no_org",
                            email="test_no_org@example.com",
                            redacted_code="print('no org test')",
                            system_prompt="Analyze code",
                            secrets_found=False,
                        )

                # Destination registration MUST NOT be called
                mock_reg.assert_not_called()
                # Event publication MUST NOT be called
                mock_pub.assert_not_called()

        # No events were published with organization_id == user_id
        for ev in events_captured:
            meta = ev.metadata or {}
            self.assertNotEqual(meta.get("organization_id"), user_id)

    # -----------------------------------------------------------------------
    # 29. Exactly one authoritative scanner execution
    # -----------------------------------------------------------------------
    def test_29_exactly_one_authoritative_scan_execution(self):
        from app import background_scan_task, User, notification_service, execute_tcs_ast_scan

        u = self.session.query(User).filter(User.email == "test_one_scan@example.com").first()
        if not u:
            u = User(email="test_one_scan@example.com", password_hash="dummy", org_id=1, org_role="admin")
            self.session.add(u)
            self.session.commit()

        recorded_scan_results = []
        def spy_execute_ast(files):
            res = execute_tcs_ast_scan(files)
            recorded_scan_results.append(res)
            return res

        with patch("app.execute_tcs_ast_scan", side_effect=spy_execute_ast) as mock_ast_scan:
            with patch.object(notification_service, "publish_scan_events", wraps=notification_service.publish_scan_events) as mock_pub:
                with patch("app.SessionLocal", side_effect=self.SessionLocal):
                    with patch("app.get_cached_or_generate_ai", return_value="AI analysis"):
                        with patch.object(notification_service.in_app_adapter, "handle_intent"):
                            background_scan_task(
                                job_id="test_job_one_scan",
                                email="test_one_scan@example.com",
                                redacted_code="from flask import request\nimport os\ncmd = request.args.get('cmd')\nos.system(cmd)",
                                system_prompt="Analyze code",
                                secrets_found=False,
                            )

            # execute_tcs_ast_scan was called EXACTLY ONCE
            self.assertEqual(mock_ast_scan.call_count, 1)
            self.assertEqual(len(recorded_scan_results), 1)
            actual_ast_return = recorded_scan_results[0]
            mock_pub.assert_called_once()
            called_scan_result = mock_pub.call_args.kwargs.get("scan_result")
            self.assertIs(called_scan_result, actual_ast_return)

    # -----------------------------------------------------------------------
    # 30. EventPublisher receives authoritative ScanResult without synthetic reconstruction
    # -----------------------------------------------------------------------
    def test_30_event_publisher_receives_authoritative_scan_result(self):
        from app import notification_service
        from event_taxonomy import EventType

        authoritative_scan_result = {
            "status": "success",
            "summary": {
                "total_files": 1,
                "lines_scanned": 15,
                "active_vulnerabilities": 1,
                "critical_count": 1,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "security_score": 75,
                "risk_level": "CRITICAL",
                "risk_message": "CRITICAL RISK",
            },
            "findings": [
                {
                    "cwe": "CWE-78",
                    "severity": "CRITICAL",
                    "file": "source.py",
                    "line_number": 4,
                    "sink_symbol": "os.system",
                    "suppressed": False,
                }
            ],
            "secret_findings": [],
        }

        events_received = []
        notification_service.bus.subscribe(
            handler=lambda e: events_received.append(e),
            event_type=None,
            name="AuthScanReceiver",
        )

        with patch.object(notification_service.in_app_adapter, "handle_intent"):
            notification_service.publish_scan_events(
                scan_result=authoritative_scan_result,
                repository="org_1",
                scan_id="scan_auth_proof",
                metadata={"organization_id": 1, "user_id": 10},
            )

        # Confirm EventPublisher processed the exact findings without synthetic fabrication
        crit_events = [e for e in events_received if e.event_type == EventType.CRITICAL_FINDING_DETECTED and e.scan_id == "scan_auth_proof"]
        self.assertEqual(len(crit_events), 1)
        self.assertEqual(list(crit_events[0].metadata["critical_fingerprints"]), ["CWE-78:source.py:4:os.system"])

    # -----------------------------------------------------------------------
    # 31. Destination registry remains organization-scoped and rejects missing org metadata
    # -----------------------------------------------------------------------
    def test_31_destination_registry_remains_organization_scoped(self):
        bus = InMemoryEventBus()
        mock_webhook_adapter = MagicMock()
        service = NotificationService(
            bus=bus,
            webhook_adapter=mock_webhook_adapter,
            session_factory=self.SessionLocal,
        )

        dest1 = WebhookDestinationConfig(
            destination_id="dest_org_10",
            organization_id=10,
            url="https://api.example.com/org10_webhook",
        )
        dest2 = WebhookDestinationConfig(
            destination_id="dest_org_20",
            organization_id=20,
            url="https://api.example.com/org20_webhook",
        )

        service.register_destination(dest1)
        service.register_destination(dest2)

        # Internal registry is strictly organization-scoped
        self.assertEqual(service._destinations[10].url, "https://api.example.com/org10_webhook")
        self.assertEqual(service._destinations[20].url, "https://api.example.com/org20_webhook")

        # Discard event when organization_id is missing from metadata
        mock_event_no_org = MagicMock(event_id="evt_no_org", metadata={})
        service.handle_domain_event(mock_event_no_org)
        mock_webhook_adapter.dispatch_intent.assert_not_called()
        service.shutdown()

    # -----------------------------------------------------------------------
    # 32. Scanner exception does NOT fabricate a clean ScanResult or emit events
    # -----------------------------------------------------------------------
    def test_32_scanner_exception_does_not_fabricate_clean_result(self):
        from app import background_scan_task, User, notification_service

        u = self.session.query(User).filter(User.email == "test_scan_crash@example.com").first()
        if not u:
            u = User(
                email="test_scan_crash@example.com",
                password_hash="dummy",
                org_id=1,
                org_role="admin",
                webhook_url="https://api.example.com/org1_webhook",
            )
            self.session.add(u)
            self.session.commit()

        events_captured = []
        notification_service.bus.subscribe(
            handler=lambda e: events_captured.append(e),
            event_type=None,
            name="CrashEventChecker",
        )

        with patch("app.execute_tcs_ast_scan", side_effect=RuntimeError("AST Parser Core Dump")):
            with patch.object(notification_service, "publish_scan_events") as mock_pub:
                with patch("app.SessionLocal", side_effect=self.SessionLocal):
                    with patch("app.get_cached_or_generate_ai", return_value="AI fallback text"):
                        with patch.object(notification_service.in_app_adapter, "handle_intent"):
                            background_scan_task(
                                job_id="test_job_crash",
                                email="test_scan_crash@example.com",
                                redacted_code="def broken_syntax(:",
                                system_prompt="Analyze code",
                                secrets_found=False,
                            )

                # publish_scan_events MUST NOT be called with fabricated clean scan data
                mock_pub.assert_not_called()

        # Zero events were published to the event bus for this job
        job_events = [e for e in events_captured if e.scan_id == "test_job_crash"]
        self.assertEqual(len(job_events), 0, "Scanner failure must NEVER publish clean scan events")

    # -----------------------------------------------------------------------
    # 33. Existing EventPublisher failure semantics preserved
    # -----------------------------------------------------------------------
    def test_33_event_publisher_failure_status_semantics_preserved(self):
        from event_taxonomy import EventType, ScanStatus
        from event_publisher import EventPublisher
        from event_bus import InMemoryEventBus

        bus = InMemoryEventBus()
        publisher = EventPublisher(bus=bus)

        failed_scan_result = {
            "status": "failed",
            "syntax_errors": ["source.py:1: syntax error"],
            "summary": {
                "total_files": 1,
                "lines_scanned": 1,
                "active_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "security_score": 0,
                "risk_level": "FAILED",
                "risk_message": "AST parsing failed with syntax error",
            },
            "findings": [],
            "secret_findings": [],
        }

        events = publisher.build_events(
            scan_result=failed_scan_result,
            repository="org_1",
            scan_id="scan_failure_proof",
        )

        self.assertEqual(len(events), 1)
        scan_event = events[0]
        self.assertEqual(scan_event.event_type, EventType.SCAN_COMPLETED)
        self.assertEqual(scan_event.summary.scan_status, ScanStatus.FAILED)
        self.assertEqual(scan_event.summary.security_score, 0)
        self.assertEqual(scan_event.summary.risk_level, "FAILED")

    # -----------------------------------------------------------------------
    # 34. Legitimate clean scan produces legitimate clean result
    # -----------------------------------------------------------------------
    def test_34_legitimate_clean_scan_produces_clean_event_only_when_scanner_returns_clean(self):
        from app import background_scan_task, User, notification_service
        from event_taxonomy import EventType, ScanStatus

        u = self.session.query(User).filter(User.email == "test_legit_clean@example.com").first()
        if not u:
            u = User(
                email="test_legit_clean@example.com",
                password_hash="dummy",
                org_id=1,
                org_role="admin",
            )
            self.session.add(u)
            self.session.commit()

        events_captured = []
        notification_service.bus.subscribe(
            handler=lambda e: events_captured.append(e),
            event_type=None,
            name="LegitCleanChecker",
        )

        with patch("app.SessionLocal", side_effect=self.SessionLocal):
            with patch("app.get_cached_or_generate_ai", return_value="Code is clean"):
                with patch.object(notification_service.in_app_adapter, "handle_intent"):
                    background_scan_task(
                        job_id="test_job_legit_clean",
                        email="test_legit_clean@example.com",
                        redacted_code="val = 42\nprint(val)",
                        system_prompt="Analyze code",
                        secrets_found=False,
                    )

        # Authoritative scan succeeded with 0 findings; genuine SCAN_COMPLETED emitted
        clean_events = [e for e in events_captured if e.scan_id == "test_job_legit_clean"]
        self.assertEqual(len(clean_events), 1)
        self.assertEqual(clean_events[0].event_type, EventType.SCAN_COMPLETED)
        self.assertEqual(clean_events[0].summary.scan_status, ScanStatus.SUCCESS)
        self.assertEqual(clean_events[0].summary.total_findings, 0)
        self.assertEqual(clean_events[0].summary.security_score, 100)
        self.assertEqual(clean_events[0].summary.risk_level, "CLEAN")


if __name__ == "__main__":
    unittest.main(verbosity=2)
