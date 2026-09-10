"""
TimeCodeSecurity (TCS) Application-Level Event Publisher.

Translates deterministic scanner output (ScanResult) into typed,
immutable SecurityDomainEvent instances and publishes them to the event bus.

Invariants:
- Never modifies the input ScanResult object.
- Never executes scanned source code or initiates network/database I/O.
- Defensive boundary: known high-risk raw secret patterns are rejected (masked values only).
- Produces deterministic dedupe keys based on semantic scan invariants.
- Supports dependency-injected clock and ID factories for test determinism.

Scan ID Contract:
- scan_id is supplied/owned by the application invocation boundary.
- Retries of the same logical scan MUST reuse the same scan_id.
- Different scan executions MUST receive different scan_id values.
- dedupe_key relies on this identity contract to ensure idempotent retry behavior.
- The event layer never generates a new scan_id automatically for a retry.
"""

from __future__ import annotations

import datetime
import hashlib
import uuid
from typing import Mapping, Any, Optional, List, Tuple, Callable, Dict

from event_taxonomy import (
    SecurityDomainEvent,
    EventType,
    ScanStatus,
    EventSummary,
    compute_dedupe_key,
    freeze_data,
    assert_no_raw_secrets
)
from event_bus import InMemoryEventBus, DispatchResult


class EventPublisher:
    """
    Adapter boundary between security scanner results and the domain event bus.
    """

    def __init__(
        self,
        bus: Optional[InMemoryEventBus] = None,
        id_factory: Optional[Callable[[], str]] = None,
        clock: Optional[Callable[[], str]] = None
    ) -> None:
        self.bus = bus or InMemoryEventBus()
        self.id_factory = id_factory or (lambda: f"evt_{uuid.uuid4().hex}")
        self.clock = clock or (lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def _determine_scan_status(self, scan_result: Mapping[str, Any]) -> ScanStatus:
        """
        Derives terminal scan status strictly from supported ScanResult data.
        """
        raw_status = str(scan_result.get("status", "success")).lower()
        syntax_errors = scan_result.get("syntax_errors")

        if raw_status in ("failed", "error"):
            return ScanStatus.FAILED
        if syntax_errors and len(syntax_errors) > 0:
            return ScanStatus.PARTIAL
        return ScanStatus.SUCCESS

    def _build_event_summary(
        self,
        scan_result: Mapping[str, Any],
        active_findings: List[Mapping[str, Any]],
        critical_findings: List[Mapping[str, Any]],
        high_findings: List[Mapping[str, Any]],
        secret_findings: List[Mapping[str, Any]],
        sca_findings: List[Mapping[str, Any]]
    ) -> EventSummary:
        """
        Constructs a machine-readable, typed EventSummary.
        """
        raw_summary = scan_result.get("summary", {})

        sast_count = int(raw_summary.get("active_vulnerabilities", len(active_findings)))
        sca_count = int(raw_summary.get("sca_vulnerabilities", len(sca_findings)))
        secrets_count = int(raw_summary.get("secrets_detected", len(secret_findings)))
        crit_count = int(raw_summary.get("critical_count", len(critical_findings)))
        high_count = int(raw_summary.get("high_count", len(high_findings)))
        med_count = int(raw_summary.get("medium_count", 0))
        low_count = int(raw_summary.get("low_count", 0))
        sec_score = int(raw_summary.get("security_score", 100))
        risk_lvl = str(raw_summary.get("risk_level", "CLEAN"))
        msg = str(raw_summary.get("risk_message", ""))
        status = self._determine_scan_status(scan_result)

        return EventSummary(
            sast_findings=sast_count,
            sca_findings=sca_count,
            secret_findings=secrets_count,
            total_findings=sast_count + sca_count + secrets_count,
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            security_score=sec_score,
            risk_level=risk_lvl,
            scan_status=status,
            message=msg
        )

    def build_events(
        self,
        scan_result: Mapping[str, Any],
        repository: str,
        scan_id: str,
        metadata: Optional[Mapping[str, Any]] = None,
        policy_thresholds: Optional[Mapping[str, Any]] = None
    ) -> List[SecurityDomainEvent]:
        """
        Translates a ScanResult into a list of typed SecurityDomainEvent objects.
        Does NOT modify the scan_result input.

        Scan ID Contract:
        - scan_id is supplied/owned by the application invocation boundary.
        - Retries of the same logical scan MUST reuse the same scan_id.
        - Different scan executions MUST receive different scan_id values.
        - dedupe_key relies on this identity contract.
        - The event layer never generates a new scan_id automatically for retries.
        """
        if not scan_id or not str(scan_id).strip():
            raise ValueError(
                "Field 'scan_id' must be a non-empty string owned by the caller/invocation boundary."
            )
        effective_scan_id = str(scan_id).strip()

        events: List[SecurityDomainEvent] = []

        # Extract findings without modifying scan_result
        raw_findings = scan_result.get("findings", [])
        active_findings = [f for f in raw_findings if not f.get("suppressed", False)]
        critical_findings = [f for f in active_findings if f.get("severity") == "CRITICAL"]
        high_findings = [f for f in active_findings if f.get("severity") == "HIGH"]
        secret_findings = scan_result.get("secret_findings", [])
        sca_findings = scan_result.get("sca_findings", [])

        # Machine-readable summary
        summary = self._build_event_summary(
            scan_result,
            active_findings,
            critical_findings,
            high_findings,
            secret_findings,
            sca_findings
        )

        high_risk_count = len(critical_findings) + len(high_findings)

        # Base metadata
        base_metadata: Dict[str, Any] = {
            "files_scanned": scan_result.get("summary", {}).get("total_files", 0),
            "lines_scanned": scan_result.get("summary", {}).get("lines_scanned", 0),
            "active_vulnerabilities": summary.sast_findings,
            "suppressed_vulnerabilities": scan_result.get("summary", {}).get("suppressed_vulnerabilities", 0),
            "scan_status": summary.scan_status.value
        }
        if metadata:
            base_metadata.update(dict(metadata))

        # 1. Event: SCAN_COMPLETED (always emitted)
        scan_completed_context = {
            "sast": summary.sast,
            "sca": summary.sca,
            "secrets": summary.secrets,
            "score": summary.security_score,
            "risk_level": summary.risk_level,
            "status": summary.scan_status.value
        }
        dedupe_scan_completed = compute_dedupe_key(
            schema_version=1,
            event_type=EventType.SCAN_COMPLETED,
            repository=repository,
            scan_id=effective_scan_id,
            semantic_context=scan_completed_context
        )
        events.append(
            SecurityDomainEvent(
                schema_version=1,
                event_id=self.id_factory(),
                event_type=EventType.SCAN_COMPLETED,
                timestamp=self.clock(),
                repository=repository,
                scan_id=effective_scan_id,
                summary=summary,
                high_risk_count=high_risk_count,
                metadata=base_metadata,
                dedupe_key=dedupe_scan_completed
            )
        )

        # 2. Event: CRITICAL_FINDING_DETECTED (if active CRITICAL findings exist)
        if critical_findings:
            crit_fingerprints = sorted([
                f"{f.get('cwe')}:{f.get('file')}:{f.get('line_number')}:{f.get('sink_symbol')}"
                for f in critical_findings
            ])
            crit_context = {
                "critical_count": len(critical_findings),
                "findings": crit_fingerprints
            }
            dedupe_critical = compute_dedupe_key(
                schema_version=1,
                event_type=EventType.CRITICAL_FINDING_DETECTED,
                repository=repository,
                scan_id=effective_scan_id,
                semantic_context=crit_context
            )
            crit_meta = dict(base_metadata)
            crit_meta["critical_fingerprints"] = crit_fingerprints
            events.append(
                SecurityDomainEvent(
                    schema_version=1,
                    event_id=self.id_factory(),
                    event_type=EventType.CRITICAL_FINDING_DETECTED,
                    timestamp=self.clock(),
                    repository=repository,
                    scan_id=effective_scan_id,
                    summary=summary,
                    high_risk_count=high_risk_count,
                    metadata=crit_meta,
                    dedupe_key=dedupe_critical
                )
            )

        # 3. Event: SECRETS_LEAK_DETECTED (if secret findings exist)
        if secret_findings:
            sec_fingerprints = sorted([
                f"{sf.get('secret_type')}:{sf.get('file')}:{sf.get('line_number')}:{sf.get('detector')}:{sf.get('masked_value')}"
                for sf in secret_findings
            ])
            sec_context = {
                "secrets_count": len(secret_findings),
                "secrets": sec_fingerprints
            }
            dedupe_secrets = compute_dedupe_key(
                schema_version=1,
                event_type=EventType.SECRETS_LEAK_DETECTED,
                repository=repository,
                scan_id=effective_scan_id,
                semantic_context=sec_context
            )
            sec_meta = dict(base_metadata)
            sec_meta["secret_fingerprints"] = sec_fingerprints
            events.append(
                SecurityDomainEvent(
                    schema_version=1,
                    event_id=self.id_factory(),
                    event_type=EventType.SECRETS_LEAK_DETECTED,
                    timestamp=self.clock(),
                    repository=repository,
                    scan_id=effective_scan_id,
                    summary=summary,
                    high_risk_count=high_risk_count,
                    metadata=sec_meta,
                    dedupe_key=dedupe_secrets
                )
            )

        # 4. Event: POLICY_VIOLATION (if policy thresholds violated)
        if policy_thresholds:
            violations = []
            min_score = policy_thresholds.get("min_security_score")
            if min_score is not None and summary.security_score < int(min_score):
                violations.append(f"Security score {summary.security_score} below minimum allowable {min_score}")

            max_crit = policy_thresholds.get("max_critical")
            if max_crit is not None and summary.critical_count > int(max_crit):
                violations.append(f"Critical count {summary.critical_count} exceeds maximum allowable {max_crit}")

            max_high = policy_thresholds.get("max_high")
            if max_high is not None and summary.high_count > int(max_high):
                violations.append(f"High count {summary.high_count} exceeds maximum allowable {max_high}")

            forbidden_cwes = policy_thresholds.get("forbidden_cwes", [])
            active_cwes = {f.get("cwe") for f in active_findings if f.get("cwe")}
            breached_cwes = sorted(list(set(forbidden_cwes).intersection(active_cwes)))
            if breached_cwes:
                violations.append(f"Forbidden CWE classes detected: {', '.join(breached_cwes)}")

            if violations:
                policy_context = {
                    "violations": sorted(violations),
                    "violation_count": len(violations)
                }
                dedupe_policy = compute_dedupe_key(
                    schema_version=1,
                    event_type=EventType.POLICY_VIOLATION,
                    repository=repository,
                    scan_id=effective_scan_id,
                    semantic_context=policy_context
                )
                pol_meta = dict(base_metadata)
                pol_meta["violations"] = violations
                events.append(
                    SecurityDomainEvent(
                        schema_version=1,
                        event_id=self.id_factory(),
                        event_type=EventType.POLICY_VIOLATION,
                        timestamp=self.clock(),
                        repository=repository,
                        scan_id=effective_scan_id,
                        summary=summary,
                        high_risk_count=high_risk_count,
                        metadata=pol_meta,
                        dedupe_key=dedupe_policy
                    )
                )

        return events

    def publish_scan_events(
        self,
        scan_result: Mapping[str, Any],
        repository: str,
        scan_id: str,
        metadata: Optional[Mapping[str, Any]] = None,
        policy_thresholds: Optional[Mapping[str, Any]] = None
    ) -> List[Tuple[SecurityDomainEvent, List[DispatchResult]]]:
        """
        Builds domain events from scan_result and publishes each synchronously to the bus.
        Returns pairs of (event, dispatch_results).
        Does NOT modify the scan_result input.
        """
        events = self.build_events(
            scan_result=scan_result,
            repository=repository,
            scan_id=scan_id,
            metadata=metadata,
            policy_thresholds=policy_thresholds
        )

        results: List[Tuple[SecurityDomainEvent, List[DispatchResult]]] = []
        for event in events:
            dispatch_results = self.bus.publish(event)
            results.append((event, dispatch_results))

        return results
