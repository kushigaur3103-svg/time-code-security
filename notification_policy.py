"""
TimeCodeSecurity (TCS) Notification Policy & Intent Framework.

Defines:
- PolicyConfig: Immutable tenant-level notification preferences.
- SafeFindingSummary: Bounded, sanitized finding representation (no raw secrets, no source code).
- NotificationIntent: Deterministic operational plan derived from SecurityDomainEvent.
- NotificationPolicy: Pure, side-effect-free evaluator.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from event_taxonomy import EventSummary, EventType, ScanStatus, SecurityDomainEvent
from notification_models import NotificationSeverity, RecipientScope

# Pre-compiled secret patterns for masking in finding summaries
_SECRET_PATTERNS = [
    re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36,}\b|\bgithub_pat_[0-9a-zA-Z_]{80,}\b"),
    re.compile(r"\bsk-[a-zA-Z0-9_-]{20,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
]

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


def mask_secrets_in_text(text: str) -> str:
    """Masks known secret patterns in text with asterisks."""
    if not text:
        return ""
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub("****************", result)
    return result


@dataclass(frozen=True)
class PolicyConfig:
    """
    Immutable configuration defining notification routing and threshold rules.
    Consumed as an explicit input to NotificationPolicy.evaluate().
    """
    organization_id: int
    min_severity_in_app: str = "LOW"
    min_severity_webhook: str = "HIGH"
    notify_on_clean_scans: bool = False
    max_findings_per_webhook: int = 10
    in_app_enabled: bool = True
    webhook_enabled: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.organization_id, int) or self.organization_id <= 0:
            raise ValueError("organization_id must be a positive integer.")
        if self.min_severity_in_app.upper() not in SEVERITY_ORDER:
            raise ValueError(f"Invalid min_severity_in_app: {self.min_severity_in_app}")
        if self.min_severity_webhook.upper() not in SEVERITY_ORDER:
            raise ValueError(f"Invalid min_severity_webhook: {self.min_severity_webhook}")


@dataclass(frozen=True)
class SafeFindingSummary:
    """
    Sanitized, bounded summary of an individual security finding.
    Strictly contains zero source code bodies, zero credentials, and masked secrets.
    """
    rule_id: str         # Bounded <= 64 chars
    cwe: str             # Bounded <= 32 chars
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW, INFO
    file_path: str       # Normalized forward-slash relative path <= 255 chars
    line: Optional[int]  # 1-indexed line number or None
    message: str         # Bounded <= 255 chars, zero raw secrets

    def __post_init__(self) -> None:
        # Enforce bounds
        object.__setattr__(self, "rule_id", str(self.rule_id).strip()[:64])
        object.__setattr__(self, "cwe", str(self.cwe).strip()[:32])
        sev = str(self.severity).upper().strip()
        if sev not in SEVERITY_ORDER:
            sev = "INFO"
        object.__setattr__(self, "severity", sev)
        norm_path = str(self.file_path).replace("\\", "/").strip()[:255]
        object.__setattr__(self, "file_path", norm_path)
        if self.line is not None and not isinstance(self.line, int):
            try:
                object.__setattr__(self, "line", int(self.line))
            except (ValueError, TypeError):
                object.__setattr__(self, "line", None)
        sanitized_msg = mask_secrets_in_text(str(self.message).strip())[:255]
        object.__setattr__(self, "message", sanitized_msg)


@dataclass(frozen=True)
class NotificationIntent:
    """
    Deterministic operational plan produced by NotificationPolicy.
    Adapters consume NotificationIntents to perform transport-specific actions.
    """
    intent_id: str                   # Deterministic identifier
    event_id: str                    # Provenance to SecurityDomainEvent
    scan_id: str                     # Correlated scan identifier
    dedupe_key: str                  # Semantic deduplication key
    notification_type: str           # "SECURITY_ALERT" | "SCAN_SUMMARY" | "SYSTEM"
    severity: str                    # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    recipient_scope: RecipientScope  # USER | ORGANIZATION
    organization_id: int             # Mandatory tenant boundary
    user_id: Optional[int] = None    # User ID if USER scope
    title: str = ""                  # Bounded title (<= 255 chars)
    message: str = ""                # Bounded message (<= 2000 chars)
    link: Optional[str] = None       # Safe relative link (e.g. "/scans/123")
    channel: str = "IN_APP"          # "IN_APP" | "WEBHOOK"
    created_at: str = ""             # ISO-8601 UTC timestamp
    safe_findings: Tuple[SafeFindingSummary, ...] = ()
    findings_truncated: bool = False
    total_findings: int = 0

    def __post_init__(self) -> None:
        if not self.intent_id:
            raise ValueError("intent_id cannot be empty.")
        if not self.event_id:
            raise ValueError("event_id cannot be empty.")
        if not self.scan_id:
            raise ValueError("scan_id cannot be empty.")
        if not self.dedupe_key:
            raise ValueError("dedupe_key cannot be empty.")
        if not isinstance(self.organization_id, int) or self.organization_id <= 0:
            raise ValueError("organization_id must be a positive integer.")
        if len(self.title) > 255:
            object.__setattr__(self, "title", self.title[:255])
        if len(self.message) > 2000:
            object.__setattr__(self, "message", self.message[:2000])


def _extract_and_sort_findings(
    metadata: Mapping[str, Any],
    max_findings: int = 10
) -> Tuple[Tuple[SafeFindingSummary, ...], bool, int]:
    """
    Extracts, sanitizes, and deterministically sorts findings from event metadata.
    Sort order: CRITICAL (5), HIGH (4), MEDIUM (3), LOW (2), INFO (1).
    """
    raw_findings = metadata.get("findings", ())
    if not isinstance(raw_findings, (list, tuple)):
        return (), False, 0

    extracted: List[SafeFindingSummary] = []
    for item in raw_findings:
        if isinstance(item, dict):
            extracted.append(
                SafeFindingSummary(
                    rule_id=str(item.get("rule_id", "UNKNOWN")),
                    cwe=str(item.get("cwe", "CWE-UNKNOWN")),
                    severity=str(item.get("severity", "INFO")),
                    file_path=str(item.get("file_path", "")),
                    line=item.get("line"),
                    message=str(item.get("message", "")),
                )
            )

    total_count = len(extracted)
    # Sort deterministically: severity desc, rule_id asc, file_path asc, line asc
    extracted.sort(
        key=lambda f: (
            -SEVERITY_ORDER.get(f.severity.upper(), 1),
            f.rule_id,
            f.file_path,
            f.line or 0,
        )
    )

    truncated = total_count > max_findings
    bounded_findings = tuple(extracted[:max_findings])
    return bounded_findings, truncated, total_count


class NotificationPolicy:
    """
    Pure policy evaluation engine for Phase 15C.
    Evaluates SecurityDomainEvents against explicit PolicyConfigs.
    Never touches database, network, disk, or global mutable state.
    """

    @staticmethod
    def evaluate(
        event: SecurityDomainEvent,
        config: PolicyConfig
    ) -> Tuple[NotificationIntent, ...]:
        """
        Pure function: produces deterministic NotificationIntents from domain event.
        """
        if not isinstance(event, SecurityDomainEvent):
            raise TypeError(f"Expected SecurityDomainEvent, got {type(event).__name__}")
        if not isinstance(config, PolicyConfig):
            raise TypeError(f"Expected PolicyConfig, got {type(config).__name__}")

        # 1. Determine event severity
        summary = event.summary
        if summary.critical_count > 0:
            event_severity = "CRITICAL"
        elif summary.high_count > 0:
            event_severity = "HIGH"
        elif summary.medium_count > 0:
            event_severity = "MEDIUM"
        elif summary.low_count > 0:
            event_severity = "LOW"
        else:
            event_severity = "INFO"

        event_score = SEVERITY_ORDER.get(event_severity, 1)

        # 2. Check clean scan suppression
        is_clean_scan = summary.total_findings == 0
        if is_clean_scan and not config.notify_on_clean_scans:
            return ()

        # 3. Extract findings
        safe_findings, truncated, total_findings = _extract_and_sort_findings(
            event.metadata,
            max_findings=config.max_findings_per_webhook
        )

        intents: List[NotificationIntent] = []
        created_at_iso = datetime.now(timezone.utc).isoformat()

        # Build notification presentation text
        repo_name = event.repository or "repository"
        if is_clean_scan:
            notif_type = "SCAN_SUMMARY"
            title = f"TCS Scan Passed: {repo_name}"
            msg = f"Security scan completed with 0 findings for {repo_name}."
        else:
            notif_type = "SECURITY_ALERT"
            title = f"TCS Alert: {summary.total_findings} findings in {repo_name}"
            msg = (
                f"Security scan detected {summary.critical_count} critical, {summary.high_count} high, "
                f"and {summary.medium_count} medium findings in {repo_name}."
            )

        safe_link = f"/scans/{event.scan_id}" if event.scan_id else "/scans"

        # 4. Evaluate In-App Channel
        min_in_app_score = SEVERITY_ORDER.get(config.min_severity_in_app.upper(), 1)
        if config.in_app_enabled and event_score >= min_in_app_score:
            in_app_intent_id = hashlib.sha256(
                f"{event.event_id}:IN_APP:{config.organization_id}".encode("utf-8")
            ).hexdigest()[:32]
            intents.append(
                NotificationIntent(
                    intent_id=in_app_intent_id,
                    event_id=event.event_id,
                    scan_id=event.scan_id,
                    dedupe_key=event.dedupe_key,
                    notification_type=notif_type,
                    severity=event_severity,
                    recipient_scope=RecipientScope.ORGANIZATION,
                    organization_id=config.organization_id,
                    user_id=None,
                    title=title,
                    message=msg,
                    link=safe_link,
                    channel="IN_APP",
                    created_at=created_at_iso,
                    safe_findings=safe_findings,
                    findings_truncated=truncated,
                    total_findings=total_findings,
                )
            )

        # 5. Evaluate Webhook Channel
        min_webhook_score = SEVERITY_ORDER.get(config.min_severity_webhook.upper(), 1)
        if config.webhook_enabled and event_score >= min_webhook_score:
            webhook_intent_id = hashlib.sha256(
                f"{event.event_id}:WEBHOOK:{config.organization_id}".encode("utf-8")
            ).hexdigest()[:32]
            intents.append(
                NotificationIntent(
                    intent_id=webhook_intent_id,
                    event_id=event.event_id,
                    scan_id=event.scan_id,
                    dedupe_key=event.dedupe_key,
                    notification_type=notif_type,
                    severity=event_severity,
                    recipient_scope=RecipientScope.ORGANIZATION,
                    organization_id=config.organization_id,
                    user_id=None,
                    title=title,
                    message=msg,
                    link=safe_link,
                    channel="WEBHOOK",
                    created_at=created_at_iso,
                    safe_findings=safe_findings,
                    findings_truncated=truncated,
                    total_findings=total_findings,
                )
            )

        return tuple(intents)
