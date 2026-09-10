"""
TimeCodeSecurity (TCS) Domain Event Taxonomy & Immutability Framework.

Defines the immutable SecurityDomainEvent, EventType, EventSummary,
and canonical deduplication key generation for Phase 15A.

Invariants:
- Defensive boundary: Known high-risk raw secret patterns are rejected before event construction.
  (This defensive check does not replace the dedicated secret scanner engine).
- True immutability via frozen dataclasses, recursive container freezing, and strict type enforcement.
- Unsupported object types in metadata are deterministically rejected with TypeError.
- Machine-readable EventSummary with typed counts (sast, sca, secrets, etc.).
- Deterministic deduplication key independent of event_id and timestamp.
"""

from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Optional, Union, Dict, Tuple, Set, List


class EventType(str, Enum):
    """Approved Phase 15A security domain event types."""
    SCAN_COMPLETED = "SCAN_COMPLETED"
    CRITICAL_FINDING_DETECTED = "CRITICAL_FINDING_DETECTED"
    SECRETS_LEAK_DETECTED = "SECRETS_LEAK_DETECTED"
    POLICY_VIOLATION = "POLICY_VIOLATION"


class ScanStatus(str, Enum):
    """Terminal scan status classifications."""
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


def freeze_data(val: Any) -> Any:
    """
    Recursively transforms supported data structures into immutable proxies/tuples.

    Supported immutable primitives:
    - None
    - bool
    - int
    - float
    - str
    - bytes

    Supported containers:
    - dict
    - list
    - tuple
    - set
    - frozenset
    - MappingProxyType

    For unsupported object types:
    REJECT deterministically with TypeError.
    """
    if val is None:
        return None
    # Note: bool is a subclass of int in Python, so bool is covered
    if isinstance(val, (bool, int, float, str, bytes)):
        return val
    if isinstance(val, MappingProxyType):
        # Validate that existing mappingproxy contents are also deeply frozen
        frozen_dict = {str(k): freeze_data(v) for k, v in val.items()}
        return MappingProxyType(frozen_dict)
    if isinstance(val, frozenset):
        return frozenset(freeze_data(item) for item in val)
    if isinstance(val, dict):
        frozen_dict = {str(k): freeze_data(v) for k, v in val.items()}
        return MappingProxyType(frozen_dict)
    if isinstance(val, (list, tuple)):
        return tuple(freeze_data(item) for item in val)
    if isinstance(val, set):
        return frozenset(freeze_data(item) for item in val)

    raise TypeError(
        f"Unsupported metadata type '{type(val).__name__}'. "
        "SecurityDomainEvent metadata strictly supports immutable primitives (None, bool, int, float, str, bytes) "
        "and standard containers (dict, list, tuple, set, frozenset, MappingProxyType)."
    )


# Pattern for detecting known high-risk raw secret patterns during event construction
_KNOWN_SECRET_PATTERNS = [
    re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
]


def assert_no_raw_secrets(data: Any, path: str = "root") -> None:
    """
    Defensive check: Known high-risk raw secret patterns are rejected before event construction.
    (Does not duplicate or replace the dedicated secret scanner engine).
    """
    if isinstance(data, str):
        for pattern in _KNOWN_SECRET_PATTERNS:
            if pattern.search(data):
                raise ValueError(
                    f"Security policy violation: Known high-risk raw secret pattern detected at '{path}'. "
                    "Secrets must be masked (e.g. 'AKIA****************') before constructing domain events."
                )
    elif isinstance(data, (dict, Mapping, MappingProxyType)):
        for k, v in data.items():
            assert_no_raw_secrets(v, f"{path}.{k}")
    elif isinstance(data, (list, tuple, set, frozenset)):
        for idx, item in enumerate(data):
            assert_no_raw_secrets(item, f"{path}[{idx}]")


@dataclass(frozen=True)
class EventSummary:
    """
    Typed, immutable, machine-readable scan summary.
    Allows policy engines and subscribers to evaluate metrics directly
    without parsing human presentation strings.
    """
    sast_findings: int = 0
    sca_findings: int = 0
    secret_findings: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    security_score: int = 100
    risk_level: str = "CLEAN"
    scan_status: ScanStatus = ScanStatus.SUCCESS
    message: str = ""

    @property
    def sast(self) -> int:
        return self.sast_findings

    @property
    def sca(self) -> int:
        return self.sca_findings

    @property
    def secrets(self) -> int:
        return self.secret_findings

    def __getitem__(self, key: str) -> Any:
        if key == "sast":
            return self.sast_findings
        if key == "sca":
            return self.sca_findings
        if key == "secrets":
            return self.secret_findings
        if hasattr(self, key):
            val = getattr(self, key)
            if isinstance(val, ScanStatus):
                return val.value
            return val
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sast_findings": self.sast_findings,
            "sca_findings": self.sca_findings,
            "secret_findings": self.secret_findings,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "security_score": self.security_score,
            "risk_level": self.risk_level,
            "scan_status": self.scan_status.value if isinstance(self.scan_status, ScanStatus) else str(self.scan_status),
            "message": self.message,
        }


def compute_dedupe_key(
    schema_version: int,
    event_type: Union[EventType, str],
    repository: str,
    scan_id: str,
    semantic_context: Optional[Mapping[str, Any]] = None
) -> str:
    """
    Computes a deterministic SHA-256 deduplication key over canonical JSON.

    Canonical Payload:
    {
        "event_type": str,
        "repository": str,
        "scan_id": str,
        "schema_version": int,
        "semantic_context": dict
    }

    Non-deterministic fields (event_id, timestamp) are strictly excluded.
    Canonical JSON enforces sorted keys and minimal separators for determinism.
    """
    evt_type_str = event_type.value if isinstance(event_type, EventType) else str(event_type)
    canonical_dict = {
        "event_type": evt_type_str,
        "repository": str(repository).strip(),
        "scan_id": str(scan_id).strip(),
        "schema_version": int(schema_version),
        "semantic_context": dict(semantic_context) if semantic_context else {}
    }
    canonical_bytes = json.dumps(
        canonical_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclass(frozen=True)
class SecurityDomainEvent:
    """
    Immutable security domain event.

    Strict invariants:
    - schema_version == 1
    - event_type in EventType
    - summary is an immutable EventSummary
    - metadata is deeply frozen (MappingProxyType) and rejects unsupported mutable types
    - dedupe_key is deterministic and excludes event_id and timestamp
    """
    schema_version: int
    event_id: str
    event_type: EventType
    timestamp: str
    repository: str
    scan_id: str
    summary: EventSummary
    high_risk_count: int
    metadata: Mapping[str, Any]
    dedupe_key: str

    def __post_init__(self) -> None:
        # 1. Validate schema_version
        if not isinstance(self.schema_version, int) or self.schema_version != 1:
            raise ValueError(f"Unsupported schema_version: {self.schema_version}. Expected 1.")

        # 2. Validate event_type
        if not isinstance(self.event_type, EventType):
            if isinstance(self.event_type, str):
                try:
                    et = EventType(self.event_type)
                    object.__setattr__(self, "event_type", et)
                except ValueError:
                    raise ValueError(f"Invalid event_type: '{self.event_type}'. Must be one of {[e.value for e in EventType]}.")
            else:
                raise ValueError(f"Invalid event_type: {self.event_type}. Expected EventType enum.")

        # 3. Validate strings
        for field_name in ["event_id", "timestamp", "repository", "scan_id"]:
            val = getattr(self, field_name)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"Field '{field_name}' must be a non-empty string.")

        # 4. Validate summary
        if not isinstance(self.summary, EventSummary):
            if isinstance(self.summary, Mapping):
                s_dict = dict(self.summary)
                status_raw = s_dict.get("scan_status", ScanStatus.SUCCESS)
                status_enum = ScanStatus(status_raw) if not isinstance(status_raw, ScanStatus) else status_raw
                s_obj = EventSummary(
                    sast_findings=int(s_dict.get("sast_findings", s_dict.get("sast", 0))),
                    sca_findings=int(s_dict.get("sca_findings", s_dict.get("sca", 0))),
                    secret_findings=int(s_dict.get("secret_findings", s_dict.get("secrets", 0))),
                    total_findings=int(s_dict.get("total_findings", 0)),
                    critical_count=int(s_dict.get("critical_count", 0)),
                    high_count=int(s_dict.get("high_count", 0)),
                    medium_count=int(s_dict.get("medium_count", 0)),
                    low_count=int(s_dict.get("low_count", 0)),
                    security_score=int(s_dict.get("security_score", 100)),
                    risk_level=str(s_dict.get("risk_level", "CLEAN")),
                    scan_status=status_enum,
                    message=str(s_dict.get("message", "")),
                )
                object.__setattr__(self, "summary", s_obj)
            else:
                raise ValueError(f"Field 'summary' must be an EventSummary instance, got {type(self.summary).__name__}.")

        # 5. Validate high_risk_count
        if not isinstance(self.high_risk_count, int) or self.high_risk_count < 0:
            raise ValueError(f"Field 'high_risk_count' must be a non-negative integer, got {self.high_risk_count}.")

        # 6. Deeply freeze metadata (rejects unsupported object types)
        frozen_meta = freeze_data(self.metadata if self.metadata is not None else {})
        if not isinstance(frozen_meta, MappingProxyType):
            frozen_meta = MappingProxyType(dict(frozen_meta) if isinstance(frozen_meta, Mapping) else {})
        object.__setattr__(self, "metadata", frozen_meta)

        # 7. Defensive check: known high-risk raw secret patterns are rejected
        assert_no_raw_secrets(self.summary.to_dict(), "summary")
        assert_no_raw_secrets(dict(self.metadata), "metadata")

        # 8. Validate dedupe_key
        if not isinstance(self.dedupe_key, str) or len(self.dedupe_key) != 64:
            raise ValueError(f"Invalid dedupe_key: '{self.dedupe_key}'. Expected a 64-character SHA-256 hex digest.")
