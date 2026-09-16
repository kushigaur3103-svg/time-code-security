"""
TimeCodeSecurity (TCS) - Vector C SCA Reachability Analysis Contracts.
Defines typed, immutable data models, enums, and serialization contracts.
"""

from __future__ import annotations
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional, Tuple, Dict, Any, List


class ScopeType(str, Enum):
    """Lexical scope hierarchy for Python bindings."""
    MODULE = "MODULE"
    CLASS = "CLASS"
    FUNCTION = "FUNCTION"


class ReachabilityState(str, Enum):
    """Fine-grained atomic evidence states."""
    PACKAGE_VULNERABLE = "PACKAGE_VULNERABLE"
    PACKAGE_NOT_VULNERABLE = "PACKAGE_NOT_VULNERABLE"
    PACKAGE_IMPORT_NOT_FOUND = "PACKAGE_IMPORT_NOT_FOUND"
    PACKAGE_IMPORTED = "PACKAGE_IMPORTED"
    API_REFERENCE_FOUND = "API_REFERENCE_FOUND"
    CALL_REACHABLE = "CALL_REACHABLE"
    CALL_UNREACHABLE = "CALL_UNREACHABLE"
    REACHABILITY_UNRESOLVED = "REACHABILITY_UNRESOLVED"


class ReachabilityClassification(str, Enum):
    """High-level conservative security classification."""
    DEPENDENCY_ACTIVE = "DEPENDENCY_ACTIVE"         # Vulnerable + imported
    DEPENDENCY_DORMANT = "DEPENDENCY_DORMANT"       # Vulnerable + NOT imported in static AST
    REACHABLE_API_USE = "REACHABLE_API_USE"         # Vulnerable + imported + call proven reachable from entrypoint
    REACHABILITY_UNRESOLVED = "REACHABILITY_UNRESOLVED"  # Vulnerable + imported + call path ambiguous/dynamic
    TRANSITIVE_VULNERABLE = "TRANSITIVE_VULNERABLE" # Transitive dependency (unimported directly)
    NOT_VULNERABLE = "NOT_VULNERABLE"               # Advisory proven disjoint from declared version


class AttributionConfidence(str, Enum):
    """Deterministic confidence level for symbol/call attribution."""
    PROVEN_STATIC = "PROVEN_STATIC"   # Full 5-link chain statically proven with definitive evidence
    POSSIBLE = "POSSIBLE"             # Plausible attribution but type inference or dynamic dispatch involved
    UNRESOLVED = "UNRESOLVED"         # Missing import link, cross-scope leakage, or dynamic ungrounded reference


@dataclass(frozen=True)
class ImportRecord:
    """
    Immutable representation of an AST import statement, bound to its exact lexical scope.
    
    Rule P-2 (Wildcard / Star-Import Contract):
    If symbol == "*", any subsequent unresolvable symbol lookup in that scope must strictly
    yield REACHABILITY_UNRESOLVED (reason: "Wildcard import prevents deterministic attribution"),
    and MUST NEVER be silently dropped.
    """
    import_style: str                    # "import" | "from_import" | "from_import_star"
    distribution_name: str               # Normalized distribution name (e.g. "urllib3")
    import_root: str                     # First dotted component of imported namespace (e.g. "urllib3")
    module: str                          # Full imported module path (e.g. "urllib3.poolmanager")
    symbol: Optional[str]                # Imported symbol name (e.g. "PoolManager"), None for bare import, "*" for star-import
    alias: Optional[str]                 # Local binding name (e.g. "u3" or "PoolManager"), None if unaliased
    file: str                            # Source file path
    line: int                            # 1-based start line
    column: int                          # 0-based column offset
    scope_type: ScopeType                # MODULE, CLASS, or FUNCTION
    scope_path: str                      # Deterministic hierarchical path: e.g. "client", "client.make_req"
    parent_scope_path: Optional[str]     # Immediate enclosing scope path, None for MODULE
    mapping_evidence: str                # Evidence level (TARGET_ENVIRONMENT_METADATA, VERIFIED_STATIC_CURATED_MAPPING, etc.)
    environment_scope: str               # "TARGET_ENVIRONMENT" | "STATIC_METADATA" | "SCANNER_ENVIRONMENT" | "NONE"

    @property
    def is_wildcard(self) -> bool:
        """Rule P-2: True if this is a wildcard import (`from module import *`)."""
        return self.symbol == "*" or self.import_style == "from_import_star"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "import_style": self.import_style,
            "distribution_name": self.distribution_name,
            "import_root": self.import_root,
            "module": self.module,
            "symbol": self.symbol,
            "alias": self.alias,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "scope_type": self.scope_type.value,
            "scope_path": self.scope_path,
            "parent_scope_path": self.parent_scope_path,
            "mapping_evidence": self.mapping_evidence,
            "environment_scope": self.environment_scope,
            "is_wildcard": self.is_wildcard,
        }


@dataclass(frozen=True)
class LocalAssignmentBinding:
    """
    Rule P-3: Tracks local variable instance assignments to maintain symbol attribution
    back to an imported class or constructor.
    Example: `manager = urllib3.PoolManager(); manager.request(...)`
    """
    variable_name: str                   # Local variable name (e.g. "manager")
    scope_path: str                      # Scope path where assignment occurred (e.g. "client.fetch")
    source_expression: str               # Expression string (e.g. "urllib3.PoolManager()")
    attributed_type: str                 # Inferred dotted type (e.g. "urllib3.PoolManager")
    attributed_import: Optional[ImportRecord] # Grounding import record
    file: str
    line: int
    column: int
    confidence: AttributionConfidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "variable_name": self.variable_name,
            "scope_path": self.scope_path,
            "source_expression": self.source_expression,
            "attributed_type": self.attributed_type,
            "attributed_import": self.attributed_import.to_dict() if self.attributed_import else None,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "confidence": self.confidence.value,
        }


@dataclass(frozen=True)
class CallRecord:
    """Represents a concrete AST call expression evaluated for dependency reachability."""
    caller_scope: str                    # Scope path of caller (e.g. "app.make_req")
    callee_expr: str                     # Raw expression (e.g. "u3.PoolManager().request")
    attributed_import: Optional[ImportRecord]  # Grounding import record
    target_symbol: str                   # Resolved symbol (e.g. "PoolManager.request")
    call_path: Tuple[str, ...]           # Call graph hops from entrypoint (e.g. ("main", "make_req", "request"))
    file: str
    line: int
    column: int
    attribution_confidence: AttributionConfidence
    is_dynamic: bool                     # True if getattr / __import__ / reflection

    def to_dict(self) -> Dict[str, Any]:
        return {
            "caller_scope": self.caller_scope,
            "callee_expr": self.callee_expr,
            "attributed_import": self.attributed_import.to_dict() if self.attributed_import else None,
            "target_symbol": self.target_symbol,
            "call_path": list(self.call_path),
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "attribution_confidence": self.attribution_confidence.value,
            "is_dynamic": self.is_dynamic,
        }


@dataclass(frozen=True)
class ImportDistributionResult:
    """Reverse lookup result: maps import namespace root to distribution package name(s)."""
    import_root: str
    distribution_names: Tuple[str, ...]   # Tuple because 1 import root can map to multiple distributions
    evidence_source: str                 # Evidence hierarchy level
    environment_scope: str               # "TARGET_ENVIRONMENT" | "STATIC_METADATA" | "SCANNER_ENVIRONMENT" | "NONE"
    is_definitive: bool                  # False if heuristic, scanner-only, or ambiguous
    limitations: Tuple[str, ...] = ()

    @property
    def is_unique(self) -> bool:
        """True if exactly one distribution was identified."""
        return len(self.distribution_names) == 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "import_root": self.import_root,
            "distribution_names": list(self.distribution_names),
            "evidence_source": self.evidence_source,
            "environment_scope": self.environment_scope,
            "is_definitive": self.is_definitive,
            "is_unique": self.is_unique,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class ImportNamespaceResult:
    """Forward lookup result: maps distribution package name to import namespace root(s)."""
    distribution_name: str
    import_roots: Tuple[str, ...]
    evidence_source: str
    environment_scope: str
    is_definitive: bool
    limitations: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "distribution_name": self.distribution_name,
            "import_roots": list(self.import_roots),
            "evidence_source": self.evidence_source,
            "environment_scope": self.environment_scope,
            "is_definitive": self.is_definitive,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class VectorCFinding:
    """
    Unified Evidence Object for Vector C SCA Reachability Analysis.
    Combines advisory affectedness with deterministic AST reachability proofs.
    """
    # 1. Advisory Grounding (from OSV via version_matcher)
    advisory_id: str
    advisory_aliases: Tuple[str, ...] = ()
    advisory_summary: str = ""
    package_name: str = ""
    declared_version: Optional[str] = None
    version_specifier: Optional[str] = None
    affected_status: str = "CONFIRMED"     # CONFIRMED | POTENTIAL | UNRESOLVED
    affected_confidence: float = 1.0

    # 2. Import Grounding
    import_status: ReachabilityState = ReachabilityState.PACKAGE_IMPORT_NOT_FOUND
    import_evidence: Optional[ImportRecord] = None
    import_evidence_source: str = "UNRESOLVED"
    environment_scope: str = "NONE"

    # 3. Call Grounding
    api_status: ReachabilityState = ReachabilityState.REACHABILITY_UNRESOLVED
    call_evidence: Optional[CallRecord] = None

    # 4. Reachability & Call Graph
    call_status: ReachabilityState = ReachabilityState.REACHABILITY_UNRESOLVED
    call_path: Tuple[str, ...] = ()
    call_depth: int = 0
    edge_type: str = "UNRESOLVED_EDGE"

    # 5. Final Classification & Advisory Severity
    reachability_classification: ReachabilityClassification = ReachabilityClassification.REACHABILITY_UNRESOLVED
    is_transitive: bool = False
    severity: str = "UNKNOWN"
    cvss_score: Optional[float] = None
    manifest_source: str = ""
    manifest_line: Optional[int] = None

    # 6. Audit & Limitations
    limitations: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "advisory_id": self.advisory_id,
            "advisory_aliases": list(self.advisory_aliases),
            "advisory_summary": self.advisory_summary,
            "package_name": self.package_name,
            "declared_version": self.declared_version,
            "version_specifier": self.version_specifier,
            "affected_status": self.affected_status,
            "affected_confidence": self.affected_confidence,
            "import_status": self.import_status.value if isinstance(self.import_status, ReachabilityState) else str(self.import_status),
            "import_evidence": self.import_evidence.to_dict() if self.import_evidence else None,
            "import_evidence_source": self.import_evidence_source,
            "environment_scope": self.environment_scope,
            "api_status": self.api_status.value if isinstance(self.api_status, ReachabilityState) else str(self.api_status),
            "call_evidence": self.call_evidence.to_dict() if self.call_evidence else None,
            "call_status": self.call_status.value if isinstance(self.call_status, ReachabilityState) else str(self.call_status),
            "call_path": list(self.call_path),
            "call_depth": self.call_depth,
            "edge_type": self.edge_type,
            "reachability_classification": self.reachability_classification.value if isinstance(self.reachability_classification, ReachabilityClassification) else str(self.reachability_classification),
            "is_transitive": self.is_transitive,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "manifest_source": self.manifest_source,
            "manifest_line": self.manifest_line,
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> VectorCFinding:
        """Reconstitutes a typed VectorCFinding from a serialized dictionary."""
        import_status_val = d.get("import_status", ReachabilityState.PACKAGE_IMPORT_NOT_FOUND.value)
        if isinstance(import_status_val, str):
            import_status_val = ReachabilityState(import_status_val)

        api_status_val = d.get("api_status", ReachabilityState.REACHABILITY_UNRESOLVED.value)
        if isinstance(api_status_val, str):
            api_status_val = ReachabilityState(api_status_val)

        call_status_val = d.get("call_status", ReachabilityState.REACHABILITY_UNRESOLVED.value)
        if isinstance(call_status_val, str):
            call_status_val = ReachabilityState(call_status_val)

        class_val = d.get("reachability_classification", ReachabilityClassification.REACHABILITY_UNRESOLVED.value)
        if isinstance(class_val, str):
            class_val = ReachabilityClassification(class_val)

        import_ev = None
        if d.get("import_evidence"):
            ie_d = d["import_evidence"]
            scope_t = ie_d.get("scope_type", ScopeType.MODULE.value)
            if isinstance(scope_t, str):
                scope_t = ScopeType(scope_t)
            import_ev = ImportRecord(
                import_style=ie_d.get("import_style", "import"),
                distribution_name=ie_d.get("distribution_name", ""),
                import_root=ie_d.get("import_root", ""),
                module=ie_d.get("module", ""),
                symbol=ie_d.get("symbol"),
                alias=ie_d.get("alias"),
                file=ie_d.get("file", ""),
                line=ie_d.get("line", 1),
                column=ie_d.get("column", 0),
                scope_type=scope_t,
                scope_path=ie_d.get("scope_path", ""),
                parent_scope_path=ie_d.get("parent_scope_path"),
                mapping_evidence=ie_d.get("mapping_evidence", "UNRESOLVED"),
                environment_scope=ie_d.get("environment_scope", "NONE"),
            )

        call_ev = None
        if d.get("call_evidence"):
            ce_d = d["call_evidence"]
            conf = ce_d.get("attribution_confidence", AttributionConfidence.UNRESOLVED.value)
            if isinstance(conf, str):
                conf = AttributionConfidence(conf)
            call_ev = CallRecord(
                caller_scope=ce_d.get("caller_scope", ""),
                callee_expr=ce_d.get("callee_expr", ""),
                attributed_import=import_ev,
                target_symbol=ce_d.get("target_symbol", ""),
                call_path=tuple(ce_d.get("call_path", ())),
                file=ce_d.get("file", ""),
                line=ce_d.get("line", 1),
                column=ce_d.get("column", 0),
                attribution_confidence=conf,
                is_dynamic=ce_d.get("is_dynamic", False),
            )

        return cls(
            advisory_id=d.get("advisory_id", ""),
            advisory_aliases=tuple(d.get("advisory_aliases", ())),
            advisory_summary=d.get("advisory_summary", ""),
            package_name=d.get("package_name", ""),
            declared_version=d.get("declared_version"),
            version_specifier=d.get("version_specifier"),
            affected_status=d.get("affected_status", "CONFIRMED"),
            affected_confidence=float(d.get("affected_confidence", 1.0)),
            import_status=import_status_val,
            import_evidence=import_ev,
            import_evidence_source=d.get("import_evidence_source", "UNRESOLVED"),
            environment_scope=d.get("environment_scope", "NONE"),
            api_status=api_status_val,
            call_evidence=call_ev,
            call_status=call_status_val,
            call_path=tuple(d.get("call_path", ())),
            call_depth=int(d.get("call_depth", 0)),
            edge_type=d.get("edge_type", "UNRESOLVED_EDGE"),
            reachability_classification=class_val,
            is_transitive=bool(d.get("is_transitive", False)),
            severity=d.get("severity", "UNKNOWN"),
            cvss_score=float(d["cvss_score"]) if d.get("cvss_score") is not None else None,
            manifest_source=d.get("manifest_source", ""),
            manifest_line=d.get("manifest_line"),
            limitations=tuple(d.get("limitations", ())),
        )
