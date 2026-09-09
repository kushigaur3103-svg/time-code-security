"""
TimeCodeSecurity (TCS) Version Matcher & SCA Findings Engine.
Deterministically evaluates dependency records against OSV vulnerability advisories
using PEP 440 semantics and emits structured SCA findings.

Includes a sound Tri-State overlap classifier (PROVEN_OVERLAP, PROVEN_DISJOINT, UNRESOLVED).
Performs zero network I/O; operates 100% offline.
"""

from __future__ import annotations
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any, Sequence

from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier

from manifest_parser import DependencyRecord, normalize_package_name
from osv_client import OSVVulnerability, OSVAffectedRange, OSVQueryResult

# Allowed finding status values
STATUS_CONFIRMED = "CONFIRMED"
STATUS_POTENTIAL = "POTENTIAL"
STATUS_UNRESOLVED = "UNRESOLVED"

# Allowed severity values
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_UNKNOWN = "UNKNOWN"


class OverlapState(Enum):
    """Tri-state range intersection evaluation result."""
    PROVEN_OVERLAP = "PROVEN_OVERLAP"
    PROVEN_DISJOINT = "PROVEN_DISJOINT"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class SCAFinding:
    """
    Typed, immutable representation of a Software Composition Analysis (SCA) finding.
    """
    package_name: str
    installed_version: Optional[str]
    requested_specifier: Optional[str]

    vulnerability_id: str
    aliases: List[str]

    severity: str
    cvss_score: Optional[float]

    summary: str
    fixed_version: Optional[str]
    matched_range: str

    confidence: float
    status: str

    manifest_source: str
    line_number: Optional[int]

    @property
    def is_confirmed(self) -> bool:
        return self.status == STATUS_CONFIRMED

    @property
    def is_potential(self) -> bool:
        return self.status == STATUS_POTENTIAL

    @property
    def is_unresolved(self) -> bool:
        return self.status == STATUS_UNRESOLVED

    def to_dict(self) -> Dict[str, Any]:
        """Serializes finding into a plain JSON-compatible dictionary."""
        return {
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "requested_specifier": self.requested_specifier,
            "vulnerability_id": self.vulnerability_id,
            "aliases": list(self.aliases),
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "summary": self.summary,
            "fixed_version": self.fixed_version,
            "matched_range": self.matched_range,
            "confidence": self.confidence,
            "status": self.status,
            "manifest_source": self.manifest_source,
            "line_number": self.line_number,
        }


def extract_severity_and_score(vuln: OSVVulnerability) -> Tuple[str, Optional[float]]:
    """
    Extracts normalized severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN) and
    optional numeric CVSS score directly from OSV payload fields.
    Does not calculate CVSS metrics from vector strings.
    """
    cvss_score: Optional[float] = None
    severity_str: Optional[str] = None

    # 1. Inspect vuln.severity array for explicit numeric score
    for item in vuln.severity:
        if isinstance(item, dict):
            raw_score = item.get("score")
            if isinstance(raw_score, (int, float)):
                cvss_score = float(raw_score)
                break
            elif isinstance(raw_score, str):
                try:
                    cvss_score = float(raw_score)
                    break
                except ValueError:
                    # Raw vector string; preserved in payload, do not compute custom arithmetic
                    pass

    # 2. Check database_specific for cvss score if not yet found
    db_spec = vuln.database_specific or {}
    if cvss_score is None:
        cvss_obj = db_spec.get("cvss")
        if isinstance(cvss_obj, dict):
            score_val = cvss_obj.get("score")
            if isinstance(score_val, (int, float)):
                cvss_score = float(score_val)
        elif isinstance(db_spec.get("cvss_score"), (int, float)):
            cvss_score = float(db_spec["cvss_score"])

    # 3. Derive severity tier: first check database_specific.severity
    raw_sev = str(db_spec.get("severity", "")).upper()
    if raw_sev == "CRITICAL":
        severity_str = SEVERITY_CRITICAL
    elif raw_sev == "HIGH":
        severity_str = SEVERITY_HIGH
    elif raw_sev in ("MODERATE", "MEDIUM"):
        severity_str = SEVERITY_MEDIUM
    elif raw_sev == "LOW":
        severity_str = SEVERITY_LOW

    # 4. If severity not provided directly, derive from numeric cvss_score if available
    if not severity_str and cvss_score is not None:
        if cvss_score >= 9.0:
            severity_str = SEVERITY_CRITICAL
        elif cvss_score >= 7.0:
            severity_str = SEVERITY_HIGH
        elif cvss_score >= 4.0:
            severity_str = SEVERITY_MEDIUM
        elif cvss_score > 0.0:
            severity_str = SEVERITY_LOW
        else:
            severity_str = SEVERITY_UNKNOWN

    if not severity_str:
        severity_str = SEVERITY_UNKNOWN

    return severity_str, cvss_score


def extract_intervals_from_events(events: Sequence[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    Groups ordered OSV events into distinct intervals.
    Handles pairs of introduced -> fixed / last_affected, as well as open bounds.
    """
    intervals: List[Dict[str, str]] = []
    current: Dict[str, str] = {}

    for ev in events:
        if not isinstance(ev, dict):
            continue
        if "introduced" in ev:
            if "introduced" in current:
                intervals.append(current)
                current = {}
            current["introduced"] = str(ev["introduced"]).strip()
        elif "fixed" in ev:
            current["fixed"] = str(ev["fixed"]).strip()
            intervals.append(current)
            current = {}
        elif "last_affected" in ev:
            current["last_affected"] = str(ev["last_affected"]).strip()
            intervals.append(current)
            current = {}
        elif "limit" in ev:
            current["limit"] = str(ev["limit"]).strip()
            intervals.append(current)
            current = {}

    if current:
        intervals.append(current)

    return intervals


def _format_interval_range(interval: Dict[str, str]) -> str:
    """Formats an interval dict into a readable range string."""
    intro = interval.get("introduced")
    fixed = interval.get("fixed")
    last_aff = interval.get("last_affected")

    parts = []
    if intro is not None:
        parts.append(f">={intro}")
    if fixed is not None:
        parts.append(f"<{fixed}")
    if last_aff is not None:
        parts.append(f"<={last_aff}")

    return ", ".join(parts) if parts else "any"


def _safe_parse_version(v_str: str) -> Optional[Version]:
    """Safely parses a version string with PEP 440, returning None on invalid format."""
    if not v_str or not isinstance(v_str, str):
        return None
    try:
        return Version(v_str.strip())
    except (InvalidVersion, TypeError):
        return None


def _is_version_in_interval(v: Version, interval: Dict[str, str]) -> bool:
    """Checks if a concrete Version falls inside an OSV event interval."""
    intro_str = interval.get("introduced")
    if intro_str:
        intro_v = _safe_parse_version(intro_str)
        if intro_v is not None and v < intro_v:
            return False

    fixed_str = interval.get("fixed")
    if fixed_str:
        fixed_v = _safe_parse_version(fixed_str)
        if fixed_v is not None and v >= fixed_v:
            return False

    last_aff_str = interval.get("last_affected")
    if last_aff_str:
        last_aff_v = _safe_parse_version(last_aff_str)
        if last_aff_v is not None and v > last_aff_v:
            return False

    limit_str = interval.get("limit")
    if limit_str:
        limit_v = _safe_parse_version(limit_str)
        if limit_v is not None and v >= limit_v:
            return False

    return True


def _get_specifier_outer_bounds(
    spec_set: SpecifierSet
) -> Tuple[Optional[Tuple[Version, bool]], Optional[Tuple[Version, bool]]]:
    """
    Computes effective outer bounds (lower_bound, upper_bound) from a SpecifierSet.
    Returns:
      lower: (Version, is_inclusive) or None
      upper: (Version, is_inclusive) or None
    """
    lower: Optional[Tuple[Version, bool]] = None
    upper: Optional[Tuple[Version, bool]] = None

    for spec in spec_set:
        op = spec.operator
        ver_str = spec.version

        if op == ">=":
            v = _safe_parse_version(ver_str)
            if v is not None:
                if lower is None or v > lower[0] or (v == lower[0] and not lower[1]):
                    lower = (v, True)
        elif op == ">":
            v = _safe_parse_version(ver_str)
            if v is not None:
                if lower is None or v >= lower[0]:
                    lower = (v, False)
        elif op == "<=":
            v = _safe_parse_version(ver_str)
            if v is not None:
                if upper is None or v < upper[0] or (v == upper[0] and not upper[1]):
                    upper = (v, True)
        elif op == "<":
            v = _safe_parse_version(ver_str)
            if v is not None:
                if upper is None or v <= upper[0]:
                    upper = (v, False)
        elif op == "==":
            if ver_str.endswith(".*"):
                prefix = ver_str[:-2].strip()
                v_low = _safe_parse_version(prefix)
                if v_low is not None:
                    if lower is None or v_low > lower[0]:
                        lower = (v_low, True)
                parts = [int(p) for p in prefix.split(".") if p.isdigit()]
                if parts:
                    parts[-1] += 1
                    v_high = _safe_parse_version(".".join(str(p) for p in parts))
                    if v_high is not None:
                        if upper is None or v_high < upper[0] or (v_high == upper[0] and upper[1]):
                            upper = (v_high, False)
            else:
                v = _safe_parse_version(ver_str)
                if v is not None:
                    if lower is None or v > lower[0]:
                        lower = (v, True)
                    if upper is None or v < upper[0]:
                        upper = (v, True)
        elif op == "~=":
            v = _safe_parse_version(ver_str)
            if v is not None:
                if lower is None or v > lower[0]:
                    lower = (v, True)
                parts = [int(p) for p in ver_str.split(".") if p.isdigit()]
                if len(parts) >= 2:
                    prefix = parts[:-1]
                    prefix[-1] += 1
                    v_high = _safe_parse_version(".".join(str(p) for p in prefix))
                    if v_high is not None:
                        if upper is None or v_high < upper[0] or (v_high == upper[0] and upper[1]):
                            upper = (v_high, False)

    return lower, upper


def classify_interval_overlap(
    spec_set: SpecifierSet,
    interval: Dict[str, str],
    explicit_versions: Sequence[str]
) -> Tuple[OverlapState, Optional[str]]:
    """
    Tri-State overlap classifier.
    Returns (PROVEN_OVERLAP | PROVEN_DISJOINT | UNRESOLVED, matched_range_desc).
    """
    intro_str = interval.get("introduced")
    fixed_str = interval.get("fixed")
    last_aff_str = interval.get("last_affected")
    limit_str = interval.get("limit")

    intro_v = _safe_parse_version(intro_str) if intro_str else None
    fixed_v = _safe_parse_version(fixed_str) if fixed_str else None
    last_aff_v = _safe_parse_version(last_aff_str) if last_aff_str else None
    limit_v = _safe_parse_version(limit_str) if limit_str else None

    # If interval has specified bounds that failed to parse into PEP 440:
    if (intro_str and intro_v is None) or (fixed_str and fixed_v is None) or \
       (last_aff_str and last_aff_v is None) or (limit_str and limit_v is None):
        return OverlapState.UNRESOLVED, None

    # Check for unsupported or ambiguous specifier operators (e.g. ===)
    for spec in spec_set:
        if spec.operator == "===":
            return OverlapState.UNRESOLVED, None
        if not spec.version.endswith(".*") and _safe_parse_version(spec.version) is None:
            return OverlapState.UNRESOLVED, None

    # Derive outer bounds of the requested specifier set
    lower_bound, upper_bound = _get_specifier_outer_bounds(spec_set)

    # Check if spec_set is internally unsatisfiable (e.g. >=2.0,<1.0)
    if lower_bound is not None and upper_bound is not None:
        req_low, req_low_inc = lower_bound
        req_up, req_up_inc = upper_bound
        if req_low > req_up or (req_low == req_up and not (req_low_inc and req_up_inc)):
            return OverlapState.PROVEN_DISJOINT, None

    # 1. MATHEMATICAL PROVEN DISJOINTNESS CHECKS:
    # A. If requested upper bound is below vulnerability lower bound
    if upper_bound is not None and intro_v is not None:
        req_up, req_up_inc = upper_bound
        if req_up < intro_v:
            return OverlapState.PROVEN_DISJOINT, None
        if req_up == intro_v and not req_up_inc:
            return OverlapState.PROVEN_DISJOINT, None

    # B. If requested lower bound is above vulnerability upper bound
    if lower_bound is not None:
        req_low, req_low_inc = lower_bound
        if fixed_v is not None:
            if req_low > fixed_v:
                return OverlapState.PROVEN_DISJOINT, None
            if req_low == fixed_v and req_low_inc:
                # vulnerable is strictly < fixed_v, requested is >= fixed_v
                return OverlapState.PROVEN_DISJOINT, None
        if last_aff_v is not None:
            if req_low > last_aff_v:
                return OverlapState.PROVEN_DISJOINT, None
            if req_low == last_aff_v and not req_low_inc:
                # vulnerable is <= last_aff_v, requested is > last_aff_v
                return OverlapState.PROVEN_DISJOINT, None
        if limit_v is not None:
            if req_low > limit_v:
                return OverlapState.PROVEN_DISJOINT, None
            if req_low == limit_v and req_low_inc:
                return OverlapState.PROVEN_DISJOINT, None

    # C. Check degenerate single-version interval (e.g. introduced == last_affected)
    if intro_v is not None and last_aff_v is not None and intro_v == last_aff_v:
        # The ONLY version in this vulnerable range is intro_v
        if intro_v in spec_set:
            return OverlapState.PROVEN_OVERLAP, f"=={intro_str}"
        return OverlapState.PROVEN_DISJOINT, None

    # 2. PROVEN OVERLAP VIA WITNESS PROBING:
    candidates: List[Version] = []

    # Explicit versions
    for ev in explicit_versions:
        ev_v = _safe_parse_version(ev)
        if ev_v is not None:
            candidates.append(ev_v)

    # Event bounds
    if intro_v is not None:
        candidates.append(intro_v)
    if last_aff_v is not None:
        candidates.append(last_aff_v)

    # Specifier boundary versions
    if lower_bound is not None:
        candidates.append(lower_bound[0])
    for spec in spec_set:
        v_s = _safe_parse_version(spec.version.rstrip(".*"))
        if v_s is not None:
            candidates.append(v_s)

    # Probing grid around overlap region
    start_v = intro_v or (lower_bound[0] if lower_bound else Version("0.0.1"))
    try:
        parts = [p for p in start_v.base_version.split(".")]
        if len(parts) >= 3:
            maj, mnr, patch = int(parts[0]), int(parts[1]), int(parts[2])
            candidates.extend([
                Version(f"{maj}.{mnr}.0"),
                Version(f"{maj}.{mnr}.{patch + 1}"),
                Version(f"{maj}.{mnr}.{patch + 2}"),
                Version(f"{maj}.{mnr}.{patch + 5}"),
                Version(f"{maj}.{mnr + 1}.0"),
                Version(f"{maj + 1}.0.0"),
            ])
        elif len(parts) == 2:
            maj, mnr = int(parts[0]), int(parts[1])
            candidates.extend([
                Version(f"{maj}.{mnr}.0"),
                Version(f"{maj}.{mnr}.1"),
                Version(f"{maj}.{mnr}.5"),
                Version(f"{maj}.{mnr + 1}.0"),
                Version(f"{maj + 1}.0.0"),
            ])
    except Exception:
        pass

    # Check candidates for concrete witness
    for cand in candidates:
        if cand in spec_set and _is_version_in_interval(cand, interval):
            return OverlapState.PROVEN_OVERLAP, _format_interval_range(interval)

    # 3. SOUND FALLBACK (UNRESOLVED):
    # Outer bounds touch or overlap, but candidate probing did not find a witness
    # (e.g. due to complex != exclusions, pre-release boundaries, or custom specs).
    # DO NOT mark safe. Emit UNRESOLVED to avoid silent false clean.
    return OverlapState.UNRESOLVED, _format_interval_range(interval)


class VersionMatcher:
    """
    Deterministic SCA Version Matcher.
    Evaluates DependencyRecords against OSV vulnerabilities.
    """

    def match_dependency(
        self,
        dep: DependencyRecord,
        osv_result: Optional[OSVQueryResult]
    ) -> List[SCAFinding]:
        """
        Matches a single DependencyRecord against OSV query result.
        Returns a list of SCAFindings (empty list if provably unaffected).
        """
        findings: List[SCAFinding] = []

        # 1. Handle missing, error, or unverified offline intelligence
        if osv_result is None:
            return [
                SCAFinding(
                    package_name=dep.name,
                    installed_version=dep.version,
                    requested_specifier=dep.version_specifier,
                    vulnerability_id="UNKNOWN",
                    aliases=[],
                    severity=SEVERITY_UNKNOWN,
                    cvss_score=None,
                    summary="No vulnerability intelligence available for this dependency.",
                    fixed_version=None,
                    matched_range="",
                    confidence=0.0,
                    status=STATUS_UNRESOLVED,
                    manifest_source=dep.source,
                    line_number=dep.line_number,
                )
            ]

        if osv_result.source == "error":
            err_msg = osv_result.error or "OSV query failed with error"
            return [
                SCAFinding(
                    package_name=dep.name,
                    installed_version=dep.version,
                    requested_specifier=dep.version_specifier,
                    vulnerability_id="UNKNOWN",
                    aliases=[],
                    severity=SEVERITY_UNKNOWN,
                    cvss_score=None,
                    summary=f"Vulnerability data could not be verified: {err_msg}",
                    fixed_version=None,
                    matched_range="",
                    confidence=0.0,
                    status=STATUS_UNRESOLVED,
                    manifest_source=dep.source,
                    line_number=dep.line_number,
                )
            ]

        if osv_result.source == "offline_fallback" and not osv_result.vulnerabilities:
            err_msg = osv_result.error or "Offline mode active; dependency unverified in local cache"
            return [
                SCAFinding(
                    package_name=dep.name,
                    installed_version=dep.version,
                    requested_specifier=dep.version_specifier,
                    vulnerability_id="UNKNOWN",
                    aliases=[],
                    severity=SEVERITY_UNKNOWN,
                    cvss_score=None,
                    summary=f"Vulnerability data could not be verified: {err_msg}",
                    fixed_version=None,
                    matched_range="",
                    confidence=0.0,
                    status=STATUS_UNRESOLVED,
                    manifest_source=dep.source,
                    line_number=dep.line_number,
                )
            ]

        # If OSV confirmed 0 vulnerabilities (clean package from network or cache)
        if not osv_result.vulnerabilities:
            return []

        # 2. Evaluate each vulnerability advisory individually
        for vuln in osv_result.vulnerabilities:
            finding = self._evaluate_advisory(dep, vuln)
            if finding is not None:
                findings.append(finding)

        return findings

    def _evaluate_advisory(
        self,
        dep: DependencyRecord,
        vuln: OSVVulnerability
    ) -> Optional[SCAFinding]:
        """Evaluates a single dependency against a single vulnerability advisory."""
        severity_str, cvss_score = extract_severity_and_score(vuln)
        summary = vuln.summary or (vuln.details[:200] if vuln.details else "Security vulnerability advisory")

        # -------------------------------------------------------------
        # BRANCH A: Pinned Dependency (exact version)
        # -------------------------------------------------------------
        if dep.pinned:
            if not dep.version:
                return SCAFinding(
                    package_name=dep.name,
                    installed_version=dep.version,
                    requested_specifier=dep.version_specifier,
                    vulnerability_id=vuln.vuln_id,
                    aliases=list(vuln.aliases),
                    severity=severity_str,
                    cvss_score=cvss_score,
                    summary=f"Pinned dependency missing version string: {summary}",
                    fixed_version=None,
                    matched_range="",
                    confidence=0.0,
                    status=STATUS_UNRESOLVED,
                    manifest_source=dep.source,
                    line_number=dep.line_number,
                )

            try:
                pinned_v = Version(dep.version)
            except InvalidVersion:
                return SCAFinding(
                    package_name=dep.name,
                    installed_version=dep.version,
                    requested_specifier=dep.version_specifier,
                    vulnerability_id=vuln.vuln_id,
                    aliases=list(vuln.aliases),
                    severity=severity_str,
                    cvss_score=cvss_score,
                    summary=f"Invalid PEP 440 version '{dep.version}': {summary}",
                    fixed_version=None,
                    matched_range="",
                    confidence=0.0,
                    status=STATUS_UNRESOLVED,
                    manifest_source=dep.source,
                    line_number=dep.line_number,
                )

            has_unresolved = False
            unresolved_desc = ""

            # Match against affected ranges
            for aff_range in vuln.affected_ranges:
                intervals = extract_intervals_from_events(aff_range.events)
                for interval in intervals:
                    # Check unparseable interval bounds
                    intro_str = interval.get("introduced")
                    fixed_str = interval.get("fixed")
                    last_aff_str = interval.get("last_affected")
                    if (intro_str and _safe_parse_version(intro_str) is None) or \
                       (fixed_str and _safe_parse_version(fixed_str) is None) or \
                       (last_aff_str and _safe_parse_version(last_aff_str) is None):
                        has_unresolved = True
                        unresolved_desc = _format_interval_range(interval)
                        continue

                    if _is_version_in_interval(pinned_v, interval):
                        fixed_ver = interval.get("fixed")
                        matched_rng = _format_interval_range(interval)
                        return SCAFinding(
                            package_name=dep.name,
                            installed_version=dep.version,
                            requested_specifier=dep.version_specifier,
                            vulnerability_id=vuln.vuln_id,
                            aliases=list(vuln.aliases),
                            severity=severity_str,
                            cvss_score=cvss_score,
                            summary=summary,
                            fixed_version=fixed_ver,
                            matched_range=matched_rng,
                            confidence=1.0,
                            status=STATUS_CONFIRMED,
                            manifest_source=dep.source,
                            line_number=dep.line_number,
                        )

                # Fallback: check explicit versions list
                if aff_range.versions:
                    for ev in aff_range.versions:
                        ev_v = _safe_parse_version(ev)
                        if ev_v is not None and pinned_v == ev_v:
                            return SCAFinding(
                                package_name=dep.name,
                                installed_version=dep.version,
                                requested_specifier=dep.version_specifier,
                                vulnerability_id=vuln.vuln_id,
                                aliases=list(vuln.aliases),
                                severity=severity_str,
                                cvss_score=cvss_score,
                                summary=summary,
                                fixed_version=None,
                                matched_range=f"=={dep.version}",
                                confidence=1.0,
                                status=STATUS_CONFIRMED,
                                manifest_source=dep.source,
                                line_number=dep.line_number,
                            )

            if has_unresolved:
                return SCAFinding(
                    package_name=dep.name,
                    installed_version=dep.version,
                    requested_specifier=dep.version_specifier,
                    vulnerability_id=vuln.vuln_id,
                    aliases=list(vuln.aliases),
                    severity=severity_str,
                    cvss_score=cvss_score,
                    summary=f"Unparseable advisory range '{unresolved_desc}': {summary}",
                    fixed_version=None,
                    matched_range=unresolved_desc,
                    confidence=0.0,
                    status=STATUS_UNRESOLVED,
                    manifest_source=dep.source,
                    line_number=dep.line_number,
                )

            # Clearly outside all affected ranges -> emit no finding
            return None

        # -------------------------------------------------------------
        # BRANCH B: Unpinned / Range Dependency
        # -------------------------------------------------------------
        spec_str = dep.version_specifier or ""
        # If dependency has no specifier (e.g. bare "requests"), it accepts any version
        if not spec_str.strip():
            spec_str = ">=0"

        try:
            spec_set = SpecifierSet(spec_str)
        except (InvalidSpecifier, Exception):
            return SCAFinding(
                package_name=dep.name,
                installed_version=dep.version,
                requested_specifier=dep.version_specifier,
                vulnerability_id=vuln.vuln_id,
                aliases=list(vuln.aliases),
                severity=severity_str,
                cvss_score=cvss_score,
                summary=f"Ambiguous or invalid version specifier '{spec_str}': {summary}",
                fixed_version=None,
                matched_range="",
                confidence=0.0,
                status=STATUS_UNRESOLVED,
                manifest_source=dep.source,
                line_number=dep.line_number,
            )

        found_overlap: Optional[Tuple[str, Optional[str]]] = None  # (desc, fixed)
        has_unresolved = False
        unresolved_desc = ""

        for aff_range in vuln.affected_ranges:
            intervals = extract_intervals_from_events(aff_range.events)

            # Case B1: Events intervals exist
            for interval in intervals:
                state, matched_desc = classify_interval_overlap(spec_set, interval, aff_range.versions)
                if state == OverlapState.PROVEN_OVERLAP:
                    found_overlap = (matched_desc or _format_interval_range(interval), interval.get("fixed"))
                    break
                elif state == OverlapState.UNRESOLVED:
                    has_unresolved = True
                    unresolved_desc = matched_desc or _format_interval_range(interval)

            if found_overlap:
                break

            # Case B2: No interval events, only explicit versions
            if not intervals and aff_range.versions:
                admitted = []
                unparseable = False
                for ev in aff_range.versions:
                    ev_v = _safe_parse_version(ev)
                    if ev_v is None:
                        unparseable = True
                    elif ev_v in spec_set:
                        admitted.append(ev)
                if admitted:
                    found_overlap = (f"in ({', '.join(admitted[:3])})", None)
                    break
                elif unparseable:
                    has_unresolved = True
                    unresolved_desc = "unparseable version in advisory"

        if found_overlap:
            matched_desc, fixed_ver = found_overlap
            return SCAFinding(
                package_name=dep.name,
                installed_version=dep.version,
                requested_specifier=dep.version_specifier,
                vulnerability_id=vuln.vuln_id,
                aliases=list(vuln.aliases),
                severity=severity_str,
                cvss_score=cvss_score,
                summary=summary,
                fixed_version=fixed_ver,
                matched_range=matched_desc,
                confidence=0.6,
                status=STATUS_POTENTIAL,
                manifest_source=dep.source,
                line_number=dep.line_number,
            )

        if has_unresolved:
            return SCAFinding(
                package_name=dep.name,
                installed_version=dep.version,
                requested_specifier=dep.version_specifier,
                vulnerability_id=vuln.vuln_id,
                aliases=list(vuln.aliases),
                severity=severity_str,
                cvss_score=cvss_score,
                summary=f"Indeterminate overlap with vulnerable range '{unresolved_desc}': {summary}",
                fixed_version=None,
                matched_range=unresolved_desc,
                confidence=0.0,
                status=STATUS_UNRESOLVED,
                manifest_source=dep.source,
                line_number=dep.line_number,
            )

        # All intervals and explicit version sets are PROVEN_DISJOINT -> emit no finding
        return None

    def match_dependencies(
        self,
        dependencies: List[DependencyRecord],
        osv_results: Dict[str, OSVQueryResult]
    ) -> List[SCAFinding]:
        """
        Matches multiple DependencyRecords against OSV query results.
        Returns deterministically sorted findings list.
        """
        all_findings: List[SCAFinding] = []

        for dep in dependencies:
            norm_name = normalize_package_name(dep.name)
            osv_res = osv_results.get(norm_name)
            dep_findings = self.match_dependency(dep, osv_res)
            all_findings.extend(dep_findings)

        # Stable deterministic sort: package_name, vuln_id, source, line_number, status
        all_findings.sort(key=lambda f: (
            f.package_name,
            f.vulnerability_id,
            f.manifest_source,
            f.line_number if f.line_number is not None else -1,
            f.status,
            f.matched_range
        ))

        return all_findings


# Module-level convenience functions
def match_dependency(dep: DependencyRecord, osv_result: Optional[OSVQueryResult]) -> List[SCAFinding]:
    """Convenience function to match a single dependency."""
    return VersionMatcher().match_dependency(dep, osv_result)


def match_dependencies(
    dependencies: List[DependencyRecord],
    osv_results: Dict[str, OSVQueryResult]
) -> List[SCAFinding]:
    """Convenience function to match multiple dependencies."""
    return VersionMatcher().match_dependencies(dependencies, osv_results)
