"""
TimeCodeSecurity (TCS) OSV API Client & Cache Layer.
Queries Open Source Vulnerabilities (osv.dev) for Python packages via /v1/querybatch.
Includes local caching, batch chunking, bounded retries, and offline fallback.
"""

from __future__ import annotations
import os
import json
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable

from manifest_parser import normalize_package_name

OSV_API_URL = "https://api.osv.dev/v1/querybatch"
DEFAULT_BATCH_CHUNK_SIZE = 500
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 0.5


@dataclass(frozen=True)
class OSVAffectedRange:
    """Represents a range or list of versions affected by an advisory."""
    type: str                                           # e.g. "ECOSYSTEM", "SEMVER", "GIT"
    events: Tuple[Dict[str, str], ...] = ()            # e.g. ({"introduced": "2.3.0"}, {"fixed": "2.31.0"})
    versions: Tuple[str, ...] = ()                      # list of explicitly enumerated version strings
    database_specific: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OSVVulnerability:
    """Normalized structured representation of an OSV advisory."""
    vuln_id: str                                        # Primary advisory ID (GHSA-..., PYSEC-..., CVE-...)
    package_name: str                                   # Normalized package name
    ecosystem: str = "PyPI"
    summary: str = ""
    details: str = ""
    aliases: Tuple[str, ...] = ()                       # Associated IDs (CVE-..., GHSA-...)
    affected_ranges: Tuple[OSVAffectedRange, ...] = ()  # Affected version ranges and explicit versions
    severity: Tuple[Dict[str, Any], ...] = ()           # CVSS vectors/scores
    references: Tuple[Dict[str, str], ...] = ()         # External advisory links
    database_specific: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)   # Raw original OSV record


@dataclass
class OSVQueryResult:
    """Result of querying advisories for a specific package."""
    package_name: str                                   # Normalized package name
    vulnerabilities: List[OSVVulnerability] = field(default_factory=list)
    source: str = "network"                             # "network", "cache", "offline_fallback", "error"
    error: Optional[str] = None

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0


def _parse_osv_vuln(package_name: str, raw_vuln: Dict[str, Any]) -> OSVVulnerability:
    """Translates a raw OSV JSON vulnerability record into an OSVVulnerability object."""
    vuln_id = raw_vuln.get("id", "UNKNOWN_ID")
    summary = raw_vuln.get("summary", "")
    details = raw_vuln.get("details", "")
    aliases = tuple(raw_vuln.get("aliases", []))
    severity = tuple(raw_vuln.get("severity", []))
    references = tuple(raw_vuln.get("references", []))
    db_specific = raw_vuln.get("database_specific", {})

    ranges_list: List[OSVAffectedRange] = []
    for affected in raw_vuln.get("affected", []):
        aff_pkg = affected.get("package", {})
        aff_pkg_name = normalize_package_name(aff_pkg.get("name", ""))
        aff_eco = aff_pkg.get("ecosystem", "PyPI")

        # Include if ecosystem is PyPI and package name matches or is unspecified
        if aff_eco.lower() == "pypi" and (not aff_pkg_name or aff_pkg_name == package_name):
            explicit_versions = tuple(affected.get("versions", []))
            for r in affected.get("ranges", []):
                ranges_list.append(OSVAffectedRange(
                    type=r.get("type", "ECOSYSTEM"),
                    events=tuple(r.get("events", [])),
                    versions=explicit_versions,
                    database_specific=r.get("database_specific", {})
                ))

            # If no range blocks were provided but explicit versions exist
            if not affected.get("ranges") and explicit_versions:
                ranges_list.append(OSVAffectedRange(
                    type="VERSIONS",
                    events=(),
                    versions=explicit_versions,
                    database_specific=affected.get("database_specific", {})
                ))

    return OSVVulnerability(
        vuln_id=vuln_id,
        package_name=package_name,
        ecosystem="PyPI",
        summary=summary,
        details=details,
        aliases=aliases,
        affected_ranges=tuple(ranges_list),
        severity=severity,
        references=references,
        database_specific=db_specific,
        raw=raw_vuln
    )


class OSVClient:
    """
    Offline-capable, batch-chunking OSV API Client for Python/PyPI packages.
    """

    def __init__(
        self,
        api_url: str = OSV_API_URL,
        cache_file: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
        batch_chunk_size: int = DEFAULT_BATCH_CHUNK_SIZE,
        offline_mode: bool = False,
        offline_fixtures: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        http_requester: Optional[Callable[[str, bytes, float], bytes]] = None
    ):
        self.api_url = api_url
        self.cache_file = cache_file
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.batch_chunk_size = batch_chunk_size
        self.offline_mode = offline_mode
        self._memory_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._http_requester = http_requester or self._default_http_post

        # Load offline fixtures if provided
        if offline_fixtures:
            for k, v in offline_fixtures.items():
                self._memory_cache[normalize_package_name(k)] = v

        # Load local disk cache if configured
        if self.cache_file:
            self._load_disk_cache()

    def _load_disk_cache(self) -> None:
        """Loads cached responses from the local cache file."""
        if not self.cache_file:
            return
        p = Path(self.cache_file)
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    for k, v in data.items():
                        if isinstance(v, list):
                            self._memory_cache[normalize_package_name(k)] = v
            except Exception:
                pass  # Tolerate corrupt cache file without crashing

    def _save_disk_cache(self) -> None:
        """Persists memory cache to the local cache file."""
        if not self.cache_file:
            return
        try:
            p = Path(self.cache_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(self._memory_cache, indent=2), encoding="utf-8")
        except Exception:
            pass  # Non-fatal if disk write fails

    def _default_http_post(self, url: str, payload_bytes: bytes, timeout: float) -> bytes:
        """Standard library HTTP POST request handler."""
        req = urllib.request.Request(
            url,
            data=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "TimeCodeSecurity-SCA/1.0"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read()

    def query_package(self, package_name: str) -> OSVQueryResult:
        """Convenience method to query a single package."""
        results = self.query_packages([package_name])
        norm = normalize_package_name(package_name)
        return results.get(norm, OSVQueryResult(package_name=norm, source="error", error="Not found"))

    def query_packages(self, package_names: List[str]) -> Dict[str, OSVQueryResult]:
        """
        Queries OSV database for multiple packages using batch requests.
        Handles caching, chunking, bounded retries, and offline fallback.
        """
        results_map: Dict[str, OSVQueryResult] = {}
        pending_names: List[str] = []

        # 1. Check local cache and offline fixtures
        for raw_name in package_names:
            norm_name = normalize_package_name(raw_name)
            if not norm_name:
                continue

            if norm_name in self._memory_cache:
                raw_vulns = self._memory_cache[norm_name]
                parsed = [_parse_osv_vuln(norm_name, v) for v in raw_vulns]
                results_map[norm_name] = OSVQueryResult(
                    package_name=norm_name,
                    vulnerabilities=parsed,
                    source="cache"
                )
            else:
                if norm_name not in pending_names:
                    pending_names.append(norm_name)

        # 2. If in offline mode, do not attempt network requests
        if self.offline_mode:
            for name in pending_names:
                results_map[name] = OSVQueryResult(
                    package_name=name,
                    vulnerabilities=[],
                    source="offline_fallback",
                    error="Offline mode active; package not found in local cache"
                )
            return results_map

        if not pending_names:
            return results_map

        # 3. Chunk pending packages into batches (up to batch_chunk_size)
        cache_dirty = False
        for i in range(0, len(pending_names), self.batch_chunk_size):
            chunk = pending_names[i:i + self.batch_chunk_size]
            chunk_results = self._fetch_batch_chunk(chunk)

            for name, (raw_vulns, source, err_msg) in chunk_results.items():
                if source == "network":
                    self._memory_cache[name] = raw_vulns
                    cache_dirty = True
                parsed_vulns = [_parse_osv_vuln(name, v) for v in raw_vulns]
                results_map[name] = OSVQueryResult(
                    package_name=name,
                    vulnerabilities=parsed_vulns,
                    source=source,
                    error=err_msg
                )

        if cache_dirty:
            self._save_disk_cache()

        return results_map

    def _fetch_batch_chunk(self, chunk: List[str]) -> Dict[str, Tuple[List[Dict[str, Any]], str, Optional[str]]]:
        """
        Executes an HTTP POST to /v1/querybatch for a single chunk of packages.
        Applies exponential backoff retries for 5xx errors/timeouts and fails fast on 4xx.
        """
        chunk_map: Dict[str, Tuple[List[Dict[str, Any]], str, Optional[str]]] = {}
        queries = [{"package": {"name": name, "ecosystem": "PyPI"}} for name in chunk]
        payload = {"queries": queries}
        payload_bytes = json.dumps(payload).encode("utf-8")

        for attempt in range(self.max_retries):
            try:
                raw_response = self._http_requester(self.api_url, payload_bytes, self.timeout)
                data = json.loads(raw_response.decode("utf-8"))
                batch_results = data.get("results", [])

                for idx, name in enumerate(chunk):
                    vulns_list: List[Dict[str, Any]] = []
                    if idx < len(batch_results):
                        entry = batch_results[idx]
                        vulns_list = entry.get("vulns", []) if isinstance(entry, dict) else []
                    chunk_map[name] = (vulns_list, "network", None)

                return chunk_map

            except urllib.error.HTTPError as http_err:
                status = http_err.code
                # Fail fast on 4xx client errors
                if 400 <= status < 500:
                    for name in chunk:
                        chunk_map[name] = ([], "error", f"HTTP {status}: Client error")
                    return chunk_map

                # 5xx server errors: retry with backoff
                if attempt < self.max_retries - 1:
                    sleep_time = self.backoff_factor * (2 ** attempt)
                    if sleep_time > 0:
                        time.sleep(sleep_time)
                else:
                    for name in chunk:
                        chunk_map[name] = ([], "error", f"HTTP {status}: Server error after {self.max_retries} attempts")
                    return chunk_map

            except (urllib.error.URLError, TimeoutError, Exception) as net_err:
                # Network / timeout errors: retry with backoff
                if attempt < self.max_retries - 1:
                    sleep_time = self.backoff_factor * (2 ** attempt)
                    if sleep_time > 0:
                        time.sleep(sleep_time)
                else:
                    for name in chunk:
                        chunk_map[name] = ([], "offline_fallback", f"Network error: {net_err}")
                    return chunk_map

        return chunk_map
