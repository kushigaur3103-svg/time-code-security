"""False-positive filtering, allowlisting, and policy engine for secret scanning.

Evaluates candidate SecretFinding objects against file path exclusions,
template and sample file rules, dummy/placeholder heuristics, mocking contexts,
and explicit allowlists.

Non-negotiable invariants:
- Zero raw secret exposure: operates exclusively on SecretFinding (which only
  contains masked values and redacted context).
- Non-destructive: retained findings preserve exact line numbers, columns, and values.
- SAST / SCA Isolation: zero imports from ast_scanner, rule_engine, or manifest_parser.
- Zero network I/O.
"""

from dataclasses import dataclass, field
import fnmatch
import os
import re
from typing import List, Optional, Set, Tuple

from secret_scanner import SecretFinding

__all__ = [
    "FilterConfig",
    "SuppressedFinding",
    "FilterResult",
    "filter_findings",
    "evaluate_findings",
]


@dataclass
class FilterConfig:
    """Configuration container for secret false-positive filtering."""

    ignored_paths: Tuple[str, ...] = (
        "tests/",
        "test/",
        "spec/",
        "specs/",
        "fixtures/",
        "fixture/",
        "mock/",
        "mocks/",
        "vendor/",
        ".git/",
        "node_modules/",
        "docs/",
        "doc/",
    )
    ignored_filenames: Set[str] = field(
        default_factory=lambda: {
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.test",
            "sample.env",
            "example.env",
            "docker-compose.test.yml",
        }
    )
    ignored_extensions: Tuple[str, ...] = (
        ".md",
        ".rst",
        ".example",
        ".sample",
    )
    dummy_patterns: Tuple[str, ...] = (
        r"(?i)\b(dummy|fake|placeholder|example|test|sample|change_me|your_token_here|my_secret_token)[\w]*",
        r"(?i)\b(00000+|11111+|xxxxxx+|abcdef)\b",
        r"AKIA0{10,}",
        r"ghp_0{10,}",
        r"xox[baprs]-0{10,}",
    )
    mock_context_patterns: Tuple[str, ...] = (
        r"(?i)\b(mock\.patch|@patch|pytest\.fixture|unittest\.mock|magicmock|responses\.add|httpretty|requests_mock)\b",
    )
    allowlisted_entries: Set[str] = field(default_factory=set)
    ignore_test_paths: bool = True
    ignore_templates: bool = True
    ignore_dummies: bool = True
    ignore_mock_contexts: bool = True
    min_entropy_threshold: Optional[float] = None


@dataclass(frozen=True)
class SuppressedFinding:
    """Audit record representing a suppressed secret finding."""

    finding: SecretFinding
    reason: str
    filter_name: str


@dataclass(frozen=True)
class FilterResult:
    """Result container separating retained and suppressed findings."""

    retained: List[SecretFinding]
    suppressed: List[SuppressedFinding]


def _normalize_path(path: str) -> str:
    """Normalize file path for cross-platform matching."""
    norm = path.replace("\\", "/").lower()
    if norm.startswith("./"):
        norm = norm[2:]
    return norm


def _is_path_ignored(file_path: str, config: FilterConfig) -> Optional[Tuple[str, str]]:
    """Check if a file path is ignored. Returns (filter_name, reason) if ignored."""
    normalized = _normalize_path(file_path)
    basename = os.path.basename(normalized)

    # 1. Check template / sample filenames
    if config.ignore_templates:
        if basename in config.ignored_filenames:
            return "PathFilter", "ignored_filename"
        if any(basename.endswith(ext) for ext in config.ignored_extensions):
            return "PathFilter", "ignored_extension"

    # 2. Check path directories
    if config.ignore_test_paths:
        slash_path = f"/{normalized}"
        for prefix in config.ignored_paths:
            norm_prefix = prefix.lower()
            if normalized.startswith(norm_prefix) or f"/{norm_prefix}" in slash_path:
                return "PathFilter", "ignored_path"
            if "*" in norm_prefix and fnmatch.fnmatch(normalized, norm_prefix):
                return "PathFilter", "ignored_path"

    return None


def _is_dummy_value(finding: SecretFinding, config: FilterConfig) -> bool:
    """Check if the finding's masked value or context indicates a dummy/placeholder."""
    if not config.ignore_dummies:
        return False

    # 1. Check masked value for repetitive dummy characters in unmasked suffix
    # e.g., AKIA************0000 or ghp_****************************0000
    mv = finding.masked_value
    if re.search(r"(?i)(0{4,}|1{4,}|x{4,})$", mv):
        return True

    # 2. Check dummy patterns against masked value
    for pattern in config.dummy_patterns:
        if re.search(pattern, mv):
            return True

    # 3. Check dummy patterns against context
    if finding.context:
        for pattern in config.dummy_patterns:
            if re.search(pattern, finding.context):
                return True

    return False


def _is_mock_context(finding: SecretFinding, file_path: str, config: FilterConfig) -> bool:
    """Check if the finding occurs within a test mock or fixture context."""
    if not config.ignore_mock_contexts:
        return False

    # 1. Check finding.context
    if finding.context:
        for pattern in config.mock_context_patterns:
            if re.search(pattern, finding.context):
                return True

    # 2. Check preceding lines if file exists on disk (e.g. preceding decorator)
    if file_path and os.path.isfile(file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            idx = finding.line_number - 1
            for offset in (1, 2, 3):
                check_idx = idx - offset
                if 0 <= check_idx < len(lines):
                    prev_line = lines[check_idx]
                    for pattern in config.mock_context_patterns:
                        if re.search(pattern, prev_line):
                            return True
        except Exception:
            pass

    return False


def _is_allowlisted(finding: SecretFinding, file_path: str, config: FilterConfig) -> bool:
    """Check if the finding matches an allowlist entry."""
    if not config.allowlisted_entries:
        return False

    norm_path = _normalize_path(file_path)
    location_key = f"{norm_path}:{finding.line_number}"
    basename_key = f"{os.path.basename(norm_path)}:{finding.line_number}"

    # Check exact masked value, location keys, detector-specific keys
    candidates = {
        finding.masked_value,
        location_key,
        basename_key,
        f"{finding.detector}:{finding.masked_value}",
    }
    return bool(candidates.intersection(config.allowlisted_entries))


def evaluate_findings(
    findings: List[SecretFinding],
    file_path: str,
    config: Optional[FilterConfig] = None,
) -> FilterResult:
    """Evaluate candidate findings against filter rules and return FilterResult."""
    if config is None:
        config = FilterConfig()

    retained: List[SecretFinding] = []
    suppressed: List[SuppressedFinding] = []

    # File-level path check
    path_rejection = _is_path_ignored(file_path, config)
    if path_rejection:
        filter_name, reason = path_rejection
        for f in findings:
            suppressed.append(
                SuppressedFinding(finding=f, reason=reason, filter_name=filter_name)
            )
        return FilterResult(retained=retained, suppressed=suppressed)

    # Finding-level checks
    for f in findings:
        # 1. Allowlist
        if _is_allowlisted(f, file_path, config):
            suppressed.append(
                SuppressedFinding(
                    finding=f, reason="allowlisted", filter_name="AllowlistFilter"
                )
            )
            continue

        # 2. Dummy / Placeholder values
        if _is_dummy_value(f, config):
            suppressed.append(
                SuppressedFinding(
                    finding=f,
                    reason="dummy_or_placeholder_value",
                    filter_name="DummyValueFilter",
                )
            )
            continue

        # 3. Mock / Test fixture contexts
        if _is_mock_context(f, file_path, config):
            suppressed.append(
                SuppressedFinding(
                    finding=f,
                    reason="mocking_or_test_fixture",
                    filter_name="ContextFilter",
                )
            )
            continue

        # Retained
        retained.append(f)

    return FilterResult(retained=retained, suppressed=suppressed)


def filter_findings(
    findings: List[SecretFinding],
    file_path: str,
    config: Optional[FilterConfig] = None,
) -> List[SecretFinding]:
    """Filter candidate findings and return only retained findings."""
    result = evaluate_findings(findings, file_path=file_path, config=config)
    return result.retained
