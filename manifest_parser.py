"""
TimeCodeSecurity (TCS) Manifest Parser.
Extracts normalized Python dependency records from:
  - requirements.txt (PEP 508 / pip format)
  - Pipfile.lock (Pipenv JSON lockfile)
  - poetry.lock (Poetry TOML lockfile)

Deterministic, offline-only parsing with NO external network access.
"""

from __future__ import annotations
import os
import re
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set

# Standard library TOML support (Python 3.11+) with fallback
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

# Optional packaging library for standard PEP 508 parsing if installed
try:
    from packaging.requirements import Requirement as PackagingRequirement
    from packaging.utils import canonicalize_name
    HAS_PACKAGING = True
except ImportError:
    HAS_PACKAGING = False


def normalize_package_name(name: str) -> str:
    """
    Normalizes a package name according to PEP 503 / PEP 685:
    Lowercased with runs of [-_.] replaced by a single '-'.
    """
    if not name:
        return ""
    if HAS_PACKAGING:
        return canonicalize_name(name)
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


@dataclass(frozen=True)
class DependencyRecord:
    """
    Typed, immutable representation of a single normalized dependency requirement
    or locked package record.
    """
    name: str                                  # Normalized package name (e.g. "requests", "django")
    version: Optional[str] = None              # Exact pinned/resolved version (e.g. "2.25.0") or None if range/unpinned
    version_specifier: Optional[str] = None    # Full original specifier (e.g. "==2.25.0", ">=1.26.0,<2.0", "~=1.2")
    source: str = ""                           # Manifest source identifier ("requirements.txt", "Pipfile.lock", "poetry.lock")
    pinned: bool = False                       # True if exact single version is pinned (==x.y.z)
    environment_marker: Optional[str] = None   # Preserved environment marker (e.g. 'python_version < "3.8"')
    extras: Tuple[str, ...] = ()               # Normalized tuple of extras (e.g. ("security",))
    editable: bool = False                     # True if editable requirement (-e)
    group: Optional[str] = None                # Dependency group/category (e.g. "default", "develop", "main", "dev")
    raw: str = ""                              # Raw original declaration string
    line_number: Optional[int] = None          # Line number in source manifest (1-based if applicable)


@dataclass
class ParseIssue:
    """Represents a malformed line, syntax error, or unparseable item in a manifest."""
    message: str
    line_number: Optional[int] = None
    raw: str = ""
    issue_type: str = "malformed"  # "malformed", "missing_field", "syntax_error"


@dataclass
class ManifestParseResult:
    """Container for the results of parsing any manifest file."""
    source_type: str                                       # "requirements.txt", "Pipfile.lock", "poetry.lock"
    source_path: Optional[str] = None                      # Path to manifest file if provided
    dependencies: List[DependencyRecord] = field(default_factory=list)
    issues: List[ParseIssue] = field(default_factory=list)
    ignored_directives: List[str] = field(default_factory=list)

    @property
    def has_issues(self) -> bool:
        return len(self.issues) > 0

    def get_unique_dependencies(self) -> Dict[str, List[DependencyRecord]]:
        """Group dependencies by normalized package name."""
        by_name: Dict[str, List[DependencyRecord]] = {}
        for dep in self.dependencies:
            by_name.setdefault(dep.name, []).append(dep)
        return by_name


# Commands and flags in requirements.txt that are not package dependencies
IGNORED_REQUIREMENTS_DIRECTIVES = (
    "-r", "--requirement",
    "-c", "--constraint",
    "-f", "--find-links",
    "-i", "--index-url",
    "--extra-index-url",
    "--no-index",
    "--trusted-host",
    "--prefer-binary",
    "--no-binary",
    "--only-binary"
)


def _strip_inline_comment(line: str) -> str:
    """
    Safely strips trailing inline comments while preserving #egg= inside URLs.
    """
    if "#egg=" in line:
        return line.strip()
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


def _parse_pep508_requirement(
    clean_line: str,
    filename: str,
    raw_line: str,
    group: Optional[str] = None,
    line_number: Optional[int] = None,
) -> Tuple[Optional[DependencyRecord], Optional[ParseIssue]]:
    """
    Parses a single PEP 508 requirement string into a DependencyRecord.
    Returns (record, None) on success, or (None, issue) on malformed syntax.
    """
    if HAS_PACKAGING:
        try:
            req = PackagingRequirement(clean_line)
            norm_name = normalize_package_name(req.name)
            extras_tuple = tuple(sorted(canonicalize_name(e) for e in req.extras)) if req.extras else ()
            marker_str = str(req.marker) if req.marker else None
            spec_str = str(req.specifier) if req.specifier else None
            pinned_flag = False
            version_val = None

            if req.specifier:
                specs = list(req.specifier)
                if (
                    len(specs) == 1
                    and specs[0].operator in ("==", "===")
                    and not specs[0].version.endswith(".*")
                    and "*" not in specs[0].version
                ):
                    pinned_flag = True
                    version_val = specs[0].version

            record = DependencyRecord(
                name=norm_name,
                version=version_val,
                version_specifier=spec_str,
                source=filename,
                pinned=pinned_flag,
                environment_marker=marker_str,
                extras=extras_tuple,
                editable=False,
                group=group,
                raw=raw_line,
                line_number=line_number
            )
            return record, None
        except Exception as pe:
            return None, ParseIssue(
                message=f"Malformed requirement: {pe}",
                line_number=line_number,
                raw=raw_line,
                issue_type="malformed"
            )
    else:
        req_match = re.match(
            r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
            r"(?:\[([^\]]+)\])?"
            r"(?:\s*([~!=><~=]+[^;]+))?"
            r"(?:\s*;\s*(.+))?$",
            clean_line
        )
        if not req_match:
            return None, ParseIssue(
                message="Malformed requirement line syntax",
                line_number=line_number,
                raw=raw_line,
                issue_type="malformed"
            )

        raw_name, raw_extras, raw_spec, raw_marker = req_match.groups()
        norm_name = normalize_package_name(raw_name)
        extras_tuple = tuple(sorted(normalize_package_name(e.strip()) for e in raw_extras.split(","))) if raw_extras else ()
        spec_str = raw_spec.strip() if raw_spec else None
        marker_str = raw_marker.strip() if raw_marker else None
        pinned_flag = False
        version_val = None

        if spec_str:
            if spec_str.startswith("==") and not spec_str.endswith(".*") and "," not in spec_str and "*" not in spec_str:
                pinned_flag = True
                version_val = spec_str[2:].strip()

        record = DependencyRecord(
            name=norm_name,
            version=version_val,
            version_specifier=spec_str,
            source=filename,
            pinned=pinned_flag,
            environment_marker=marker_str,
            extras=extras_tuple,
            editable=False,
            group=group,
            raw=raw_line,
            line_number=line_number
        )
        return record, None


def parse_requirements_txt(content_or_path: str, filename: str = "requirements.txt") -> ManifestParseResult:
    """
    Deterministically parses a requirements.txt file or string content.
    Extracts pinned versions, version ranges, markers, extras, and editable flags.
    Captures non-dependency directives without raising errors.
    """
    source_path = None
    if "\n" not in content_or_path and os.path.isfile(content_or_path):
        source_path = content_or_path
        filename = os.path.basename(content_or_path)
        with open(content_or_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    else:
        content = content_or_path

    result = ManifestParseResult(source_type="requirements.txt", source_path=source_path)

    lines = content.splitlines()
    for idx, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        clean_line = _strip_inline_comment(stripped)
        if not clean_line:
            continue

        # Check for non-dependency directives (-r, -c, --index-url, etc.)
        first_token = clean_line.split()[0]
        if first_token in IGNORED_REQUIREMENTS_DIRECTIVES or any(clean_line.startswith(f"{d} ") or clean_line.startswith(f"{d}=") for d in IGNORED_REQUIREMENTS_DIRECTIVES):
            result.ignored_directives.append(stripped)
            continue

        # Check for editable requirements (-e, --editable)
        if first_token in ("-e", "--editable") or clean_line.startswith("-e ") or clean_line.startswith("--editable "):
            editable_target = clean_line.split(None, 1)[1].strip() if len(clean_line.split(None, 1)) > 1 else ""
            pkg_name = ""
            if "#egg=" in editable_target:
                raw_name = editable_target.split("#egg=")[1].split("&")[0].strip()
                pkg_name = normalize_package_name(raw_name)
            else:
                pkg_name = editable_target

            record = DependencyRecord(
                name=pkg_name,
                version=None,
                version_specifier=None,
                source=filename,
                pinned=False,
                environment_marker=None,
                extras=(),
                editable=True,
                group=None,
                raw=stripped,
                line_number=idx
            )
            result.dependencies.append(record)
            continue

        # General unsupported command line option starting with -- or -
        if clean_line.startswith("-"):
            result.ignored_directives.append(stripped)
            continue

        # Standard requirement specification
        record, issue = _parse_pep508_requirement(
            clean_line=clean_line,
            filename=filename,
            raw_line=stripped,
            group=None,
            line_number=idx
        )
        if record:
            result.dependencies.append(record)
        if issue:
            result.issues.append(issue)

    return result


def parse_pipfile_lock(content_or_path: str, filename: str = "Pipfile.lock") -> ManifestParseResult:
    """
    Parses a Pipfile.lock JSON document into normalized DependencyRecords.
    Tolerates optional fields and extracts both 'default' and 'develop' packages.
    """
    source_path = None
    if "\n" not in content_or_path and os.path.isfile(content_or_path):
        source_path = content_or_path
        filename = os.path.basename(content_or_path)
        with open(content_or_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    else:
        content = content_or_path

    result = ManifestParseResult(source_type="Pipfile.lock", source_path=source_path)

    try:
        data = json.loads(content)
    except Exception as je:
        result.issues.append(ParseIssue(
            message=f"Malformed JSON in Pipfile.lock: {je}",
            issue_type="malformed",
            raw=content[:200]
        ))
        return result

    if not isinstance(data, dict):
        result.issues.append(ParseIssue(
            message="Pipfile.lock root must be a JSON object",
            issue_type="malformed"
        ))
        return result

    for section_name, packages in data.items():
        if section_name == "_meta":
            continue
        if not isinstance(packages, dict):
            continue

        for pkg_name, pkg_info in packages.items():
            if not isinstance(pkg_info, dict):
                result.issues.append(ParseIssue(
                    message=f"Package entry '{pkg_name}' must be an object",
                    issue_type="malformed"
                ))
                continue

            raw_ver = pkg_info.get("version")
            markers = pkg_info.get("markers")
            extras = pkg_info.get("extras", [])
            editable = bool(pkg_info.get("editable", False))
            extras_tuple = tuple(sorted(normalize_package_name(e) for e in extras)) if isinstance(extras, list) else ()

            pinned_flag = False
            version_val = None
            spec_str = None

            if raw_ver:
                raw_ver_str = str(raw_ver).strip()
                spec_str = raw_ver_str
                if (
                    raw_ver_str.startswith("==")
                    and not raw_ver_str.endswith(".*")
                    and "*" not in raw_ver_str
                    and "," not in raw_ver_str
                ):
                    pinned_flag = True
                    version_val = raw_ver_str[2:].strip()
                elif (
                    raw_ver_str
                    and not any(op in raw_ver_str for op in ["<", ">", "=", "!", "~"])
                ):
                    pinned_flag = True
                    version_val = raw_ver_str
                    spec_str = f"=={raw_ver_str}"

            norm_name = normalize_package_name(pkg_name)
            record = DependencyRecord(
                name=norm_name,
                version=version_val,
                version_specifier=spec_str,
                source=filename,
                pinned=pinned_flag,
                environment_marker=str(markers) if markers else None,
                extras=extras_tuple,
                editable=editable,
                group=section_name,
                raw=f'"{pkg_name}": {json.dumps(pkg_info)}'
            )
            result.dependencies.append(record)

    return result


def _parse_poetry_lock_simple_toml(content: str) -> List[Dict[str, Any]]:
    """
    Minimal state-machine fallback TOML parser for poetry.lock [[package]] tables
    if tomllib/tomli is not available in the environment.
    """
    packages = []
    current_pkg = None
    in_subtable = False

    for line in content.splitlines():
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            continue

        if line_clean == "[[package]]":
            if current_pkg and "name" in current_pkg:
                packages.append(current_pkg)
            current_pkg = {}
            in_subtable = False
            continue

        if line_clean.startswith("[") and not line_clean.startswith("[["):
            in_subtable = True
            continue

        if current_pkg is not None and not in_subtable and "=" in line_clean:
            k, v = line_clean.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            current_pkg[k] = v

    if current_pkg and "name" in current_pkg:
        packages.append(current_pkg)

    return packages


def parse_poetry_lock(content_or_path: str, filename: str = "poetry.lock") -> ManifestParseResult:
    """
    Parses a poetry.lock TOML document into normalized DependencyRecords.
    Extracts locked packages, exact versions, and category/groups.
    """
    source_path = None
    if "\n" not in content_or_path and os.path.isfile(content_or_path):
        source_path = content_or_path
        filename = os.path.basename(content_or_path)
        with open(content_or_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    else:
        content = content_or_path

    result = ManifestParseResult(source_type="poetry.lock", source_path=source_path)

    packages = []
    if tomllib is not None:
        try:
            data = tomllib.loads(content)
            raw_packages = data.get("package", [])
            if not isinstance(raw_packages, list):
                result.issues.append(ParseIssue(
                    message="poetry.lock 'package' field must be an array of tables",
                    issue_type="malformed"
                ))
                return result
            packages = raw_packages
        except Exception as te:
            result.issues.append(ParseIssue(
                message=f"Malformed TOML in poetry.lock: {te}",
                issue_type="malformed",
                raw=content[:200]
            ))
            return result
    else:
        packages = _parse_poetry_lock_simple_toml(content)

    for pkg in packages:
        if not isinstance(pkg, dict):
            result.issues.append(ParseIssue(
                message="Package record in poetry.lock must be a table",
                issue_type="malformed"
            ))
            continue

        name = pkg.get("name")
        if not name:
            result.issues.append(ParseIssue(
                message="Package record in poetry.lock missing required 'name' field",
                issue_type="missing_field"
            ))
            continue

        version = pkg.get("version")
        if not version:
            result.issues.append(ParseIssue(
                message=f"Package record '{name}' in poetry.lock missing required 'version' field",
                issue_type="missing_field"
            ))
            continue

        version_str = str(version).strip()
        category = pkg.get("category")
        groups = pkg.get("groups")
        group_str = category if category else (", ".join(groups) if isinstance(groups, list) else None)
        python_versions = pkg.get("python-versions")
        extras_dict = pkg.get("extras", {})
        extras_tuple = tuple(sorted(normalize_package_name(e) for e in extras_dict.keys())) if isinstance(extras_dict, dict) else ()

        norm_name = normalize_package_name(name)
        record = DependencyRecord(
            name=norm_name,
            version=version_str,
            version_specifier=f"=={version_str}",
            source=filename,
            pinned=True,
            environment_marker=str(python_versions) if python_versions else None,
            extras=extras_tuple,
            editable=False,
            group=group_str,
            raw=f'name = "{name}", version = "{version_str}"'
        )
        result.dependencies.append(record)

    return result


def _parse_poetry_dependency_dict(
    dep_dict: Dict[str, Any],
    filename: str,
    group: Optional[str],
    result: ManifestParseResult
) -> None:
    """Helper to parse a Poetry dependencies dictionary into DependencyRecords."""
    for pkg_name, constraint in dep_dict.items():
        if not isinstance(pkg_name, str) or not pkg_name.strip():
            result.issues.append(ParseIssue(
                message="Package name in poetry dependencies must be a non-empty string",
                issue_type="malformed",
                raw=str(pkg_name)
            ))
            continue

        raw_pkg = pkg_name.strip()
        norm_name = normalize_package_name(raw_pkg)

        # In Poetry, python is a runtime version constraint, not an installable package
        if norm_name == "python":
            result.ignored_directives.append(f"python = {constraint}")
            continue

        if isinstance(constraint, str):
            raw_ver = constraint.strip()
            pinned = False
            version_val = None
            spec_str = raw_ver

            if raw_ver.startswith("==") and not raw_ver.endswith(".*") and "*" not in raw_ver and "," not in raw_ver:
                pinned = True
                version_val = raw_ver[2:].strip()
            elif raw_ver and not any(op in raw_ver for op in ["<", ">", "=", "!", "~", "^", "*"]):
                # In Poetry, bare version "2.25.0" means exact pin
                pinned = True
                version_val = raw_ver
                spec_str = f"=={raw_ver}"

            record = DependencyRecord(
                name=norm_name,
                version=version_val,
                version_specifier=spec_str,
                source=filename,
                pinned=pinned,
                group=group,
                raw=f'{raw_pkg} = "{raw_ver}"'
            )
            result.dependencies.append(record)

        elif isinstance(constraint, dict):
            raw_ver = constraint.get("version")
            extras = constraint.get("extras", [])
            markers = constraint.get("markers") or constraint.get("python")
            extras_tuple = tuple(sorted(normalize_package_name(e) for e in extras)) if isinstance(extras, list) else ()

            pinned = False
            version_val = None
            spec_str = None

            if raw_ver is not None:
                raw_ver_str = str(raw_ver).strip()
                spec_str = raw_ver_str
                if raw_ver_str.startswith("==") and not raw_ver_str.endswith(".*") and "*" not in raw_ver_str and "," not in raw_ver_str:
                    pinned = True
                    version_val = raw_ver_str[2:].strip()
                elif raw_ver_str and not any(op in raw_ver_str for op in ["<", ">", "=", "!", "~", "^", "*"]):
                    pinned = True
                    version_val = raw_ver_str
                    spec_str = f"=={raw_ver_str}"

            record = DependencyRecord(
                name=norm_name,
                version=version_val,
                version_specifier=spec_str,
                source=filename,
                pinned=pinned,
                environment_marker=str(markers) if markers else None,
                extras=extras_tuple,
                group=group,
                raw=f'{raw_pkg} = {json.dumps(constraint)}'
            )
            result.dependencies.append(record)

        else:
            result.issues.append(ParseIssue(
                message=f"Invalid dependency specification for '{raw_pkg}': {constraint}",
                issue_type="malformed",
                raw=f"{raw_pkg} = {constraint}"
            ))


def _parse_pep735_dependency_groups(
    dep_groups: Any,
    filename: str,
    result: ManifestParseResult
) -> None:
    """
    Parses and resolves PEP 735 [dependency-groups] with support for:
      - Group name normalization (PEP 503 / canonicalize_name)
      - Collision detection on normalized group names
      - Direct dependency specifiers (strings)
      - Dependency group includes: { "include-group": "<group>" }
      - Recursive includes
      - Cycle detection (2-level and multi-level)
      - Validation against unexpected keys or malformed tables
    """
    if not isinstance(dep_groups, dict):
        result.issues.append(ParseIssue(
            message="dependency-groups must be a table",
            issue_type="malformed",
            raw=str(dep_groups)[:100]
        ))
        return

    # Track normalized names to detect collisions
    normalized_names: Dict[str, str] = {}
    group_items_map: Dict[str, List[Any]] = {}

    for raw_name, items in dep_groups.items():
        if not isinstance(raw_name, str) or not raw_name.strip():
            result.issues.append(ParseIssue(
                message=f"dependency-groups key must be a non-empty string: {raw_name}",
                issue_type="malformed",
                raw=str(raw_name)
            ))
            continue

        norm_name = normalize_package_name(raw_name)
        if norm_name in normalized_names:
            first_raw = normalized_names[norm_name]
            result.issues.append(ParseIssue(
                message=f"Duplicate or colliding dependency-group name after normalization: '{raw_name}' collides with '{first_raw}'",
                issue_type="malformed",
                raw=raw_name
            ))
            continue
        normalized_names[norm_name] = raw_name

        if not isinstance(items, list):
            result.issues.append(ParseIssue(
                message=f"dependency-groups.{raw_name} must be a list",
                issue_type="malformed",
                raw=str(items)[:100]
            ))
            continue

        group_items_map[norm_name] = items

    parsed_group_items: Dict[str, List[Tuple[str, Any, Any]]] = {}

    for norm_grp, items in group_items_map.items():
        parsed_group_items[norm_grp] = []
        raw_grp_name = normalized_names[norm_grp]

        for item in items:
            if isinstance(item, str):
                clean = _strip_inline_comment(item)
                if clean:
                    parsed_group_items[norm_grp].append(("req", clean, item))
            elif isinstance(item, dict):
                if "include-group" not in item:
                    result.issues.append(ParseIssue(
                        message=f"Dictionary in dependency-groups.{raw_grp_name} missing 'include-group' key: {item}",
                        issue_type="malformed",
                        raw=str(item)
                    ))
                    continue
                if len(item) > 1:
                    result.issues.append(ParseIssue(
                        message=f"include-group table in dependency-groups.{raw_grp_name} contains unexpected keys (only 'include-group' is allowed): {item}",
                        issue_type="malformed",
                        raw=str(item)
                    ))
                    continue
                inc_target = item["include-group"]
                if not isinstance(inc_target, str) or not inc_target.strip():
                    result.issues.append(ParseIssue(
                        message=f"include-group target in dependency-groups.{raw_grp_name} must be a non-empty string: {inc_target}",
                        issue_type="malformed",
                        raw=str(item)
                    ))
                    continue
                norm_target = normalize_package_name(inc_target)
                parsed_group_items[norm_grp].append(("include", norm_target, inc_target))
            else:
                result.issues.append(ParseIssue(
                    message=f"Item in dependency-groups.{raw_grp_name} must be a string or include-group table: {item}",
                    issue_type="malformed",
                    raw=str(item)
                ))

    # Resolve each root group with active call-stack cycle detection.
    # In accordance with PEP 735, dependency duplication across includes or within
    # groups is strictly preserved (pure syntactic expansion without deduplication).
    for root_norm_grp in group_items_map.keys():
        root_raw_name = normalized_names[root_norm_grp]
        resolved_reqs: List[Tuple[str, str]] = []

        def dfs(current_norm: str, call_stack: List[str]) -> None:
            if current_norm in call_stack:
                cycle_str = " -> ".join([normalized_names.get(g, g) for g in call_stack] + [normalized_names.get(current_norm, current_norm)])
                result.issues.append(ParseIssue(
                    message=f"Circular dependency-group include detected: {cycle_str}",
                    issue_type="malformed",
                    raw=cycle_str
                ))
                return

            if current_norm not in group_items_map:
                result.issues.append(ParseIssue(
                    message=f"Included dependency group '{current_norm}' not found in dependency-groups",
                    issue_type="malformed",
                    raw=current_norm
                ))
                return

            next_stack = call_stack + [current_norm]
            for item_type, val1, val2 in parsed_group_items.get(current_norm, []):
                if item_type == "req":
                    resolved_reqs.append((val1, val2))
                elif item_type == "include":
                    dfs(val1, next_stack)

        dfs(root_norm_grp, [])

        for clean_line, raw_line in resolved_reqs:
            rec, issue = _parse_pep508_requirement(
                clean_line=clean_line,
                filename=filename,
                raw_line=raw_line,
                group=root_raw_name,
                line_number=None
            )
            if rec:
                result.dependencies.append(rec)
            if issue:
                result.issues.append(issue)


def parse_pyproject_toml(content_or_path: str, filename: str = "pyproject.toml") -> ManifestParseResult:
    """
    Deterministically parses a pyproject.toml document into normalized DependencyRecords.
    Supports:
      - PEP 621: [project.dependencies] and [project.optional-dependencies]
      - PEP 735: [dependency-groups]
      - Poetry: [tool.poetry.dependencies], [tool.poetry.dev-dependencies], and [tool.poetry.group.<name>.dependencies]
    """
    source_path = None
    if "\n" not in content_or_path and os.path.isfile(content_or_path):
        source_path = content_or_path
        filename = os.path.basename(content_or_path)
        with open(content_or_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    else:
        content = content_or_path

    result = ManifestParseResult(source_type="pyproject.toml", source_path=source_path)

    if tomllib is None:
        result.issues.append(ParseIssue(
            message="TOML parser unavailable (requires Python 3.11+ or tomli)",
            issue_type="malformed"
        ))
        return result

    try:
        data = tomllib.loads(content)
    except Exception as te:
        result.issues.append(ParseIssue(
            message=f"Malformed TOML in pyproject.toml: {te}",
            issue_type="malformed",
            raw=content[:200]
        ))
        return result

    if not isinstance(data, dict):
        result.issues.append(ParseIssue(
            message="pyproject.toml root must be a table",
            issue_type="malformed"
        ))
        return result

    # 1. PEP 621 Declarations: [project]
    project = data.get("project")
    if isinstance(project, dict):
        # [project.dependencies]
        deps = project.get("dependencies")
        if isinstance(deps, list):
            for dep_item in deps:
                if not isinstance(dep_item, str):
                    result.issues.append(ParseIssue(
                        message=f"Dependency item in project.dependencies must be string: {dep_item}",
                        issue_type="malformed",
                        raw=str(dep_item)
                    ))
                    continue
                clean = _strip_inline_comment(dep_item)
                if not clean:
                    continue
                rec, issue = _parse_pep508_requirement(
                    clean_line=clean,
                    filename=filename,
                    raw_line=dep_item,
                    group=None,
                    line_number=None
                )
                if rec:
                    result.dependencies.append(rec)
                if issue:
                    result.issues.append(issue)
        elif deps is not None:
            result.issues.append(ParseIssue(
                message="project.dependencies must be a list",
                issue_type="malformed",
                raw=str(deps)[:100]
            ))

        # [project.optional-dependencies]
        opt_deps = project.get("optional-dependencies")
        if isinstance(opt_deps, dict):
            for grp_name, grp_items in opt_deps.items():
                if isinstance(grp_items, list):
                    for dep_item in grp_items:
                        if not isinstance(dep_item, str):
                            result.issues.append(ParseIssue(
                                message=f"Dependency item in optional-dependencies.{grp_name} must be string: {dep_item}",
                                issue_type="malformed",
                                raw=str(dep_item)
                            ))
                            continue
                        clean = _strip_inline_comment(dep_item)
                        if not clean:
                            continue
                        rec, issue = _parse_pep508_requirement(
                            clean_line=clean,
                            filename=filename,
                            raw_line=dep_item,
                            group=grp_name,
                            line_number=None
                        )
                        if rec:
                            result.dependencies.append(rec)
                        if issue:
                            result.issues.append(issue)
                else:
                    result.issues.append(ParseIssue(
                        message=f"optional-dependencies.{grp_name} must be a list",
                        issue_type="malformed",
                        raw=str(grp_items)[:100]
                    ))
        elif opt_deps is not None:
            result.issues.append(ParseIssue(
                message="project.optional-dependencies must be a table",
                issue_type="malformed",
                raw=str(opt_deps)[:100]
            ))

    # PEP 735: [dependency-groups]
    if "dependency-groups" in data:
        dep_groups = data.get("dependency-groups")
        _parse_pep735_dependency_groups(dep_groups, filename, result)

    # 2. Poetry Declarations: [tool.poetry]
    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            # [tool.poetry.dependencies]
            p_deps = poetry.get("dependencies")
            if isinstance(p_deps, dict):
                _parse_poetry_dependency_dict(p_deps, filename, group="main", result=result)
            elif p_deps is not None:
                result.issues.append(ParseIssue(
                    message="tool.poetry.dependencies must be a table",
                    issue_type="malformed",
                    raw=str(p_deps)[:100]
                ))

            # [tool.poetry.dev-dependencies] (legacy)
            p_dev = poetry.get("dev-dependencies")
            if isinstance(p_dev, dict):
                _parse_poetry_dependency_dict(p_dev, filename, group="dev", result=result)
            elif p_dev is not None:
                result.issues.append(ParseIssue(
                    message="tool.poetry.dev-dependencies must be a table",
                    issue_type="malformed",
                    raw=str(p_dev)[:100]
                ))

            # [tool.poetry.group.<name>.dependencies]
            p_groups = poetry.get("group")
            if isinstance(p_groups, dict):
                for grp_name, grp_table in p_groups.items():
                    if isinstance(grp_table, dict):
                        sub_deps = grp_table.get("dependencies")
                        if isinstance(sub_deps, dict):
                            _parse_poetry_dependency_dict(sub_deps, filename, group=grp_name, result=result)
                        elif sub_deps is not None:
                            result.issues.append(ParseIssue(
                                message=f"tool.poetry.group.{grp_name}.dependencies must be a table",
                                issue_type="malformed",
                                raw=str(sub_deps)[:100]
                            ))

    return result


def detect_manifest_type(filename: str) -> Optional[str]:
    """Infers manifest type ('requirements.txt', 'Pipfile.lock', 'poetry.lock', 'pyproject.toml') from a filename."""
    base = os.path.basename(filename).lower()
    if "requirements" in base or base.endswith(".txt"):
        return "requirements.txt"
    if base == "pipfile.lock":
        return "Pipfile.lock"
    if base == "poetry.lock":
        return "poetry.lock"
    if base == "pyproject.toml":
        return "pyproject.toml"
    return None


def parse_manifest(file_path_or_content: str, manifest_type: Optional[str] = None, filename: Optional[str] = None) -> ManifestParseResult:
    """
    Unified entrypoint: Parses requirements.txt, Pipfile.lock, poetry.lock, or pyproject.toml.
    Infers manifest type from file path if manifest_type is omitted.
    """
    effective_name = filename or ("manifest" if "\n" in file_path_or_content else os.path.basename(file_path_or_content))
    mtype = manifest_type or detect_manifest_type(effective_name)

    if mtype == "requirements.txt":
        return parse_requirements_txt(file_path_or_content, filename=effective_name)
    elif mtype == "Pipfile.lock":
        return parse_pipfile_lock(file_path_or_content, filename=effective_name)
    elif mtype == "poetry.lock":
        return parse_poetry_lock(file_path_or_content, filename=effective_name)
    elif mtype == "pyproject.toml":
        return parse_pyproject_toml(file_path_or_content, filename=effective_name)
    else:
        # Fallback to requirements.txt
        return parse_requirements_txt(file_path_or_content, filename=effective_name)
