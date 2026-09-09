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
from typing import Dict, List, Optional, Tuple, Any

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
                    group=None,
                    raw=stripped,
                    line_number=idx
                )
                result.dependencies.append(record)
                continue
            except Exception as pe:
                result.issues.append(ParseIssue(
                    message=f"Malformed requirement: {pe}",
                    line_number=idx,
                    raw=stripped,
                    issue_type="malformed"
                ))
                continue
        else:
            # Pure-Python regex fallback if packaging library is absent
            req_match = re.match(
                r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
                r"(?:\[([^\]]+)\])?"
                r"(?:\s*([~!=><~=]+[^;]+))?"
                r"(?:\s*;\s*(.+))?$",
                clean_line
            )
            if not req_match:
                result.issues.append(ParseIssue(
                    message="Malformed requirement line syntax",
                    line_number=idx,
                    raw=stripped,
                    issue_type="malformed"
                ))
                continue

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
                group=None,
                raw=stripped,
                line_number=idx
            )
            result.dependencies.append(record)

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


def detect_manifest_type(filename: str) -> Optional[str]:
    """Infers manifest type ('requirements.txt', 'Pipfile.lock', 'poetry.lock') from a filename."""
    base = os.path.basename(filename).lower()
    if "requirements" in base or base.endswith(".txt"):
        return "requirements.txt"
    if base == "pipfile.lock":
        return "Pipfile.lock"
    if base == "poetry.lock":
        return "poetry.lock"
    return None


def parse_manifest(file_path_or_content: str, manifest_type: Optional[str] = None, filename: Optional[str] = None) -> ManifestParseResult:
    """
    Unified entrypoint: Parses requirements.txt, Pipfile.lock, or poetry.lock.
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
    else:
        # Fallback to requirements.txt
        return parse_requirements_txt(file_path_or_content, filename=effective_name)
