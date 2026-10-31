"""Root `.tcs.yaml`: repository-level path exclusions and per-rule path overrides.

Schema (only these keys; anything else is rejected so a typo cannot silently exempt a tree):

    exclude_paths: ["tests/**", "docs/**"]
    rules:
      CWE-338:
        exclude: ["**/demo/**", "**/fixtures/**"]

Matching is segment-aware: `**` spans zero or more path segments, which fnmatch cannot
express because its `*` already swallows `/`. A pattern with no `/` matches any single path
segment, mirroring `--exclude` (`tests` hits `a/tests/b.py`).

The file is read from the working directory and only when it exists, so a scan without
`.tcs.yaml` behaves exactly as it did before this module existed.
"""

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Dict, List, Optional, Tuple

CONFIG_FILENAME = ".tcs.yaml"
_ALLOWED_TOP_LEVEL = frozenset({"exclude_paths", "rules"})
_ALLOWED_RULE_KEYS = frozenset({"exclude"})


def _normalize_pattern(pattern: str) -> str:
    text = str(pattern).replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text.strip("/")


def _segments(text: str) -> List[str]:
    return [part for part in text.split("/") if part not in ("", ".")]


def _match_parts(path_parts: List[str], pattern_parts: List[str]) -> bool:
    if not pattern_parts:
        return not path_parts
    head = pattern_parts[0]
    if head == "**":
        return _match_parts(path_parts, pattern_parts[1:]) or (
            bool(path_parts) and _match_parts(path_parts[1:], pattern_parts))
    if not path_parts:
        return False
    if not fnmatchcase(path_parts[0], head):
        return False
    return _match_parts(path_parts[1:], pattern_parts[1:])


def path_matches(path_key: str, pattern: str) -> bool:
    """True when `path_key` is selected by one `.tcs.yaml` glob."""
    normalized = _normalize_pattern(pattern)
    if not normalized:
        return False
    parts = _segments(str(path_key).replace("\\", "/"))
    if "/" not in normalized:
        return any(fnmatchcase(part, normalized) for part in parts)
    return _match_parts(parts, _segments(normalized))


def normalize_rule_id(value: str) -> Optional[str]:
    text = str(value).strip().upper()
    if text.startswith("CWE-") and text[4:].isdigit():
        return text
    if text.startswith("CWE") and text[3:].strip("-").isdigit():
        return f"CWE-{text[3:].strip('-')}"
    if text.isdigit():
        return f"CWE-{text}"
    return None


@dataclass(frozen=True)
class TcsConfig:
    exclude_paths: Tuple[str, ...] = ()
    rule_excludes: Dict[str, Tuple[str, ...]] = field(default_factory=dict)

    def excludes_path(self, path_key: str) -> bool:
        return any(path_matches(path_key, pattern) for pattern in self.exclude_paths)

    def rule_excluded(self, cwe: str, path_key: str) -> bool:
        patterns = self.rule_excludes.get(str(cwe).upper())
        if not patterns:
            return False
        return any(path_matches(path_key, pattern) for pattern in patterns)


def _string_list(value, where: str) -> Tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Invalid {CONFIG_FILENAME}: {where} must be a list of strings")
    return tuple(item for item in value if item.strip())


def load_config(directory: Optional[Path] = None) -> Optional[TcsConfig]:
    """Return the parsed `.tcs.yaml` in `directory`, or None when the file is absent.

    A malformed file raises ValueError: an exclusion the user wrote but the scanner
    ignored would overstate coverage, which is the same harm as a missed finding.
    """
    base = Path(directory) if directory is not None else Path.cwd()
    path = base / CONFIG_FILENAME
    if not path.is_file():
        return None
    try:
        import yaml
    except ImportError as exc:
        raise ValueError(f"{CONFIG_FILENAME} present but PyYAML is not installed") from exc

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid {CONFIG_FILENAME}: {exc}") from exc

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError(f"Invalid {CONFIG_FILENAME}: top level must be a mapping")
    unknown = sorted(set(data) - _ALLOWED_TOP_LEVEL)
    if unknown:
        raise ValueError(f"Invalid {CONFIG_FILENAME}: unknown key(s) {unknown}")

    exclude_paths = _string_list(data.get("exclude_paths"), "exclude_paths")

    rules_raw = data.get("rules") or {}
    if not isinstance(rules_raw, dict):
        raise ValueError(f"Invalid {CONFIG_FILENAME}: rules must be a mapping")
    rule_excludes: Dict[str, Tuple[str, ...]] = {}
    for rule_id, body in rules_raw.items():
        cwe = normalize_rule_id(rule_id)
        if cwe is None:
            raise ValueError(f"Invalid {CONFIG_FILENAME}: {rule_id!r} is not a CWE id")
        if not isinstance(body, dict):
            raise ValueError(f"Invalid {CONFIG_FILENAME}: rules.{rule_id} must be a mapping")
        unknown_rule = sorted(set(body) - _ALLOWED_RULE_KEYS)
        if unknown_rule:
            raise ValueError(
                f"Invalid {CONFIG_FILENAME}: unknown key(s) {unknown_rule} under rules.{rule_id}")
        rule_excludes[cwe] = _string_list(body.get("exclude"), f"rules.{rule_id}.exclude")

    return TcsConfig(exclude_paths=exclude_paths, rule_excludes=rule_excludes)
