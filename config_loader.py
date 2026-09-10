"""
TimeCodeSecurity (TCS) Configuration Loader.
Loads, validates, and manages .tcs.yml configuration objects with strict schema
validation, deterministic error handling, and immutable configuration structures.
"""

from __future__ import annotations
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Set, FrozenSet, Dict, Any, List, Union
import yaml

SUPPORTED_RULES: FrozenSet[str] = frozenset({
    "CWE-22",
    "CWE-78",
    "CWE-89",
    "CWE-95",
    "CWE-502",
    "CWE-1336"
})

SUPPORTED_FORMATS: FrozenSet[str] = frozenset({"table", "json", "sarif"})
SUPPORTED_VERSION: int = 1


class ConfigValidationError(Exception):
    """Raised when .tcs.yml fails syntax, structure, or policy validation."""
    pass


@dataclass(frozen=True)
class RulesConfig:
    enabled: FrozenSet[str]
    disabled: FrozenSet[str]


@dataclass(frozen=True)
class ScanConfig:
    sca: bool
    secrets: bool


@dataclass(frozen=True)
class SuppressionConfig:
    enabled: bool


@dataclass(frozen=True)
class OutputConfig:
    format: str


@dataclass(frozen=True)
class TCSConfig:
    version: int
    rules: RulesConfig
    scan: ScanConfig
    suppression: SuppressionConfig
    output: OutputConfig
    config_path: Optional[str] = None

    @property
    def effective_rules(self) -> FrozenSet[str]:
        """
        Derives the effective set of active rules:
        - If enabled is empty, start with all known SUPPORTED_RULES.
        - If enabled is populated, start only with enabled rules.
        - Subtract disabled rules.
        """
        base_set = self.rules.enabled if self.rules.enabled else SUPPORTED_RULES
        return base_set - self.rules.disabled

    def is_rule_enabled(self, cwe_id: str) -> bool:
        """Check whether a specific CWE is active under this configuration."""
        norm_cwe = cwe_id.strip().upper()
        return norm_cwe in self.effective_rules


DEFAULT_CONFIG: TCSConfig = TCSConfig(
    version=SUPPORTED_VERSION,
    rules=RulesConfig(
        enabled=frozenset(),
        disabled=frozenset()
    ),
    scan=ScanConfig(
        sca=False,
        secrets=False
    ),
    suppression=SuppressionConfig(
        enabled=True
    ),
    output=OutputConfig(
        format="table"
    ),
    config_path=None
)


def parse_config(raw_yaml: str, config_path: Optional[str] = None) -> TCSConfig:
    """
    Parses and strictly validates a raw YAML configuration string against schema v1.
    """
    try:
        data = yaml.safe_load(raw_yaml)
    except Exception as e:
        raise ConfigValidationError(f"Malformed YAML in configuration: {e}")

    if data is None:
        raise ConfigValidationError("Configuration root must be a mapping/dictionary, got empty document.")

    if not isinstance(data, dict):
        raise ConfigValidationError(f"Configuration root must be a mapping/dictionary, got {type(data).__name__}.")

    # 1. Top-Level Keys
    allowed_top_keys = {"version", "rules", "scan", "suppression", "output"}
    unknown_top_keys = set(data.keys()) - allowed_top_keys
    if unknown_top_keys:
        raise ConfigValidationError(f"Unknown top-level configuration key(s): {sorted(unknown_top_keys)}")

    # 2. Version
    if "version" not in data:
        raise ConfigValidationError("Missing required 'version' field in configuration.")

    ver = data["version"]
    if type(ver) is not int or ver != SUPPORTED_VERSION:
        raise ConfigValidationError(
            f"Unsupported configuration version: {ver!r}. Only version {SUPPORTED_VERSION} is supported."
        )

    # 3. Rules Section
    raw_rules = data.get("rules", {})
    if raw_rules is None:
        raw_rules = {}
    elif not isinstance(raw_rules, dict):
        raise ConfigValidationError(f"'rules' section must be a mapping, got {type(raw_rules).__name__}.")

    allowed_rules_keys = {"enabled", "disabled"}
    unknown_rules_keys = set(raw_rules.keys()) - allowed_rules_keys
    if unknown_rules_keys:
        raise ConfigValidationError(f"Unknown key(s) in 'rules' section: {sorted(unknown_rules_keys)}")

    # 3a. Enabled rules
    raw_enabled = raw_rules.get("enabled", [])
    if raw_enabled is None:
        raw_enabled = []
    elif not isinstance(raw_enabled, list):
        raise ConfigValidationError(f"'rules.enabled' must be a list, got {type(raw_enabled).__name__}.")

    enabled_set: Set[str] = set()
    for item in raw_enabled:
        if not isinstance(item, str):
            raise ConfigValidationError(
                f"Invalid rule identifier type in 'rules.enabled': expected string, got {type(item).__name__}."
            )
        norm_id = item.strip().upper()
        if norm_id not in SUPPORTED_RULES:
            raise ConfigValidationError(
                f"Unknown rule identifier in 'rules.enabled': '{item}'. Supported rules: {sorted(SUPPORTED_RULES)}"
            )
        enabled_set.add(norm_id)

    # 3b. Disabled rules
    raw_disabled = raw_rules.get("disabled", [])
    if raw_disabled is None:
        raw_disabled = []
    elif not isinstance(raw_disabled, list):
        raise ConfigValidationError(f"'rules.disabled' must be a list, got {type(raw_disabled).__name__}.")

    disabled_set: Set[str] = set()
    for item in raw_disabled:
        if not isinstance(item, str):
            raise ConfigValidationError(
                f"Invalid rule identifier type in 'rules.disabled': expected string, got {type(item).__name__}."
            )
        norm_id = item.strip().upper()
        if norm_id not in SUPPORTED_RULES:
            raise ConfigValidationError(
                f"Unknown rule identifier in 'rules.disabled': '{item}'. Supported rules: {sorted(SUPPORTED_RULES)}"
            )
        disabled_set.add(norm_id)

    # 3c. Contradiction Check
    overlap = enabled_set & disabled_set
    if overlap:
        raise ConfigValidationError(
            f"Contradictory rule configuration: Rule(s) {sorted(overlap)} cannot be present in both 'enabled' and 'disabled'."
        )

    # 4. Scan Section
    raw_scan = data.get("scan", {})
    if raw_scan is None:
        raw_scan = {}
    elif not isinstance(raw_scan, dict):
        raise ConfigValidationError(f"'scan' section must be a mapping, got {type(raw_scan).__name__}.")

    allowed_scan_keys = {"sca", "secrets"}
    unknown_scan_keys = set(raw_scan.keys()) - allowed_scan_keys
    if unknown_scan_keys:
        raise ConfigValidationError(f"Unknown key(s) in 'scan' section: {sorted(unknown_scan_keys)}")

    sca_val = raw_scan.get("sca", False)
    if not isinstance(sca_val, bool):
        raise ConfigValidationError(f"'scan.sca' must be a boolean (true/false), got {type(sca_val).__name__}.")

    secrets_val = raw_scan.get("secrets", False)
    if not isinstance(secrets_val, bool):
        raise ConfigValidationError(f"'scan.secrets' must be a boolean (true/false), got {type(secrets_val).__name__}.")

    # 5. Suppression Section
    raw_supp = data.get("suppression", {})
    if raw_supp is None:
        raw_supp = {}
    elif not isinstance(raw_supp, dict):
        raise ConfigValidationError(f"'suppression' section must be a mapping, got {type(raw_supp).__name__}.")

    allowed_supp_keys = {"enabled"}
    unknown_supp_keys = set(raw_supp.keys()) - allowed_supp_keys
    if unknown_supp_keys:
        raise ConfigValidationError(f"Unknown key(s) in 'suppression' section: {sorted(unknown_supp_keys)}")

    supp_val = raw_supp.get("enabled", True)
    if not isinstance(supp_val, bool):
        raise ConfigValidationError(f"'suppression.enabled' must be a boolean (true/false), got {type(supp_val).__name__}.")

    # 6. Output Section
    raw_output = data.get("output", {})
    if raw_output is None:
        raw_output = {}
    elif not isinstance(raw_output, dict):
        raise ConfigValidationError(f"'output' section must be a mapping, got {type(raw_output).__name__}.")

    allowed_output_keys = {"format"}
    unknown_output_keys = set(raw_output.keys()) - allowed_output_keys
    if unknown_output_keys:
        raise ConfigValidationError(f"Unknown key(s) in 'output' section: {sorted(unknown_output_keys)}")

    fmt_val = raw_output.get("format", "table")
    if not isinstance(fmt_val, str) or fmt_val.lower() not in SUPPORTED_FORMATS:
        raise ConfigValidationError(
            f"Invalid 'output.format': {fmt_val!r}. Supported formats are: {sorted(SUPPORTED_FORMATS)}"
        )

    return TCSConfig(
        version=ver,
        rules=RulesConfig(
            enabled=frozenset(enabled_set),
            disabled=frozenset(disabled_set)
        ),
        scan=ScanConfig(
            sca=sca_val,
            secrets=secrets_val
        ),
        suppression=SuppressionConfig(
            enabled=supp_val
        ),
        output=OutputConfig(
            format=fmt_val.lower()
        ),
        config_path=config_path
    )


def load_config(
    path: Optional[Union[str, Path]] = None,
    base_dir: Optional[Union[str, Path]] = None
) -> TCSConfig:
    """
    Loads and validates configuration.
    - If `path` is specified: loads that exact file or raises ConfigValidationError if missing.
    - If `path` is None: looks for `./.tcs.yml` under `base_dir` (or cwd). Returns DEFAULT_CONFIG if absent.
    """
    if path is not None:
        p = Path(path).resolve()
        if not p.exists() or not p.is_file():
            raise ConfigValidationError(f"Configuration file not found: {path}")
        try:
            content = p.read_text(encoding="utf-8")
        except Exception as e:
            raise ConfigValidationError(f"Unable to read configuration file '{path}': {e}")
        return parse_config(content, config_path=str(p))

    # Default discovery: look for .tcs.yml in base_dir or cwd
    base = Path(base_dir).resolve() if base_dir is not None else Path.cwd().resolve()
    default_config_file = base / ".tcs.yml"
    if default_config_file.exists() and default_config_file.is_file():
        try:
            content = default_config_file.read_text(encoding="utf-8")
        except Exception as e:
            raise ConfigValidationError(f"Unable to read configuration file '{default_config_file}': {e}")
        return parse_config(content, config_path=str(default_config_file))

    return DEFAULT_CONFIG
