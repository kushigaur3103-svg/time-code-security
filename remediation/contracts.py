"""
TimeCodeSecurity (TCS) - Vector D Remediation Engine Contracts.
Defines immutable data models, state invariant validation, and semantic
remediation schemas for automated vulnerability patching and verification.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


class PatchStatus(str, Enum):
    """Execution status of an automated remediation patch."""
    SUCCESS = "SUCCESS"
    FAILED_SYNTAX = "FAILED_SYNTAX"
    FAILED_VERIFICATION = "FAILED_VERIFICATION"
    UNSUPPORTED_CWE = "UNSUPPORTED_CWE"


class RemediationRule(str, Enum):
    """Categorical AST rewrite rule identifiers."""
    SQLI_PARAMETERIZE = "SQLI_PARAMETERIZE"
    PATH_TRAVERSAL_RESOLVE = "PATH_TRAVERSAL_RESOLVE"
    CMD_INJECTION_SPLIT = "CMD_INJECTION_SPLIT"


@dataclass(frozen=True)
class RemediationRecord:
    """
    Immutable representation of an automated vulnerability remediation patch attempt.
    Enforces strict state invariants forbidding contradictory outcomes.
    """
    finding_id: str
    cwe: str
    remediation_rule: RemediationRule
    original_file: str
    line_number: int
    patch_status: PatchStatus
    original_code_snippet: str
    patched_code_snippet: str
    unified_diff: str
    verification_passed: bool
    limitations: Tuple[str, ...] = ()
    patched_source: Optional[str] = None

    def __post_init__(self):
        # Blocker 1 & Contract Validation: Type integrity
        if not isinstance(self.patch_status, PatchStatus):
            try:
                object.__setattr__(self, "patch_status", PatchStatus(self.patch_status))
            except (ValueError, TypeError) as err:
                raise ValueError(f"Invalid patch_status: {self.patch_status}") from err

        if not isinstance(self.remediation_rule, RemediationRule):
            try:
                object.__setattr__(self, "remediation_rule", RemediationRule(self.remediation_rule))
            except (ValueError, TypeError) as err:
                raise ValueError(f"Invalid remediation_rule: {self.remediation_rule}") from err

        # Blocker 2: State invariant enforcement - strictly forbid contradictory states
        if self.patch_status == PatchStatus.SUCCESS and not self.verification_passed:
            raise ValueError(
                "Contradictory state: patch_status SUCCESS requires verification_passed == True"
            )
        if self.patch_status in (
            PatchStatus.FAILED_SYNTAX,
            PatchStatus.FAILED_VERIFICATION,
            PatchStatus.UNSUPPORTED_CWE,
        ) and self.verification_passed:
            raise ValueError(
                f"Contradictory state: patch_status {self.patch_status.value} requires verification_passed == False"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the record to a standard JSON-compatible dictionary."""
        d = {
            "finding_id": self.finding_id,
            "cwe": self.cwe,
            "remediation_rule": self.remediation_rule.value if isinstance(self.remediation_rule, Enum) else str(self.remediation_rule),
            "original_file": self.original_file,
            "line_number": self.line_number,
            "patch_status": self.patch_status.value if isinstance(self.patch_status, Enum) else str(self.patch_status),
            "original_code_snippet": self.original_code_snippet,
            "patched_code_snippet": self.patched_code_snippet,
            "unified_diff": self.unified_diff,
            "verification_passed": self.verification_passed,
            "limitations": list(self.limitations),
        }
        if self.patched_source is not None:
            d["patched_source"] = self.patched_source
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RemediationRecord":
        """Deserializes a dictionary into a frozen RemediationRecord."""
        raw_status = data.get("patch_status", PatchStatus.UNSUPPORTED_CWE)
        status = PatchStatus(raw_status) if isinstance(raw_status, str) else raw_status

        raw_rule = data.get("remediation_rule")
        if not raw_rule:
            raise ValueError("Missing required 'remediation_rule' in RemediationRecord payload")
        rule = RemediationRule(raw_rule) if isinstance(raw_rule, str) else raw_rule

        return cls(
            finding_id=str(data["finding_id"]),
            cwe=str(data["cwe"]),
            remediation_rule=rule,
            original_file=str(data["original_file"]),
            line_number=int(data["line_number"]),
            patch_status=status,
            original_code_snippet=str(data.get("original_code_snippet", "")),
            patched_code_snippet=str(data.get("patched_code_snippet", "")),
            unified_diff=str(data.get("unified_diff", "")),
            verification_passed=bool(data.get("verification_passed", False)),
            limitations=tuple(data.get("limitations", ())),
            patched_source=data.get("patched_source"),
        )


# ======================================================================
# GOLDEN FIXTURE SEMANTIC CONTRACT REGISTRY (PHASE 2 ORACLE)
# ======================================================================

FIXTURE_SEMANTIC_CONTRACTS: Dict[str, Dict[str, Any]] = {
    "fixture_01_sqli_fstring": {
        "fixture_id": "fixture_01_sqli_fstring",
        "cwe": "CWE-89",
        "remediation_rule": RemediationRule.SQLI_PARAMETERIZE,
        "expected_security_property": "SQL data MUST NOT remain concatenated/interpolated into SQL text; user input is bound via driver placeholder tuple.",
        "input_ast_pattern": "ast.Call to cursor.execute where query argument is an ast.JoinedStr (f-string).",
        "vulnerable_sink": "cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")",
        "expected_ast_transformation": "Extract string constant literal fragments, replace formatted values ({username}) with driver placeholders (?), strip surrounding quotes from SQL text, and append tuple of interpolated expressions as second argument to cursor.execute.",
        "placeholder_style": "?",
        "parameter_ordering": "Positional tuple matches left-to-right order of ast.FormattedValue expressions in ast.JoinedStr.",
        "assumptions_and_limitations": [
            "Assumes SQLite parameter syntax '?'",
            "Does not support dynamic table/column identifiers via query parameters",
            "Only handles inline FormattedValue expressions"
        ]
    },
    "fixture_02_sqli_concat": {
        "fixture_id": "fixture_02_sqli_concat",
        "cwe": "CWE-89",
        "remediation_rule": RemediationRule.SQLI_PARAMETERIZE,
        "expected_security_property": "Dynamic concatenation operands are stripped from query string construction and bound as SQL query parameters.",
        "input_ast_pattern": "ast.BinOp(op=ast.Add()) constructing SQL query string passed to cursor.execute.",
        "vulnerable_sink": "cursor.execute(query) where query = '...' + str(order_id)",
        "expected_ast_transformation": "Decompose binary addition tree: replace dynamic operands (e.g. str(order_id) or order_id) with driver placeholder (?), strip surrounding quote delimiters if present, and bind dynamic operand expressions as a tuple argument to cursor.execute.",
        "operands_becoming_parameters": "Right-hand dynamic operand 'order_id' (with redundant type conversions unwrapped if present).",
        "assumptions_and_limitations": [
            "Operands must represent scalar data values, not SQL keywords or table names",
            "Preserves underlying operand evaluation order in parameter tuple"
        ]
    },
    "fixture_03_cmdi_shell_true": {
        "fixture_id": "fixture_03_cmdi_shell_true",
        "cwe": "CWE-78",
        "remediation_rule": RemediationRule.CMD_INJECTION_SPLIT,
        "expected_security_property": "Command execution bypasses system shell parser (/bin/sh or cmd.exe) by utilizing direct execve array invocation with shell=False.",
        "input_ast_pattern": "ast.Call to subprocess.{call,run,Popen,check_output} with keyword argument shell=ast.Constant(value=True).",
        "vulnerable_sink": "subprocess.call(cmd, shell=True)",
        "expected_ast_transformation": "Transform string command into structured argument list (via static tokenization or shlex.split), set keyword argument shell=False (or omit shell default).",
        "command_splitting_mechanism": "Decompose command string into argument list [executable, arg1, arg2, ...] while preserving argument boundaries so shell metacharacters (; | & ` $ ()) cannot alter execution topology.",
        "assumptions_and_limitations": [
            "Bypasses shell built-ins (cd, echo) which require explicit executable binaries",
            "Shell pipelines (|) or redirection (>, <) require multi-process piping or file descriptors"
        ]
    },
    "fixture_04_path_traversal_open": {
        "fixture_id": "fixture_04_path_traversal_open",
        "cwe": "CWE-22",
        "remediation_rule": RemediationRule.PATH_TRAVERSAL_RESOLVE,
        "expected_security_property": "Canonicalized target path is mathematically guaranteed to remain within the trusted base directory boundary via is_relative_to.",
        "input_ast_pattern": "ast.Call to open() or os.path operations concatenating untrusted filename to a base directory.",
        "vulnerable_sink": "open(base_dir + filename)",
        "expected_ast_transformation": "Resolve trusted base directory (Path(base_dir).resolve()), resolve candidate target path ((safe_base / filename).resolve()), and insert containment guard (if not target_path.is_relative_to(safe_base): raise ValueError).",
        "resolution_step": "Both base directory and target path are fully canonicalized with Path.resolve() to collapse symlinks and '..' traversal segments.",
        "containment_check": "target_path.is_relative_to(safe_base) verifies prefix containment.",
        "failure_behavior": "Explicitly raises ValueError or SecurityException when target path resolves outside trusted base directory boundary.",
        "assumptions_and_limitations": [
            "Requires Python 3.9+ for Path.is_relative_to",
            "Calling resolve() alone is insufficient without the containment check against safe_base"
        ]
    }
}
