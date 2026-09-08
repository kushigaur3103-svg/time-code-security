"""
TimeCodeSecurity (TCS) Rule Engine.
Defines typed SecurityRule representations and provides declarative rule matching,
safety evaluation, remediation, and severity mappings.
"""

from __future__ import annotations
import ast
from dataclasses import dataclass, field
from typing import Callable, Optional, Dict, Any, List, Set


@dataclass(frozen=True)
class SecurityRule:
    cwe_id: str
    name: str
    category: str
    operation: str
    confirmed_severity: str
    potential_severity: str
    remediation: str
    sarif_metadata: Dict[str, Any] = field(default_factory=dict)
    sink_matcher: Optional[Callable[[ast.AST, str, Optional[str]], bool]] = None
    safety_filter: Optional[Callable[[ast.Call, str], bool]] = None

    def matches_sink(self, node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
        if self.sink_matcher:
            return self.sink_matcher(node, name, canon_name)
        return False

    def is_safe(self, node: ast.Call, sink_name: str) -> bool:
        if self.safety_filter:
            return self.safety_filter(node, sink_name)
        return False

    def get_severity(self, confidence_label: str) -> str:
        if confidence_label == "CONFIRMED":
            return self.confirmed_severity
        return self.potential_severity


class RuleRegistry:
    def __init__(self):
        self._rules: Dict[str, SecurityRule] = {}

    def register(self, rule: SecurityRule) -> None:
        self._rules[rule.cwe_id] = rule

    def get_rule(self, cwe_id: str) -> Optional[SecurityRule]:
        return self._rules.get(cwe_id)

    def match_sink(self, node: ast.AST, name: str, canon_name: Optional[str] = None) -> Optional[SecurityRule]:
        for rule in self._rules.values():
            if rule.matches_sink(node, name, canon_name):
                return rule
        return None

    def check_safety(self, node: ast.Call, sink_name: str) -> bool:
        for rule in self._rules.values():
            if rule.is_safe(node, sink_name):
                return True
        return False

    def all_rules(self) -> List[SecurityRule]:
        return list(self._rules.values())


# ==============================================================================
# CWE-89 (SQL Injection) Pilot Rule Implementation
# ==============================================================================

def _cwe89_sink_matcher(node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
    """Matches method calls ending with .execute (e.g. cursor.execute, db.execute)."""
    if name and name.endswith(".execute"):
        return True
    if canon_name and canon_name.endswith(".execute"):
        return True
    return False


def _cwe89_safety_filter(node: ast.Call, sink_name: str) -> bool:
    """
    Exempts parameterized queries: calls to .execute with > 1 argument or keyword bindings.
    """
    if sink_name and sink_name.endswith(".execute"):
        if len(node.args) > 1 or getattr(node, "keywords", []):
            return True
    return False


CWE_89_RULE = SecurityRule(
    cwe_id="CWE-89",
    name="SqlInjection",
    category="SQL_INJECTION",
    operation="SQL_EXECUTION",
    confirmed_severity="HIGH",
    potential_severity="MEDIUM",
    remediation="Use parameterized SQL queries with bind variables instead of string concatenation/formatting, e.g., cursor.execute('SELECT * FROM tbl WHERE id = ?', (user_id,)).",
    sarif_metadata={
        "id": "CWE-89",
        "name": "SqlInjection",
        "shortDescription": {
            "text": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
        },
        "fullDescription": {
            "text": "The software constructs an SQL command using untrusted input from an upstream component without parameterization or proper escaping, allowing arbitrary SQL execution."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/89.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "8.5",
            "tags": ["security", "external/cwe/cwe-89"]
        }
    },
    sink_matcher=_cwe89_sink_matcher,
    safety_filter=_cwe89_safety_filter
)

# ==============================================================================
# CWE-95 (Code Execution / eval & exec) Rule Implementation
# ==============================================================================

def _cwe95_sink_matcher(node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
    """Matches direct and qualified calls to eval and exec."""
    candidates = {c for c in (name, canon_name) if c}
    return any(c in ("eval", "exec", "builtins.eval", "builtins.exec") for c in candidates)


CWE_95_RULE = SecurityRule(
    cwe_id="CWE-95",
    name="CodeExecution",
    category="CODE_EXECUTION",
    operation="ARBITRARY_CODE_EXECUTION",
    confirmed_severity="CRITICAL",
    potential_severity="HIGH",
    remediation="Avoid passing untrusted input to eval(). Use ast.literal_eval() for parsing Python literals, or parse structured data using json.loads().",
    sarif_metadata={
        "id": "CWE-95",
        "name": "CodeExecution",
        "shortDescription": {
            "text": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"
        },
        "fullDescription": {
            "text": "The software receives input from an upstream source and executes it via eval() or exec() without proper sanitization, allowing arbitrary code execution."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/95.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "9.8",
            "tags": ["security", "external/cwe/cwe-95"]
        }
    },
    sink_matcher=_cwe95_sink_matcher,
    safety_filter=None
)

# ==============================================================================
# CWE-78 (Command Injection / os.system & subprocess.*) Rule Implementation
# ==============================================================================

CWE78_SINKS = {
    "os.system",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
}


def _cwe78_sink_matcher(node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
    """Matches direct and qualified calls to os.system and subprocess execution functions."""
    candidates = {c for c in (name, canon_name) if c}
    return bool(candidates & CWE78_SINKS)


def _cwe78_safety_filter(node: ast.Call, sink_name: str) -> bool:
    """
    Exempts subprocess invocations using shell=False or argument list without shell=True.
    os.system always executes via shell and is never exempted.
    """
    if sink_name in ("subprocess.run", "subprocess.call", "subprocess.Popen"):
        shell_kw = next((kw.value.value for kw in getattr(node, 'keywords', []) if kw.arg == "shell" and isinstance(kw.value, ast.Constant)), None)
        if shell_kw is False:
            return True
        if shell_kw is None and node.args and isinstance(node.args[0], ast.List):
            return True
    return False


CWE_78_RULE = SecurityRule(
    cwe_id="CWE-78",
    name="CommandInjection",
    category="COMMAND_INJECTION",
    operation="OS_COMMAND_EXECUTION",
    confirmed_severity="CRITICAL",
    potential_severity="HIGH",
    remediation="Avoid shell execution with dynamic input. Use subprocess.run() with an argument list and shell=False, e.g., subprocess.run(['cmd', arg], shell=False).",
    sarif_metadata={
        "id": "CWE-78",
        "name": "CommandInjection",
        "shortDescription": {
            "text": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
        },
        "fullDescription": {
            "text": "The software executes an OS command using untrusted input without proper neutralization, allowing attackers to execute arbitrary system commands."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/78.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "9.5",
            "tags": ["security", "external/cwe/cwe-78"]
        }
    },
    sink_matcher=_cwe78_sink_matcher,
    safety_filter=_cwe78_safety_filter
)

# ==============================================================================
# CWE-22 (Path Traversal / open & pathlib.Path) Rule Implementation
# ==============================================================================

CWE22_BUILTIN_SINKS = {"open", "builtins.open"}
CWE22_PATH_ATTRS = {"read_text", "read_bytes", "write_text", "write_bytes"}


def _cwe22_sink_matcher(node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
    """Matches direct/qualified calls to open() and pathlib.Path file I/O attributes."""
    candidates = {c for c in (name, canon_name) if c}
    if any(c in CWE22_BUILTIN_SINKS for c in candidates):
        # Exclude method calls like arbitrary_object.open()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            return False
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in CWE22_PATH_ATTRS:
            return True
    return False


CWE_22_RULE = SecurityRule(
    cwe_id="CWE-22",
    name="PathTraversal",
    category="PATH_TRAVERSAL",
    operation="FILE_ACCESS",
    confirmed_severity="HIGH",
    potential_severity="MEDIUM",
    remediation="Validate and sanitize file paths using secure_path_join() or verify containment with os.path.abspath / pathlib.Path.resolve() against an allowed base directory.",
    sarif_metadata={
        "id": "CWE-22",
        "name": "PathTraversal",
        "shortDescription": {
            "text": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
        },
        "fullDescription": {
            "text": "The software uses external input to construct a pathname without sufficient validation or containment checking, resolving to locations outside intended directories."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/22.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "7.5",
            "tags": ["security", "external/cwe/cwe-22"]
        }
    },
    sink_matcher=_cwe22_sink_matcher,
    safety_filter=None
)

# ==============================================================================
# CWE-502 (Unsafe Deserialization / pickle.*) Rule Implementation
# ==============================================================================

CWE502_SINKS = {
    "pickle.loads",
    "pickle.load",
    "_pickle.loads",
    "_pickle.load",
}


def _cwe502_sink_matcher(node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
    """Matches direct and qualified calls to pickle.loads, pickle.load, and _pickle variants."""
    candidates = {c for c in (name, canon_name) if c}
    return bool(candidates & CWE502_SINKS)


CWE_502_RULE = SecurityRule(
    cwe_id="CWE-502",
    name="UnsafeDeserialization",
    category="UNSAFE_DESERIALIZATION",
    operation="DESERIALIZATION",
    confirmed_severity="CRITICAL",
    potential_severity="HIGH",
    remediation="Do not deserialize untrusted data with pickle. Use safe serialization formats such as JSON (json.loads), Protocol Buffers, or messagepack.",
    sarif_metadata={
        "id": "CWE-502",
        "name": "UnsafeDeserialization",
        "shortDescription": {
            "text": "Deserialization of Untrusted Data"
        },
        "fullDescription": {
            "text": "The application deserializes untrusted data using pickle without verifying its validity, enabling arbitrary object instantiation and code execution."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/502.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "9.8",
            "tags": ["security", "external/cwe/cwe-502"]
        }
    },
    sink_matcher=_cwe502_sink_matcher,
    safety_filter=None
)

# ==============================================================================
# CWE-1336 (Server-Side Template Injection) Rule Implementation
# ==============================================================================

CWE1336_DIRECT_SINKS = {
    "render_template_string",
    "flask.render_template_string",
}


def _cwe1336_sink_matcher(node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
    """Matches direct render_template_string calls and template .render() attribute calls."""
    candidates = {c for c in (name, canon_name) if c}

    # Dynamic attribute method call: template.render(...)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "render":
        return True

    # Direct function calls or qualified calls on flask module
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            return bool(candidates & CWE1336_DIRECT_SINKS)
        elif isinstance(node.func, ast.Attribute):
            if "flask.render_template_string" in candidates:
                return True
            # Reject arbitrary method calls like SomeClass().render_template_string
            return False

    return bool(candidates & CWE1336_DIRECT_SINKS)


CWE_1336_RULE = SecurityRule(
    cwe_id="CWE-1336",
    name="ServerSideTemplateInjection",
    category="TEMPLATE_INJECTION",
    operation="TEMPLATE_RENDERING",
    confirmed_severity="CRITICAL",
    potential_severity="HIGH",
    remediation="Avoid passing user input directly into render_template_string(). Use standard render_template() with parameterized template context variables to enforce auto-escaping.",
    sarif_metadata={
        "id": "CWE-1336",
        "name": "ServerSideTemplateInjection",
        "shortDescription": {
            "text": "Improper Neutralization of Special Elements Used in a Template Engine ('Server-Side Template Injection')"
        },
        "fullDescription": {
            "text": "The application passes untrusted user input directly into template constructors or render_template_string, allowing attackers to inject template directives and achieve arbitrary code execution."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/1336.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "9.0",
            "tags": ["security", "external/cwe/cwe-1336"]
        }
    },
    sink_matcher=_cwe1336_sink_matcher,
    safety_filter=None
)

# Global Registry instance initialized with migrated security rules
GLOBAL_RULE_REGISTRY = RuleRegistry()
GLOBAL_RULE_REGISTRY.register(CWE_89_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_95_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_78_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_22_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_502_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_1336_RULE)


def get_rule(cwe_id: str) -> Optional[SecurityRule]:
    return GLOBAL_RULE_REGISTRY.get_rule(cwe_id)


def match_sink_rule(node: ast.AST, name: str, canon_name: Optional[str] = None) -> Optional[SecurityRule]:
    return GLOBAL_RULE_REGISTRY.match_sink(node, name, canon_name)


def check_sink_safety_rules(node: ast.Call, sink_name: str) -> bool:
    return GLOBAL_RULE_REGISTRY.check_safety(node, sink_name)
