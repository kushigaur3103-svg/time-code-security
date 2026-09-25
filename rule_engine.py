"""
TimeCodeSecurity (TCS) Rule Engine.
Defines typed SecurityRule representations and provides declarative rule matching,
safety evaluation, remediation, and severity mappings.
"""

from __future__ import annotations
import ast
import importlib.util
import os
from dataclasses import dataclass, field
from typing import Callable, Optional, Dict, Any, List, Set


def _load_master_rules_bank():
    """Load master_rules_bank.py from the repository root (pure-data module).

    Returns None on any failure so production imports never break if the bank
    file is absent; the merge below is then simply a no-op.
    """
    path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "master_rules_bank.py"
    )
    try:
        spec = importlib.util.spec_from_file_location("_tcs_master_rules_bank", path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


_MASTER_RULES_BANK = _load_master_rules_bank()

try:
    import yaml
except ImportError:
    yaml = None


def load_yaml_rules(rules_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """Safely loads declarative security rules from YAML files (Semgrep-style).

    FALLBACK INVARIANT:
    If YAML files are missing, unreadable, or yaml module is unavailable,
    falls back cleanly to native internal dictionaries without raising exceptions.
    """
    if yaml is None:
        return []

    if rules_dir is None:
        rules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")

    if not os.path.isdir(rules_dir):
        return []

    loaded_rules: List[Dict[str, Any]] = []
    try:
        rule_files = sorted(
            f for f in os.listdir(rules_dir)
            if f.endswith(".yaml") or f.endswith(".yml")
        )
    except Exception:
        return []

    for fname in rule_files:
        fpath = os.path.join(rules_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as rf:
                content = yaml.safe_load(rf)
                if isinstance(content, dict):
                    if "id" in content and "cwe" in content and "sinks" in content:
                        loaded_rules.append(content)
                elif isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and "id" in item and "cwe" in item and "sinks" in item:
                            loaded_rules.append(item)
        except Exception:
            continue

    return loaded_rules


# Global cached declarative rules
DECLARATIVE_YAML_RULES: List[Dict[str, Any]] = load_yaml_rules()
DECLARATIVE_RULES_BY_CWE: Dict[str, Dict[str, Any]] = {
    r["cwe"]: r for r in DECLARATIVE_YAML_RULES if "cwe" in r
}
DECLARATIVE_RULES_BY_ID: Dict[str, Dict[str, Any]] = {
    r["id"]: r for r in DECLARATIVE_YAML_RULES if "id" in r
}


def get_declarative_rule(cwe_or_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a declarative rule dictionary by CWE ID or Rule ID."""
    return DECLARATIVE_RULES_BY_CWE.get(cwe_or_id) or DECLARATIVE_RULES_BY_ID.get(cwe_or_id)



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
    """Matches method calls for SQL execution (execute, raw, extra, RawSQL)."""
    target_names = {"execute", "raw", "extra", "RawSQL"}
    if "CWE-89" in DECLARATIVE_RULES_BY_CWE:
        target_names = target_names | {str(s) for s in DECLARATIVE_RULES_BY_CWE["CWE-89"].get("sinks", []) if s}
    for candidate in (name, canon_name):
        if candidate:
            if candidate in target_names or any(candidate.endswith(f".{t}") for t in target_names):
                return True
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr in target_names:
            return True
        if isinstance(node.func, ast.Name) and node.func.id in target_names:
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            val = node.func.value
            while isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute):
                if val.func.attr == "cursor":
                    return True
                val = val.func.value
    return False


def _cwe89_safety_filter(node: ast.Call, sink_name: str) -> bool:
    """
    Exempts parameterized queries: calls to .execute with > 1 argument or keyword bindings,
    or .raw with params, or RawSQL with params.
    """
    if sink_name:
        if sink_name.endswith(".execute") or sink_name == "execute":
            if len(node.args) > 1 or getattr(node, "keywords", []):
                return True
        if sink_name.endswith(".raw") or sink_name == "raw":
            if len(node.args) > 1 or any(kw.arg == "params" for kw in getattr(node, "keywords", [])):
                return True
        if sink_name.endswith(".RawSQL") or sink_name == "RawSQL":
            if len(node.args) > 1 or any(kw.arg == "params" for kw in getattr(node, "keywords", [])):
                return True
        if sink_name.endswith(".extra") or sink_name == "extra":
            if any(kw.arg == "params" for kw in getattr(node, "keywords", [])):
                return True
    return False


CWE_89_RULE = SecurityRule(
    cwe_id="CWE-89",
    name="SqlInjection",
    category="SQL_INJECTION",
    operation="SQL_EXECUTION",
    confirmed_severity="CRITICAL",
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
    """Matches direct and qualified calls to eval, exec, and compile."""
    target_sinks = {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile"}
    if "CWE-95" in DECLARATIVE_RULES_BY_CWE:
        target_sinks = target_sinks | {str(s) for s in DECLARATIVE_RULES_BY_CWE["CWE-95"].get("sinks", []) if s}
    candidates = {c for c in (name, canon_name) if c}
    return any(c in target_sinks for c in candidates)


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
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
}
if "CWE-78" in DECLARATIVE_RULES_BY_CWE:
    CWE78_SINKS.update(str(s) for s in DECLARATIVE_RULES_BY_CWE["CWE-78"].get("sinks", []) if s)


def _cwe78_sink_matcher(node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
    """Matches direct and qualified calls to os.system and subprocess execution functions."""
    candidates = {c for c in (name, canon_name) if c}
    return bool(candidates & CWE78_SINKS)


def _cwe78_safety_filter(node: ast.Call, sink_name: str) -> bool:
    """
    Exempts subprocess invocations using shell=False or static argument lists without shell=True.
    os.system always executes via shell and is never exempted.
    """
    if sink_name in ("subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"):
        shell_kw = next((kw.value.value for kw in getattr(node, 'keywords', []) if kw.arg == "shell" and isinstance(kw.value, ast.Constant)), None)
        if shell_kw is False:
            return True
        if shell_kw is None and node.args and isinstance(node.args[0], ast.List):
            if all(isinstance(elt, ast.Constant) for elt in node.args[0].elts):
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
CWE22_ADDITIONAL_SINKS = {
    "shutil.rmtree", "os.remove", "os.unlink", "os.rmdir",
    "shutil.move", "shutil.copy", "shutil.copy2", "shutil.copytree",
    "zipfile.ZipFile.extractall", "zipfile.ZipFile.extract",
    "tarfile.TarFile.extractall", "tarfile.TarFile.extract",
}
if "CWE-22" in DECLARATIVE_RULES_BY_CWE:
    CWE22_ADDITIONAL_SINKS.update(
        str(s) for s in DECLARATIVE_RULES_BY_CWE["CWE-22"].get("sinks", [])
        if s and str(s) not in CWE22_BUILTIN_SINKS and str(s) not in CWE22_PATH_ATTRS
    )


def _cwe22_sink_matcher(node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
    """Matches direct/qualified calls to open(), pathlib file I/O, archive extraction, and path removals."""
    candidates = {c for c in (name, canon_name) if c}
    if any(c in CWE22_BUILTIN_SINKS for c in candidates):
        # Exclude method calls like arbitrary_object.open()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            return False
        return True
    if any(c in CWE22_ADDITIONAL_SINKS for c in candidates):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in CWE22_PATH_ATTRS:
            return True
        if node.func.attr in ("extractall", "extract", "rmtree"):
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
    "yaml.load",
    "yaml.unsafe_load",
}


def _cwe502_sink_matcher(node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
    """Matches direct and qualified calls to pickle.loads, pickle.load, _pickle variants, and yaml.load/unsafe_load."""
    candidates = {c for c in (name, canon_name) if c}
    return bool(candidates & CWE502_SINKS)


def _cwe502_safety_filter(node: ast.Call, sink_name: str) -> bool:
    """
    Exempts yaml.load when called with safe loaders (e.g. Loader=yaml.SafeLoader or CSafeLoader or BaseLoader).
    yaml.unsafe_load and pickle.* are never exempted.
    """
    if "yaml.load" in sink_name:
        safe_loaders = {
            "yaml.SafeLoader", "SafeLoader", "yaml.CSafeLoader", "CSafeLoader",
            "yaml.BaseLoader", "BaseLoader", "yaml.CBaseLoader", "CBaseLoader"
        }
        for kw in getattr(node, "keywords", []):
            if kw.arg == "Loader":
                val_str = None
                if isinstance(kw.value, ast.Name):
                    val_str = kw.value.id
                elif isinstance(kw.value, ast.Attribute):
                    val_str = f"{getattr(kw.value.value, 'id', '')}.{kw.value.attr}"
                if val_str in safe_loaders:
                    return True
        if len(node.args) > 1:
            arg1 = node.args[1]
            val_str = None
            if isinstance(arg1, ast.Name):
                val_str = arg1.id
            elif isinstance(arg1, ast.Attribute):
                val_str = f"{getattr(arg1.value, 'id', '')}.{arg1.attr}"
            if val_str in safe_loaders:
                return True
    return False


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
    safety_filter=_cwe502_safety_filter
)

# ==============================================================================
# CWE-1336 (Server-Side Template Injection) Rule Implementation
# ==============================================================================

CWE1336_DIRECT_SINKS = {
    "render_template_string",
    "flask.render_template_string",
    "jinja2.Template",
}


def _cwe1336_sink_matcher(node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
    """Matches direct render_template_string calls, jinja2.Template calls, and template .render() attribute calls."""
    candidates = {c for c in (name, canon_name) if c}

    # Strict exclusion: standard library string.Template must NEVER be flagged
    if any(c == "string.Template" or c.startswith("string.Template") for c in candidates):
        return False

    # Dynamic attribute method call: template.render(...)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "render":
        return True

    # Direct function calls or qualified calls on flask module or jinja2
    if any(c in CWE1336_DIRECT_SINKS for c in candidates):
        return True

    return False


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

CWE_798_RULE = SecurityRule(
    cwe_id="CWE-798",
    name="HardcodedCredentials",
    category="HARDCODED_CREDENTIALS",
    operation="CREDENTIAL_EXPOSURE",
    confirmed_severity="CRITICAL",
    potential_severity="HIGH",
    remediation="Never commit plaintext credentials. Rotate secret immediately and move to environment variables or vault.",
    sarif_metadata={
        "id": "CWE-798",
        "name": "HardcodedCredentials",
        "shortDescription": {
            "text": "Use of Hard-coded Credentials"
        },
        "fullDescription": {
            "text": "The software contains hard-coded credentials, such as a password or cryptographic key, which can be compromised if the source code is accessed."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/798.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "very-high",
            "security-severity": "9.8",
            "tags": ["security", "external/cwe/cwe-798"]
        }
    }
)

# ==============================================================================
# CWE-611 (XML External Entity / XXE) Rule Implementation
# ==============================================================================

CWE611_SINKS = {
    "xml.etree.ElementTree.fromstring", "xml.etree.ElementTree.parse",
    "ET.fromstring", "ET.parse",
    "fromstring", "parse",
    "lxml.etree.fromstring", "lxml.etree.parse",
    "xml.dom.minidom.parseString", "xml.dom.minidom.parse",
    "xml.sax.parseString", "xml.sax.parse",
}


def _cwe611_sink_matcher(node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
    """Matches direct and qualified calls to XML parsing functions."""
    candidates = {c for c in (name, canon_name) if c}
    if any(c in CWE611_SINKS or any(c.endswith(f".{s}") for s in ("fromstring",)) for c in candidates):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in ("fromstring", "parse") and any(c.startswith(("xml.", "ET.", "lxml.")) for c in candidates):
            return True
        if node.func.attr == "fromstring":
            return True
    return False


CWE_611_RULE = SecurityRule(
    cwe_id="CWE-611",
    name="XmlExternalEntity",
    category="XML_EXTERNAL_ENTITY",
    operation="XML_PARSING",
    confirmed_severity="HIGH",
    potential_severity="MEDIUM",
    remediation="Disable external entity resolution (DTD) or use defusedxml to safely parse untrusted XML documents.",
    sarif_metadata={
        "id": "CWE-611",
        "name": "XmlExternalEntity",
        "shortDescription": {
            "text": "Improper Restriction of XML External Entity Reference ('XXE')"
        },
        "fullDescription": {
            "text": "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/611.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "8.0",
            "tags": ["security", "external/cwe/cwe-611"]
        }
    },
    sink_matcher=_cwe611_sink_matcher,
    safety_filter=None
)

# ==============================================================================
# CWE-918 (Server-Side Request Forgery / SSRF) Rule Implementation
# ==============================================================================

CWE918_SINKS = {
    "urllib.request.urlopen", "urllib.request.Request",
    "urlopen", "Request",
    "requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch", "requests.head", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.patch", "httpx.head", "httpx.request",
    "aiohttp.ClientSession.get", "aiohttp.ClientSession.post", "aiohttp.ClientSession.request",
}


def _cwe918_sink_matcher(node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
    """Matches network request functions vulnerable to Server-Side Request Forgery."""
    candidates = {c for c in (name, canon_name) if c}
    if any(c in CWE918_SINKS or any(c.endswith(f".{s}") for s in ("urlopen", "Request")) for c in candidates):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "urlopen":
            return True
    return False


CWE_918_RULE = SecurityRule(
    cwe_id="CWE-918",
    name="ServerSideRequestForgery",
    category="SERVER_SIDE_REQUEST_FORGERY",
    operation="SSRF_REQUEST",
    confirmed_severity="HIGH",
    potential_severity="MEDIUM",
    remediation="Validate and allowlist URLs against trusted domains and restrict requests to private/internal IP ranges.",
    sarif_metadata={
        "id": "CWE-918",
        "name": "ServerSideRequestForgery",
        "shortDescription": {
            "text": "Server-Side Request Forgery (SSRF)"
        },
        "fullDescription": {
            "text": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL without sufficiently validating the destination address."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/918.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "8.5",
            "tags": ["security", "external/cwe/cwe-918"]
        }
    },
    sink_matcher=_cwe918_sink_matcher,
    safety_filter=None
)

# ==============================================================================
# CWE-1333 (Regular Expression Denial of Service / ReDoS) Rule Implementation
# ==============================================================================

CWE1333_SINKS = {
    "re.compile", "regex.compile",
}


def _cwe1333_sink_matcher(node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
    """Matches dynamic regular expression compilation functions vulnerable to ReDoS."""
    candidates = {c for c in (name, canon_name) if c}
    return bool(candidates & CWE1333_SINKS) or any(c.endswith(".compile") and ("re." in c or "regex." in c) for c in candidates)


CWE_1333_RULE = SecurityRule(
    cwe_id="CWE-1333",
    name="RegularExpressionDoS",
    category="REGULAR_EXPRESSION_DOS",
    operation="REGEX_COMPILATION",
    confirmed_severity="HIGH",
    potential_severity="LOW",
    remediation="Avoid constructing regular expressions from untrusted input or escape metacharacters using re.escape.",
    sarif_metadata={
        "id": "CWE-1333",
        "name": "RegularExpressionDoS",
        "shortDescription": {
            "text": "Inefficient Regular Expression Complexity ('ReDoS')"
        },
        "fullDescription": {
            "text": "The software uses a regular expression that can take an exponential amount of time to evaluate, causing a denial of service."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/1333.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "7.5",
            "tags": ["security", "external/cwe/cwe-1333"]
        }
    },
    sink_matcher=_cwe1333_sink_matcher,
    safety_filter=None
)

# ==============================================================================
# CWE-601 (URL Redirection to Untrusted Site / Open Redirect) Rule Implementation
# ==============================================================================

CWE601_SINKS = {
    "redirect", "flask.redirect", "django.shortcuts.redirect"
}


def _cwe601_sink_matcher(node: ast.AST, name: str, canon_name: Optional[str] = None) -> bool:
    """Matches redirect functions susceptible to open URL redirection."""
    candidates = {c for c in (name, canon_name) if c}
    return any(c in CWE601_SINKS or any(c.endswith(f".{s}") for s in ("redirect",)) for c in candidates)


def _cwe601_safety_filter(node: ast.Call, sink_name: str) -> bool:
    """Exempts safe redirects to constant relative paths, e.g. redirect('/') or redirect('/login')."""
    # Only applies to genuine redirect sinks; check_safety invokes every rule's
    # filter against every node, so guard against suppressing unrelated sinks
    # (e.g. z.extractall("/tmp/...")) that merely pass a constant leading-slash arg.
    if not (sink_name in CWE601_SINKS or sink_name.endswith(".redirect") or sink_name == "redirect"):
        return False
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        val = node.args[0].value
        if val.startswith("/") and not val.startswith("//"):
            return True
    return False


CWE_601_RULE = SecurityRule(
    cwe_id="CWE-601",
    name="OpenRedirect",
    category="URL_REDIRECTION",
    operation="OPEN_REDIRECT",
    confirmed_severity="MEDIUM",
    potential_severity="LOW",
    remediation="Validate target redirect URLs against an allowlist of permitted domains or enforce strict relative paths.",
    sarif_metadata={
        "id": "CWE-601",
        "name": "OpenRedirect",
        "shortDescription": {
            "text": "URL Redirection to Untrusted Site ('Open Redirect')"
        },
        "fullDescription": {
            "text": "A web application accepts a user-controlled input that specifies a link to an external site and uses that link in a redirect, enabling phishing attacks."
        },
        "helpUri": "https://cwe.mitre.org/data/definitions/601.html",
        "defaultConfiguration": {
            "level": "error"
        },
        "properties": {
            "precision": "high",
            "security-severity": "6.1",
            "tags": ["security", "external/cwe/cwe-601"]
        }
    },
    sink_matcher=_cwe601_sink_matcher,
    safety_filter=_cwe601_safety_filter
)

# ==============================================================================
# Master Rules Bank merge (append-only; never overwrites existing sink entries)
# ==============================================================================

# Maps a bank CWE onto the pre-existing per-CWE sink set so bank function names
# are picked up by the existing matchers. CWEs absent here get a generated rule.
_BANK_CWE_TO_SINK_SET: Dict[str, Set[str]] = {
    "CWE-502": CWE502_SINKS,
    "CWE-22": CWE22_ADDITIONAL_SINKS,
    "CWE-611": CWE611_SINKS,
    "CWE-918": CWE918_SINKS,
    "CWE-601": CWE601_SINKS,
    "CWE-1333": CWE1333_SINKS,
    "CWE-1336": CWE1336_DIRECT_SINKS,
}

# Metadata for CWE families present in the bank but without a pre-existing rule.
_BANK_NEW_RULE_META: Dict[str, Dict[str, Any]] = {
    "CWE-79": {
        "name": "CrossSiteScripting",
        "category": "XSS",
        "operation": "HTML_INJECTION",
        "confirmed_severity": "HIGH",
        "potential_severity": "MEDIUM",
        "remediation": "Do not mark untrusted input as safe. Contextually encode output (HTML/JS/URL) or use a vetted sanitizer before rendering.",
        "short": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "full": "The application marks attacker-controlled input as safe HTML (e.g. markupsafe.Markup / django mark_safe), bypassing auto-escaping and enabling cross-site scripting.",
        "security_severity": "6.1",
    },
    "CWE-295": {
        "name": "ImproperCertificateValidation",
        "category": "INSECURE_TRANSPORT",
        "operation": "HOST_KEY_VERIFICATION_BYPASS",
        "confirmed_severity": "HIGH",
        "potential_severity": "MEDIUM",
        "remediation": "Do not use AutoAddPolicy or disable host key/certificate verification. Verify host keys against a known_hosts store and validate certificates.",
        "short": "Improper Certificate Validation",
        "full": "The application auto-accepts unknown SSH host keys or disables certificate validation, enabling man-in-the-middle attacks.",
        "security_severity": "5.9",
    },
    "CWE-327": {
        "name": "BrokenCryptographicAlgorithm",
        "category": "WEAK_CRYPTOGRAPHY",
        "operation": "WEAK_HASH",
        "confirmed_severity": "MEDIUM",
        "potential_severity": "LOW",
        "remediation": "Avoid broken hashes (MD5/SHA1) for security purposes. Use SHA-256 or stronger (e.g. hashlib.sha256, blake2).",
        "short": "Use of a Broken or Risky Cryptographic Algorithm",
        "full": "The application uses a cryptographically broken hash algorithm (MD5 or SHA1), which is vulnerable to collision and preimage attacks.",
        "security_severity": "5.3",
    },
    "CWE-338": {
        "name": "InsecureRandomness",
        "category": "INSECURE_RANDOMNESS",
        "operation": "INSECURE_RANDOM",
        "confirmed_severity": "MEDIUM",
        "potential_severity": "LOW",
        "remediation": "Do not use standard pseudo-random number generators (random module) for security-sensitive contexts. Use secrets (e.g. secrets.token_hex, secrets.choice) or os.urandom instead.",
        "short": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
        "full": "The application uses a cryptographically weak pseudo-random number generator (such as random.randint or random.choice) in a security context.",
        "security_severity": "5.3",
    },
    "CWE-400": {
        "name": "ResourceExhaustion",
        "category": "RESOURCE_EXHAUSTION",
        "operation": "REGEX_COMPILATION",
        "confirmed_severity": "MEDIUM",
        "potential_severity": "LOW",
        "remediation": "Escape user input using re.escape before passing to regex operations, and enforce size limits on file reads (read(MAX_SIZE)).",
        "short": "Uncontrolled Resource Consumption ('Resource Exhaustion')",
        "full": "The application performs regex operations or file reads on untrusted data without size or complexity limits, exposing it to denial of service.",
        "security_severity": "5.3",
    },
}

_BANK_NEW_CWE_SINKS: Dict[str, Set[str]] = {}


def _build_bank_rule(cwe_id: str, sink_set: Set[str]) -> SecurityRule:
    meta = _BANK_NEW_RULE_META[cwe_id]

    def _matcher(node: ast.AST, name: str, canon_name: Optional[str] = None, _s: Set[str] = sink_set) -> bool:
        candidates = {c for c in (name, canon_name) if c}
        return bool(candidates & _s)

    return SecurityRule(
        cwe_id=cwe_id,
        name=meta["name"],
        category=meta["category"],
        operation=meta["operation"],
        confirmed_severity=meta["confirmed_severity"],
        potential_severity=meta["potential_severity"],
        remediation=meta["remediation"],
        sarif_metadata={
            "id": cwe_id,
            "name": meta["name"],
            "shortDescription": {"text": meta["short"]},
            "fullDescription": {"text": meta["full"]},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html",
            "defaultConfiguration": {"level": "error"},
            "properties": {
                "precision": "high",
                "security-severity": meta["security_severity"],
                "tags": ["security", f"external/cwe/cwe-{cwe_id.split('-')[1].lower()}"],
            },
        },
        sink_matcher=_matcher,
        safety_filter=None,
    )


if _MASTER_RULES_BANK is not None:
    _ENTERPRISE_SINKS_BANK = getattr(_MASTER_RULES_BANK, "ENTERPRISE_SINKS_BANK", {}) or {}
    for _fn_name, _fn_meta in _ENTERPRISE_SINKS_BANK.items():
        _cwe = _fn_meta.get("cwe")
        _existing_set = _BANK_CWE_TO_SINK_SET.get(_cwe)
        if _existing_set is not None:
            _existing_set.add(_fn_name)  # append-only; sets dedupe, no overwrite
        elif _cwe in _BANK_NEW_RULE_META:
            _BANK_NEW_CWE_SINKS.setdefault(_cwe, set()).add(_fn_name)

_BANK_GENERATED_RULES: List[SecurityRule] = [
    _build_bank_rule(_cwe, _sinks) for _cwe, _sinks in _BANK_NEW_CWE_SINKS.items()
]

def _load_catalog_security_rules(registry: RuleRegistry) -> None:
    """Loads all 107 enterprise security rules from data/rules_catalog.json into the registry.

    Ensures GLOBAL_RULE_REGISTRY contains complete SARIF metadata, remediation advice,
    and severity levels for all supported CWEs. Native rules with AST sink matchers
    and safety filters take precedence and are NEVER overwritten.
    """
    import json
    catalog_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "rules_catalog.json")
    if not os.path.isfile(catalog_path):
        return
    try:
        with open(catalog_path, "r", encoding="utf-8") as f:
            cat_data = json.load(f)
        cwes = cat_data.get("cwes", {})
        for cwe_id, meta in cwes.items():
            if cwe_id in registry._rules:
                continue
            cwe_num = cwe_id.split("-")[-1] if "-" in cwe_id else cwe_id
            name = meta.get("name", cwe_id).replace(" ", "_").replace("-", "_")
            category = meta.get("category", "Vulnerability")
            severity = str(meta.get("severity", "HIGH")).upper()
            remediation = meta.get("remediation", f"Remediate {cwe_id} according to secure coding standards.")
            desc = meta.get("description", f"Detects patterns violating {cwe_id}.")

            rule = SecurityRule(
                cwe_id=cwe_id,
                name=name,
                category=category,
                operation="SECURITY_POLICY",
                confirmed_severity=severity,
                potential_severity="LOW" if severity in ("LOW", "NOTE") else "MEDIUM",
                remediation=remediation,
                sarif_metadata={
                    "id": cwe_id,
                    "name": name,
                    "shortDescription": {"text": meta.get("name", cwe_id)},
                    "fullDescription": {"text": desc},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                    "defaultConfiguration": {
                        "level": "error" if severity in ("CRITICAL", "HIGH") else "warning"
                    },
                    "properties": {
                        "precision": "high",
                        "security-severity": "8.0" if severity in ("CRITICAL", "HIGH") else "5.0",
                        "tags": ["security", f"external/cwe/cwe-{cwe_num.lower()}"]
                    }
                },
                sink_matcher=None,
                safety_filter=None
            )
            registry.register(rule)
    except Exception:
        pass


# Global Registry instance initialized with migrated security rules
GLOBAL_RULE_REGISTRY = RuleRegistry()
GLOBAL_RULE_REGISTRY.register(CWE_89_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_95_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_78_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_22_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_502_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_1336_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_798_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_611_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_918_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_1333_RULE)
GLOBAL_RULE_REGISTRY.register(CWE_601_RULE)
for _bank_rule in _BANK_GENERATED_RULES:
    GLOBAL_RULE_REGISTRY.register(_bank_rule)
_load_catalog_security_rules(GLOBAL_RULE_REGISTRY)


def get_rule(cwe_id: str) -> Optional[SecurityRule]:
    return GLOBAL_RULE_REGISTRY.get_rule(cwe_id)


def match_sink_rule(node: ast.AST, name: str, canon_name: Optional[str] = None) -> Optional[SecurityRule]:
    return GLOBAL_RULE_REGISTRY.match_sink(node, name, canon_name)


def check_sink_safety_rules(node: ast.Call, sink_name: str) -> bool:
    return GLOBAL_RULE_REGISTRY.check_safety(node, sink_name)
