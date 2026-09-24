from __future__ import annotations
import ast
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, List, Dict, Any, Union, Tuple
from rule_engine import match_sink_rule, check_sink_safety_rules, get_rule

class NodeType(str, Enum):
    SOURCE = "source"
    TRANSFORM = "transform"
    SINK = "sink"

class TaintState(str, Enum):
    CLEAN = "CLEAN"
    TAINTED = "TAINTED"
    UNKNOWN = "UNKNOWN"

class ProvenanceState(str, Enum):
    STATIC = "STATIC"
    INTERNAL_DYNAMIC = "INTERNAL_DYNAMIC"
    UNKNOWN = "UNKNOWN"
    TAINTED = "TAINTED"

@dataclass(frozen=True)
class ProvenanceValue:
    state: ProvenanceState
    confidence: float = 1.0
    source_id: Optional[str] = None
    source_trace: tuple[str, ...] = field(default_factory=tuple)
    origin_node: Optional[ast.AST] = None

PROVENANCE_COMPOSITION_TABLE: dict[tuple[ProvenanceState, ProvenanceState], ProvenanceState] = {
    (ProvenanceState.STATIC, ProvenanceState.STATIC):           ProvenanceState.STATIC,
    (ProvenanceState.STATIC, ProvenanceState.INTERNAL_DYNAMIC): ProvenanceState.INTERNAL_DYNAMIC,
    (ProvenanceState.STATIC, ProvenanceState.UNKNOWN):          ProvenanceState.UNKNOWN,
    (ProvenanceState.STATIC, ProvenanceState.TAINTED):          ProvenanceState.TAINTED,

    (ProvenanceState.INTERNAL_DYNAMIC, ProvenanceState.STATIC):           ProvenanceState.INTERNAL_DYNAMIC,
    (ProvenanceState.INTERNAL_DYNAMIC, ProvenanceState.INTERNAL_DYNAMIC): ProvenanceState.INTERNAL_DYNAMIC,
    (ProvenanceState.INTERNAL_DYNAMIC, ProvenanceState.UNKNOWN):          ProvenanceState.UNKNOWN,
    (ProvenanceState.INTERNAL_DYNAMIC, ProvenanceState.TAINTED):          ProvenanceState.TAINTED,

    (ProvenanceState.UNKNOWN, ProvenanceState.STATIC):           ProvenanceState.UNKNOWN,
    (ProvenanceState.UNKNOWN, ProvenanceState.INTERNAL_DYNAMIC): ProvenanceState.UNKNOWN,
    (ProvenanceState.UNKNOWN, ProvenanceState.UNKNOWN):          ProvenanceState.UNKNOWN,
    (ProvenanceState.UNKNOWN, ProvenanceState.TAINTED):          ProvenanceState.TAINTED,

    (ProvenanceState.TAINTED, ProvenanceState.STATIC):           ProvenanceState.TAINTED,
    (ProvenanceState.TAINTED, ProvenanceState.INTERNAL_DYNAMIC): ProvenanceState.TAINTED,
    (ProvenanceState.TAINTED, ProvenanceState.UNKNOWN):          ProvenanceState.TAINTED,
    (ProvenanceState.TAINTED, ProvenanceState.TAINTED):          ProvenanceState.TAINTED,
}

def compose_path_provenance(
    left: ProvenanceValue,
    right: ProvenanceValue,
    operator: str = "path_join"
) -> ProvenanceValue:
    pair = (left.state, right.state)
    if pair not in PROVENANCE_COMPOSITION_TABLE:
        raise RuntimeError(f"Unmapped provenance composition pair: {pair}")
    result_state = PROVENANCE_COMPOSITION_TABLE[pair]

    source_id = None
    if result_state == ProvenanceState.TAINTED:
        if left.state == ProvenanceState.TAINTED and right.state == ProvenanceState.TAINTED:
            confidence = max(left.confidence, right.confidence)
            source_id = left.source_id or right.source_id
            combined_trace = (*left.source_trace, f"[{operator}]", *right.source_trace)
        elif left.state == ProvenanceState.TAINTED:
            confidence = left.confidence
            source_id = left.source_id
            combined_trace = left.source_trace
        else:
            confidence = right.confidence
            source_id = right.source_id
            combined_trace = right.source_trace
    elif result_state == ProvenanceState.UNKNOWN:
        confidence = 0.50
        source_id = left.source_id or right.source_id
        combined_trace = (*left.source_trace, f"[{operator}]", *right.source_trace)
    elif result_state == ProvenanceState.INTERNAL_DYNAMIC:
        confidence = min(left.confidence, right.confidence)
        combined_trace = (*left.source_trace, f"[{operator}]", *right.source_trace)
    else:
        confidence = 1.00
        combined_trace = (*left.source_trace, f"[{operator}]", *right.source_trace)

    origin = right.origin_node or left.origin_node
    return ProvenanceValue(
        state=result_state,
        confidence=confidence,
        source_id=source_id,
        source_trace=combined_trace,
        origin_node=origin
    )

STD_INTERNAL_PATH_PRODUCERS: dict[str, dict] = {
    "tempfile.TemporaryDirectory": {"is_context_manager": True, "return_type": "str"},
    "tempfile.mkdtemp": {"is_context_manager": False, "return_type": "str"},
    "tempfile.NamedTemporaryFile": {"is_context_manager": True, "return_type": "file"},
    "tempfile.mkstemp": {"is_context_manager": False, "return_type": "tuple"},
    "tempfile.gettempdir": {"is_context_manager": False, "return_type": "str"},
    "argparse.ArgumentParser.parse_args": {"is_context_manager": False, "return_type": "namespace"},
}

@dataclass(frozen=True)
class CodeLocation:
    file: str
    line_start: int
    line_end: int
    column_start: int = 0
    column_end: int = 0

@dataclass
class SecurityNode:
    id: str
    node_type: NodeType
    symbol: str
    operation: str
    location: CodeLocation
    metadata: dict = field(default_factory=dict)

class ProofNodeType(str, Enum):
    SOURCE = "SOURCE"
    ASSIGNMENT = "ASSIGNMENT"
    PARAM_BINDING = "PARAM_BINDING"
    CALL_SITE = "CALL_SITE"
    TRANSFORM = "TRANSFORM"
    SANITIZER = "SANITIZER"
    SINK = "SINK"

@dataclass(frozen=True)
class ProofNode:
    """
    Represents a single deterministic hop or operation in a ProofGraphIR.

    CONTRACT:
    `node_id` represents graph-instance identity ONLY (scoped to this specific AST flow graph).
    It MUST NOT be used as the future Vector 5 semantic finding identity.
    """
    node_id: str
    step_index: int
    node_type: ProofNodeType
    file_path: str
    start_line: int
    end_line: int
    symbol: str
    expression_snippet: str
    scope_id: str

@dataclass(frozen=True)
class ProofEdge:
    from_node_id: str
    to_node_id: str
    edge_type: str

@dataclass
class ProofGraphIR:
    finding_id: str
    cwe: str
    confidence: float
    nodes: list[ProofNode]
    edges: list[ProofEdge]
    sanitizer_applied: Optional[str] = None

    @property
    def proof_nodes(self) -> list[ProofNode]:
        return self.nodes

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "cwe": self.cwe,
            "confidence": self.confidence,
            "nodes": [
                {
                    "node_id": n.node_id,
                    "step_index": n.step_index,
                    "node_type": n.node_type.value if isinstance(n.node_type, ProofNodeType) else str(n.node_type),
                    "file_path": n.file_path,
                    "start_line": n.start_line,
                    "end_line": n.end_line,
                    "symbol": n.symbol,
                    "expression_snippet": n.expression_snippet,
                    "scope_id": n.scope_id
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "from_node_id": e.from_node_id,
                    "to_node_id": e.to_node_id,
                    "edge_type": e.edge_type
                }
                for e in self.edges
            ],
            "sanitizer_applied": self.sanitizer_applied
        }

def render_proof_graph_ascii(proof_graph: ProofGraphIR) -> str:
    box_width = 78
    inner_width = box_width - 2
    lines = []
    
    hdr_text = " [SECURITY PROOF] "
    hdr_dashes = box_width - 1 - len("┌──") - len(hdr_text)
    lines.append(f"┌──{hdr_text}{'─' * max(0, hdr_dashes)}┐")
    
    conf_label = "CONFIRMED" if proof_graph.confidence >= 1.0 else "POTENTIAL"
    title_str = f" {proof_graph.cwe} | Confidence: {proof_graph.confidence:.2f} ({conf_label})"
    if len(title_str) > inner_width:
        title_str = title_str[:inner_width]
    lines.append(f"│{title_str.ljust(inner_width)}│")
    lines.append(f"├{'─' * inner_width}┤")
    
    for idx, node in enumerate(proof_graph.nodes):
        type_str = node.node_type.value if hasattr(node.node_type, "value") else str(node.node_type)
        if node.symbol:
            step_hdr = f" [{node.step_index}. {type_str}: {node.symbol}]"
        else:
            step_hdr = f" [{node.step_index}. {type_str}]"
        lines.append(f"│{step_hdr.ljust(inner_width)}│")
        
        snip = node.expression_snippet.strip() if node.expression_snippet else node.symbol
        snip_lines = snip.splitlines()
        first_snip = snip_lines[0] if snip_lines else node.symbol
        if len(first_snip) > inner_width - 5:
            first_snip = first_snip[:inner_width - 8] + "..."
        lines.append(f"│    {first_snip.ljust(inner_width - 4)}│")
        
        func_name = node.scope_id.split(":")[-1] if ":" in node.scope_id else node.scope_id
        loc_str = f"└─► {node.file_path}:{node.start_line} (in function: {func_name})"
        if len(loc_str) > inner_width - 5:
            loc_str = loc_str[:inner_width - 5]
        lines.append(f"│    {loc_str.ljust(inner_width - 4)}│")
        
        if idx < len(proof_graph.nodes) - 1:
            lines.append(f"│{' ' * 9}│{' ' * (inner_width - 10)}│")
            lines.append(f"│{' ' * 9}▼{' ' * (inner_width - 10)}│")
            
    lines.append(f"└{'─' * inner_width}┘")
    return "\n".join(lines)

@dataclass
class DataFlowEdge:
    source_id: str
    target_id: str
    kind: str
    confidence: float
    transform: Optional[str] = None
    proof_graph: Optional[ProofGraphIR] = None

    @property
    def proof_nodes(self) -> list[ProofNode]:
        return self.proof_graph.nodes if self.proof_graph else []

@dataclass
class TaintValue:
    state: TaintState
    source_id: Optional[str] = None
    confidence: float = 1.0
    path: list[str] = field(default_factory=list)
    last_operation: Optional[str] = None
    proof_nodes: list[ProofNode] = field(default_factory=list)
    proof_edges: list[ProofEdge] = field(default_factory=list)

@dataclass
class SecuritySlice:
    source: SecurityNode
    sink: SecurityNode
    edges: list[DataFlowEdge]
    code: str

@dataclass
class AssignmentRecord:
    target_name: str
    value_node: ast.AST
    lineno: int
    scope_id: str
    is_conditional: bool

@dataclass
class SinkRecord:
    node: ast.Call
    security_node: SecurityNode
    lineno: int
    scope_id: str
    call_context: Optional[dict[str, Any]] = None

SOURCE_REGISTRY = {
    "request.args.get": {"operation": "HTTP_QUERY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.args.getlist": {"operation": "HTTP_QUERY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.form.get": {"operation": "HTTP_BODY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.form.getlist": {"operation": "HTTP_BODY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.values.get": {"operation": "HTTP_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.values.getlist": {"operation": "HTTP_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.get_json": {"operation": "HTTP_BODY_JSON_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.get_data": {"operation": "HTTP_BODY_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.headers.get": {"operation": "HTTP_HEADER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.cookies.get": {"operation": "HTTP_COOKIE_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.files.get": {"operation": "HTTP_FILE_UPLOAD_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.files.getlist": {"operation": "HTTP_FILE_UPLOAD_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.files": {"operation": "HTTP_FILE_UPLOAD_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.GET.get": {"operation": "HTTP_QUERY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.GET.getlist": {"operation": "HTTP_QUERY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.POST.get": {"operation": "HTTP_BODY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.POST.getlist": {"operation": "HTTP_BODY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "request.query_params.get": {"operation": "HTTP_QUERY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "sys.argv": {"operation": "CLI_ARGUMENT_ACCESS", "source_type": "USER_CONTROLLED"},
    "os.environ.get": {"operation": "ENVIRONMENT_VARIABLE_ACCESS", "source_type": "USER_CONTROLLED"},
    "os.environ": {"operation": "ENVIRONMENT_VARIABLE_ACCESS", "source_type": "USER_CONTROLLED"},
    "input": {"operation": "STDIN_READ", "source_type": "USER_CONTROLLED"},
    "builtins.input": {"operation": "STDIN_READ", "source_type": "USER_CONTROLLED"},
    "os.getenv": {"operation": "ENVIRONMENT_VARIABLE_ACCESS", "source_type": "USER_CONTROLLED"},
    "fastapi.Query": {"operation": "HTTP_QUERY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED"},
    "fastapi.Header": {"operation": "HTTP_HEADER_ACCESS", "source_type": "USER_CONTROLLED"},
    "fastapi.Cookie": {"operation": "HTTP_COOKIE_ACCESS", "source_type": "USER_CONTROLLED"},
    "fastapi.Body": {"operation": "HTTP_BODY_ACCESS", "source_type": "USER_CONTROLLED"},
}

SANITIZER_REGISTRY = {
    # Canonical Vector-to-Sanitizers Mapping
    "CWE-78": {"shlex.quote", "quote"},
    "CWE-22": {
        "os.path.basename", "basename",
        "werkzeug.utils.secure_filename", "secure_filename",
        "pathlib.Path.name", "Path.name",
        "secure_path_join",
        "uuid.UUID", "UUID",
    },
    "CWE-95": {"safe_eval_input"},
    "CWE-79": {"html.escape"},
    "CWE-918": {
        "is_safe_url", "validate_url",
        "check_domain_allowlist", "is_allowed_domain",
        "validate_private_ip", "is_private_ip",
    },
    "CWE-611": {
        "defusedxml.ElementTree.parse", "defusedxml.ElementTree.fromstring",
        "defusedxml.parse", "defusedxml.fromstring",
        "defused_parse", "defused_fromstring",
    },
    "CWE-601": {
        "is_safe_redirect_url", "validate_redirect_url",
        "url_has_allowed_host_and_scheme", "is_relative_url",
    },
    "CWE-327": {
        "hashlib.sha256", "sha256",
        "hashlib.sha512", "sha512",
        "bcrypt.hashpw", "bcrypt",
        "argon2.PasswordHasher", "argon2",
    },
    "CWE-328": {
        "hashlib.sha256", "sha256",
        "hashlib.sha512", "sha512",
        "bcrypt.hashpw", "bcrypt",
        "argon2.PasswordHasher", "argon2",
    },
    "CWE-338": {
        "secrets.token_hex", "token_hex",
        "secrets.token_urlsafe", "token_urlsafe",
        "secrets.choice",
        "os.urandom",
        "secrets.randbelow", "randbelow",
    },
    "CWE-295": {
        "verify_ssl_cert",
        "ssl.create_default_context", "create_default_context",
        "cert_verify",
    },
    "CWE-400": {
        "re.escape", "escape",
        "safe_read_chunked", "read_chunked",
    },
    "CWE-776": {
        "defusedxml.ElementTree.parse", "defusedxml.ElementTree.fromstring",
        "defusedxml.parse", "defusedxml.fromstring",
        "defused_parse", "defused_fromstring",
    },

    # Function-to-Metadata Mapping (Backward compatibility & fine-grained sink matching)
    "html.escape": {"protected_cwes": {"CWE-79"}, "protected_sinks": {"XSS"}},
    "safe_eval_input": {"protected_cwes": {"CWE-95"}, "protected_sinks": {"CODE_EXECUTION"}},
    "secure_path_join": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},
    "shlex.quote": {"protected_cwes": {"CWE-78"}, "protected_sinks": {"COMMAND_INJECTION", "OS_COMMAND_EXECUTION"}},
    "quote": {"protected_cwes": {"CWE-78"}, "protected_sinks": {"COMMAND_INJECTION", "OS_COMMAND_EXECUTION"}},
    "os.path.basename": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},
    "basename": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},
    "werkzeug.utils.secure_filename": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},
    "secure_filename": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},
    "pathlib.Path.name": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},
    "Path.name": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},
    "uuid.UUID": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},
    "UUID": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},

    # CWE-918 Sanitizers
    "is_safe_url": {"protected_cwes": {"CWE-918"}, "protected_sinks": {"SERVER_SIDE_REQUEST_FORGERY", "SSRF_REQUEST"}},
    "validate_url": {"protected_cwes": {"CWE-918"}, "protected_sinks": {"SERVER_SIDE_REQUEST_FORGERY", "SSRF_REQUEST"}},
    "check_domain_allowlist": {"protected_cwes": {"CWE-918"}, "protected_sinks": {"SERVER_SIDE_REQUEST_FORGERY", "SSRF_REQUEST"}},
    "is_allowed_domain": {"protected_cwes": {"CWE-918"}, "protected_sinks": {"SERVER_SIDE_REQUEST_FORGERY", "SSRF_REQUEST"}},
    "validate_private_ip": {"protected_cwes": {"CWE-918"}, "protected_sinks": {"SERVER_SIDE_REQUEST_FORGERY", "SSRF_REQUEST"}},
    "is_private_ip": {"protected_cwes": {"CWE-918"}, "protected_sinks": {"SERVER_SIDE_REQUEST_FORGERY", "SSRF_REQUEST"}},

    # CWE-611 Sanitizers
    "defusedxml.ElementTree.parse": {"protected_cwes": {"CWE-611", "CWE-776"}, "protected_sinks": {"XML_PARSING", "XML_EXTERNAL_ENTITY"}},
    "defusedxml.ElementTree.fromstring": {"protected_cwes": {"CWE-611", "CWE-776"}, "protected_sinks": {"XML_PARSING", "XML_EXTERNAL_ENTITY"}},
    "defusedxml.parse": {"protected_cwes": {"CWE-611", "CWE-776"}, "protected_sinks": {"XML_PARSING", "XML_EXTERNAL_ENTITY"}},
    "defusedxml.fromstring": {"protected_cwes": {"CWE-611", "CWE-776"}, "protected_sinks": {"XML_PARSING", "XML_EXTERNAL_ENTITY"}},
    "defused_parse": {"protected_cwes": {"CWE-611", "CWE-776"}, "protected_sinks": {"XML_PARSING", "XML_EXTERNAL_ENTITY"}},
    "defused_fromstring": {"protected_cwes": {"CWE-611", "CWE-776"}, "protected_sinks": {"XML_PARSING", "XML_EXTERNAL_ENTITY"}},

    # CWE-601 Sanitizers
    "is_safe_redirect_url": {"protected_cwes": {"CWE-601"}, "protected_sinks": {"OPEN_REDIRECT", "URL_REDIRECTION"}},
    "validate_redirect_url": {"protected_cwes": {"CWE-601"}, "protected_sinks": {"OPEN_REDIRECT", "URL_REDIRECTION"}},
    "url_has_allowed_host_and_scheme": {"protected_cwes": {"CWE-601"}, "protected_sinks": {"OPEN_REDIRECT", "URL_REDIRECTION"}},
    "is_relative_url": {"protected_cwes": {"CWE-601"}, "protected_sinks": {"OPEN_REDIRECT", "URL_REDIRECTION"}},

    # CWE-327 / CWE-328 Sanitizers
    "hashlib.sha256": {"protected_cwes": {"CWE-327", "CWE-328"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY"}},
    "sha256": {"protected_cwes": {"CWE-327", "CWE-328"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY"}},
    "hashlib.sha512": {"protected_cwes": {"CWE-327", "CWE-328"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY"}},
    "sha512": {"protected_cwes": {"CWE-327", "CWE-328"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY"}},
    "bcrypt.hashpw": {"protected_cwes": {"CWE-327", "CWE-328"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY"}},
    "bcrypt": {"protected_cwes": {"CWE-327", "CWE-328"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY"}},
    "argon2.PasswordHasher": {"protected_cwes": {"CWE-327", "CWE-328"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY"}},
    "argon2": {"protected_cwes": {"CWE-327", "CWE-328"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY"}},

    # CWE-338 Sanitizers
    "secrets.token_hex": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "token_hex": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "secrets.token_urlsafe": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "token_urlsafe": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "secrets.choice": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "os.urandom": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "secrets.randbelow": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "randbelow": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},

    # CWE-295 Sanitizers
    "verify_ssl_cert": {"protected_cwes": {"CWE-295"}, "protected_sinks": {"DISABLED_SSL_VERIFICATION", "INSECURE_TRANSPORT"}},
    "ssl.create_default_context": {"protected_cwes": {"CWE-295"}, "protected_sinks": {"DISABLED_SSL_VERIFICATION", "INSECURE_TRANSPORT"}},
    "create_default_context": {"protected_cwes": {"CWE-295"}, "protected_sinks": {"DISABLED_SSL_VERIFICATION", "INSECURE_TRANSPORT"}},
    "cert_verify": {"protected_cwes": {"CWE-295"}, "protected_sinks": {"DISABLED_SSL_VERIFICATION", "INSECURE_TRANSPORT"}},

    # CWE-400 / CWE-776 Sanitizers
    "re.escape": {"protected_cwes": {"CWE-400", "CWE-776", "CWE-1333"}, "protected_sinks": {"REGEX_COMPILATION", "REGULAR_EXPRESSION_DOS", "RESOURCE_EXHAUSTION"}},
    "escape": {"protected_cwes": {"CWE-400", "CWE-776", "CWE-1333"}, "protected_sinks": {"REGEX_COMPILATION", "REGULAR_EXPRESSION_DOS", "RESOURCE_EXHAUSTION"}},
    "safe_read_chunked": {"protected_cwes": {"CWE-400", "CWE-776"}, "protected_sinks": {"RESOURCE_EXHAUSTION", "FILE_ACCESS"}},
    "read_chunked": {"protected_cwes": {"CWE-400", "CWE-776"}, "protected_sinks": {"RESOURCE_EXHAUSTION", "FILE_ACCESS"}},
}

PRIMITIVE_NUMERIC_CASTS = {"int", "float", "bool", "math.floor", "math.ceil"}

CWE338_SECURITY_KEYWORDS = (
    "token", "key", "secret", "password", "session",
    "auth", "nonce", "salt", "otp", "pin", "csrf"
)
CWE338_BASE_SECURITY_TOKENS = {
    "token", "secret", "password", "session", "auth",
    "nonce", "salt", "otp", "csrf", "passwd", "credential", "credentials"
}
CWE338_NON_SECURITY_KEY_TOKENS = {
    "pressed", "press", "keyboard", "event", "nav", "navigation",
    "arrow", "input", "down", "up", "release", "shortcut"
}
CWE338_NON_SECURITY_PIN_ADJACENT = {
    "postal", "geo", "zip", "address", "map", "location", "board", "display", "needle", "bowling"
}

def tokenize_identifier(ident: str) -> list[str]:
    """Splits snake_case and camelCase identifiers into lowercase tokens."""
    if not ident:
        return []
    cleaned = re.sub(r'[^a-zA-Z0-9]+', '_', ident)
    parts = cleaned.split('_')
    tokens = []
    for part in parts:
        if not part:
            continue
        subparts = re.findall(r'[A-Z]+(?=[A-Z][a-z]|\d|\b)|[A-Z]?[a-z]+|[0-9]+', part)
        if subparts:
            tokens.extend(p.lower() for p in subparts)
        else:
            tokens.append(part.lower())
    return tokens

def is_security_identifier(name: str) -> bool:
    """Classifies whether an identifier or attribute represents a security-sensitive credential/token."""
    if not name:
        return False
    tokens = tokenize_identifier(name)
    if not tokens:
        return False

    # 1. Base security tokens
    if any(t in CWE338_BASE_SECURITY_TOKENS for t in tokens):
        return True

    # 2. 'key' token with non-security compound suppression (e.g. pressed_key, key_event, keyboard_key)
    if "key" in tokens:
        if not any(t in CWE338_NON_SECURITY_KEY_TOKENS for t in tokens):
            return True

    # 3. 'pin' token with adjacent word suppression (e.g. postal_pin, zip_pin, map_pin)
    if "pin" in tokens:
        pin_indices = [i for i, t in enumerate(tokens) if t == "pin"]
        for idx in pin_indices:
            prev_token = tokens[idx - 1] if idx > 0 else None
            next_token = tokens[idx + 1] if idx < len(tokens) - 1 else None
            if (prev_token in CWE338_NON_SECURITY_PIN_ADJACENT) or (next_token in CWE338_NON_SECURITY_PIN_ADJACENT):
                continue
            return True

    return False

CWE338_SECURITY_FUNC_KEYWORDS = (
    "auth", "login", "session", "token", "crypto", "hash",
    "password", "secret", "set_cookie", "cookie", "jwt",
    "verify", "credentials", "cipher", "authenticate"
)
CWE327_NON_CRYPTO_KEYWORDS = ("cache_key", "etag", "checksum", "fingerprint", "thumb")
CWE_PREDICATE_GUARDS = {
    "is_safe_url", "validate_url", "check_domain_allowlist", "is_allowed_domain",
    "validate_private_ip", "is_private_ip", "is_safe_redirect_url", "validate_redirect_url",
    "url_has_allowed_host_and_scheme", "is_relative_url"
}
NETWORK_INPUT_KEYWORDS = (
    "request", "stream", "socket", "sock", "uploaded_file", "upload",
    "files", "client", "connection", "conn", "raw", "aiohttp", "httpx",
    "urllib", "body_file", "raw_request", "wsgi", "network"
)

# String/bytes methods that never cleanse taint: the result carries the receiver's
# taint state unchanged (e.g. request.get_data().decode(), cookie.split(":")[0]).
TAINT_PRESERVING_RECEIVER_METHODS = {
    "decode", "encode", "split", "rsplit", "splitlines", "strip", "lstrip", "rstrip",
    "lower", "upper", "title", "capitalize", "swapcase", "casefold", "replace",
    "removeprefix", "removesuffix", "expandtabs", "center", "ljust", "rjust",
    "zfill", "partition", "rpartition",
}

# Container-mutating methods whose added element taints the whole container.
CONTAINER_MUTATION_METHODS = {
    "append": 0, "add": 0, "extend": 0, "insert": 1,
    "update": 0, "setdefault": 1, "push": 0,
}

SINK_REGISTRY = {
    # CWE-95: Code Execution
    "eval": {"operation": "ARBITRARY_CODE_EXECUTION", "category": "CODE_EXECUTION", "cwe": "CWE-95"},
    "exec": {"operation": "ARBITRARY_CODE_EXECUTION", "category": "CODE_EXECUTION", "cwe": "CWE-95"},
    "compile": {"operation": "ARBITRARY_CODE_EXECUTION", "category": "CODE_EXECUTION", "cwe": "CWE-95"},
    "builtins.eval": {"operation": "ARBITRARY_CODE_EXECUTION", "category": "CODE_EXECUTION", "cwe": "CWE-95"},
    "builtins.exec": {"operation": "ARBITRARY_CODE_EXECUTION", "category": "CODE_EXECUTION", "cwe": "CWE-95"},
    "builtins.compile": {"operation": "ARBITRARY_CODE_EXECUTION", "category": "CODE_EXECUTION", "cwe": "CWE-95"},

    # CWE-78: Command Injection
    "os.system": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.run": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.call": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.check_call": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.check_output": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.Popen": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},

    # CWE-502: Unsafe Deserialization
    "pickle.loads": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},
    "pickle.load": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},
    "_pickle.loads": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},
    "_pickle.load": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},
    "yaml.load": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},
    "yaml.unsafe_load": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},

    # CWE-22: Path Traversal
    "open": {"operation": "FILE_ACCESS", "category": "PATH_TRAVERSAL", "cwe": "CWE-22"},
    "shutil.rmtree": {"operation": "FILE_DELETE", "category": "PATH_TRAVERSAL", "cwe": "CWE-22"},
    "extractall": {"operation": "ARCHIVE_EXTRACTION", "category": "PATH_TRAVERSAL", "cwe": "CWE-22"},
    "extract": {"operation": "ARCHIVE_EXTRACTION", "category": "PATH_TRAVERSAL", "cwe": "CWE-22"},

    # CWE-1336: SSTI
    "render_template_string": {"operation": "TEMPLATE_EVALUATION", "category": "SSTI", "cwe": "CWE-1336"},
    "flask.render_template_string": {"operation": "TEMPLATE_EVALUATION", "category": "SSTI", "cwe": "CWE-1336"},
    "jinja2.Template": {"operation": "TEMPLATE_EVALUATION", "category": "SSTI", "cwe": "CWE-1336"},

    # CWE-89: SQL Injection
    "raw": {"operation": "SQL_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"},
    "extra": {"operation": "SQL_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"},
    "RawSQL": {"operation": "SQL_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"},
    "objects.raw": {"operation": "SQL_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"},
    "objects.extra": {"operation": "SQL_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"},

    # CWE-611: XML External Entity (XXE)
    "xml.etree.ElementTree.fromstring": {"operation": "XML_PARSING", "category": "XML_EXTERNAL_ENTITY", "cwe": "CWE-611"},
    "xml.etree.ElementTree.parse": {"operation": "XML_PARSING", "category": "XML_EXTERNAL_ENTITY", "cwe": "CWE-611"},
    "xml.dom.minidom.parseString": {"operation": "XML_PARSING", "category": "XML_EXTERNAL_ENTITY", "cwe": "CWE-611"},
    "xml.dom.minidom.parse": {"operation": "XML_PARSING", "category": "XML_EXTERNAL_ENTITY", "cwe": "CWE-611"},
    "lxml.etree.fromstring": {"operation": "XML_PARSING", "category": "XML_EXTERNAL_ENTITY", "cwe": "CWE-611"},
    "lxml.etree.parse": {"operation": "XML_PARSING", "category": "XML_EXTERNAL_ENTITY", "cwe": "CWE-611"},

    # CWE-918: Server-Side Request Forgery (SSRF)
    "urllib.request.urlopen": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918"},
    "urlopen": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918"},
    "requests.get": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918"},
    "requests.post": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918"},
    "requests.put": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918"},
    "requests.delete": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918"},
    "httpx.get": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918"},
    "httpx.post": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918"},
    "aiohttp.ClientSession.get": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918"},
    "aiohttp.ClientSession.post": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918"},

    # CWE-601: Open Redirect
    "redirect": {"operation": "OPEN_REDIRECT", "category": "URL_REDIRECTION", "cwe": "CWE-601"},
    "flask.redirect": {"operation": "OPEN_REDIRECT", "category": "URL_REDIRECTION", "cwe": "CWE-601"},
    "django.shortcuts.redirect": {"operation": "OPEN_REDIRECT", "category": "URL_REDIRECTION", "cwe": "CWE-601"},

    # CWE-327 / CWE-328: Broken Cryptographic Hashes & Ciphers
    "hashlib.md5": {"operation": "WEAK_HASH", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "hashlib.sha1": {"operation": "WEAK_HASH", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "Crypto.Cipher.DES": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "Crypto.Cipher.DES.new": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "DES.new": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},

    # CWE-338: Insecure Randomness
    "random.random": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.randint": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.choice": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.randrange": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.sample": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},

    # CWE-295: Disabled SSL/TLS Verification
    "paramiko.client.AutoAddPolicy": {"operation": "HOST_KEY_VERIFICATION_BYPASS", "category": "INSECURE_TRANSPORT", "cwe": "CWE-295"},
    "paramiko.AutoAddPolicy": {"operation": "HOST_KEY_VERIFICATION_BYPASS", "category": "INSECURE_TRANSPORT", "cwe": "CWE-295"},
    "urllib3.disable_warnings": {"operation": "DISABLED_SSL_VERIFICATION", "category": "INSECURE_TRANSPORT", "cwe": "CWE-295"},
    "ssl._create_unverified_context": {"operation": "DISABLED_SSL_VERIFICATION", "category": "INSECURE_TRANSPORT", "cwe": "CWE-295"},

    # CWE-400 / CWE-1333: Resource Exhaustion / ReDoS
    "re.compile": {"operation": "REGEX_COMPILATION", "category": "RESOURCE_EXHAUSTION", "cwe": "CWE-400"},
    "re.search": {"operation": "REGEX_SEARCH", "category": "RESOURCE_EXHAUSTION", "cwe": "CWE-400"},
    "re.match": {"operation": "REGEX_MATCH", "category": "RESOURCE_EXHAUSTION", "cwe": "CWE-400"},
}

def location(node: ast.AST, file_path: str) -> CodeLocation:
    return CodeLocation(
        file=file_path,
        line_start=getattr(node, "lineno", 1),
        line_end=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
        column_start=getattr(node, "col_offset", 0),
        column_end=getattr(node, "end_col_offset", getattr(node, "col_offset", 0)),
    )

def unroll_chained_call(node: ast.AST) -> Optional[str]:
    """Unrolls chained attribute/call expressions like conn.cursor().execute or db.get_conn().cursor().execute."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = unroll_chained_call(node.value)
        if parent:
            return f"{parent}.{node.attr}"
        return node.attr
    if isinstance(node, ast.Call):
        func_str = unroll_chained_call(node.func)
        if func_str:
            return f"{func_str}()"
    return None

def is_cursor_call_node(node: ast.AST) -> bool:
    """Checks whether node is an ast.Call whose attribute or chained attribute is 'cursor'."""
    val = node
    while isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute):
        if val.func.attr == "cursor":
            return True
        val = val.func.value
    return False

def dotted_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute):
        if node.attr == "execute" and is_cursor_call_node(node.value):
            unrolled = unroll_chained_call(node)
            if unrolled:
                return unrolled
        parent = dotted_name(node.value)
        if parent: return f"{parent}.{node.attr}"
        return node.attr
    return None

def extract_subscript_key(slice_node: ast.AST) -> Optional[Union[str, int]]:
    """Extracts a static string or integer key from a subscript slice (Python 3.8-3.12 compatible)."""
    if slice_node is None:
        return None
    curr = slice_node
    if hasattr(ast, "Index") and isinstance(curr, ast.Index):
        curr = curr.value
    if isinstance(curr, ast.Constant):
        if isinstance(curr.value, (str, int)):
            return curr.value
    elif isinstance(curr, ast.Str):
        return curr.s
    elif isinstance(curr, ast.Num):
        if isinstance(curr.n, int):
            return curr.n
    elif isinstance(curr, ast.UnaryOp) and isinstance(curr.op, ast.USub):
        if isinstance(curr.operand, ast.Constant) and isinstance(curr.operand.value, int):
            return -curr.operand.value
        elif isinstance(curr.operand, ast.Num) and isinstance(curr.operand.n, int):
            return -curr.operand.n
    return None

class TaintTracker:
    def __init__(self, files: dict[str, str] = None, source: str = None, file_path: str = "target.py", audit_all: bool = False):
        self.files = files if files is not None else {file_path: source}
        self.audit_all = audit_all
        self.modules: dict[str, ast.AST] = {}
        self.file_paths: dict[str, str] = {}
        for fpath, code in self.files.items():
            mod_name = fpath.replace("\\\\", "/").replace(".py", "").replace("/", ".")
            if mod_name.endswith(".__init__"): mod_name = mod_name[:-9]
            try:
                tree = ast.parse(code, filename=fpath)
                for p in ast.walk(tree):
                    for child in ast.iter_child_nodes(p):
                        child.parent = p
                self.modules[mod_name] = tree
                self.file_paths[mod_name] = fpath
            except SyntaxError:
                pass
        self.imports = {m: {} for m in self.modules}
        self.sources: list[SecurityNode] = []
        self.sinks: list[SecurityNode] = []
        self.edges: list[DataFlowEdge] = []
        self.assignments_by_scope: dict[tuple[str, str], list[AssignmentRecord]] = {}
        self.class_field_assignments: dict[tuple[str, str], list[AssignmentRecord]] = {}
        self.classes: set[str] = set()
        self.sink_records: list[SinkRecord] = []
        self.functions: dict[str, ast.FunctionDef] = {}
        self.returns_by_scope: dict[str, list[ast.Return]] = {}
        self.raw_calls: list[tuple[ast.Call, str, int]] = []
        self.call_sites_by_target: dict[str, list[tuple[ast.Call, str, int]]] = {}
        self.containment_guards: list[dict] = []
        self.list_mutations: dict[tuple[str, str], list[tuple[int, ast.AST]]] = {}
        self.instance_field_writes: dict[tuple[str, str], list[tuple[int, ast.AST, str]]] = {}
        self._source_counter = 0
        self._sink_counter = 0

    def next_source_id(self) -> str:
        self._source_counter += 1
        return f"SRC-{self._source_counter:03d}"

    def next_sink_id(self) -> str:
        self._sink_counter += 1
        return f"SNK-{self._sink_counter:03d}"

    def get_source_snippet(self, file_path: str, start_line: int, end_line: int, node: Optional[ast.AST] = None) -> str:
        code = self.files.get(file_path)
        if code is not None:
            lines = code.splitlines()
            if 1 <= start_line <= len(lines):
                end_l = min(end_line if end_line >= start_line else start_line, len(lines))
                if node and getattr(node, "lineno", None) == getattr(node, "end_lineno", None) == start_line:
                    c_start = getattr(node, "col_offset", None)
                    c_end = getattr(node, "end_col_offset", None)
                    if c_start is not None and c_end is not None and c_start < c_end:
                        line_text = lines[start_line - 1]
                        if c_end <= len(line_text):
                            col_slice = line_text[c_start:c_end].strip()
                            if col_slice:
                                return col_slice
                selected = lines[start_line - 1 : end_l]
                snippet = "\n".join(selected).strip()
                if snippet:
                    return snippet
        if node is not None:
            try:
                return ast.unparse(node).strip()
            except Exception:
                pass
        return ""

    def create_proof_node(
        self,
        step_index: int,
        node_type: ProofNodeType,
        file_path: str,
        node: Optional[ast.AST],
        symbol: str,
        scope_id: str,
        lineno: Optional[int] = None,
        end_lineno: Optional[int] = None,
        override_snippet: Optional[str] = None
    ) -> ProofNode:
        start_l = lineno or (getattr(node, "lineno", 1) if node else 1)
        end_l = end_lineno or (getattr(node, "end_lineno", start_l) if node else start_l)
        if override_snippet:
            snippet = override_snippet
        else:
            snippet = self.get_source_snippet(file_path, start_l, end_l, node)
        node_id = f"{node_type.value.lower()}:{file_path}:{start_l}:{symbol}#{step_index}"
        return ProofNode(
            node_id=node_id,
            step_index=step_index,
            node_type=node_type,
            file_path=file_path,
            start_line=start_l,
            end_line=end_l,
            symbol=symbol,
            expression_snippet=snippet,
            scope_id=scope_id
        )

    def _extract_subscript_key(self, slice_node: ast.AST, scope_id: str = "") -> Optional[Union[str, int]]:
        """Extracts static or statically resolved variable key from subscript slice."""
        key = extract_subscript_key(slice_node)
        if key is not None:
            return key
        curr = slice_node
        if hasattr(ast, "Index") and isinstance(curr, ast.Index):
            curr = curr.value
        if isinstance(curr, ast.Name) and scope_id:
            current_scope = scope_id
            mod_name = scope_id.split(":")[0] if scope_id else ""
            while current_scope:
                recs = self.assignments_by_scope.get((current_scope, curr.id), [])
                if recs:
                    latest = recs[-1]
                    k_val = extract_subscript_key(latest.value_node)
                    if k_val is not None:
                        return k_val
                    break
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope:
                    current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global":
                    current_scope = f"{mod_name}:global"
                else:
                    break
        return None

    def _eval_const_str(self, node: Optional[ast.AST], scope_id: Optional[str] = None, visited: Optional[set[str]] = None) -> Optional[str]:
        if node is None:
            return None
        if visited is None:
            visited = set()
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return str(node.value)
        if hasattr(ast, "Str") and isinstance(node, ast.Str):
            return str(node.s)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._eval_const_str(node.left, scope_id, visited)
            right = self._eval_const_str(node.right, scope_id, visited)
            if left is not None and right is not None:
                return left + right
            return None
        if isinstance(node, ast.Name) and scope_id:
            curr = scope_id
            mod_name = scope_id.split(":")[0] if ":" in scope_id else scope_id
            var_key = f"{scope_id}:{node.id}"
            if var_key in visited:
                return None
            visited.add(var_key)
            while curr:
                recs = self.assignments_by_scope.get((curr, node.id), [])
                if recs:
                    latest = [r for r in recs if not r.is_conditional]
                    rec = latest[-1] if latest else recs[-1]
                    return self._eval_const_str(rec.value_node, rec.scope_id, visited)
                if "." in curr and "function" in curr:
                    curr = curr.rsplit(".", 1)[0]
                elif ":function" in curr:
                    curr = f"{mod_name}:global"
                elif curr != f"{mod_name}:global":
                    curr = f"{mod_name}:global"
                else:
                    break
        return None

    def _eval_const_str_with_params(self, node: Optional[ast.AST], scope_id: Optional[str] = None, visited: Optional[set[str]] = None) -> Optional[str]:
        """Like _eval_const_str but also resolves a bare parameter Name to the constant
        argument passed at the enclosing function's call sites (higher-order getattr)."""
        val = self._eval_const_str(node, scope_id, visited)
        if val is not None:
            return val
        if isinstance(node, ast.Name) and scope_id:
            enc_scope = scope_id
            while enc_scope:
                f_node = self.functions.get(enc_scope)
                if f_node and any(a.arg == node.id for a in f_node.args.args):
                    param_names = [a.arg for a in f_node.args.args]
                    param_idx = param_names.index(node.id)
                    for call_node, caller_scope, _call_lineno in self.call_sites_by_target.get(enc_scope, []):
                        arg_expr = None
                        for kw in getattr(call_node, "keywords", []):
                            if kw.arg == node.id:
                                arg_expr = kw.value
                                break
                        if arg_expr is None:
                            pos_idx = param_idx
                            if param_names and param_names[0] in ("self", "cls"):
                                pos_idx -= 1
                            if 0 <= pos_idx < len(call_node.args):
                                arg_expr = call_node.args[pos_idx]
                        if arg_expr is not None:
                            c = self._eval_const_str(arg_expr, caller_scope, visited)
                            if c is not None:
                                return c
                    break
                if "." in enc_scope and "function" in enc_scope:
                    enc_scope = enc_scope.rsplit(".", 1)[0]
                else:
                    break
        return None

    def resolve_canonical_name(self, node: ast.AST, scope_id: str = "", visited: Optional[set[str]] = None) -> Optional[str]:
        if visited is None:
            visited = set()
        mod_name = scope_id.split(":")[0] if scope_id else ""

        if isinstance(node, ast.Name):
            if node.id == "__builtins__":
                return "builtins"
            if mod_name and mod_name in self.imports and node.id in self.imports[mod_name]:
                return self.imports[mod_name][node.id]

            var_key = f"{scope_id}:{node.id}"
            if var_key not in visited:
                visited.add(var_key)
                current_scope = scope_id
                found_record = None
                while current_scope:
                    recs = self.assignments_by_scope.get((current_scope, node.id), [])
                    if recs:
                        uncond = [r for r in recs if not r.is_conditional]
                        found_record = uncond[-1] if uncond else recs[-1]
                        break
                    if "." in current_scope and "function" in current_scope:
                        current_scope = current_scope.rsplit(".", 1)[0]
                    elif ":function" in current_scope:
                        current_scope = f"{mod_name}:global"
                    elif current_scope != f"{mod_name}:global":
                        current_scope = f"{mod_name}:global"
                    else:
                        break

                if found_record:
                    resolved = self.resolve_canonical_name(found_record.value_node, found_record.scope_id, visited)
                    if resolved:
                        return resolved
                    if node.id in ("exec", "eval", "open"):
                        return f"shadowed:{node.id}"

                # Higher-order function parameter lookup (if node.id is a parameter of enclosing function)
                enc_scope = scope_id
                while enc_scope:
                    f_node = self.functions.get(enc_scope)
                    if f_node and any(a.arg == node.id for a in f_node.args.args):
                        param_names = [a.arg for a in f_node.args.args]
                        param_idx = param_names.index(node.id)
                        call_sites = self.call_sites_by_target.get(enc_scope, [])
                        if call_sites:
                            for call_node, caller_scope, call_lineno in call_sites:
                                arg_expr = None
                                for kw in getattr(call_node, "keywords", []):
                                    if kw.arg == node.id:
                                        arg_expr = kw.value
                                        break
                                if arg_expr is None:
                                    pos_idx = param_idx
                                    if param_names and param_names[0] in ("self", "cls"):
                                        pos_idx = param_idx - 1
                                    if 0 <= pos_idx < len(call_node.args):
                                        arg_expr = call_node.args[pos_idx]
                                if arg_expr is not None:
                                    p_key = f"param_canon:{enc_scope}:{node.id}:{caller_scope}:{call_lineno}"
                                    if p_key not in visited:
                                        v_copy = visited.copy()
                                        v_copy.add(p_key)
                                        resolved_param = self.resolve_canonical_name(arg_expr, caller_scope, v_copy)
                                        if resolved_param:
                                            return resolved_param
                        break
                    if "." in enc_scope and "function" in enc_scope:
                        enc_scope = enc_scope.rsplit(".", 1)[0]
                    else:
                        break

            return node.id

        if isinstance(node, ast.Attribute):
            if node.attr == "execute" and is_cursor_call_node(node.value):
                unrolled = unroll_chained_call(node)
                if unrolled:
                    return unrolled
            base_canon = self.resolve_canonical_name(node.value, scope_id, visited)
            if base_canon:
                full_name = f"{base_canon}.{node.attr}"
                if mod_name and mod_name in self.imports and full_name in self.imports[mod_name]:
                    return self.imports[mod_name][full_name]
                return full_name
            return node.attr

        if isinstance(node, ast.Call):
            call_name = dotted_name(node.func)

            # 1. getattr(target, attr_name) dynamic resolution
            if (call_name in ("getattr", "builtins.getattr") or (call_name and call_name.endswith(".getattr"))) and len(node.args) >= 2:
                target_canon = self.resolve_canonical_name(node.args[0], scope_id, visited) or dotted_name(node.args[0])
                attr_str = self._eval_const_str_with_params(node.args[1], scope_id, visited)
                if target_canon and attr_str:
                    return f"{target_canon}.{attr_str}"

            # 2. __import__("mod") dynamic module import
            if (call_name in ("__import__", "builtins.__import__") or (call_name and call_name.endswith(".__import__"))) and node.args:
                mod_target = self._eval_const_str(node.args[0], scope_id)
                if mod_target:
                    return mod_target

            # 3. globals().get("key") / locals().get("key") reflection
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
                if isinstance(node.func.value, ast.Call) and dotted_name(node.func.value.func) in ("globals", "locals", "builtins.globals", "builtins.locals"):
                    key_str = self._eval_const_str(node.args[0], scope_id)
                    if key_str:
                        if mod_name and mod_name in self.imports and key_str in self.imports[mod_name]:
                            return self.imports[mod_name][key_str]
                        func_cand = f"{mod_name}:function:{key_str}"
                        if func_cand in self.functions:
                            return f"{mod_name}.{key_str}"
                        curr = scope_id
                        while curr:
                            recs = self.assignments_by_scope.get((curr, key_str), [])
                            if recs:
                                uncond = [r for r in recs if not r.is_conditional]
                                found = uncond[-1] if uncond else recs[-1]
                                resolved = self.resolve_canonical_name(found.value_node, found.scope_id, visited)
                                if resolved:
                                    return resolved
                                break
                            if "." in curr and "function" in curr:
                                curr = curr.rsplit(".", 1)[0]
                            elif ":function" in curr:
                                curr = f"{mod_name}:global"
                            elif curr != f"{mod_name}:global":
                                curr = f"{mod_name}:global"
                            else:
                                break
                        return key_str

            if call_name:
                func_scope = self._resolve_function_scope(call_name, scope_id)
                if func_scope and func_scope not in visited:
                    visited.add(func_scope)
                    returns = self.returns_by_scope.get(func_scope, [])
                    if returns:
                        ret_canons = [self.resolve_canonical_name(r.value, func_scope, visited) for r in returns if r.value]
                        if ret_canons and all(c == ret_canons[0] and c is not None for c in ret_canons):
                            return ret_canons[0]

        if isinstance(node, ast.Subscript):
            # Check globals()["key"] / locals()["key"] reflection
            if isinstance(node.value, ast.Call) and dotted_name(node.value.func) in ("globals", "locals", "builtins.globals", "builtins.locals"):
                key_str = self._eval_const_str(node.slice, scope_id)
                if key_str:
                    if mod_name and mod_name in self.imports and key_str in self.imports[mod_name]:
                        return self.imports[mod_name][key_str]
                    func_cand = f"{mod_name}:function:{key_str}"
                    if func_cand in self.functions:
                        return f"{mod_name}.{key_str}"
                    curr = scope_id
                    while curr:
                        recs = self.assignments_by_scope.get((curr, key_str), [])
                        if recs:
                            uncond = [r for r in recs if not r.is_conditional]
                            found = uncond[-1] if uncond else recs[-1]
                            resolved = self.resolve_canonical_name(found.value_node, found.scope_id, visited)
                            if resolved:
                                return resolved
                            break
                        if "." in curr and "function" in curr:
                            curr = curr.rsplit(".", 1)[0]
                        elif ":function" in curr:
                            curr = f"{mod_name}:global"
                        elif curr != f"{mod_name}:global":
                            curr = f"{mod_name}:global"
                        else:
                            break
                    return key_str

            # X.__dict__["name"] -> X.name (module / builtins reflection)
            if isinstance(node.value, ast.Attribute) and node.value.attr == "__dict__":
                base_canon = self.resolve_canonical_name(node.value.value, scope_id, visited)
                dict_key = self._extract_subscript_key(node.slice, scope_id)
                if base_canon and dict_key is not None:
                    return f"{base_canon}.{dict_key}"

            key = self._extract_subscript_key(node.slice, scope_id)
            base_var = node.value.id if isinstance(node.value, ast.Name) else None

            # 1. Composite key in assignments_by_scope: dispatcher["run"] = ...
            if base_var and key is not None:
                comp_key = f"{base_var}[{key}]"
                current_scope = scope_id
                found_record = None
                while current_scope:
                    recs = self.assignments_by_scope.get((current_scope, comp_key), [])
                    if recs:
                        uncond = [r for r in recs if not r.is_conditional]
                        found_record = uncond[-1] if uncond else recs[-1]
                        break
                    if "." in current_scope and "function" in current_scope:
                        current_scope = current_scope.rsplit(".", 1)[0]
                    elif ":function" in current_scope:
                        current_scope = f"{mod_name}:global"
                    elif current_scope != f"{mod_name}:global":
                        current_scope = f"{mod_name}:global"
                    else:
                        break
                if found_record:
                    sub_key = f"{scope_id}:{comp_key}"
                    if sub_key not in visited:
                        v_copy = visited.copy()
                        v_copy.add(sub_key)
                        resolved = self.resolve_canonical_name(found_record.value_node, found_record.scope_id, v_copy)
                        if resolved:
                            return resolved

            # 2. Base variable initialized with a dict, list, or tuple literal
            if base_var:
                current_scope = scope_id
                found_record = None
                while current_scope:
                    recs = self.assignments_by_scope.get((current_scope, base_var), [])
                    if recs:
                        uncond = [r for r in recs if not r.is_conditional]
                        found_record = uncond[-1] if uncond else recs[-1]
                        break
                    if "." in current_scope and "function" in current_scope:
                        current_scope = current_scope.rsplit(".", 1)[0]
                    elif ":function" in current_scope:
                        current_scope = f"{mod_name}:global"
                    elif current_scope != f"{mod_name}:global":
                        current_scope = f"{mod_name}:global"
                    else:
                        break
                if found_record:
                    val_node = found_record.value_node
                    if isinstance(val_node, ast.Dict) and key is not None:
                        for k, v in zip(val_node.keys, val_node.values):
                            k_val = self._extract_subscript_key(k, found_record.scope_id)
                            if k_val == key:
                                resolved = self.resolve_canonical_name(v, found_record.scope_id, visited)
                                if resolved:
                                    return resolved
                    elif isinstance(val_node, (ast.List, ast.Tuple)) and isinstance(key, int):
                        if -len(val_node.elts) <= key < len(val_node.elts):
                            resolved = self.resolve_canonical_name(val_node.elts[key], found_record.scope_id, visited)
                            if resolved:
                                return resolved

            # 3. Direct Dict or List/Tuple literal
            if isinstance(node.value, ast.Dict) and key is not None:
                for k, v in zip(node.value.keys, node.value.values):
                    k_val = self._extract_subscript_key(k, scope_id)
                    if k_val == key:
                        resolved = self.resolve_canonical_name(v, scope_id, visited)
                        if resolved:
                            return resolved
            elif isinstance(node.value, (ast.List, ast.Tuple)) and isinstance(key, int):
                if -len(node.value.elts) <= key < len(node.value.elts):
                    resolved = self.resolve_canonical_name(node.value.elts[key], scope_id, visited)
                    if resolved:
                        return resolved

        return None

    def is_source_call(self, node: ast.AST, scope_id: str = "") -> bool:
        if not isinstance(node, ast.Call): return False
        canon = self.resolve_canonical_name(node.func, scope_id) if scope_id else dotted_name(node.func)
        if canon:
            if canon in SOURCE_REGISTRY: return True
            if canon.startswith("flask.") and canon[6:] in SOURCE_REGISTRY: return True
        name = dotted_name(node.func)
        if name in SOURCE_REGISTRY: return True
        if name and name.startswith("flask.") and name[6:] in SOURCE_REGISTRY: return True
        return False

    def get_or_create_source(self, node: ast.AST, file_path: str, scope_id: str = "") -> SecurityNode:
        loc = location(node, file_path)
        for existing in self.sources:
            if existing.location == loc: return existing
        source_id = self.next_source_id()
        target_node = node.func if isinstance(node, ast.Call) else (node.value if isinstance(node, ast.Subscript) else node)
        canon_name = self.resolve_canonical_name(target_node, scope_id) if scope_id else None
        name = dotted_name(target_node)
        lookup_name = canon_name if (canon_name and canon_name in SOURCE_REGISTRY) else name
        if lookup_name not in SOURCE_REGISTRY and canon_name and canon_name.startswith("flask."):
            unq = canon_name[6:]
            if unq in SOURCE_REGISTRY: lookup_name = unq
        if lookup_name not in SOURCE_REGISTRY and name and name.startswith("flask."):
            unq = name[6:]
            if unq in SOURCE_REGISTRY: lookup_name = unq
        meta = SOURCE_REGISTRY.get(lookup_name, {})
        sym = f"{lookup_name}(...)" if isinstance(node, ast.Call) else (f"{lookup_name}[...]" if isinstance(node, ast.Subscript) else f"{lookup_name}")
        source = SecurityNode(
            id=source_id, node_type=NodeType.SOURCE, symbol=sym,
            operation=meta.get("operation", "USER_INPUT_ACCESS"), location=loc,
            metadata={"source_type": meta.get("source_type", "USER_CONTROLLED")}
        )
        self.sources.append(source)
        return source

    def _is_builtin_shadowed(self, name: str, scope_id: str, lineno: int = 0) -> bool:
        if name not in ("exec", "eval", "open"):
            return False

        mod_name = scope_id.split(":")[0] if scope_id else ""
        curr_scope = scope_id
        while curr_scope:
            f_node = self.functions.get(curr_scope)
            if f_node:
                all_args = [a.arg for a in f_node.args.args]
                if getattr(f_node.args, "vararg", None):
                    all_args.append(f_node.args.vararg.arg)
                if getattr(f_node.args, "kwarg", None):
                    all_args.append(f_node.args.kwarg.arg)
                for kw in getattr(f_node.args, "kwonlyargs", []):
                    all_args.append(kw.arg)
                for p in getattr(f_node.args, "posonlyargs", []):
                    all_args.append(p.arg)
                if name in all_args:
                    return True

            recs = self.assignments_by_scope.get((curr_scope, name), [])
            valid_recs = [r for r in recs if r.lineno < lineno] if (curr_scope == scope_id and lineno > 0) else recs
            if valid_recs:
                last_rec = valid_recs[-1]
                target_canon = self.resolve_canonical_name(last_rec.value_node, last_rec.scope_id)
                if target_canon in (name, f"builtins.{name}"):
                    return False
                return True

            test_func_scope = f"{curr_scope}.{name}" if ":function" in curr_scope else f"{mod_name}:function:{name}"
            if test_func_scope in self.functions:
                return True

            if "." in curr_scope and "function" in curr_scope:
                curr_scope = curr_scope.rsplit(".", 1)[0]
            elif ":function" in curr_scope:
                curr_scope = f"{mod_name}:global"
            elif curr_scope != f"{mod_name}:global":
                curr_scope = f"{mod_name}:global"
            else:
                break

        if f"{mod_name}:function:{name}" in self.functions:
            return True

        return False

    def _has_disabled_ssl(self, node: ast.Call) -> bool:
        for kw in getattr(node, "keywords", []):
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                return True
            if kw.arg == "cert_reqs" and isinstance(kw.value, ast.Constant) and str(kw.value.value).upper() in ("CERT_NONE", "NONE"):
                return True
        return False

    def _is_security_sensitive_random(self, node: ast.Call, scope_id: str = "", lineno: int = 0) -> bool:
        call_lineno = lineno or getattr(node, "lineno", 0)

        # 1. Walk up the parent AST hierarchy to find enclosing assignment or call
        curr = getattr(node, "parent", None)
        while curr is not None:
            if isinstance(curr, ast.Assign):
                for t in curr.targets:
                    if isinstance(t, ast.Name) and is_security_identifier(t.id):
                        return True
                    if isinstance(t, ast.Attribute) and is_security_identifier(t.attr):
                        return True
                    if isinstance(t, ast.Subscript) and isinstance(t.slice, (ast.Constant, ast.Str)):
                        s_val = str(t.slice.value if isinstance(t.slice, ast.Constant) else t.slice.s)
                        if is_security_identifier(s_val):
                            return True
                    if isinstance(t, (ast.Tuple, ast.List)):
                        for elt in t.elts:
                            if isinstance(elt, ast.Name) and is_security_identifier(elt.id):
                                return True
                            if isinstance(elt, ast.Attribute) and is_security_identifier(elt.attr):
                                return True
                break
            elif isinstance(curr, ast.AnnAssign):
                if isinstance(curr.target, ast.Name) and is_security_identifier(curr.target.id):
                    return True
                if isinstance(curr.target, ast.Attribute) and is_security_identifier(curr.target.attr):
                    return True
                break
            elif isinstance(curr, ast.Call) and curr is not node:
                func_name = (dotted_name(curr.func) or "").lower()
                func_tokens = tokenize_identifier(func_name)
                if any(t in CWE338_SECURITY_FUNC_KEYWORDS for t in func_tokens) or any(kw in func_name for kw in CWE338_SECURITY_FUNC_KEYWORDS):
                    return True
                for kw in getattr(curr, "keywords", []):
                    if kw.arg and is_security_identifier(kw.arg):
                        return True
            elif isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if is_security_identifier(curr.name):
                    return True
                break
            elif isinstance(curr, (ast.ClassDef, ast.Module)):
                break
            curr = getattr(curr, "parent", None)

        # 2. Check assignments_by_scope fallback
        if scope_id:
            for (sc, var_name), recs in self.assignments_by_scope.items():
                if sc == scope_id:
                    for r in recs:
                        if r.lineno == call_lineno:
                            for sub in ast.walk(r.value_node):
                                if sub is node:
                                    if is_security_identifier(var_name):
                                        return True
        return False

    def _get_hashlib_new_algo(self, node: ast.Call, scope_id: str = "") -> Optional[str]:
        """Detects whether node is a call to hashlib.new(...) and returns the lowercased algorithm name."""
        if not isinstance(node, ast.Call):
            return None
        fn_name = dotted_name(node.func) or ""
        canon = self.resolve_canonical_name(node.func, scope_id) if (scope_id and hasattr(self, "resolve_canonical_name")) else fn_name
        is_hashlib_new = False
        if fn_name in ("hashlib.new", "_hashlib.new") or canon in ("hashlib.new", "_hashlib.new"):
            is_hashlib_new = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "new":
            val_name = dotted_name(node.func.value) or ""
            val_canon = self.resolve_canonical_name(node.func.value, scope_id) if (scope_id and hasattr(self, "resolve_canonical_name")) else val_name
            if val_name in ("hashlib", "_hashlib") or val_canon in ("hashlib", "_hashlib"):
                is_hashlib_new = True
        elif fn_name == "new" and (canon in ("hashlib.new", "_hashlib.new") or (scope_id and "hashlib" in str(self.imports.get(scope_id.split(":")[0], {})))):
            is_hashlib_new = True

        if not is_hashlib_new:
            return None

        algo = None
        if node.args:
            arg0 = node.args[0]
            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                algo = arg0.value.strip().lower()
            elif isinstance(arg0, ast.Str):
                algo = arg0.s.strip().lower()
        if not algo:
            for kw in getattr(node, "keywords", []):
                if kw.arg == "name":
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        algo = kw.value.value.strip().lower()
                    elif isinstance(kw.value, ast.Str):
                        algo = kw.value.s.strip().lower()
                    break
        return algo

    def _is_exempt_cwe327(self, node: ast.Call, scope_id: str = "", lineno: int = 0) -> bool:
        call_lineno = lineno or getattr(node, "lineno", 0)

        # 1. Keyword usedforsecurity=False
        for kw in getattr(node, "keywords", []):
            if kw.arg == "usedforsecurity":
                val = getattr(kw.value, "value", None)
                if val is False:
                    return True
                if isinstance(kw.value, ast.NameConstant) and kw.value.value is False:
                    return True

        # 2. Check enclosing assignment targets for non-cryptographic checksumming
        curr = getattr(node, "parent", None)
        while curr is not None:
            if isinstance(curr, ast.Assign):
                for t in curr.targets:
                    target_str = ""
                    if isinstance(t, ast.Name): target_str = t.id.lower()
                    elif isinstance(t, ast.Attribute): target_str = t.attr.lower()
                    elif isinstance(t, ast.Subscript) and isinstance(t.slice, (ast.Constant, ast.Str)):
                        target_str = str(t.slice.value if isinstance(t.slice, ast.Constant) else t.slice.s).lower()
                    if any(kw in target_str for kw in CWE327_NON_CRYPTO_KEYWORDS):
                        return True
                break
            elif isinstance(curr, ast.AnnAssign):
                target_str = curr.target.id.lower() if isinstance(curr.target, ast.Name) else (curr.target.attr.lower() if isinstance(curr.target, ast.Attribute) else "")
                if any(kw in target_str for kw in CWE327_NON_CRYPTO_KEYWORDS):
                    return True
                break
            elif isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(kw in curr.name.lower() for kw in CWE327_NON_CRYPTO_KEYWORDS):
                    return True
                break
            elif isinstance(curr, (ast.ClassDef, ast.Module)):
                break
            curr = getattr(curr, "parent", None)

        # 3. Fallback check via assignments_by_scope
        if scope_id:
            for (sc, var_name), recs in self.assignments_by_scope.items():
                if sc == scope_id:
                    for r in recs:
                        if r.lineno == call_lineno:
                            if any(kw in var_name.lower() for kw in CWE327_NON_CRYPTO_KEYWORDS):
                                for sub in ast.walk(r.value_node):
                                    if sub is node:
                                        return True
        return False

    def _is_definitely_safe_local_read(self, receiver: ast.AST, scope_id: str = "", lineno: int = 0) -> bool:
        if isinstance(receiver, ast.Call):
            func_name = dotted_name(receiver.func) or ""
            if func_name == "open" and receiver.args:
                first_arg = receiver.args[0]
                if isinstance(first_arg, (ast.Constant, ast.Str)):
                    return True
        return False

    def _is_untrusted_stream(self, receiver: ast.AST, scope_id: str, lineno: int, recv_taint: Optional[TaintValue] = None) -> bool:
        # 1. Receiver is tracked as tainted
        if recv_taint and recv_taint.state == TaintState.TAINTED:
            return True

        # 2. Check names in receiver AST
        for sub in ast.walk(receiver):
            if isinstance(sub, ast.Name) and any(kw in sub.id.lower() for kw in NETWORK_INPUT_KEYWORDS):
                return True
            if isinstance(sub, ast.Attribute) and any(kw in sub.attr.lower() for kw in NETWORK_INPUT_KEYWORDS):
                return True

        # 3. Check taint path or trace
        if recv_taint and hasattr(recv_taint, "path"):
            for p in recv_taint.path:
                p_lower = p.lower()
                if any(kw in p_lower for kw in NETWORK_INPUT_KEYWORDS):
                    return True

        # 4. Check if receiver is a variable assigned from network / request input
        if isinstance(receiver, ast.Name) and scope_id:
            curr = scope_id
            while curr:
                recs = self.assignments_by_scope.get((curr, receiver.id), [])
                for r in recs:
                    if r.lineno <= lineno:
                        for sub in ast.walk(r.value_node):
                            if isinstance(sub, ast.Name) and any(kw in sub.id.lower() for kw in NETWORK_INPUT_KEYWORDS):
                                return True
                            if isinstance(sub, ast.Attribute) and any(kw in sub.attr.lower() for kw in NETWORK_INPUT_KEYWORDS):
                                return True
                            if isinstance(sub, ast.Call):
                                call_name = (dotted_name(sub.func) or "").lower()
                                if any(kw in call_name for kw in NETWORK_INPUT_KEYWORDS):
                                    return True
                if "." in curr:
                    curr = curr.rsplit(".", 1)[0]
                elif ":function" in curr:
                    curr = f"{curr.split(':')[0]}:global"
                else:
                    break

        return False

    def _is_dummy_validator_func(self, func_node: ast.FunctionDef) -> bool:
        """Check if a validator function is a dummy (e.g. merely returns True without checks)."""
        meaningful = []
        for s in func_node.body:
            if isinstance(s, ast.Expr) and isinstance(s.value, (ast.Constant, ast.Str)):
                continue  # docstring
            if isinstance(s, ast.Pass):
                continue
            meaningful.append(s)
        if not meaningful:
            return True
        if len(meaningful) == 1 and isinstance(meaningful[0], ast.Return):
            ret_val = meaningful[0].value
            if ret_val is None:
                return True
            if isinstance(ret_val, ast.Constant) and bool(ret_val.value) is True:
                return True
            if isinstance(ret_val, ast.NameConstant) and ret_val.value is True:
                return True
        has_check = any(isinstance(s, (ast.If, ast.Raise, ast.Assert, ast.Try)) for s in ast.walk(func_node))
        if not has_check:
            has_validation = any(isinstance(s, (ast.Compare, ast.Call, ast.BoolOp)) for s in ast.walk(func_node))
            if not has_validation:
                return True
        return False

    def is_sink_call(self, node: ast.AST, scope_id: str = "", lineno: int = 0) -> bool:
        if not isinstance(node, ast.Call): return False
        call_lineno = lineno or getattr(node, "lineno", 0)
        name = dotted_name(node.func) or ""
        canon = self.resolve_canonical_name(node.func, scope_id) if scope_id else name

        if (canon and canon.startswith("defusedxml.")) or (name and name.startswith("defusedxml.")):
            return False
        if canon in SANITIZER_REGISTRY or name in SANITIZER_REGISTRY:
            return False

        # Check for CWE-295 (Disabled SSL verification in HTTP / socket calls)
        if self._has_disabled_ssl(node):
            return True

        # Check for hashlib.new(...) with weak algorithm (CWE-327)
        hashlib_algo = self._get_hashlib_new_algo(node, scope_id)
        if hashlib_algo in ("md5", "sha1", "des"):
            if self._is_exempt_cwe327(node, scope_id, call_lineno):
                return False
            return True

        # Check for CWE-327 exemption (usedforsecurity=False or non-crypto checksum target)
        if self._is_exempt_cwe327(node, scope_id, call_lineno):
            return False

        # Check for CWE-338 (Randomness): only classify as sink in security contexts
        candidates = {c for c in (name, canon) if c}
        for c in list(candidates):
            if "." in c:
                candidates.add(c.split(".")[-1])

        cwe338_names = {
            "random.random", "random.randint", "random.choice", "random.randrange", "random.sample",
            "randint", "randrange", "choice", "sample"
        }
        if candidates & cwe338_names:
            if not self._is_security_sensitive_random(node, scope_id, call_lineno):
                return False

        if canon:
            if canon.startswith("shadowed:"):
                return False
            if name and not name.startswith("builtins.") and not name.startswith("flask.") and scope_id and self._is_builtin_shadowed(name, scope_id, call_lineno):
                return False
            matched = match_sink_rule(node, name, canon)
            if matched:
                if matched.cwe_id == "CWE-327" and self._is_exempt_cwe327(node, scope_id, call_lineno):
                    return False
                if matched.cwe_id == "CWE-338" and not self._is_security_sensitive_random(node, scope_id, call_lineno):
                    return False
                if isinstance(node.func, ast.Attribute) and node.func.attr == "render":
                    if not self._is_jinja_template_expr(node.func.value, scope_id):
                        return False
                return True

        if name:
            if scope_id and not name.startswith("builtins.") and not name.startswith("flask.") and self._is_builtin_shadowed(name, scope_id, call_lineno):
                return False
            matched = match_sink_rule(node, name, canon)
            if matched:
                if matched.cwe_id == "CWE-327" and self._is_exempt_cwe327(node, scope_id, call_lineno):
                    return False
                if matched.cwe_id == "CWE-338" and not self._is_security_sensitive_random(node, scope_id, call_lineno):
                    return False
                if isinstance(node.func, ast.Attribute) and node.func.attr == "render":
                    if not self._is_jinja_template_expr(node.func.value, scope_id):
                        return False
                return True

        # Check direct SINK_REGISTRY membership
        for c in candidates:
            if c in SINK_REGISTRY:
                cwe = SINK_REGISTRY[c].get("cwe")
                if cwe == "CWE-327" and self._is_exempt_cwe327(node, scope_id, call_lineno):
                    return False
                if cwe == "CWE-338" and not self._is_security_sensitive_random(node, scope_id, call_lineno):
                    return False
                return True

        if isinstance(node.func, ast.Attribute):
            if node.func.attr in {"read_text", "read_bytes", "write_text", "write_bytes"}:
                return True
            if node.func.attr == "open" and self._is_path_expr(node.func.value, scope_id):
                return True
            if node.func.attr == "render" and self._is_jinja_template_expr(node.func.value, scope_id):
                return True
            # Unbounded file read without size parameter (CWE-400)
            if node.func.attr == "read" and len(node.args) == 0:
                if self._is_definitely_safe_local_read(node.func.value, scope_id, call_lineno):
                    return False
                return True
        return False

    def check_sink_safety(self, node: ast.Call, sink_name: str) -> bool:
        if self._is_exempt_cwe327(node):
            return True
        if check_sink_safety_rules(node, sink_name):
            return True
        return False

    def get_or_create_sink(self, node: ast.Call, file_path: str, scope_id: str = "", force_cwe: Optional[str] = None) -> SecurityNode:
        loc = location(node, file_path)
        for existing in self.sinks:
            if existing.location == loc and (force_cwe is None or existing.metadata.get("cwe") == force_cwe):
                return existing
        sink_id = self.next_sink_id()
        canon_name = self.resolve_canonical_name(node.func, scope_id) if scope_id else None
        name = dotted_name(node.func) or "sink"

        if force_cwe == "CWE-295":
            meta = {"operation": "DISABLED_SSL_VERIFICATION", "category": "INSECURE_TRANSPORT", "cwe": "CWE-295"}
        else:
            matched_rule = match_sink_rule(node, name, canon_name)
            if matched_rule and isinstance(node.func, ast.Attribute) and node.func.attr == "render":
                if not self._is_jinja_template_expr(node.func.value, scope_id):
                    matched_rule = None
            if matched_rule:
                meta = {"operation": matched_rule.operation, "category": matched_rule.category, "cwe": matched_rule.cwe_id}
            else:
                meta = {}
                # 1. Check for CWE-295: disabled SSL/TLS verification
                if self._has_disabled_ssl(node):
                    meta = {"operation": "DISABLED_SSL_VERIFICATION", "category": "INSECURE_TRANSPORT", "cwe": "CWE-295"}
                # 2. Check for hashlib.new(...) with weak algorithm (CWE-327)
                elif (hashlib_algo := self._get_hashlib_new_algo(node, scope_id)) in ("md5", "sha1", "des"):
                    meta = {
                        "operation": "WEAK_CIPHER" if hashlib_algo == "des" else "WEAK_HASH",
                        "category": "WEAK_CRYPTOGRAPHY",
                        "cwe": "CWE-327"
                    }
                # 3. Check for unbounded read (CWE-400)
                elif isinstance(node.func, ast.Attribute) and node.func.attr == "read" and len(node.args) == 0:
                    meta = {"operation": "UNBOUNDED_READ", "category": "RESOURCE_EXHAUSTION", "cwe": "CWE-400"}
                # 3. Check SINK_REGISTRY
                if not meta:
                    candidates = [c for c in (canon_name, name) if c]
                    for c in candidates:
                        if c in SINK_REGISTRY:
                            meta = dict(SINK_REGISTRY[c])
                            break
                        short_c = c.split(".")[-1]
                        if short_c in SINK_REGISTRY:
                            meta = dict(SINK_REGISTRY[short_c])
                            break
            if not meta and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"read_text", "read_bytes", "write_text", "write_bytes"} or (node.func.attr == "open" and self._is_path_expr(node.func.value, scope_id)):
                    cwe22_rule = get_rule("CWE-22")
                    if cwe22_rule:
                        meta = {"operation": cwe22_rule.operation, "category": cwe22_rule.category, "cwe": cwe22_rule.cwe_id}
                    else:
                        meta = {"operation": "FILE_ACCESS", "category": "PATH_TRAVERSAL", "cwe": "CWE-22"}
        sink = SecurityNode(
            id=sink_id, node_type=NodeType.SINK, symbol=canon_name or name,
            operation=meta.get("operation", "UNKNOWN_OPERATION"), location=loc,
            metadata={"sink_type": meta.get("category", "UNKNOWN_CATEGORY"), "cwe": meta.get("cwe", "UNKNOWN_CWE")}
        )
        self.sinks.append(sink)
        return sink

    def sanitizer_protects_context(self, function_name: str, sink: SecurityNode) -> bool:
        if not sink or not hasattr(sink, "metadata"):
            return False

        # Predicate guards (e.g. is_safe_url, is_safe_redirect_url) are NOT expression sanitizers.
        # They only protect when evaluated as conditional guards enclosing the sink.
        fn_clean = function_name.replace("builtins.", "")
        fn_short = fn_clean.split(".")[-1]
        if fn_clean in CWE_PREDICATE_GUARDS or fn_short in CWE_PREDICATE_GUARDS:
            return False

        sink_cwe = sink.metadata.get("cwe")
        sink_type = sink.metadata.get("sink_type") or sink.metadata.get("category")

        # 1. Check direct CWE registry mapping
        if sink_cwe and sink_cwe in SANITIZER_REGISTRY:
            cwe_sanitizers = SANITIZER_REGISTRY[sink_cwe]
            if isinstance(cwe_sanitizers, (set, list, tuple)):
                if fn_clean in cwe_sanitizers or fn_short in cwe_sanitizers:
                    return True

        # 2. Check function rule dict mapping
        rule = SANITIZER_REGISTRY.get(function_name)
        if not rule and "." in function_name:
            rule = SANITIZER_REGISTRY.get(function_name.split(".")[-1])
        if isinstance(rule, dict):
            return (sink_cwe in rule.get("protected_cwes", set()) or
                    sink_type in rule.get("protected_sinks", set()))
        return False

    def _extract_target_from_parents_attr(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Attribute) and node.attr == "parents":
            val = node.value
            if isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute) and val.func.attr == "resolve":
                return dotted_name(val.func.value)
            return dotted_name(val)
        return None

    def _extract_target_from_relative_to(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "is_relative_to":
            val = node.func.value
            if isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute) and val.func.attr == "resolve":
                return dotted_name(val.func.value)
            return dotted_name(val)
        return None

    def _extract_containment_pairs(self, test_node: ast.AST) -> list[tuple[str, ast.AST]]:
        pairs = []
        if isinstance(test_node, ast.Compare):
            for op, comp in zip(test_node.ops, test_node.comparators):
                if isinstance(op, ast.In):
                    target_name = self._extract_target_from_parents_attr(comp)
                    if target_name:
                        pairs.append((target_name, test_node.left))
                    elif isinstance(test_node.left, ast.Name):
                        pairs.append((test_node.left.id, comp))
        elif isinstance(test_node, ast.UnaryOp) and isinstance(test_node.op, ast.Not):
            # Inverted containment check (e.g., `if not target.is_relative_to(base):`)
            return self._extract_containment_pairs(test_node.operand)
        elif isinstance(test_node, ast.Call):
            if isinstance(test_node.func, ast.Attribute) and test_node.func.attr == "is_relative_to":
                target_name = self._extract_target_from_relative_to(test_node)
                base_arg = test_node.args[0] if test_node.args else None
                if target_name and base_arg:
                    pairs.append((target_name, base_arg))
            elif isinstance(test_node.func, ast.Attribute) and test_node.func.attr == "fullmatch":
                # re.fullmatch(pattern, var) or compiled_pattern.fullmatch(var):
                # a full-match anchor constrains var to a safe character class.
                base_name = dotted_name(test_node.func.value)
                if base_name == "re" and len(test_node.args) >= 2 and isinstance(test_node.args[1], ast.Name):
                    pairs.append((test_node.args[1].id, None))
                elif base_name != "re" and len(test_node.args) >= 1 and isinstance(test_node.args[0], ast.Name):
                    pairs.append((test_node.args[0].id, None))
            else:
                fn_name = dotted_name(test_node.func) or ""
                canon = self.resolve_canonical_name(test_node.func) if hasattr(self, "resolve_canonical_name") else ""
                names_to_check = {fn_name, canon} - {"", None}
                val_funcs = ("is_safe_url", "validate_url", "check_domain_allowlist", "is_allowed_domain",
                             "is_safe_redirect_url", "validate_redirect_url", "url_has_allowed_host_and_scheme",
                             "is_relative_url", "is_private_ip", "validate_private_ip")
                if any(any(n == vf or n.endswith(f".{vf}") for vf in val_funcs) for n in names_to_check):
                    target_arg = None
                    if test_node.args:
                        target_arg = test_node.args[0]
                    elif test_node.keywords:
                        target_arg = test_node.keywords[0].value

                    if target_arg:
                        short_fn = fn_name.split(".")[-1]
                        func_node = None
                        for f_scope, f_def in self.functions.items():
                            if f_def.name == short_fn or f_scope.endswith(f":{short_fn}"):
                                func_node = f_def
                                break
                        if func_node and self._is_dummy_validator_func(func_node):
                            pass  # Dummy validator (e.g. return True): DO NOT create containment guard!
                        else:
                            # External / imported validator (func_node is None) or valid local validator:
                            # Create containment guard for the protected variable!
                            if isinstance(target_arg, ast.Name):
                                pairs.append((target_arg.id, None))
                            elif isinstance(target_arg, ast.Attribute):
                                pairs.append((target_arg.attr, None))
        elif isinstance(test_node, ast.BoolOp) and isinstance(test_node.op, ast.And):
            for val in test_node.values:
                pairs.extend(self._extract_containment_pairs(val))
        return pairs

    def is_var_contained(self, var_name: str, scope_id: str, lineno: int, sink: Optional[SecurityNode] = None, visited: Optional[set[str]] = None) -> bool:
        if sink is not None:
            cwe = sink.metadata.get("cwe")
            stype = sink.metadata.get("sink_type")
            allowed_cwes = {"CWE-22", "CWE-918", "CWE-601", "CWE-400", "CWE-1333"}
            allowed_types = {"PATH_TRAVERSAL", "FILE_ACCESS", "SSRF", "OPEN_REDIRECT", "REGEX_COMPILATION", "RESOURCE_EXHAUSTION"}
            if cwe not in allowed_cwes and stype not in allowed_types:
                return False

        if visited is not None and f"guard_check:{scope_id}:{var_name}" in visited:
            return False

        sink_line = sink.location.line_start if (sink and hasattr(sink, "location") and sink.location) else lineno

        for guard in self.containment_guards:
            if guard["var_name"] == var_name:
                if guard["scope_id"] == scope_id or scope_id.startswith(guard["scope_id"] + "."):
                    if sink and hasattr(sink, "location") and sink.location:
                        is_in_body = (guard["start_line"] <= sink_line <= guard["end_line"])
                    else:
                        is_in_body = (guard["start_line"] <= lineno <= guard["end_line"])
                    if is_in_body:
                        # Check if var_name was reassigned between check_line and current evaluation line
                        check_pt = max(lineno, sink_line)
                        recs = self.assignments_by_scope.get((guard["scope_id"], var_name), [])
                        reassigned = any(guard["check_line"] < r.lineno <= check_pt for r in recs)
                        if reassigned:
                            continue

                        # Check if base_node is clean (not tainted by user input)
                        base_node = guard.get("base_node")
                        if base_node:
                            base_visited = visited.copy() if visited is not None else set()
                            base_visited.add(f"guard_check:{guard['scope_id']}:{var_name}")
                            base_taint = self.resolve_expression(base_node, sink, guard["scope_id"], guard["check_line"], base_visited)
                            if base_taint.state == TaintState.TAINTED:
                                continue
                        return True
        return False

    def _resolve_transitive_import(self, r_mod: str, r_func: str, visited: set[str], depth: int) -> str | None:
        if depth > 5 or r_mod not in self.imports:
            return None
        f_parts = r_func.split(".")
        for j in range(len(f_parts), 0, -1):
            f_head = ".".join(f_parts[:j])
            f_tail = ".".join(f_parts[j:])
            if f_head in self.imports[r_mod]:
                imported_target = self.imports[r_mod][f_head]
                full_target = imported_target + ("." + f_tail if f_tail else "")
                visit_key = f"{r_mod}->{full_target}"
                if visit_key not in visited:
                    v_copy = visited.copy()
                    v_copy.add(visit_key)
                    res = self._resolve_function_scope(full_target, f"{r_mod}:global", v_copy, depth + 1)
                    if res:
                        return res
        return None

    def _resolve_function_scope(self, call_name: str, current_scope: str, visited: Optional[set[str]] = None, depth: int = 0) -> str | None:
        if visited is None:
            visited = set()
        if depth > 5:
            return None
        mod_name = current_scope.split(":")[0]
        if "function:" in current_scope:
            nested = f"{current_scope}.{call_name}"
            if nested in self.functions: return nested
        local_glob = f"{mod_name}:function:{call_name}"
        if local_glob in self.functions: return local_glob
        parts = call_name.split(".")

        if len(parts) > 1:
            for i in range(len(parts)-1, 0, -1):
                r_mod = ".".join(parts[:i])
                r_func = ".".join(parts[i:])
                test_scope = f"{r_mod}:function:{r_func}"
                if test_scope in self.functions: return test_scope
                trans = self._resolve_transitive_import(r_mod, r_func, visited, depth)
                if trans: return trans

        base_name = parts[0]
        # Check if base_name is a variable holding a class instance (e.g. loader = Loader(); loader.method)
        if len(parts) > 1:
            method_attr = ".".join(parts[1:])
            curr = current_scope
            while curr:
                recs = self.assignments_by_scope.get((curr, base_name), [])
                if recs:
                    latest = recs[-1]
                    if isinstance(latest.value_node, ast.Call):
                        cls_name = dotted_name(latest.value_node.func)
                        if cls_name:
                            shadowed = False
                            cls_recs = [r for r in self.assignments_by_scope.get((curr, cls_name), []) if r.lineno < latest.lineno]
                            if cls_recs:
                                last_cls_rec = cls_recs[-1]
                                if not isinstance(last_cls_rec.value_node, ast.Name):
                                    shadowed = True

                            if not shadowed:
                                candidate = f"{mod_name}:function:{cls_name}.{method_attr}"
                                if candidate in self.functions: return candidate

                                resolved_cls = None
                                if cls_name in self.imports.get(mod_name, {}):
                                    resolved_cls = self.imports[mod_name][cls_name]
                                else:
                                    cls_parts = cls_name.split(".")
                                    if cls_parts[0] in self.imports.get(mod_name, {}):
                                        res_base = self.imports[mod_name][cls_parts[0]]
                                        resolved_cls = res_base + "." + ".".join(cls_parts[1:])

                                if resolved_cls:
                                    parts_cls = resolved_cls.split(".")
                                    for i in range(len(parts_cls)-1, 0, -1):
                                        r_mod = ".".join(parts_cls[:i])
                                        r_cls = ".".join(parts_cls[i:])
                                        cand = f"{r_mod}:function:{r_cls}.{method_attr}"
                                        if cand in self.functions: return cand
                                        trans = self._resolve_transitive_import(r_mod, f"{r_cls}.{method_attr}", visited, depth)
                                        if trans: return trans
                    break
                if "." in curr and "function" in curr: curr = curr.rsplit(".", 1)[0]
                elif ":function" in curr: curr = f"{mod_name}:global"
                elif curr != f"{mod_name}:global": curr = f"{mod_name}:global"
                else: break

        if base_name in self.imports.get(mod_name, {}):
            resolved_base = self.imports[mod_name][base_name]
            resolved_full = resolved_base + "." + ".".join(parts[1:]) if len(parts) > 1 else resolved_base
            parts2 = resolved_full.split(".")
            for i in range(len(parts2)-1, 0, -1):
                r_mod = ".".join(parts2[:i])
                r_func = ".".join(parts2[i:])
                test_scope = f"{r_mod}:function:{r_func}"
                if test_scope in self.functions: return test_scope
                trans = self._resolve_transitive_import(r_mod, r_func, visited, depth)
                if trans: return trans
        return None

    def _get_enclosing_class_scope(self, scope_id: str) -> Optional[str]:
        curr = scope_id
        while curr:
            if curr in self.classes:
                return curr
            if "." in curr:
                curr = curr.rsplit(".", 1)[0]
            else:
                break
        if ":function:" in scope_id:
            prefix, func_part = scope_id.split(":function:", 1)
            if "." in func_part:
                cls_candidate = f"{prefix}:function:{func_part.split('.')[0]}"
                return cls_candidate
        return None

    def _resolve_instance_class_scope(self, var_name: str, scope_id: str) -> Optional[str]:
        curr = scope_id
        mod_name = scope_id.split(":")[0] if scope_id else ""
        while curr:
            recs = self.assignments_by_scope.get((curr, var_name), [])
            if recs:
                latest = recs[-1]
                if isinstance(latest.value_node, ast.Call):
                    cls_name = dotted_name(latest.value_node.func)
                    if cls_name:
                        cand = f"{mod_name}:function:{cls_name}"
                        if cand in self.classes or any(k[0] == cand for k in self.class_field_assignments):
                            return cand
                break
            if "." in curr and "function" in curr:
                curr = curr.rsplit(".", 1)[0]
            elif ":function" in curr:
                curr = f"{mod_name}:global"
            elif curr != f"{mod_name}:global":
                curr = f"{mod_name}:global"
            else:
                break
        return None

    def merge_taints(self, taints: list[TaintValue], node_id: str) -> TaintValue:
        if not taints: return TaintValue(state=TaintState.CLEAN)
        if all(t.state == TaintState.CLEAN for t in taints):
            return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"clean:{node_id}")
        all_tainted = all(t.state == TaintState.TAINTED for t in taints)
        first_tainted = next((t for t in taints if t.state != TaintState.CLEAN), taints[0])
        combined_path = []
        for t in taints:
            if t.state != TaintState.CLEAN: combined_path.extend(t.path)
        combined_path.append(node_id)

        candidate = max((t for t in taints if t.state == TaintState.TAINTED), key=lambda t: t.confidence, default=first_tainted)
        active_taints = [t for t in taints if t.state != TaintState.CLEAN]
        if not active_taints:
            active_taints = [first_tainted]

        seen_node_ids = set()
        merged_nodes = []
        merged_edges = []
        seen_edge_keys = set()

        for t in active_taints:
            for n in t.proof_nodes:
                if n.node_id not in seen_node_ids:
                    seen_node_ids.add(n.node_id)
                    merged_nodes.append(n)
            for e in t.proof_edges:
                e_key = (e.from_node_id, e.to_node_id, e.edge_type)
                if e_key not in seen_edge_keys:
                    seen_edge_keys.add(e_key)
                    merged_edges.append(e)

        f_path = node_id.split(":")[0] if ":" in node_id else "target.py"
        sym_name = node_id.split(":")[-1] if ":" in node_id else node_id
        step_idx = len(merged_nodes)
        merge_pn = ProofNode(
            node_id=f"assignment:{f_path}:0:{sym_name}#{step_idx}",
            step_index=step_idx,
            node_type=ProofNodeType.ASSIGNMENT if not sym_name.startswith("return") else ProofNodeType.TRANSFORM,
            file_path=f_path,
            start_line=1,
            end_line=1,
            symbol=sym_name,
            expression_snippet=f"merge({sym_name})",
            scope_id=f_path
        )
        for t in active_taints:
            if t.proof_nodes:
                b_edge = ProofEdge(from_node_id=t.proof_nodes[-1].node_id, to_node_id=merge_pn.node_id, edge_type="BRANCH_MERGE")
                e_key = (b_edge.from_node_id, b_edge.to_node_id, b_edge.edge_type)
                if e_key not in seen_edge_keys:
                    seen_edge_keys.add(e_key)
                    merged_edges.append(b_edge)
        merged_nodes.append(merge_pn)

        if all_tainted:
            return TaintValue(state=TaintState.TAINTED, source_id=first_tainted.source_id, confidence=min(t.confidence for t in taints), path=combined_path, last_operation=f"merged:{node_id}", proof_nodes=merged_nodes, proof_edges=merged_edges)
        return TaintValue(state=TaintState.UNKNOWN, source_id=first_tainted.source_id, confidence=0.50, path=combined_path, last_operation=f"path_dependent:{node_id}", proof_nodes=merged_nodes, proof_edges=merged_edges)

    def _collect_calls_in_expr(self, expr: ast.AST, scope_id: str, lineno: int):
        for subnode in ast.walk(expr):
            if isinstance(subnode, ast.Call):
                self.raw_calls.append((subnode, scope_id, getattr(subnode, "lineno", lineno)))

    def _collect_named_exprs(self, expr: ast.AST, scope_id: str, lineno: int, is_conditional: bool = False):
        if not expr:
            return
        for subnode in ast.walk(expr):
            if isinstance(subnode, ast.NamedExpr):
                if isinstance(subnode.target, ast.Name):
                    t_lineno = getattr(subnode, "lineno", lineno)
                    record = AssignmentRecord(
                        target_name=subnode.target.id,
                        value_node=subnode.value,
                        lineno=t_lineno,
                        scope_id=scope_id,
                        is_conditional=is_conditional
                    )
                    self.assignments_by_scope.setdefault((scope_id, subnode.target.id), []).append(record)
                    if scope_id in self.classes:
                        self.class_field_assignments.setdefault((scope_id, subnode.target.id), []).append(record)

    def collect_statements(self, statements: list[ast.stmt], scope_id: str, is_conditional: bool = False):
        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                child_scope = f"{scope_id}.{stmt.name}" if ":global" not in scope_id else f"{scope_id.split(':')[0]}:function:{stmt.name}"
                self.functions[child_scope] = stmt
                self.collect_statements(stmt.body, scope_id=child_scope, is_conditional=False)
            elif isinstance(stmt, ast.ClassDef):
                mod_name = scope_id.split(":")[0]
                class_scope = f"{scope_id}.{stmt.name}" if ":global" not in scope_id else f"{mod_name}:function:{stmt.name}"
                self.classes.add(class_scope)
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_scope = f"{mod_name}:function:{stmt.name}.{item.name}"
                        self.functions[method_scope] = item
                        self.collect_statements(item.body, scope_id=method_scope, is_conditional=False)
                    else:
                        self.collect_statements([item], scope_id=class_scope, is_conditional=is_conditional)
            elif isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        record = AssignmentRecord(target_name=target.id, value_node=stmt.value, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                        self.assignments_by_scope.setdefault((scope_id, target.id), []).append(record)
                        if scope_id in self.classes:
                            self.class_field_assignments.setdefault((scope_id, target.id), []).append(record)
                    elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id in ("self", "cls"):
                        cls_scope = self._get_enclosing_class_scope(scope_id)
                        if cls_scope:
                            record = AssignmentRecord(target_name=target.attr, value_node=stmt.value, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                            self.class_field_assignments.setdefault((cls_scope, target.attr), []).append(record)
                    elif isinstance(target, ast.Subscript):
                        key = self._extract_subscript_key(target.slice, scope_id)
                        if key is not None:
                            if isinstance(target.value, ast.Name):
                                comp_key = f"{target.value.id}[{key}]"
                                record = AssignmentRecord(target_name=comp_key, value_node=stmt.value, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                                self.assignments_by_scope.setdefault((scope_id, comp_key), []).append(record)
                            elif isinstance(target.value, ast.Attribute) and isinstance(target.value.value, ast.Name) and target.value.value.id in ("self", "cls"):
                                cls_scope = self._get_enclosing_class_scope(scope_id)
                                if cls_scope:
                                    comp_key = f"{target.value.attr}[{key}]"
                                    record = AssignmentRecord(target_name=comp_key, value_node=stmt.value, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                                    self.class_field_assignments.setdefault((cls_scope, comp_key), []).append(record)
                        elif isinstance(target.value, ast.Attribute) and isinstance(target.value.value, ast.Name) and target.value.value.id in ("self", "cls"):
                            # Dynamic-key instance container write: self.field[k] = value
                            cls_scope = self._get_enclosing_class_scope(scope_id)
                            if cls_scope:
                                self.instance_field_writes.setdefault((cls_scope, target.value.attr), []).append((stmt.lineno, stmt.value, scope_id))
                    elif isinstance(target, (ast.Tuple, ast.List)):
                        for idx, elt in enumerate(target.elts):
                            val_node = stmt.value.elts[idx] if (isinstance(stmt.value, (ast.Tuple, ast.List)) and idx < len(stmt.value.elts)) else stmt.value
                            if isinstance(elt, ast.Name):
                                record = AssignmentRecord(target_name=elt.id, value_node=val_node, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                                self.assignments_by_scope.setdefault((scope_id, elt.id), []).append(record)
                                if scope_id in self.classes:
                                    self.class_field_assignments.setdefault((scope_id, elt.id), []).append(record)
                            elif isinstance(elt, ast.Attribute) and isinstance(elt.value, ast.Name) and elt.value.id in ("self", "cls"):
                                cls_scope = self._get_enclosing_class_scope(scope_id)
                                if cls_scope:
                                    record = AssignmentRecord(target_name=elt.attr, value_node=val_node, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                                    self.class_field_assignments.setdefault((cls_scope, elt.attr), []).append(record)
                            elif isinstance(elt, ast.Subscript):
                                key = self._extract_subscript_key(elt.slice, scope_id)
                                if key is not None and isinstance(elt.value, ast.Name):
                                    comp_key = f"{elt.value.id}[{key}]"
                                    record = AssignmentRecord(target_name=comp_key, value_node=val_node, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                                    self.assignments_by_scope.setdefault((scope_id, comp_key), []).append(record)
                self.scan_for_sinks(stmt.value, scope_id, stmt.lineno)
                self._collect_calls_in_expr(stmt.value, scope_id, stmt.lineno)
                self._collect_named_exprs(stmt.value, scope_id, stmt.lineno, is_conditional=is_conditional)
            elif isinstance(stmt, ast.AnnAssign):
                if isinstance(stmt.target, ast.Name) and stmt.value:
                    record = AssignmentRecord(target_name=stmt.target.id, value_node=stmt.value, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                    self.assignments_by_scope.setdefault((scope_id, stmt.target.id), []).append(record)
                    if scope_id in self.classes:
                        self.class_field_assignments.setdefault((scope_id, stmt.target.id), []).append(record)
                elif isinstance(stmt.target, ast.Attribute) and isinstance(stmt.target.value, ast.Name) and stmt.target.value.id in ("self", "cls") and stmt.value:
                    cls_scope = self._get_enclosing_class_scope(scope_id)
                    if cls_scope:
                        record = AssignmentRecord(target_name=stmt.target.attr, value_node=stmt.value, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                        self.class_field_assignments.setdefault((cls_scope, stmt.target.attr), []).append(record)
                elif isinstance(stmt.target, ast.Subscript) and stmt.value:
                    key = self._extract_subscript_key(stmt.target.slice, scope_id)
                    if key is not None:
                        if isinstance(stmt.target.value, ast.Name):
                            comp_key = f"{stmt.target.value.id}[{key}]"
                            record = AssignmentRecord(target_name=comp_key, value_node=stmt.value, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                            self.assignments_by_scope.setdefault((scope_id, comp_key), []).append(record)
                        elif isinstance(stmt.target.value, ast.Attribute) and isinstance(stmt.target.value.value, ast.Name) and stmt.target.value.value.id in ("self", "cls"):
                            cls_scope = self._get_enclosing_class_scope(scope_id)
                            if cls_scope:
                                comp_key = f"{stmt.target.value.attr}[{key}]"
                                record = AssignmentRecord(target_name=comp_key, value_node=stmt.value, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                                self.class_field_assignments.setdefault((cls_scope, comp_key), []).append(record)
                if stmt.value:
                    self.scan_for_sinks(stmt.value, scope_id, stmt.lineno)
                    self._collect_calls_in_expr(stmt.value, scope_id, stmt.lineno)
                    self._collect_named_exprs(stmt.value, scope_id, stmt.lineno, is_conditional=is_conditional)
            elif isinstance(stmt, ast.AugAssign):
                # x += rhs: taint on rhs must propagate onto the existing target x.
                # Model the Name target as `x <op> rhs` so that prior taint on x and
                # new taint from rhs are combined (never loses an existing taint).
                if isinstance(stmt.target, ast.Name):
                    combined = ast.BinOp(
                        left=ast.Name(id=stmt.target.id, ctx=ast.Load()),
                        op=stmt.op,
                        right=stmt.value,
                    )
                    ast.copy_location(combined, stmt)
                    ast.copy_location(combined.left, stmt)
                    ast.fix_missing_locations(combined)
                    record = AssignmentRecord(target_name=stmt.target.id, value_node=combined, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                    self.assignments_by_scope.setdefault((scope_id, stmt.target.id), []).append(record)
                    if scope_id in self.classes:
                        self.class_field_assignments.setdefault((scope_id, stmt.target.id), []).append(record)
                elif isinstance(stmt.target, ast.Attribute) and isinstance(stmt.target.value, ast.Name) and stmt.target.value.id in ("self", "cls"):
                    cls_scope = self._get_enclosing_class_scope(scope_id)
                    if cls_scope:
                        record = AssignmentRecord(target_name=stmt.target.attr, value_node=stmt.value, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                        self.class_field_assignments.setdefault((cls_scope, stmt.target.attr), []).append(record)
                elif isinstance(stmt.target, ast.Subscript):
                    key = self._extract_subscript_key(stmt.target.slice, scope_id)
                    if key is not None:
                        if isinstance(stmt.target.value, ast.Name):
                            comp_key = f"{stmt.target.value.id}[{key}]"
                            record = AssignmentRecord(target_name=comp_key, value_node=stmt.value, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                            self.assignments_by_scope.setdefault((scope_id, comp_key), []).append(record)
                        elif isinstance(stmt.target.value, ast.Attribute) and isinstance(stmt.target.value.value, ast.Name) and stmt.target.value.value.id in ("self", "cls"):
                            cls_scope = self._get_enclosing_class_scope(scope_id)
                            if cls_scope:
                                comp_key = f"{stmt.target.value.attr}[{key}]"
                                record = AssignmentRecord(target_name=comp_key, value_node=stmt.value, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                                self.class_field_assignments.setdefault((cls_scope, comp_key), []).append(record)
                    elif isinstance(stmt.target.value, ast.Attribute) and isinstance(stmt.target.value.value, ast.Name) and stmt.target.value.value.id in ("self", "cls"):
                        cls_scope = self._get_enclosing_class_scope(scope_id)
                        if cls_scope:
                            self.instance_field_writes.setdefault((cls_scope, stmt.target.value.attr), []).append((stmt.lineno, stmt.value, scope_id))
                self.scan_for_sinks(stmt.value, scope_id, stmt.lineno)
                self._collect_calls_in_expr(stmt.value, scope_id, stmt.lineno)
                self._record_container_mutation(stmt.value, scope_id, stmt.lineno)
                self._collect_named_exprs(stmt.value, scope_id, stmt.lineno, is_conditional=is_conditional)
            elif isinstance(stmt, ast.If):
                self.scan_for_sinks(stmt.test, scope_id, stmt.lineno)
                self._collect_calls_in_expr(stmt.test, scope_id, stmt.lineno)
                self._collect_named_exprs(stmt.test, scope_id, stmt.lineno, is_conditional=False)
                pairs = self._extract_containment_pairs(stmt.test)
                if pairs:
                    is_inverted = isinstance(stmt.test, ast.UnaryOp) and isinstance(stmt.test.op, ast.Not)
                    body_terminates = any(isinstance(s, (ast.Raise, ast.Return)) for s in stmt.body)
                    if is_inverted and body_terminates:
                        # Control-flow static analysis for guard clauses:
                        # When `if not target.is_relative_to(safe_base):` terminates unconditionally
                        # via raise or return, all subsequent statements in the scope are guaranteed
                        # to execute only if containment was satisfied.
                        for target_name, base_node in pairs:
                            self.containment_guards.append({
                                "var_name": target_name,
                                "base_node": base_node,
                                "scope_id": scope_id,
                                "check_line": stmt.lineno,
                                "start_line": stmt.lineno + 1,
                                "end_line": 999999,
                            })
                    elif not is_inverted and stmt.body:
                        body_start = stmt.body[0].lineno
                        body_end = max(getattr(s, "end_lineno", s.lineno) for s in stmt.body)
                        for target_name, base_node in pairs:
                            self.containment_guards.append({
                                "var_name": target_name,
                                "base_node": base_node,
                                "scope_id": scope_id,
                                "check_line": stmt.lineno,
                                "start_line": body_start,
                                "end_line": body_end,
                            })
                    elif is_inverted and stmt.orelse:
                        orelse_start = stmt.orelse[0].lineno
                        orelse_end = max(getattr(s, "end_lineno", s.lineno) for s in stmt.orelse)
                        for target_name, base_node in pairs:
                            self.containment_guards.append({
                                "var_name": target_name,
                                "base_node": base_node,
                                "scope_id": scope_id,
                                "check_line": stmt.lineno,
                                "start_line": orelse_start,
                                "end_line": orelse_end,
                            })
                self.collect_statements(stmt.body, scope_id=scope_id, is_conditional=True)
                self.collect_statements(stmt.orelse, scope_id=scope_id, is_conditional=True)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                if isinstance(stmt, ast.While):
                    self.scan_for_sinks(stmt.test, scope_id, stmt.lineno)
                    self._collect_calls_in_expr(stmt.test, scope_id, stmt.lineno)
                    self._collect_named_exprs(stmt.test, scope_id, stmt.lineno, is_conditional=False)
                else:
                    self.scan_for_sinks(stmt.iter, scope_id, stmt.lineno)
                    self._collect_calls_in_expr(stmt.iter, scope_id, stmt.lineno)
                    self._collect_named_exprs(stmt.iter, scope_id, stmt.lineno, is_conditional=is_conditional)
                    targets = []
                    if isinstance(stmt.target, ast.Name):
                        targets.append(stmt.target.id)
                    elif isinstance(stmt.target, (ast.Tuple, ast.List)):
                        for elt in stmt.target.elts:
                            if isinstance(elt, ast.Name):
                                targets.append(elt.id)
                    for t_name in targets:
                        record = AssignmentRecord(target_name=t_name, value_node=stmt.iter, lineno=stmt.lineno, scope_id=scope_id, is_conditional=True)
                        self.assignments_by_scope.setdefault((scope_id, t_name), []).append(record)
                self.collect_statements(stmt.body, scope_id=scope_id, is_conditional=True)
                self.collect_statements(stmt.orelse, scope_id=scope_id, is_conditional=True)
            elif isinstance(stmt, ast.Try):
                self.collect_statements(stmt.body, scope_id=scope_id, is_conditional=True)
                for handler in stmt.handlers: self.collect_statements(handler.body, scope_id=scope_id, is_conditional=True)
                self.collect_statements(stmt.orelse, scope_id=scope_id, is_conditional=True)
                self.collect_statements(stmt.finalbody, scope_id=scope_id, is_conditional=False)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    self.scan_for_sinks(item.context_expr, scope_id, stmt.lineno)
                    self._collect_calls_in_expr(item.context_expr, scope_id, stmt.lineno)
                    self._collect_named_exprs(item.context_expr, scope_id, stmt.lineno, is_conditional=is_conditional)
                    if item.optional_vars:
                        targets = []
                        if isinstance(item.optional_vars, ast.Name):
                            targets.append(item.optional_vars.id)
                        elif isinstance(item.optional_vars, (ast.Tuple, ast.List)):
                            for elt in item.optional_vars.elts:
                                if isinstance(elt, ast.Name):
                                    targets.append(elt.id)
                        for t_name in targets:
                            record = AssignmentRecord(target_name=t_name, value_node=item.context_expr, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                            self.assignments_by_scope.setdefault((scope_id, t_name), []).append(record)
                self.collect_statements(stmt.body, scope_id=scope_id, is_conditional=is_conditional)
            elif isinstance(stmt, ast.Return):
                self.returns_by_scope.setdefault(scope_id, []).append(stmt)
                if stmt.value:
                    self.scan_for_sinks(stmt.value, scope_id, stmt.lineno)
                    self._collect_calls_in_expr(stmt.value, scope_id, stmt.lineno)
                    self._collect_named_exprs(stmt.value, scope_id, stmt.lineno, is_conditional=is_conditional)
            elif isinstance(stmt, ast.Expr):
                if isinstance(stmt.value, (ast.Yield, ast.YieldFrom)):
                    self.returns_by_scope.setdefault(scope_id, []).append(stmt.value)
                self._record_container_mutation(stmt.value, scope_id, stmt.lineno)
                self.scan_for_sinks(stmt.value, scope_id, stmt.lineno)
                self._collect_calls_in_expr(stmt.value, scope_id, stmt.lineno)
                self._collect_named_exprs(stmt.value, scope_id, stmt.lineno, is_conditional=is_conditional)

    def _record_container_mutation(self, expr: ast.AST, scope_id: str, lineno: int):
        """Record `container.append/extend/insert/add/update(x)` so a later
        `"".join(container)` can see taint introduced by mutation."""
        if not isinstance(expr, ast.Call) or not isinstance(expr.func, ast.Attribute):
            return
        attr = expr.func.attr
        if attr not in CONTAINER_MUTATION_METHODS:
            return
        if not isinstance(expr.func.value, ast.Name):
            return
        arg_idx = CONTAINER_MUTATION_METHODS[attr]
        if arg_idx >= len(expr.args):
            return
        var_name = expr.func.value.id
        self.list_mutations.setdefault((scope_id, var_name), []).append((lineno, expr.args[arg_idx]))

    def _resolve_container_mutation_taint(self, container_node, sink, scope_id, current_lineno, visited, call_context):
        """Resolve taint introduced into a container via .append()/.extend()/etc.
        Returns a merged TaintValue or None when the container has no tracked mutations."""
        if not isinstance(container_node, ast.Name):
            return None
        var_name = container_node.id
        mod_name = scope_id.split(":")[0] if scope_id else ""
        muts = self.list_mutations.get((scope_id, var_name))
        if not muts:
            curr = scope_id
            while curr:
                muts = self.list_mutations.get((curr, var_name))
                if muts:
                    break
                if "." in curr and "function" in curr:
                    curr = curr.rsplit(".", 1)[0]
                elif ":function" in curr:
                    curr = f"{mod_name}:global"
                elif curr != f"{mod_name}:global":
                    curr = f"{mod_name}:global"
                else:
                    break
        if not muts:
            return None
        results = []
        for lineno, val_node in muts:
            if lineno >= current_lineno:
                continue
            results.append(self.resolve_expression(val_node, sink, scope_id, lineno, visited.copy(), call_context))
        if not results:
            return None
        return self.merge_taints(results, f"{scope_id}:{var_name}:mutations")

    def _resolve_instance_field_write_taint(self, cls_scope, attr, sink, visited):
        """Resolve taint written into an instance container via a dynamic-key write
        (self.field[k] = value), binding the writing method's parameters to the
        arguments passed at each call site."""
        writes = self.instance_field_writes.get((cls_scope, attr))
        if not writes:
            return None
        results = []
        for lineno, value_node, method_scope in writes:
            f_node = self.functions.get(method_scope)
            param_names = [a.arg for a in f_node.args.args] if f_node else []
            call_sites = self.call_sites_by_target.get(method_scope, [])
            if call_sites and param_names:
                has_self = param_names[0] in ("self", "cls")
                for call_node, caller_scope, call_lineno in call_sites:
                    ctx = {}
                    for i, p in enumerate(param_names):
                        if p in ("self", "cls"):
                            continue
                        arg_idx = i - 1 if has_self else i
                        arg_node = None
                        for kw in getattr(call_node, "keywords", []):
                            if kw.arg == p:
                                arg_node = kw.value
                                break
                        if arg_node is None and 0 <= arg_idx < len(call_node.args):
                            arg_node = call_node.args[arg_idx]
                        if arg_node is not None:
                            ctx[p] = self.resolve_expression(arg_node, sink, caller_scope, call_lineno, visited.copy(), {})
                    results.append(self.resolve_expression(value_node, sink, method_scope, lineno, visited.copy(), ctx))
            else:
                results.append(self.resolve_expression(value_node, sink, method_scope, lineno, visited.copy(), {}))
        if not results:
            return None
        return self.merge_taints(results, f"{cls_scope}:{attr}:field_writes")

    def scan_for_sinks(self, expr: ast.AST, scope_id: str, lineno: int):
        mod_name = scope_id.split(":")[0]
        file_path = self.file_paths.get(mod_name, "unknown.py")
        for subnode in ast.walk(expr):
            call_lineno = getattr(subnode, "lineno", lineno)
            if isinstance(subnode, ast.Call) and self.is_sink_call(subnode, scope_id, call_lineno):
                canon_name = self.resolve_canonical_name(subnode.func, scope_id) or dotted_name(subnode.func) or ""
                if not self.check_sink_safety(subnode, canon_name):
                    sink_node = self.get_or_create_sink(subnode, file_path, scope_id)
                    self.sink_records.append(SinkRecord(node=subnode, security_node=sink_node, lineno=call_lineno, scope_id=scope_id))
                    if sink_node.metadata.get("cwe") != "CWE-295" and self._has_disabled_ssl(subnode):
                        ssl_sink = self.get_or_create_sink(subnode, file_path, scope_id, force_cwe="CWE-295")
                        self.sink_records.append(SinkRecord(node=subnode, security_node=ssl_sink, lineno=call_lineno, scope_id=scope_id))

    def _is_string_expr(self, expr_node: ast.AST, scope_id: str) -> bool:
        if isinstance(expr_node, ast.Constant) and isinstance(expr_node.value, str):
            return True
        if isinstance(expr_node, ast.JoinedStr):
            return True
        if isinstance(expr_node, ast.Name):
            curr = scope_id
            mod_name = scope_id.split(":")[0]
            while curr:
                recs = self.assignments_by_scope.get((curr, expr_node.id), [])
                if recs:
                    latest = recs[-1]
                    if isinstance(latest.value_node, ast.Constant) and isinstance(latest.value_node.value, str):
                        return True
                    if isinstance(latest.value_node, ast.JoinedStr):
                        return True
                    break
                if "." in curr and "function" in curr: curr = curr.rsplit(".", 1)[0]
                elif ":function" in curr: curr = f"{mod_name}:global"
                elif curr != f"{mod_name}:global": curr = f"{mod_name}:global"
                else: break
        return False

    def _is_path_expr(self, expr_node: ast.AST, scope_id: str) -> bool:
        if isinstance(expr_node, ast.Call):
            fname = self.resolve_canonical_name(expr_node.func, scope_id) or dotted_name(expr_node.func) or ""
            if fname in ("Path", "pathlib.Path"):
                return True
            if isinstance(expr_node.func, ast.Attribute) and expr_node.func.attr in ("resolve", "absolute", "expanduser", "joinpath"):
                return self._is_path_expr(expr_node.func.value, scope_id)
            if isinstance(expr_node.func, ast.Attribute) and expr_node.func.attr in ("cwd", "home"):
                return fname in ("Path.cwd", "pathlib.Path.cwd", "Path.home", "pathlib.Path.home")
        if isinstance(expr_node, ast.Attribute):
            if expr_node.attr in ("parent", "parents", "name", "stem", "suffix", "suffixes"):
                return self._is_path_expr(expr_node.value, scope_id)
        if isinstance(expr_node, ast.BinOp) and isinstance(expr_node.op, ast.Div):
            return self._is_path_expr(expr_node.left, scope_id) or self._is_path_expr(expr_node.right, scope_id)
        if isinstance(expr_node, ast.Name):
            curr = scope_id
            mod_name = scope_id.split(":")[0]
            while curr:
                recs = self.assignments_by_scope.get((curr, expr_node.id), [])
                if recs:
                    latest = recs[-1]
                    if self._is_path_expr(latest.value_node, curr):
                        return True
                    break
                if "." in curr and "function" in curr: curr = curr.rsplit(".", 1)[0]
                elif ":function" in curr: curr = f"{mod_name}:global"
                elif curr != f"{mod_name}:global": curr = f"{mod_name}:global"
                else: break
        return False

    def _is_jinja_imported(self, mod_name: str) -> bool:
        if not mod_name or mod_name not in self.imports:
            return False
        return any(v == "jinja2" or v.startswith("jinja2.") for v in self.imports[mod_name].values())

    def _is_jinja_env_expr(self, expr_node: ast.AST, scope_id: str, visited: Optional[set[str]] = None) -> bool:
        if visited is None: visited = set()
        mod_name = scope_id.split(":")[0] if scope_id else ""

        if isinstance(expr_node, ast.Call):
            fname = self.resolve_canonical_name(expr_node.func, scope_id) or dotted_name(expr_node.func) or ""
            if fname == "jinja2.Environment":
                return True
            if fname == "Environment" and (self._is_jinja_imported(mod_name) or not self.imports.get(mod_name)):
                if not self._resolve_function_scope("Environment", scope_id):
                    return True

            func_scope = self._resolve_function_scope(fname, scope_id)
            if func_scope and func_scope not in visited:
                visited.add(func_scope)
                returns = self.returns_by_scope.get(func_scope, [])
                for r in returns:
                    if r.value and self._is_jinja_env_expr(r.value, func_scope, visited.copy()):
                        return True

        if isinstance(expr_node, ast.Name):
            var_key = f"{scope_id}:{expr_node.id}"
            if var_key in visited: return False
            visited.add(var_key)
            curr = scope_id
            while curr:
                recs = self.assignments_by_scope.get((curr, expr_node.id), [])
                if recs:
                    latest = recs[-1]
                    return self._is_jinja_env_expr(latest.value_node, curr, visited.copy())
                if "." in curr and "function" in curr: curr = curr.rsplit(".", 1)[0]
                elif ":function" in curr: curr = f"{mod_name}:global"
                elif curr != f"{mod_name}:global": curr = f"{mod_name}:global"
                else: break

        return False

    def _is_jinja_template_expr(self, expr_node: ast.AST, scope_id: str, visited: Optional[set[str]] = None) -> bool:
        if visited is None: visited = set()
        mod_name = scope_id.split(":")[0] if scope_id else ""

        if isinstance(expr_node, ast.Call):
            fname = self.resolve_canonical_name(expr_node.func, scope_id) or dotted_name(expr_node.func) or ""
            # 1. Direct instantiation: Call to Template() or jinja2.Template() (matching resolved import)
            if fname == "jinja2.Template":
                return True
            if fname == "Template" and (self._is_jinja_imported(mod_name) or not self.imports.get(mod_name)):
                if not self._resolve_function_scope("Template", scope_id):
                    return True

            # 2. Direct constructor calls: Environment().from_string()
            if isinstance(expr_node.func, ast.Attribute) and expr_node.func.attr == "from_string":
                if self._is_jinja_env_expr(expr_node.func.value, scope_id):
                    return True
            if fname in ("jinja2.Environment.from_string", "Environment.from_string"):
                return True

            # 3. Interprocedural return: Resolving the called function's AST return statement
            func_scope = self._resolve_function_scope(fname, scope_id)
            if func_scope and func_scope not in visited:
                visited.add(func_scope)
                returns = self.returns_by_scope.get(func_scope, [])
                for r in returns:
                    if r.value and self._is_jinja_template_expr(r.value, func_scope, visited.copy()):
                        return True

        # 4. Local variable assignments pointing back to 1, 2, or 3
        if isinstance(expr_node, ast.Name):
            var_key = f"{scope_id}:{expr_node.id}"
            if var_key in visited: return False
            visited.add(var_key)
            curr = scope_id
            while curr:
                recs = self.assignments_by_scope.get((curr, expr_node.id), [])
                if recs:
                    latest = recs[-1]
                    return self._is_jinja_template_expr(latest.value_node, curr, visited.copy())
                if "." in curr and "function" in curr: curr = curr.rsplit(".", 1)[0]
                elif ":function" in curr: curr = f"{mod_name}:global"
                elif curr != f"{mod_name}:global": curr = f"{mod_name}:global"
                else: break

        return False

    def resolve_expression(self, node: ast.AST, sink: SecurityNode, scope_id: str, current_lineno: int, visited: Optional[set[str]] = None, call_context: Optional[dict[str, TaintValue]] = None) -> TaintValue:
        if visited is None: visited = set()
        if call_context is None: call_context = {}
        mod_name = scope_id.split(":")[0]
        file_name = self.file_paths.get(mod_name, f"{mod_name}.py")

        # Handle Python f-strings (ast.JoinedStr)
        if isinstance(node, ast.JoinedStr):
            part_values = []
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    part_values.append(self.resolve_expression(part.value, sink, scope_id, current_lineno, visited.copy(), call_context))
                elif isinstance(part, ast.Constant):
                    part_values.append(TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="constant"))
                else:
                    part_values.append(self.resolve_expression(part, sink, scope_id, current_lineno, visited.copy(), call_context))

            tainted_parts = [p for p in part_values if p.state == TaintState.TAINTED]
            if tainted_parts:
                best_p = max(tainted_parts, key=lambda p: p.confidence)
                combined_path = []
                combined_nodes = []
                seen_nids = set()
                combined_edges = []
                seen_ekeys = set()
                for p in tainted_parts:
                    for hop in p.path:
                        if hop not in combined_path:
                            combined_path.append(hop)
                    for pn in p.proof_nodes:
                        if pn.node_id not in seen_nids:
                            seen_nids.add(pn.node_id)
                            combined_nodes.append(pn)
                    for pe in p.proof_edges:
                        ek = (pe.from_node_id, pe.to_node_id, pe.edge_type)
                        if ek not in seen_ekeys:
                            seen_ekeys.add(ek)
                            combined_edges.append(pe)
                combined_path.append(f"{file_name}:f_string")
                return TaintValue(
                    state=TaintState.TAINTED,
                    source_id=best_p.source_id,
                    confidence=best_p.confidence,
                    path=combined_path,
                    last_operation="f_string",
                    proof_nodes=combined_nodes,
                    proof_edges=combined_edges
                )
            unknown_parts = [p for p in part_values if p.state != TaintState.CLEAN]
            if unknown_parts:
                first_u = unknown_parts[0]
                combined_path = []
                combined_nodes = []
                combined_edges = []
                seen_nids = set()
                seen_ekeys = set()
                for p in unknown_parts:
                    for hop in p.path:
                        if hop not in combined_path:
                            combined_path.append(hop)
                    for pn in p.proof_nodes:
                        if pn.node_id not in seen_nids:
                            seen_nids.add(pn.node_id)
                            combined_nodes.append(pn)
                    for pe in p.proof_edges:
                        ek = (pe.from_node_id, pe.to_node_id, pe.edge_type)
                        if ek not in seen_ekeys:
                            seen_ekeys.add(ek)
                            combined_edges.append(pe)
                combined_path.append(f"{file_name}:f_string")
                return TaintValue(
                    state=TaintState.UNKNOWN,
                    source_id=first_u.source_id,
                    confidence=0.50,
                    path=combined_path,
                    last_operation="f_string_unknown",
                    proof_nodes=combined_nodes,
                    proof_edges=combined_edges
                )
            return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="constant")

        if isinstance(node, ast.Call) and self.is_source_call(node, scope_id):
            source = self.get_or_create_source(node, file_name, scope_id)
            src_sym = dotted_name(node.func) or "source"
            src_pn = self.create_proof_node(
                step_index=0,
                node_type=ProofNodeType.SOURCE,
                file_path=file_name,
                node=node,
                symbol=src_sym,
                scope_id=scope_id
            )
            return TaintValue(state=TaintState.TAINTED, source_id=source.id, confidence=1.0, path=[source.id], last_operation=src_sym, proof_nodes=[src_pn], proof_edges=[])

        if isinstance(node, ast.Attribute):
            attr_name = dotted_name(node)
            if attr_name and self.is_var_contained(attr_name, scope_id, current_lineno, sink, visited):
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, path=[f"{file_name}:{attr_name}", "path_containment_proven"], last_operation="path_containment_proven")
            canon_attr = self.resolve_canonical_name(node, scope_id) or attr_name
            norm_attr = canon_attr[6:] if (canon_attr and canon_attr.startswith("flask.")) else canon_attr
            if norm_attr in ("request.data", "request.json", "request.query_string", "request.body", "request.META", "request.FILES") or (attr_name in ("request.data", "request.json", "request.query_string", "request.body", "request.META", "request.FILES")):
                loc = location(node, file_name)
                for existing in self.sources:
                    if existing.location == loc:
                        src_pn = self.create_proof_node(
                            step_index=0,
                            node_type=ProofNodeType.SOURCE,
                            file_path=file_name,
                            node=node,
                            symbol=norm_attr,
                            scope_id=scope_id
                        )
                        return TaintValue(state=TaintState.TAINTED, source_id=existing.id, confidence=1.0, path=[existing.id], last_operation=norm_attr, proof_nodes=[src_pn], proof_edges=[])
                source_id = self.next_source_id()
                src = SecurityNode(id=source_id, node_type=NodeType.SOURCE, symbol=norm_attr, operation="HTTP_BODY_ACCESS", location=loc, metadata={"source_type": "USER_CONTROLLED"})
                self.sources.append(src)
                src_pn = self.create_proof_node(
                    step_index=0,
                    node_type=ProofNodeType.SOURCE,
                    file_path=file_name,
                    node=node,
                    symbol=norm_attr,
                    scope_id=scope_id
                )
                return TaintValue(state=TaintState.TAINTED, source_id=source_id, confidence=1.0, path=[source_id], last_operation=norm_attr, proof_nodes=[src_pn], proof_edges=[])

            # Class attribute access (self.<attr>, cls.<attr>, or instance.<attr>)
            target_cls_scope = None
            is_self_cls = isinstance(node.value, ast.Name) and node.value.id in ("self", "cls")
            if is_self_cls:
                target_cls_scope = self._get_enclosing_class_scope(scope_id)
            elif isinstance(node.value, ast.Name):
                target_cls_scope = self._resolve_instance_class_scope(node.value.id, scope_id)

            if target_cls_scope:
                attr_key = f"class_attr:{target_cls_scope}:{node.attr}"
                if attr_key in visited:
                    return TaintValue(state=TaintState.UNKNOWN, confidence=0.50, path=[f"{file_name}:self.{node.attr}"], last_operation="circular_attribute")
                v_copy = visited.copy()
                v_copy.add(attr_key)

                records = self.class_field_assignments.get((target_cls_scope, node.attr), [])
                if not records:
                    # Rule C: Unrecorded / External: fall back to UNKNOWN with confidence 0.50
                    return TaintValue(
                        state=TaintState.UNKNOWN,
                        confidence=0.50,
                        path=[f"{file_name}:self.{node.attr}"],
                        last_operation=f"unrecorded_attr:self.{node.attr}"
                    )

                resolved_values = []
                for r in records:
                    r_taint = self.resolve_expression(r.value_node, sink, r.scope_id, r.lineno, v_copy.copy(), call_context)
                    resolved_values.append(r_taint)

                # Rule A (Taint Preservation): If ANY recorded assignment evaluates to TAINTED
                tainted = [v for v in resolved_values if v.state == TaintState.TAINTED]
                if tainted:
                    best_t = max(tainted, key=lambda v: v.confidence)
                    step_idx = len(best_t.proof_nodes)
                    attr_pn = self.create_proof_node(
                        step_index=step_idx,
                        node_type=ProofNodeType.ASSIGNMENT,
                        file_path=file_name,
                        node=node,
                        symbol=f"self.{node.attr}",
                        scope_id=scope_id,
                        lineno=current_lineno
                    )
                    new_edges = list(best_t.proof_edges)
                    if best_t.proof_nodes:
                        new_edges.append(ProofEdge(from_node_id=best_t.proof_nodes[-1].node_id, to_node_id=attr_pn.node_id, edge_type="ASSIGNMENT"))
                    return TaintValue(
                        state=TaintState.TAINTED,
                        source_id=best_t.source_id,
                        confidence=1.0,
                        path=[*best_t.path, f"{file_name}:self.{node.attr}"],
                        last_operation=f"class_attr:self.{node.attr}",
                        proof_nodes=[*best_t.proof_nodes, attr_pn],
                        proof_edges=new_edges
                    )

                # Rule B (Clean Proof): If ALL recorded assignments evaluate to CLEAN
                if all(v.state == TaintState.CLEAN for v in resolved_values):
                    # A dynamic-key write (self.field[k] = tainted) can taint the container
                    # even when the static initializer is clean.
                    dyn = self._resolve_instance_field_write_taint(target_cls_scope, node.attr, sink, v_copy)
                    if dyn is not None and dyn.state != TaintState.CLEAN and dyn.source_id:
                        return TaintValue(
                            state=dyn.state,
                            source_id=dyn.source_id,
                            confidence=dyn.confidence,
                            path=[*dyn.path, f"{file_name}:self.{node.attr}[]"],
                            last_operation=f"instance_field_write:self.{node.attr}",
                            proof_nodes=dyn.proof_nodes,
                            proof_edges=dyn.proof_edges
                        )
                    return TaintValue(
                        state=TaintState.CLEAN,
                        confidence=1.0,
                        path=[f"{file_name}:self.{node.attr}"],
                        last_operation=f"clean_class_attr:self.{node.attr}"
                    )

                # Fallback for unknown / unconfirmed values
                first_u = next((v for v in resolved_values if v.state != TaintState.CLEAN), resolved_values[0])
                return TaintValue(
                    state=TaintState.UNKNOWN,
                    source_id=first_u.source_id,
                    confidence=0.50,
                    path=[*first_u.path, f"{file_name}:self.{node.attr}"],
                    last_operation=f"unknown_class_attr:self.{node.attr}"
                )
            elif is_self_cls:
                return TaintValue(
                    state=TaintState.UNKNOWN,
                    confidence=0.50,
                    path=[f"{file_name}:self.{node.attr}"],
                    last_operation=f"unrecorded_attr:self.{node.attr}"
                )

            # Path attribute navigation (.parent, .parents, .name, .stem, .suffix, .suffixes)
            if node.attr in ("parent", "parents", "name", "stem", "suffix", "suffixes") or self._is_path_expr(node.value, scope_id):
                recv_taint = self.resolve_expression(node.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                if recv_taint.state == TaintState.TAINTED:
                    return TaintValue(state=TaintState.TAINTED, source_id=recv_taint.source_id, confidence=recv_taint.confidence, path=[*recv_taint.path, f"{file_name}:{node.attr}"], last_operation=f"path_{node.attr}")
                elif recv_taint.state == TaintState.CLEAN:
                    return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"path_{node.attr}")
                else:
                    return TaintValue(state=TaintState.UNKNOWN, source_id=recv_taint.source_id, confidence=0.50, path=[*recv_taint.path, f"{file_name}:{node.attr}"], last_operation=f"path_{node.attr}")

        if isinstance(node, ast.Name):
            if self.is_var_contained(node.id, scope_id, current_lineno, sink, visited):
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, path=[f"{file_name}:{node.id}", "path_containment_proven"], last_operation="path_containment_proven")

            var_key = f"{scope_id}:{node.id}"
            if var_key in visited: return TaintValue(state=TaintState.UNKNOWN, confidence=0.50, path=[f"{file_name}:{node.id}"], last_operation="circular_reference")
            visited.add(var_key)
            current_scope = scope_id
            records_before = []
            is_param_in_context = False

            while current_scope:
                records = self.assignments_by_scope.get((current_scope, node.id), [])
                records_before = [r for r in records if r.lineno < current_lineno]
                if records_before: break
                if current_scope == scope_id and node.id in call_context:
                    is_param_in_context = True
                    break
                if "." in current_scope and "function" in current_scope: current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope: current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global": current_scope = f"{mod_name}:global"
                else: break

            base_taint = None
            if is_param_in_context:
                ctx_t = call_context[node.id]
                step_idx = len(ctx_t.proof_nodes)
                param_pn = self.create_proof_node(
                    step_index=step_idx,
                    node_type=ProofNodeType.PARAM_BINDING,
                    file_path=file_name,
                    node=node,
                    symbol=node.id,
                    scope_id=scope_id,
                    lineno=current_lineno,
                    override_snippet=f"{node.id} (param context)"
                )
                new_edges = list(ctx_t.proof_edges)
                if ctx_t.proof_nodes:
                    new_edges.append(ProofEdge(from_node_id=ctx_t.proof_nodes[-1].node_id, to_node_id=param_pn.node_id, edge_type="PARAM_BINDING"))
                base_taint = TaintValue(
                    state=ctx_t.state,
                    source_id=ctx_t.source_id,
                    confidence=ctx_t.confidence,
                    path=[*ctx_t.path, f"{file_name}:{node.id}"],
                    last_operation=f"{file_name}:{node.id}",
                    proof_nodes=[*ctx_t.proof_nodes, param_pn],
                    proof_edges=new_edges
                )

            if not records_before:
                if base_taint: return base_taint

                # Interprocedural argument -> parameter flow resolution (supports closures and outer scopes)
                enc_scope = scope_id
                target_func_node = None
                target_scope = None
                while enc_scope:
                    f_node = self.functions.get(enc_scope)
                    if f_node and any(a.arg == node.id for a in f_node.args.args):
                        target_func_node = f_node
                        target_scope = enc_scope
                        break
                    if "." in enc_scope:
                        enc_scope = enc_scope.rsplit(".", 1)[0]
                    else:
                        break

                if target_func_node and target_scope:
                    param_names = [a.arg for a in target_func_node.args.args]
                    param_idx = param_names.index(node.id)
                    call_sites = self.call_sites_by_target.get(target_scope, [])
                    if call_sites:
                        caller_matches = []
                        for call_node, caller_scope, call_lineno in call_sites:
                            arg_expr = None
                            for kw in getattr(call_node, "keywords", []):
                                if kw.arg == node.id:
                                    arg_expr = kw.value
                                    break
                            if arg_expr is None:
                                pos_idx = param_idx
                                if param_names and param_names[0] in ("self", "cls"):
                                    pos_idx = param_idx - 1
                                if 0 <= pos_idx < len(call_node.args):
                                    arg_expr = call_node.args[pos_idx]

                            if arg_expr is not None:
                                call_site_key = f"param_flow:{target_scope}:{node.id}:{caller_scope}:{call_lineno}"
                                if call_site_key not in visited:
                                    v_copy = visited.copy()
                                    v_copy.add(call_site_key)
                                    caller_taint = self.resolve_expression(arg_expr, sink, caller_scope, call_lineno, v_copy)
                                    caller_matches.append((caller_taint, call_node, caller_scope, call_lineno))

                        # If any caller is confirmed tainted, preserve confirmed taint
                        tainted_matches = [m for m in caller_matches if m[0].state == TaintState.TAINTED]
                        if tainted_matches:
                            best_match = max(tainted_matches, key=lambda m: m[0].confidence)
                            best_t, best_call_node, best_caller_scope, best_call_lineno = best_match

                            caller_file = best_caller_scope.split(":", 1)[0] if ":" in best_caller_scope else file_name
                            call_func_symbol = dotted_name(best_call_node.func) if hasattr(best_call_node, "func") else "call"
                            call_snippet = self.get_source_snippet(caller_file, best_call_lineno, best_call_lineno, best_call_node) or f"{call_func_symbol}(...)"

                            step_idx = len(best_t.proof_nodes)
                            call_site_pn = self.create_proof_node(
                                step_index=step_idx,
                                node_type=ProofNodeType.CALL_SITE,
                                file_path=caller_file,
                                node=best_call_node,
                                symbol=call_func_symbol,
                                scope_id=best_caller_scope,
                                lineno=best_call_lineno,
                                override_snippet=call_snippet
                            )

                            callee_line = target_func_node.lineno if target_func_node else current_lineno
                            param_pn = self.create_proof_node(
                                step_index=step_idx + 1,
                                node_type=ProofNodeType.PARAM_BINDING,
                                file_path=file_name,
                                node=target_func_node,
                                symbol=node.id,
                                scope_id=target_scope or scope_id,
                                lineno=callee_line,
                                override_snippet=self.get_source_snippet(file_name, callee_line, callee_line, target_func_node) or f"def {target_func_node.name}(..., {node.id}, ...)"
                            )

                            new_edges = list(best_t.proof_edges)
                            if best_t.proof_nodes:
                                new_edges.append(ProofEdge(from_node_id=best_t.proof_nodes[-1].node_id, to_node_id=call_site_pn.node_id, edge_type="CALL_SITE"))
                            new_edges.append(ProofEdge(from_node_id=call_site_pn.node_id, to_node_id=param_pn.node_id, edge_type="PARAM_BINDING"))

                            return TaintValue(
                                state=TaintState.TAINTED,
                                source_id=best_t.source_id,
                                confidence=best_t.confidence,
                                path=[*best_t.path, f"call:{call_func_symbol}", f"{file_name}:{node.id}"],
                                last_operation=f"param:{node.id}",
                                proof_nodes=[*best_t.proof_nodes, call_site_pn, param_pn],
                                proof_edges=new_edges
                            )
                        elif caller_matches:
                            merged = self.merge_taints([m[0] for m in caller_matches], f"{file_name}:{node.id}")
                            is_cli_arg = any(
                                any(
                                    dotted_name(a) == "sys.argv" or (isinstance(a, ast.Subscript) and dotted_name(a.value) == "sys.argv")
                                    for a in getattr(call_n, "args", [])
                                )
                                for _, call_n, _, _ in caller_matches
                            )
                            if not self.audit_all and merged.state == TaintState.UNKNOWN and not is_cli_arg:
                                return TaintValue(state=TaintState.CLEAN, confidence=1.0, path=merged.path, last_operation=f"unbound_param:{node.id}")
                            return merged

                    # Parameter with no call sites (or self/cls)
                    if node.id in ("self", "cls"):
                        return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"self:{node.id}")
                    # Parameter with no active taint binding to an untrusted source:
                    # In default high-signal mode (not audit_all), suppress speculative POTENTIAL warnings.
                    # In aggressive mode (--audit-all), emit UNKNOWN (confidence 0.50).
                    if self.audit_all:
                        param_symbol = f"{node.id} ({target_func_node.name})"
                        param_pn = self.create_proof_node(
                            step_index=0,
                            node_type=ProofNodeType.SOURCE,
                            file_path=file_name,
                            node=target_func_node,
                            symbol=param_symbol,
                            scope_id=target_scope or scope_id,
                            lineno=target_func_node.lineno,
                            override_snippet=self.get_source_snippet(file_name, target_func_node.lineno, target_func_node.lineno, target_func_node) or f"def {target_func_node.name}(..., {node.id}, ...)"
                        )
                        source_id = self.next_source_id()
                        src_node = SecurityNode(
                            id=source_id,
                            node_type=NodeType.SOURCE,
                            symbol=param_symbol,
                            operation="PARAMETER_INPUT",
                            location=CodeLocation(file=file_name, line_start=target_func_node.lineno, line_end=target_func_node.lineno, column_start=0, column_end=0),
                            metadata={"source_type": "FUNCTION_PARAMETER", "parameter": node.id, "function": target_func_node.name}
                        )
                        self.sources.append(src_node)
                        return TaintValue(
                            state=TaintState.UNKNOWN,
                            source_id=source_id,
                            confidence=0.50,
                            path=[f"{file_name}:{node.id}"],
                            last_operation=f"unresolved_param:{node.id}",
                            proof_nodes=[param_pn],
                            proof_edges=[]
                        )
                    return TaintValue(state=TaintState.CLEAN, confidence=1.0, path=[f"{file_name}:{node.id}"], last_operation=f"unbound_param:{node.id}")

                # Check known builtins / constants / imports
                if node.id == "__file__":
                    return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="__file__")
                if node.id in ("__name__", "__doc__", "__package__", "True", "False", "None"):
                    return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="builtin_constant")
                if node.id in self.imports.get(mod_name, {}):
                    return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"import:{node.id}")
                if f"{mod_name}:function:{node.id}" in self.functions:
                    return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"function:{node.id}")
                if node.id in ("int", "str", "bytes", "float", "bool", "list", "dict", "set", "tuple", "len", "range", "enumerate", "zip", "open", "print", "isinstance", "issubclass", "getattr", "setattr", "hasattr", "Exception", "ValueError", "TypeError", "FileNotFoundError", "dir", "min", "max", "sum", "any", "all", "map", "filter"):
                    return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="builtin_symbol")

                # Name has no assignment, is not a known builtin, not an import, not a function: unresolved provenance
                return TaintValue(state=TaintState.UNKNOWN, confidence=0.50, path=[f"{file_name}:{node.id}"], last_operation=f"unresolved:{node.id}")

            last_uncond_idx = -1
            for idx, r in enumerate(records_before):
                if not r.is_conditional: last_uncond_idx = idx

            if last_uncond_idx != -1:
                reaching = [records_before[last_uncond_idx]] + [r for r in records_before[last_uncond_idx + 1:] if r.is_conditional]
                base_taint = None 
            else:
                reaching = records_before

            if len(reaching) == 1 and not reaching[0].is_conditional and not base_taint:
                target_rec = reaching[0]
                resolved = self.resolve_expression(target_rec.value_node, sink, target_rec.scope_id, target_rec.lineno, visited, call_context)
                step_idx = len(resolved.proof_nodes)
                assign_pn = self.create_proof_node(
                    step_index=step_idx,
                    node_type=ProofNodeType.ASSIGNMENT,
                    file_path=file_name,
                    node=target_rec.value_node,
                    symbol=node.id,
                    scope_id=target_rec.scope_id,
                    lineno=target_rec.lineno,
                    override_snippet=self.get_source_snippet(file_name, target_rec.lineno, target_rec.lineno) or f"{node.id} = {ast.unparse(target_rec.value_node)}"
                )
                new_edges = list(resolved.proof_edges)
                if resolved.proof_nodes:
                    new_edges.append(ProofEdge(from_node_id=resolved.proof_nodes[-1].node_id, to_node_id=assign_pn.node_id, edge_type="ASSIGNMENT"))
                return TaintValue(
                    state=resolved.state,
                    source_id=resolved.source_id,
                    confidence=resolved.confidence,
                    path=[*resolved.path, f"{file_name}:{node.id}"],
                    last_operation=f"variable:{node.id}",
                    proof_nodes=[*resolved.proof_nodes, assign_pn],
                    proof_edges=new_edges
                )
            else:
                resolved_list = [self.resolve_expression(r.value_node, sink, r.scope_id, r.lineno, visited.copy(), call_context) for r in reaching]
                if base_taint: resolved_list.append(base_taint)
                return self.merge_taints(resolved_list, f"{file_name}:{node.id}")

        if isinstance(node, ast.Call):
            canon_name = self.resolve_canonical_name(node.func, scope_id)
            function_name = canon_name or dotted_name(node.func) or "<unknown_function>"
            arg_values = [self.resolve_expression(arg, sink, scope_id, current_lineno, visited.copy(), call_context) for arg in node.args]

            fn_base = function_name.replace("builtins.", "")
            d_base = (dotted_name(node.func) or "").replace("builtins.", "")
            if fn_base in PRIMITIVE_NUMERIC_CASTS or d_base in PRIMITIVE_NUMERIC_CASTS:
                sink_cwe = sink.metadata.get("cwe") if sink and hasattr(sink, "metadata") else None
                sink_type = sink.metadata.get("sink_type") if sink and hasattr(sink, "metadata") else None
                protected_cwes = {"CWE-89", "CWE-78", "CWE-22", "CWE-95", "UNKNOWN_CWE"}
                if not sink_cwe or sink_cwe in protected_cwes or sink_type in ("SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL", "CODE_EXECUTION", "FILE_ACCESS"):
                    first_tainted = next((a for a in arg_values if a.state != TaintState.CLEAN), None)
                    san_nodes = list(first_tainted.proof_nodes) if first_tainted else []
                    san_edges = list(first_tainted.proof_edges) if first_tainted else []
                    step_idx = len(san_nodes)
                    san_pn = self.create_proof_node(
                        step_index=step_idx,
                        node_type=ProofNodeType.SANITIZER,
                        file_path=file_name,
                        node=node,
                        symbol=f"{fn_base or d_base}()",
                        scope_id=scope_id,
                        lineno=current_lineno
                    )
                    if san_nodes:
                        san_edges.append(ProofEdge(from_node_id=san_nodes[-1].node_id, to_node_id=san_pn.node_id, edge_type="SANITIZER"))
                    san_nodes.append(san_pn)
                    return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"primitive_cast:{fn_base or d_base}", proof_nodes=san_nodes, proof_edges=san_edges)

            if fn_base in ("str", "repr", "bytes") or d_base in ("str", "repr", "bytes"):
                tainted_args = [a for a in arg_values if a.state == TaintState.TAINTED]
                for kw in getattr(node, "keywords", []):
                    kw_val = self.resolve_expression(kw.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                    if kw_val.state == TaintState.TAINTED:
                        tainted_args.append(kw_val)
                if tainted_args:
                    best_arg = max(tainted_args, key=lambda a: a.confidence)
                    step_idx = len(best_arg.proof_nodes)
                    cast_pn = self.create_proof_node(
                        step_index=step_idx,
                        node_type=ProofNodeType.TRANSFORM,
                        file_path=file_name,
                        node=node,
                        symbol=f"{fn_base or d_base}()",
                        scope_id=scope_id,
                        lineno=current_lineno
                    )
                    new_edges = list(best_arg.proof_edges)
                    if best_arg.proof_nodes:
                        new_edges.append(ProofEdge(from_node_id=best_arg.proof_nodes[-1].node_id, to_node_id=cast_pn.node_id, edge_type="TRANSFORM"))
                    return TaintValue(
                        state=TaintState.TAINTED,
                        source_id=best_arg.source_id,
                        confidence=best_arg.confidence,
                        path=[*best_arg.path, f"{file_name}:{fn_base or d_base}()"],
                        last_operation=f"cast:{fn_base or d_base}",
                        proof_nodes=[*best_arg.proof_nodes, cast_pn],
                        proof_edges=new_edges
                    )
                unknown_args = [a for a in arg_values if a.state != TaintState.CLEAN]
                for kw in getattr(node, "keywords", []):
                    kw_val = self.resolve_expression(kw.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                    if kw_val.state != TaintState.CLEAN:
                        unknown_args.append(kw_val)
                if unknown_args:
                    first_u = unknown_args[0]
                    return TaintValue(
                        state=TaintState.UNKNOWN,
                        source_id=first_u.source_id,
                        confidence=0.50,
                        path=[*first_u.path, f"{file_name}:{fn_base or d_base}()"],
                        last_operation=f"cast:{fn_base or d_base}"
                    )
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"cast:{fn_base or d_base}")

            if function_name in SANITIZER_REGISTRY and self.sanitizer_protects_context(function_name, sink):
                first_tainted = next((arg for arg in arg_values if arg.state != TaintState.CLEAN), None)
                if first_tainted:
                    step_idx = len(first_tainted.proof_nodes)
                    san_pn = self.create_proof_node(
                        step_index=step_idx,
                        node_type=ProofNodeType.SANITIZER,
                        file_path=file_name,
                        node=node,
                        symbol=f"{function_name}()",
                        scope_id=scope_id,
                        lineno=current_lineno
                    )
                    new_edges = list(first_tainted.proof_edges)
                    if first_tainted.proof_nodes:
                        new_edges.append(ProofEdge(from_node_id=first_tainted.proof_nodes[-1].node_id, to_node_id=san_pn.node_id, edge_type="SANITIZER"))
                    return TaintValue(state=TaintState.CLEAN, source_id=None, confidence=1.0, path=[*first_tainted.path, f"{file_name}:{function_name}()"], last_operation=f"sanitized:{function_name}", proof_nodes=[*first_tainted.proof_nodes, san_pn], proof_edges=new_edges)
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=function_name)

            if function_name in SANITIZER_REGISTRY:
                first_tainted = next((arg for arg in arg_values if arg.state != TaintState.CLEAN), None)
                if first_tainted:
                    return TaintValue(state=TaintState.TAINTED, source_id=first_tainted.source_id, confidence=0.50, path=[*first_tainted.path, f"{file_name}:{function_name}()"], last_operation=f"irrelevant_sanitizer:{function_name}")

            # Receiver .get() / .getlist() / .pop() on dictionary or object (e.g. d.get("key"), payload = request.get_json(); payload.get("x"))
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "getlist", "pop"):
                # Field-sensitive dictionary lookup when key is extractable
                if node.args:
                    key = self._extract_subscript_key(node.args[0], scope_id)
                    base_var = node.func.value.id if isinstance(node.func.value, ast.Name) else None

                    # 1. Composite key in assignments: d["cmd"] = ...
                    if base_var and key is not None:
                        comp_key = f"{base_var}[{key}]"
                        current_scope = scope_id
                        found_record = None
                        while current_scope:
                            recs = self.assignments_by_scope.get((current_scope, comp_key), [])
                            recs_before = [r for r in recs if r.lineno < current_lineno]
                            if recs_before:
                                uncond = [r for r in recs_before if not r.is_conditional]
                                found_record = uncond[-1] if uncond else recs_before[-1]
                                break
                            if "." in current_scope and "function" in current_scope:
                                current_scope = current_scope.rsplit(".", 1)[0]
                            elif ":function" in current_scope:
                                current_scope = f"{mod_name}:global"
                            elif current_scope != f"{mod_name}:global":
                                current_scope = f"{mod_name}:global"
                            else:
                                break
                        if found_record:
                            comp_v_key = f"{scope_id}:{comp_key}:{found_record.lineno}"
                            if comp_v_key not in visited:
                                v_copy = visited.copy()
                                v_copy.add(comp_v_key)
                                res = self.resolve_expression(found_record.value_node, sink, found_record.scope_id, found_record.lineno, v_copy, call_context)
                                if res.state != TaintState.CLEAN:
                                    step_idx = len(res.proof_nodes)
                                    cont_pn = self.create_proof_node(
                                        step_index=step_idx,
                                        node_type=ProofNodeType.ASSIGNMENT,
                                        file_path=file_name,
                                        node=found_record.value_node,
                                        symbol=comp_key,
                                        scope_id=found_record.scope_id,
                                        lineno=found_record.lineno,
                                        override_snippet=self.get_source_snippet(file_name, found_record.lineno, found_record.lineno) or f"{comp_key} = ..."
                                    )
                                    new_edges = list(res.proof_edges)
                                    if res.proof_nodes:
                                        new_edges.append(ProofEdge(from_node_id=res.proof_nodes[-1].node_id, to_node_id=cont_pn.node_id, edge_type="ASSIGNMENT"))
                                    return TaintValue(
                                        state=res.state,
                                        source_id=res.source_id,
                                        confidence=res.confidence,
                                        path=[*res.path, f"{file_name}:{comp_key}"],
                                        last_operation=f"container_key:{comp_key}",
                                        proof_nodes=[*res.proof_nodes, cont_pn],
                                        proof_edges=new_edges
                                    )
                                else:
                                    return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"container_key:{comp_key}")

                    # 2. Check base variable definition if initialized as dict literal
                    if base_var and key is not None:
                        current_scope = scope_id
                        found_base_record = None
                        while current_scope:
                            recs = self.assignments_by_scope.get((current_scope, base_var), [])
                            recs_before = [r for r in recs if r.lineno < current_lineno]
                            if recs_before:
                                uncond = [r for r in recs_before if not r.is_conditional]
                                found_base_record = uncond[-1] if uncond else recs_before[-1]
                                break
                            if "." in current_scope and "function" in current_scope:
                                current_scope = current_scope.rsplit(".", 1)[0]
                            elif ":function" in current_scope:
                                current_scope = f"{mod_name}:global"
                            elif current_scope != f"{mod_name}:global":
                                current_scope = f"{mod_name}:global"
                            else:
                                break
                        if found_base_record:
                            val_node = found_base_record.value_node
                            if isinstance(val_node, ast.Dict):
                                matched_key_val = None
                                for k, v in zip(val_node.keys, val_node.values):
                                    k_val = self._extract_subscript_key(k, found_base_record.scope_id)
                                    if k_val == key:
                                        matched_key_val = v
                                        break
                                if matched_key_val is not None:
                                    key_v_key = f"{found_base_record.scope_id}:{base_var}[{key}]:{found_base_record.lineno}"
                                    if key_v_key not in visited:
                                        v_copy = visited.copy()
                                        v_copy.add(key_v_key)
                                        return self.resolve_expression(matched_key_val, sink, found_base_record.scope_id, found_base_record.lineno, v_copy, call_context)
                                else:
                                    if len(node.args) > 1:
                                        return self.resolve_expression(node.args[1], sink, scope_id, current_lineno, visited.copy(), call_context)
                                    return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"container_key_missing:{base_var}[{key}]")

                    # 3. Check direct literal: {"a": val}.get("a")
                    if isinstance(node.func.value, ast.Dict) and key is not None:
                        for k, v in zip(node.func.value.keys, node.func.value.values):
                            k_val = self._extract_subscript_key(k, scope_id)
                            if k_val == key:
                                return self.resolve_expression(v, sink, scope_id, current_lineno, visited.copy(), call_context)
                        if len(node.args) > 1:
                            return self.resolve_expression(node.args[1], sink, scope_id, current_lineno, visited.copy(), call_context)
                        return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"container_key_missing:[{key}]")

                # Fallback: receiver taint propagation
                recv_taint = self.resolve_expression(node.func.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                if recv_taint.state != TaintState.CLEAN and recv_taint.source_id:
                    return TaintValue(state=recv_taint.state, source_id=recv_taint.source_id, confidence=recv_taint.confidence, path=[*recv_taint.path, f"{file_name}:{node.func.attr}()"], last_operation=f"{node.func.attr}()", proof_nodes=recv_taint.proof_nodes, proof_edges=recv_taint.proof_edges)
                if recv_taint.state == TaintState.CLEAN:
                    # A clean receiver must not silently drop tainted arguments:
                    # if any positional/keyword argument is TAINTED, propagate it.
                    arg_tainted = [a for a in arg_values if a.state == TaintState.TAINTED and a.source_id]
                    for kw in getattr(node, "keywords", []):
                        if kw.arg:
                            kw_v = self.resolve_expression(kw.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                            if kw_v.state == TaintState.TAINTED and kw_v.source_id:
                                arg_tainted.append(kw_v)
                    if arg_tainted:
                        best_a = max(arg_tainted, key=lambda a: a.confidence)
                        return TaintValue(state=TaintState.TAINTED, source_id=best_a.source_id, confidence=best_a.confidence, path=[*best_a.path, f"{file_name}:{node.func.attr}()"], last_operation=f"{node.func.attr}()", proof_nodes=best_a.proof_nodes, proof_edges=best_a.proof_edges)
                    return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"{node.func.attr}()")

            # Robust .format() on non-literal receivers: when the template is not a
            # statically recognizable string expr, still propagate tainted arguments
            # instead of falling through to generic call handling.
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and not self._is_string_expr(node.func.value, scope_id)
            ):
                robust_fmt_args = list(arg_values)
                for kw in getattr(node, "keywords", []):
                    if kw.arg:
                        robust_fmt_args.append(self.resolve_expression(kw.value, sink, scope_id, current_lineno, visited.copy(), call_context))
                tainted_fmt_args = [a for a in robust_fmt_args if a.state == TaintState.TAINTED and a.source_id]
                if tainted_fmt_args:
                    best_arg = max(tainted_fmt_args, key=lambda a: a.confidence)
                    return TaintValue(state=TaintState.TAINTED, source_id=best_arg.source_id, confidence=best_arg.confidence, path=[*best_arg.path, f"{file_name}:format()"], last_operation="format", proof_nodes=best_arg.proof_nodes, proof_edges=best_arg.proof_edges)

            # Format calls on string literals or templates
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format" and self._is_string_expr(node.func.value, scope_id):
                format_args = [self.resolve_expression(arg, sink, scope_id, current_lineno, visited.copy(), call_context) for arg in node.args]
                for kw in getattr(node, "keywords", []):
                    format_args.append(self.resolve_expression(kw.value, sink, scope_id, current_lineno, visited.copy(), call_context))
                tainted_args = [a for a in format_args if a.state == TaintState.TAINTED]
                if tainted_args:
                    best_arg = max(tainted_args, key=lambda a: a.confidence)
                    step_idx = len(best_arg.proof_nodes)
                    fmt_pn = self.create_proof_node(
                        step_index=step_idx,
                        node_type=ProofNodeType.TRANSFORM,
                        file_path=file_name,
                        node=node,
                        symbol="format()",
                        scope_id=scope_id,
                        lineno=current_lineno
                    )
                    new_edges = list(best_arg.proof_edges)
                    if best_arg.proof_nodes:
                        new_edges.append(ProofEdge(from_node_id=best_arg.proof_nodes[-1].node_id, to_node_id=fmt_pn.node_id, edge_type="TRANSFORM"))
                    return TaintValue(state=TaintState.TAINTED, source_id=best_arg.source_id, confidence=best_arg.confidence, path=[*best_arg.path, f"{file_name}:format()"], last_operation="format", proof_nodes=[*best_arg.proof_nodes, fmt_pn], proof_edges=new_edges)
                unknown_args = [a for a in format_args if a.state != TaintState.CLEAN]
                if unknown_args:
                    first_u = unknown_args[0]
                    return TaintValue(state=TaintState.UNKNOWN, source_id=first_u.source_id, confidence=0.50, path=[*first_u.path, f"{file_name}:format()"], last_operation="format")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="format")

            # Path constructor (Path or pathlib.Path)
            if function_name in ("Path", "pathlib.Path"):
                if node.args:
                    arg_taint = self.resolve_expression(node.args[0], sink, scope_id, current_lineno, visited.copy(), call_context)
                    if arg_taint.state == TaintState.TAINTED:
                        return TaintValue(state=TaintState.TAINTED, source_id=arg_taint.source_id, confidence=arg_taint.confidence, path=[*arg_taint.path, f"{file_name}:Path()"], last_operation="path_construct")
                    elif arg_taint.state == TaintState.UNKNOWN:
                        return TaintValue(state=TaintState.UNKNOWN, source_id=arg_taint.source_id, confidence=0.50, path=[*arg_taint.path, f"{file_name}:Path()"], last_operation="path_construct")
                    else:
                        return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="path_construct")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="path_construct")

            # Path.cwd() or Path.home()
            if function_name in ("Path.cwd", "pathlib.Path.cwd", "Path.home", "pathlib.Path.home"):
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=function_name)

            # Path.resolve() / Path.absolute() / Path.expanduser() call
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("resolve", "absolute", "expanduser"):
                recv_taint = self.resolve_expression(node.func.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                if recv_taint.state == TaintState.TAINTED:
                    return TaintValue(state=TaintState.TAINTED, source_id=recv_taint.source_id, confidence=recv_taint.confidence, path=[*recv_taint.path, f"{file_name}:{node.func.attr}()"], last_operation=f"path_{node.func.attr}")
                elif recv_taint.state == TaintState.UNKNOWN:
                    return TaintValue(state=TaintState.UNKNOWN, source_id=recv_taint.source_id, confidence=0.50, path=[*recv_taint.path, f"{file_name}:{node.func.attr}()"], last_operation=f"path_{node.func.attr}")
                else:
                    return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"path_{node.func.attr}")

            # Path.joinpath(*args) — propagate taint ONLY from tainted operands.
            if isinstance(node.func, ast.Attribute) and node.func.attr == "joinpath":
                recv_taint = self.resolve_expression(node.func.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                arg_taints = [self.resolve_expression(arg, sink, scope_id, current_lineno, visited.copy(), call_context) for arg in node.args]
                all_taints = [recv_taint] + arg_taints
                tainted_parts = [t for t in all_taints if t.state == TaintState.TAINTED]
                if tainted_parts:
                    best_t = max(tainted_parts, key=lambda t: t.confidence)
                    # Only include path steps from tainted operands — discard clean literals
                    combined_path = []
                    for t in tainted_parts:
                        if t.path:
                            combined_path.extend(t.path)
                    combined_path.append(f"{file_name}:joinpath()")
                    return TaintValue(
                        state=TaintState.TAINTED,
                        source_id=best_t.source_id,
                        confidence=best_t.confidence,
                        path=combined_path,
                        last_operation="path_joinpath",
                        proof_nodes=best_t.proof_nodes,
                        proof_edges=best_t.proof_edges,
                    )
                unknown_parts = [t for t in all_taints if t.state != TaintState.CLEAN]
                if unknown_parts:
                    first_u = unknown_parts[0]
                    return TaintValue(state=TaintState.UNKNOWN, source_id=first_u.source_id, confidence=0.50, path=[*first_u.path, f"{file_name}:joinpath()"], last_operation="path_joinpath")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="path_joinpath")

            # os.path.join — propagate taint ONLY from tainted arguments.
            # Safe literal base paths (e.g. "/var/www/uploads") are dropped from the
            # proof chain to avoid noise and incorrect literal→[join] ordering.
            if function_name in ("os.path.join", "posixpath.join", "ntpath.join"):
                arg_taints = [self.resolve_expression(arg, sink, scope_id, current_lineno, visited.copy(), call_context) for arg in node.args]
                tainted_args = [a for a in arg_taints if a.state == TaintState.TAINTED]
                if tainted_args:
                    best_arg = max(tainted_args, key=lambda a: a.confidence)
                    # Only include path steps from tainted arguments — discard clean literals
                    combined_path = []
                    for a in tainted_args:
                        if a.path:
                            combined_path.extend(a.path)
                    combined_path.append(f"{file_name}:os.path.join()")
                    return TaintValue(
                        state=TaintState.TAINTED,
                        source_id=best_arg.source_id,
                        confidence=best_arg.confidence,
                        path=combined_path,
                        last_operation="os.path.join",
                        proof_nodes=best_arg.proof_nodes,
                        proof_edges=best_arg.proof_edges,
                    )
                unknown_args = [a for a in arg_taints if a.state != TaintState.CLEAN]
                if unknown_args:
                    first_u = unknown_args[0]
                    return TaintValue(state=TaintState.UNKNOWN, source_id=first_u.source_id, confidence=0.50, path=[*first_u.path, f"{file_name}:os.path.join()"], last_operation="os.path.join")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="os.path.join")

            # os.path.normpath (does not sanitize directory traversal)
            if function_name in ("os.path.normpath", "posixpath.normpath", "ntpath.normpath"):
                if node.args:
                    arg_taint = self.resolve_expression(node.args[0], sink, scope_id, current_lineno, visited.copy(), call_context)
                    if arg_taint.state == TaintState.TAINTED:
                        return TaintValue(state=TaintState.TAINTED, source_id=arg_taint.source_id, confidence=arg_taint.confidence, path=[*arg_taint.path, f"{file_name}:os.path.normpath()"], last_operation="os.path.normpath")
                    elif arg_taint.state == TaintState.UNKNOWN:
                        return TaintValue(state=TaintState.UNKNOWN, source_id=arg_taint.source_id, confidence=0.50, path=[*arg_taint.path, f"{file_name}:os.path.normpath()"], last_operation="os.path.normpath")
                    else:
                        return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="os.path.normpath")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="os.path.normpath")

            # Builtin compile(...) transformation
            if function_name in ("compile", "builtins.compile"):
                source_expr = None
                if node.args:
                    source_expr = node.args[0]
                else:
                    for kw in getattr(node, "keywords", []):
                        if kw.arg == "source":
                            source_expr = kw.value
                            break

                if source_expr is not None:
                    arg_taint = self.resolve_expression(source_expr, sink, scope_id, current_lineno, visited.copy(), call_context)
                    if arg_taint.state == TaintState.TAINTED:
                        return TaintValue(state=TaintState.TAINTED, source_id=arg_taint.source_id, confidence=arg_taint.confidence, path=[*arg_taint.path, f"{file_name}:compile()"], last_operation="compile", proof_nodes=arg_taint.proof_nodes, proof_edges=arg_taint.proof_edges)
                    elif arg_taint.state == TaintState.UNKNOWN:
                        return TaintValue(state=TaintState.UNKNOWN, source_id=arg_taint.source_id, confidence=0.50, path=[*arg_taint.path, f"{file_name}:compile()"], last_operation="compile", proof_nodes=arg_taint.proof_nodes, proof_edges=arg_taint.proof_edges)
                    else:
                        return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="compile")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="compile")

            # Jinja2 Template(...) constructor
            if function_name == "jinja2.Template" or (function_name == "Template" and (self._is_jinja_imported(mod_name) or not self.imports.get(mod_name)) and not self._resolve_function_scope("Template", scope_id)):
                source_expr = None
                if node.args:
                    source_expr = node.args[0]
                else:
                    for kw in getattr(node, "keywords", []):
                        if kw.arg in ("source", "template"):
                            source_expr = kw.value
                            break

                if source_expr is not None:
                    arg_taint = self.resolve_expression(source_expr, sink, scope_id, current_lineno, visited.copy(), call_context)
                    if arg_taint.state == TaintState.TAINTED:
                        return TaintValue(state=TaintState.TAINTED, source_id=arg_taint.source_id, confidence=arg_taint.confidence, path=[*arg_taint.path, f"{file_name}:Template()"], last_operation="template_construct", proof_nodes=arg_taint.proof_nodes, proof_edges=arg_taint.proof_edges)
                    elif arg_taint.state == TaintState.UNKNOWN:
                        return TaintValue(state=TaintState.UNKNOWN, source_id=arg_taint.source_id, confidence=0.50, path=[*arg_taint.path, f"{file_name}:Template()"], last_operation="template_construct", proof_nodes=arg_taint.proof_nodes, proof_edges=arg_taint.proof_edges)
                    else:
                        return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="template_construct")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="template_construct")

            # Jinja2 Environment.from_string(...)
            if (isinstance(node.func, ast.Attribute) and node.func.attr == "from_string" and self._is_jinja_env_expr(node.func.value, scope_id)) or function_name in ("Environment.from_string", "jinja2.Environment.from_string"):
                source_expr = None
                if node.args:
                    source_expr = node.args[0]
                else:
                    for kw in getattr(node, "keywords", []):
                        if kw.arg in ("source", "template", "s"):
                            source_expr = kw.value
                            break

                if source_expr is not None:
                    arg_taint = self.resolve_expression(source_expr, sink, scope_id, current_lineno, visited.copy(), call_context)
                    if arg_taint.state == TaintState.TAINTED:
                        return TaintValue(state=TaintState.TAINTED, source_id=arg_taint.source_id, confidence=arg_taint.confidence, path=[*arg_taint.path, f"{file_name}:from_string()"], last_operation="template_from_string", proof_nodes=arg_taint.proof_nodes, proof_edges=arg_taint.proof_edges)
                    elif arg_taint.state == TaintState.UNKNOWN:
                        return TaintValue(state=TaintState.UNKNOWN, source_id=arg_taint.source_id, confidence=0.50, path=[*arg_taint.path, f"{file_name}:from_string()"], last_operation="template_from_string", proof_nodes=arg_taint.proof_nodes, proof_edges=arg_taint.proof_edges)
                    else:
                        return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="template_from_string")
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="template_from_string")

            # Taint-preserving receiver methods and mutated-container str.join
            if isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                if attr == "join" and node.args:
                    mut = self._resolve_container_mutation_taint(node.args[0], sink, scope_id, current_lineno, visited, call_context)
                    if mut is not None and mut.state != TaintState.CLEAN and mut.source_id:
                        return TaintValue(state=mut.state, source_id=mut.source_id, confidence=mut.confidence, path=[*mut.path, f"{file_name}:join()"], last_operation="join", proof_nodes=mut.proof_nodes, proof_edges=mut.proof_edges)
                elif attr in TAINT_PRESERVING_RECEIVER_METHODS and not self._resolve_function_scope(function_name, scope_id):
                    recv = self.resolve_expression(node.func.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                    if recv.state != TaintState.CLEAN and recv.source_id:
                        return TaintValue(state=recv.state, source_id=recv.source_id, confidence=recv.confidence, path=[*recv.path, f"{file_name}:{attr}()"], last_operation=f"{attr}()", proof_nodes=recv.proof_nodes, proof_edges=recv.proof_edges)

            func_scope = self._resolve_function_scope(function_name, scope_id)
            if func_scope:
                call_sig = f"call:{func_scope}:{current_lineno}"
                if call_sig in visited: return TaintValue(state=TaintState.UNKNOWN, confidence=0.50, path=[f"recursive_call:{function_name}"], last_operation="recursion")
                visited.add(call_sig)

                func_node = self.functions[func_scope]
                param_names = [arg.arg for arg in func_node.args.args]
                new_call_context = {}
                for i, p_name in enumerate(param_names):
                    if i < len(arg_values): new_call_context[p_name] = arg_values[i]
                    else: new_call_context[p_name] = TaintValue(state=TaintState.CLEAN, confidence=1.0)

                # Process keyword arguments for interprocedural call context
                for kw in getattr(node, "keywords", []):
                    if kw.arg and kw.arg in param_names:
                        new_call_context[kw.arg] = self.resolve_expression(kw.value, sink, scope_id, current_lineno, visited.copy(), call_context)

                returns = self.returns_by_scope.get(func_scope, [])
                if not returns: return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"void_return:{function_name}")

                callee_mod = func_scope.split(":")[0]
                callee_file = self.file_paths.get(callee_mod, "unknown.py")
                callee_func = func_scope.split(":")[-1]

                ret_taints = []
                for ret in returns:
                    if ret.value:
                        r_taint = self.resolve_expression(ret.value, sink, func_scope, ret.lineno, visited.copy(), new_call_context)
                        if r_taint.state != TaintState.CLEAN:
                            ret_step = len(r_taint.proof_nodes)
                            callee_return_pn = self.create_proof_node(
                                step_index=ret_step,
                                node_type=ProofNodeType.TRANSFORM,
                                file_path=callee_file,
                                node=ret,
                                symbol=f"return {ast.unparse(ret.value) if hasattr(ast, 'unparse') else 'value'}",
                                scope_id=func_scope,
                                lineno=ret.lineno,
                                override_snippet=self.get_source_snippet(callee_file, ret.lineno, ret.lineno, ret) or f"return {dotted_name(ret.value) or 'expr'}"
                            )
                            r_edges = list(r_taint.proof_edges)
                            if r_taint.proof_nodes:
                                r_edges.append(ProofEdge(from_node_id=r_taint.proof_nodes[-1].node_id, to_node_id=callee_return_pn.node_id, edge_type="RETURN"))
                            r_taint = TaintValue(
                                state=r_taint.state,
                                source_id=r_taint.source_id,
                                confidence=r_taint.confidence,
                                path=[*r_taint.path, f"return:{callee_file}:{ret.lineno}"],
                                last_operation=f"return:{callee_func}",
                                proof_nodes=[*r_taint.proof_nodes, callee_return_pn],
                                proof_edges=r_edges
                            )
                        ret_taints.append(r_taint)
                    else:
                        ret_taints.append(TaintValue(state=TaintState.CLEAN, confidence=1.0))

                if len(ret_taints) == 1:
                    merged_ret = ret_taints[0]
                else:
                    merged_ret = self.merge_taints(ret_taints, f"{callee_file}:return")
                if merged_ret.state != TaintState.CLEAN:
                    src_id = merged_ret.source_id
                    if not src_id:
                        for a in arg_values:
                            if a.source_id: src_id = a.source_id; break
                        if not src_id:
                            for kw in new_call_context.values():
                                if kw.source_id: src_id = kw.source_id; break
                    step_idx = len(merged_ret.proof_nodes)
                    ret_pn = self.create_proof_node(
                        step_index=step_idx,
                        node_type=ProofNodeType.TRANSFORM,
                        file_path=file_name,
                        node=node,
                        symbol=f"return_from:{callee_func}",
                        scope_id=scope_id,
                        lineno=current_lineno,
                        override_snippet=self.get_source_snippet(file_name, current_lineno, current_lineno, node) or f"{function_name}()"
                    )
                    new_edges = list(merged_ret.proof_edges)
                    if merged_ret.proof_nodes:
                        new_edges.append(ProofEdge(from_node_id=merged_ret.proof_nodes[-1].node_id, to_node_id=ret_pn.node_id, edge_type="RETURN"))
                    return TaintValue(state=merged_ret.state, source_id=src_id, confidence=merged_ret.confidence, path=[*merged_ret.path, f"return_from:{callee_file}:{callee_func}"], last_operation=f"call:{function_name}", proof_nodes=[*merged_ret.proof_nodes, ret_pn], proof_edges=new_edges)
                return merged_ret

            tainted_args = [arg for arg in arg_values if arg.state != TaintState.CLEAN]
            # Check keyword arguments for unknown wrappers as well
            for kw in getattr(node, "keywords", []):
                kw_val = self.resolve_expression(kw.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                if kw_val.state != TaintState.CLEAN:
                    tainted_args.append(kw_val)
            if not tainted_args: return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=function_name)

            first_tainted = tainted_args[0]
            return TaintValue(state=TaintState.UNKNOWN, source_id=first_tainted.source_id, confidence=0.50, path=[*first_tainted.path, f"{file_name}:{function_name}()"], last_operation=f"unknown_wrapper:{function_name}")

        if isinstance(node, ast.Subscript):
            canon_val = self.resolve_canonical_name(node.value, scope_id) or dotted_name(node.value)
            norm_val = canon_val[6:] if (canon_val and canon_val.startswith("flask.")) else canon_val
            dname_val = dotted_name(node.value)
            framework_sources = (
                "request.args", "request.form", "request.values", "request.headers",
                "request.cookies", "request.GET", "request.POST", "request.query_params", "sys.argv",
                "os.environ", "request.META", "request.FILES"
            )
            if norm_val in framework_sources or dname_val in framework_sources:
                loc = location(node, file_name)
                is_env = (norm_val == "os.environ" or dname_val == "os.environ")
                is_sys_argv = (norm_val == "sys.argv" or dname_val == "sys.argv")
                target_state = TaintState.UNKNOWN if (is_sys_argv or is_env) else TaintState.TAINTED
                target_conf = 0.50 if (is_sys_argv or is_env) else 1.0
                target_op = (
                    "ENVIRONMENT_VARIABLE_ACCESS" if is_env
                    else "CLI_ARGUMENT_ACCESS" if is_sys_argv
                    else "HTTP_PARAMETER_ACCESS"
                )
                for existing in self.sources:
                    if existing.location == loc:
                        src_pn = self.create_proof_node(
                            step_index=0,
                            node_type=ProofNodeType.SOURCE,
                            file_path=file_name,
                            node=node,
                            symbol=f"{norm_val}[]",
                            scope_id=scope_id
                        )
                        return TaintValue(state=target_state, source_id=existing.id, confidence=target_conf, path=[existing.id], last_operation=f"{norm_val}[]", proof_nodes=[src_pn], proof_edges=[])
                source_id = self.next_source_id()
                src = SecurityNode(id=source_id, node_type=NodeType.SOURCE, symbol=f"{norm_val}[...]", operation=target_op, location=loc, metadata={"source_type": "USER_CONTROLLED"})
                self.sources.append(src)
                src_pn = self.create_proof_node(
                    step_index=0,
                    node_type=ProofNodeType.SOURCE,
                    file_path=file_name,
                    node=node,
                    symbol=f"{norm_val}[]",
                    scope_id=scope_id
                )
                return TaintValue(state=target_state, source_id=source_id, confidence=target_conf, path=[source_id], last_operation=f"{norm_val}[]", proof_nodes=[src_pn], proof_edges=[])

            # Field-sensitive container taint tracking
            key = self._extract_subscript_key(node.slice, scope_id)
            base_var = node.value.id if isinstance(node.value, ast.Name) else None

            # 1. Composite key in assignments: d["cmd"] = ...
            if base_var and key is not None:
                comp_key = f"{base_var}[{key}]"
                current_scope = scope_id
                found_record = None
                while current_scope:
                    recs = self.assignments_by_scope.get((current_scope, comp_key), [])
                    recs_before = [r for r in recs if r.lineno < current_lineno]
                    if recs_before:
                        uncond = [r for r in recs_before if not r.is_conditional]
                        found_record = uncond[-1] if uncond else recs_before[-1]
                        break
                    if "." in current_scope and "function" in current_scope:
                        current_scope = current_scope.rsplit(".", 1)[0]
                    elif ":function" in current_scope:
                        current_scope = f"{mod_name}:global"
                    elif current_scope != f"{mod_name}:global":
                        current_scope = f"{mod_name}:global"
                    else:
                        break
                if found_record:
                    comp_v_key = f"{scope_id}:{comp_key}:{found_record.lineno}"
                    if comp_v_key not in visited:
                        v_copy = visited.copy()
                        v_copy.add(comp_v_key)
                        res = self.resolve_expression(found_record.value_node, sink, found_record.scope_id, found_record.lineno, v_copy, call_context)
                        if res.state != TaintState.CLEAN:
                            step_idx = len(res.proof_nodes)
                            cont_pn = self.create_proof_node(
                                step_index=step_idx,
                                node_type=ProofNodeType.ASSIGNMENT,
                                file_path=file_name,
                                node=found_record.value_node,
                                symbol=comp_key,
                                scope_id=found_record.scope_id,
                                lineno=found_record.lineno,
                                override_snippet=self.get_source_snippet(file_name, found_record.lineno, found_record.lineno) or f"{comp_key} = ..."
                            )
                            new_edges = list(res.proof_edges)
                            if res.proof_nodes:
                                new_edges.append(ProofEdge(from_node_id=res.proof_nodes[-1].node_id, to_node_id=cont_pn.node_id, edge_type="ASSIGNMENT"))
                            return TaintValue(
                                state=res.state,
                                source_id=res.source_id,
                                confidence=res.confidence,
                                path=[*res.path, f"{file_name}:{comp_key}"],
                                last_operation=f"container_key:{comp_key}",
                                proof_nodes=[*res.proof_nodes, cont_pn],
                                proof_edges=new_edges
                            )
                        else:
                            return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"container_key:{comp_key}")

            # 2. Check base variable definition if initialized as dict/list literal
            if base_var and key is not None:
                current_scope = scope_id
                found_base_record = None
                while current_scope:
                    recs = self.assignments_by_scope.get((current_scope, base_var), [])
                    recs_before = [r for r in recs if r.lineno < current_lineno]
                    if recs_before:
                        uncond = [r for r in recs_before if not r.is_conditional]
                        found_base_record = uncond[-1] if uncond else recs_before[-1]
                        break
                    if "." in current_scope and "function" in current_scope:
                        current_scope = current_scope.rsplit(".", 1)[0]
                    elif ":function" in current_scope:
                        current_scope = f"{mod_name}:global"
                    elif current_scope != f"{mod_name}:global":
                        current_scope = f"{mod_name}:global"
                    else:
                        break
                if found_base_record:
                    val_node = found_base_record.value_node
                    if isinstance(val_node, ast.Dict):
                        matched_key_val = None
                        for k, v in zip(val_node.keys, val_node.values):
                            k_val = self._extract_subscript_key(k, found_base_record.scope_id)
                            if k_val == key:
                                matched_key_val = v
                                break
                        if matched_key_val is not None:
                            key_v_key = f"{found_base_record.scope_id}:{base_var}[{key}]:{found_base_record.lineno}"
                            if key_v_key not in visited:
                                v_copy = visited.copy()
                                v_copy.add(key_v_key)
                                return self.resolve_expression(matched_key_val, sink, found_base_record.scope_id, found_base_record.lineno, v_copy, call_context)
                    elif isinstance(val_node, (ast.List, ast.Tuple)) and isinstance(key, int):
                        if -len(val_node.elts) <= key < len(val_node.elts):
                            matched_elt = val_node.elts[key]
                            elt_v_key = f"{found_base_record.scope_id}:{base_var}[{key}]:{found_base_record.lineno}"
                            if elt_v_key not in visited:
                                v_copy = visited.copy()
                                v_copy.add(elt_v_key)
                                return self.resolve_expression(matched_elt, sink, found_base_record.scope_id, found_base_record.lineno, v_copy, call_context)
                    elif isinstance(val_node, (ast.ListComp, ast.GeneratorExp)):
                        elt_v_key = f"{found_base_record.scope_id}:{base_var}[*]:{found_base_record.lineno}"
                        if elt_v_key not in visited:
                            v_copy = visited.copy()
                            v_copy.add(elt_v_key)
                            return self.resolve_expression(val_node.elt, sink, found_base_record.scope_id, found_base_record.lineno, v_copy, call_context)

            # 3. Check direct literal
            if isinstance(node.value, ast.Dict) and key is not None:
                for k, v in zip(node.value.keys, node.value.values):
                    k_val = self._extract_subscript_key(k, scope_id)
                    if k_val == key:
                        return self.resolve_expression(v, sink, scope_id, current_lineno, visited.copy(), call_context)
            elif isinstance(node.value, (ast.List, ast.Tuple)) and isinstance(key, int):
                if -len(node.value.elts) <= key < len(node.value.elts):
                    return self.resolve_expression(node.value.elts[key], sink, scope_id, current_lineno, visited.copy(), call_context)
            elif isinstance(node.value, (ast.ListComp, ast.GeneratorExp)):
                return self.resolve_expression(node.value.elt, sink, scope_id, current_lineno, visited.copy(), call_context)

            # 4. Fallback: evaluate base container value (unions all keys or dynamic subscript)
            val_taint = self.resolve_expression(node.value, sink, scope_id, current_lineno, visited.copy(), call_context)
            if val_taint.state != TaintState.CLEAN and val_taint.source_id:
                return TaintValue(state=val_taint.state, source_id=val_taint.source_id, confidence=val_taint.confidence, path=[*val_taint.path, f"{file_name}:subscript"], last_operation="subscript")
            if val_taint.state == TaintState.CLEAN:
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="subscript")
            return val_taint

        if isinstance(node, ast.IfExp):
            true_taint = self.resolve_expression(node.body, sink, scope_id, current_lineno, visited.copy(), call_context)
            false_taint = self.resolve_expression(node.orelse, sink, scope_id, current_lineno, visited.copy(), call_context)

            if true_taint.state == TaintState.CLEAN and false_taint.state == TaintState.CLEAN:
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="ternary")

            tainted_branches = [t for t in (true_taint, false_taint) if t.state == TaintState.TAINTED]
            if tainted_branches:
                best_t = max(tainted_branches, key=lambda t: t.confidence)
                combined_path = []
                for t in tainted_branches:
                    if t.path:
                        combined_path.extend(t.path)
                combined_path.append(f"{file_name}:ternary")
                combined_nodes = []
                seen_nids = set()
                combined_edges = []
                seen_ekeys = set()
                for t in tainted_branches:
                    for pn in t.proof_nodes:
                        if pn.node_id not in seen_nids:
                            seen_nids.add(pn.node_id)
                            combined_nodes.append(pn)
                    for pe in t.proof_edges:
                        ek = (pe.from_node_id, pe.to_node_id, pe.edge_type)
                        if ek not in seen_ekeys:
                            seen_ekeys.add(ek)
                            combined_edges.append(pe)
                return TaintValue(
                    state=TaintState.TAINTED,
                    source_id=best_t.source_id,
                    confidence=best_t.confidence,
                    path=combined_path,
                    last_operation="ternary",
                    proof_nodes=combined_nodes,
                    proof_edges=combined_edges
                )

            unknown_branches = [t for t in (true_taint, false_taint) if t.state != TaintState.CLEAN]
            first_u = unknown_branches[0]
            return TaintValue(
                state=TaintState.UNKNOWN,
                source_id=first_u.source_id,
                confidence=0.50,
                path=[*true_taint.path, *false_taint.path, "ternary"],
                last_operation="ternary",
                proof_nodes=first_u.proof_nodes,
                proof_edges=first_u.proof_edges
            )

        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            elt_taint = self.resolve_expression(node.elt, sink, scope_id, current_lineno, visited.copy(), call_context)
            if elt_taint.state == TaintState.TAINTED:
                return TaintValue(
                    state=TaintState.TAINTED,
                    source_id=elt_taint.source_id,
                    confidence=elt_taint.confidence,
                    path=[*elt_taint.path, f"{file_name}:comprehension"],
                    last_operation="comprehension",
                    proof_nodes=elt_taint.proof_nodes,
                    proof_edges=elt_taint.proof_edges
                )
            for gen in node.generators:
                iter_taint = self.resolve_expression(gen.iter, sink, scope_id, current_lineno, visited.copy(), call_context)
                if iter_taint.state == TaintState.TAINTED:
                    return TaintValue(
                        state=TaintState.TAINTED,
                        source_id=iter_taint.source_id,
                        confidence=iter_taint.confidence,
                        path=[*iter_taint.path, f"{file_name}:comprehension"],
                        last_operation="comprehension",
                        proof_nodes=iter_taint.proof_nodes,
                        proof_edges=iter_taint.proof_edges
                    )
            if elt_taint.state == TaintState.CLEAN:
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="comprehension")
            return elt_taint

        if isinstance(node, ast.DictComp):
            key_taint = self.resolve_expression(node.key, sink, scope_id, current_lineno, visited.copy(), call_context)
            val_taint = self.resolve_expression(node.value, sink, scope_id, current_lineno, visited.copy(), call_context)
            if val_taint.state == TaintState.TAINTED:
                return TaintValue(state=TaintState.TAINTED, source_id=val_taint.source_id, confidence=val_taint.confidence, path=[*val_taint.path, f"{file_name}:dict_comp"], last_operation="dict_comp", proof_nodes=val_taint.proof_nodes, proof_edges=val_taint.proof_edges)
            if key_taint.state == TaintState.TAINTED:
                return TaintValue(state=TaintState.TAINTED, source_id=key_taint.source_id, confidence=key_taint.confidence, path=[*key_taint.path, f"{file_name}:dict_comp"], last_operation="dict_comp", proof_nodes=key_taint.proof_nodes, proof_edges=key_taint.proof_edges)
            if val_taint.state == TaintState.CLEAN and key_taint.state == TaintState.CLEAN:
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="dict_comp")
            return val_taint if val_taint.state != TaintState.CLEAN else key_taint

        if isinstance(node, ast.NamedExpr):
            if isinstance(node.target, ast.Name):
                record = AssignmentRecord(
                    target_name=node.target.id,
                    value_node=node.value,
                    lineno=getattr(node, "lineno", current_lineno),
                    scope_id=scope_id,
                    is_conditional=False
                )
                self.assignments_by_scope.setdefault((scope_id, node.target.id), []).append(record)
            return self.resolve_expression(node.value, sink, scope_id, current_lineno, visited.copy(), call_context)

        if isinstance(node, ast.Constant):
            return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="constant")

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            if not node.elts:
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="constant")
            elt_taints = [self.resolve_expression(elt, sink, scope_id, current_lineno, visited.copy(), call_context) for elt in node.elts]
            tainted_elts = [e for e in elt_taints if e.state == TaintState.TAINTED]
            if tainted_elts:
                best_e = max(tainted_elts, key=lambda e: e.confidence)
                return TaintValue(state=TaintState.TAINTED, source_id=best_e.source_id, confidence=best_e.confidence, path=[*best_e.path, f"{file_name}:collection"], last_operation="collection")
            unknown_elts = [e for e in elt_taints if e.state != TaintState.CLEAN]
            if unknown_elts:
                first_u = unknown_elts[0]
                return TaintValue(state=TaintState.UNKNOWN, source_id=first_u.source_id, confidence=0.50, path=[*first_u.path, f"{file_name}:collection"], last_operation="collection")
            return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="constant")

        if isinstance(node, ast.Dict):
            items_to_check = []
            for k in node.keys:
                if k: items_to_check.append(k)
            items_to_check.extend(node.values)
            if not items_to_check:
                return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="constant")
            item_taints = [self.resolve_expression(item, sink, scope_id, current_lineno, visited.copy(), call_context) for item in items_to_check]
            tainted_items = [e for e in item_taints if e.state == TaintState.TAINTED]
            if tainted_items:
                best_e = max(tainted_items, key=lambda e: e.confidence)
                return TaintValue(state=TaintState.TAINTED, source_id=best_e.source_id, confidence=best_e.confidence, path=[*best_e.path, f"{file_name}:dict"], last_operation="dict")
            unknown_items = [e for e in item_taints if e.state != TaintState.CLEAN]
            if unknown_items:
                first_u = unknown_items[0]
                return TaintValue(state=TaintState.UNKNOWN, source_id=first_u.source_id, confidence=0.50, path=[*first_u.path, f"{file_name}:dict"], last_operation="dict")
            return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="constant")
        if isinstance(node, ast.BinOp):
            left = self.resolve_expression(node.left, sink, scope_id, current_lineno, visited.copy(), call_context)
            right = self.resolve_expression(node.right, sink, scope_id, current_lineno, visited.copy(), call_context)
            if left.state == TaintState.CLEAN and right.state == TaintState.CLEAN: return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation="binary_op")

            is_str_add = isinstance(node.op, ast.Add) and (self._is_string_expr(node.left, scope_id) or self._is_string_expr(node.right, scope_id))
            is_str_mod = isinstance(node.op, ast.Mod) and self._is_string_expr(node.left, scope_id)
            is_path_div = isinstance(node.op, ast.Div) and (self._is_path_expr(node.left, scope_id) or self._is_path_expr(node.right, scope_id))

            if is_str_add or is_str_mod or is_path_div:
                if left.state == TaintState.TAINTED or right.state == TaintState.TAINTED:
                    best_t = left if left.state == TaintState.TAINTED else right
                    if left.state == TaintState.TAINTED and right.state == TaintState.TAINTED:
                        best_t = left if left.confidence >= right.confidence else right
                    op_label = "path_join" if is_path_div else "binary_op"
                    combined_path = [*left.path, *right.path, op_label]
                    combined_nodes = []
                    seen_nids = set()
                    combined_edges = []
                    seen_ekeys = set()
                    for t in (left, right):
                        if t.state == TaintState.TAINTED:
                            for pn in t.proof_nodes:
                                if pn.node_id not in seen_nids:
                                    seen_nids.add(pn.node_id)
                                    combined_nodes.append(pn)
                            for pe in t.proof_edges:
                                ek = (pe.from_node_id, pe.to_node_id, pe.edge_type)
                                if ek not in seen_ekeys:
                                    seen_ekeys.add(ek)
                                    combined_edges.append(pe)
                    return TaintValue(
                        state=TaintState.TAINTED,
                        source_id=best_t.source_id,
                        confidence=best_t.confidence,
                        path=combined_path,
                        last_operation=op_label,
                        proof_nodes=combined_nodes,
                        proof_edges=combined_edges
                    )
                else:
                    src_id = left.source_id or right.source_id
                    op_label = "path_join" if is_path_div else "binary_op"
                    combined_path = [*left.path, *right.path, op_label]
                    combined_nodes = []
                    seen_nids = set()
                    combined_edges = []
                    seen_ekeys = set()
                    for t in (left, right):
                        if t.state != TaintState.CLEAN:
                            for pn in t.proof_nodes:
                                if pn.node_id not in seen_nids:
                                    seen_nids.add(pn.node_id)
                                    combined_nodes.append(pn)
                            for pe in t.proof_edges:
                                ek = (pe.from_node_id, pe.to_node_id, pe.edge_type)
                                if ek not in seen_ekeys:
                                    seen_ekeys.add(ek)
                                    combined_edges.append(pe)
                    return TaintValue(
                        state=TaintState.UNKNOWN,
                        source_id=src_id,
                        confidence=0.50,
                        path=combined_path,
                        last_operation=op_label,
                        proof_nodes=combined_nodes,
                        proof_edges=combined_edges
                    )

            src_id = left.source_id or right.source_id
            combined_nodes = []
            seen_nids = set()
            combined_edges = []
            seen_ekeys = set()
            for t in (left, right):
                if t.state != TaintState.CLEAN:
                    for pn in t.proof_nodes:
                        if pn.node_id not in seen_nids:
                            seen_nids.add(pn.node_id)
                            combined_nodes.append(pn)
                    for pe in t.proof_edges:
                        ek = (pe.from_node_id, pe.to_node_id, pe.edge_type)
                        if ek not in seen_ekeys:
                            seen_ekeys.add(ek)
                            combined_edges.append(pe)
            # Container/general concatenation: EITHER tainted operand taints the
            # result (prefer the higher-confidence tainted side).
            tainted_op = None
            if left.state == TaintState.TAINTED and right.state == TaintState.TAINTED:
                tainted_op = left if left.confidence >= right.confidence else right
            elif left.state == TaintState.TAINTED:
                tainted_op = left
            elif right.state == TaintState.TAINTED:
                tainted_op = right
            return TaintValue(
                state=TaintState.TAINTED if tainted_op is not None else TaintState.UNKNOWN,
                source_id=tainted_op.source_id if tainted_op is not None else src_id,
                confidence=tainted_op.confidence if tainted_op is not None else min(left.confidence, right.confidence),
                path=[*left.path, *right.path, "binary_op"],
                last_operation="binary_op",
                proof_nodes=combined_nodes,
                proof_edges=combined_edges
            )
        return TaintValue(state=TaintState.UNKNOWN, confidence=0.50, last_operation="unknown_expression")

    def resolve_path_provenance(
        self,
        node: ast.AST,
        sink: SecurityNode,
        scope_id: str,
        current_lineno: int,
        visited: Optional[set[str]] = None,
        call_context: Optional[dict[str, ProvenanceValue]] = None
    ) -> ProvenanceValue:
        if visited is None: visited = set()
        if call_context is None: call_context = {}
        mod_name = scope_id.split(":")[0]
        file_name = self.file_paths.get(mod_name, f"{mod_name}.py")

        # 1. Path containment check
        if isinstance(node, (ast.Name, ast.Attribute)):
            dname = dotted_name(node)
            if dname and self.is_var_contained(dname, scope_id, current_lineno, sink, visited):
                return ProvenanceValue(
                    state=ProvenanceState.STATIC,
                    confidence=1.0,
                    source_trace=(f"{file_name}:{dname}", "path_containment_proven"),
                    origin_node=node
                )

        # Class attribute check for self.<attr> / cls.<attr> / inst.<attr>
        if isinstance(node, ast.Attribute):
            target_cls_scope = None
            if isinstance(node.value, ast.Name) and node.value.id in ("self", "cls"):
                target_cls_scope = self._get_enclosing_class_scope(scope_id)
            elif isinstance(node.value, ast.Name):
                target_cls_scope = self._resolve_instance_class_scope(node.value.id, scope_id)

            if target_cls_scope:
                records = self.class_field_assignments.get((target_cls_scope, node.attr), [])
                if records:
                    provs = [self.resolve_path_provenance(r.value_node, sink, r.scope_id, r.lineno, visited.copy(), call_context) for r in records]
                    tainted = [p for p in provs if p.state == ProvenanceState.TAINTED]
                    if tainted:
                        best_p = max(tainted, key=lambda p: p.confidence)
                        return ProvenanceValue(
                            state=ProvenanceState.TAINTED,
                            confidence=1.0,
                            source_id=best_p.source_id,
                            source_trace=(*best_p.source_trace, f"{file_name}:self.{node.attr}"),
                            origin_node=node
                        )
                    if all(p.state in (ProvenanceState.STATIC, ProvenanceState.INTERNAL_DYNAMIC) for p in provs):
                        return ProvenanceValue(
                            state=ProvenanceState.STATIC,
                            confidence=1.0,
                            source_trace=(f"{file_name}:self.{node.attr}", "clean_class_attr"),
                            origin_node=node
                        )

        # 2. String/Bytes Constants
        if isinstance(node, ast.Constant):
            return ProvenanceValue(
                state=ProvenanceState.STATIC,
                confidence=1.0,
                source_trace=("literal",),
                origin_node=node
            )

        # Ternary Expressions (ast.IfExp)
        if isinstance(node, ast.IfExp):
            p_body = self.resolve_path_provenance(node.body, sink, scope_id, current_lineno, visited.copy(), call_context)
            p_orelse = self.resolve_path_provenance(node.orelse, sink, scope_id, current_lineno, visited.copy(), call_context)
            return compose_path_provenance(p_body, p_orelse, operator="ternary")

        # 3. JoinedStr (f-strings)
        if isinstance(node, ast.JoinedStr):
            parts: list[ProvenanceValue] = []
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    parts.append(self.resolve_path_provenance(part.value, sink, scope_id, current_lineno, visited.copy(), call_context))
                elif isinstance(part, ast.Constant):
                    parts.append(ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=("fstring_const",), origin_node=part))
                else:
                    parts.append(self.resolve_path_provenance(part, sink, scope_id, current_lineno, visited.copy(), call_context))
            if not parts:
                return ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=("fstring_empty",), origin_node=node)
            res = parts[0]
            for p in parts[1:]:
                res = compose_path_provenance(res, p, operator="fstring")
            return res

        # 4. BinOp (path joins via /, +, %)
        if isinstance(node, ast.BinOp):
            left = self.resolve_path_provenance(node.left, sink, scope_id, current_lineno, visited.copy(), call_context)
            right = self.resolve_path_provenance(node.right, sink, scope_id, current_lineno, visited.copy(), call_context)
            op_label = "/" if isinstance(node.op, ast.Div) else ("+" if isinstance(node.op, ast.Add) else "%")
            return compose_path_provenance(left, right, operator=op_label)

        # 4b. Collections (List, Tuple, Set)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            if not node.elts:
                return ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=("empty_collection",), origin_node=node)
            elt_provs = [self.resolve_path_provenance(elt, sink, scope_id, current_lineno, visited.copy(), call_context) for elt in node.elts]
            tainted_elts = [e for e in elt_provs if e.state == ProvenanceState.TAINTED]
            if tainted_elts:
                best_e = max(tainted_elts, key=lambda e: e.confidence)
                return ProvenanceValue(
                    state=ProvenanceState.TAINTED,
                    confidence=best_e.confidence,
                    source_id=best_e.source_id,
                    source_trace=(*best_e.source_trace, "collection"),
                    origin_node=node
                )
            unknown_elts = [e for e in elt_provs if e.state == ProvenanceState.UNKNOWN]
            if unknown_elts:
                first_u = unknown_elts[0]
                return ProvenanceValue(
                    state=ProvenanceState.UNKNOWN,
                    confidence=0.50,
                    source_id=first_u.source_id,
                    source_trace=(*first_u.source_trace, "collection"),
                    origin_node=node
                )
            if all(e.state == ProvenanceState.STATIC for e in elt_provs):
                return ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=("collection_static",), origin_node=node)
            return ProvenanceValue(state=ProvenanceState.INTERNAL_DYNAMIC, confidence=1.0, source_trace=("collection_dynamic",), origin_node=node)

        # 5. Call
        if isinstance(node, ast.Call):
            if self.is_source_call(node, scope_id):
                src = self.get_or_create_source(node, file_name, scope_id)
                return ProvenanceValue(
                    state=ProvenanceState.TAINTED,
                    confidence=1.0,
                    source_id=src.id,
                    source_trace=(src.id,),
                    origin_node=node
                )

            canon_name = self.resolve_canonical_name(node.func, scope_id) or dotted_name(node.func) or ""
            d_name = dotted_name(node.func) or ""

            if (canon_name in SANITIZER_REGISTRY and self.sanitizer_protects_context(canon_name, sink)) or \
               (d_name in SANITIZER_REGISTRY and self.sanitizer_protects_context(d_name, sink)):
                return ProvenanceValue(
                    state=ProvenanceState.STATIC,
                    confidence=1.0,
                    source_trace=(f"sanitizer:{canon_name or d_name}",),
                    origin_node=node
                )

            fn_base = (canon_name or d_name).replace("builtins.", "")
            d_base = d_name.replace("builtins.", "")
            if fn_base in PRIMITIVE_NUMERIC_CASTS or d_base in PRIMITIVE_NUMERIC_CASTS:
                return ProvenanceValue(
                    state=ProvenanceState.STATIC,
                    confidence=1.0,
                    source_trace=(f"primitive_cast:{fn_base or d_base}",),
                    origin_node=node
                )

            if fn_base in ("str", "repr", "bytes") or d_base in ("str", "repr", "bytes"):
                if node.args:
                    return self.resolve_path_provenance(node.args[0], sink, scope_id, current_lineno, visited.copy(), call_context)

            # 1. User-defined function resolution MUST take precedence over semantic stdlib producer lookup
            func_scope = self._resolve_function_scope(d_name or canon_name, scope_id)
            if func_scope:
                call_sig = f"prov_call:{func_scope}:{current_lineno}"
                if call_sig not in visited:
                    visited.add(call_sig)
                    func_node = self.functions[func_scope]
                    param_names = [a.arg for a in func_node.args.args]
                    arg_provs = [self.resolve_path_provenance(a, sink, scope_id, current_lineno, visited.copy(), call_context) for a in node.args]
                    new_ctx = {}
                    for idx, p_name in enumerate(param_names):
                        if idx < len(arg_provs):
                            new_ctx[p_name] = arg_provs[idx]
                        else:
                            new_ctx[p_name] = ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0)
                    for kw in getattr(node, "keywords", []):
                        if kw.arg and kw.arg in param_names:
                            new_ctx[kw.arg] = self.resolve_path_provenance(kw.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                    returns = self.returns_by_scope.get(func_scope, [])
                    if returns:
                        ret_provs = []
                        for r in returns:
                            if r.value:
                                ret_provs.append(self.resolve_path_provenance(r.value, sink, func_scope, r.lineno, visited.copy(), new_ctx))
                            else:
                                ret_provs.append(ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0))
                        res_p = ret_provs[0]
                        for rp in ret_provs[1:]:
                            res_p = compose_path_provenance(res_p, rp, operator="return_merge")
                        return res_p

            # 2. Standard library internal path producers (only canonical/import-qualified)
            if canon_name in STD_INTERNAL_PATH_PRODUCERS:
                return ProvenanceValue(
                    state=ProvenanceState.INTERNAL_DYNAMIC,
                    confidence=1.0,
                    source_trace=(f"std_internal:{canon_name}",),
                    origin_node=node
                )
            if isinstance(node.func, ast.Attribute) and node.func.attr == "parse_args":
                recv_name = getattr(node.func.value, "id", "")
                recs = self.assignments_by_scope.get((scope_id, recv_name), [])
                if recs and isinstance(recs[-1].value_node, ast.Call):
                    cname = dotted_name(recs[-1].value_node.func)
                    if cname in ("argparse.ArgumentParser", "ArgumentParser"):
                        return ProvenanceValue(
                            state=ProvenanceState.INTERNAL_DYNAMIC,
                            confidence=1.0,
                            source_trace=("std_internal:argparse.parse_args",),
                            origin_node=node
                        )

            # 3. Built-in type conversions / path wrappers (str, bytes, os.fspath)
            if (canon_name in ("str", "bytes", "os.fspath", "builtins.str", "builtins.bytes") or d_name in ("str", "bytes", "os.fspath")) and node.args:
                return self.resolve_path_provenance(node.args[0], sink, scope_id, current_lineno, visited.copy(), call_context)

            if canon_name in ("os.walk", "walk") or d_name in ("os.walk", "walk"):
                root_expr = node.args[0] if node.args else None
                if root_expr:
                    root_prov = self.resolve_path_provenance(root_expr, sink, scope_id, current_lineno, visited.copy(), call_context)
                else:
                    root_prov = ProvenanceValue(state=ProvenanceState.UNKNOWN, confidence=0.50)

                if root_prov.state == ProvenanceState.TAINTED:
                    return ProvenanceValue(
                        state=ProvenanceState.TAINTED,
                        confidence=root_prov.confidence,
                        source_id=root_prov.source_id,
                        source_trace=(*root_prov.source_trace, "os.walk(tainted_root)"),
                        origin_node=node
                    )
                elif root_prov.state == ProvenanceState.UNKNOWN:
                    return ProvenanceValue(
                        state=ProvenanceState.UNKNOWN,
                        confidence=0.50,
                        source_id=root_prov.source_id,
                        source_trace=(*root_prov.source_trace, "os.walk(unknown_root)"),
                        origin_node=node
                    )
                else:
                    return ProvenanceValue(
                        state=ProvenanceState.INTERNAL_DYNAMIC,
                        confidence=1.0,
                        source_trace=(*root_prov.source_trace, "os.walk(internal_root)"),
                        origin_node=node
                    )

            if canon_name in ("Path", "pathlib.Path") or d_name in ("Path", "pathlib.Path"):
                if node.args:
                    arg_prov = self.resolve_path_provenance(node.args[0], sink, scope_id, current_lineno, visited.copy(), call_context)
                    return ProvenanceValue(
                        state=arg_prov.state,
                        confidence=arg_prov.confidence,
                        source_id=arg_prov.source_id,
                        source_trace=(*arg_prov.source_trace, f"{file_name}:Path()"),
                        origin_node=node
                    )
                return ProvenanceValue(
                    state=ProvenanceState.INTERNAL_DYNAMIC,
                    confidence=1.0,
                    source_trace=(f"{file_name}:Path()",),
                    origin_node=node
                )

            if canon_name in ("Path.cwd", "pathlib.Path.cwd", "Path.home", "pathlib.Path.home") or \
               d_name in ("Path.cwd", "pathlib.Path.cwd", "Path.home", "pathlib.Path.home"):
                return ProvenanceValue(
                    state=ProvenanceState.INTERNAL_DYNAMIC,
                    confidence=1.0,
                    source_trace=(canon_name or d_name,),
                    origin_node=node
                )

            if isinstance(node.func, ast.Attribute) and node.func.attr in ("resolve", "absolute", "expanduser"):
                recv_prov = self.resolve_path_provenance(node.func.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                return ProvenanceValue(
                    state=recv_prov.state,
                    confidence=recv_prov.confidence,
                    source_id=recv_prov.source_id,
                    source_trace=(*recv_prov.source_trace, f".{node.func.attr}()"),
                    origin_node=node
                )

            if (isinstance(node.func, ast.Attribute) and node.func.attr == "joinpath") or \
               canon_name in ("os.path.join", "posixpath.join", "ntpath.join") or \
               d_name in ("os.path.join", "posixpath.join", "ntpath.join"):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "joinpath":
                    all_arg_nodes = [node.func.value] + list(node.args)
                else:
                    all_arg_nodes = list(node.args)

                arg_provs = [self.resolve_path_provenance(a, sink, scope_id, current_lineno, visited.copy(), call_context) for a in all_arg_nodes]
                tainted_provs = [p for p in arg_provs if p.state == ProvenanceState.TAINTED]
                if tainted_provs:
                    best_t = max(tainted_provs, key=lambda a: a.confidence)
                    return ProvenanceValue(
                        state=ProvenanceState.TAINTED,
                        confidence=best_t.confidence,
                        source_id=best_t.source_id,
                        source_trace=(*best_t.source_trace, "[join]"),
                        origin_node=node
                    )
                if any(p.state == ProvenanceState.UNKNOWN for p in arg_provs):
                    return ProvenanceValue(state=ProvenanceState.UNKNOWN, confidence=0.50, source_trace=("[os.path.join]",), origin_node=node)
                if any(p.state == ProvenanceState.INTERNAL_DYNAMIC for p in arg_provs):
                    return ProvenanceValue(state=ProvenanceState.INTERNAL_DYNAMIC, confidence=1.0, source_trace=("[join_internal]",), origin_node=node)
                return ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=("literal",), origin_node=node)

            if (canon_name in ("os.path.normpath", "posixpath.normpath", "ntpath.normpath",
                               "os.path.dirname", "posixpath.dirname", "ntpath.dirname",
                               "os.path.abspath", "posixpath.abspath", "ntpath.abspath",
                               "os.path.realpath", "posixpath.realpath", "ntpath.realpath") or \
                d_name in ("os.path.normpath", "posixpath.normpath", "ntpath.normpath",
                           "os.path.dirname", "posixpath.dirname", "ntpath.dirname",
                           "os.path.abspath", "posixpath.abspath", "ntpath.abspath",
                           "os.path.realpath", "posixpath.realpath", "ntpath.realpath")) and node.args:
                return self.resolve_path_provenance(node.args[0], sink, scope_id, current_lineno, visited.copy(), call_context)

            # Unmodeled / opaque call: check if any arguments are tainted
            arg_provs = [self.resolve_path_provenance(a, sink, scope_id, current_lineno, visited.copy(), call_context) for a in node.args]
            for kw in getattr(node, "keywords", []):
                arg_provs.append(self.resolve_path_provenance(kw.value, sink, scope_id, current_lineno, visited.copy(), call_context))
            tainted_args = [a for a in arg_provs if a.state == ProvenanceState.TAINTED]
            if tainted_args:
                best_t = max(tainted_args, key=lambda a: a.confidence)
                return ProvenanceValue(
                    state=ProvenanceState.UNKNOWN,
                    confidence=0.50,
                    source_id=best_t.source_id,
                    source_trace=(*best_t.source_trace, f"unknown_wrapper:{canon_name or d_name}()"),
                    origin_node=node
                )
            t_val = self.resolve_expression(node, sink, scope_id, current_lineno, visited.copy(), {})
            if t_val.state == TaintState.TAINTED:
                return ProvenanceValue(
                    state=ProvenanceState.TAINTED,
                    confidence=t_val.confidence,
                    source_id=t_val.source_id,
                    source_trace=tuple(t_val.path) or (t_val.source_id,),
                    origin_node=node
                )
            return ProvenanceValue(
                state=ProvenanceState.UNKNOWN,
                confidence=0.50,
                source_id=t_val.source_id,
                source_trace=tuple(t_val.path) or (f"opaque_call:{canon_name or d_name}()",),
                origin_node=node
            )

        # 6. Attribute
        if isinstance(node, ast.Attribute):
            canon_attr = self.resolve_canonical_name(node, scope_id) or dotted_name(node) or ""
            norm_attr = canon_attr[6:] if canon_attr.startswith("flask.") else canon_attr
            if norm_attr in ("request.data", "request.json", "request.query_string", "request.body", "request.META", "request.FILES") or (node.attr in ("data", "json", "query_string", "body", "META", "FILES") and dotted_name(node.value) == "request"):
                src = self.get_or_create_source(node, file_name, scope_id)
                return ProvenanceValue(
                    state=ProvenanceState.TAINTED,
                    confidence=1.0,
                    source_id=src.id,
                    source_trace=(src.id,),
                    origin_node=node
                )

            if node.attr in ("parent", "parents", "name", "stem", "suffix", "suffixes"):
                if node.attr == "name" and self.sanitizer_protects_context("pathlib.Path.name", sink):
                    return ProvenanceValue(
                        state=ProvenanceState.STATIC,
                        confidence=1.0,
                        source_trace=("sanitizer:pathlib.Path.name",),
                        origin_node=node
                    )
                recv_prov = self.resolve_path_provenance(node.value, sink, scope_id, current_lineno, visited.copy(), call_context)
                return ProvenanceValue(
                    state=recv_prov.state,
                    confidence=recv_prov.confidence,
                    source_id=recv_prov.source_id,
                    source_trace=(*recv_prov.source_trace, f".{node.attr}"),
                    origin_node=node
                )

            recv_prov = self.resolve_path_provenance(node.value, sink, scope_id, current_lineno, visited.copy(), call_context)
            if recv_prov.state == ProvenanceState.INTERNAL_DYNAMIC:
                return ProvenanceValue(
                    state=ProvenanceState.INTERNAL_DYNAMIC,
                    confidence=recv_prov.confidence,
                    source_trace=(*recv_prov.source_trace, f".{node.attr}"),
                    origin_node=node
                )
            elif recv_prov.state == ProvenanceState.TAINTED:
                return ProvenanceValue(
                    state=ProvenanceState.TAINTED,
                    confidence=recv_prov.confidence,
                    source_id=recv_prov.source_id,
                    source_trace=(*recv_prov.source_trace, f".{node.attr}"),
                    origin_node=node
                )
            return ProvenanceValue(state=ProvenanceState.UNKNOWN, confidence=0.50, source_trace=(f".{node.attr}",), origin_node=node)

        # 7. Subscript (e.g. request.args["param"])
        if isinstance(node, ast.Subscript):
            canon_val = self.resolve_canonical_name(node.value, scope_id) or dotted_name(node.value) or ""
            norm_val = canon_val[6:] if canon_val.startswith("flask.") else canon_val
            if norm_val in ("request.args", "request.form", "request.values", "request.headers", "request.cookies", "request.META", "request.FILES") or dotted_name(node.value) in ("request.args", "request.form", "request.values", "request.headers", "request.cookies", "request.META", "request.FILES"):
                src = self.get_or_create_source(node, file_name, scope_id)
                return ProvenanceValue(
                    state=ProvenanceState.TAINTED,
                    confidence=1.0,
                    source_id=src.id,
                    source_trace=(src.id,),
                    origin_node=node
                )
            val_prov = self.resolve_path_provenance(node.value, sink, scope_id, current_lineno, visited.copy(), call_context)
            if val_prov.state == ProvenanceState.TAINTED:
                return ProvenanceValue(state=ProvenanceState.TAINTED, confidence=val_prov.confidence, source_id=val_prov.source_id, source_trace=(*val_prov.source_trace, "subscript"), origin_node=node)
            elif val_prov.state == ProvenanceState.INTERNAL_DYNAMIC:
                return ProvenanceValue(state=ProvenanceState.INTERNAL_DYNAMIC, confidence=val_prov.confidence, source_trace=(*val_prov.source_trace, "subscript"), origin_node=node)
            elif val_prov.state == ProvenanceState.STATIC:
                return ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=(*val_prov.source_trace, "subscript"), origin_node=node)
            return ProvenanceValue(state=ProvenanceState.UNKNOWN, confidence=0.50, source_trace=("subscript",), origin_node=node)

        # 8. Name
        if isinstance(node, ast.Name):
            if node.id == "__file__":
                return ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=("__file__",), origin_node=node)
            if node.id in ("__name__", "__doc__", "__package__", "True", "False", "None"):
                return ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=("builtin_constant",), origin_node=node)
            if node.id in ("self", "cls"):
                return ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=(node.id,), origin_node=node)

            var_key = f"prov:{scope_id}:{node.id}"
            if var_key in visited:
                return ProvenanceValue(state=ProvenanceState.UNKNOWN, confidence=0.50, source_trace=(f"circular:{node.id}",), origin_node=node)
            visited.add(var_key)

            if node.id in call_context:
                ctx_v = call_context[node.id]
                return ProvenanceValue(
                    state=ctx_v.state,
                    confidence=ctx_v.confidence,
                    source_id=ctx_v.source_id,
                    source_trace=(*ctx_v.source_trace, f"{file_name}:{node.id}"),
                    origin_node=node
                )

            current_scope = scope_id
            records_before = []
            while current_scope:
                recs = self.assignments_by_scope.get((current_scope, node.id), [])
                records_before = [r for r in recs if r.lineno < current_lineno]
                if records_before:
                    break
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope:
                    current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global":
                    current_scope = f"{mod_name}:global"
                else:
                    break

            if records_before:
                last_uncond_idx = -1
                for idx, r in enumerate(records_before):
                    if not r.is_conditional: last_uncond_idx = idx
                reaching = [records_before[last_uncond_idx]] + [r for r in records_before[last_uncond_idx + 1:] if r.is_conditional] if last_uncond_idx != -1 else records_before

                if len(reaching) == 1 and not reaching[0].is_conditional:
                    target_rec = reaching[0]
                    resolved = self.resolve_path_provenance(target_rec.value_node, sink, target_rec.scope_id, target_rec.lineno, visited, call_context)
                    return ProvenanceValue(
                        state=resolved.state,
                        confidence=resolved.confidence,
                        source_id=resolved.source_id,
                        source_trace=(*resolved.source_trace, f"{file_name}:{node.id}"),
                        origin_node=node
                    )
                else:
                    resolved_list = [self.resolve_path_provenance(r.value_node, sink, r.scope_id, r.lineno, visited.copy(), call_context) for r in reaching]
                    res_p = resolved_list[0]
                    for rp in resolved_list[1:]:
                        res_p = compose_path_provenance(res_p, rp, operator="branch_merge")
                    return ProvenanceValue(
                        state=res_p.state,
                        confidence=res_p.confidence,
                        source_id=res_p.source_id,
                        source_trace=(*res_p.source_trace, f"{file_name}:{node.id}"),
                        origin_node=node
                    )

            # Parameter flow from callers
            enc_scope = scope_id
            target_func_node = None
            target_scope = None
            while enc_scope:
                f_node = self.functions.get(enc_scope)
                if f_node and any(a.arg == node.id for a in f_node.args.args):
                    target_func_node = f_node
                    target_scope = enc_scope
                    break
                if "." in enc_scope:
                    enc_scope = enc_scope.rsplit(".", 1)[0]
                else:
                    break

            if target_func_node and target_scope:
                param_names = [a.arg for a in target_func_node.args.args]
                param_idx = param_names.index(node.id)
                call_sites = self.call_sites_by_target.get(target_scope, [])
                if call_sites:
                    caller_provs = []
                    for call_node, caller_scope, call_lineno in call_sites:
                        arg_expr = None
                        for kw in getattr(call_node, "keywords", []):
                            if kw.arg == node.id:
                                arg_expr = kw.value
                                break
                        if arg_expr is None:
                            pos_idx = param_idx
                            if param_names and param_names[0] in ("self", "cls"):
                                pos_idx = param_idx - 1
                            if 0 <= pos_idx < len(call_node.args):
                                arg_expr = call_node.args[pos_idx]
                        if arg_expr is not None:
                            site_key = f"prov_param:{target_scope}:{node.id}:{caller_scope}:{call_lineno}"
                            if site_key not in visited:
                                v_copy = visited.copy()
                                v_copy.add(site_key)
                                caller_prov = self.resolve_path_provenance(arg_expr, sink, caller_scope, call_lineno, v_copy)
                                caller_provs.append(caller_prov)
                    if caller_provs:
                        res_p = caller_provs[0]
                        for cp in caller_provs[1:]:
                            res_p = compose_path_provenance(res_p, cp, operator="caller_merge")
                        return ProvenanceValue(
                            state=res_p.state,
                            confidence=res_p.confidence,
                            source_id=res_p.source_id,
                            source_trace=(*res_p.source_trace, f"param:{node.id}"),
                            origin_node=node
                        )
                # Unresolved parameter with no call sites
                param_symbol = f"{node.id} ({target_func_node.name})"
                source_id = self.next_source_id()
                src_node = SecurityNode(
                    id=source_id,
                    node_type=NodeType.SOURCE,
                    symbol=param_symbol,
                    operation="PARAMETER_INPUT",
                    location=CodeLocation(file=file_name, line_start=target_func_node.lineno, line_end=target_func_node.lineno, column_start=0, column_end=0),
                    metadata={"source_type": "FUNCTION_PARAMETER", "parameter": node.id, "function": target_func_node.name}
                )
                self.sources.append(src_node)
                return ProvenanceValue(
                    state=ProvenanceState.UNKNOWN,
                    confidence=0.50,
                    source_id=source_id,
                    source_trace=(f"unresolved_param:{node.id}", f"{file_name}:{node.id}"),
                    origin_node=node
                )

            # Known imports, functions, builtins
            if node.id in self.imports.get(mod_name, {}):
                return ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=(f"import:{node.id}",), origin_node=node)
            if f"{mod_name}:function:{node.id}" in self.functions:
                return ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=(f"function:{node.id}",), origin_node=node)
            if node.id in ("int", "str", "bytes", "float", "bool", "list", "dict", "set", "tuple", "len", "range", "open", "print"):
                return ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=(f"builtin:{node.id}",), origin_node=node)

            return ProvenanceValue(state=ProvenanceState.UNKNOWN, confidence=0.50, source_trace=(f"unresolved:{node.id}",), origin_node=node)

        t_val = self.resolve_expression(node, sink, scope_id, current_lineno, visited.copy(), {})
        if t_val.state == TaintState.TAINTED:
            return ProvenanceValue(
                state=ProvenanceState.TAINTED,
                confidence=t_val.confidence,
                source_id=t_val.source_id,
                source_trace=tuple(t_val.path) or (t_val.source_id,),
                origin_node=node
            )
        return ProvenanceValue(state=ProvenanceState.UNKNOWN, confidence=0.50, source_trace=("unknown_expr",), origin_node=node)

    def analyze(self):
        for mod_name, tree in self.modules.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names: self.imports[mod_name][alias.asname or alias.name] = alias.name
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if getattr(node, 'level', 0) > 0:
                        parts = mod_name.split(".")
                        base = ".".join(parts[:-node.level]) if len(parts) > node.level else ""
                        module = f"{base}.{module}" if base and module else base or module
                    for alias in node.names: self.imports[mod_name][alias.asname or alias.name] = f"{module}.{alias.name}" if module else alias.name
        for mod_name, tree in self.modules.items():
            self.collect_statements(tree.body, scope_id=f"{mod_name}:global", is_conditional=False)

        # Index call sites by target function scope
        for call_node, caller_scope, lineno in self.raw_calls:
            canon_name = self.resolve_canonical_name(call_node.func, caller_scope)
            fname = canon_name or dotted_name(call_node.func)
            if fname:
                func_scope = self._resolve_function_scope(fname, caller_scope)
                if func_scope:
                    self.call_sites_by_target.setdefault(func_scope, []).append((call_node, caller_scope, lineno))

        # Re-scan raw_calls for any sinks resolved after call-site indexing (higher-order callbacks)
        for call_node, caller_scope, lineno in self.raw_calls:
            # Check if this call is a parameter callback (higher-order function invocation)
            func_def = self.functions.get(caller_scope)
            p_fn_name = None
            if func_def:
                param_names = [a.arg for a in func_def.args.args]
                cand = call_node.func.id if isinstance(call_node.func, ast.Name) else None
                if cand:
                    if cand in param_names:
                        p_fn_name = cand
                    else:
                        recs = self.assignments_by_scope.get((caller_scope, cand), [])
                        recs_before = [r for r in recs if r.lineno < lineno]
                        if recs_before and isinstance(recs_before[-1].value_node, ast.Name) and recs_before[-1].value_node.id in param_names:
                            p_fn_name = recs_before[-1].value_node.id

            if p_fn_name and func_def:
                param_names = [a.arg for a in func_def.args.args]
                p_fn_idx = param_names.index(p_fn_name)
                call_sites = self.call_sites_by_target.get(caller_scope, [])
                mod_name = caller_scope.split(":")[0]
                file_path = self.file_paths.get(mod_name, "unknown.py")

                for cs_call, cs_scope, cs_lineno in call_sites:
                    arg_for_fn = None
                    for kw in getattr(cs_call, "keywords", []):
                        if kw.arg == p_fn_name:
                            arg_for_fn = kw.value
                            break
                    if arg_for_fn is None:
                        pos_idx = p_fn_idx
                        if param_names and param_names[0] in ("self", "cls"):
                            pos_idx = p_fn_idx - 1
                        if 0 <= pos_idx < len(cs_call.args):
                            arg_for_fn = cs_call.args[pos_idx]

                    if arg_for_fn is None:
                        continue

                    fn_canon = self.resolve_canonical_name(arg_for_fn, cs_scope) or dotted_name(arg_for_fn)
                    if not fn_canon:
                        continue

                    matched_rule = match_sink_rule(call_node, dotted_name(arg_for_fn) or "", fn_canon)
                    if matched_rule and not self.check_sink_safety(call_node, fn_canon):
                        ctx = {}
                        for idx, p_name in enumerate(param_names):
                            p_expr = None
                            for kw in getattr(cs_call, "keywords", []):
                                if kw.arg == p_name:
                                    p_expr = kw.value
                                    break
                            if p_expr is None:
                                p_pos = idx
                                if param_names and param_names[0] in ("self", "cls"):
                                    p_pos = idx - 1
                                if 0 <= p_pos < len(cs_call.args):
                                    p_expr = cs_call.args[p_pos]
                            if p_expr is not None:
                                p_taint = self.resolve_expression(p_expr, None, cs_scope, cs_lineno)
                                if p_taint.state != TaintState.CLEAN:
                                    caller_file = cs_scope.split(":", 1)[0] if ":" in cs_scope else file_path
                                    call_func_symbol = dotted_name(cs_call.func) if hasattr(cs_call, "func") else "call"
                                    call_snippet = self.get_source_snippet(caller_file, cs_lineno, cs_lineno, cs_call) or f"{call_func_symbol}(...)"
                                    step_idx = len(p_taint.proof_nodes)
                                    cs_pn = self.create_proof_node(
                                        step_index=step_idx,
                                        node_type=ProofNodeType.CALL_SITE,
                                        file_path=caller_file,
                                        node=cs_call,
                                        symbol=call_func_symbol,
                                        scope_id=cs_scope,
                                        lineno=cs_lineno,
                                        override_snippet=call_snippet
                                    )
                                    callee_line = func_def.lineno if func_def else lineno
                                    param_pn = self.create_proof_node(
                                        step_index=step_idx + 1,
                                        node_type=ProofNodeType.PARAM_BINDING,
                                        file_path=file_path,
                                        node=func_def,
                                        symbol=p_name,
                                        scope_id=caller_scope,
                                        lineno=callee_line,
                                        override_snippet=self.get_source_snippet(file_path, callee_line, callee_line, func_def) or f"def {func_def.name}(..., {p_name}, ...)"
                                    )
                                    new_edges = list(p_taint.proof_edges)
                                    if p_taint.proof_nodes:
                                        new_edges.append(ProofEdge(from_node_id=p_taint.proof_nodes[-1].node_id, to_node_id=cs_pn.node_id, edge_type="CALL_SITE"))
                                    new_edges.append(ProofEdge(from_node_id=cs_pn.node_id, to_node_id=param_pn.node_id, edge_type="PARAM_BINDING"))
                                    p_taint = TaintValue(
                                        state=p_taint.state,
                                        source_id=p_taint.source_id,
                                        confidence=p_taint.confidence,
                                        path=[*p_taint.path, f"call:{call_func_symbol}", f"{file_path}:{p_name}"],
                                        last_operation=f"param:{p_name}",
                                        proof_nodes=[*p_taint.proof_nodes, cs_pn, param_pn],
                                        proof_edges=new_edges
                                    )
                                ctx[p_name] = p_taint
                            else:
                                ctx[p_name] = TaintValue(state=TaintState.CLEAN, confidence=1.0)

                        sink_id = self.next_sink_id()
                        sink_meta = {
                            "operation": matched_rule.operation,
                            "category": matched_rule.category,
                            "cwe": matched_rule.cwe_id,
                            "sink_type": matched_rule.category,
                        }
                        loc = location(call_node, file_path)
                        sink_node = SecurityNode(
                            id=sink_id,
                            node_type=NodeType.SINK,
                            symbol=fn_canon,
                            operation=matched_rule.operation,
                            location=loc,
                            metadata=sink_meta
                        )
                        self.sinks.append(sink_node)
                        self.sink_records.append(SinkRecord(
                            node=call_node,
                            security_node=sink_node,
                            lineno=lineno,
                            scope_id=caller_scope,
                            call_context=ctx
                        ))
            elif not any(r.node is call_node for r in self.sink_records):
                if self.is_sink_call(call_node, caller_scope, lineno):
                    canon_name = self.resolve_canonical_name(call_node.func, caller_scope) or dotted_name(call_node.func) or ""
                    if not self.check_sink_safety(call_node, canon_name):
                        mod_name = caller_scope.split(":")[0]
                        file_path = self.file_paths.get(mod_name, "unknown.py")
                        sink_node = self.get_or_create_sink(call_node, file_path, caller_scope)
                        self.sink_records.append(SinkRecord(node=call_node, security_node=sink_node, lineno=lineno, scope_id=caller_scope))
                        if sink_node.metadata.get("cwe") != "CWE-295" and self._has_disabled_ssl(call_node):
                            ssl_sink = self.get_or_create_sink(call_node, file_path, caller_scope, force_cwe="CWE-295")
                            self.sink_records.append(SinkRecord(node=call_node, security_node=ssl_sink, lineno=lineno, scope_id=caller_scope))

        for mod_name, tree in self.modules.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and self.is_source_call(node, f"{mod_name}:global"):
                    self.get_or_create_source(node, self.file_paths.get(mod_name, "unknown.py"), f"{mod_name}:global")
        for record in self.sink_records:
            sink = record.security_node
            target_expr = None
            if isinstance(record.node.func, ast.Attribute) and (record.node.func.attr in {"read_text", "read_bytes", "write_text", "write_bytes", "extractall", "extract"} or (record.node.func.attr == "open" and self._is_path_expr(record.node.func.value, record.scope_id))):
                target_expr = record.node.func.value
            elif isinstance(record.node.func, ast.Attribute) and record.node.func.attr == "render":
                if self._is_jinja_template_expr(record.node.func.value, record.scope_id):
                    target_expr = record.node.func.value
                else:
                    if sink in self.sinks:
                        self.sinks.remove(sink)
                    continue
            elif record.node.args:
                target_expr = record.node.args[0]
            elif getattr(record.node, "keywords", []):
                for kw in record.node.keywords:
                    if kw.arg in ("source", "template", "s"):
                        target_expr = kw.value
                        break

            cwe = sink.metadata.get("cwe")
            stype = sink.metadata.get("sink_type")
            op = sink.metadata.get("operation")

            if cwe == "CWE-295":
                self.edges.append(DataFlowEdge(
                    source_id="INSECURE_CONFIGURATION",
                    target_id=sink.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=1.0,
                    transform="disabled_ssl_verification"
                ))
                continue

            if cwe == "CWE-338":
                self.edges.append(DataFlowEdge(
                    source_id="INSECURE_PRNG",
                    target_id=sink.id,
                    kind="CONFIRMED_DATA_FLOW" if self.audit_all else "POTENTIAL_DATA_FLOW",
                    confidence=1.0 if self.audit_all else 0.85,
                    transform="insecure_random_generator"
                ))
                continue

            if op == "UNBOUNDED_READ" or (cwe in ("CWE-400", "CWE-776") and isinstance(record.node.func, ast.Attribute) and record.node.func.attr == "read" and len(record.node.args) == 0):
                receiver = record.node.func.value
                recv_taint = self.resolve_expression(receiver, sink, record.scope_id, record.lineno, call_context=record.call_context)
                if not self._is_untrusted_stream(receiver, record.scope_id, record.lineno, recv_taint):
                    if sink in self.sinks:
                        self.sinks.remove(sink)
                    continue

                source_id = recv_taint.source_id if (recv_taint and recv_taint.source_id) else "UNBOUNDED_READ"
                confidence = recv_taint.confidence if (recv_taint and recv_taint.state == TaintState.TAINTED) else (1.0 if self.audit_all else 0.85)
                kind = "CONFIRMED_DATA_FLOW" if confidence >= 1.0 else "POTENTIAL_DATA_FLOW"
                full_path_str = " -> ".join(recv_taint.path) if (recv_taint and recv_taint.path) else "unbounded_file_read"
                pg = None
                if recv_taint and recv_taint.state in (TaintState.TAINTED, TaintState.UNKNOWN):
                    pg = self._build_proof_graph(recv_taint, sink, record, cwe or "CWE-400")

                self.edges.append(DataFlowEdge(
                    source_id=source_id,
                    target_id=sink.id,
                    kind=kind,
                    confidence=confidence,
                    transform=full_path_str,
                    proof_graph=pg
                ))
                continue

            if target_expr is None:
                continue

            cwe = sink.metadata.get("cwe")
            stype = sink.metadata.get("sink_type")
            op = sink.metadata.get("operation")
            is_cwe22 = (cwe == "CWE-22" or stype in ("PATH_TRAVERSAL", "FILE_ACCESS") or op == "FILE_ACCESS")

            if is_cwe22:
                prov = self.resolve_path_provenance(target_expr, sink, record.scope_id, record.lineno)
                full_path_str = " -> ".join(prov.source_trace) if prov.source_trace else "path_provenance"
                if prov.state in (ProvenanceState.STATIC, ProvenanceState.INTERNAL_DYNAMIC):
                    continue
                elif prov.state == ProvenanceState.TAINTED:
                    kind = "CONFIRMED_DATA_FLOW" if prov.confidence >= 1.0 else "POTENTIAL_DATA_FLOW"
                    pg = self._build_cwe22_proof_graph(prov, sink, record)
                    self.edges.append(DataFlowEdge(
                        source_id=prov.source_id or "UNKNOWN",
                        target_id=sink.id,
                        kind=kind,
                        confidence=prov.confidence,
                        transform=full_path_str,
                        proof_graph=pg
                    ))
                elif prov.state == ProvenanceState.UNKNOWN:
                    pg = self._build_cwe22_proof_graph(prov, sink, record)
                    self.edges.append(DataFlowEdge(
                        source_id=prov.source_id or "UNKNOWN",
                        target_id=sink.id,
                        kind="POTENTIAL_DATA_FLOW",
                        confidence=0.50,
                        transform=full_path_str,
                        proof_graph=pg
                    ))
            else:
                taint = self.resolve_expression(target_expr, sink, record.scope_id, record.lineno, call_context=record.call_context)
                full_path_str = " -> ".join(taint.path) if taint.path else taint.last_operation
                pg = None
                if taint.state in (TaintState.TAINTED, TaintState.UNKNOWN):
                    pg = self._build_proof_graph(taint, sink, record, cwe)
                if taint.state == TaintState.TAINTED:
                    kind = "CONFIRMED_DATA_FLOW" if taint.confidence >= 1.0 else "POTENTIAL_DATA_FLOW"
                    self.edges.append(DataFlowEdge(source_id=taint.source_id or "UNKNOWN", target_id=sink.id, kind=kind, confidence=taint.confidence, transform=full_path_str, proof_graph=pg))
                elif taint.state == TaintState.UNKNOWN:
                    self.edges.append(DataFlowEdge(source_id=taint.source_id or "UNKNOWN", target_id=sink.id, kind="POTENTIAL_DATA_FLOW", confidence=0.50, transform=full_path_str, proof_graph=pg))
        return self.sources, self.sinks, self.edges

    def _build_proof_graph(self, taint: TaintValue, sink: SecurityNode, record: SinkRecord, cwe: str) -> ProofGraphIR:
        sink_file = sink.location.file
        sink_pn = self.create_proof_node(
            step_index=len(taint.proof_nodes),
            node_type=ProofNodeType.SINK,
            file_path=sink_file,
            node=record.node,
            symbol=sink.symbol,
            scope_id=record.scope_id,
            lineno=record.lineno,
            override_snippet=self.get_source_snippet(sink_file, record.lineno, record.lineno, record.node) or f"{sink.symbol}(...)"
        )

        graph_nodes = []
        if taint.proof_nodes and taint.proof_nodes[0].node_type == ProofNodeType.SOURCE:
            graph_nodes.extend(taint.proof_nodes)
        else:
            src_obj = next((s for s in self.sources if s.id == taint.source_id), None)
            if src_obj:
                s_file = src_obj.location.file
                src_pn = self.create_proof_node(
                    step_index=0,
                    node_type=ProofNodeType.SOURCE,
                    file_path=s_file,
                    node=None,
                    symbol=src_obj.symbol,
                    scope_id=f"{s_file}:global",
                    lineno=src_obj.location.line_start,
                    override_snippet=self.get_source_snippet(s_file, src_obj.location.line_start, src_obj.location.line_start) or f"Source: {src_obj.symbol}"
                )
                graph_nodes.append(src_pn)
            graph_nodes.extend(taint.proof_nodes)

        # Invariant: graph_nodes MUST contain a SOURCE node at index 0
        if not any(n.node_type == ProofNodeType.SOURCE for n in graph_nodes):
            enc_func = self.functions.get(record.scope_id)
            matched_param = None
            if enc_func and enc_func.args.args:
                for p_str in getattr(taint, "path", []):
                    for arg_node in enc_func.args.args:
                        if p_str.endswith(f":{arg_node.arg}") or p_str == arg_node.arg:
                            matched_param = arg_node
                            break
                    if matched_param:
                        break
                if not matched_param:
                    matched_param = enc_func.args.args[0] if enc_func.args.args[0].arg not in ("self", "cls") else (enc_func.args.args[1] if len(enc_func.args.args) > 1 else enc_func.args.args[0])

            if enc_func and matched_param:
                param_sym = f"{matched_param.arg} ({enc_func.name})"
                src_pn = self.create_proof_node(
                    step_index=0,
                    node_type=ProofNodeType.SOURCE,
                    file_path=sink_file,
                    node=enc_func,
                    symbol=param_sym,
                    scope_id=record.scope_id,
                    lineno=enc_func.lineno,
                    override_snippet=self.get_source_snippet(sink_file, enc_func.lineno, enc_func.lineno, enc_func) or f"def {enc_func.name}(..., {matched_param.arg}, ...)"
                )
            else:
                func_name = enc_func.name if enc_func else (record.scope_id.split(":")[-1] if (record.scope_id and ":" in record.scope_id and record.scope_id.split(":")[-1] != "global") else "handler")
                src_sym = f"user_input ({func_name})"
                src_pn = self.create_proof_node(
                    step_index=0,
                    node_type=ProofNodeType.SOURCE,
                    file_path=sink_file,
                    node=None,
                    symbol=src_sym,
                    scope_id=record.scope_id,
                    lineno=max(1, record.lineno - 1),
                    override_snippet=src_sym
                )
            graph_nodes.insert(0, src_pn)

        all_candidate_nodes = [*graph_nodes, sink_pn]
        reindexed_nodes = []
        for idx, n in enumerate(all_candidate_nodes):
            reindexed_nodes.append(ProofNode(
                node_id=n.node_id,
                step_index=idx,
                node_type=n.node_type,
                file_path=n.file_path,
                start_line=n.start_line,
                end_line=n.end_line,
                symbol=n.symbol,
                expression_snippet=n.expression_snippet,
                scope_id=n.scope_id
            ))

        if taint.proof_edges:
            graph_edges = list(taint.proof_edges)
            if len(reindexed_nodes) >= 2:
                sink_incoming = reindexed_nodes[-2]
                sink_edge = ProofEdge(
                    from_node_id=sink_incoming.node_id,
                    to_node_id=sink_pn.node_id,
                    edge_type=ProofNodeType.SINK.value
                )
                if (sink_edge.from_node_id, sink_edge.to_node_id, sink_edge.edge_type) not in {(e.from_node_id, e.to_node_id, e.edge_type) for e in graph_edges}:
                    graph_edges.append(sink_edge)
                if not any(e.from_node_id == reindexed_nodes[0].node_id for e in graph_edges):
                    graph_edges.insert(0, ProofEdge(
                        from_node_id=reindexed_nodes[0].node_id,
                        to_node_id=reindexed_nodes[1].node_id,
                        edge_type=reindexed_nodes[1].node_type.value
                    ))
        else:
            graph_edges = []
            for i in range(len(reindexed_nodes) - 1):
                graph_edges.append(ProofEdge(
                    from_node_id=reindexed_nodes[i].node_id,
                    to_node_id=reindexed_nodes[i+1].node_id,
                    edge_type=reindexed_nodes[i+1].node_type.value
                ))

        return ProofGraphIR(
            finding_id=f"TCS-IR-{sink.id}",
            cwe=cwe or "UNKNOWN_CWE",
            confidence=taint.confidence,
            nodes=reindexed_nodes,
            edges=graph_edges
        )

    def _build_cwe22_proof_graph(self, prov: ProvenanceValue, sink: SecurityNode, record: SinkRecord) -> ProofGraphIR:
        cwe22_nodes = []
        src_obj = next((s for s in self.sources if s.id == prov.source_id), None)
        if src_obj:
            s_file = src_obj.location.file
            src_pn = self.create_proof_node(
                step_index=0,
                node_type=ProofNodeType.SOURCE,
                file_path=s_file,
                node=None,
                symbol=src_obj.symbol,
                scope_id=f"{s_file}:global",
                lineno=src_obj.location.line_start
            )
            cwe22_nodes.append(src_pn)

        # Intermediate variable assignments from prov.source_trace
        for item in prov.source_trace:
            if ":" in item and not item.startswith("["):
                fname, var_name = item.split(":", 1)
                for (sc, target_name), recs in self.assignments_by_scope.items():
                    if target_name == var_name:
                        for r in recs:
                            if r.lineno <= record.lineno:
                                assign_pn = self.create_proof_node(
                                    step_index=len(cwe22_nodes),
                                    node_type=ProofNodeType.ASSIGNMENT,
                                    file_path=fname,
                                    node=r.value_node,
                                    symbol=var_name,
                                    scope_id=r.scope_id,
                                    lineno=r.lineno,
                                    override_snippet=self.get_source_snippet(fname, r.lineno, r.lineno) or f"{var_name} = ..."
                                )
                                if not any(n.symbol == var_name and n.start_line == r.lineno for n in cwe22_nodes):
                                    cwe22_nodes.append(assign_pn)

        sink_file = sink.location.file

        # Invariant: cwe22_nodes MUST contain a SOURCE node
        if not any(n.node_type == ProofNodeType.SOURCE for n in cwe22_nodes):
            enc_func = self.functions.get(record.scope_id)
            matched_param = None
            if enc_func and enc_func.args.args:
                for p_str in getattr(prov, "source_trace", []):
                    for arg_node in enc_func.args.args:
                        if p_str.endswith(f":{arg_node.arg}") or p_str == arg_node.arg:
                            matched_param = arg_node
                            break
                    if matched_param:
                        break
                if not matched_param:
                    matched_param = enc_func.args.args[0] if enc_func.args.args[0].arg not in ("self", "cls") else (enc_func.args.args[1] if len(enc_func.args.args) > 1 else enc_func.args.args[0])

            if enc_func and matched_param:
                param_sym = f"{matched_param.arg} ({enc_func.name})"
                src_pn = self.create_proof_node(
                    step_index=0,
                    node_type=ProofNodeType.SOURCE,
                    file_path=sink_file,
                    node=enc_func,
                    symbol=param_sym,
                    scope_id=record.scope_id,
                    lineno=enc_func.lineno,
                    override_snippet=self.get_source_snippet(sink_file, enc_func.lineno, enc_func.lineno, enc_func) or f"def {enc_func.name}(..., {matched_param.arg}, ...)"
                )
            else:
                func_name = enc_func.name if enc_func else (record.scope_id.split(":")[-1] if (record.scope_id and ":" in record.scope_id and record.scope_id.split(":")[-1] != "global") else "handler")
                src_sym = f"user_input ({func_name})"
                src_pn = self.create_proof_node(
                    step_index=0,
                    node_type=ProofNodeType.SOURCE,
                    file_path=sink_file,
                    node=None,
                    symbol=src_sym,
                    scope_id=record.scope_id,
                    lineno=max(1, record.lineno - 1),
                    override_snippet=src_sym
                )
            cwe22_nodes.insert(0, src_pn)

        sink_pn = self.create_proof_node(
            step_index=len(cwe22_nodes),
            node_type=ProofNodeType.SINK,
            file_path=sink_file,
            node=record.node,
            symbol=sink.symbol,
            scope_id=record.scope_id,
            lineno=record.lineno,
            override_snippet=self.get_source_snippet(sink_file, record.lineno, record.lineno, record.node) or f"{sink.symbol}(...)"
        )
        cwe22_nodes.append(sink_pn)

        # Enforce strict chronological order:
        # Order by start_line, then type weight (SOURCE=0, PARAM_BINDING=1, ASSIGNMENT=2, CALL_SITE=3, TRANSFORM=4, SANITIZER=5, SINK=6)
        type_order = {
            ProofNodeType.SOURCE: 0,
            ProofNodeType.PARAM_BINDING: 1,
            ProofNodeType.ASSIGNMENT: 2,
            ProofNodeType.CALL_SITE: 3,
            ProofNodeType.TRANSFORM: 4,
            ProofNodeType.SANITIZER: 5,
            ProofNodeType.SINK: 6,
        }
        cwe22_nodes.sort(key=lambda n: (n.start_line, type_order.get(n.node_type, 9)))

        reindexed_nodes = []
        for idx, n in enumerate(cwe22_nodes):
            reindexed_nodes.append(ProofNode(
                node_id=n.node_id,
                step_index=idx,
                node_type=n.node_type,
                file_path=n.file_path,
                start_line=n.start_line,
                end_line=n.end_line,
                symbol=n.symbol,
                expression_snippet=n.expression_snippet,
                scope_id=n.scope_id
            ))

        graph_edges = []
        for i in range(len(reindexed_nodes) - 1):
            graph_edges.append(ProofEdge(
                from_node_id=reindexed_nodes[i].node_id,
                to_node_id=reindexed_nodes[i+1].node_id,
                edge_type=reindexed_nodes[i+1].node_type.value
            ))

        return ProofGraphIR(
            finding_id=f"TCS-IR-{sink.id}",
            cwe="CWE-22",
            confidence=prov.confidence,
            nodes=reindexed_nodes,
            edges=graph_edges
        )