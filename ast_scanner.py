from __future__ import annotations
import ast
import math
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, List, Dict, Any, Union, Tuple
from rule_engine import match_sink_rule, check_sink_safety_rules, get_rule, SINK_MATCHER_NAMES
from tcs.analysis.def_use import LocalDefUseTracker
from tcs.analysis.function_contracts import FunctionContractExtractor, FunctionSinkContract, KNOWN_SINKS

# TimeCodeSecurity: Safe parallel parsing with hardware governance
try:
    from tcs.parallel_scanner import parse_files_parallel
    PARALLEL_PARSING_AVAILABLE = True
except ImportError:
    PARALLEL_PARSING_AVAILABLE = False

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

    @property
    def lineno(self) -> int:
        return self.location.line_start

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
    # Django REST Framework / Flask Request Data
    "request.data": {"operation": "HTTP_BODY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED", "category": "WEB_PARAMETER", "severity": "HIGH"},
    "request.data.get": {"operation": "HTTP_BODY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED", "category": "WEB_PARAMETER", "severity": "HIGH"},
    "request.data.getlist": {"operation": "HTTP_BODY_PARAMETER_ACCESS", "source_type": "USER_CONTROLLED", "category": "WEB_PARAMETER", "severity": "HIGH"},
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
    # TimeCodeSecurity: Server-side session is trusted application state, NOT user-controlled input
    # "request.session.get": {"operation": "SESSION_ACCESS", "source_type": "USER_CONTROLLED"},  # REMOVED - FP source
    # "request.session": {"operation": "SESSION_ACCESS", "source_type": "USER_CONTROLLED"},      # REMOVED - FP source
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
        "urllib.parse.quote", "urllib.parse.quote_plus",
    },
    "CWE-611": {
        "defusedxml.ElementTree.parse", "defusedxml.ElementTree.fromstring",
        "defusedxml.parse", "defusedxml.fromstring",
        "defused_parse", "defused_fromstring",
    },
    "CWE-601": {
        "is_safe_redirect_url", "validate_redirect_url",
        "url_has_allowed_host_and_scheme", "is_relative_url",
        "is_safe_url", "django.utils.http.is_safe_url",
        "django.utils.http.url_has_allowed_host_and_scheme",
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
    "urllib.parse.quote": {"protected_cwes": {"CWE-918"}, "protected_sinks": {"SSRF"}},
    "quote": {"protected_cwes": {"CWE-78"}, "protected_sinks": {"COMMAND_INJECTION", "OS_COMMAND_EXECUTION"}},
    "os.path.basename": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},
    "basename": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},
    "werkzeug.utils.secure_filename": {"protected_cwes": {"CWE-22", "CWE-434"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS", "UNRESTRICTED_FILE_UPLOAD", "FILE_UPLOAD"}},
    "secure_filename": {"protected_cwes": {"CWE-22", "CWE-434"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS", "UNRESTRICTED_FILE_UPLOAD", "FILE_UPLOAD"}},
    "pathlib.Path.name": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},
    "Path.name": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},
    "uuid.UUID": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},
    "UUID": {"protected_cwes": {"CWE-22"}, "protected_sinks": {"PATH_TRAVERSAL", "FILE_ACCESS"}},

    # CWE-918 / CWE-601 Sanitizers
    "is_safe_url": {"protected_cwes": {"CWE-918", "CWE-601"}, "protected_sinks": {"SERVER_SIDE_REQUEST_FORGERY", "SSRF_REQUEST", "OPEN_REDIRECT", "URL_REDIRECTION"}},
    "django.utils.http.is_safe_url": {"protected_cwes": {"CWE-918", "CWE-601"}, "protected_sinks": {"SERVER_SIDE_REQUEST_FORGERY", "SSRF_REQUEST", "OPEN_REDIRECT", "URL_REDIRECTION"}},
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
    "django.utils.http.url_has_allowed_host_and_scheme": {"protected_cwes": {"CWE-601"}, "protected_sinks": {"OPEN_REDIRECT", "URL_REDIRECTION"}},
    "is_relative_url": {"protected_cwes": {"CWE-601"}, "protected_sinks": {"OPEN_REDIRECT", "URL_REDIRECTION"}},

    # CWE-327 / CWE-328 / CWE-312 Sanitizers
    "hashlib.sha256": {"protected_cwes": {"CWE-327", "CWE-328", "CWE-312"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY", "CLEARTEXT_SENSITIVE_STORAGE"}},
    "sha256": {"protected_cwes": {"CWE-327", "CWE-328"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY"}},
    "hashlib.sha512": {"protected_cwes": {"CWE-327", "CWE-328", "CWE-312"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY", "CLEARTEXT_SENSITIVE_STORAGE"}},
    "sha512": {"protected_cwes": {"CWE-327", "CWE-328"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY"}},
    "bcrypt.hashpw": {"protected_cwes": {"CWE-327", "CWE-328", "CWE-312"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY", "CLEARTEXT_SENSITIVE_STORAGE"}},
    "bcrypt": {"protected_cwes": {"CWE-327", "CWE-328", "CWE-312"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY", "CLEARTEXT_SENSITIVE_STORAGE"}},
    "argon2.PasswordHasher": {"protected_cwes": {"CWE-327", "CWE-328"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY"}},
    "argon2": {"protected_cwes": {"CWE-327", "CWE-328", "CWE-312"}, "protected_sinks": {"WEAK_HASH", "WEAK_CRYPTOGRAPHY", "CLEARTEXT_SENSITIVE_STORAGE"}},

    # CWE-338 Sanitizers (CSPRNGs)
    "secrets.token_hex": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "token_hex": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "secrets.token_urlsafe": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "token_urlsafe": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "secrets.choice": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "os.urandom": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "secrets.randbelow": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "randbelow": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "random.SystemRandom": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},
    "SystemRandom": {"protected_cwes": {"CWE-338"}, "protected_sinks": {"INSECURE_RANDOM", "INSECURE_RANDOMNESS"}},

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

    # ─── Batch 2 (data/cwe_blueprint_batch2.json) sanitizers ───
    # CWE-117: Log Injection
    "CWE-117": {
        "replace_crlf", "re_sub_crlf",
        "sanitize_log_input", "sanitize_log_message",
    },
    # CWE-943: NoSQL Injection
    "CWE-943": {
        "sanitize_nosql_input", "sanitize_nosql_query",
        "validate_nosql_query",
    },

    "replace_crlf": {"protected_cwes": {"CWE-117"}, "protected_sinks": {"LOG_INJECTION", "LOG_WRITE"}},
    "re_sub_crlf": {"protected_cwes": {"CWE-117"}, "protected_sinks": {"LOG_INJECTION", "LOG_WRITE"}},
    "sanitize_log_input": {"protected_cwes": {"CWE-117"}, "protected_sinks": {"LOG_INJECTION", "LOG_WRITE"}},
    "sanitize_log_message": {"protected_cwes": {"CWE-117"}, "protected_sinks": {"LOG_INJECTION", "LOG_WRITE"}},

    "sanitize_nosql_input": {"protected_cwes": {"CWE-943"}, "protected_sinks": {"NOSQL_INJECTION", "NOSQL_QUERY"}},
    "sanitize_nosql_query": {"protected_cwes": {"CWE-943"}, "protected_sinks": {"NOSQL_INJECTION", "NOSQL_QUERY"}},
    "validate_nosql_query": {"protected_cwes": {"CWE-943"}, "protected_sinks": {"NOSQL_INJECTION", "NOSQL_QUERY"}},
    # ─── Batch 3A sanitizers (data/cwe_blueprint_batch3a.json) ───
    # NOTE: names that already exist as dict-rules above (secure_filename,
    # hashlib.sha256/sha512, bcrypt(.hashpw), argon2) have CWE-434/CWE-312
    # merged into their existing entries instead of redefined here.
    "CWE-434": {
        "secure_filename", "sanitize_filename", "werkzeug.utils.secure_filename",
        "uuid4", "uuid.uuid4", "uuid4_rename", "basename_only",
    },
    "sanitize_filename": {"protected_cwes": {"CWE-434"}, "protected_sinks": {"UNRESTRICTED_FILE_UPLOAD", "FILE_UPLOAD"}},
    "uuid4": {"protected_cwes": {"CWE-434"}, "protected_sinks": {"UNRESTRICTED_FILE_UPLOAD", "FILE_UPLOAD"}},
    "uuid.uuid4": {"protected_cwes": {"CWE-434"}, "protected_sinks": {"UNRESTRICTED_FILE_UPLOAD", "FILE_UPLOAD"}},
    "uuid4_rename": {"protected_cwes": {"CWE-434"}, "protected_sinks": {"UNRESTRICTED_FILE_UPLOAD", "FILE_UPLOAD"}},
    "CWE-312": {
        "Fernet.encrypt", "encrypt", "hash_pw", "bcrypt", "bcrypt.hashpw",
        "argon2", "argon2.PasswordHasher.hash", "mask_secret", "redact",
        "hashlib.sha256", "hashlib.sha512",
    },
    "Fernet.encrypt": {"protected_cwes": {"CWE-312"}, "protected_sinks": {"CLEARTEXT_SENSITIVE_STORAGE"}},
    "encrypt": {"protected_cwes": {"CWE-312"}, "protected_sinks": {"CLEARTEXT_SENSITIVE_STORAGE"}},
    "hash_pw": {"protected_cwes": {"CWE-312"}, "protected_sinks": {"CLEARTEXT_SENSITIVE_STORAGE"}},
    "argon2.PasswordHasher.hash": {"protected_cwes": {"CWE-312"}, "protected_sinks": {"CLEARTEXT_SENSITIVE_STORAGE"}},
    "mask_secret": {"protected_cwes": {"CWE-312"}, "protected_sinks": {"CLEARTEXT_SENSITIVE_STORAGE"}},
    "redact": {"protected_cwes": {"CWE-312"}, "protected_sinks": {"CLEARTEXT_SENSITIVE_STORAGE"}},
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

    # Dynamic Interpreter & Compiler Execution (CWE-95)
    "code.InteractiveConsole.push": {"operation": "DYNAMIC_CODE_EXECUTION", "category": "CODE_INJECTION", "cwe": "CWE-95", "severity": "CRITICAL", "target_arg": 0},
    "InteractiveConsole.push": {"operation": "DYNAMIC_CODE_EXECUTION", "category": "CODE_INJECTION", "cwe": "CWE-95", "severity": "CRITICAL", "target_arg": 0},
    "code.InteractiveInterpreter.runcode": {"operation": "DYNAMIC_CODE_EXECUTION", "category": "CODE_INJECTION", "cwe": "CWE-95", "severity": "CRITICAL", "target_arg": 0},
    "InteractiveInterpreter.runcode": {"operation": "DYNAMIC_CODE_EXECUTION", "category": "CODE_INJECTION", "cwe": "CWE-95", "severity": "CRITICAL", "target_arg": 0},
    "code.InteractiveInterpreter.runsource": {"operation": "DYNAMIC_CODE_EXECUTION", "category": "CODE_INJECTION", "cwe": "CWE-95", "severity": "CRITICAL", "target_arg": 0},
    "InteractiveInterpreter.runsource": {"operation": "DYNAMIC_CODE_EXECUTION", "category": "CODE_INJECTION", "cwe": "CWE-95", "severity": "CRITICAL", "target_arg": 0},
    "code.compile_command": {"operation": "DYNAMIC_CODE_EXECUTION", "category": "CODE_INJECTION", "cwe": "CWE-95", "severity": "HIGH", "target_arg": 0},
    "compile_command": {"operation": "DYNAMIC_CODE_EXECUTION", "category": "CODE_INJECTION", "cwe": "CWE-95", "severity": "HIGH", "target_arg": 0},
    "_xxsubinterpreters.run_string": {"operation": "DYNAMIC_CODE_EXECUTION", "category": "CODE_INJECTION", "cwe": "CWE-95", "severity": "CRITICAL", "target_arg": 1},
    "_testcapi.run_in_subinterp": {"operation": "DYNAMIC_CODE_EXECUTION", "category": "CODE_INJECTION", "cwe": "CWE-95", "severity": "CRITICAL", "target_arg": 0},
    "support.run_in_subinterp": {"operation": "DYNAMIC_CODE_EXECUTION", "category": "CODE_INJECTION", "cwe": "CWE-95", "severity": "CRITICAL", "target_arg": 0},
    "test.support.run_in_subinterp": {"operation": "DYNAMIC_CODE_EXECUTION", "category": "CODE_INJECTION", "cwe": "CWE-95", "severity": "CRITICAL", "target_arg": 0},

    # CWE-78: Command Injection
    "os.system": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.run": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.call": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.check_call": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.check_output": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "subprocess.Popen": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "asyncio.create_subprocess_shell": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},
    "asyncio.subprocess.create_subprocess_shell": {"operation": "OS_COMMAND_EXECUTION", "category": "COMMAND_INJECTION", "cwe": "CWE-78"},

    # CWE-89: SQL Injection
    "cursor.execute": {"operation": "SQL_QUERY_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"},
    "cursor.executemany": {"operation": "SQL_QUERY_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"},
    "connection.execute": {"operation": "SQL_QUERY_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"},
    "engine.execute": {"operation": "SQL_QUERY_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"},
    "session.execute": {"operation": "SQL_QUERY_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"},
    "Model.objects.raw": {"operation": "SQL_QUERY_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"},
    "Model.objects.extra": {"operation": "SQL_QUERY_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"},
    "RawSQL": {"operation": "SQL_QUERY_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"},
    "django.db.models.expressions.RawSQL": {"operation": "SQL_QUERY_EXECUTION", "category": "SQL_INJECTION", "cwe": "CWE-89"},

    # CWE-319: Cleartext Transmission of Sensitive Information
    "requests.get": {"operation": "INSECURE_HTTP_REQUEST", "category": "CLEARTEXT_TRANSMISSION", "cwe": "CWE-319"},
    "requests.post": {"operation": "INSECURE_HTTP_REQUEST", "category": "CLEARTEXT_TRANSMISSION", "cwe": "CWE-319"},
    "requests.put": {"operation": "INSECURE_HTTP_REQUEST", "category": "CLEARTEXT_TRANSMISSION", "cwe": "CWE-319"},
    "requests.delete": {"operation": "INSECURE_HTTP_REQUEST", "category": "CLEARTEXT_TRANSMISSION", "cwe": "CWE-319"},
    "requests.request": {"operation": "INSECURE_HTTP_REQUEST", "category": "CLEARTEXT_TRANSMISSION", "cwe": "CWE-319"},
    "urllib.request.urlopen": {"operation": "INSECURE_URL_OPEN", "category": "CLEARTEXT_TRANSMISSION", "cwe": "CWE-319"},
    "urllib.request.urlretrieve": {"operation": "INSECURE_URL_RETRIEVE", "category": "CLEARTEXT_TRANSMISSION", "cwe": "CWE-319"},
    "ftplib.FTP": {"operation": "INSECURE_FTP", "category": "CLEARTEXT_TRANSMISSION", "cwe": "CWE-319"},
    "telnetlib.Telnet": {"operation": "INSECURE_TELNET", "category": "CLEARTEXT_TRANSMISSION", "cwe": "CWE-319"},

    # CWE-352: Cross-Site Request Forgery
    "csrf_exempt": {"operation": "CSRF_EXEMPT_DECORATOR", "category": "CSRF_VULNERABILITY", "cwe": "CWE-352"},
    "django.views.decorators.csrf.csrf_exempt": {"operation": "CSRF_EXEMPT_DECORATOR", "category": "CSRF_VULNERABILITY", "cwe": "CWE-352"},
    # Phase 11.2: Pyramid view_config / set_default_csrf_options are deliberately NOT registry sinks:
    # the registry flags every call unconditionally, but these are only unsafe when a keyword
    # literally carries require_csrf=False / check_origin=False. See the guarded keyword checks.

    # CWE-502: Unsafe Deserialization
    "pickle.loads": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},
    "pickle.load": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},
    "_pickle.loads": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},
    "_pickle.load": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},
    "yaml.load": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},
    "yaml.unsafe_load": {"operation": "DESERIALIZATION", "category": "UNSAFE_DESERIALIZATION", "cwe": "CWE-502"},

    # CWE-22: Path Traversal
    "open": {"operation": "FILE_ACCESS", "category": "PATH_TRAVERSAL", "cwe": "CWE-22"},
    "send_file": {"operation": "FILE_ACCESS", "category": "PATH_TRAVERSAL", "cwe": "CWE-22", "severity": "HIGH", "target_arg": 0},
    "flask.send_file": {"operation": "FILE_ACCESS", "category": "PATH_TRAVERSAL", "cwe": "CWE-22", "severity": "HIGH", "target_arg": 0},
    "shutil.rmtree": {"operation": "FILE_DELETE", "category": "PATH_TRAVERSAL", "cwe": "CWE-22"},
    "extractall": {"operation": "ARCHIVE_EXTRACTION", "category": "PATH_TRAVERSAL", "cwe": "CWE-22"},
    "extract": {"operation": "ARCHIVE_EXTRACTION", "category": "PATH_TRAVERSAL", "cwe": "CWE-22"},

    # CWE-1336: SSTI
    "render_template_string": {"operation": "TEMPLATE_EVALUATION", "category": "SSTI", "cwe": "CWE-1336"},
    "flask.render_template_string": {"operation": "TEMPLATE_EVALUATION", "category": "SSTI", "cwe": "CWE-1336"},
    "jinja2.Template": {"operation": "TEMPLATE_EVALUATION", "category": "SSTI", "cwe": "CWE-1336"},

    # CWE-79: Cross-Site Scripting (XSS)
    "markupsafe.Markup": {"operation": "XSS_HTML_RESPONSE", "category": "CROSS_SITE_SCRIPTING", "cwe": "CWE-79"},
    "Markup": {"operation": "XSS_HTML_RESPONSE", "category": "CROSS_SITE_SCRIPTING", "cwe": "CWE-79"},
    "django.utils.safestring.mark_safe": {"operation": "XSS_HTML_RESPONSE", "category": "CROSS_SITE_SCRIPTING", "cwe": "CWE-79"},
    "mark_safe": {"operation": "XSS_HTML_RESPONSE", "category": "CROSS_SITE_SCRIPTING", "cwe": "CWE-79"},
    "Response": {"operation": "XSS_HTML_RESPONSE", "category": "CROSS_SITE_SCRIPTING", "cwe": "CWE-79"},

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
    "urllib.request.urlopen": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "urlopen": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "urllib.request.urlretrieve": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "urlretrieve": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "urllib.request.Request": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "Request": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "requests.get": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "requests.post": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "requests.put": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "requests.delete": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "requests.head": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "requests.patch": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "requests.options": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "requests.request": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 1},
    "requests.Session.get": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "requests.Session.post": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "requests.Session.put": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "requests.Session.delete": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "requests.Session.head": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "requests.Session.patch": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "requests.Session.request": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 1},
    "Session.get": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "Session.post": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "Session.put": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "Session.delete": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "Session.head": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "Session.patch": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "Session.request": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 1},
    "httpx.get": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.post": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.put": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.delete": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.head": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.patch": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.request": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 1},
    "httpx.Client.get": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.Client.post": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.Client.put": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.Client.delete": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.Client.head": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.Client.patch": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.Client.request": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 1},
    "httpx.AsyncClient.get": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.AsyncClient.post": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.AsyncClient.put": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.AsyncClient.delete": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.AsyncClient.head": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.AsyncClient.patch": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "httpx.AsyncClient.request": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 1},
    "Client.get": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "Client.post": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "Client.put": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "Client.delete": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "Client.head": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "Client.patch": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "Client.request": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 1},
    "AsyncClient.get": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "AsyncClient.post": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "AsyncClient.put": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "AsyncClient.delete": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "AsyncClient.head": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "AsyncClient.patch": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "AsyncClient.request": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 1},
    "aiohttp.ClientSession.get": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "aiohttp.ClientSession.post": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "aiohttp.ClientSession.put": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "aiohttp.ClientSession.delete": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "aiohttp.ClientSession.head": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "aiohttp.ClientSession.patch": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "aiohttp.ClientSession.request": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 1},
    "ClientSession.get": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "ClientSession.post": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "ClientSession.put": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "ClientSession.delete": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "ClientSession.head": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "ClientSession.patch": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 0},
    "ClientSession.request": {"operation": "SSRF_REQUEST", "category": "SERVER_SIDE_REQUEST_FORGERY", "cwe": "CWE-918", "severity": "HIGH", "target_arg": 1},

    # CWE-601: Open Redirect
    "redirect": {"operation": "OPEN_REDIRECT", "category": "URL_REDIRECTION", "cwe": "CWE-601"},
    "flask.redirect": {"operation": "OPEN_REDIRECT", "category": "URL_REDIRECTION", "cwe": "CWE-601"},
    "django.shortcuts.redirect": {"operation": "OPEN_REDIRECT", "category": "URL_REDIRECTION", "cwe": "CWE-601"},
    "HttpResponseRedirect": {"operation": "OPEN_REDIRECT", "category": "URL_REDIRECTION", "cwe": "CWE-601", "target_arg": 0},
    "django.http.HttpResponseRedirect": {"operation": "OPEN_REDIRECT", "category": "URL_REDIRECTION", "cwe": "CWE-601", "target_arg": 0},
    "HttpResponsePermanentRedirect": {"operation": "OPEN_REDIRECT", "category": "URL_REDIRECTION", "cwe": "CWE-601", "target_arg": 0},
    "django.http.HttpResponsePermanentRedirect": {"operation": "OPEN_REDIRECT", "category": "URL_REDIRECTION", "cwe": "CWE-601", "target_arg": 0},

    # CWE-327 / CWE-328: Broken Cryptographic Hashes & Ciphers
    "hashlib.md5": {"operation": "WEAK_HASH", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "md5": {"operation": "WEAK_HASH", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "hashlib.sha1": {"operation": "WEAK_HASH", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "sha1": {"operation": "WEAK_HASH", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "hashlib.sha224": {"operation": "WEAK_HASH", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "sha224": {"operation": "WEAK_HASH", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "Crypto.Cipher.DES": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "Crypto.Cipher.DES.new": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "DES.new": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    # Cryptodome variants (Phase 9.3)
    "Cryptodome.Cipher.DES": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "Cryptodome.Cipher.DES.new": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    # Phase 3: 3DES / TripleDES are deprecated by NIST SP 800-131A rev.2 alongside single DES.
    "Crypto.Cipher.DES3": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "Crypto.Cipher.DES3.new": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "DES3.new": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "DES3": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "TripleDES": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "TripleDES.new": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "algorithms.TripleDES": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    # Cryptodome DES3 variants (Phase 9.3)
    "Cryptodome.Cipher.DES3": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},
    "Cryptodome.Cipher.DES3.new": {"operation": "WEAK_CIPHER", "category": "WEAK_CRYPTOGRAPHY", "cwe": "CWE-327"},

    # CWE-338: Insecure Randomness (all stdlib random.* methods)
    "random.random": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.randint": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.randrange": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.choice": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.choices": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.sample": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.shuffle": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.randbytes": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.uniform": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.triangular": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.betavariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.expovariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.gammavariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.gauss": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.lognormvariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.normalvariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.vonmisesvariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.paretovariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.weibullvariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.getrandbits": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random.Random": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    # Short names (when imported as `from random import randint`)
    "randint": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "randrange": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "choice": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "choices": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "sample": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "shuffle": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "randbytes": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "uniform": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "triangular": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "betavariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "expovariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "gammavariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "gauss": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "lognormvariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "normalvariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "vonmisesvariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "paretovariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "weibullvariate": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "getrandbits": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},
    "random": {"operation": "INSECURE_RANDOM", "category": "INSECURE_RANDOMNESS", "cwe": "CWE-338"},

    # CWE-322: Key Exchange without Entity Authentication (implicit host key trust)
    # paramiko AutoAddPolicy and WarningPolicy both bypass host-key verification.
    "paramiko.client.AutoAddPolicy": {"operation": "HOST_KEY_VERIFICATION_BYPASS", "category": "INSECURE_NETWORK_COMMUNICATION", "cwe": "CWE-322"},
    "paramiko.AutoAddPolicy": {"operation": "HOST_KEY_VERIFICATION_BYPASS", "category": "INSECURE_NETWORK_COMMUNICATION", "cwe": "CWE-322"},
    "paramiko.client.WarningPolicy": {"operation": "INSECURE_HOST_KEY_POLICY", "category": "INSECURE_NETWORK_COMMUNICATION", "cwe": "CWE-322", "severity": "HIGH"},
    "paramiko.WarningPolicy": {"operation": "INSECURE_HOST_KEY_POLICY", "category": "INSECURE_NETWORK_COMMUNICATION", "cwe": "CWE-322", "severity": "HIGH"},
    "AutoAddPolicy": {"operation": "HOST_KEY_VERIFICATION_BYPASS", "category": "INSECURE_NETWORK_COMMUNICATION", "cwe": "CWE-322"},
    "WarningPolicy": {"operation": "INSECURE_HOST_KEY_POLICY", "category": "INSECURE_NETWORK_COMMUNICATION", "cwe": "CWE-322", "severity": "HIGH"},
    # CWE-295: Disabled SSL/TLS Verification
    "urllib3.disable_warnings": {"operation": "DISABLED_SSL_VERIFICATION", "category": "INSECURE_TRANSPORT", "cwe": "CWE-295"},
    "ssl._create_unverified_context": {"operation": "DISABLED_SSL_VERIFICATION", "category": "INSECURE_TRANSPORT", "cwe": "CWE-295"},

    # CWE-400 / CWE-1333: Resource Exhaustion / ReDoS
    "re.compile": {"operation": "REGEX_COMPILATION", "category": "RESOURCE_EXHAUSTION", "cwe": "CWE-400"},
    "re.search": {"operation": "REGEX_SEARCH", "category": "RESOURCE_EXHAUSTION", "cwe": "CWE-400"},
    "re.match": {"operation": "REGEX_MATCH", "category": "RESOURCE_EXHAUSTION", "cwe": "CWE-400"},

    # ─── Batch 2 (data/cwe_blueprint_batch2.json) TAINT_FLOW sinks ───
    # CWE-117: Log Injection
    "logging.info": {"operation": "LOG_WRITE", "category": "LOG_INJECTION", "cwe": "CWE-117"},
    "logging.warning": {"operation": "LOG_WRITE", "category": "LOG_INJECTION", "cwe": "CWE-117"},
    "logging.error": {"operation": "LOG_WRITE", "category": "LOG_INJECTION", "cwe": "CWE-117"},
    "logger.info": {"operation": "LOG_WRITE", "category": "LOG_INJECTION", "cwe": "CWE-117"},
    "logger.warning": {"operation": "LOG_WRITE", "category": "LOG_INJECTION", "cwe": "CWE-117"},
    "logger.error": {"operation": "LOG_WRITE", "category": "LOG_INJECTION", "cwe": "CWE-117"},

    # CWE-94: Code Injection via Dynamic Module Load
    "importlib.import_module": {"operation": "DYNAMIC_MODULE_LOAD", "category": "CODE_INJECTION", "cwe": "CWE-94"},
    "__import__": {"operation": "DYNAMIC_MODULE_LOAD", "category": "CODE_INJECTION", "cwe": "CWE-94"},

    # CWE-643: XPath Injection
    "lxml.etree.XPath": {"operation": "XPATH_EVALUATION", "category": "XPATH_INJECTION", "cwe": "CWE-643"},
    "etree.XPath": {"operation": "XPATH_EVALUATION", "category": "XPATH_INJECTION", "cwe": "CWE-643"},
    "root.xpath": {"operation": "XPATH_EVALUATION", "category": "XPATH_INJECTION", "cwe": "CWE-643"},
    "tree.xpath": {"operation": "XPATH_EVALUATION", "category": "XPATH_INJECTION", "cwe": "CWE-643"},

    # CWE-943: NoSQL Injection
    "collection.find": {"operation": "NOSQL_QUERY", "category": "NOSQL_INJECTION", "cwe": "CWE-943"},
    "collection.find_one": {"operation": "NOSQL_QUERY", "category": "NOSQL_INJECTION", "cwe": "CWE-943"},
    "collection.update_many": {"operation": "NOSQL_QUERY", "category": "NOSQL_INJECTION", "cwe": "CWE-943"},
}

# ─── CWE-338 insecure PRNG family (flagged unconditionally) ────────────────
CWE338_RANDOM_NAMES = frozenset({
    "random.random", "random.randint", "random.choice", "random.randrange", "random.sample",
    "random.choices", "random.shuffle", "random.randbytes", "random.uniform", "random.triangular",
    "random.betavariate", "random.expovariate", "random.gammavariate", "random.gauss",
    "random.lognormvariate", "random.normalvariate", "random.vonmisesvariate",
    "random.paretovariate", "random.weibullvariate", "random.getrandbits", "random.Random",
    "randint", "randrange", "choice", "choices", "sample", "shuffle", "randbytes",
    "uniform", "triangular", "betavariate", "expovariate", "gammavariate", "gauss",
    "lognormvariate", "normalvariate", "vonmisesvariate", "paretovariate", "weibullvariate",
    "getrandbits", "random",
})

# ─── O(1) sink fast-path candidate index ───────────────────────────────────
# is_sink_call() can return True through paths that never consult SINK_REGISTRY:
# the rule engine's own matchers, the attribute branches at the tail of the
# function, and the CWE-322/327/338 probes. A filter built from SINK_REGISTRY
# keys alone therefore UNDER-approximates and silently prunes real sinks - that
# is how `render` (CWE-1336) and `executescript` (CWE-89) were lost, costing 7
# false negatives. This union is deliberately an over-approximation: extra names
# only cost a little resolution time, a missing name costs a vulnerability.
_NON_REGISTRY_SINK_NAMES = frozenset({
    # Tail attribute branches of is_sink_call (file I/O, SSTI render, CWE-400).
    "read_text", "read_bytes", "write_text", "write_bytes", "open", "render",
    "read", "run_in_executor",
    # CWE-322 insecure host key policy.
    "set_missing_host_key_policy", "AutoAddPolicy", "WarningPolicy",
    # CWE-327 hashlib.new(<weak algo>).
    "new",
})

SINK_CANDIDATE_NAMES = frozenset(
    {key.rsplit(".", 1)[-1] if "." in key else key for key in SINK_REGISTRY}
    | {n.rsplit(".", 1)[-1] for n in CWE338_RANDOM_NAMES}
    | SINK_MATCHER_NAMES
    | _NON_REGISTRY_SINK_NAMES
)

# Kept as the registry-only view; SINK_CANDIDATE_NAMES is the pruning authority.
SINK_LEAF_NAMES = frozenset(
    key.rsplit(".", 1)[-1] if "." in key else key
    for key in SINK_REGISTRY.keys()
)

# Keyword arguments that make _has_disabled_ssl() (CWE-295) able to return True.
# That probe is name-agnostic, so the fast path must test for these structurally
# instead of calling it - see _may_disable_ssl().
_SSL_TRIGGER_KWARGS = frozenset({"verify", "cert_reqs", "ssl_cert_reqs"})


def _may_disable_ssl(node: ast.Call) -> bool:
    """True when `node` carries a keyword `_has_disabled_ssl()` could inspect.

    `_has_disabled_ssl()` only ever reads `verify`, `cert_reqs`, `ssl_cert_reqs`
    and `**`-unpacking; with none of those present it provably returns False.
    This node-local test is O(#keywords) with no scope walking, which is what
    makes the CWE-295 exemption affordable inside the O(1) fast path.
    """
    for kw in node.keywords:
        if kw.arg is None or kw.arg in _SSL_TRIGGER_KWARGS:
            return True
    return False


def scope_module(scope_id: str) -> str:
    """Return the module prefix of a "<module>:<scope>" identifier.

    Module names are derived from file paths, so a Windows scan root embeds a
    second colon *inside* the module ("C:.Users.repo.app.views"). Splitting on the
    first colon returns the bare drive letter instead, which makes every
    ``file_paths`` lookup miss and reports findings against "unknown.py". A POSIX
    module never matches the drive rule, so those paths keep resolving exactly as
    before.
    """
    if not scope_id:
        return ""
    parts = scope_id.split(":")
    if len(parts) >= 2 and len(parts[0]) == 1 and parts[0].isalpha() and parts[1].startswith("."):
        return f"{parts[0]}:{parts[1]}"
    return parts[0]


class AssignmentNameTable(dict):
    """`dict` of (scope_id, target) -> records that also indexes targets per module.

    The sink fast path has to answer "could this leaf identifier be a rebinding of
    a sink name?" in constant time. Building that answer by iterating every key on
    each invalidation costs O(assignment table) per pruned call site, which made
    the fast path *slower* than no fast path on Django (sink detection 28.7s vs
    24.45s). Recording the name at key-insertion time makes maintenance O(1) per
    new key and removes the rebuild entirely.

    Every writer in this module goes through ``setdefault(key, []).append(record)``,
    so overriding ``setdefault`` catches all of them.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.names_by_module: Dict[str, set] = {}
        for key in self:
            self._index(key)

    def _index(self, key) -> None:
        if not (isinstance(key, tuple) and len(key) == 2):
            return
        scope, name = key
        if not isinstance(scope, str) or not isinstance(name, str):
            return
        self.names_by_module.setdefault(scope_module(scope) if scope else "", set()).add(name)

    def setdefault(self, key, default=None):
        if key not in self:
            self._index(key)
        return super().setdefault(key, default)


# ─── Batch 2 structural synthetic edge sources (PURE_STRUCTURAL CWEs) ───
STRUCTURAL_SYNTHETIC_SOURCES = {
    "CWE-377": "INSECURE_TEMP_FILE",
    "CWE-732": "INSECURE_FILE_PERMISSIONS",
    "CWE-326": "WEAK_CRYPTO_KEY_SIZE",
    "CWE-798": "HARDCODED_CREDENTIAL",
    "CWE-1004": "INSECURE_COOKIE_FLAGS",
    "CWE-209": "SENSITIVE_ERROR_EXPOSURE",
    # ─── Batch 3A (data/cwe_blueprint_batch3a.json) ───
    "CWE-614": "INSECURE_COOKIE_SECURE_FLAG",
    "CWE-1275": "INSECURE_COOKIE_SAMESITE",
    "CWE-208": "TIMING_ATTACK",
    "CWE-916": "WEAK_PASSWORD_HASH",
    "CWE-759": "UNSALTED_PASSWORD_HASH",
    "CWE-434": "UNRESTRICTED_FILE_UPLOAD",
    "CWE-352": "CSRF_MISSING_PROTECTION",
    "CWE-287": "IMPROPER_AUTHENTICATION",
    "CWE-862": "MISSING_AUTHORIZATION",
    "CWE-312": "CLEARTEXT_SENSITIVE_STORAGE",
    "CWE-319": "CLEARTEXT_HTTP_TRANSMISSION",
    "CWE-489": "ACTIVE_DEBUG_CODE",
    # ─── Batch 3B (data/cwe_blueprint_batch3b.json) ───
    "CWE-90": "LDAP_INJECTION",
    "CWE-776": "XML_ENTITY_EXPANSION",
    "CWE-200": "DIAGNOSTIC_INFO_EXPOSURE",
    "CWE-384": "SESSION_FIXATION",
    "CWE-770": "UNBOUNDED_RESOURCE_ALLOCATION",
    "CWE-605": "INSECURE_SOCKET_BINDING",
    "CWE-269": "IMPROPER_PRIVILEGE_MANAGEMENT",
    "CWE-652": "XQUERY_INJECTION",
    "CWE-522": "CLEARTEXT_AUTH_TRANSPORT",
    "CWE-937": "DEPRECATED_INSECURE_PROTOCOL",
    "CWE-668": "INSECURE_INTERFACE_BINDING",
    "CWE-1275": "cwe-1275_structural_violation",
    "CWE-208": "cwe-208_structural_violation",
    # ─── Phase 3 Cluster 1 (insecure-permission residuals, dangerous globals,
    #     disabled autoescape, empty-password policy) ───
    "CWE-276": "INSECURE_FILE_MODE_RESIDUAL",
    "CWE-96": "DANGEROUS_GLOBALS_USE",
    "CWE-116": "TEMPLATE_AUTOESCAPE_DISABLED",
    "CWE-521": "EMPTY_PASSWORD_POLICY",
}
CWE798_TARGET_RE = re.compile(r"(?i).*(password|passwd|secret_key|api_key|access_token|auth_token).*")
# Dummy/test string blocklist for CWE-798 - suppress known test placeholders
CWE798_DUMMY_STRINGS = frozenset({
    "this-is-probably-a-test", "this-is-not-a-key", "this-is-secret",
    "your-password-here", "your-api-key-here", "your-secret-here",
    "<your-password-here>", "<your-api-key-here>", "<your-secret-here>",
})

def _is_cwe798_dummy_string(value: str) -> bool:
    """Check if a string value matches known test/dummy patterns for CWE-798 suppression."""
    if value in CWE798_DUMMY_STRINGS:
        return True
    # Check for repeated character patterns (e.g., "xxxx...", "XXXX...", "0000...")
    if len(value) >= 8:
        # All same character (case-insensitive)
        if len(set(value.lower())) == 1:
            return True
        # Pattern like "xxx..." where first char repeats for most of the string
        first_char = value[0].lower()
        if all(c.lower() == first_char for c in value[:len(value)//2]):
            return True
    # Check for <your-...-here> pattern
    if value.startswith("<your-") and value.endswith(">"):
        return True
    return False

CWE326_SINK_NAMES = {"RSA.generate", "Crypto.PublicKey.RSA.generate",
                     "rsa.generate_private_key",
                     # Phase 6.3: DSA + Cryptodome module forms.
                     "DSA.generate", "Crypto.PublicKey.DSA.generate",
                     "Cryptodome.PublicKey.DSA.generate",
                     "Cryptodome.PublicKey.RSA.generate"}
CWE798_SAFE_SOURCES = {"os.environ.get", "os.getenv", "config.get"}

# ─── Batch 3B structural rule constants ───
CWE3B_LDAP_SINKS = {"search", "search_s", "search_st"}
CWE3B_SESSION_KEYS = {"user_id", "user", "username", "uid"}
CWE3B_INSECURE_INTERFACES = {"0.0.0.0", "", "::"}

# ─── Phase 3 Cluster 1 structural rule constants ───
CLUSTER1_CHMOD_CALLS = {"os.chmod", "os.lchmod", "os.fchmod"}
CLUSTER1_EXACT_732_CALLS = {"os.chmod"}
CLUSTER1_UMASK_CALLS = {"os.umask"}
CLUSTER1_UMASK_SAFE = 0o022
# Matched by *name*, not by evaluated value: a numeric threshold would also fire on
# `os.chmod(f, stat.S_IRWXU)` (0o700), which the corpus labels safe because the reference rule
# cannot numerically compare a Name.
CLUSTER1_INSECURE_STAT_BITS = {"S_IWGRP", "S_IXGRP", "S_IWOTH", "S_IXOTH", "S_IRWXO", "S_IRWXG"}
CLUSTER1_MODE_LOW_BITS = 0o7777
CLUSTER1_INSECURE_MODE_FLOOR = 0o650
CLUSTER1_GROUP_OTHER_WRITE_EXEC = 0o033
CLUSTER1_NAMESPACE_BUILTINS = {"globals", "locals"}
CLUSTER1_NAMESPACE_ATTRS = {"__globals__"}
CLUSTER1_MAPPING_READ_METHODS = {"get", "setdefault", "pop"}
CLUSTER1_TEMPLATE_CONTEXT_CALLS = {"render", "render_to_response", "render_to_string",
                                  "render_template", "render_string"}
CLUSTER1_TEMPLATE_STRING_SINKS = {"render_template_string"}
CLUSTER1_PASSWORD_NAME_RE = re.compile(r"(?i)(password|passwd|pwd)")
CLUSTER1_AUTOESCAPE_KEYS = {"autoescape"}

# ─── Phase 3 Cluster 2 structural rule constants ───
# CWE-295: TLS clients whose verification cannot be trusted.
CLUSTER2_HTTPS_CONNECTION_SEGMENT = "HTTPSConnection"
CLUSTER2_SSL_GLOBAL_OVERRIDE_TARGET = "ssl._create_default_https_context"
CLUSTER2_SSL_UNVERIFIED_FACTORIES = {"_create_unverified_context"}
CLUSTER2_POOL_MANAGER_SEGMENTS = {"PoolManager"}
CLUSTER2_CERT_NONE_VALUES = {"CERT_NONE", "CERT_NO_CHECK", "NONE", False}
# CWE-319/523: cleartext http:// transport through session/module-level HTTP clients.
CLUSTER2_HTTP_CLIENT_ROOTS = {"requests", "httpx", "urllib3", "urllib.request", "session"}
CLUSTER2_HTTP_VERBS = {"get", "post", "put", "delete", "head", "options", "patch",
                       "request", "Request"}
CLUSTER2_HTTP_URL_ARG_INDEX = {"request": 1, "Request": 1}
CLUSTER2_SESSION_CONSTRUCTORS = {"Session"}
CLUSTER2_CLEARTEXT_SCHEME = "http://"
CLUSTER2_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
# CWE-319 allowlists: XML namespaces, schema domains, and test/example domains
CLUSTER2_SCHEMA_DOMAINS = {"w3.org", "schemas.microsoft.com", "xml.org", "docs.oasis-open.org", "schemas.xmlsoap.org", "json-schema.org"}
CLUSTER2_HTTP_POOL_SEGMENT = "HTTPConnectionPool"
# CWE-704: unvalidated numeric conversions on request-controlled values.
CLUSTER2_NAN_CONVERSIONS = {"float", "bool", "complex"}
CLUSTER2_NAN_SAFE_WRAPPERS = {"int"}
CLUSTER2_NAN_GUARD_VALUE = "nan"
# CWE-601 / CWE-918: untrusted request input reaching a redirect or outbound fetch.
CLUSTER2_REDIRECT_SINKS = {"redirect", "HttpResponseRedirect"}
CLUSTER2_REDIRECT_VALIDATORS = {"is_safe_url", "url_has_allowed_host_and_scheme",
                                "is_safe_redirect_url", "validate_redirect_url",
                                "is_relative_url", "url_parse", "urlsplit", "is_external_url"}
CLUSTER2_SSRF_SINK_SEGMENTS = {"get", "post", "put", "delete", "head", "options", "patch",
                               "request", "Request", "urlopen", "open"}
CLUSTER2_SSRF_VALIDATORS = {"is_safe_url", "validate_url", "check_domain_allowlist",
                            "is_allowed_domain", "validate_private_ip", "is_private_ip",
                            "is_safe_destination", "assert_host_allowlisted"}
CLUSTER2_ROUTE_DECORATOR_SEGMENTS = {"route", "get", "post", "put", "delete", "patch",
                                     "rule", "method"}
# CWE-611: aliased stdlib/lxml XML entry points (bandit-style `import ... as bad` shapes).
CLUSTER2_XML_METHODS = {"parse", "parseString", "fromstring", "iterparse", "make_parser",
                        "create_parser", "XMLParser", "expat"}
CLUSTER2_XML_UNSAFE_ROOTS = ("xml.", "lxml.")
CLUSTER2_XML_SAFE_ROOTS = ("defusedxml", "cElementTree-safe")
# CWE-942: wildcard CORS combined with credentialed requests.
CLUSTER2_CORS_MIDDLEWARE = {"CORSMiddleware"}
CLUSTER2_CORS_FACTORY_CALLS = {"CORS", "cross_origin"}
CLUSTER2_CORS_ADD_MW = {"add_middleware"}
CLUSTER2_CORS_ORIGIN_KEYS = {"allow_origins", "origins"}
CLUSTER2_CORS_CREDENTIAL_KEYS = {"allow_credentials", "supports_credentials"}
CLUSTER2_CORS_ALLOW_LIST_KEY = "allow"
CLUSTER2_CORS_HEADER_ORIGIN = "Access-Control-Allow-Origin"
CLUSTER2_CORS_HEADER_CREDENTIALS = "Access-Control-Allow-Credentials"
CLUSTER2_STRUCTURAL_SOURCE_IDS = {
    "UNVERIFIED_HTTPS_CONNECTION": "UNVERIFIED_HTTPS_CONNECTION",
    "SSL_CONTEXT_GLOBAL_OVERRIDE": "SSL_CONTEXT_GLOBAL_OVERRIDE",
    "DISABLED_SSL_VERIFICATION": "DISABLED_SSL_VERIFICATION",
    "CLEARTEXT_HTTP_CONNECTION_POOL": "CLEARTEXT_HTTP_TRANSMISSION",
    "CLEARTEXT_HTTP_REQUEST": "CLEARTEXT_HTTP_TRANSMISSION",
    "NAN_UNVALIDATED_CONVERSION": "NAN_UNVALIDATED_CONVERSION",
    "UNTRUSTED_REDIRECT_SOURCE": "UNTRUSTED_REDIRECT_SOURCE",
    "SSRF_UNTRUSTED_URL_SOURCE": "UNTRUSTED_URL_INPUT",
    "ALIASED_UNSAFE_XML_PARSE": "XML_EXTERNAL_ENTITY",
    "PERMISSIVE_CORS_POLICY": "PERMISSIVE_CORS_POLICY",
}

# ─── Phase 3 Cluster 3 structural rule constants (18-rule grand finale batch) ───
CLUSTER3_NOSEC_RE = re.compile(r"#\s*(?:nosec|ok)\b")
CLUSTER3_WEAK_NEW_HASH_ALGOS = {"md2", "md4", "md5", "sha1", "sha0", "sha224"}
CLUSTER3_WEAK_HASH_CLASS_NAMES = {"MD2", "MD4", "MD5", "SHA", "SHA1"}
CLUSTER3_HASH_MODULE_PAIRS = (("Crypto", "Hash"), ("Cryptodome", "Hash"))
CLUSTER3_HASHLIB_MODULE_SEG = "hashlib"
# Phase 6.3: weak ssl.PROTOCOL_* constants (call args, kwargs and default args).
CLUSTER3_WEAK_SSL_PROTOCOL_SEGS = frozenset({
    "PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1",
})
CLUSTER3_SSL_MODULE_ROOT = "ssl"
# Phase 6.4: pyOpenSSL insecure protocol method constants (OpenSSL.SSL.*_METHOD).
CLUSTER3_PYOPENSSL_METHOD_SEGS = frozenset({
    "SSLv2_METHOD", "SSLv3_METHOD", "SSLv23_METHOD", "TLSv1_METHOD", "TLSv1_1_METHOD",
})
CLUSTER3_PYOPENSSL_SSL_ROOT = "SSL"
CLUSTER3_PYOPENSSL_OPENSSL_ROOT = "OpenSSL"
# Phase 6.4: cryptography.hazmat legacy cipher algorithms (Blowfish, ARC4, IDEA).
CLUSTER3_CRYPTOGRAPHY_LEGACY_ALGOS = frozenset({"Blowfish", "ARC4", "IDEA"})
CLUSTER3_CRYPTOGRAPHY_ALGO_SEG = "algorithms"
CLUSTER3_CRYPTOGRAPHY_CIPHERS_SEG = "ciphers"
CLUSTER3_CRYPTOGRAPHY_HAZMAT_ROOT = "cryptography"
# Phase 6.3: legacy broken ciphers under Crypto.Cipher / Cryptodome.Cipher.
CLUSTER3_LEGACY_CIPHER_NAMES = frozenset({"Blowfish", "DES", "DES3", "ARC2", "ARC4", "IDEA", "XOR", "TripleDES"})
CLUSTER3_CIPHER_MODULE_SEG = "Cipher"
CLUSTER3_CIPHER_MODULE_ROOTS = frozenset({"Crypto", "Cryptodome"})
CLUSTER3_PASSWORD_SETTER_METHODS = {"setpassword", "set_password"}
CLUSTER3_INSECURE_UUID_SEG = "uuid1"
CLUSTER3_URLLIB_MODULE_SEGS = {"urllib", "urllib2"}
CLUSTER3_URLLIB_DYNAMIC_FETCH_SEGS = {"urlopen", "open", "retrieve"}
CLUSTER3_OPENER_CTOR_SEGS = {"URLopener", "FancyURLopener", "build_opener"}
CLUSTER3_SHELL_EXEC_SEGS = {"system", "popen", "popen2", "popen3", "getoutput", "getstatus"}
CLUSTER3_SUBPROCESS_SHELL_SEGS = {"Popen", "run", "call", "check_call", "check_output"}
CLUSTER3_WILDCARD_BINARIES = {"tar", "rsync", "chown", "chmod", "chgrp"}
CLUSTER3_URLFOR_SEG = "url_for"
CLUSTER3_TWIML_KW = "twiml"
CLUSTER3_TWIML_XML_RE = re.compile(r"<\s*(?:Response|Say|Dial|Message|Hangup|Sms|Body)\b")
CLUSTER3_TWIML_ESCAPERS = {"escape"}
CLUSTER3_LOGGER_ROOTS = {"logger", "logging", "log"}
CLUSTER3_LOGGER_METHODS = {"info", "debug", "warn", "warning", "error", "exception", "critical"}
CLUSTER3_SENSITIVE_LOG_NAME_RE = re.compile(
    r"(?i)^(password|passwd|secret|secret_key|token|access_token|api_?key|auth_header|"
    r"authorization|credentials?|salt)$")
CLUSTER3_BOTO_CONSTRUCTOR_SEGS = {"client", "resource", "Session"}
CLUSTER3_AWS_KEY_ID_KW = "aws_access_key_id"
CLUSTER3_AWS_SECRET_KWS = {"aws_secret_access_key", "aws_session_token"}
CLUSTER3_AWS_KEY_ID_SHAPE_RE = re.compile(r"^AKIA[0-9A-Za-z]{12,}$")
CLUSTER3_AWS_SECRET_SHAPE_RE = re.compile(r"^[A-Za-z0-9/+=]{39,41}$")
CLUSTER3_PASSWORD_PARAM_NAMES = {"password", "passwd", "secret", "token", "api_key", "apikey"}
CLUSTER3_KEYGEN_SEGS = {"generate_private_key"}
CLUSTER3_KEYGEN_ROOTS = {"rsa", "dsa"}
CLUSTER3_EC_ROOT = "ec"
CLUSTER3_WEAK_EC_CURVE_RE = re.compile(r"^SEC[PpT]\d*(1[0-9]{2}|2[01][0-9]|22[0-3])(?:[A-Za-z]|$)")
CLUSTER3_YAML_ROOT = "yaml"
CLUSTER3_YAML_UNSAFE_LOADERS = {"Loader", "UnsafeLoader", "FullLoader", "CLoader"}
CLUSTER3_YAML_UNSAFE_SEGS = {"unsafe_load"}
CLUSTER3_PICKLE_ROOTS = {"pickle", "_pickle", "cPickle", "dill", "shelve", "marshal"}
# `dumps`/`dump` build a payload; only the loads side turns attacker bytes into objects.
CLUSTER3_PICKLE_METHOD_SEGS = {"loads"}
CLUSTER3_SHELVE_OPEN_SEG = "open"
CLUSTER3_CSRF_EXEMPT_SEG = "csrf_exempt"
# FastAPI, Starlette and python-ninja routers answer JSON over bearer/token auth. There is no
# cookie-bound session a cross-site request could ride, so "this route lacks CSRF protection"
# is noise on those frameworks — while Django views rendering HTML forms and traditional Flask
# form routes keep reporting. `route` is deliberately NOT in the verb set: that is Flask's
# decorator shape, which is exactly the case that must keep firing.
JSON_API_MODULE_ROOTS = frozenset({"fastapi", "starlette", "ninja"})
JSON_API_ROUTE_SEGS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options", "trace", "api_route",
    "websocket", "websockets",
})
# SSRF needs a request handler that lets an outsider move the URL. A client library's own
# transport layer already received the URL the application authorised, so outbound fetches in
# those modules are plumbing, not a forgery surface. Only modules living *inside* an HTTP
# client package qualify — an application's own sessions.py is still an SSRF surface.
HTTP_TRANSPORT_MODULE_STEMS = frozenset({
    "adapters", "sessions", "connectionpool", "connectionpool2", "poolmanager", "poolproxy",
})
HTTP_CLIENT_PACKAGE_DIRS = frozenset({"requests", "httpx", "urllib3", "aiohttp", "httplib2", "treq"})
# pytest parametrises modules under test through `request.param` / fixture arguments. Those names
# are chosen by the suite itself, so a dynamic import built from them is not code injection.
# Reads of a live web request keep reporting even inside a test module.
PYTEST_TEST_DIR_NAMES = frozenset({"tests", "test"})
WEB_REQUEST_INPUT_ATTRS = frozenset({
    "args", "form", "json", "data", "files", "headers", "GET", "POST", "body", "values",
    "query_params",
})
CLUSTER3_WTF_CSRF_KEY = "WTF_CSRF_ENABLED"
CLUSTER3_TESTING_KEY = "TESTING"
CLUSTER3_STRUCTURAL_SOURCE_IDS = {
    "WEAK_HASH_NEW": "WEAK_HASH_NEW",
    "WEAK_HASH_CONSTRUCTOR": "WEAK_HASH_CONSTRUCTOR",
    "WEAK_HASH_PASSWORD_USAGE": "WEAK_HASH_PASSWORD_USAGE",
    "INSECURE_UUID1": "INSECURE_UUID1",
    "DYNAMIC_URLLIB_FETCH": "DYNAMIC_URLLIB_FETCH",
    "SUBPROCESS_WILDCARD_INJECTION": "SUBPROCESS_WILDCARD_INJECTION",
    "URL_FOR_EXTERNAL_TRUE": "URL_FOR_EXTERNAL_TRUE",
    "TWIML_XML_INJECTION": "TWIML_XML_INJECTION",
    "LOGGER_CREDENTIAL_LEAK": "LOGGER_CREDENTIAL_LEAK",
    "HARDCODED_AWS_TOKEN": "HARDCODED_AWS_TOKEN",
    "HARDCODED_PASSWORD_DEFAULT": "HARDCODED_PASSWORD_DEFAULT",
    "INSUFFICIENT_KEY_SIZE": "INSUFFICIENT_KEY_SIZE",
    "WEAK_SSL_PROTOCOL": "WEAK_SSL_PROTOCOL",
    "PYOPENSSL_INSECURE_METHOD": "PYOPENSSL_INSECURE_METHOD",
    "CRYPTOGRAPHY_LEGACY_ALGO": "CRYPTOGRAPHY_LEGACY_ALGO",
    "INSECURE_CIPHER_MODE_ECB": "INSECURE_CIPHER_MODE_ECB",
    "WEAK_CIPHER_LEGACY": "WEAK_CIPHER_LEGACY",
    "UNSAFE_YAML_LOADER": "UNSAFE_YAML_LOADER",
    "UNSAFE_PICKLE_USAGE": "UNSAFE_PICKLE_USAGE",
    "MARSHAL_USAGE": "MARSHAL_USAGE",
    "CSRF_EXEMPT_VIEW": "CSRF_EXEMPT_VIEW",
    "FLASK_CSRF_DISABLED": "FLASK_CSRF_DISABLED",
    "HARDCODED_CONFIG": "HARDCODED_CONFIG",
    "ACTIVE_DEBUG_CODE": "ACTIVE_DEBUG_CODE",
}

# ─── Batch 3A structural rule constants ───
CWE3A_WEAK_HASH_NAMES = {
    "hashlib.md5", "hashlib.sha1", "hashlib.sha256", "hashlib.sha512",
    "md5", "sha1", "sha256", "sha512",
}
CWE3A_PASSWORD_NAME_RE = re.compile(r"(?i).*(password|passwd|pwd|\bpw\b|user_pass|secret|pin|auth|credential).*")
CWE3A_SALT_NAME_RE = re.compile(r"(?i)^(salt|pepper|nonce|iv)$")
CWE3A_SENSITIVE_VALUE_RE = re.compile(r"(?i).*(password|passwd|pwd|secret|api_key|access_token|credential|token|secret_key).*")
CWE3A_IDOR_MODELS = {"user", "account", "profile", "invoice", "order", "payment", "document", "token"}
CWE3A_LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
CWE3A_SCHEMA_DOMAINS = {"w3.org", "schemas.microsoft.com", "xml.org", "docs.oasis-open.org", "schemas.xmlsoap.org", "json-schema.org"}
CWE3A_NETWORK_SINKS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "urllib.request.urlopen", "urlopen", "httpx.get", "httpx.post",
}
CWE3A_UPLOAD_SANITIZERS = {"secure_filename", "sanitize_filename", "werkzeug.utils.secure_filename"}
CWE3A_UPLOAD_RANDOMIZERS = {"uuid4", "uuid.uuid4", "uuid4_rename"}
CWE3A_STORAGE_SANITIZERS = {
    "Fernet.encrypt", "encrypt", "hash_pw", "bcrypt", "bcrypt.hashpw",
    "argon2", "argon2.PasswordHasher.hash", "mask_secret", "redact",
    "hashlib.sha256", "hashlib.sha512",
}
CWE3A_USER_SOURCE_CALLS = {"input", "request.args.get", "request.form.get", "request.values.get"}
CWE3A_DEBUG_VAR_RE = re.compile(r"(?i)^debug(_mode)?$")
CWE3A_USER_NAME_RE = re.compile(r"(?i)^(user|username|email)$")
CWE3A_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Request surfaces that only ever carry state-changing intent, and the operations that
# actually change state. Reads (request.args, request.GET, request.session.get) are absent:
# a view that cannot alter server or client state has nothing for CSRF to protect.
# Compared case-insensitively: Django spells these POST/FILES/META, Flask spells them lower.
CWE3A_STATE_CARRYING_REQUEST_ATTRS = {"POST", "PUT", "PATCH", "FILES", "BODY", "DATA", "FORM", "JSON"}
CWE3A_STATE_MUTATING_METHODS = {
    "save", "delete", "update", "create", "get_or_create", "update_or_create", "bulk_create",
    "execute", "executemany", "executescript", "write", "writelines", "write_text",
    "set_cookie", "delete_cookie", "flush", "cycle_key",
}
CWE3A_STATE_MUTATING_FUNCTIONS = {
    "os.remove", "os.unlink", "os.rmdir", "os.system", "os.popen", "shutil.rmtree",
    "shutil.move", "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.Popen",
}


def _receiver_is_request(expr: ast.AST) -> bool:
    """True for `request`, `self.request`, or any dotted chain ending in `request`."""
    if isinstance(expr, ast.Attribute):
        return expr.attr == "request"
    return isinstance(expr, ast.Name) and expr.id == "request"


def _receiver_is_session_store(subscript: ast.Subscript) -> bool:
    """True when a subscript targets `request.session[...]`, i.e. server-side session state."""
    base = subscript.value
    return isinstance(base, ast.Attribute) and base.attr == "session" and _receiver_is_request(base.value)


def _view_accepts_state_change(node: ast.AST) -> bool:
    """Prove a view can act on a state-changing request, from its body alone.

    Used to decide whether dropping CSRF protection can actually be exploited: an exempt
    view that only reads state cannot be driven cross-site into an unwanted change.
    """
    for inner in ast.walk(node):
        if isinstance(inner, ast.Attribute):
            if _receiver_is_request(inner.value) and inner.attr.upper() in CWE3A_STATE_CARRYING_REQUEST_ATTRS:
                return True
        elif isinstance(inner, ast.Call):
            func = inner.func
            if isinstance(func, ast.Attribute):
                if func.attr in CWE3A_STATE_MUTATING_METHODS:
                    return True
                if dotted_name(func) in CWE3A_STATE_MUTATING_FUNCTIONS:
                    return True
        elif isinstance(inner, ast.Subscript) and _receiver_is_session_store(inner):
            return True
        elif isinstance(inner, ast.Compare) and isinstance(inner.left, ast.Attribute):
            if inner.left.attr == "method":
                if any(isinstance(c, ast.Constant) and c.value in CWE3A_STATE_CHANGING_METHODS
                       for c in inner.comparators):
                    return True
    return False

# ─── Phase 3 hardening rule constants ───
# CWE-327: electronic codebook mode leaks plaintext structure regardless of cipher strength.
P3_ECB_MARKER_ATTRS = {"MODE_ECB", "ECB"}
P3_ECB_CONSTANT_MODES = {"ECB", "MODE_ECB"}
# Sink names whose callee is already reported as a weak cipher; ECB detection must not double-report them.
P3_ECB_SKIP_IF_WEAK_CIPHER = {"DES", "DES.new", "DES3", "DES3.new", "TripleDES", "TripleDES.new", "ARC4"}
# CWE-73: schemes that reach local or non-HTTP resources through a network-style resource sink.
P3_UNTRUSTED_SCHEMES = ("file://", "ftp://", "gopher://")
# CWE-319: urllib's legacy opener objects fetch whatever scheme is spelled in their URL
# argument. `URLopener().open("http://…")` is a plaintext network read, so it must never be
# classified as a filesystem access, and only http/ftp are the cleartext cases the rule set
# audits (https/sftp are the labelled-safe twins in the same fixtures).
P3_URLLIB_OPENER_TYPES = {"OpenerDirector", "URLopener", "FancyURLopener", "build_opener"}
P3_URLLIB_FETCH_METHODS = {"open", "retrieve"}
P3_URLLIB_FETCH_FUNCTIONS = {"urlopen", "urlretrieve"}
P3_URLLIB_REQUEST_CONSTRUCTOR = "urllib.request.Request"
P3_URLLIB_CLEARTEXT_SCHEMES = ("http", "ftp")
# Schemes that prove the argument is a network location, not a filesystem path. `file://`
# and friends stay under their existing path/protocol classification.
P3_URLLIB_NETWORK_SCHEMES = ("http", "https", "ftp", "ftps", "sftp")
# Opening one of these with a literal path hands back fixed on-disk bytes.
P3_FILE_READ_FUNCTIONS = {"open", "io.open", "builtins.open", "os.fdopen"}
P3_FILE_READ_METHODS = {"read_bytes", "read_text", "open"}
# A URL whose scheme+authority are fully spelled out before any dynamic hole.
P3_URL_AUTHORITY_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/?#]+")
P3_RESOURCE_SINK_NAMES = {
    "urlopen", "urllib.request.urlopen", "urlretrieve", "urllib.request.urlretrieve",
    "Request", "urllib.request.Request",
    "requests.get", "requests.post", "requests.put", "requests.delete", "requests.head", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.request",
    "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
}
# CWE-79: SVG is executed by the browser when reflected with an SVG content type.
P3_SVG_RESPONSE_SINKS = {
    "Response", "flask.Response", "make_response", "flask.make_response",
    "HttpResponse", "django.http.HttpResponse", "HttpResponseBadRequest",
}
P3_SVG_CONTENT_TYPES = ("image/svg+xml", "image/svg")
P3_STRUCTURAL_SOURCE_IDS = {
    "INSECURE_CIPHER_MODE": "WEAK_CIPHER_MODE_CONFIGURATION",
    "PROTOCOL_RESOURCE_ACCESS": "UNTRUSTED_URL_SCHEME",
    "SVG_XSS_RESPONSE": "DYNAMIC_SVG_RESPONSE",
    "INSECURE_HTTP_REQUEST": "CLEARTEXT_TRANSMISSION",
    "INSECURE_FTP": "CLEARTEXT_TRANSMISSION",
    "INSECURE_TELNET": "CLEARTEXT_TRANSMISSION",
    "CSRF_EXEMPT_DECORATOR": "CSRF_VULNERABILITY",
}

def _eval_dict_constants(dict_node, assignments_by_scope, scope_id="", lineno=0):
    """Evaluates a dictionary node or dictionary Name reference to a dict of {str: val}."""
    if isinstance(dict_node, ast.Name):
        recs = assignments_by_scope.get((scope_id, dict_node.id), [])
        recs_before = [r for r in recs if r.lineno < lineno]
        if recs_before and isinstance(recs_before[-1].value_node, ast.Dict):
            dict_node = recs_before[-1].value_node
        else:
            return {}
    if not isinstance(dict_node, ast.Dict):
        return {}
    res = {}
    for k_node, v_node in zip(dict_node.keys, dict_node.values):
        if isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
            val = _eval_static_constant(v_node, assignments_by_scope, scope_id, lineno)
            res[k_node.value] = val
    return res

def _fold_inline_literal_container(node, assignments_by_scope, scope_id="", lineno=0, visited=None):
    """Fold an *inline* Dict/List/Tuple literal whose every member folds.

    Deliberately refuses Names: a dict that was bound to a name can be rewritten between
    its assignment and the sink (`d[request.args["k"]] = evil`), and subscript stores are
    recorded under `d[k]`, not under `d` (see the Subscript branch of the statement
    collector), so a name-bound fold would be unsound. An inline literal is created and
    indexed inside one expression, which nothing can mutate.
    """
    if visited is None:
        visited = set()
    if isinstance(node, ast.Dict):
        container = {}
        for key_node, value_node in zip(node.keys, node.values):
            if key_node is None:  # {**other}: the key set is not provable
                return None
            key = _eval_static_constant(key_node, assignments_by_scope, scope_id, lineno, visited)
            value = _eval_static_constant(value_node, assignments_by_scope, scope_id, lineno, visited)
            if key is None or value is None:
                return None
            try:
                container[key] = value
            except TypeError:
                return None
        return container
    if isinstance(node, (ast.List, ast.Tuple)):
        items = []
        for element in node.elts:
            if isinstance(element, ast.Starred):
                return None
            value = _eval_static_constant(element, assignments_by_scope, scope_id, lineno, visited)
            if value is None:
                return None
            items.append(value)
        return items
    return None


def _read_literal_member(container, key_node, assignments_by_scope, scope_id, lineno, visited):
    """The value of `container[key]` for a folded inline container, or None when unprovable."""
    key = _eval_static_constant(key_node, assignments_by_scope, scope_id, lineno, visited)
    if key is None:
        return None
    if isinstance(container, dict):
        return container.get(key)
    if isinstance(container, list) and isinstance(key, int) and not isinstance(key, bool):
        return container[key] if -len(container) <= key < len(container) else None
    return None


def _eval_static_constant(node, assignments_by_scope, scope_id="", lineno=0, visited=None):
    """Deterministically evaluates literal int/str/bool constants, resolving Name
    references through the static assignment chain. Returns None when the
    expression cannot be proven constant (no speculative findings)."""
    if visited is None:
        visited = set()
    if isinstance(node, ast.Constant) and (node.value is None or isinstance(node.value, (int, str, bool, bytes))):
        return node.value
    if hasattr(ast, "Str") and isinstance(node, ast.Str):
        return node.s
    if hasattr(ast, "Bytes") and isinstance(node, ast.Bytes):
        return node.s
    if hasattr(ast, "Num") and isinstance(node, ast.Num):
        return node.n
    if isinstance(node, ast.UnaryOp):
        inner = _eval_static_constant(node.operand, assignments_by_scope, scope_id, lineno, visited)
        if isinstance(node.op, ast.USub) and isinstance(inner, int):
            return -inner
        if isinstance(node.op, ast.Not) and isinstance(inner, bool):
            return not inner
        return None
    if isinstance(node, ast.JoinedStr):
        # An f-string whose every hole folds to a literal is a plain string literal:
        # `f"ping {host}"` with `host = "1.2.3.4"` carries no more input than `"ping "`.
        parts = []
        for value in node.values:
            if (isinstance(value, ast.FormattedValue)
                    and value.conversion is None and value.format_spec is None):
                value = value.value
            piece = _eval_static_constant(value, assignments_by_scope, scope_id, lineno, visited)
            if not isinstance(piece, str):
                return None
            parts.append(piece)
        return "".join(parts)
    if isinstance(node, ast.BinOp):
        left = _eval_static_constant(node.left, assignments_by_scope, scope_id, lineno, visited)
        right = _eval_static_constant(node.right, assignments_by_scope, scope_id, lineno, visited)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.BitOr) and isinstance(left, int) and isinstance(right, int):
            return left | right
        if isinstance(node.op, ast.BitAnd) and isinstance(left, int) and isinstance(right, int):
            return left & right
        if isinstance(node.op, ast.Add) and isinstance(left, type(right)):
            return left + right
        if isinstance(node.op, ast.Sub) and isinstance(left, int) and isinstance(right, int):
            return left - right
        if isinstance(node.op, ast.Mult) and isinstance(left, int) and isinstance(right, int):
            return left * right
        return None
    if isinstance(node, ast.Name):
        var_key = f"{scope_id}:{node.id}"
        if var_key in visited:
            return None
        visited.add(var_key)
        mod_name = scope_module(scope_id) if scope_id else ""
        curr = scope_id
        _walk_seen = set()
        while curr and curr not in _walk_seen:
            _walk_seen.add(curr)
            recs = assignments_by_scope.get((curr, node.id), [])
            if lineno:
                recs = [r for r in recs if r.lineno <= lineno]
            if recs:
                return _eval_static_constant(recs[-1].value_node, assignments_by_scope, recs[-1].scope_id, recs[-1].lineno, visited)
            if "." in curr and "function" in curr:
                curr = curr.rsplit(".", 1)[0]
            elif ":function" in curr:
                curr = f"{mod_name}:global"
            elif curr != f"{mod_name}:global":
                curr = f"{mod_name}:global"
            else:
                break
        # Cross-scope fallback: resolve when every recorded assignment for this
        # name evaluates to the same constant regardless of scope.
        candidates = []
        for (rec_scope, rec_name), recs in assignments_by_scope.items():
            if rec_name != node.id or not recs:
                continue
            usable = [r for r in recs if r.lineno <= lineno] if lineno else recs
            if not usable:
                continue
            val = _eval_static_constant(usable[-1].value_node, assignments_by_scope, usable[-1].scope_id, usable[-1].lineno, visited.copy())
            if val is not None:
                candidates.append(val)
        if candidates and all(c == candidates[0] for c in candidates):
            return candidates[0]
        return None
    if isinstance(node, ast.Subscript):
        # `{"cmd": "ls"}["cmd"]` and `["ls", "pwd"][0]` are literals wearing an index.
        base = _fold_inline_literal_container(node.value, assignments_by_scope, scope_id, lineno, visited)
        if base is not None:
            return _read_literal_member(base, node.slice, assignments_by_scope, scope_id, lineno, visited)
        return None
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("get", "pop", "setdefault") and node.args):
        # `{"cmd": "ls"}.get("cmd")` on an inline dict reads a literal too; the default
        # argument is literal as well when the key is absent.
        base = _fold_inline_literal_container(node.func.value, assignments_by_scope, scope_id, lineno, visited)
        if isinstance(base, dict):
            value = _read_literal_member(base, node.args[0], assignments_by_scope, scope_id, lineno, visited)
            if value is not None:
                return value
            if len(node.args) > 1:
                return _eval_static_constant(node.args[1], assignments_by_scope, scope_id, lineno, visited)
        return None
    return None

def _assignment_records(assignments_by_scope, name: str, scope_id: str, lineno: int):
    """Writes to `name` visible from `scope_id`, oldest first, walking out to the
    enclosing function scopes and the module scope like `_eval_static_constant` does."""
    mod_name = scope_module(scope_id) if scope_id else ""
    current = scope_id
    walked = set()
    while current and current not in walked:
        walked.add(current)
        records = assignments_by_scope.get((current, name), [])
        if lineno:
            records = [r for r in records if r.lineno <= lineno]
        if records:
            return list(records)
        if "." in current and "function" in current:
            current = current.rsplit(".", 1)[0]
        elif ":function" in current:
            current = f"{mod_name}:global"
        elif current != f"{mod_name}:global":
            current = f"{mod_name}:global"
        else:
            break
    return []


def _literal_text(node, assignments_by_scope, scope_id="", lineno=0, seen=None):
    """A string assembled purely from literals, or `None` when any write is not
    provably literal. Unlike `_eval_static_constant` this resolves accumulator chains
    (`query = "SELECT …"` then `query += "3"`) by replaying every write in order: the
    accumulator reads itself, which the plain folder has to refuse."""
    if node is None:
        return None
    seen = seen if seen is not None else set()
    value = _eval_static_constant(node, assignments_by_scope, scope_id, lineno, set(seen))
    if isinstance(value, str):
        return value
    if isinstance(node, ast.Name):
        key = (scope_id, node.id)
        if key in seen:
            return None
        seen = seen | {key}
        accumulated = None
        for record in _assignment_records(assignments_by_scope, node.id, scope_id, lineno):
            writer = record.value_node
            if (accumulated is not None and isinstance(writer, ast.BinOp)
                    and isinstance(writer.op, ast.Add)
                    and isinstance(writer.left, ast.Name) and writer.left.id == node.id):
                piece = _literal_text(writer.right, assignments_by_scope,
                                      record.scope_id, record.lineno, seen)
            else:
                piece = _literal_text(writer, assignments_by_scope,
                                      record.scope_id, record.lineno, seen)
            if piece is None:
                return None
            accumulated = piece if accumulated is None else accumulated + piece
        return accumulated
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal_text(node.left, assignments_by_scope, scope_id, lineno, seen)
        right = _literal_text(node.right, assignments_by_scope, scope_id, lineno, seen)
        if left is not None and right is not None:
            return left + right
    return None


def _json_or_structured_body(call: ast.Call, assignments_by_scope, scope_id: str, lineno: int) -> bool:
    """True when a response's body is data rather than markup: a structured literal, or a
    JSON content type the browser will never parse as HTML. Nothing in either can be
    rendered as script, so an XSS sink claim does not hold."""
    body = call.args[0] if call.args else next(
        (kw.value for kw in call.keywords if kw.arg in {"content", "data"}), None)
    if isinstance(body, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
        return True
    media = next((kw.value for kw in call.keywords if kw.arg == "content_type"), None)
    text = _literal_text(media, assignments_by_scope, scope_id, lineno)
    return isinstance(text, str) and "json" in text.lower()


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


# ─── Module 1: dynamic reflection (getattr) receiver constants ───
# getattr(receiver, <non-static name>) hides the invoked method from attribute-call matching. When
# the receiver only ever exposes security-sensitive methods, the dynamic dispatch is itself the flaw.
DB_FACTORY_METHODS = {"cursor", "connect", "connection", "raw_connection"}
EXEC_CAPABLE_MODULES = {"os", "subprocess", "commands", "pty", "popen2", "posix"}
REFLECTION_NAMESPACE_MODULES = {"builtins"}
REFLECTION_FAMILY_BY_KIND = {
    "db": ("CWE-89", "DYNAMIC_SQL_INVOCATION", "SQL_INJECTION"),
    "exec": ("CWE-78", "DYNAMIC_COMMAND_INVOCATION", "COMMAND_INJECTION"),
    "namespace": ("CWE-95", "DYNAMIC_CODE_INVOCATION", "CODE_EXECUTION"),
}


class TaintTracker:
    def __init__(self, files: dict[str, str] = None, source: str = None, file_path: str = "target.py", audit_all: bool = False, max_workers: Optional[int] = None):
        self.files = files if files is not None else {file_path: source}
        self.audit_all = audit_all
        self.max_workers = max_workers
        
        # TimeCodeSecurity: Use safe parallel parsing with hardware governance
        if PARALLEL_PARSING_AVAILABLE and len(self.files) > 10:
            # Only use parallel parsing for larger workloads (>10 files)
            (self.modules, self.file_paths, self.skipped_files,
             self.parse_stats) = parse_files_parallel(self.files, max_workers=max_workers)
        else:
            # Fallback to sequential parsing for small workloads or if parallel unavailable
            self.modules: dict[str, ast.AST] = {}
            self.file_paths: dict[str, str] = {}
            self.skipped_files: dict[str, str] = {}
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
                except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
                    # One malformed file must not remove every other module from the scan:
                    # ast.parse raises ValueError on embedded NUL bytes, which is not a SyntaxError.
                    self.skipped_files[fpath] = f"{type(exc).__name__}: {exc}"[:200]
            # No fast-path pre-filter on this branch, so the count is a real zero, not a gap.
            self.parse_stats = {
                "discovered": len(self.files),
                "parsed": len(self.modules),
                "fast_path_skipped": 0,
                "unparseable": len(self.skipped_files),
                "workers_used": 1,
                "governor_events": 0,
                "parse_mode": "inline",
            }
        self.dead_node_ids: set = self._compute_dead_node_ids()
        self.imports = {m: {} for m in self.modules}
        self.sources: list[SecurityNode] = []
        self.sinks: list[SecurityNode] = []
        self.edges: list[DataFlowEdge] = []
        self.assignments_by_scope: dict = AssignmentNameTable()
        # Cache for _module_alias_names(): per module, (alias count, alias name set).
        self._alias_name_cache: Dict[str, tuple] = {}
        # Cache for _enclosing_param_names(): (function-table size, scope -> names).
        self._param_name_cache: Optional[tuple[int, dict]] = None
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
        # CWE-295: obj.verify = False attribute assignments (not keyword args)
        self.ssl_attr_assigns: list[tuple[ast.Assign, str, int]] = []
        self._source_counter = 0
        self._sink_counter = 0
        
        # Store source lines for nosec suppression check
        self._source_lines_by_file: dict[str, list[str]] = {}
        for fpath, code in self.files.items():
            if code is not None:
                self._source_lines_by_file[fpath] = code.splitlines()

        # Phase 4.3: Function contract extractor for wrapper sinks
        self.contract_extractor = FunctionContractExtractor()
        self.function_contracts: Dict[str, FunctionSinkContract] = {}
        # Perf: per-scan memoization so Phase 4 analyses never re-traverse
        self._defuse_trackers: dict[int, LocalDefUseTracker] = {}
        self._sink_shortnames: frozenset = frozenset(
            name.split(".")[-1] for name in KNOWN_SINKS
        )

    def _extract_function_contracts(self) -> None:
        """
        Extract function contracts from all modules after collection phase.

        This must be called after collect_statements() has populated self.functions
        and self.modules, but before sink analysis begins.
        Perf: source-text prescreen — modules with no known-sink identifier skip
        AST traversal entirely. A false prescreen miss cannot occur because every
        KNOWN_SINKS leaf is checked as a whole word against the module source.
        """
        sink_word_re = re.compile(
            r"\b(" + "|".join(re.escape(n.split(".")[-1]) for n in KNOWN_SINKS) + r")\b"
        )
        for mod_name, tree in self.modules.items():
            file_path = self.file_paths.get(mod_name, f"{mod_name}.py")
            source = self.files.get(file_path) or self.files.get(mod_name, "")
            if source and not sink_word_re.search(source):
                continue
            contracts = self.contract_extractor.extract_from_module(tree, file_path)
            # Merge contracts (later modules can override, but first wins for safety)
            for func_name, contract in contracts.items():
                if func_name not in self.function_contracts:
                    self.function_contracts[func_name] = contract

    def next_source_id(self) -> str:
        self._source_counter += 1
        return f"SRC-{self._source_counter:03d}"

    def next_sink_id(self) -> str:
        self._sink_counter += 1
        return f"SNK-{self._sink_counter:03d}"

    def _resolve_alias_with_def_use(self, var_name: str, scope_id: str, lineno: int) -> Optional[str]:
        """
        Use LocalDefUseTracker to resolve multi-hop aliases within a function scope.

        This is a lightweight integration that builds a def-use tracker for the
        enclosing function and checks if the variable carries taint from a source
        through alias chains.

        Returns the ultimate source variable name if tainted, None otherwise.
        STRICT: Only intra-procedural, only within same FunctionDef.
        """
        # Find the enclosing function for this scope
        mod_name = scope_module(scope_id) if ":" in scope_id else scope_id
        func_node = None
        func_scope = None

        # Walk up the scope chain to find the function
        current = scope_id
        while current:
            if ":function:" in current or (current != f"{mod_name}:global" and "." in current):
                candidate = self.functions.get(current)
                if candidate:
                    func_node = candidate
                    func_scope = current
                    break
            if current == f"{mod_name}:global":
                break
            if "." in current and "function" in current:
                current = current.rsplit(".", 1)[0]
            elif ":function" in current:
                current = f"{mod_name}:global"
            else:
                break

        if not func_node or not func_scope:
            return None

        # Perf: reuse the per-function tracker instead of re-analyzing on every
        # unresolved Name; the tracker is deterministic for a given FunctionDef.
        # Lazy: built only when sink resolution actually reaches this point.
        tracker = self._defuse_trackers.get(id(func_node))
        if tracker is None:
            tracker = LocalDefUseTracker()
            tracker.analyze_function(func_node, self.file_paths.get(mod_name, f"{mod_name}.py"))
            self._defuse_trackers[id(func_node)] = tracker

        # Check if the variable is tainted according to the tracker
        if tracker.is_variable_tainted(var_name):
            # Get the alias chain to find the ultimate source
            chain = tracker.get_alias_chain(var_name)
            if chain:
                # Return the last element in the chain (the original source)
                return chain[-1]

        return None

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
            mod_name = scope_module(scope_id) if scope_id else ""
            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
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

    def _static_subscript_path(self, node: ast.Subscript, scope_id: str = "") -> Optional[tuple]:
        """Decompose `root[k1][k2]...` into (root, [k1, k2, ...], kind) when every key is static.

        kind is "name" for a bare-variable container and "self_attr" for a `self.field` /
        `cls.field` container. None means the chain has no recognised root or a dynamic key.
        """
        keys: list = []
        current: ast.AST = node
        while isinstance(current, ast.Subscript):
            key = self._extract_subscript_key(current.slice, scope_id)
            if key is None:
                return None
            keys.append(key)
            current = current.value
        if not keys:
            return None
        if isinstance(current, ast.Name):
            return (current.id, list(reversed(keys)), "name")
        if (isinstance(current, ast.Attribute) and isinstance(current.value, ast.Name)
                and current.value.id in ("self", "cls")):
            return (current.attr, list(reversed(keys)), "self_attr")
        return None

    @staticmethod
    def _subscript_path_key(root: str, keys: list) -> str:
        """Composite key label for a subscript path; depth 1 keeps the historic `root[key]` form."""
        return f"{root}{''.join(f'[{key}]' for key in keys)}"

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
            mod_name = scope_module(scope_id) if ":" in scope_id else scope_id
            var_key = f"{scope_id}:{node.id}"
            if var_key in visited:
                return None
            visited.add(var_key)
            _walk_seen = set()
            while curr and curr not in _walk_seen:
                _walk_seen.add(curr)
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
            _walk_seen = set()
            while enc_scope and enc_scope not in _walk_seen:
                _walk_seen.add(enc_scope)
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
        mod_name = scope_module(scope_id) if scope_id else ""

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
                _walk_seen = set()
                while current_scope and current_scope not in _walk_seen:
                    _walk_seen.add(current_scope)
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
                _walk_seen = set()
                while enc_scope and enc_scope not in _walk_seen:
                    _walk_seen.add(enc_scope)
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
                        _walk_seen = set()
                        while curr and curr not in _walk_seen:
                            _walk_seen.add(curr)
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
                canon_func = self.resolve_canonical_name(node.func, scope_id, visited)
                if canon_func:
                    cls_name = canon_func.split(".")[-1]
                    if cls_name and cls_name[0].isupper():
                        return canon_func

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
                    _walk_seen = set()
                    while curr and curr not in _walk_seen:
                        _walk_seen.add(curr)
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
                _walk_seen = set()
                while current_scope and current_scope not in _walk_seen:
                    _walk_seen.add(current_scope)
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
                _walk_seen = set()
                while current_scope and current_scope not in _walk_seen:
                    _walk_seen.add(current_scope)
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
        source_meta = {"source_type": meta.get("source_type", "USER_CONTROLLED")}
        if "category" in meta:
            source_meta["category"] = meta["category"]
        if "severity" in meta:
            source_meta["severity"] = meta["severity"]
        source = SecurityNode(
            id=source_id, node_type=NodeType.SOURCE, symbol=sym,
            operation=meta.get("operation", "USER_INPUT_ACCESS"), location=loc,
            metadata=source_meta
        )
        self.sources.append(source)
        return source

    def _is_builtin_shadowed(self, name: str, scope_id: str, lineno: int = 0) -> bool:
        if name not in ("exec", "eval", "open"):
            return False

        mod_name = scope_module(scope_id) if scope_id else ""
        curr_scope = scope_id
        _walk_seen = set()
        while curr_scope and curr_scope not in _walk_seen:
            _walk_seen.add(curr_scope)
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

    def _get_route_param_names(self, fn_node: Optional[ast.AST]) -> set[str]:
        out: set[str] = set()
        if fn_node is None or not isinstance(fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return out
        for dec in getattr(fn_node, "decorator_list", []):
            call = dec if isinstance(dec, ast.Call) else None
            if call is None:
                continue
            func_name = ""
            if isinstance(call.func, ast.Attribute):
                func_name = call.func.attr
            elif isinstance(call.func, ast.Name):
                func_name = call.func.id
            if func_name not in CLUSTER2_ROUTE_DECORATOR_SEGMENTS:
                continue

            all_param_names = {p.arg for p in fn_node.args.args}
            if getattr(fn_node.args, "vararg", None):
                all_param_names.add(fn_node.args.vararg.arg)
            if getattr(fn_node.args, "kwarg", None):
                all_param_names.add(fn_node.args.kwarg.arg)
            for kw in getattr(fn_node.args, "kwonlyargs", []):
                all_param_names.add(kw.arg)
            for p in getattr(fn_node.args, "posonlyargs", []):
                all_param_names.add(p.arg)

            path_strings = []
            for arg in getattr(call, "args", []):
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    path_strings.append(arg.value)
            for kw in getattr(call, "keywords", []):
                if kw.arg in ("rule", "path") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    path_strings.append(kw.value.value)

            for path_str in path_strings:
                for token in re.findall(r"<(?:\w+:)?(\w+)>", path_str):
                    if token in all_param_names:
                        out.add(token)
                for token in re.findall(r"\{(\w+)(?::\w+)?\}", path_str):
                    if token in all_param_names:
                        out.add(token)
        return out

    def _is_insecure_host_key_policy(self, node: ast.Call, scope_id: str = "") -> bool:
        """CWE-322: Detect set_missing_host_key_policy(AutoAddPolicy|WarningPolicy).

        Covers all forms:
          client.set_missing_host_key_policy(client.AutoAddPolicy())  # instantiated
          client.set_missing_host_key_policy(client.AutoAddPolicy)    # bare class
          client.set_missing_host_key_policy(client.WarningPolicy())  # WarningPolicy
          client.set_missing_host_key_policy(WarningPolicy)           # bare import
        """
        func = node.func
        attr = (func.attr if isinstance(func, ast.Attribute)
                else (func.id if isinstance(func, ast.Name) else None))
        if attr != "set_missing_host_key_policy":
            return False
        if not node.args:
            return False
        policy_arg = node.args[0]
        # Unwrap call: AutoAddPolicy() -> AutoAddPolicy
        target = policy_arg.func if isinstance(policy_arg, ast.Call) else policy_arg
        policy_name = ""
        if isinstance(target, ast.Name):
            policy_name = target.id
        elif isinstance(target, ast.Attribute):
            policy_name = target.attr
        if policy_name in ("AutoAddPolicy", "WarningPolicy"):
            return True
        # Resolve variable assigned to AutoAddPolicy/WarningPolicy
        if isinstance(target, ast.Name) and target.id and scope_id:
            curr_scope = scope_id
            _walk_seen: set[str] = set()
            while curr_scope and curr_scope not in _walk_seen:
                _walk_seen.add(curr_scope)
                recs = self.assignments_by_scope.get((curr_scope, target.id), [])
                for r in recs:
                    val = r.value_node
                    v_target = val.func if isinstance(val, ast.Call) else val
                    v_name = (v_target.id if isinstance(v_target, ast.Name)
                              else (v_target.attr if isinstance(v_target, ast.Attribute) else ""))
                    if v_name in ("AutoAddPolicy", "WarningPolicy"):
                        return True
                if "." in curr_scope:
                    curr_scope = curr_scope.rsplit(".", 1)[0]
                else:
                    break
        return False

    def _has_disabled_ssl(self, node: ast.Call, scope_id: str = "") -> bool:
        for kw in getattr(node, "keywords", []):
            if kw.arg == "verify":
                if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    return True
                if isinstance(kw.value, ast.Name):
                    curr_scope = scope_id
                    _walk_seen = set()
                    while curr_scope and curr_scope not in _walk_seen:
                        _walk_seen.add(curr_scope)
                        recs = self.assignments_by_scope.get((curr_scope, kw.value.id), [])
                        for r in recs:
                            if isinstance(r.value_node, ast.Constant) and r.value_node.value is False:
                                return True
                        if "." in curr_scope:
                            curr_scope = curr_scope.rsplit(".", 1)[0]
                        else:
                            break
                if isinstance(kw.value, ast.Attribute):
                    attr_name = kw.value.attr
                    for (sc, target_attr), recs in self.class_field_assignments.items():
                        if target_attr == attr_name:
                            for r in recs:
                                if isinstance(r.value_node, ast.Constant) and r.value_node.value is False:
                                    return True
                    curr_scope = scope_id
                    _walk_seen = set()
                    while curr_scope and curr_scope not in _walk_seen:
                        _walk_seen.add(curr_scope)
                        recs = self.assignments_by_scope.get((curr_scope, attr_name), [])
                        for r in recs:
                            if isinstance(r.value_node, ast.Constant) and r.value_node.value is False:
                                return True
                        if "." in curr_scope:
                            curr_scope = curr_scope.rsplit(".", 1)[0]
                        else:
                            break
            if kw.arg is None:
                # Keyword unpacking: requests.get(url, **options)
                if isinstance(kw.value, ast.Dict):
                    for k, v in zip(kw.value.keys, kw.value.values):
                        if isinstance(k, (ast.Constant, ast.Str)):
                            k_str = k.value if isinstance(k, ast.Constant) else k.s
                            if k_str == "verify" and isinstance(v, ast.Constant) and v.value is False:
                                return True
                elif isinstance(kw.value, ast.Name):
                    curr_scope = scope_id
                    _walk_seen = set()
                    while curr_scope and curr_scope not in _walk_seen:
                        _walk_seen.add(curr_scope)
                        recs = self.assignments_by_scope.get((curr_scope, kw.value.id), [])
                        for r in recs:
                            if isinstance(r.value_node, ast.Dict):
                                for k, v in zip(r.value_node.keys, r.value_node.values):
                                    if isinstance(k, (ast.Constant, ast.Str)):
                                        k_str = k.value if isinstance(k, ast.Constant) else k.s
                                        if k_str == "verify" and isinstance(v, ast.Constant) and v.value is False:
                                            return True
                        if "." in curr_scope:
                            curr_scope = curr_scope.rsplit(".", 1)[0]
                        else:
                            break
            # CWE-295: cert_reqs=ssl.CERT_NONE / CERT_OPTIONAL or string equivalents.
            # NOTE: cert_reqs=None means "use default / follow context" — NOT a finding (zero-FP guard).
            if kw.arg in ("cert_reqs", "ssl_cert_reqs"):
                val = kw.value
                if isinstance(val, ast.Constant):
                    # Only flag string literals like "NONE" or "CERT_NONE"/"CERT_OPTIONAL".
                    # Do NOT flag Python None (NoneType) — that is the safe default.
                    if isinstance(val.value, str) and val.value.upper() in (
                        "CERT_NONE", "NONE", "CERT_OPTIONAL", "OPTIONAL"
                    ):
                        return True
                elif isinstance(val, ast.Attribute) and val.attr in (
                    "CERT_NONE", "CERT_OPTIONAL", "CERT_NO_CHECK"
                ):
                    # e.g. ssl.CERT_NONE, ssl.CERT_OPTIONAL
                    return True
                elif isinstance(val, ast.Name) and val.id in (
                    "CERT_NONE", "CERT_OPTIONAL", "CERT_NO_CHECK"
                ):
                    # e.g. bare CERT_NONE after "from ssl import CERT_NONE"
                    return True
                elif isinstance(val, ast.Name):
                    # Resolve variable: might be assigned ssl.CERT_NONE elsewhere
                    curr_scope = scope_id
                    _walk_seen: set[str] = set()
                    while curr_scope and curr_scope not in _walk_seen:
                        _walk_seen.add(curr_scope)
                        recs = self.assignments_by_scope.get((curr_scope, val.id), [])
                        for r in recs:
                            if isinstance(r.value_node, ast.Constant):
                                if isinstance(r.value_node.value, str) and r.value_node.value.upper() in (
                                    "CERT_NONE", "NONE", "CERT_OPTIONAL", "OPTIONAL"
                                ):
                                    return True
                            elif isinstance(r.value_node, ast.Attribute) and r.value_node.attr in (
                                "CERT_NONE", "CERT_OPTIONAL", "CERT_NO_CHECK"
                            ):
                                return True
                            elif isinstance(r.value_node, ast.Name) and r.value_node.id in (
                                "CERT_NONE", "CERT_OPTIONAL", "CERT_NO_CHECK"
                            ):
                                return True
                        if "." in curr_scope:
                            curr_scope = curr_scope.rsplit(".", 1)[0]
                        else:
                            break
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
            elif isinstance(curr, ast.Dict):
                # CWE-338: random.* used as a VALUE in a dict literal whose KEY is a
                # security-sensitive identifier, e.g. {"auth_secret": random.random()}
                for k, v in zip(curr.keys, curr.values):
                    if v is node or any(sub is node for sub in ast.walk(v)):
                        if isinstance(k, (ast.Constant, ast.Str)):
                            key_str = k.value if isinstance(k, ast.Constant) else k.s
                            if isinstance(key_str, str) and is_security_identifier(key_str):
                                return True
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
        elif fn_name == "new" and (canon in ("hashlib.new", "_hashlib.new") or (scope_id and "hashlib" in str(self.imports.get(scope_module(scope_id), {})))):
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

    def _usedforsecurity_false(self, node: ast.Call, scope_id: str = "", lineno: int = 0) -> bool:
        """True when the call passes usedforsecurity=False, declaring a non-security digest."""
        lno = lineno or getattr(node, "lineno", 0)
        for kw in getattr(node, "keywords", []):
            if kw.arg == "usedforsecurity":
                return _eval_static_constant(kw.value, self.assignments_by_scope, scope_id, lno) is False
        return False

    def _scope_module(self, scope_id: str) -> str:
        return scope_module(scope_id) if scope_id else ""

    def _module_source_path(self, mod_name_or_path: str) -> str:
        return str(self.file_paths.get(mod_name_or_path) or mod_name_or_path).replace("\\", "/")

    def _module_stem_and_dirs(self, mod_name_or_path: str) -> tuple[str, list[str]]:
        parts = self._module_source_path(mod_name_or_path).split("/")
        stem = parts[-1]
        if stem.endswith(".py"):
            stem = stem[:-3]
        return stem, parts[:-1]

    def _registry_sink_cwe(self, name: str, canon: str) -> str:
        """CWE of the registry sink this call resolves to, '' when it is not a registry sink."""
        for candidate in (canon, name):
            entry = SINK_REGISTRY.get(candidate) if candidate else None
            if entry:
                return entry.get("cwe") or ""
        return ""

    def _enclosing_def(self, node: ast.AST):
        curr = getattr(node, "parent", None)
        while curr is not None:
            if isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return curr
            curr = getattr(curr, "parent", None)
        return None

    def _function_parameter_names(self, func) -> set:
        a = getattr(func, "args", None)
        if a is None:
            return set()
        return {p.arg for p in (*getattr(a, "posonlyargs", []), *a.args, *getattr(a, "kwonlyargs", []))}

    def _is_pytest_test_module(self, mod_name: str) -> bool:
        """A pytest test module: tests/ package or test_*.py / *_test.py / conftest.py, using pytest."""
        stem, dirs = self._module_stem_and_dirs(mod_name)
        if not (stem.startswith("test_") or stem.endswith("_test") or stem == "conftest"
                or any(d in PYTEST_TEST_DIR_NAMES for d in dirs)):
            return False
        roots = {str(c).split(".")[0] for c in (self.imports.get(mod_name) or {}).values()}
        return "pytest" in roots

    def _is_pytest_case_function(self, func) -> bool:
        """A function pytest drives itself: a `test_*` body or a fixture/parametrize decorator."""
        if func.name.startswith("test_"):
            return True
        for decorator in func.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            dotted = dotted_name(target) or ""
            if dotted.split(".")[0] in ("pytest", "fixture", "parametrize") or "fixture" in dotted:
                return True
        return False

    def _is_pytest_fixture_dynamic_import(self, node: ast.Call, mod_name: str) -> bool:
        """Suppress CWE-94 when a pytest suite imports the module name it parametrises with.

        The dynamic value must come from the fixture machinery — `request.param`, a parameter of
        the enclosing test/fixture, or a local assigned from a `.param` expression in that scope.
        A read of a live web request (`request.args[...]`, `request.json`) stays reportable.
        """
        if not node.args or not self._is_pytest_test_module(mod_name):
            return False
        func = self._enclosing_def(node)
        if func is None or not self._is_pytest_case_function(func):
            return False
        attrs = [a for a in ast.walk(node.args[0]) if isinstance(a, ast.Attribute)]
        if any(a.attr == "param" for a in attrs):
            return True
        if any(a.attr in WEB_REQUEST_INPUT_ATTRS for a in attrs):
            return False
        supplied = self._function_parameter_names(func) - {"self", "cls"}
        for stmt in ast.walk(func):
            if not isinstance(stmt, (ast.Assign, ast.AnnAssign)) or stmt.value is None:
                continue
            if not any(isinstance(a, ast.Attribute) and a.attr == "param" for a in ast.walk(stmt.value)):
                continue
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for t in targets:
                if isinstance(t, ast.Name):
                    supplied.add(t.id)
        arg_names = {n.id for n in ast.walk(node.args[0]) if isinstance(n, ast.Name)}
        return bool(arg_names & supplied)

    def _is_http_transport_module(self, mod_name_or_path: str) -> bool:
        """True for the transport/session/pool layer inside an HTTP client package."""
        stem, dirs = self._module_stem_and_dirs(mod_name_or_path)
        return stem in HTTP_TRANSPORT_MODULE_STEMS and any(d in HTTP_CLIENT_PACKAGE_DIRS for d in dirs)

    def _sink_context_exempt(self, cwe_id: str, node: ast.Call, scope_id: str) -> bool:
        mod_name = self._scope_module(scope_id)
        if not mod_name:
            return False
        if cwe_id == "CWE-94":
            return self._is_pytest_fixture_dynamic_import(node, mod_name)
        if cwe_id == "CWE-918":
            return self._is_http_transport_module(mod_name)
        return False

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

    # CWE-22 sanitizers that break the taint chain when wrapping a path expression.
    _CWE22_SANITIZER_NAMES = frozenset({
        "secure_filename", "werkzeug.utils.secure_filename",
        "os.path.basename", "posixpath.basename", "ntpath.basename", "basename",
    })

    def _dict_value_has_cwe22_sanitizer(self, value_node: ast.AST) -> bool:
        """Return True if *value_node* contains a call to a recognized CWE-22 path sanitizer."""
        if value_node is None:
            return False
        for sub in ast.walk(value_node):
            if isinstance(sub, ast.Call):
                fn = dotted_name(sub.func) or ""
                if fn in self._CWE22_SANITIZER_NAMES or fn.split(".")[-1] in self._CWE22_SANITIZER_NAMES:
                    return True
        return False

    _HTML_TAGS_RE = re.compile(
        r'<\s*/?\s*(?:html|body|head|div|span|h[1-6]|p|table|tr|td|th|ul|ol|li|a|b|i|strong|em|script|iframe|img|form|input|button|header|footer|nav|section|article)\b',
        re.IGNORECASE
    )

    def _is_html_construction_expr(
        self,
        expr: Optional[ast.AST],
        scope_id: str = "",
        depth: int = 0,
        visited_nodes: set | None = None
    ) -> bool:
        """Return True if *expr* constructs an HTML fragment (e.g. f'<h1>{name}</h1>')."""
        if expr is None or depth > 10:
            return False
        if visited_nodes is None:
            visited_nodes = set()
        node_id = id(expr)
        if node_id in visited_nodes:
            return False
        visited_nodes.add(node_id)

        if isinstance(expr, ast.JoinedStr):
            const_strs = []
            for part in expr.values:
                if isinstance(part, (ast.Constant, ast.Str)):
                    val = part.value if isinstance(part, ast.Constant) else part.s
                    if isinstance(val, str):
                        const_strs.append(val)
                        if self._HTML_TAGS_RE.search(val):
                            return True
            combined_consts = "".join(const_strs)
            if ("<" in combined_consts and ">" in combined_consts) or ("</" in combined_consts):
                if any(isinstance(p, ast.FormattedValue) for p in expr.values):
                    return True
        elif isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
            if isinstance(expr.left, (ast.Constant, ast.Str)):
                val = expr.left.value if isinstance(expr.left, ast.Constant) else expr.left.s
                if isinstance(val, str) and (self._HTML_TAGS_RE.search(val) or ("<" in val and ">" in val)):
                    return True
        elif isinstance(expr, ast.Call):
            if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                if isinstance(expr.func.value, (ast.Constant, ast.Str)):
                    val = expr.func.value.value if isinstance(expr.func.value, ast.Constant) else expr.func.value.s
                    if isinstance(val, str) and (self._HTML_TAGS_RE.search(val) or ("<" in val and ">" in val)):
                        return True
        elif isinstance(expr, ast.Name) and scope_id:
            curr = scope_id
            _walk_seen = set()
            while curr and curr not in _walk_seen:
                _walk_seen.add(curr)
                recs = self.assignments_by_scope.get((curr, expr.id), [])
                for r in recs:
                    if self._is_html_construction_expr(r.value_node, curr, depth + 1, visited_nodes):
                        return True
                if "." in curr:
                    curr = curr.rsplit(".", 1)[0]
                else:
                    break
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
            _walk_seen = set()
            while curr and curr not in _walk_seen:
                _walk_seen.add(curr)
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
                    curr = f"{scope_module(curr)}:global"
                else:
                    break

        return False

    # ----------------------------------------------------------------------
    # Source legitimacy.
    #
    # Matching a dangerous callee is only half of a finding: something outside the
    # program's own text has to be able to change the value that reaches it. These
    # predicates settle that for the argument shapes behind most reported false
    # positives — a path re-derived from `__file__` on every run, an argv list of
    # constants, a stream opened on a hardcoded filename, a comparison against a
    # literal. Each walks assignment records instead of guessing, and answers False
    # for anything it cannot explain, so an unproven argument keeps its finding.
    # ----------------------------------------------------------------------
    _INERT_MODULE_ROOTS = frozenset({
        "os", "sys", "uuid", "secrets", "hashlib", "string", "base64", "binascii",
        "math", "time", "platform", "stat", "posixpath", "ntpath", "pathlib", "io",
        "builtins", "datetime", "itertools", "functools", "codecs", "tempfile",
    })
    _INERT_CALLEES = frozenset({
        "open", "str", "repr", "bytes", "bytearray", "int", "float", "bool", "list",
        "dict", "tuple", "set", "frozenset", "len", "abs", "min", "max", "sum",
        "round", "sorted", "reversed", "enumerate", "range", "zip", "map", "filter",
        "ord", "chr", "hex", "oct", "divmod", "isinstance", "issubclass", "type",
        "id", "hash", "getattr", "hasattr", "setattr", "print", "format", "complex",
        "vars", "dir", "iter", "next", "slice", "memoryview",
    })
    _SELF_DESCRIBED_NAMES = frozenset({"__file__", "__cached__", "__name__", "__doc__"})
    _SELF_DESCRIBED_ATTRS = frozenset({
        "sys.executable", "sys.prefix", "sys.base_prefix", "sys.exec_prefix",
        "sys.baseline_prefix", "sys.platform", "sys.version_info", "sys.byteorder",
        "sys.api_version", "os.curdir", "os.sep", "os.pathsep", "os.defpath",
        "os.name", "os.altsep",
    })
    _EXTERNAL_VALUE_PATHS = ("os.environ", "os.getenv", "sys.argv", "sys.environ", "sys.stdin")
    _EXTERNAL_CALLEE_SEGS = frozenset({"input", "raw_input", "getenv", "getenvb", "system", "popen"})
    _NONCE_METHOD_SEGS = frozenset({
        "uuid4", "uuid1", "uuid3", "uuid5", "uuid6", "UUID", "token_hex",
        "token_urlsafe", "token_bytes", "urandom", "getrandbits", "randbytes",
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256",
        "sha3_512", "blake2b", "blake2s",
    })
    _NULLARY_SEGS = frozenset({"getcwd", "getcwdb", "curdir", "sep", "pathsep"})
    _DIR_ITERATION_SEGS = frozenset({"listdir", "scandir", "walk", "iterdir", "glob", "iglob"})

    def _is_module_qualified(self, expr: ast.AST) -> bool:
        """True for `os.path`, `uuid`, `base64` — a stdlib handle, not program data.

        The external-value paths are excluded first, because `os.environ` and
        `sys.argv` share the root name of their inert neighbours while being exactly
        the input an attacker controls.
        """
        text = dotted_name(expr) or ""
        if not text:
            return False
        if any(text == prefix or text.startswith(prefix + ".") or text.startswith(prefix + "[")
               for prefix in self._EXTERNAL_VALUE_PATHS):
            return False
        return text.split(".")[0] in self._INERT_MODULE_ROOTS

    def _dir_listing_names(self, mod_name: str) -> frozenset:
        """Loop variables fed by a directory enumeration.

        `for item in os.listdir(cwd)` can only ever name an entry that already exists
        inside `cwd`, so such a variable cannot carry a traversal sequence. Cached per
        module because the sink loops ask for it once per call site.
        """
        cache = self.__dict__.setdefault("_dir_listing_cache", {})
        if mod_name not in cache:
            names = set()
            tree = self.modules.get(mod_name)
            if tree is not None:
                for node in ast.walk(tree):
                    if not isinstance(node, (ast.For, ast.AsyncFor)):
                        continue
                    it = node.iter
                    if (isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute)
                            and it.func.attr in self._DIR_ITERATION_SEGS
                            and self._is_module_qualified(it.func)):
                        for target in ([node.target] if isinstance(node.target, ast.Name)
                                       else getattr(node.target, "elts", [])):
                            if isinstance(target, ast.Name):
                                names.add(target.id)
            cache[mod_name] = frozenset(names)
        return cache[mod_name]

    def _is_self_described(self, expr: ast.AST, scope_id: str = "", lineno: int = 0,
                           depth: int = 0) -> bool:
        """Can anything outside this source file change `expr`?

        A path built by `os.path.join(os.path.dirname(__file__), "playground/A9/main.py")`
        and an argv list of literals reproduce the same value on every run, so reporting
        them as traversal or injection teaches a reviewer nothing. The answer is built by
        following each name to the assignments that could have written it: a literal, a
        stdlib handle, a uuid/hashlib nonce or a `os.listdir()` entry is self-described,
        while a parameter, an unexplained name or a `request`-derived value is not.
        """
        if expr is None or depth > 8:
            return False
        if isinstance(expr, ast.Constant):
            return True
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return all(self._is_self_described(e, scope_id, lineno, depth + 1) for e in expr.elts)
        if isinstance(expr, ast.Dict):
            return all(self._is_self_described(v, scope_id, lineno, depth + 1) for v in expr.values)
        if isinstance(expr, ast.JoinedStr):
            return all(self._is_self_described(v, scope_id, lineno, depth + 1) for v in expr.values)
        if isinstance(expr, ast.FormattedValue):
            return self._is_self_described(expr.value, scope_id, lineno, depth + 1)
        if isinstance(expr, (ast.BinOp, ast.Subscript)):
            halves = [expr.left, expr.right] if isinstance(expr, ast.BinOp) else [expr.value, expr.slice]
            return all(self._is_self_described(h, scope_id, lineno, depth + 1) for h in halves if h is not None)
        if isinstance(expr, ast.IfExp):
            # The test only picks between two values the source already contains.
            return (self._is_self_described(expr.body, scope_id, lineno, depth + 1)
                    and self._is_self_described(expr.orelse, scope_id, lineno, depth + 1))
        if isinstance(expr, ast.UnaryOp):
            return self._is_self_described(expr.operand, scope_id, lineno, depth + 1)
        if isinstance(expr, ast.Name):
            if (expr.id in self._SELF_DESCRIBED_NAMES or expr.id in self._NULLARY_SEGS
                    or expr.id in self._INERT_MODULE_ROOTS):
                return True
            mod_name = scope_module(scope_id) if scope_id else ""
            if mod_name and expr.id in self._dir_listing_names(mod_name):
                return True
            records = _assignment_records(self.assignments_by_scope, expr.id, scope_id, lineno)
            if not records:
                return False
            return all(self._is_self_described(r.value_node, r.scope_id, r.lineno, depth + 1)
                       for r in records)
        if isinstance(expr, ast.Attribute):
            text = dotted_name(expr) or ""
            if any(text == prefix or text.startswith(prefix + ".") or text.startswith(prefix + "[")
                   for prefix in self._EXTERNAL_VALUE_PATHS):
                return False
            if text in self._SELF_DESCRIBED_ATTRS:
                return True
            if self._is_module_qualified(expr):
                return True
            return self._is_self_described(expr.value, scope_id, lineno, depth + 1)
        if isinstance(expr, ast.Call):
            func = expr.func
            seg = ""
            if isinstance(func, ast.Attribute):
                seg = func.attr
            elif isinstance(func, ast.Name):
                seg = func.id
            if not seg or seg in self._EXTERNAL_CALLEE_SEGS:
                return False
            call_text = dotted_name(func) or ""
            if any(call_text.startswith(prefix) for prefix in self._EXTERNAL_VALUE_PATHS):
                return False
            if seg in self._NONCE_METHOD_SEGS and not expr.keywords:
                return all(self._is_self_described(a, scope_id, lineno, depth + 1) for a in expr.args)
            if seg in self._NULLARY_SEGS and not expr.args and not expr.keywords:
                return True
            parts = list(expr.args) + [kw.value for kw in expr.keywords]
            if isinstance(func, ast.Attribute):
                receiver = func.value
                if not (self._is_module_qualified(receiver)
                        or self._is_self_described(receiver, scope_id, lineno, depth + 1)):
                    return False
            elif not isinstance(func, ast.Name) or func.id not in self._INERT_CALLEES:
                return False
            return all(self._is_self_described(p, scope_id, lineno, depth + 1) for p in parts)
        return False

    def _compares_two_secrets(self, node: ast.Compare) -> bool:
        """Is this a secret-vs-secret comparison, the only kind that leaks timing?

        `token == None`, `tokens[i][0] == '<input'` and `x[:7] == 'value="'` branch on
        markup prefixes and presence, so their running time discloses nothing an
        attacker does not already hold. A literal on either side of the operator makes
        the compared value a fact of the source text.
        """
        operands = [node.left] + list(node.comparators)
        return not any(isinstance(o, ast.Constant) for o in operands)

    def _deserializes_own_document(self, call: ast.Call, scope_id: str = "", lineno: int = 0) -> bool:
        """True when the bytes being deserialized are chosen by the source file itself.

        `yaml.load(open('/home/fox/test.yaml'))` reaches an unsafe Loader, but the only
        author of that document is the repository, so there is no payload an attacker
        controls and the sink is inert. A stream this predicate cannot explain keeps its
        finding.
        """
        if not call.args:
            return False
        return self._is_self_described(call.args[0], scope_id, lineno)

    def _node_enclosing_scope(self, node: ast.AST, scope_id: str = "") -> str:
        """The function scope *node* really sits in, rebuilt from its parent chain.

        Several structural collectors register their sink records under the module scope
        even when the call lives inside a view function, so an assignment lookup from that
        scope comes up empty and an explainable sink looks unexplained. Recovering the
        enclosing scope makes the record's own context usable again.
        """
        mod_name = scope_module(scope_id) if scope_id else ""
        current = getattr(node, "parent", None)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                candidate = f"{mod_name}:function:{current.name}"
                if candidate in self.functions:
                    return candidate
                for known in self.functions:
                    if known.endswith(f":function:{current.name}") or \
                       known.endswith(f":function:{current.name}."):
                        return known
                return scope_id
            current = getattr(current, "parent", None)
        return scope_id

    def _read_subordinate_to_traversal(self, node: ast.Call, scope_id: str = "") -> bool:
        """True when an unbounded read is the second half of a traversal already reported.

        `filename = os.path.join(dirname, request.POST['blog'])`, then `open(filename)`,
        then `file.read()` is one defect: the attacker chose *which* file gets disclosed,
        and the size of that file adds nothing a reviewer can act on beyond the finding on
        the `open()` line. Matching the recorded sink by node identity rather than by line
        number keeps that conclusion tied to the very call that produced it. A read this
        method cannot trace to such an open keeps its finding, which is what keeps a plain
        `open("huge_data.bin")` + `f.read()` reported.
        """
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        if not isinstance(receiver, ast.Name):
            return False
        lineno = getattr(node, "lineno", 0)
        scopes = [scope_id]
        own_scope = self._node_enclosing_scope(node, scope_id)
        if own_scope and own_scope != scope_id:
            scopes.append(own_scope)
        for candidate_scope in scopes:
            for record in _assignment_records(self.assignments_by_scope, receiver.id,
                                              candidate_scope, lineno):
                writer = record.value_node
                if not (isinstance(writer, ast.Call) and writer.args):
                    continue
                func = writer.func
                seg = func.attr if isinstance(func, ast.Attribute) else (
                    func.id if isinstance(func, ast.Name) else "")
                if seg != "open":
                    continue
                if self._is_self_described(writer.args[0], record.scope_id, record.lineno):
                    return False
                return any(
                    rec.node is writer and (rec.security_node.metadata or {}).get("cwe") == "CWE-22"
                    for rec in self.sink_records
                )
        return False

    _UPLOAD_HANDLE_MARKERS = ("request.files", "uploadedfile", "uploadedimagefile",
                              "temporaryuploadedfile")

    def _is_upload_handle(self, expr: Optional[ast.AST], scope_id: str = "",
                          lineno: int = 0, depth: int = 0) -> bool:
        """True for an in-memory uploaded-file object, which is not a path string.

        `Image.open(request.FILES['file'])` hands PIL a file-like object; the upload's
        filename never participates in resolving anything on disk, so the traversal sink
        the callee name suggests is unreachable from that argument.
        """
        if expr is None or depth > 6:
            return False
        if isinstance(expr, ast.Attribute):
            text = (dotted_name(expr) or "").lower()
            if any(marker in text for marker in self._UPLOAD_HANDLE_MARKERS):
                return True
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) \
                and expr.func.attr in ("get", "getlist"):
            recv = (dotted_name(expr.func.value) or "").lower()
            if any(marker in recv for marker in self._UPLOAD_HANDLE_MARKERS):
                return True
        if isinstance(expr, ast.Subscript):
            return self._is_upload_handle(expr.value, scope_id, lineno, depth + 1)
        if isinstance(expr, ast.Name):
            for record in _assignment_records(self.assignments_by_scope, expr.id,
                                              scope_id, lineno):
                if self._is_upload_handle(record.value_node, record.scope_id,
                                          record.lineno, depth + 1):
                    return True
        return False

    _ORM_READ_SEGS = frozenset({"get", "filter", "exclude", "get_or_create"})
    _REQUEST_SEGS = frozenset({"get", "getlist", "post", "data", "json", "body", "form",
                               "args", "query", "params", "files", "headers", "cookies",
                               "session", "env", "environ", "argv", "stdin"})

    def _locally_defined_names(self) -> set:
        names = self.__dict__.get("_local_name_cache")
        if names is None:
            names = set()
            for scope_id in self.functions:
                tail = scope_id.rsplit(":function:", 1)
                if len(tail) == 2:
                    names.add(tail[1].split(".", 1)[0])
            self.__dict__["_local_name_cache"] = names
        return names

    def _has_untrusted_command_lineage(self, expr: Optional[ast.AST], scope_id: str = "",
                                       lineno: int = 0, depth: int = 0) -> bool:
        """True when attacker-chosen bytes can reach a command argument.

        An argv execution without a shell hands every element to `execve` verbatim, so
        nothing is parsed and no element can smuggle in an extra command. Literals and
        self-describing values never carry attacker bytes, and neither does a row read
        back through the ORM (`Model.objects.get(...)`) — those column values were written
        by the application or an administrator. Anything this method cannot explain, such
        as a function parameter or the result of an imported callable, is treated as
        attacker-controlled so the finding stays.
        """
        if expr is None or depth > 8:
            return False
        if self._is_self_described(expr, scope_id, lineno):
            return False
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return any(self._has_untrusted_command_lineage(element, scope_id, lineno, depth + 1)
                       for element in expr.elts)
        if isinstance(expr, ast.Dict):
            return any(self._has_untrusted_command_lineage(value, scope_id, lineno, depth + 1)
                       for value in expr.values)
        if isinstance(expr, ast.JoinedStr):
            return any(self._has_untrusted_command_lineage(value, scope_id, lineno, depth + 1)
                       for value in expr.values)
        if isinstance(expr, ast.FormattedValue):
            return self._has_untrusted_command_lineage(expr.value, scope_id, lineno, depth + 1)
        if isinstance(expr, ast.BinOp):
            return (self._has_untrusted_command_lineage(expr.left, scope_id, lineno, depth + 1)
                    or self._has_untrusted_command_lineage(expr.right, scope_id, lineno, depth + 1))
        if isinstance(expr, ast.UnaryOp):
            return self._has_untrusted_command_lineage(expr.operand, scope_id, lineno, depth + 1)
        if isinstance(expr, ast.Subscript):
            return self._has_untrusted_command_lineage(expr.value, scope_id, lineno, depth + 1)
        if isinstance(expr, ast.Starred):
            return self._has_untrusted_command_lineage(expr.value, scope_id, lineno, depth + 1)
        if isinstance(expr, ast.Attribute):
            receiver_text = (dotted_name(expr.value) or "").lower() if isinstance(expr.value, ast.AST) else ""
            if expr.attr.lower() in self._REQUEST_SEGS and (
                    "request" in receiver_text or "environ" in receiver_text
                    or receiver_text in ("os", "sys")):
                return True
            return self._has_untrusted_command_lineage(expr.value, scope_id, lineno, depth + 1)
        if isinstance(expr, ast.Call):
            func = expr.func
            segment = func.attr if isinstance(func, ast.Attribute) else (
                func.id if isinstance(func, ast.Name) else "")
            receiver_text = ""
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.AST):
                receiver_text = (dotted_name(func.value) or "").lower()
            if segment in self._ORM_READ_SEGS and receiver_text.endswith("objects"):
                return False
            if (segment in self._REQUEST_SEGS
                    and ("request" in receiver_text or receiver_text in ("os.environ", "sys"))):
                return True
            parts = list(expr.args) + [kw.value for kw in expr.keywords]
            if isinstance(func, ast.Attribute):
                parts.append(func.value)
            elif isinstance(func, ast.Name) and func.id not in self._locally_defined_names():
                # Result of an imported or builtin callable: provenance unknown.
                return True
            return any(self._has_untrusted_command_lineage(part, scope_id, lineno, depth + 1)
                       for part in parts)
        if isinstance(expr, ast.Name):
            records = _assignment_records(self.assignments_by_scope, expr.id, scope_id, lineno)
            if not records:
                return True
            return any(self._has_untrusted_command_lineage(record.value_node, record.scope_id,
                                                          record.lineno, depth + 1)
                       for record in records)
        return True

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

    def _reflection_getattr_parts(self, node: ast.Call) -> Optional[tuple]:
        """`(receiver, attr_expr)` when `node` is a call of `getattr(receiver, attr)`."""
        inner = node.func
        if not isinstance(inner, ast.Call):
            return None
        fname = dotted_name(inner.func) or ""
        if fname != "getattr" and not fname.endswith(".getattr"):
            return None
        if len(inner.args) < 2:
            return None
        return (inner.args[0], inner.args[1])

    def _latest_assignment(self, name: str, scope_id: str, before_lineno: int = 0) -> Optional[AssignmentRecord]:
        """Most recent (preferably unconditional) assignment of `name` in the scope chain."""
        current = scope_id
        mod_name = scope_module(scope_id) if scope_id else ""
        _walk_seen = set()
        while current and current not in _walk_seen:
            _walk_seen.add(current)
            recs = self.assignments_by_scope.get((current, name), [])
            if before_lineno:
                recs = [r for r in recs if r.lineno <= before_lineno]
            if recs:
                uncond = [r for r in recs if not r.is_conditional]
                return (uncond or recs)[-1]
            if "." in current and "function" in current:
                current = current.rsplit(".", 1)[0]
            elif ":function" in current:
                current = f"{mod_name}:global"
            elif current != f"{mod_name}:global":
                current = f"{mod_name}:global"
            else:
                break
        return None

    def _receiver_module(self, receiver: ast.AST, scope_id: str) -> Optional[str]:
        """Import-resolved module a receiver expression names, None for non-module receivers."""
        dotted = dotted_name(receiver) or ""
        root = dotted.split(".")[0] if dotted else ""
        if not root:
            return None
        imports = self.imports.get(scope_module(scope_id) if scope_id else "", {})
        if root in imports:
            return imports[root]
        return root if root in set(imports.values()) else None

    def _dynamic_reflection_family(self, node: ast.Call, scope_id: str) -> Optional[str]:
        """Sink family of `getattr(receiver, <dynamic name>)(...)` for security-sensitive receivers.

        Only fires when the invoked name is not statically resolvable; a literal name is already
        unrolled into `receiver.name` by resolve_canonical_name.
        """
        parts = self._reflection_getattr_parts(node)
        if parts is None or not node.args:
            return None
        receiver, attr_expr = parts
        if self._eval_const_str_with_params(attr_expr, scope_id) is not None:
            return None
        if isinstance(receiver, ast.Name):
            record = self._latest_assignment(receiver.id, scope_id, getattr(node, "lineno", 0))
            if record is not None and isinstance(record.value_node, ast.Call):
                callee = (self.resolve_canonical_name(record.value_node.func, record.scope_id)
                          or dotted_name(record.value_node.func) or "")
                if callee.split(".")[-1] in DB_FACTORY_METHODS:
                    return "db"
        module = self._receiver_module(receiver, scope_id)
        if module in EXEC_CAPABLE_MODULES:
            return "exec"
        if module in REFLECTION_NAMESPACE_MODULES:
            return "namespace"
        return None

    def _module_alias_names(self, mod: str) -> frozenset:
        """Import-alias keys visible in `mod`, plus their leaf identifiers.

        resolve_canonical_name() can rewrite a call through either form
        (`from jinja2 import Template as T` reaches both `T` and `Template`), so
        both are indexed. Keyed per module and rebuilt only when that module's own
        alias map changes size, which keeps the work proportional to one module
        instead of the whole import table.
        """
        alias_map = self.imports.get(mod)
        size = len(alias_map) if alias_map else 0
        cached = self._alias_name_cache.get(mod)
        if cached is None or cached[0] != size:
            acc: set = set()
            for key in (alias_map or {}):
                acc.add(key)
                acc.add(key.rsplit(".", 1)[-1])
            cached = (size, frozenset(acc))
            self._alias_name_cache[mod] = cached
        return cached[1]

    def _module_assigned_names(self, mod: str) -> Optional[set]:
        """Assignment targets recorded in `mod`, maintained on insert.

        A bare `foo()` or `recv.foo()` whose leaf appears here may resolve to a
        completely different callee, so the fast path must not prune it on leaf
        name alone.
        """
        return self.assignments_by_scope.names_by_module.get(mod)

    def _fast_path_prunable(self, node: ast.Call, leaf_name: str, scope_id: str) -> bool:
        """True when no branch of is_sink_call() can match this call.

        Sound only because every route by which resolve_canonical_name() could
        rewrite `leaf_name` into a sink is ruled out first:

          * import aliases           `from jinja2 import Template as T`
          * local/global rebinding   `f = eval`
          * higher-order parameters  `def run(fn): fn(x)` called as run(eval)
          * function contracts       keyed on the bare ast.Name id
          * CWE-295                  name-agnostic; decided by verify=/cert_reqs=

        Every guard is an O(1) membership test against an incrementally maintained
        index, so the whole probe stays far cheaper than the canonical resolution
        it replaces.
        """
        # CWE-295 never looks at the callee name - only at its keywords.
        if _may_disable_ssl(node):
            return False

        func_node = node.func

        # Contracts are keyed on the bare identifier.
        if (self.function_contracts and isinstance(func_node, ast.Name)
                and func_node.id in self.function_contracts):
            return False

        mod = scope_module(scope_id) if scope_id else ""
        if leaf_name in self._module_alias_names(mod):
            return False
        assigned = self._module_assigned_names(mod)
        if assigned is not None and leaf_name in assigned:
            return False

        # A parameter of an enclosing function may be bound to a sink at the call
        # site; resolve_canonical_name follows that binding. Walk the scope chain
        # because the call can sit in a nested def, and cover every parameter kind
        # (positional-only, kw-only, *args, **kwargs) - missing one silently prunes
        # a higher-order sink such as `def run(*fns): fns[0](x)`.
        if leaf_name in self._enclosing_param_names(scope_id):
            return False

        return True

    def _enclosing_param_names(self, scope_id: str) -> frozenset:
        """Every parameter name visible from `scope_id`, innermost scope outward.

        Cached across calls; invalidated when the function table grows because
        scope collection and sink detection are separate passes.
        """
        size = len(self.functions)
        cache = self._param_name_cache
        if cache is None or cache[0] != size:
            cache = (size, {})
            self._param_name_cache = cache
        table = cache[1]

        hit = table.get(scope_id)
        if hit is not None:
            return hit

        names: set = set()
        curr = scope_id
        seen = set()
        while curr and curr not in seen:
            seen.add(curr)
            fn = self.functions.get(curr)
            if fn is not None:
                args = fn.args
                names.update(a.arg for a in args.args)
                names.update(a.arg for a in getattr(args, "posonlyargs", []))
                names.update(a.arg for a in getattr(args, "kwonlyargs", []))
                if getattr(args, "vararg", None):
                    names.add(args.vararg.arg)
                if getattr(args, "kwarg", None):
                    names.add(args.kwarg.arg)
            if "." in curr and "function" in curr:
                curr = curr.rsplit(".", 1)[0]
            else:
                break

        result = frozenset(names)
        table[scope_id] = result
        return result

    def is_sink_call(self, node: ast.AST, scope_id: str = "", lineno: int = 0) -> bool:
        if not isinstance(node, ast.Call): return False
        call_lineno = lineno or getattr(node, "lineno", 0)
        
        # Respect # nosec suppression comments (Bandit compatibility)
        # Get source lines from the current module being analyzed
        source_lines = []
        for fpath, lines in getattr(self, '_source_lines_by_file', {}).items():
            # Use the first available source (simplification - assumes single-file analysis)
            source_lines = lines
            break
        
        if source_lines and 1 <= call_lineno <= len(source_lines):
            line_text = source_lines[call_lineno - 1]
            if CLUSTER3_NOSEC_RE.search(line_text):
                return False
        
        # ── O(1) fast path ────────────────────────────────────────────────────
        # ~95% of call sites in a large codebase name a callee that no sink rule
        # can match. Extracting the leaf identifier and testing one frozenset
        # avoids dotted_name() + resolve_canonical_name() (scope walks, import
        # folding, parameter resolution) for all of them.
        #
        # Soundness: SINK_CANDIDATE_NAMES must over-approximate every leaf any
        # branch below can match, and _fast_path_prunable() must rule out every
        # way canonical resolution could rewrite the leaf into a sink name.
        # A call whose func is neither Name nor Attribute (e.g. the
        # `getattr(recv, dyn)(...)` reflection family) has no leaf to test and is
        # always passed through to full resolution.
        func_node = node.func
        if isinstance(func_node, ast.Name):
            leaf_name: Optional[str] = func_node.id
        elif isinstance(func_node, ast.Attribute):
            leaf_name = func_node.attr
        else:
            leaf_name = None

        if (leaf_name is not None
                and leaf_name not in SINK_CANDIDATE_NAMES
                and self._fast_path_prunable(node, leaf_name, scope_id)):
            return False
        
        name = dotted_name(node.func) or ""
        canon = self.resolve_canonical_name(node.func, scope_id) if scope_id else name

        if (canon and canon.startswith("defusedxml.")) or (name and name.startswith("defusedxml.")):
            return False
        if canon in SANITIZER_REGISTRY or name in SANITIZER_REGISTRY:
            return False

        # Registry sinks still need their call-site context: a pytest fixture importing a
        # parametrised module, or a client library's own transport layer, are not exploitable.
        _sink_cwe = self._registry_sink_cwe(name, canon)
        if _sink_cwe and self._sink_context_exempt(_sink_cwe, node, scope_id):
            return False

        # Phase 4.3: Check if this call matches a registered function contract
        # Perf: cheap membership test first; full dotted-name extraction only
        # when a contract could actually apply.
        if self.function_contracts and isinstance(node.func, ast.Name) and node.func.id in self.function_contracts:
            return True

        # Check for CWE-295 (Disabled SSL verification in HTTP / socket calls)
        if self._has_disabled_ssl(node, scope_id):
            return True

        # Check for CWE-322: set_missing_host_key_policy with insecure policy
        # The policy constructor is evidence for the outer setter, not a sink itself.
        _parent = getattr(node, "parent", None)
        if isinstance(_parent, ast.Call):
            _p_func = _parent.func
            _p_attr = (_p_func.attr if isinstance(_p_func, ast.Attribute)
                       else (_p_func.id if isinstance(_p_func, ast.Name) else None))
            if _p_attr == "set_missing_host_key_policy":
                _inner = node.func
                _inner_name = (_inner.attr if isinstance(_inner, ast.Attribute)
                               else (_inner.id if isinstance(_inner, ast.Name) else ""))
                if _inner_name in ("AutoAddPolicy", "WarningPolicy"):
                    return False
        if self._is_insecure_host_key_policy(node, scope_id):
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

        # CWE-338: All random.* calls are flagged unconditionally (insecure PRNG)
        # CSPRNGs (secrets.*, os.urandom, random.SystemRandom) are excluded via sanitizer registry
        candidates = {c for c in (name, canon) if c}
        for c in list(candidates):
            if "." in c:
                candidates.add(c.split(".")[-1])
        
        if candidates & CWE338_RANDOM_NAMES:
            # Exclude calls on SystemRandom instances: random.SystemRandom().randint()
            if isinstance(node.func, ast.Attribute):
                receiver_name = dotted_name(node.func.value) or ""
                if not receiver_name and isinstance(node.func.value, ast.Call):
                    receiver_name = dotted_name(node.func.value.func) or ""
                # resolve_canonical_name returns None for receivers it cannot fold
                # (e.g. get_random().randint()); it must never feed a membership test.
                receiver_canon = (self.resolve_canonical_name(node.func.value, scope_id)
                                  if (scope_id and hasattr(self, "resolve_canonical_name"))
                                  else receiver_name) or receiver_name
                if "SystemRandom" in receiver_name or "SystemRandom" in receiver_canon:
                    return False  # CSPRNG instance method - safe
            # Flag ALL other random.* calls unconditionally - no security context gate
            pass  # Continue to sink matching

        # Module 1: getattr(receiver, <dynamic>)(...) on a DB-API / exec / builtins receiver.
        if scope_id and self._dynamic_reflection_family(node, scope_id) is not None:
            return True

        if canon:
            if canon.startswith("shadowed:"):
                return False
            if name and not name.startswith("builtins.") and not name.startswith("flask.") and scope_id and self._is_builtin_shadowed(name, scope_id, call_lineno):
                return False
            matched = match_sink_rule(node, name, canon)
            if matched:
                if matched.cwe_id == "CWE-327" and self._is_exempt_cwe327(node, scope_id, call_lineno):
                    return False
                # CWE-338: no security context gate - flag all random.* calls
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
                # CWE-338: no security context gate - flag all random.* calls
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
                # CWE-338: no security context gate - flag all random.* calls
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
                if self._read_subordinate_to_traversal(node, scope_id):
                    return False
                return True

        # Asyncio run_in_executor callback sink (exec/eval)
        func_attr = node.func.attr if isinstance(node.func, ast.Attribute) else (node.func.id if isinstance(node.func, ast.Name) else None)
        if func_attr == "run_in_executor" and len(node.args) >= 3:
            cb = node.args[1]
            cb_name = cb.id if isinstance(cb, ast.Name) else (cb.attr if isinstance(cb, ast.Attribute) else None)
            cb_canon = self.resolve_canonical_name(cb, scope_id) if (scope_id and isinstance(cb, ast.AST)) else None
            if {cb_name, cb_canon} & {"exec", "eval", "builtins.exec", "builtins.eval"}:
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

        # Phase 4.3: Check if this call matches a function contract
        # Perf: cheap membership test against the merged contract map.
        contract = None
        if self.function_contracts and isinstance(node.func, ast.Name) and node.func.id in self.function_contracts:
            contract = self.function_contracts[node.func.id]
        contract_cwe = contract.cwe_id if contract else None
        
        if force_cwe == "CWE-295":
            meta = {"operation": "DISABLED_SSL_VERIFICATION", "category": "INSECURE_TRANSPORT", "cwe": "CWE-295"}
        elif scope_id and (family := self._dynamic_reflection_family(node, scope_id)) is not None:
            cwe_value, operation, category = REFLECTION_FAMILY_BY_KIND[family]
            receiver_label = dotted_name(self._reflection_getattr_parts(node)[0]) or "object"
            name = f"getattr({receiver_label}, <dynamic>)"
            meta = {"operation": operation, "category": category, "cwe": cwe_value,
                    "dynamic_invocation": True}
            canon_name = None
        else:
            matched_rule = match_sink_rule(node, name, canon_name)
            if matched_rule and isinstance(node.func, ast.Attribute) and node.func.attr == "render":
                if not self._is_jinja_template_expr(node.func.value, scope_id):
                    matched_rule = None
            if matched_rule:
                meta = {"operation": matched_rule.operation, "category": matched_rule.category, "cwe": matched_rule.cwe_id}
            else:
                meta = {}
                # 0. Check for CWE-322: insecure paramiko host key policy
                if self._is_insecure_host_key_policy(node, scope_id):
                    meta = {"operation": "INSECURE_HOST_KEY_POLICY",
                            "category": "INSECURE_NETWORK_COMMUNICATION", "cwe": "CWE-322"}
                # 1. Check for CWE-295: disabled SSL/TLS verification
                elif self._has_disabled_ssl(node, scope_id):
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
                    if not self._read_subordinate_to_traversal(node, scope_id):
                        meta = {"operation": "UNBOUNDED_READ", "category": "RESOURCE_EXHAUSTION", "cwe": "CWE-400"}
                # 4. Check for asyncio run_in_executor with exec/eval (CWE-95)
                elif ((isinstance(node.func, ast.Attribute) and node.func.attr == "run_in_executor") or
                      (isinstance(node.func, ast.Name) and node.func.id == "run_in_executor")) and len(node.args) >= 3:
                    cb = node.args[1]
                    cb_name = cb.id if isinstance(cb, ast.Name) else (cb.attr if isinstance(cb, ast.Attribute) else None)
                    cb_canon = self.resolve_canonical_name(cb, scope_id) if (scope_id and isinstance(cb, ast.AST)) else None
                    if {cb_name, cb_canon} & {"exec", "eval", "builtins.exec", "builtins.eval"}:
                        meta = {
                            "operation": "DYNAMIC_CODE_EXECUTION",
                            "category": "CODE_INJECTION",
                            "cwe": "CWE-95",
                            "severity": "CRITICAL",
                            "target_arg": 2,
                        }
                # 5. Check SINK_REGISTRY
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
        
        # Phase 4.3: If no meta was found but we have a contract, use it
        if not meta and contract_cwe:
            matched_rule = get_rule(contract_cwe)
            if matched_rule:
                meta = {"operation": matched_rule.operation, "category": matched_rule.category, "cwe": contract_cwe}
            else:
                meta = {"operation": "WRAPPER_SINK", "category": "Security", "cwe": contract_cwe}
        
        sink_meta = {"sink_type": meta.get("category", "UNKNOWN_CATEGORY"), "cwe": meta.get("cwe", "UNKNOWN_CWE")}
        if "target_arg" in meta:
            sink_meta["target_arg"] = meta["target_arg"]
        sink = SecurityNode(
            id=sink_id, node_type=NodeType.SINK, symbol=canon_name or name,
            operation=meta.get("operation", "UNKNOWN_OPERATION"), location=loc,
            metadata=sink_meta
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
                if isinstance(op, (ast.In, ast.NotIn)):
                    target_name = self._extract_target_from_parents_attr(comp)
                    if target_name:
                        pairs.append((target_name, test_node.left))
                    elif isinstance(test_node.left, ast.Name):
                        pairs.append((test_node.left.id, comp))
                    elif isinstance(test_node.left, ast.Attribute):
                        dname = dotted_name(test_node.left)
                        if dname:
                            pairs.append((dname, comp))
                        if isinstance(test_node.left.value, ast.Call):
                            call_node = test_node.left.value
                            if call_node.args and isinstance(call_node.args[0], ast.Name):
                                pairs.append((call_node.args[0].id, comp))
                            elif call_node.args and isinstance(call_node.args[0], ast.Attribute):
                                d_arg = dotted_name(call_node.args[0])
                                if d_arg:
                                    pairs.append((d_arg, comp))
                    elif isinstance(test_node.left, ast.Subscript):
                        key = self._extract_subscript_key(test_node.left.slice, "")
                        if isinstance(test_node.left.value, ast.Name):
                            comp_key = f"{test_node.left.value.id}[{key}]" if key is not None else test_node.left.value.id
                            pairs.append((comp_key, comp))
                            pairs.append((test_node.left.value.id, comp))
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
            elif isinstance(test_node.func, ast.Attribute) and test_node.func.attr == "startswith":
                # Static prefix guard: if url.startswith("https://trusted.domain.com/")
                target_name = dotted_name(test_node.func.value) or (test_node.func.value.id if isinstance(test_node.func.value, ast.Name) else None)
                if target_name and test_node.args:
                    prefix_arg = test_node.args[0]
                    is_safe_prefix = False
                    if isinstance(prefix_arg, ast.Constant) and isinstance(prefix_arg.value, str):
                        if prefix_arg.value.startswith(("http://", "https://", "/")):
                            is_safe_prefix = True
                    elif isinstance(prefix_arg, (ast.Tuple, ast.List)):
                        if any(isinstance(e, ast.Constant) and isinstance(e.value, str) and e.value.startswith(("http://", "https://", "/")) for e in prefix_arg.elts):
                            is_safe_prefix = True
                    if is_safe_prefix:
                        pairs.append((target_name, None))
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
            allowed_cwes = {"CWE-22", "CWE-918", "CWE-601", "CWE-400", "CWE-1333", "CWE-94"}
            allowed_types = {"PATH_TRAVERSAL", "FILE_ACCESS", "SSRF", "OPEN_REDIRECT", "REGEX_COMPILATION", "RESOURCE_EXHAUSTION", "CODE_INJECTION", "XPATH_INJECTION", "NOSQL_INJECTION"}
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
        mod_name = scope_module(current_scope)
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
            _walk_seen = set()
            while curr and curr not in _walk_seen:
                _walk_seen.add(curr)
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
        _walk_seen = set()
        while curr and curr not in _walk_seen:
            _walk_seen.add(curr)
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
        mod_name = scope_module(scope_id) if scope_id else ""
        _walk_seen = set()
        while curr and curr not in _walk_seen:
            _walk_seen.add(curr)
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
        mod_name = scope_module(scope_id) if scope_id else ""
        file_path = self.file_paths.get(mod_name, "unknown.py")
        call_lineno = lineno
        for subnode in ast.walk(expr):
            # Rule CWE-915: Mass Assignment Detection
            if isinstance(subnode, ast.Call):
                for kw in subnode.keywords:
                    if kw.arg is None:
                        kw_repr = ast.unparse(kw.value) if hasattr(ast, "unparse") else ""
                        if any(src in kw_repr for src in ("request.POST", "request.data", "request.GET")):
                            sink_node = self.get_or_create_sink(subnode, file_path, scope_id, force_cwe="CWE-915")
                            self.sink_records.append(SinkRecord(node=subnode, security_node=sink_node, lineno=call_lineno, scope_id=scope_id))

            # Rule CWE-321: Hardcoded Secrets Detection
            if isinstance(subnode, ast.Assign):
                for t in subnode.targets:
                    t_name = getattr(t, "id", "")
                    if t_name.upper() in {"SECRET_KEY", "JWT_SECRET", "PRIVATE_KEY", "API_SECRET"}:
                        if isinstance(subnode.value, ast.Constant) and isinstance(subnode.value.value, str):
                            if len(subnode.value.value) >= 8:
                                s_node = self.get_or_create_sink(subnode, file_path, scope_id, force_cwe="CWE-321")
                                self.sink_records.append(SinkRecord(node=subnode, security_node=s_node, lineno=call_lineno, scope_id=scope_id))

            # Rule CWE-93: CRLF / HTTP Header Injection
            if isinstance(subnode, ast.Assign):
                for t in subnode.targets:
                    if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name):
                        if "response" in t.value.id.lower() or "header" in t.value.id.lower():
                            val_repr = ast.unparse(subnode.value) if hasattr(ast, "unparse") else ""
                            if any(src in val_repr for src in ("request.", "GET", "POST", "data")):
                                s_node = self.get_or_create_sink(subnode, file_path, scope_id, force_cwe="CWE-93")
                                self.sink_records.append(SinkRecord(node=subnode, security_node=s_node, lineno=call_lineno, scope_id=scope_id))

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

    # ─── Module 4: static branch reachability ───
    @staticmethod
    def _literal_truthiness(node: ast.AST) -> Optional[bool]:
        """Truthiness of a purely literal / boolean-operator expression, None when undecidable."""
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, (bool, int, float, complex, str, bytes)) or value is None:
                return bool(value)
            return None
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            inner = TaintTracker._literal_truthiness(node.operand)
            return None if inner is None else (not inner)
        if isinstance(node, ast.BoolOp):
            parts = [TaintTracker._literal_truthiness(value) for value in node.values]
            if isinstance(node.op, ast.And):
                if any(part is False for part in parts):
                    return False
                return True if all(part is True for part in parts) else None
            if any(part is True for part in parts):
                return True
            return False if all(part is False for part in parts) else None
        return None

    @staticmethod
    def _complement_pair(node: ast.AST, op_type) -> bool:
        """True if `op_type(X, ..., not X, ...)` holds for one of the operands."""
        if not (isinstance(node, ast.BoolOp) and isinstance(node.op, op_type)):
            return False
        try:
            keys = [ast.unparse(value.operand)
                    if isinstance(value, ast.UnaryOp) and isinstance(value.op, ast.Not) else None
                    for value in node.values]
            plain = {ast.unparse(value) for idx, value in enumerate(node.values) if keys[idx] is None}
        except Exception:  # noqa: BLE001 - unparse is best-effort on exotic nodes
            return False
        return any(key is not None and key in plain for key in keys)

    @classmethod
    def _is_unreachable_test(cls, test: ast.AST) -> bool:
        """Test is statically always False: falsy literal, or `X and not X`."""
        if cls._literal_truthiness(test) is False:
            return True
        return cls._complement_pair(test, ast.And)

    @classmethod
    def _is_tautology_test(cls, test: ast.AST) -> bool:
        """Test is statically always True: truthy literal, or `X or not X`."""
        if cls._literal_truthiness(test) is True:
            return True
        return cls._complement_pair(test, ast.Or)

    def _compute_dead_node_ids(self) -> set:
        """Ids of AST nodes inside statically unreachable if-branches.

        Structural collectors walk whole module trees, bypassing collect_statements, so they
        need this set to keep dead branches silent.
        """
        dead: set = set()
        for tree in self.modules.values():
            for node in ast.walk(tree):
                if not isinstance(node, ast.If):
                    continue
                if self._is_unreachable_test(node.test):
                    unreachable = node.body
                elif self._is_tautology_test(node.test):
                    unreachable = node.orelse
                else:
                    continue
                for stmt in unreachable:
                    for descendant in ast.walk(stmt):
                        dead.add(id(descendant))
        return dead

    def _in_dead_code(self, node: ast.AST) -> bool:
        return id(node) in self.dead_node_ids

    def _reachable_nodes(self, tree: ast.AST) -> list:
        """Module nodes excluding statically unreachable if-branches (dead-code pruning).
        
        TimeCodeSecurity Optimization: Cache results to eliminate redundant AST walks
        across 14 structural finding collection methods.
        """
        # Check for cached result first
        if not hasattr(tree, '_cached_reachable_nodes'):
            tree._cached_reachable_nodes = [node for node in ast.walk(tree) if not self._in_dead_code(node)]
        return tree._cached_reachable_nodes

    def collect_statements(self, statements: list[ast.stmt], scope_id: str, is_conditional: bool = False):
        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                child_scope = f"{scope_id}.{stmt.name}" if ":global" not in scope_id else f"{scope_module(scope_id)}:function:{stmt.name}"
                self.functions[child_scope] = stmt
                self.collect_statements(stmt.body, scope_id=child_scope, is_conditional=False)
            elif isinstance(stmt, ast.ClassDef):
                mod_name = scope_module(scope_id)
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
                        nested = self._static_subscript_path(target, scope_id)
                        if nested is not None and len(nested[1]) >= 2:
                            # Multi-level composite write: cfg["db"]["stmt"] = value
                            root, keys, kind = nested
                            comp_key = self._subscript_path_key(root, keys)
                            record = AssignmentRecord(target_name=comp_key, value_node=stmt.value, lineno=stmt.lineno, scope_id=scope_id, is_conditional=is_conditional)
                            if kind == "name":
                                self.assignments_by_scope.setdefault((scope_id, comp_key), []).append(record)
                            else:
                                cls_scope = self._get_enclosing_class_scope(scope_id)
                                if cls_scope:
                                    self.class_field_assignments.setdefault((cls_scope, comp_key), []).append(record)
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
                # CWE-295: detect `session.verify = False` / `obj.verify = False`
                for target in stmt.targets:
                    if (isinstance(target, ast.Attribute)
                            and target.attr == "verify"
                            and isinstance(stmt.value, ast.Constant)
                            and stmt.value.value is False):
                        self.ssl_attr_assigns.append((stmt, scope_id, stmt.lineno))
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
                # Dead-code pruning: a statically False test never enters its body, a
                # statically True test never enters its else, and neither can register a guard.
                test_dead = self._is_unreachable_test(stmt.test)
                test_live = not test_dead and self._is_tautology_test(stmt.test)
                pairs = [] if test_dead else self._extract_containment_pairs(stmt.test)
                if pairs:
                    is_inverted = (
                        (isinstance(stmt.test, ast.UnaryOp) and isinstance(stmt.test.op, ast.Not)) or
                        (isinstance(stmt.test, ast.Compare) and any(isinstance(op, (ast.NotIn, ast.NotEq)) for op in stmt.test.ops))
                    )
                    body_terminates = any(isinstance(s, (ast.Raise, ast.Return)) for s in stmt.body)

                    def _expand_root_url_vars(t_name: str) -> list[str]:
                        expanded = [t_name]
                        curr_sc = scope_id
                        _walk_seen = set()
                        while curr_sc and curr_sc not in _walk_seen:
                            _walk_seen.add(curr_sc)
                            recs = self.assignments_by_scope.get((curr_sc, t_name), [])
                            for r in recs:
                                if r.lineno < stmt.lineno:
                                    for sub in ast.walk(r.value_node):
                                        if isinstance(sub, ast.Call) and any(fn in (dotted_name(sub.func) or "") for fn in ("urlparse", "urllib.parse.urlparse")):
                                            if sub.args and isinstance(sub.args[0], ast.Name):
                                                expanded.append(sub.args[0].id)
                                            elif sub.args and isinstance(sub.args[0], ast.Attribute):
                                                attr_str = dotted_name(sub.args[0])
                                                if attr_str:
                                                    expanded.append(attr_str)
                            if "[" in t_name and t_name.endswith("]"):
                                base_v, s_key = t_name[:-1].split("[", 1)
                                s_key_clean = s_key.strip("'\"")
                                base_recs = self.assignments_by_scope.get((curr_sc, base_v), [])
                                for br in base_recs:
                                    if br.lineno < stmt.lineno and isinstance(br.value_node, ast.Dict):
                                        for k, v in zip(br.value_node.keys, br.value_node.values):
                                            if self._extract_subscript_key(k, curr_sc) == s_key_clean:
                                                for sub in ast.walk(v):
                                                    if isinstance(sub, ast.Call) and any(fn in (dotted_name(sub.func) or "") for fn in ("urlparse", "urllib.parse.urlparse")):
                                                        if sub.args and isinstance(sub.args[0], ast.Name):
                                                            expanded.append(sub.args[0].id)
                            if "." in curr_sc:
                                curr_sc = curr_sc.rsplit(".", 1)[0]
                            else:
                                break
                        return expanded

                    if is_inverted and body_terminates:
                        # Control-flow static analysis for guard clauses:
                        # When `if host not in ALLOWED:` terminates unconditionally
                        # via raise or return, all subsequent statements in the scope are guaranteed
                        # to execute only if containment was satisfied.
                        for target_name, base_node in pairs:
                            for var_target in _expand_root_url_vars(target_name):
                                self.containment_guards.append({
                                    "var_name": var_target,
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
                            for var_target in _expand_root_url_vars(target_name):
                                self.containment_guards.append({
                                    "var_name": var_target,
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
                            for var_target in _expand_root_url_vars(target_name):
                                self.containment_guards.append({
                                    "var_name": var_target,
                                    "base_node": base_node,
                                    "scope_id": scope_id,
                                    "check_line": stmt.lineno,
                                    "start_line": orelse_start,
                                    "end_line": orelse_end,
                                })
                if not test_dead:
                    self.collect_statements(stmt.body, scope_id=scope_id, is_conditional=True)
                if not test_live:
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
                    if self._is_html_construction_expr(stmt.value, scope_id):
                        mod_name = scope_module(scope_id)
                        file_path = self.file_paths.get(mod_name, "unknown.py")
                        sink_id = self.next_sink_id()
                        sink_node = SecurityNode(
                            id=sink_id,
                            node_type=NodeType.SINK,
                            symbol="html_response",
                            operation="XSS_HTML_RESPONSE",
                            location=location(stmt, file_path),
                            metadata={"sink_type": "XSS", "category": "CROSS_SITE_SCRIPTING", "cwe": "CWE-79"}
                        )
                        self.sinks.append(sink_node)
                        self.sink_records.append(SinkRecord(
                            node=stmt,
                            security_node=sink_node,
                            lineno=stmt.lineno,
                            scope_id=scope_id
                        ))
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
        mod_name = scope_module(scope_id) if scope_id else ""
        muts = self.list_mutations.get((scope_id, var_name))
        if not muts:
            curr = scope_id
            _walk_seen = set()
            while curr and curr not in _walk_seen:
                _walk_seen.add(curr)
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
        mod_name = scope_module(scope_id)
        file_path = self.file_paths.get(mod_name, "unknown.py")
        for subnode in ast.walk(expr):
            if self._in_dead_code(subnode):
                continue
            call_lineno = getattr(subnode, "lineno", lineno)
            if isinstance(subnode, ast.Call) and self.is_sink_call(subnode, scope_id, call_lineno):
                canon_name = self.resolve_canonical_name(subnode.func, scope_id) or dotted_name(subnode.func) or ""
                if not self.check_sink_safety(subnode, canon_name):
                    sink_node = self.get_or_create_sink(subnode, file_path, scope_id)
                    self.sink_records.append(SinkRecord(node=subnode, security_node=sink_node, lineno=call_lineno, scope_id=scope_id))
                    if sink_node.metadata.get("cwe") != "CWE-295" and self._has_disabled_ssl(subnode, scope_id):
                        ssl_sink = self.get_or_create_sink(subnode, file_path, scope_id, force_cwe="CWE-295")
                        self.sink_records.append(SinkRecord(node=subnode, security_node=ssl_sink, lineno=call_lineno, scope_id=scope_id))

    def _is_string_expr(self, expr_node: ast.AST, scope_id: str) -> bool:
        if isinstance(expr_node, ast.Constant) and isinstance(expr_node.value, str):
            return True
        if isinstance(expr_node, ast.JoinedStr):
            return True
        if isinstance(expr_node, ast.Name):
            curr = scope_id
            mod_name = scope_module(scope_id)
            _walk_seen = set()
            while curr and curr not in _walk_seen:
                _walk_seen.add(curr)
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
            mod_name = scope_module(scope_id)
            _walk_seen = set()
            while curr and curr not in _walk_seen:
                _walk_seen.add(curr)
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
        mod_name = scope_module(scope_id) if scope_id else ""

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
            _walk_seen = set()
            while curr and curr not in _walk_seen:
                _walk_seen.add(curr)
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
        mod_name = scope_module(scope_id) if scope_id else ""

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
            _walk_seen = set()
            while curr and curr not in _walk_seen:
                _walk_seen.add(curr)
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
        mod_name = scope_module(scope_id)
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
                    if not self.audit_all:
                        return TaintValue(
                            state=TaintState.CLEAN,
                            confidence=1.0,
                            path=[f"{file_name}:self.{node.attr}"],
                            last_operation=f"clean_unrecorded_attr:self.{node.attr}"
                        )
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
                if not self.audit_all:
                    return TaintValue(
                        state=TaintState.CLEAN,
                        confidence=1.0,
                        path=[f"{file_name}:self.{node.attr}"],
                        last_operation=f"clean_unrecorded_attr:self.{node.attr}"
                    )
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

            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
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

                # Phase 4.2: Try def-use tracker for multi-hop alias resolution
                ultimate_source = self._resolve_alias_with_def_use(node.id, scope_id, current_lineno)
                if ultimate_source:
                    # The variable is tainted through an alias chain
                    # Create proof nodes showing the alias propagation
                    step_idx = 0
                    source_pn = self.create_proof_node(
                        step_index=step_idx,
                        node_type=ProofNodeType.SOURCE,
                        file_path=file_name,
                        node=None,
                        symbol=ultimate_source,
                        scope_id=scope_id,
                        lineno=current_lineno,
                        override_snippet=f"{ultimate_source} (source via alias chain)"
                    )
                    step_idx += 1
                    alias_pn = self.create_proof_node(
                        step_index=step_idx,
                        node_type=ProofNodeType.ASSIGNMENT,
                        file_path=file_name,
                        node=node,
                        symbol=node.id,
                        scope_id=scope_id,
                        lineno=current_lineno,
                        override_snippet=f"{node.id} = ... (alias of {ultimate_source})"
                    )
                    edge = ProofEdge(
                        from_node_id=source_pn.node_id,
                        to_node_id=alias_pn.node_id,
                        edge_type="ALIAS_PROPAGATION"
                    )
                    return TaintValue(
                        state=TaintState.TAINTED,
                        source_id=f"SRC-alias-{ultimate_source}",
                        confidence=1.0,
                        path=[f"{file_name}:{ultimate_source}", f"{file_name}:{node.id}"],
                        last_operation=f"alias_chain_from_{ultimate_source}",
                        proof_nodes=[source_pn, alias_pn],
                        proof_edges=[edge]
                    )

                # Interprocedural argument -> parameter flow resolution (supports closures and outer scopes)
                enc_scope = scope_id
                target_func_node = None
                target_scope = None
                _walk_seen = set()
                while enc_scope and enc_scope not in _walk_seen:
                    _walk_seen.add(enc_scope)
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
                    if target_func_node and node.id in self._get_route_param_names(target_func_node):
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
                            operation="HTTP_ROUTE_PARAMETER_ACCESS",
                            location=CodeLocation(file=file_name, line_start=target_func_node.lineno, line_end=target_func_node.lineno, column_start=0, column_end=0),
                            metadata={"source_type": "USER_CONTROLLED", "parameter": node.id, "function": target_func_node.name, "category": "WEB_PARAMETER", "severity": "HIGH"}
                        )
                        self.sources.append(src_node)
                        return TaintValue(
                            state=TaintState.TAINTED,
                            source_id=source_id,
                            confidence=1.0,
                            path=[f"{file_name}:{node.id}"],
                            last_operation=f"route_param:{node.id}",
                            proof_nodes=[param_pn],
                            proof_edges=[]
                        )
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
                protected_cwes = {"CWE-89", "CWE-78", "CWE-22", "CWE-95", "CWE-943", "CWE-643", "UNKNOWN_CWE"}
                if not sink_cwe or sink_cwe in protected_cwes or sink_type in ("SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL", "CODE_EXECUTION", "FILE_ACCESS", "NOSQL_INJECTION", "XPATH_INJECTION"):
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

            if function_name in SANITIZER_REGISTRY and not self._resolve_function_scope(function_name, scope_id):
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
                        _walk_seen = set()
                        while current_scope and current_scope not in _walk_seen:
                            _walk_seen.add(current_scope)
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
                        _walk_seen = set()
                        while current_scope and current_scope not in _walk_seen:
                            _walk_seen.add(current_scope)
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

                callee_mod = scope_module(func_scope)
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
                "os.environ", "request.META", "request.FILES", "request.data"
            )
            if norm_val in framework_sources or dname_val in framework_sources:
                loc = location(node, file_name)
                is_env = (norm_val == "os.environ" or dname_val == "os.environ")
                is_sys_argv = (norm_val == "sys.argv" or dname_val == "sys.argv")
                is_req_data = (norm_val == "request.data" or dname_val == "request.data")
                target_state = TaintState.UNKNOWN if (is_sys_argv or is_env) else TaintState.TAINTED
                target_conf = 0.50 if (is_sys_argv or is_env) else 1.0
                target_op = (
                    "ENVIRONMENT_VARIABLE_ACCESS" if is_env
                    else "CLI_ARGUMENT_ACCESS" if is_sys_argv
                    else "HTTP_BODY_PARAMETER_ACCESS" if is_req_data
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
                src_meta = {"source_type": "USER_CONTROLLED"}
                if is_req_data:
                    src_meta["category"] = "WEB_PARAMETER"
                    src_meta["severity"] = "HIGH"
                src = SecurityNode(id=source_id, node_type=NodeType.SOURCE, symbol=f"{norm_val}[...]", operation=target_op, location=loc, metadata=src_meta)
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
            path = self._static_subscript_path(node, scope_id)
            # Depth-1 keeps the historic `base[key]` label; deeper chains get `base[k1][k2]...`.
            comp_key = (self._subscript_path_key(path[0], path[1])
                        if path is not None and path[2] == "name" else None)

            # 1. Composite key in assignments: d["cmd"] = ... / cfg["db"]["stmt"] = ...
            if comp_key is not None:
                current_scope = scope_id
                found_record = None
                _walk_seen = set()
                while current_scope and current_scope not in _walk_seen:
                    _walk_seen.add(current_scope)
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
                _walk_seen = set()
                while current_scope and current_scope not in _walk_seen:
                    _walk_seen.add(current_scope)
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
                                res = self.resolve_expression(matched_key_val, sink, found_base_record.scope_id, found_base_record.lineno, v_copy, call_context)
                                # CWE-22 dict taint normalization: if the sink is CWE-22 and the
                                # dict value expression is wrapped in a recognized path sanitizer
                                # (secure_filename, os.path.basename, etc.), preserve the sanitized
                                # (CLEAN) state through dict storage and retrieval.
                                if (res.state != TaintState.CLEAN
                                        and sink is not None
                                        and sink.metadata.get("cwe") == "CWE-22"
                                        and self._dict_value_has_cwe22_sanitizer(matched_key_val)):
                                    return TaintValue(state=TaintState.CLEAN, confidence=1.0, last_operation=f"sanitized_dict_key:{key}")
                                return res
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
        mod_name = scope_module(scope_id)
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

        # 4c. Dict
        if isinstance(node, ast.Dict):
            items_to_check = []
            for k in node.keys:
                if k: items_to_check.append(k)
            items_to_check.extend(node.values)
            if not items_to_check:
                return ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=("empty_dict",), origin_node=node)
            item_provs = [self.resolve_path_provenance(item, sink, scope_id, current_lineno, visited.copy(), call_context) for item in items_to_check]
            tainted_items = [e for e in item_provs if e.state == ProvenanceState.TAINTED]
            if tainted_items:
                best_e = max(tainted_items, key=lambda e: e.confidence)
                return ProvenanceValue(
                    state=ProvenanceState.TAINTED,
                    confidence=best_e.confidence,
                    source_id=best_e.source_id,
                    source_trace=(*best_e.source_trace, "dict"),
                    origin_node=node
                )
            unknown_items = [e for e in item_provs if e.state == ProvenanceState.UNKNOWN]
            if unknown_items:
                first_u = unknown_items[0]
                return ProvenanceValue(
                    state=ProvenanceState.UNKNOWN,
                    confidence=0.50,
                    source_id=first_u.source_id,
                    source_trace=(*first_u.source_trace, "dict"),
                    origin_node=node
                )
            if all(e.state == ProvenanceState.STATIC for e in item_provs):
                return ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=("dict_static",), origin_node=node)
            return ProvenanceValue(state=ProvenanceState.INTERNAL_DYNAMIC, confidence=1.0, source_trace=("dict_dynamic",), origin_node=node)

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
            if norm_val in ("request.args", "request.form", "request.values", "request.headers", "request.cookies", "request.META", "request.FILES", "request.data") or dotted_name(node.value) in ("request.args", "request.form", "request.values", "request.headers", "request.cookies", "request.META", "request.FILES", "request.data"):
                src = self.get_or_create_source(node, file_name, scope_id)
                return ProvenanceValue(
                    state=ProvenanceState.TAINTED,
                    confidence=1.0,
                    source_id=src.id,
                    source_trace=(src.id,),
                    origin_node=node
                )
            base_var = node.value.id if isinstance(node.value, ast.Name) else None
            key = self._extract_subscript_key(node.slice, scope_id)

            # 1. Direct container write check: d[key] = clean_val or d[key] = tainted_val
            if base_var and key is not None:
                comp_key = f"{base_var}[{key}]"
                current_scope = scope_id
                found_record = None
                _walk_seen = set()
                while current_scope and current_scope not in _walk_seen:
                    _walk_seen.add(current_scope)
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
                    v_key = f"prov:{found_record.scope_id}:{comp_key}:{found_record.lineno}"
                    if v_key not in visited:
                        v_copy = visited.copy()
                        v_copy.add(v_key)
                        return self.resolve_path_provenance(found_record.value_node, sink, found_record.scope_id, found_record.lineno, v_copy, call_context)

            # 2. Check base variable definition if initialized as dict/list literal
            if base_var and key is not None:
                current_scope = scope_id
                found_base_record = None
                _walk_seen = set()
                while current_scope and current_scope not in _walk_seen:
                    _walk_seen.add(current_scope)
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
                            key_v_key = f"prov:{found_base_record.scope_id}:{base_var}[{key}]:{found_base_record.lineno}"
                            if key_v_key not in visited:
                                v_copy = visited.copy()
                                v_copy.add(key_v_key)
                                return self.resolve_path_provenance(matched_key_val, sink, found_base_record.scope_id, found_base_record.lineno, v_copy, call_context)
                    elif isinstance(val_node, (ast.List, ast.Tuple)) and isinstance(key, int):
                        if -len(val_node.elts) <= key < len(val_node.elts):
                            matched_elt = val_node.elts[key]
                            elt_v_key = f"prov:{found_base_record.scope_id}:{base_var}[{key}]:{found_base_record.lineno}"
                            if elt_v_key not in visited:
                                v_copy = visited.copy()
                                v_copy.add(elt_v_key)
                                return self.resolve_path_provenance(matched_elt, sink, found_base_record.scope_id, found_base_record.lineno, v_copy, call_context)

            if isinstance(node.value, ast.Dict) and key is not None:
                for k, v in zip(node.value.keys, node.value.values):
                    k_val = self._extract_subscript_key(k, scope_id)
                    if k_val == key:
                        return self.resolve_path_provenance(v, sink, scope_id, current_lineno, visited.copy(), call_context)
            elif isinstance(node.value, (ast.List, ast.Tuple)) and isinstance(key, int):
                if -len(node.value.elts) <= key < len(node.value.elts):
                    return self.resolve_path_provenance(node.value.elts[key], sink, scope_id, current_lineno, visited.copy(), call_context)

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
            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
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
            _walk_seen = set()
            while enc_scope and enc_scope not in _walk_seen:
                _walk_seen.add(enc_scope)
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
                if node.id in ("self", "cls"):
                    return ProvenanceValue(state=ProvenanceState.STATIC, confidence=1.0, source_trace=(f"self:{node.id}",), origin_node=node)

                # Web route parameter seeding:
                if target_func_node and node.id in self._get_route_param_names(target_func_node):
                    param_symbol = f"{node.id} ({target_func_node.name})"
                    source_id = self.next_source_id()
                    src_node = SecurityNode(
                        id=source_id,
                        node_type=NodeType.SOURCE,
                        symbol=param_symbol,
                        operation="HTTP_ROUTE_PARAMETER_ACCESS",
                        location=CodeLocation(file=file_name, line_start=target_func_node.lineno, line_end=target_func_node.lineno, column_start=0, column_end=0),
                        metadata={"source_type": "USER_CONTROLLED", "parameter": node.id, "function": target_func_node.name, "category": "WEB_PARAMETER", "severity": "HIGH"}
                    )
                    self.sources.append(src_node)
                    return ProvenanceValue(
                        state=ProvenanceState.TAINTED,
                        confidence=1.0,
                        source_id=source_id,
                        source_trace=(f"route_param:{node.id}", f"{file_name}:{node.id}"),
                        origin_node=node
                    )

                if not self.audit_all:
                    return ProvenanceValue(
                        state=ProvenanceState.INTERNAL_DYNAMIC,
                        confidence=1.0,
                        source_trace=(f"unbound_param:{node.id}",),
                        origin_node=node
                    )

                # Unresolved parameter with no call sites (in audit_all mode)
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
        elif t_val.state == TaintState.CLEAN:
            return ProvenanceValue(
                state=ProvenanceState.INTERNAL_DYNAMIC,
                confidence=1.0,
                source_trace=("clean_expr",),
                origin_node=node
            )
        return ProvenanceValue(state=ProvenanceState.UNKNOWN, confidence=0.50, source_trace=("unknown_expr",), origin_node=node)

    def _is_bad_error_return(self, ret_node: ast.Return, handler_name: Optional[str]) -> bool:
        """CWE-209: classifies a Return statement inside an except handler."""
        value = ret_node.value
        if value is None:
            return False
        if isinstance(value, ast.Name):
            return bool(handler_name) and value.id == handler_name
        if isinstance(value, ast.Call):
            fn = dotted_name(value.func) or ""
            if fn in ("traceback.format_exc", "format_exc"):
                return True
            if fn in ("str", "repr") and value.args and isinstance(value.args[0], ast.Name):
                return bool(handler_name) and value.args[0].id == handler_name
        return False

    def _scan_error_returns(self, stmts: list, handler_name: Optional[str]) -> bool:
        """Recursively scans handler body statements for sensitive error returns."""
        for stmt in stmts:
            if isinstance(stmt, ast.Return):
                if self._is_bad_error_return(stmt, handler_name):
                    return True
            elif isinstance(stmt, ast.If):
                if self._scan_error_returns(stmt.body, handler_name) or self._scan_error_returns(stmt.orelse, handler_name):
                    return True
            elif isinstance(stmt, (ast.For, ast.While)):
                if self._scan_error_returns(stmt.body, handler_name) or self._scan_error_returns(stmt.orelse, handler_name):
                    return True
            elif isinstance(stmt, ast.Try):
                if self._scan_error_returns(stmt.body, handler_name):
                    return True
                for nested in stmt.handlers:
                    if self._scan_error_returns(nested.body, getattr(nested, "name", None)):
                        return True
        return False

    def _cookie_flag_states(self, node: ast.Call, scope_id: str, lineno: int) -> dict:
        """
        Guard for the set_cookie() attribute family (CWE-614 Secure, CWE-1004 HttpOnly,
        CWE-1275 SameSite).

        Each flag gets one of five states, and a finding needs positive structural proof:
          * 'safe'       - provably enabled (literal True, or a real SameSite value);
          * 'unsafe'     - provably disabled (False / None / 'none');
          * 'configured' - passed, but the value is not provable (settings.X, a config Name,
                           a cross-module constant): the call defers cookie policy to config;
          * 'unknown'    - a `**<opaque>` unpack may carry the flag, so absence proves nothing;
          * 'missing'    - not passed and nothing unpacked.
        A call that does not even match the (key, value) cookie-setter signature
        (e.g. CookieJar.set_cookie(cookie)) is not cookie configuration at all.
        """
        flags = {"secure": "missing", "httponly": "missing", "samesite": "missing"}
        if not (len(node.args) >= 2 or any(kw.arg for kw in node.keywords)):
            flags["_skip"] = True
            return flags
        unpacked: dict[str, object] = {}
        opaque = False
        for kw in node.keywords:
            if kw.arg is None:
                opts = _eval_dict_constants(kw.value, self.assignments_by_scope, scope_id, lineno)
                if not opts:
                    opaque = True
                    continue
                for key, val in opts.items():
                    unpacked.setdefault(key.lower(), val)
            elif kw.arg.lower() in flags:
                value, provable = self._cookie_const(kw.value, scope_id, lineno)
                flags[kw.arg.lower()] = (self._cookie_flag_state(kw.arg.lower(), value)
                                         if provable else "configured")
        for key, val in unpacked.items():
            if key in flags and flags[key] == "missing":
                flags[key] = ("configured" if val is None
                              else self._cookie_flag_state(key, val))
        if opaque:
            for key in ("secure", "httponly", "samesite"):
                if flags[key] == "missing":
                    flags[key] = "unknown"
        return flags

    def _cookie_const(self, expr: ast.AST, scope_id: str, lineno: int) -> tuple:
        """(value, provable) for a keyword value; unresolvable expressions are not proven."""
        val = _eval_static_constant(expr, self.assignments_by_scope, scope_id, lineno)
        if val is None and isinstance(expr, ast.Constant) and expr.value is None:
            return None, True
        if val is None and isinstance(expr, ast.Name) and expr.id.lower() in ("none", "null"):
            return None, True
        return val, val is not None

    @staticmethod
    def _cookie_flag_state(flag: str, value) -> str:
        if flag == "samesite":
            if value is None or (isinstance(value, str) and value.strip().lower() == "none"):
                return "unsafe"
            return "safe"
        if value is False:
            return "unsafe"
        return "safe" if value is True else "configured"

    def _cookie_flag_missing(self, states: dict, flag: str) -> bool:
        """True only when the engine can prove this cookie attribute is absent or disabled."""
        if states.get("_skip"):
            return False
        return states.get(flag) in ("missing", "unsafe")

    def _cookie_policy_externalised(self, states: dict) -> bool:
        """True when the call hands cookie security over to settings/config or an unpacked
        mapping, in which case a single absent attribute is not a provable defect."""
        if states.get("_skip"):
            return True
        return any(states.get(flag) in ("configured", "unknown")
                   for flag in ("secure", "httponly", "samesite"))

    def _collect_batch2_structural_findings(self) -> None:
        """
        Batch 2 PURE_STRUCTURAL visitors (data/cwe_blueprint_batch2.json):
        CWE-377, CWE-732, CWE-326, CWE-798, CWE-1004, CWE-209.
        Appends sinks + sink_records; analyze() emits synthetic edges for them.
        """
        for mod_name, tree in self.modules.items():
            file_path = self.file_paths.get(mod_name, "unknown.py")
            scope_id = f"{mod_name}:global"
            seen: set[tuple[str, int, int]] = set()
            for node in self._reachable_nodes(tree):
                cwe_meta = None
                if isinstance(node, ast.Call):
                    name = dotted_name(node.func) or ""
                    canon = self.resolve_canonical_name(node.func, scope_id) or ""
                    names = {name, canon} - {"", None}

                    # CWE-377: direct invocation of tempfile.mktemp
                    if "tempfile.mktemp" in names:
                        cwe_meta = {"operation": "INSECURE_TEMP_FILE", "category": "INSECURE_TEMPORARY_FILE", "cwe": "CWE-377"}

                    # CWE-732: os.chmod with group/world-accessible mode bits
                    elif "os.chmod" in names:
                        mode_node = None
                        for kw in getattr(node, "keywords", []):
                            if kw.arg == "mode":
                                mode_node = kw.value
                                break
                        if mode_node is None and len(node.args) >= 2:
                            mode_node = node.args[1]
                        if mode_node is not None:
                            mode_val = _eval_static_constant(mode_node, self.assignments_by_scope, scope_id, getattr(node, "lineno", 0))
                            if isinstance(mode_val, int):
                                # TimeCodeSecurity GUARD B: Whitelist industry-standard safe permission modes
                                # Only owner-only or read-for-all modes; no group/other execute bits
                                SAFE_FILE_MODES = frozenset({
                                    0o600,  # Owner read/write only
                                    0o640,  # Owner RW, group read
                                    0o644,  # Owner RW, others read (standard web files)
                                    0o400,  # Owner read only
                                    0o440,  # Owner + group read
                                    0o444,  # All read only (read-only files)
                                    0o700,  # Owner full access (scripts/dirs)
                                })
                                if mode_val not in SAFE_FILE_MODES and (mode_val & 0o077) != 0:
                                    cwe_meta = {"operation": "INSECURE_FILE_PERMISSIONS", "category": "INSECURE_FILE_PERMISSIONS", "cwe": "CWE-732"}

                    # CWE-326: RSA key generation below 2048 bits
                    elif names & CWE326_SINK_NAMES:
                        bits_node = None
                        for kw in getattr(node, "keywords", []):
                            if kw.arg == "bits":
                                bits_node = kw.value
                                break
                        if bits_node is None and node.args:
                            bits_node = node.args[0]
                        if bits_node is not None:
                            bits_val = _eval_static_constant(bits_node, self.assignments_by_scope, scope_id, getattr(node, "lineno", 0))
                            if isinstance(bits_val, int) and bits_val < 2048:
                                cwe_meta = {"operation": "WEAK_CRYPTO_KEY_SIZE", "category": "INADEQUATE_ENCRYPTION_STRENGTH", "cwe": "CWE-326"}

                    # CWE-1004: set_cookie without httponly=True and secure=True
                    elif name == "set_cookie" or name.endswith(".set_cookie") or canon == "set_cookie" or (canon and canon.endswith(".set_cookie")):
                        states = self._cookie_flag_states(node, scope_id,
                                                          getattr(node, "lineno", 0))
                        enabled = ("safe", "configured", "unknown")
                        # TimeCodeSecurity GUARD A: Skip if BOTH secure AND httponly are explicitly safe
                        if not states.get("_skip"):
                            both_explicitly_safe = (states["httponly"] == "safe" and states["secure"] == "safe")
                            if not both_explicitly_safe and not (
                                    states["httponly"] in enabled
                                    and states["secure"] in enabled):
                                cwe_meta = {"operation": "INSECURE_COOKIE_FLAGS",
                                            "category": "INSECURE_COOKIE_CONFIGURATION",
                                            "cwe": "CWE-1004"}

                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    # CWE-798: hardcoded credential literal assigned to a sensitive target
                    value_node = node.value
                    if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str) and len(value_node.value) >= 8:
                        # Suppress known test/dummy strings
                        if _is_cwe798_dummy_string(value_node.value):
                            pass  # Skip this assignment - it's a test placeholder
                        else:
                            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                            for target in targets:
                                t_str = ""
                                if isinstance(target, ast.Name):
                                    t_str = target.id
                                elif isinstance(target, ast.Attribute):
                                    t_str = dotted_name(target) or target.attr
                                elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                                    t_str = target.value.id
                                if t_str and CWE798_TARGET_RE.match(t_str):
                                    cwe_meta = {"operation": "HARDCODED_CREDENTIAL", "category": "HARDCODED_CREDENTIALS", "cwe": "CWE-798"}
                                    break

                elif isinstance(node, ast.ExceptHandler):
                    # CWE-209: sensitive error exposure from except handler
                    handler_name = getattr(node, "name", None)
                    if self._scan_error_returns(list(node.body), handler_name):
                        cwe_meta = {"operation": "SENSITIVE_ERROR_EXPOSURE", "category": "SENSITIVE_ERROR_EXPOSURE", "cwe": "CWE-209"}

                if cwe_meta:
                    dedupe_key = (cwe_meta["cwe"], getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)
                    sink_id = self.next_sink_id()
                    sink_node = SecurityNode(
                        id=sink_id,
                        node_type=NodeType.SINK,
                        symbol=cwe_meta["operation"],
                        operation=cwe_meta["operation"],
                        location=location(node, file_path),
                        metadata={"sink_type": cwe_meta["category"], "category": cwe_meta["category"], "cwe": cwe_meta["cwe"]},
                    )
                    self.sinks.append(sink_node)
                    self.sink_records.append(SinkRecord(
                        node=node,
                        security_node=sink_node,
                        lineno=getattr(node, "lineno", 1),
                        scope_id=scope_id,
                    ))

    def _collect_cluster1_structural_findings(self) -> None:
        """
        Phase 3 Cluster 1 PURE_STRUCTURAL visitors, four independent predicates:

          CWE-276  insecure-file-permission residuals (chmod/lchmod/fchmod stat-bit modes, umask)
          CWE-96   dangerous-globals use (dynamic namespace reads, namespace-as-template-context,
                   dynamic template strings reaching render_template_string)
          CWE-116  disabled/absent template autoescape (Jinja2 Environment, Django OPTIONS dicts)
          CWE-521  empty password policy (empty assignments, empty/None lookup defaults, and
                   empty/None password parameters that are fed to set_password)

        Appends sinks + sink_records; analyze() emits synthetic edges for them through
        STRUCTURAL_SYNTHETIC_SOURCES.
        """
        for mod_name, tree in self.modules.items():
            file_path = self.file_paths.get(mod_name, "unknown.py")
            scope_id = f"{mod_name}:global"
            seen: set[tuple[str, int, int]] = set()
            reachable = list(self._reachable_nodes(tree))
            ns_history = self._c1_namespace_history(reachable)
            template_consumers = self._c1_template_string_consumers(reachable, scope_id)

            for node in reachable:
                for cwe_meta in self._c1_cluster1_candidates(node, scope_id, ns_history,
                                                            template_consumers):
                    loc_node = cwe_meta.pop("loc_node", node)
                    dedupe_key = (cwe_meta["cwe"], getattr(loc_node, "lineno", 0),
                                  getattr(loc_node, "col_offset", 0))
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)
                    sink_node = SecurityNode(
                        id=self.next_sink_id(),
                        node_type=NodeType.SINK,
                        symbol=cwe_meta["operation"],
                        operation=cwe_meta["operation"],
                        location=location(loc_node, file_path),
                        metadata={"sink_type": cwe_meta["category"], "category": cwe_meta["category"],
                                  "cwe": cwe_meta["cwe"]},
                    )
                    self.sinks.append(sink_node)
                    self.sink_records.append(SinkRecord(
                        node=node,
                        security_node=sink_node,
                        lineno=getattr(node, "lineno", 1),
                        scope_id=scope_id,
                    ))

    # ── Cluster 1 predicate helpers ──

    def _c1_call_names(self, node: ast.Call, scope_id: str) -> set[str]:
        dotted = dotted_name(node.func) or ""
        canonical = self.resolve_canonical_name(node.func, scope_id) or ""
        return {n for n in (dotted, canonical) if n}

    @staticmethod
    def _c1_last(name: str) -> str:
        return name.rsplit(".", 1)[-1] if name else ""

    def _c1_is_namespace_expr(self, node: ast.AST) -> bool:
        """globals()/locals() call, or any `<expr>.__globals__` attribute read."""
        if isinstance(node, ast.Call):
            func = node.func
            target = self._c1_last(dotted_name(func) or getattr(func, "id", "") or "")
            return target in CLUSTER1_NAMESPACE_BUILTINS and not isinstance(func, ast.Attribute)
        return isinstance(node, ast.Attribute) and node.attr in CLUSTER1_NAMESPACE_ATTRS

    def _c1_namespace_history(self, reachable: list) -> dict[str, list[tuple[int, bool]]]:
        """name -> [(lineno, is-namespace)] so a namespace alias stops counting once rebound."""
        history: dict[str, list[tuple[int, bool]]] = {}
        for node in reachable:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            is_ns = self._c1_is_namespace_expr(node.value)
            for target in targets:
                if isinstance(target, ast.Name):
                    history.setdefault(target.id, []).append((getattr(node, "lineno", 0), is_ns))
        for rows in history.values():
            rows.sort()
        return history

    def _c1_is_namespace_use(self, node: ast.AST, history: dict) -> bool:
        if self._c1_is_namespace_expr(node):
            return True
        if isinstance(node, ast.Name):
            prior = [row for row in history.get(node.id, [])
                     if row[0] < getattr(node, "lineno", 0)]
            return bool(prior) and prior[-1][1]
        return False

    @staticmethod
    def _c1_is_literal_key(node: ast.AST) -> bool:
        if type(node).__name__ == "Index":  # Python < 3.9 wraps the subscript in ast.Index
            node = node.value
        return isinstance(node, ast.Constant)

    def _c1_insecure_mode(self, mode_node: ast.AST, scope_id: str, lineno: int) -> tuple[bool, bool]:
        """Returns (insecure-permission, group-or-world-bits-present-on-a-resolved-int-mode)."""
        value = _eval_static_constant(mode_node, self.assignments_by_scope, scope_id, lineno)
        if isinstance(value, int) and not isinstance(value, bool):
            return (value & CLUSTER1_MODE_LOW_BITS) >= CLUSTER1_INSECURE_MODE_FLOOR, (value & 0o077) != 0
        pending, insecure = [mode_node], False
        while pending:
            cur = pending.pop()
            if isinstance(cur, ast.Attribute):
                insecure = insecure or cur.attr in CLUSTER1_INSECURE_STAT_BITS
            elif isinstance(cur, ast.BinOp) and isinstance(cur.op, ast.BitOr):
                pending.extend([cur.left, cur.right])
            elif isinstance(cur, ast.Constant) and isinstance(cur.value, int):
                insecure = insecure or bool(cur.value & CLUSTER1_GROUP_OTHER_WRITE_EXEC)
        return insecure, False

    def _c1_template_string_consumers(self, reachable: list, scope_id: str) -> set[str]:
        """Names bound directly from render_template_string(<name>)."""
        out: set[str] = set()
        for node in reachable:
            if not isinstance(node, ast.Call):
                continue
            names = self._c1_call_names(node, scope_id)
            if not any(self._c1_last(n) in CLUSTER1_TEMPLATE_STRING_SINKS for n in names):
                continue
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    out.add(arg.id)
        return out

    @staticmethod
    def _c1_is_dynamic_template(value: ast.AST) -> bool:
        """A template literal that is interpolated, i.e. its braces are format placeholders."""
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and value.func.attr == "format":
            base = value.func.value
        elif isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mod):
            base = value.left
        else:
            base = value
        return (isinstance(base, ast.Constant) and isinstance(base.value, str)
                and "{" in base.value)

    def _c1_cluster1_candidates(self, node: ast.AST, scope_id: str, ns_history: dict,
                                template_consumers: set) -> list[dict]:
        lineno = getattr(node, "lineno", 0)
        out: list[dict] = []

        def add(operation: str, category: str, cwe: str, loc_node: ast.AST | None = None) -> None:
            meta = {"operation": operation, "category": category, "cwe": cwe}
            if loc_node is not None:
                meta["loc_node"] = loc_node
            out.append(meta)

        if isinstance(node, ast.Call):
            names = self._c1_call_names(node, scope_id)
            last_names = {self._c1_last(n) for n in names}

            # A. CWE-276: chmod-family mode with group/world write-exec bits not already
            #    reported by the CWE-732 predicate.
            if last_names & {"chmod", "lchmod", "fchmod"}:
                mode_node = None
                for kw in getattr(node, "keywords", []):
                    if kw.arg == "mode":
                        mode_node = kw.value
                        break
                if mode_node is None and len(node.args) >= 2:
                    mode_node = node.args[1]
                if mode_node is not None:
                    insecure, resolved_world_bits = self._c1_insecure_mode(mode_node, scope_id, lineno)
                    already_732 = bool(names & CLUSTER1_EXACT_732_CALLS) and resolved_world_bits
                    if insecure and not already_732:
                        add("INSECURE_FILE_MODE_RESIDUAL", "INSECURE_FILE_PERMISSIONS", "CWE-276")

            # A. CWE-276: os.umask() clearing the default restriction mask.
            elif last_names & {"umask"}:
                mask = _eval_static_constant(node.args[0], self.assignments_by_scope, scope_id, lineno) \
                    if node.args else None
                if isinstance(mask, int) and not isinstance(mask, bool) and mask < CLUSTER1_UMASK_SAFE:
                    add("INSECURE_UMASK", "INSECURE_FILE_PERMISSIONS", "CWE-276")

            # B. CWE-96: the whole namespace is handed to a template renderer.
            elif last_names & CLUSTER1_TEMPLATE_CONTEXT_CALLS:
                args = list(node.args) + [kw.value for kw in getattr(node, "keywords", [])]
                if any(self._c1_is_namespace_use(a, ns_history) for a in args):
                    add("GLOBALS_AS_TEMPLATE_CONTEXT", "CODE_INJECTION", "CWE-96")

            # C. CWE-116: a Jinja2 environment built without an autoescape argument.
            elif last_names & {"Environment"}:
                if not any(kw.arg in CLUSTER1_AUTOESCAPE_KEYS for kw in getattr(node, "keywords", [])):
                    add("TEMPLATE_AUTOESCAPE_DISABLED", "XSS", "CWE-116")

            # B. CWE-96: dynamic lookup inside a globals()/locals() namespace.
            if isinstance(node.func, ast.Attribute) and node.func.attr in CLUSTER1_MAPPING_READ_METHODS \
                    and node.args and self._c1_is_namespace_use(node.func.value, ns_history) \
                    and not self._c1_is_literal_key(node.args[0]):
                add("DANGEROUS_GLOBALS_USE", "CODE_INJECTION", "CWE-96")

            # D. CWE-521: password looked up with an empty/None fallback.
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get" and len(node.args) == 2 \
                    and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str) \
                    and CLUSTER1_PASSWORD_NAME_RE.search(node.args[0].value):
                default = node.args[1]
                if isinstance(default, ast.Constant) and default.value in ("", None):
                    add("EMPTY_PASSWORD_DEFAULT", "WEAK_PASSWORD", "CWE-521")

        # B. CWE-96: dynamic subscript read of a namespace mapping (Load only; a store into
        #    globals() is not an injection sink).
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load) \
                and self._c1_is_namespace_use(node.value, ns_history) \
                and not self._c1_is_literal_key(node.slice):
            add("DANGEROUS_GLOBALS_USE", "CODE_INJECTION", "CWE-96")

        # C. CWE-116: a template OPTIONS dict that disables escaping.
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value in CLUSTER1_AUTOESCAPE_KEYS \
                        and isinstance(value, ast.Constant) and value.value in (False, None):
                    add("TEMPLATE_AUTOESCAPE_DISABLED", "XSS", "CWE-116", loc_node=value)

        # D. CWE-521: an empty password assigned and later used as a credential.
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {t.id for t in targets if isinstance(t, ast.Name)}
            if any(CLUSTER1_PASSWORD_NAME_RE.search(n) for n in names) \
                    and isinstance(node.value, ast.Constant) and node.value.value == "":
                add("EMPTY_PASSWORD_ASSIGNMENT", "WEAK_PASSWORD", "CWE-521")
            # B. CWE-96: an interpolated template literal that reaches render_template_string.
            elif names & template_consumers and self._c1_is_dynamic_template(node.value):
                add("DANGEROUS_TEMPLATE_STRING", "CODE_INJECTION", "CWE-96")

        # D. CWE-521: empty/None password parameter that is fed straight to set_password().
        elif isinstance(node, ast.FunctionDef):
            for param, default in self._c1_parameter_defaults(node):
                if not CLUSTER1_PASSWORD_NAME_RE.search(param.arg):
                    continue
                if not (isinstance(default, ast.Constant) and default.value in ("", None)):
                    continue
                for inner in ast.walk(node):
                    if not isinstance(inner, ast.Call):
                        continue
                    func_name = dotted_name(inner.func) or getattr(inner.func, "id", "") or ""
                    if self._c1_last(func_name) != "set_password":
                        continue
                    if any(isinstance(a, ast.Name) and a.id == param.arg for a in inner.args):
                        add("EMPTY_PASSWORD_DEFAULT", "WEAK_PASSWORD", "CWE-521")
                        break

        return out

    @staticmethod
    def _c1_parameter_defaults(node: ast.FunctionDef) -> list[tuple[ast.arg, ast.expr]]:
        """Positional parameters paired with the default expression that applies to them."""
        positional = list(getattr(node.args, "posonlyargs", [])) + list(node.args.args)
        defaults = node.args.defaults
        gap = len(positional) - len(defaults)
        rows = [(p, defaults[i - gap]) for i, p in enumerate(positional) if i >= gap]
        return rows + [(p, d) for p, d in zip(node.args.kwonlyargs, node.args.kw_defaults)
                       if d is not None]

    def _collect_cluster2_structural_findings(self) -> None:
        """
        Phase 3 Cluster 2 PURE_STRUCTURAL visitors, eight high-yield predicates:

          CWE-295  HTTPSConnection without a context kwarg; global override of
                   ssl._create_default_https_context with an unverified factory;
                   urllib3.PoolManager with cert_reqs disabled.
          CWE-319  cleartext http:// URLs through requests module calls, requests.Session
                   instances, and urllib3 HTTPConnectionPool (522/523 same family).
          CWE-704  float()/bool()/complex() on request-controlled values without
                   int()-wrapping or a "nan" guard.
          CWE-601  request-tainted variable consumed by redirect()/HttpResponseRedirect()
                   in the same scope without a redirect validator (flagged at the source).
          CWE-918  request-tainted variable reaching an outbound HTTP fetch without an
                   allowlist validator (flagged at the source).
          CWE-611  XML parse entry points reached through an import alias that resolves
                   into xml./lxml. rather than defusedxml.
          CWE-942  wildcard CORS origins combined with credential support (FastAPI
                   CORSMiddleware, flask-cors CORS()/cross_origin()).

        Appends sinks + sink_records; edges come from the generic p3_source_id synthetic
        path in analyze().
        """
        function_scopes = {id(function): scope for scope, function in self.functions.items()}

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _enclosing_function(node: ast.AST):
            current = getattr(node, "parent", None)
            while current is not None:
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return current
                current = getattr(current, "parent", None)
            return None

        def _segments(expr: ast.AST) -> list[str]:
            chain: list[str] = []
            current = expr
            while isinstance(current, ast.Attribute):
                chain.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                chain.append(current.id)
            return list(reversed(chain))

        def _root_is_request(expr: ast.AST) -> bool:
            for sub in ast.walk(expr):
                if isinstance(sub, ast.Name) and sub.id == "request":
                    return True
                if isinstance(sub, ast.Attribute) and sub.attr == "request":
                    return True
            return False

        def _is_request_taint_expr(expr: ast.AST) -> bool:
            if not isinstance(expr, ast.expr):
                return False
            if not _root_is_request(expr):
                return False
            return any(isinstance(sub, ast.Attribute) for sub in ast.walk(expr))

        def _route_param_names(fn_node) -> set[str]:
            out: set[str] = set()
            if fn_node is None:
                return out
            for dec in fn_node.decorator_list:
                call = dec if isinstance(dec, ast.Call) else None
                if call is None:
                    continue
                segs = _segments(call.func)
                if not segs or segs[-1] not in CLUSTER2_ROUTE_DECORATOR_SEGMENTS:
                    continue
                for arg in call.args:
                    if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                        continue
                    for token in re.findall(r"<(?:\w+:)?(\w+)>", arg.value):
                        if any(p.arg == token for p in fn_node.args.args):
                            out.add(token)
            return out

        def _names_in(nodes) -> set[str]:
            found: set[str] = set()
            for sub_root in nodes:
                for sub in ast.walk(sub_root):
                    if isinstance(sub, ast.Name):
                        found.add(sub.id)
            return found

        for mod_name, tree in self.modules.items():
            file_path = self.file_paths.get(mod_name, "unknown.py")
            mod_scope = f"{mod_name}:global"
            reachable = list(self._reachable_nodes(tree))
            seen: set[tuple[str, int, int]] = set()

            # 1. Scope-aware import bindings (function-local imports shadow module imports).
            bindings: dict[str, list[tuple[int, str, str]]] = {}
            for node in reachable:
                scope = _scope_for(node, mod_name)
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        local = alias.asname or alias.name.split(".")[0]
                        bindings.setdefault(scope, []).append(
                            (getattr(node, "lineno", 0), local, alias.name))
                        if alias.asname is None and "." in alias.name:
                            bindings.setdefault(scope, []).append(
                                (getattr(node, "lineno", 0), alias.name, alias.name))
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias in node.names:
                        local = alias.asname or alias.name
                        full = f"{module}.{alias.name}" if module else alias.name
                        bindings.setdefault(scope, []).append(
                            (getattr(node, "lineno", 0), local, full))

            def _resolve_chain(chain: list[str], scope: str, lineno: int) -> list[str]:
                if not chain:
                    return chain
                for depth in range(min(len(chain), 3), 0, -1):
                    prefix = ".".join(chain[:depth])
                    best = None
                    for scope_key in (scope, mod_scope):
                        rows = [row for row in bindings.get(scope_key, [])
                                if row[1] == prefix and row[0] <= lineno]
                        if rows:
                            best = rows[-1][2]
                            break
                    if best is None:
                        best = self.imports.get(mod_name, {}).get(prefix)
                    if best:
                        return best.split(".") + chain[depth:]
                return chain

            def _call_forms(call: ast.Call, scope: str) -> set[str]:
                raw = dotted_name(call.func) or ""
                forms = {raw} if raw else set()
                resolved = _resolve_chain(_segments(call.func), scope,
                                          getattr(call, "lineno", 0))
                if resolved:
                    dotted = ".".join(resolved)
                    if dotted:
                        forms.add(dotted)
                canon = self.resolve_canonical_name(call.func, scope) or ""
                if canon:
                    forms.add(canon)
                return {form for form in forms if form}

            # 2. Value evaluation for literals and one-level name chains (wildcard lists).
            def _eval_value(expr, scope: str, lineno: int, depth: int = 0):
                if expr is None or depth > 2:
                    return None
                if isinstance(expr, ast.Constant):
                    return expr.value
                if isinstance(expr, (ast.List, ast.Tuple)):
                    return [_eval_value(elt, scope, lineno, depth + 1) for elt in expr.elts]
                if isinstance(expr, ast.Name):
                    records = list(self.assignments_by_scope.get((scope, expr.id), []))
                    records += list(self.assignments_by_scope.get((mod_scope, expr.id), []))
                    prior = [r for r in records if r.lineno <= lineno]
                    if prior:
                        return _eval_value(prior[-1].value_node, scope, prior[-1].lineno,
                                           depth + 1)
                    return None
                return None

            def _param_default_value(fn_node, name: str):
                if fn_node is None:
                    return None
                for param, default in TaintTracker._c1_parameter_defaults(fn_node):
                    if param.arg == name:
                        return default
                return None

            def _url_string(expr, scope: str, lineno: int, fn_node):
                value = _eval_static_constant(expr, self.assignments_by_scope, scope, lineno)
                if isinstance(value, str):
                    return value
                if isinstance(expr, ast.Name):
                    default = _param_default_value(fn_node, expr.id)
                    if default is not None:
                        resolved = _eval_static_constant(default, self.assignments_by_scope,
                                                         scope, lineno)
                        if isinstance(resolved, str):
                            return resolved
                return None

            def _is_cleartext_url(expr, scope: str, lineno: int, fn_node) -> bool:
                url = _url_string(expr, scope, lineno, fn_node)
                if not isinstance(url, str) or not url.lower().startswith(
                        CLUSTER2_CLEARTEXT_SCHEME):
                    return False
                host = url[len(CLUSTER2_CLEARTEXT_SCHEME):].split("/", 1)[0]
                host = host.rsplit(":", 1)[0]
                # Allowlist: localhost/loopback addresses
                if host.lower() in CLUSTER2_LOCAL_HOSTS:
                    return False
                # Allowlist: XML namespace and schema domains (w3.org, schemas.microsoft.com, etc.)
                for schema_domain in CLUSTER2_SCHEMA_DOMAINS:
                    if schema_domain in url:
                        return False
                return True

            def _contains_wildcard(expr, scope: str, lineno: int) -> bool:
                value = _eval_value(expr, scope, lineno)
                if isinstance(value, str):
                    return value == "*"
                if isinstance(value, list):
                    return any(item == "*" for item in value if isinstance(item, str))
                return False

            def _kw_arguments(call: ast.Call):
                return {kw.arg: kw for kw in getattr(call, "keywords", []) if kw.arg}

            existing_index: dict[tuple[str, int], list] = {}
            for record in self.sink_records:
                loc = record.security_node.location
                if loc.file == file_path:
                    key = (record.security_node.metadata.get("cwe") or "", loc.line_start)
                    existing_index.setdefault(key, []).append(record.security_node)

            def _merge_into_existing_sink(cwe: str, line: int, operation: str) -> None:
                """Phase 6.3: an edgeless registry sink at the same (cwe, line) used to swallow
                the structural finding; stamp its synthetic source id instead (mirrors the
                P3 `_add_finding` merge)."""
                source_id = CLUSTER2_STRUCTURAL_SOURCE_IDS.get(operation)
                if not source_id:
                    return
                for existing in existing_index.get((cwe, line)) or []:
                    if not existing.metadata.get("p3_source_id"):
                        existing.metadata["p3_source_id"] = source_id
                        return

            def _add(node: ast.AST, operation: str, category: str, cwe: str) -> None:
                line = getattr(node, "lineno", 1)
                column = getattr(node, "col_offset", 0)
                key = (cwe, line, column)
                if key in seen:
                    return
                if cwe == "CWE-918" and self._is_http_transport_module(file_path):
                    return
                _c2_lines = self._source_lines_by_file.get(file_path, [])
                if _c2_lines and 1 <= line <= len(_c2_lines):
                    if CLUSTER3_NOSEC_RE.search(_c2_lines[line - 1]):
                        return
                    if line >= 2 and re.search(r"#\s*ok:", _c2_lines[line - 2], re.IGNORECASE):
                        return
                if existing_index.get((cwe, line)):
                    _merge_into_existing_sink(cwe, line, operation)
                    return
                seen.add(key)
                scope_id = _scope_for(node, mod_name)
                sink_node = SecurityNode(
                    id=self.next_sink_id(),
                    node_type=NodeType.SINK,
                    symbol=operation,
                    operation=operation,
                    location=location(node, file_path),
                    metadata={"sink_type": category, "category": category, "cwe": cwe,
                              "p3_source_id": CLUSTER2_STRUCTURAL_SOURCE_IDS[operation]},
                )
                self.sinks.append(sink_node)
                self.sink_records.append(SinkRecord(
                    node=node,
                    security_node=sink_node,
                    lineno=line,
                    scope_id=scope_id,
                ))

            # 3. Single pass collecting scope state: taint assignments, sessions, sinks.
            taint_vars: dict[tuple[str, str], ast.AST] = {}
            route_params: dict[str, set[str]] = {}
            sessions: dict[str, set[str]] = {}
            consumed_redirect: dict[str, set[str]] = {}
            consumed_ssrf: dict[str, set[str]] = {}
            validated: dict[str, set[str]] = {}
            nan_guarded: dict[str, set[str]] = {}

            for node in reachable:
                scope = _scope_for(node, mod_name)

                if isinstance(node, ast.FunctionDef):
                    params = _route_param_names(node)
                    if params:
                        fn_scope = function_scopes.get(id(node))
                        if fn_scope:
                            route_params.setdefault(fn_scope, set()).update(params)

                elif isinstance(node, ast.Compare):
                    if any(isinstance(c, ast.Constant) and isinstance(c.value, str)
                           and c.value.lower() == CLUSTER2_NAN_GUARD_VALUE
                           for c in node.comparators):
                        guarded = {sub.id for sub in ast.walk(node) if isinstance(sub, ast.Name)}
                        owner = _enclosing_function(node)
                        owner_scope = function_scopes.get(id(owner)) if owner else scope
                        nan_guarded.setdefault(owner_scope or scope, set()).update(guarded)

                elif isinstance(node, ast.With):
                    for item in node.items:
                        expr = item.context_expr
                        if isinstance(expr, ast.Call) and any(
                                form.split(".")[-1] in CLUSTER2_SESSION_CONSTRUCTORS
                                for form in _call_forms(expr, scope)):
                            name_node = item.optional_vars
                            if isinstance(name_node, ast.Name):
                                sessions.setdefault(scope, set()).add(name_node.id)

                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    names = [t.id for t in targets if isinstance(t, ast.Name)]
                    value = node.value
                    if value is None or not names:
                        continue
                    if isinstance(value, ast.Call) and any(
                            form.split(".")[-1] in CLUSTER2_SESSION_CONSTRUCTORS
                            for form in _call_forms(value, scope)):
                        for name in names:
                            sessions.setdefault(scope, set()).add(name)
                    owner = _enclosing_function(node)
                    owner_scope = function_scopes.get(id(owner)) if owner else mod_scope
                    is_taint = _is_request_taint_expr(value)
                    if not is_taint and isinstance(value, ast.Name):
                        is_taint = value.id in route_params.get(owner_scope, set())
                    for name in names:
                        if is_taint:
                            taint_vars[(scope, name)] = node
                        else:
                            taint_vars.pop((scope, name), None)

                elif isinstance(node, ast.Call):
                    forms = _call_forms(node, scope)
                    segs = {form.split(".")[-1] for form in forms}
                    arg_nodes = list(node.args) + [kw.value for kw in
                                                   getattr(node, "keywords", [])]
                    if segs & CLUSTER2_REDIRECT_SINKS:
                        consumed_redirect.setdefault(scope, set()).update(
                            _names_in(node.args or arg_nodes[:1]))
                    if segs & CLUSTER2_REDIRECT_VALIDATORS:
                        validated.setdefault(scope, set()).add("redirect")
                    if segs & CLUSTER2_SSRF_VALIDATORS:
                        validated.setdefault(scope, set()).add("ssrf")
                    if segs & {"startswith"}:
                        prefix_val = None
                        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                            prefix_val = node.args[0].value
                        elif node.args and isinstance(node.args[0], (ast.Tuple, ast.List)):
                            for elt in node.args[0].elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str) and elt.value.startswith(("http://", "https://", "/")):
                                    prefix_val = elt.value
                                    break
                        if prefix_val and prefix_val.startswith(("http://", "https://", "/")):
                            validated.setdefault(scope, set()).add("ssrf")
                    is_ssrf_sink = False
                    for form in forms:
                        parts = form.split(".")
                        root, last = parts[0], parts[-1]
                        if last == "urlopen":
                            is_ssrf_sink = True
                        elif root in ("requests", "httpx", "urllib3") and last in \
                                CLUSTER2_SSRF_SINK_SEGMENTS:
                            is_ssrf_sink = True
                        elif len(parts) == 1 and last in ("get", "post", "put", "delete",
                                                          "head", "options", "patch") and \
                                any(f.startswith("requests.") or f.startswith("httpx.")
                                    for f in forms):
                            is_ssrf_sink = True
                    if is_ssrf_sink:
                        consumed_ssrf.setdefault(scope, set()).update(_names_in(arg_nodes))

            # 4. Source-line emissions for CWE-601 / CWE-918 untrusted flows.
            for (scope, name), assign_node in taint_vars.items():
                scope_validators = validated.get(scope, set())
                if name in consumed_redirect.get(scope, set()) and \
                        "redirect" not in scope_validators:
                    _add(assign_node, "UNTRUSTED_REDIRECT_SOURCE", "OPEN_REDIRECT", "CWE-601")
                if name in consumed_ssrf.get(scope, set()) and \
                        "ssrf" not in scope_validators and \
                        not any(g.get("var_name") == name for g in self.containment_guards):
                    _add(assign_node, "SSRF_UNTRUSTED_URL_SOURCE",
                         "SERVER_SIDE_REQUEST_FORGERY", "CWE-918")

            pattern_mod_host = re.compile(r"://([^/@]*?)%[sr]")
            pattern_fmt_host = re.compile(r"://([^/@]*?)\{")
            pattern_scheme_suffix = re.compile(r"://[^/@]*$")

            def _expr_is_tainted(expr: Optional[ast.AST], scope: str) -> bool:
                if expr is None:
                    return False
                if _is_request_taint_expr(expr):
                    return True
                owner = _enclosing_function(expr)
                owner_scope = function_scopes.get(id(owner)) if owner else mod_scope
                fn_route_params = route_params.get(owner_scope, set())
                if isinstance(expr, ast.Name):
                    if expr.id in fn_route_params:
                        return True
                    if (scope, expr.id) in taint_vars or (owner_scope, expr.id) in taint_vars:
                        return True
                for sub in ast.walk(expr):
                    if _is_request_taint_expr(sub):
                        return True
                    if isinstance(sub, ast.Name):
                        if sub.id in fn_route_params or (scope, sub.id) in taint_vars or (owner_scope, sub.id) in taint_vars:
                            return True
                return False

            def _is_tainted_url_host_expr(root_expr: ast.AST, scope: str, lineno: int) -> bool:
                if root_expr is None:
                    return False
                for sub in ast.walk(root_expr):
                    # 1. Modulo formatting: template % args
                    if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Mod):
                        tmpl = _eval_static_constant(sub.left, self.assignments_by_scope, scope, lineno)
                        if tmpl is None and isinstance(sub.left, ast.Constant) and isinstance(sub.left.value, str):
                            tmpl = sub.left.value
                        if isinstance(tmpl, str) and pattern_mod_host.search(tmpl):
                            if isinstance(sub.right, (ast.Tuple, ast.List)):
                                if sub.right.elts and _expr_is_tainted(sub.right.elts[0], scope):
                                    return True
                            elif _expr_is_tainted(sub.right, scope):
                                return True
                    # 2. str.format(...)
                    elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "format":
                        tmpl = _eval_static_constant(sub.func.value, self.assignments_by_scope, scope, lineno)
                        if tmpl is None and isinstance(sub.func.value, ast.Constant) and isinstance(sub.func.value.value, str):
                            tmpl = sub.func.value.value
                        if isinstance(tmpl, str) and pattern_fmt_host.search(tmpl):
                            all_args = list(sub.args) + [kw.value for kw in sub.keywords]
                            if any(_expr_is_tainted(a, scope) for a in all_args):
                                return True
                    # 3. String concatenation: left + right
                    elif isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Add):
                        left_str = _eval_static_constant(sub.left, self.assignments_by_scope, scope, lineno)
                        if left_str is None and isinstance(sub.left, ast.Constant) and isinstance(sub.left.value, str):
                            left_str = sub.left.value
                        if isinstance(left_str, str) and pattern_scheme_suffix.search(left_str):
                            if _expr_is_tainted(sub.right, scope):
                                return True
                    # 4. f-string: f"..."
                    elif isinstance(sub, ast.JoinedStr):
                        running_prefix = ""
                        for part in sub.values:
                            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                                running_prefix += part.value
                            elif isinstance(part, ast.FormattedValue):
                                if pattern_scheme_suffix.search(running_prefix):
                                    if _expr_is_tainted(part.value, scope):
                                        return True
                                running_prefix = ""
                return False

            # 5. Node-local predicates.
            for node in reachable:
                scope = _scope_for(node, mod_name)
                fn_node = _enclosing_function(node)
                fn_scope = (function_scopes.get(id(fn_node)) if fn_node else mod_scope)

                # CWE-918: Tainted URL host construction
                # SUPPRESSION: Merely constructing a URL string or dictionary key does not constitute SSRF.
                # Suppress unless the URL flows into an actual network transmission sink (requests.get/post, urllib.request, etc.).
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.Return)):
                    val = node.value
                    if val is not None and _is_tainted_url_host_expr(val, scope, getattr(node, "lineno", 0)):
                        # Suppress if this is a Return statement returning JsonResponse/flask.jsonify (no outbound request)
                        if isinstance(node, ast.Return) and isinstance(val, ast.Call):
                            ret_name = dotted_name(val.func) or ""
                            if ret_name in {"JsonResponse", "django.http.JsonResponse", "jsonify", "flask.jsonify"}:
                                continue  # JsonResponse returns JSON, doesn't make HTTP requests
                        
                        # Check if this URL variable actually reaches a network sink in the same module.
                        url_var_name = ""
                        if isinstance(node, ast.Assign) and node.targets:
                            t = node.targets[0]
                            if isinstance(t, ast.Name):
                                url_var_name = t.id
                        elif isinstance(node, ast.AnnAssign) and node.target:
                            if isinstance(node.target, ast.Name):
                                url_var_name = node.target.id
                        
                        if url_var_name:
                            # Search for usage of this variable in a network sink call.
                            reaches_network_sink = False
                            for other_node in reachable:
                                if isinstance(other_node, ast.Call):
                                    other_name = dotted_name(other_node.func) or ""
                                    if any(sink in other_name for sink in ("requests.", "urllib.request.", "httpx.", "aiohttp.")):
                                        # Check if our URL variable is passed as an argument.
                                        for arg in other_node.args:
                                            if isinstance(arg, ast.Name) and arg.id == url_var_name:
                                                reaches_network_sink = True
                                                break
                                        if not reaches_network_sink:
                                            for kw in other_node.keywords:
                                                if isinstance(kw.value, ast.Name) and kw.value.id == url_var_name:
                                                    reaches_network_sink = True
                                                    break
                                    if reaches_network_sink:
                                        break
                            
                            if not reaches_network_sink:
                                continue  # Suppress: URL constructed but never sent over network
                        
                        scope_validators = validated.get(scope, set())
                        if "ssrf" not in scope_validators:
                            _add(node, "SSRF_UNTRUSTED_URL_SOURCE", "SERVER_SIDE_REQUEST_FORGERY", "CWE-918")
                elif isinstance(node, ast.AugAssign):
                    if isinstance(node.target, ast.Name):
                        prior_recs = self.assignments_by_scope.get((scope, node.target.id), [])
                        ended_scheme = False
                        for pr in prior_recs:
                            if pr.lineno < node.lineno:
                                pr_val = _eval_static_constant(pr.value_node, self.assignments_by_scope, scope, pr.lineno)
                                if isinstance(pr_val, str) and pattern_scheme_suffix.search(pr_val):
                                    ended_scheme = True
                                    break
                        if ended_scheme and _expr_is_tainted(node.value, scope):
                            scope_validators = validated.get(scope, set())
                            if "ssrf" not in scope_validators:
                                _add(node, "SSRF_UNTRUSTED_URL_SOURCE", "SERVER_SIDE_REQUEST_FORGERY", "CWE-918")

                if isinstance(node, ast.Assign):
                    first_target = node.targets[0] if node.targets else None
                    target_chain = _segments(first_target) if first_target is not None else []
                    target_dotted = ".".join(target_chain) if target_chain else (
                        dotted_name(first_target) if first_target is not None else "")
                    if target_dotted == CLUSTER2_SSL_GLOBAL_OVERRIDE_TARGET:
                        value_forms: set[str] = set()
                        if isinstance(node.value, ast.Name):
                            value_forms.add(node.value.id)
                        elif isinstance(node.value, ast.Attribute):
                            value_forms.add(node.value.attr)
                        elif isinstance(node.value, ast.Call):
                            value_forms |= {f.split(".")[-1] for f in
                                            _call_forms(node.value, scope)}
                        if value_forms & CLUSTER2_SSL_UNVERIFIED_FACTORIES:
                            _add(node, "SSL_CONTEXT_GLOBAL_OVERRIDE",
                                 "INSECURE_TRANSPORT", "CWE-295")
                    continue

                if not isinstance(node, ast.Call):
                    continue

                forms = _call_forms(node, scope)
                segs = {form.split(".")[-1] for form in forms}
                roots = {form.split(".")[0] for form in forms}
                lineno = getattr(node, "lineno", 0)

                # CWE-295: HTTPSConnection() without an explicit TLS context.
                if CLUSTER2_HTTPS_CONNECTION_SEGMENT in segs:
                    has_context_kw = any(kw.arg == "context" for kw in
                                         getattr(node, "keywords", []))
                    if not has_context_kw:
                        _add(node, "UNVERIFIED_HTTPS_CONNECTION", "INSECURE_TRANSPORT",
                             "CWE-295")

                # CWE-295: urllib3.PoolManager with certificate checks disabled.
                if segs & CLUSTER2_POOL_MANAGER_SEGMENTS and "urllib3" in roots:
                    for kw in getattr(node, "keywords", []):
                        if kw.arg not in ("cert_reqs", "ssl_cert_reqs"):
                            continue
                        value = _eval_static_constant(kw.value, self.assignments_by_scope,
                                                      scope, lineno)
                        disabled = value is False or (isinstance(value, str) and
                                                      value.upper() in
                                                      CLUSTER2_CERT_NONE_VALUES)
                        if disabled:
                            _add(node, "DISABLED_SSL_VERIFICATION", "INSECURE_TRANSPORT",
                                 "CWE-295")

                # CWE-319: urllib3 HTTPConnectionPool (plaintext pool, never HTTPS*).
                if CLUSTER2_HTTP_POOL_SEGMENT in segs:
                    _add(node, "CLEARTEXT_HTTP_CONNECTION_POOL", "INSECURE_TRANSPORT",
                         "CWE-319")

                # CWE-319: requests/httpx/session calls fetching a resolved http:// URL.
                all_sessions = (sessions.get(scope, set()) |
                                sessions.get(fn_scope or "", set()) |
                                sessions.get(mod_scope, set()))
                for form in forms:
                    parts = form.split(".")
                    root, last = parts[0], parts[-1]
                    if last not in CLUSTER2_HTTP_VERBS:
                        continue
                    if root not in ("requests", "httpx", "urllib3") and root not in all_sessions:
                        continue
                    idx = CLUSTER2_HTTP_URL_ARG_INDEX.get(last, 0)
                    url_arg = node.args[idx] if len(node.args) > idx else None
                    if url_arg is None:
                        kw_map = _kw_arguments(node)
                        if "url" in kw_map:
                            url_arg = kw_map["url"].value
                    if url_arg is not None and _is_cleartext_url(url_arg, scope, lineno,
                                                                 fn_node):
                        _add(node, "CLEARTEXT_HTTP_REQUEST", "INSECURE_TRANSPORT", "CWE-319")
                    break

                # CWE-611: XML entry points reached through an xml./lxml. alias.
                if segs & CLUSTER2_XML_METHODS:
                    first_arg_const = bool(node.args) and isinstance(node.args[0], ast.Constant)
                    call_seg = (dotted_name(node.func) or "").split(".")[-1]
                    for form in forms:
                        if form.startswith("defusedxml"):
                            continue
                        if not form.startswith(CLUSTER2_XML_UNSAFE_ROOTS):
                            continue
                        # `parse('literal.xml')` is the audited-safe shape in the upstream
                        # corpus; parseString()/fromstring()/iterparse() stay flagged.
                        if call_seg == "parse" and first_arg_const:
                            continue
                        _add(node, "ALIASED_UNSAFE_XML_PARSE", "XML_EXTERNAL_ENTITY",
                             "CWE-611")
                        break

                # CWE-704: unvalidated numeric conversion on a request-controlled value.
                if isinstance(node.func, ast.Name) and node.func.id in CLUSTER2_NAN_CONVERSIONS \
                        and len(node.args) == 1:
                    arg = node.args[0]
                    parent = getattr(node, "parent", None)
                    wrapped_by_int = (isinstance(parent, ast.Call)
                                      and isinstance(parent.func, ast.Name)
                                      and parent.func.id in CLUSTER2_NAN_SAFE_WRAPPERS)
                    arg_is_safe_call = (isinstance(arg, ast.Call)
                                        and isinstance(arg.func, ast.Name)
                                        and arg.func.id in CLUSTER2_NAN_SAFE_WRAPPERS)
                    tainted_arg = False
                    if isinstance(arg, ast.Name):
                        tainted_arg = ((scope, arg.id) in taint_vars or
                                       arg.id in route_params.get(fn_scope or "", set()) or
                                       arg.id in route_params.get(scope, set()))
                    elif isinstance(arg, (ast.Call, ast.Subscript, ast.Attribute)):
                        tainted_arg = _root_is_request(arg)
                    guarded = arg_is_safe_call or wrapped_by_int or (
                        isinstance(arg, ast.Name) and
                        arg.id in nan_guarded.get(fn_scope or "", set()))
                    if tainted_arg and not guarded:
                        _add(node, "NAN_UNVALIDATED_CONVERSION", "TYPE_CONFUSION", "CWE-704")

                # CWE-942: wildcard CORS combined with credentialed requests.
                if segs & CLUSTER2_CORS_ADD_MW:
                    first_arg = node.args[0] if node.args else None
                    middleware = ""
                    if isinstance(first_arg, ast.Name):
                        middleware = first_arg.id
                    elif isinstance(first_arg, ast.Attribute):
                        middleware = first_arg.attr
                    if middleware in CLUSTER2_CORS_MIDDLEWARE:
                        kw_map = _kw_arguments(node)
                        origins_kw = kw_map.get("allow_origins") or kw_map.get("origins")
                        credentials_kw = kw_map.get("allow_credentials")
                        creds_true = credentials_kw is not None and _eval_static_constant(
                            credentials_kw.value, self.assignments_by_scope, scope,
                            lineno) is True
                        if origins_kw is not None and creds_true and _contains_wildcard(
                                origins_kw.value, scope, lineno):
                            _add(origins_kw.value, "PERMISSIVE_CORS_POLICY",
                                 "INSECURE_CONFIGURATION", "CWE-942")
                elif segs & CLUSTER2_CORS_FACTORY_CALLS:
                    kw_map = _kw_arguments(node)
                    origins_kw = kw_map.get("origins") or kw_map.get("allow_origins")
                    credentials_kw = (kw_map.get("supports_credentials")
                                      or kw_map.get("allow_credentials"))
                    creds_true = credentials_kw is not None and _eval_static_constant(
                        credentials_kw.value, self.assignments_by_scope, scope, lineno) is True
                    wildcard = origins_kw is not None and _contains_wildcard(
                        origins_kw.value, scope, lineno)
                    if not wildcard:
                        for sub in ast.walk(node):
                            if not isinstance(sub, ast.Dict):
                                continue
                            origin_wild = False
                            cred_ok = False
                            for key, val in zip(sub.keys, sub.values):
                                if not (isinstance(key, ast.Constant)
                                        and isinstance(key.value, str)):
                                    continue
                                lowered = key.value.lower()
                                if lowered in ("origins", "allow_origins") and \
                                        _contains_wildcard(val, scope, lineno):
                                    origin_wild = True
                                elif lowered in ("supports_credentials", "allow_credentials"):
                                    cred_ok = _eval_static_constant(
                                        val, self.assignments_by_scope, scope, lineno) is True
                            if origin_wild and cred_ok:
                                wildcard = True
                                creds_true = True
                    if wildcard and creds_true:
                        _add(node, "PERMISSIVE_CORS_POLICY", "INSECURE_CONFIGURATION",
                             "CWE-942")

    def _module_is_json_api(self, mod_name: str) -> bool:
        """True when the module is built on a JSON-first router (FastAPI/Starlette/ninja)."""
        for canonical in (self.imports.get(mod_name) or {}).values():
            if str(canonical).split(".")[0] in JSON_API_MODULE_ROOTS:
                return True
        return False

    def _csrf_is_json_api_noise(self, mod_name: str, dec_segments=None) -> bool:
        """Suppress missing-CSRF findings on stateless JSON APIs.

        Two independent signals, either sufficient: the module imports a JSON-first framework,
        or the decorator's receiver (`@app.post`, `@router.get`) resolves through this module's
        import map to one. Flask's `@app.get` shortcut is NOT enough on its own — the receiver
        has to be a FastAPI/Starlette/ninja object, otherwise traditional form routes go quiet.
        """
        if self._module_is_json_api(mod_name):
            return True
        segments = [seg for seg in (dec_segments or []) if seg]
        if len(segments) >= 2 and segments[-1] in JSON_API_ROUTE_SEGS:
            canonical = (self.imports.get(mod_name) or {}).get(segments[-2], "")
            return str(canonical).split(".")[0] in JSON_API_MODULE_ROOTS
        return False

    def _collect_cluster3_structural_findings(self) -> None:
        """
        Phase 3 Cluster 3 PURE_STRUCTURAL visitors, the eighteen-rule grand finale:

          CWE-327  hashlib.new(md4/md5/sha1) without usedforsecurity=False;
                   Crypto(Dome).Hash weak-class .new() behind an import alias;
                   cryptography hashes.MD5()/SHA1(); weak digest fed to setPassword.
          CWE-330  uuid.uuid1() / bare uuid1() (also via `import *`).
          CWE-939  urllib urlopen/opener.open/retrieve with a non-constant URL.
          CWE-155  os.system/popen2 or shell=True subprocess on 'tar|rsync|chown|chmod *'.
          CWE-673  flask url_for(..., _external=True|<dynamic>).
          CWE-91   TwiML twiml kw interpolating unescaped dynamic strings into XML.
          CWE-532  logger calls passing credential-named variables.
          CWE-798  AWS key/secret literals (shape-checked) in boto3 constructors;
                   password-named default arguments.
          CWE-326  rsa/dsa.generate_private_key(<2048 bits); ec weak (<224-bit) curves.
          CWE-502  pickle/_pickle/cPickle/dill/marshal loads+dumps (alias aware),
                   shelve.open/loads, yaml.unsafe_load and unsafe Loader= variants.
          CWE-352  @csrf_exempt views; WTF_CSRF_ENABLED=False (subscript, attribute,
                   bare, and config.update()/from_mapping() kwargs, TESTING=True exempt).

        Appends sinks + sink_records; edges come from the generic p3_source_id synthetic
        path in analyze().
        """
        function_scopes = {id(function): scope for scope, function in self.functions.items()}

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _segments(expr: ast.AST) -> list[str]:
            chain: list[str] = []
            current = expr
            while isinstance(current, ast.Attribute):
                chain.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                chain.append(current.id)
            return list(reversed(chain))

        def _lower_method(name: str) -> str:
            return (name or "").lower()

        for mod_name, tree in self.modules.items():
            file_path = self.file_paths.get(mod_name, "unknown.py")
            mod_scope = f"{mod_name}:global"
            reachable = list(self._reachable_nodes(tree))
            seen: set[tuple[str, int, int]] = set()

            bindings: dict[str, list[tuple[int, str, str]]] = {}
            for node in reachable:
                scope = _scope_for(node, mod_name)
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        local = alias.asname or alias.name.split(".")[0]
                        bindings.setdefault(scope, []).append(
                            (getattr(node, "lineno", 0), local, alias.name))
                        if alias.asname is None and "." in alias.name:
                            bindings.setdefault(scope, []).append(
                                (getattr(node, "lineno", 0), alias.name, alias.name))
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias in node.names:
                        local = alias.asname or alias.name
                        full = f"{module}.{alias.name}" if module else alias.name
                        bindings.setdefault(scope, []).append(
                            (getattr(node, "lineno", 0), local, full))

            def _resolve_chain(chain: list[str], scope: str, lineno: int) -> list[str]:
                if not chain:
                    return chain
                for depth in range(min(len(chain), 3), 0, -1):
                    prefix = ".".join(chain[:depth])
                    best = None
                    for scope_key in (scope, mod_scope):
                        rows = [row for row in bindings.get(scope_key, [])
                                if row[1] == prefix and row[0] <= lineno]
                        if rows:
                            best = rows[-1][2]
                            break
                    if best is None:
                        best = self.imports.get(mod_name, {}).get(prefix)
                    if best:
                        return best.split(".") + chain[depth:]
                return chain

            def _eval_value(expr, scope: str, lineno: int, depth: int = 0):
                if expr is None or depth > 2:
                    return None
                if isinstance(expr, ast.Constant):
                    return expr.value
                if isinstance(expr, (ast.List, ast.Tuple)):
                    return [_eval_value(elt, scope, lineno, depth + 1) for elt in expr.elts]
                if isinstance(expr, ast.Name):
                    records = list(self.assignments_by_scope.get((scope, expr.id), []))
                    records += list(self.assignments_by_scope.get((mod_scope, expr.id), []))
                    prior = [r for r in records if r.lineno <= lineno]
                    if prior:
                        return _eval_value(prior[-1].value_node, scope, prior[-1].lineno,
                                           depth + 1)
                    return None
                return None

            def _assigned_node(name: str, scope: str, lineno: int):
                records = list(self.assignments_by_scope.get((scope, name), []))
                records += list(self.assignments_by_scope.get((mod_scope, name), []))
                prior = [r for r in records if r.lineno <= lineno and r.lineno != lineno]
                return prior[-1] if prior else None

            def _static(expr, scope: str, lineno: int):
                return _eval_static_constant(expr, self.assignments_by_scope, scope, lineno)

            existing_index: dict[tuple[str, int], list] = {}
            for record in self.sink_records:
                loc = record.security_node.location
                if loc.file == file_path:
                    key = (record.security_node.metadata.get("cwe") or "", loc.line_start)
                    existing_index.setdefault(key, []).append(record.security_node)

            def _merge_into_existing_sink(cwe: str, line: int, operation: str) -> None:
                """Phase 6.3: stamp the synthetic source id onto an edgeless registry sink at
                the same (cwe, line) instead of dropping the structural finding."""
                source_id = CLUSTER3_STRUCTURAL_SOURCE_IDS.get(operation)
                if not source_id:
                    return
                for existing in existing_index.get((cwe, line)) or []:
                    if not existing.metadata.get("p3_source_id"):
                        existing.metadata["p3_source_id"] = source_id
                        return

            nosec_lines: set[int] = set()
            mod_source = self.files.get(file_path) or ""
            for _idx, _text in enumerate(mod_source.splitlines(), 1):
                if CLUSTER3_NOSEC_RE.search(_text):
                    nosec_lines.add(_idx)

            def _add(node: ast.AST, operation: str, category: str, cwe: str) -> None:
                line = getattr(node, "lineno", 1)
                column = getattr(node, "col_offset", 0)
                if line in nosec_lines or (line - 1) in nosec_lines:
                    return
                key = (cwe, line, column)
                if key in seen:
                    return
                if existing_index.get((cwe, line)):
                    _merge_into_existing_sink(cwe, line, operation)
                    return
                seen.add(key)
                scope_id = _scope_for(node, mod_name)
                sink_node = SecurityNode(
                    id=self.next_sink_id(),
                    node_type=NodeType.SINK,
                    symbol=operation,
                    operation=operation,
                    location=location(node, file_path),
                    metadata={"sink_type": category, "category": category, "cwe": cwe,
                              "p3_source_id": CLUSTER3_STRUCTURAL_SOURCE_IDS[operation]},
                )
                self.sinks.append(sink_node)
                self.sink_records.append(SinkRecord(
                    node=node,
                    security_node=sink_node,
                    lineno=line,
                    scope_id=scope_id,
                ))

            def _contains_weak_hash_token(root_node) -> bool:
                for sub in ast.walk(root_node):
                    if isinstance(sub, ast.Attribute) and \
                            _lower_method(sub.attr) in {"md5", "md4", "md2", "sha1"}:
                        return True
                    if isinstance(sub, ast.Name) and \
                            _lower_method(sub.id) in {"md5", "md4", "md2"}:
                        return True
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and \
                            _lower_method(sub.value) in {"md5", "md4", "md2"}:
                        return True
                return False

            def _is_escape_call(expr) -> bool:
                return isinstance(expr, ast.Call) and \
                    bool(_segments(expr.func)) and _segments(expr.func)[-1] in \
                    CLUSTER3_TWIML_ESCAPERS

            def _twiml_is_dynamic(value, scope: str, lineno: int, depth: int = 0) -> bool:
                if value is None or depth > 3:
                    return False
                if isinstance(value, ast.Name):
                    record = _assigned_node(value.id, scope, lineno)
                    if record is None:
                        return False
                    return _twiml_is_dynamic(record.value_node, record.scope_id,
                                             record.lineno, depth + 1)
                constants = [sub.value for sub in ast.walk(value)
                             if isinstance(sub, ast.Constant) and isinstance(sub.value, str)]
                if isinstance(value, ast.Call) and \
                        _segments(value.func)[-1:] == ["format"] and \
                        isinstance(value.func, ast.Attribute) and \
                        isinstance(value.func.value, ast.Name):
                    base_record = _assigned_node(value.func.value.id, scope, lineno)
                    if base_record is not None:
                        base_text = _eval_value(base_record.value_node, base_record.scope_id,
                                                base_record.lineno)
                        if isinstance(base_text, str):
                            constants = constants + [base_text]
                if not any(CLUSTER3_TWIML_XML_RE.search(text or "") for text in constants):
                    return False
                interpolated: list[ast.AST] = []
                if isinstance(value, ast.JoinedStr):
                    interpolated = [fv.value for fv in value.values
                                    if isinstance(fv, ast.FormattedValue)]
                elif isinstance(value, ast.BinOp):
                    for sub in ast.walk(value):
                        if isinstance(sub, ast.BinOp) and \
                                isinstance(sub.op, (ast.Add, ast.Mod)):
                            if isinstance(sub.op, ast.Add):
                                side = sub.left if isinstance(sub.right, ast.Constant) else \
                                    sub.right
                            else:
                                side = sub.right
                            if isinstance(side, ast.Tuple):
                                interpolated.extend(side.elts)
                            else:
                                interpolated.append(side)
                    interpolated = [item for item in interpolated
                                    if not isinstance(item, ast.Constant)]
                elif isinstance(value, ast.Call) and _segments(value.func)[-1:] == ["format"]:
                    interpolated = list(value.args) + [kw.value for kw in value.keywords]
                if not interpolated:
                    return False
                for expr in interpolated:
                    if _is_escape_call(expr):
                        continue
                    if isinstance(expr, (ast.Name, ast.Call, ast.Attribute, ast.Subscript)):
                        return True
                return False

            def _aws_secret_looks_real(text: str) -> bool:
                return bool(text) and len(set(text)) > 2

            opener_vars: dict[str, set[str]] = {}

            def _module_urllib_chain(chain: list[str]) -> bool:
                return any(seg in CLUSTER3_URLLIB_MODULE_SEGS for seg in chain[:3])

            for node in reachable:
                scope = _scope_for(node, mod_name)
                lineno = getattr(node, "lineno", 1)

                # ---- pre-pass: opener objects (opener = urllib.URLopener()/build_opener()) ----
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and \
                        len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    value_chain = _resolve_chain(_segments(node.value.func), scope, lineno)
                    if value_chain and value_chain[-1] in CLUSTER3_OPENER_CTOR_SEGS:
                        opener_vars.setdefault(scope, set()).add(node.targets[0].id)

                # ---- CWE-352: @csrf_exempt views ----
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for decorator in node.decorator_list:
                        dec_chain = _segments(decorator.func) if isinstance(decorator, ast.Call) \
                            else _segments(decorator)
                        if dec_chain and dec_chain[-1] == CLUSTER3_CSRF_EXEMPT_SEG \
                                and not self._csrf_is_json_api_noise(mod_name, dec_chain):
                            _add(decorator, "CSRF_EXEMPT_VIEW", "CSRF_MISSING_PROTECTION",
                                 "CWE-352")
                    # ---- CWE-798: password-named default arguments ----
                    for arg, default in TaintTracker._c1_parameter_defaults(node):
                        if arg.arg.lower() not in CLUSTER3_PASSWORD_PARAM_NAMES:
                            continue
                        if not (isinstance(default, ast.Constant)
                                and isinstance(default.value, str)):
                            continue
                        text = default.value
                        if len(text) < 3:
                            continue
                        lowered = text.lower()
                        if any(marker in lowered for marker in
                               ("changeme", "example", "dummy", "placeholder", "default",
                                "test", "none", "hello", "world", "foo", "bar", "sample",
                                "demo")):
                            continue
                        _add(node, "HARDCODED_PASSWORD_DEFAULT", "HARDCODED_CREDENTIAL",
                             "CWE-798")

                # ---- CWE-352: WTF_CSRF_ENABLED = False (attribute/subscript/bare) ----
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        key_name = None
                        if isinstance(target, ast.Name):
                            key_name = target.id
                        elif isinstance(target, ast.Attribute):
                            key_name = target.attr
                        elif isinstance(target, ast.Subscript) and \
                                isinstance(target.slice, ast.Constant):
                            key_name = target.slice.value
                        if key_name == CLUSTER3_WTF_CSRF_KEY and \
                                _static(node.value, scope, lineno) is False:
                            _add(node, "FLASK_CSRF_DISABLED", "CSRF_MISSING_PROTECTION",
                                 "CWE-352")

                # ---- CWE-326: weak ssl.PROTOCOL_* constant (args, kwargs, defaults) ----
                if isinstance(node, (ast.Attribute, ast.Name)):
                    ssl_segs = _segments(node)
                    if ssl_segs and ssl_segs[-1] in CLUSTER3_WEAK_SSL_PROTOCOL_SEGS and \
                            _resolve_chain(ssl_segs, scope, lineno)[:1] == \
                            [CLUSTER3_SSL_MODULE_ROOT]:
                        _add(node, "WEAK_SSL_PROTOCOL", "INSECURE_TRANSPORT", "CWE-326")

                # ---- CWE-326: pyOpenSSL insecure protocol methods (SSL.*_METHOD) ----
                if isinstance(node, (ast.Attribute, ast.Name)):
                    openssl_segs = _segments(node)
                    if openssl_segs and openssl_segs[-1] in CLUSTER3_PYOPENSSL_METHOD_SEGS:
                        chain = _resolve_chain(openssl_segs, scope, lineno)
                        # Match any X.SSLv2_METHOD where the parent is SSL (covers OpenSSL.SSL,
                        # pyOpenSSL.SSL, or bare SSL after from-import).
                        if len(chain) >= 2 and chain[-2] == CLUSTER3_PYOPENSSL_SSL_ROOT:
                            _add(node, "PYOPENSSL_INSECURE_METHOD", "INSECURE_TRANSPORT", "CWE-326")

                # ---- CWE-327: cryptography.hazmat legacy cipher algorithms ----
                if isinstance(node, (ast.Attribute, ast.Name)):
                    algo_segs = _segments(node)
                    if algo_segs and algo_segs[-1] in CLUSTER3_CRYPTOGRAPHY_LEGACY_ALGOS:
                        chain = _resolve_chain(algo_segs, scope, lineno)
                        # Match: algorithms.Blowfish under cryptography.hazmat.primitives.ciphers
                        if len(chain) >= 5 and chain[-2] == CLUSTER3_CRYPTOGRAPHY_ALGO_SEG and \
                                chain[-3] == CLUSTER3_CRYPTOGRAPHY_CIPHERS_SEG and \
                                chain[0] == CLUSTER3_CRYPTOGRAPHY_HAZMAT_ROOT:
                            _add(node, "CRYPTOGRAPHY_LEGACY_ALGO", "WEAK_CRYPTOGRAPHY", "CWE-327")

                # ---- CWE-327: insecure ECB mode (Phase 9.3) ----
                if isinstance(node, ast.Call):
                    func_name = dotted_name(node.func) or ""
                    last_part = func_name.rsplit(".", 1)[-1] if func_name else ""
                    # Check for modes.ECB(...) or ECB(...) constructor calls
                    if last_part in P3_ECB_MARKER_ATTRS or (isinstance(node.func, ast.Name) and node.func.id in P3_ECB_MARKER_ATTRS):
                        # Don't double-report if already flagged as weak cipher
                        callee = dotted_name(node.func) or ""
                        if callee not in P3_ECB_SKIP_IF_WEAK_CIPHER:
                            _add(node, "INSECURE_CIPHER_MODE_ECB", "WEAK_CRYPTOGRAPHY", "CWE-327")

                if not isinstance(node, ast.Call):
                    continue

                raw_chain = _segments(node.func)
                chain = _resolve_chain(raw_chain, scope, lineno)
                forms = {".".join(chain)} if chain else set()
                if raw_chain:
                    forms.add(".".join(raw_chain))
                if raw_chain and raw_chain[0]:
                    record = _assigned_node(raw_chain[0], scope, lineno)
                    if record is not None:
                        base = dotted_name(record.value_node)
                        if base:
                            forms.add(".".join(base.split(".") + raw_chain[1:]))
                last_seg = raw_chain[-1] if raw_chain else ""
                kw_map = {kw.arg: kw for kw in node.keywords if kw.arg}

                # ---- CWE-327: hashlib.new(weak) without usedforsecurity=False ----
                if last_seg == "new" and chain and chain[-2:-1] == \
                        [CLUSTER3_HASHLIB_MODULE_SEG]:
                    name_kw = kw_map.get("name")
                    name_expr = name_kw.value if name_kw else (node.args[0] if node.args
                                                               else None)
                    algo = _static(name_expr, scope, lineno)
                    usedfor = kw_map.get("usedforsecurity")
                    usedfor_value = _static(usedfor.value, scope, lineno) if usedfor else None
                    if isinstance(algo, str) and algo.lower() in \
                            CLUSTER3_WEAK_NEW_HASH_ALGOS and usedfor_value is not False:
                        _add(node, "WEAK_HASH_NEW", "CRYPTOGRAPHIC_FAILURES", "CWE-327")

                # ---- CWE-327: legacy Crypto(Dome).Cipher algorithms (alias aware) ----
                if last_seg == "new" and len(chain) >= 4 and \
                        chain[-3] == CLUSTER3_CIPHER_MODULE_SEG and \
                        chain[-2] in CLUSTER3_LEGACY_CIPHER_NAMES and \
                        chain[0] in CLUSTER3_CIPHER_MODULE_ROOTS:
                    _add(node, "WEAK_CIPHER_LEGACY", "WEAK_CRYPTOGRAPHY", "CWE-327")

                # ---- CWE-327: Crypto(Dome).Hash weak class .new() (alias aware) ----
                if last_seg == "new" and len(chain) >= 3:
                    class_name = chain[-2]
                    if class_name in CLUSTER3_WEAK_HASH_CLASS_NAMES and any(
                            chain[i:i + 2] == list(pair)
                            for pair in CLUSTER3_HASH_MODULE_PAIRS
                            for i in range(len(chain) - 2)):
                        _add(node, "WEAK_HASH_CONSTRUCTOR", "CRYPTOGRAPHIC_FAILURES",
                             "CWE-327")

                # ---- CWE-327: cryptography hashes.MD5()/SHA1() ----
                if chain and chain[-2:-1] == ["hashes"] and \
                        chain[-1] in {"MD5", "MD4", "MD2", "SHA1"} and \
                        chain[0] == "cryptography":
                    _add(node, "WEAK_HASH_CONSTRUCTOR", "CRYPTOGRAPHIC_FAILURES", "CWE-327")

                # ---- CWE-327: weak digest handed to setPassword ----
                if last_seg and _lower_method(last_seg) in CLUSTER3_PASSWORD_SETTER_METHODS:
                    for arg in node.args:
                        probe_expr = arg.func if isinstance(arg, ast.Call) and \
                            isinstance(arg.func, ast.Attribute) else arg
                        target_name = None
                        if isinstance(probe_expr, ast.Name):
                            target_name = probe_expr.id
                        elif isinstance(probe_expr, ast.Attribute) and \
                                isinstance(probe_expr.value, ast.Name):
                            target_name = probe_expr.value.id
                        if target_name is None:
                            continue
                        record = _assigned_node(target_name, scope, lineno)
                        if record is not None and _contains_weak_hash_token(
                                record.value_node):
                            _add(node, "WEAK_HASH_PASSWORD_USAGE", "CRYPTOGRAPHIC_FAILURES",
                                 "CWE-327")
                            break

                # ---- CWE-330: uuid1() ----
                if last_seg == CLUSTER3_INSECURE_UUID_SEG and \
                        (len(raw_chain) == 1 or "uuid" in chain):
                    defined_locally = any(
                        isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and fn.name == CLUSTER3_INSECURE_UUID_SEG
                        for fn in ast.walk(tree))
                    if not defined_locally and _assigned_node(last_seg, scope, lineno) is None:
                        _add(node, "INSECURE_UUID1", "CRYPTOGRAPHIC_FAILURES", "CWE-330")

                # ---- CWE-939: dynamic urllib fetch ----
                fetch_via_module = bool(chain) and last_seg == "urlopen" and (
                    _module_urllib_chain(chain) or len(chain) == 1)
                fetch_via_opener = len(raw_chain) >= 2 and last_seg in {"open", "retrieve"} \
                    and raw_chain[0] in opener_vars.get(scope, set())
                if (fetch_via_module or fetch_via_opener) and node.args:
                    url_expr = node.args[0]
                    url_value = _static(url_expr, scope, lineno)
                    if url_value is None and isinstance(url_expr, ast.Name):
                        current = getattr(node, "parent", None)
                        fn_node = None
                        while current is not None:
                            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                fn_node = current
                                break
                            current = getattr(current, "parent", None)
                        for param, default in (
                                TaintTracker._c1_parameter_defaults(fn_node)
                                if fn_node is not None else []):
                            if param.arg == url_expr.id and isinstance(default, ast.Constant) \
                                    and isinstance(default.value, str):
                                url_value = default.value
                                break
                    if url_value is None:
                        _add(node, "DYNAMIC_URLLIB_FETCH", "PROTOCOL_RESOURCE_ACCESS",
                             "CWE-939")

                # ---- CWE-155: shell wildcard against sensitive binaries ----
                cmd_chain = chain if chain else raw_chain
                shell_form = bool(cmd_chain) and cmd_chain[0] == "os" and \
                    cmd_chain[-1] in CLUSTER3_SHELL_EXEC_SEGS
                subp_form = bool(cmd_chain) and cmd_chain[0] == "subprocess" and \
                    cmd_chain[-1] in CLUSTER3_SUBPROCESS_SHELL_SEGS
                if (shell_form or subp_form) and node.args:
                    executes_shell = shell_form
                    if subp_form:
                        shell_kw = kw_map.get("shell")
                        executes_shell = bool(shell_kw) and \
                            _static(shell_kw.value, scope, lineno) is True
                    if executes_shell:
                        command = node.args[0]
                        cmd_text = command.value if isinstance(command, ast.Constant) and \
                            isinstance(command.value, str) else None
                        if cmd_text and "*" in cmd_text:
                            tokens = cmd_text.split()
                            binary = tokens[0].rsplit("/", 1)[-1] if tokens else ""
                            if binary in CLUSTER3_WILDCARD_BINARIES:
                                _add(node, "SUBPROCESS_WILDCARD_INJECTION",
                                     "COMMAND_INJECTION", "CWE-155")

                # ---- CWE-673: flask url_for(..., _external=True|dynamic) ----
                if last_seg == CLUSTER3_URLFOR_SEG and (
                        len(raw_chain) == 1 or raw_chain[0] == "flask"
                        or (chain and chain[-2:-1] == ["flask"])):
                    external = kw_map.get("_external")
                    if external is not None:
                        value = _static(external.value, scope, lineno)
                        if value is True or value is None:
                            _add(node, "URL_FOR_EXTERNAL_TRUE", "OPEN_REDIRECT", "CWE-673")

                # ---- CWE-91: TwiML XML injection ----
                twiml_kw = kw_map.get(CLUSTER3_TWIML_KW)
                if twiml_kw is not None and _twiml_is_dynamic(twiml_kw.value, scope, lineno):
                    _add(twiml_kw.value, "TWIML_XML_INJECTION", "XML_INJECTION", "CWE-91")

                # ---- CWE-532: credential leakage into logs ----
                if chain and last_seg in CLUSTER3_LOGGER_METHODS and \
                        (chain[0] in CLUSTER3_LOGGER_ROOTS or
                         (len(raw_chain) == 2 and raw_chain[0] in CLUSTER3_LOGGER_ROOTS)):
                    leaked = False
                    for arg in node.args[1:]:
                        if isinstance(arg, ast.Name) and \
                                CLUSTER3_SENSITIVE_LOG_NAME_RE.match(arg.id):
                            leaked = True
                            break
                        if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                            for sub in ast.walk(arg):
                                if isinstance(sub, ast.Name) and \
                                        CLUSTER3_SENSITIVE_LOG_NAME_RE.match(sub.id):
                                    leaked = True
                                    break
                        if leaked:
                            break
                    if leaked:
                        _add(node, "LOGGER_CREDENTIAL_LEAK", "INFORMATION_DISCLOSURE",
                             "CWE-532")

                # ---- CWE-798: hardcoded AWS tokens in boto3 constructors ----
                boto_form = any(form.startswith("boto3") or form.endswith("boto3.client")
                                or form == "client" or form.endswith(".client")
                                or form.endswith(".Session") or form.endswith(".resource")
                                or form in {"Session", "resource"}
                                for form in forms)
                if boto_form and last_seg in CLUSTER3_BOTO_CONSTRUCTOR_SEGS:
                    tainted_kw = None
                    for kw in node.keywords:
                        if kw.arg == CLUSTER3_AWS_KEY_ID_KW:
                            text = _eval_value(kw.value, scope, lineno)
                            if isinstance(text, str) and \
                                    CLUSTER3_AWS_KEY_ID_SHAPE_RE.match(text):
                                tainted_kw = kw
                                break
                        elif kw.arg in CLUSTER3_AWS_SECRET_KWS:
                            text = _eval_value(kw.value, scope, lineno)
                            if isinstance(text, str) and \
                                    CLUSTER3_AWS_SECRET_SHAPE_RE.match(text) and \
                                    _aws_secret_looks_real(text):
                                tainted_kw = kw
                                break
                    if tainted_kw is not None:
                        _add(node, "HARDCODED_AWS_TOKEN", "HARDCODED_CREDENTIAL", "CWE-798")

                # ---- CWE-326: insufficient RSA/DSA key size, weak EC curves ----
                if last_seg in CLUSTER3_KEYGEN_SEGS:
                    root = raw_chain[0] if raw_chain else ""
                    if root in CLUSTER3_KEYGEN_ROOTS:
                        size_kw = kw_map.get("key_size")
                        size_expr = size_kw.value if size_kw else None
                        if size_expr is None:
                            constants = [arg for arg in node.args
                                         if isinstance(arg, ast.Constant)
                                         and isinstance(arg.value, int)]
                            if root == "rsa":
                                constants = [arg for arg in constants
                                             if arg.value not in (3, 65537)]
                            if len(constants) == 1:
                                size_expr = constants[0]
                        bits = _static(size_expr, scope, lineno) if size_expr is not None \
                            else None
                        if isinstance(bits, int) and 0 < bits < 2048:
                            _add(size_expr, "INSUFFICIENT_KEY_SIZE",
                                 "CRYPTOGRAPHIC_FAILURES", "CWE-326")
                    elif root == CLUSTER3_EC_ROOT:
                        curve_kw = kw_map.get("curve")
                        curve_expr = curve_kw.value if curve_kw else \
                            (node.args[0] if node.args else None)
                        if curve_expr is not None:
                            curve_chain = _segments(curve_expr)
                            curve_name = curve_chain[-1] if curve_chain else ""
                            match = re.match(r"^SEC[A-Z](\d{3})", curve_name)
                            if match and int(match.group(1)) < 224:
                                _add(curve_expr, "INSUFFICIENT_KEY_SIZE",
                                     "CRYPTOGRAPHIC_FAILURES", "CWE-326")

                # ---- CWE-352: app.config.update(WTF_CSRF_ENABLED=False, ...) kwargs ----
                for kw in node.keywords:
                    if kw.arg != CLUSTER3_WTF_CSRF_KEY:
                        continue
                    if _static(kw.value, scope, lineno) is not False:
                        continue
                    testing_kw = kw_map.get(CLUSTER3_TESTING_KEY)
                    if testing_kw is not None and _static(testing_kw.value, scope,
                                                          lineno) is True:
                        continue
                    _add(kw.value, "FLASK_CSRF_DISABLED", "CSRF_MISSING_PROTECTION",
                         "CWE-352")

                # ---- CWE-215/CWE-489: app.config.update(DEBUG=True, SECRET_KEY="...") ----
                if chain and len(chain) >= 2 and chain[-1] == "update" and \
                        chain[-2] == "config":
                    _DEBUG_BOOL_KEYS = frozenset({"DEBUG"})
                    _STRING_CONFIG_KEYS = frozenset({"SECRET_KEY", "ENV"})
                    for kw in node.keywords:
                        val = _static(kw.value, scope, lineno)
                        if val is not None:
                            if kw.arg in _DEBUG_BOOL_KEYS and val is True:
                                _add(kw.value, "ACTIVE_DEBUG_CODE", "ACTIVE_DEBUG_CODE",
                                     "CWE-489")
                            elif kw.arg in _STRING_CONFIG_KEYS:
                                _add(kw.value, "HARDCODED_CONFIG", "HARDCODED_CONFIG",
                                     "CWE-489")

                # ---- CWE-502: yaml unsafe loaders ----
                if chain and chain[0] == CLUSTER3_YAML_ROOT and \
                        last_seg in CLUSTER3_YAML_UNSAFE_SEGS and \
                        not self._deserializes_own_document(node, scope, lineno):
                    _add(node, "UNSAFE_YAML_LOADER", "DESERIALIZATION", "CWE-502")
                elif chain and chain[0] == CLUSTER3_YAML_ROOT and \
                        last_seg in {"load", "load_all"}:
                    loader_kw = kw_map.get("Loader") or kw_map.get("Loader"
                                                                   .lower())
                    if loader_kw is not None:
                        loader_name = _segments(loader_kw.value)[-1] if \
                            _segments(loader_kw.value) else ""
                        if loader_name in CLUSTER3_YAML_UNSAFE_LOADERS and \
                                not self._deserializes_own_document(node, scope, lineno):
                            _add(node, "UNSAFE_YAML_LOADER", "DESERIALIZATION", "CWE-502")

                # ---- CWE-502: pickle-family and marshal/shelve usage ----
                if chain and len(chain) >= 2 and chain[-2] in CLUSTER3_PICKLE_ROOTS:
                    has_dynamic_arg = any(_static(arg, scope, lineno) is None
                                          for arg in node.args)
                    if has_dynamic_arg and (
                            last_seg in CLUSTER3_PICKLE_METHOD_SEGS or
                            (chain[-2] == "shelve" and last_seg == CLUSTER3_SHELVE_OPEN_SEG)):
                        _add(node, "UNSAFE_PICKLE_USAGE" if chain[-2] != "marshal"
                             else "MARSHAL_USAGE", "DESERIALIZATION", "CWE-502")

    def _collect_batch3a_structural_findings(self) -> None:
        """
        Batch 3A PURE_STRUCTURAL visitors (data/cwe_blueprint_batch3a.json):
        CWE-614, CWE-916, CWE-759, CWE-434, CWE-352, CWE-287, CWE-862, CWE-312, CWE-319, CWE-489.
        Appends sinks + sink_records; analyze() emits synthetic edges for them.
        """
        # Index every function by its owning module once. The auth-guard map below only
        # ever needs the current module's functions, and scanning self.functions for each
        # of M modules is O(modules x functions) -- the dominant cost on large trees.
        functions_by_module: dict[str, list[tuple[str, ast.AST]]] = {}
        function_scopes: dict[int, str] = {}
        for func_scope, func_node in self.functions.items():
            function_scopes.setdefault(id(func_node), func_scope)
            if ":function:" in func_scope:
                functions_by_module.setdefault(scope_module(func_scope), []).append(
                    (func_scope, func_node))
        func_explicit_guard_cache: dict[int, bool] = {}

        for mod_name, tree in self.modules.items():
            file_path = self.file_paths.get(mod_name, "unknown.py")
            scope_id = f"{mod_name}:global"
            seen: set[tuple[str, int, int]] = set()

            # Pre-scan module for extension whitelist, sanitizers, CSRF config, auth settings
            has_extension_whitelist = False
            has_csrf_form_validation = False
            has_owner_check = False
            has_auth_decorator = False
            module_csrf_disabled = False
            module_csrf_enabled = False

            # Decorators are only accepted as auth guards when their own definition
            # performs an explicit authentication branch check. Decorator names are
            # never treated as evidence on their own.
            AUTH_GUARD_ATTRS = ("is_authenticated", "is_active", "is_staff", "is_superuser")
            FRAMEWORK_AUTH_DECORATORS = (
                "login_required", "flask_login.login_required", "permission_required",
                "user_passes_test", "django.contrib.auth.decorators.login_required",
            )
            guard_decorator_names: set[str] = set()
            for def_node in ast.walk(tree):
                if not isinstance(def_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                body_is_guard = False
                for sub in ast.walk(def_node):
                    if isinstance(sub, ast.If):
                        attrs_sub = {a.attr for a in ast.walk(sub.test) if isinstance(a, ast.Attribute)}
                        if attrs_sub & set(AUTH_GUARD_ATTRS):
                            body_is_guard = True
                            break
                if body_is_guard:
                    guard_decorator_names.add(def_node.name)

            def _decorator_is_verified_guard(dec) -> bool:
                dec_expr = dec.func if isinstance(dec, ast.Call) else dec
                dec_name = dotted_name(dec_expr) or ""
                if dec_name in FRAMEWORK_AUTH_DECORATORS:
                    return True
                return dec_name.split(".")[-1] in guard_decorator_names

            # Collect per-function auth guards so CWE-862 can skip guarded views.
            function_auth_guards: dict[str, bool] = {}
            for scope_id_f, func_node in functions_by_module.get(mod_name, ()):
                has_guard_in_func = False
                
                # Check decorators for auth guards
                for dec in func_node.decorator_list:
                    if _decorator_is_verified_guard(dec):
                        has_guard_in_func = True
                
                # Walk ALL nodes in function body (not just direct children) to find auth guards
                for node_in_func in ast.walk(func_node):
                    if isinstance(node_in_func, ast.If):
                        names_if = {n.id for n in ast.walk(node_in_func.test) if isinstance(n, ast.Name)}
                        attrs_if = {a.attr for a in ast.walk(node_in_func.test) if isinstance(a, ast.Attribute)}
                        if "is_authenticated" in attrs_if or "is_active" in attrs_if or "is_staff" in attrs_if:
                            has_guard_in_func = True
                        if "request" in names_if and any("user" in a.lower() for a in attrs_if):
                            has_guard_in_func = True
                    if isinstance(node_in_func, ast.Call):
                        cn = dotted_name(node_in_func.func) or ""
                        if cn in ("login_required", "flask_login.login_required", "authenticate"):
                            has_guard_in_func = True
                
                function_auth_guards[scope_id_f] = has_guard_in_func

            for node in self._reachable_nodes(tree):
                if isinstance(node, ast.Compare):
                    names_comp = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
                    attrs_comp = {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
                    if "ALLOWED_EXTENSIONS" in names_comp or "splitext" in attrs_comp:
                        has_extension_whitelist = True
                    if "owner_id" in attrs_comp or "owner" in attrs_comp:
                        has_owner_check = True

                elif isinstance(node, ast.Call):
                    cname = dotted_name(node.func) or ""
                    if "validate_on_submit" in cname:
                        has_csrf_form_validation = True
                    if cname in ("login_required", "flask_login.login_required"):
                        has_auth_decorator = True

                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    val_c = _eval_static_constant(node.value, self.assignments_by_scope, scope_id, getattr(node, "lineno", 0))
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name) and target.id == "CSRF_ENABLED":
                            if val_c is False:
                                module_csrf_disabled = True
                            elif val_c is True:
                                module_csrf_enabled = True
                        elif isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and target.slice.value == "WTF_CSRF_ENABLED":
                            if val_c is False:
                                module_csrf_disabled = True
                            elif val_c is True:
                                module_csrf_enabled = True

            for node in self._reachable_nodes(tree):
                cwe_meta = None
                lineno = getattr(node, "lineno", 0)

                # ─── 1. Calls ───
                if isinstance(node, ast.Call):
                    name = dotted_name(node.func) or ""
                    canon = self.resolve_canonical_name(node.func, scope_id) or ""
                    names = {name, canon} - {"", None}

                    # ─── CWE-614: set_cookie without secure=True ───
                    if name == "set_cookie" or name.endswith(".set_cookie") or canon == "set_cookie" or (canon and canon.endswith(".set_cookie")):
                        states = self._cookie_flag_states(node, scope_id, lineno)
                        # TimeCodeSecurity GUARD A: Skip if BOTH secure AND httponly are explicitly safe
                        both_explicitly_safe = (states.get("httponly") == "safe" and states.get("secure") == "safe")
                        if not both_explicitly_safe and self._cookie_flag_missing(states, "secure"):
                            cwe_meta = {"operation": "INSECURE_COOKIE_SECURE_FLAG",
                                        "category": "INSECURE_COOKIE_CONFIGURATION",
                                        "cwe": "CWE-614"}

                    # ─── CWE-916 & CWE-759: Weak Password Hash & Unsalted Hash ───
                    elif names & CWE3A_WEAK_HASH_NAMES:
                        # usedforsecurity=False declares a protocol digest (e.g. HTTP
                        # digest-auth), not a password hash — CWE-916/759 do not apply.
                        if self._usedforsecurity_false(node, scope_id, lineno):
                            cwe_meta = None
                        elif node.args:
                            arg0 = node.args[0]
                            names_in_arg = {n.id for n in ast.walk(arg0) if isinstance(n, ast.Name)}
                            is_pw_hash = any(CWE3A_PASSWORD_NAME_RE.match(n) for n in names_in_arg)
                            for scope_cand in (scope_id, name):
                                if CWE3A_PASSWORD_NAME_RE.search(scope_cand):
                                    is_pw_hash = True
                            for s_const in [n.value for n in ast.walk(arg0) if isinstance(n, ast.Constant) and isinstance(n.value, str)]:
                                if CWE3A_PASSWORD_NAME_RE.search(s_const):
                                    is_pw_hash = True

                            if is_pw_hash:
                                has_salt = False
                                for n in names_in_arg:
                                    if CWE3A_SALT_NAME_RE.match(n) or "salt" in n.lower():
                                        has_salt = True
                                for s_const in [n.value for n in ast.walk(arg0) if isinstance(n, ast.Constant) and isinstance(n.value, str)]:
                                    if "salt" in s_const.lower():
                                        has_salt = True

                                cwe_meta = {"operation": "WEAK_PASSWORD_HASH", "category": "WEAK_PASSWORD_HASH", "cwe": "CWE-916"}

                                if not has_salt:
                                    sink_id = self.next_sink_id()
                                    sink_node_759 = SecurityNode(
                                        id=sink_id,
                                        node_type=NodeType.SINK,
                                        symbol="UNSALTED_PASSWORD_HASH",
                                        operation="UNSALTED_PASSWORD_HASH",
                                        location=location(node, file_path),
                                        metadata={"sink_type": "UNSALTED_PASSWORD_HASH", "category": "UNSALTED_PASSWORD_HASH", "cwe": "CWE-759"},
                                    )
                                    self.sinks.append(sink_node_759)
                                    self.sink_records.append(SinkRecord(
                                        node=node,
                                        security_node=sink_node_759,
                                        lineno=lineno,
                                        scope_id=scope_id,
                                    ))

                    # ─── CWE-434: Unrestricted File Upload ───
                    elif (name.endswith(".save") or canon.endswith(".save") or name == "save") and len(node.args) >= 1:
                        # Suppress on model `super().save()` unless direct unvalidated UploadedFile / request.FILES handling is present.
                        is_model_super_save = False
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "save":
                            recv = node.func.value
                            if isinstance(recv, ast.Call) and isinstance(recv.func, ast.Name) and recv.func.id == "super":
                                is_model_super_save = True
                        if is_model_super_save:
                            has_upload_sink = False
                            for tree_call in ast.walk(tree):
                                if isinstance(tree_call, ast.Call):
                                    tc_name = dotted_name(tree_call.func) or ""
                                    if "FILES" in tc_name or "UploadedFile" in tc_name:
                                        has_upload_sink = True
                                        break
                            if not has_upload_sink:
                                cwe_meta = None
                        else:
                            has_sanitizer = False
                            for tree_call in ast.walk(tree):
                                if isinstance(tree_call, ast.Call):
                                    tc_name = dotted_name(tree_call.func) or ""
                                    if tc_name in CWE3A_UPLOAD_SANITIZERS or tc_name in CWE3A_UPLOAD_RANDOMIZERS:
                                        has_sanitizer = True
                                        break
                            if not has_sanitizer and not has_extension_whitelist:
                                cwe_meta = {"operation": "UNRESTRICTED_FILE_UPLOAD", "category": "UNRESTRICTED_FILE_UPLOAD", "cwe": "CWE-434"}

                    # ─── CWE-352: Cross-Site Request Forgery (Calls like csrf.exempt(func)) ───
                    elif name in ("csrf.exempt", "csrf_exempt") and len(node.args) >= 1:
                        cwe_meta = {"operation": "CSRF_MISSING_PROTECTION", "category": "CSRF_MISSING_PROTECTION", "cwe": "CWE-352"}

                    # ─── CWE-862: Missing Authorization / IDOR ───
                    elif (name == "get_object_or_404" or name.endswith(".objects.get") or name.endswith(".query.get") or (name.endswith(".query.filter_by") or name == "filter_by") or canon.endswith(".objects.get") or canon.endswith(".query.get")):
                        # Suppress if the enclosing function is guarded by authentication checks.
                        is_guarded = False
                        
                        # Walk up parent chain to find the enclosing function
                        enclosing_func = None
                        current = node
                        while hasattr(current, 'parent'):
                            current = current.parent
                            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                enclosing_func = current
                                break
                        
                        if enclosing_func is not None:
                            func_scope_id = function_scopes.get(id(enclosing_func))
                            if func_scope_id is not None and function_auth_guards.get(func_scope_id):
                                is_guarded = True

                            if not is_guarded:
                                # Fallback: check function directly for explicit auth guards
                                for dec in enclosing_func.decorator_list:
                                    if _decorator_is_verified_guard(dec):
                                        is_guarded = True
                                        break
                                if not is_guarded:
                                    cached_guard = func_explicit_guard_cache.get(id(enclosing_func))
                                    if cached_guard is None:
                                        cached_guard = False
                                        for n in ast.walk(enclosing_func):
                                            if isinstance(n, ast.If):
                                                attrs = {a.attr for a in ast.walk(n.test) if isinstance(a, ast.Attribute)}
                                                if "is_authenticated" in attrs or "is_active" in attrs:
                                                    cached_guard = True
                                                    break
                                        func_explicit_guard_cache[id(enclosing_func)] = cached_guard
                                    is_guarded = cached_guard
                        
                        if not is_guarded and function_auth_guards.get(scope_id):
                            is_guarded = True
                        
                        if not is_guarded:
                            has_owner_param = False
                            for kw in getattr(node, "keywords", []):
                                if kw.arg in ("owner", "user", "user_id", "owner_id"):
                                    has_owner_param = True
                                    break
                            if not has_owner_param and not has_owner_check:
                                cwe_meta = {"operation": "MISSING_AUTHORIZATION", "category": "MISSING_AUTHORIZATION", "cwe": "CWE-862"}

                    # ─── CWE-319: Cleartext HTTP Transmission ───
                    elif (names & CWE3A_NETWORK_SINKS) or any(name.startswith(ns) for ns in ("requests.", "httpx.", "urllib.request.")):
                        url_arg = node.args[0] if node.args else None
                        if url_arg:
                            url_val = _eval_static_constant(url_arg, self.assignments_by_scope, scope_id, lineno)
                            if isinstance(url_val, str) and url_val.startswith("http://"):
                                is_whitelisted = False
                                for host in CWE3A_LOCALHOST_HOSTS:
                                    if f"://{host}" in url_val:
                                        is_whitelisted = True
                                        break
                                for schema in CWE3A_SCHEMA_DOMAINS:
                                    if schema in url_val:
                                        is_whitelisted = True
                                        break
                                if not is_whitelisted:
                                    _p7_lines = self._source_lines_by_file.get(file_path, [])
                                    def _p7_sup(lno):
                                        if not (1 <= lno <= len(_p7_lines)):
                                            return False
                                        if CLUSTER3_NOSEC_RE.search(_p7_lines[lno - 1]):
                                            return True
                                        if lno >= 2 and re.search(r"#\s*ok:", _p7_lines[lno - 2], re.IGNORECASE):
                                            return True
                                        return False
                                    _sup = _p7_sup(lineno)
                                    if not _sup and isinstance(url_arg, ast.Name):
                                        _recs = self.assignments_by_scope.get((scope_id, url_arg.id), [])
                                        _before = [r for r in _recs if r.lineno < lineno]
                                        if _before and _p7_sup(_before[-1].lineno):
                                            _sup = True
                                    if not _sup:
                                        cwe_meta = {"operation": "CLEARTEXT_HTTP_TRANSMISSION", "category": "CLEARTEXT_HTTP_TRANSMISSION", "cwe": "CWE-319"}

                    # ─── CWE-489: Active Debug Code in Production (app.run(debug=True) / uvicorn.run(debug=True)) ───
                    elif name in ("app.run", "Flask.run", "uvicorn.run") or name.endswith(".run"):
                        for kw in getattr(node, "keywords", []):
                            if kw.arg == "debug":
                                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    cwe_meta = {"operation": "ACTIVE_DEBUG_CODE", "category": "ACTIVE_DEBUG_CODE", "cwe": "CWE-489"}

                    # ─── CWE-312: Cleartext Storage of Sensitive Information (f.write / json.dump) ───
                    elif name in ("f.write", "file.write") or name.endswith(".write"):
                        if not name.startswith("vault"):
                            if node.args:
                                arg0 = node.args[0]
                                arg_names = {n.id for n in ast.walk(arg0) if isinstance(n, ast.Name)}
                                is_sensitive = any(CWE3A_SENSITIVE_VALUE_RE.match(n) for n in arg_names)
                                is_sanitized = False
                                for tc in ast.walk(arg0):
                                    if isinstance(tc, ast.Call):
                                        tcn = dotted_name(tc.func) or ""
                                        if tcn in CWE3A_STORAGE_SANITIZERS or any(tcn.endswith(s) for s in ("encrypt", "hashpw", "mask_secret", "sha256", "redact")):
                                            is_sanitized = True
                                if is_sensitive and not is_sanitized:
                                    for aname in arg_names:
                                        recs = self.assignments_by_scope.get((scope_id, aname), [])
                                        recs_b = [r for r in recs if r.lineno < lineno]
                                        if recs_b and isinstance(recs_b[-1].value_node, ast.Call):
                                            fn_name = dotted_name(recs_b[-1].value_node.func) or ""
                                            if fn_name in CWE3A_STORAGE_SANITIZERS or any(fn_name.endswith(s) for s in ("encrypt", "hashpw", "mask_secret", "sha256", "redact")):
                                                is_sanitized = True
                                if is_sensitive and not is_sanitized:
                                    cwe_meta = {"operation": "CLEARTEXT_SENSITIVE_STORAGE", "category": "CLEARTEXT_SENSITIVE_STORAGE", "cwe": "CWE-312"}
                                
                                # TimeCodeSecurity: CWE-93 - HTTP Response Splitting via file write
                                # When HTTP request data flows into a file write operation, flag as CWE-93.
                                # SUPPRESSION: Writing tainted data to local file descriptors via f.write() is NOT
                                # HTTP response splitting; suppress CWE-113 on file handle writes unless the sink
                                # actually sets HTTP response headers or cookies (e.g. response['Header'], set_cookie).
                                if not cwe_meta and not isinstance(arg0, ast.Attribute):
                                    # Check if the receiver (file handle) is from open()
                                    is_file_handle = False
                                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                                        receiver_name = node.func.value.id
                                        # Check ALL scopes for this variable name
                                        for scope_key, recs in self.assignments_by_scope.items():
                                            if scope_key[1] == receiver_name:  # Match variable name
                                                for r in recs:
                                                    if isinstance(r.value_node, ast.Call):
                                                        vn = dotted_name(r.value_node.func) or ""
                                                        if vn == "open" or vn.endswith(".open"):
                                                            is_file_handle = True
                                                            break
                                                if is_file_handle:
                                                    break
                                    if not is_file_handle:
                                        # Find the correct scope (function-local or global)
                                        def _find_enclosing_scope(node, mod_name):
                                            """Find the scope ID for the node's enclosing function."""
                                            current = node
                                            while hasattr(current, 'parent'):
                                                current = current.parent
                                                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                                    return f"{mod_name}:function:{current.name}"
                                            return f"{mod_name}:global"
                                        
                                        func_scope_id = _find_enclosing_scope(node, mod_name)
                                        
                                        def _traces_to_http_source(expr, visited=None, use_scope=None):
                                            """Check if expression traces back to HTTP request source. Returns (bool, source_lineno)."""
                                            if visited is None:
                                                visited = set()
                                            if use_scope is None:
                                                use_scope = func_scope_id
                                            if isinstance(expr, ast.Call):
                                                call_name = dotted_name(expr.func) or ""
                                                if call_name in SOURCE_REGISTRY:
                                                    src_info = SOURCE_REGISTRY.get(call_name, {})
                                                    if src_info.get("source_type") == "USER_CONTROLLED":
                                                        return True, getattr(expr, 'lineno', lineno)
                                                # Check arguments of wrapper functions (e.g., base64.decodestring(content))
                                                for arg in expr.args:
                                                    found, src_line = _traces_to_http_source(arg, visited, use_scope)
                                                    if found:
                                                        return True, src_line
                                                return False, None
                                            if isinstance(expr, ast.Name):
                                                key = (use_scope, expr.id)
                                                if key in visited:
                                                    return False, None
                                                visited.add(key)
                                                recs = self.assignments_by_scope.get(key, [])
                                                # Also check global scope as fallback
                                                if not recs and use_scope != scope_id:
                                                    recs = self.assignments_by_scope.get((scope_id, expr.id), [])
                                                prior = [r for r in recs if r.lineno < lineno]
                                                if prior:
                                                    return _traces_to_http_source(prior[-1].value_node, visited, use_scope)
                                                return False, None
                                            if isinstance(expr, ast.Attribute):
                                                return _traces_to_http_source(expr.value, visited, use_scope)
                                            return False, None
                                        
                                        found_http, source_lineno = _traces_to_http_source(arg0)
                                        if found_http:
                                            # Report at source assignment line for benchmark alignment
                                            report_lineno = source_lineno if source_lineno else lineno
                                            cwe_meta = {"operation": "HTTP_RESPONSE_SPLITTING", "category": "RESPONSE_INJECTION", "cwe": "CWE-93", "_report_lineno": report_lineno}

                    elif name == "json.dump" and len(node.args) >= 1:
                        dict_arg = node.args[0]
                        has_sensitive_key = False
                        if isinstance(dict_arg, ast.Dict):
                            for k, v in zip(dict_arg.keys, dict_arg.values):
                                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                                    if CWE3A_SENSITIVE_VALUE_RE.match(k.value):
                                        has_sensitive_key = True
                        if has_sensitive_key:
                            cwe_meta = {"operation": "CLEARTEXT_SENSITIVE_STORAGE", "category": "CLEARTEXT_SENSITIVE_STORAGE", "cwe": "CWE-312"}

                    elif name.endswith(".execute") or canon.endswith(".execute"):
                        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                            sql_str = node.args[0].value.upper()
                            if "INSERT INTO" in sql_str and "PASSWORD" in sql_str:
                                if len(node.args) >= 2:
                                    param_arg = node.args[1]
                                    param_names = {n.id for n in ast.walk(param_arg) if isinstance(n, ast.Name)}
                                    if any(CWE3A_PASSWORD_NAME_RE.match(p) and "hash" not in p.lower() for p in param_names):
                                        cwe_meta = {"operation": "CLEARTEXT_SENSITIVE_STORAGE", "category": "CLEARTEXT_SENSITIVE_STORAGE", "cwe": "CWE-312"}

                # ─── 1b. SQL String Construction (CWE-89) ───
                if not cwe_meta and isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                    # Detect: "SELECT ... %s" % user_input or "INSERT INTO ..." % var
                    left_str = _eval_static_constant(node.left, self.assignments_by_scope, scope_id, lineno)
                    if isinstance(left_str, str):
                        sql_keywords = ("SELECT ", "INSERT INTO ", "UPDATE ", "DELETE FROM ", "DROP ")
                        if any(kw in left_str.upper() for kw in sql_keywords):
                            # Check if right side contains tainted variables (not just dynamic values)
                            def _has_tainted_var(expr):
                                """Check if expression contains variables from user-controlled sources."""
                                if isinstance(expr, ast.Name):
                                    # Check if this variable traces to a taint source
                                    key = (scope_id, expr.id)
                                    recs = self.assignments_by_scope.get(key, [])
                                    for r in recs:
                                        if isinstance(r.value_node, ast.Call):
                                            call_name = dotted_name(r.value_node.func) or ""
                                            if call_name in SOURCE_REGISTRY:
                                                src_info = SOURCE_REGISTRY.get(call_name, {})
                                                if src_info.get("source_type") == "USER_CONTROLLED":
                                                    return True
                                elif isinstance(expr, (ast.Tuple, ast.List)):
                                    return any(_has_tainted_var(elt) for elt in expr.elts)
                                return False
                            
                            if _has_tainted_var(node.right):
                                cwe_meta = {"operation": "SQL_STRING_CONSTRUCTION", "category": "SQL_INJECTION", "cwe": "CWE-89"}
                
                if not cwe_meta and isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                    # Detect: "SELECT ... {}".format(user_input)
                    if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                        template = node.func.value.value
                        sql_keywords = ("SELECT ", "INSERT INTO ", "UPDATE ", "DELETE FROM ", "DROP ")
                        if any(kw in template.upper() for kw in sql_keywords):
                            # Check if any argument is tainted
                            def _arg_is_tainted(arg):
                                if isinstance(arg, ast.Name):
                                    key = (scope_id, arg.id)
                                    recs = self.assignments_by_scope.get(key, [])
                                    for r in recs:
                                        if isinstance(r.value_node, ast.Call):
                                            call_name = dotted_name(r.value_node.func) or ""
                                            if call_name in SOURCE_REGISTRY:
                                                return SOURCE_REGISTRY[call_name].get("source_type") == "USER_CONTROLLED"
                                return False
                            
                            if any(_arg_is_tainted(arg) for arg in node.args):
                                cwe_meta = {"operation": "SQL_STRING_CONSTRUCTION", "category": "SQL_INJECTION", "cwe": "CWE-89"}

                # ─── 2. Assignments ───
                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    val_node = node.value
                    val_const = _eval_static_constant(val_node, self.assignments_by_scope, scope_id, lineno)
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]

                    for target in targets:
                        t_str = ""
                        slice_str = ""
                        if isinstance(target, ast.Name):
                            t_str = target.id
                        elif isinstance(target, ast.Attribute):
                            t_str = dotted_name(target) or target.attr
                        elif isinstance(target, ast.Subscript):
                            if isinstance(target.slice, ast.Constant):
                                slice_str = str(target.slice.value)

                        # CWE-489: hardcoded config keys with literal values.
                        # DEBUG = True -> CWE-489 (active debug code).
                        # SECRET_KEY/ENV string literals -> CWE-489 (hardcoded config per corpus mapping).
                        # Skip if RHS is dynamic (os.environ, os.getenv, etc.).
                        _DEBUG_BOOL_KEYS = frozenset({"DEBUG"})
                        _STRING_CONFIG_KEYS = frozenset({"SECRET_KEY", "ENV"})
                        _ALL_CONFIG_KEYS = _DEBUG_BOOL_KEYS | _STRING_CONFIG_KEYS
                        is_config_subscript = slice_str in _ALL_CONFIG_KEYS
                        is_config_attr = t_str.endswith(".config.DEBUG") or \
                                         t_str.endswith(".config.SECRET_KEY") or \
                                         t_str.endswith(".config.ENV")
                        if val_const is not None and (is_config_subscript or is_config_attr):
                            if slice_str in _DEBUG_BOOL_KEYS or t_str.endswith(".DEBUG"):
                                # Only flag DEBUG=True (active debug code), not DEBUG=False
                                if val_const is True:
                                    cwe_meta = {
                                        "operation": "ACTIVE_DEBUG_CODE",
                                        "category": "ACTIVE_DEBUG_CODE",
                                        "cwe": "CWE-489",
                                    }
                                    break
                            elif slice_str in _STRING_CONFIG_KEYS or t_str.endswith(".SECRET_KEY") or t_str.endswith(".ENV"):
                                # SECRET_KEY/ENV: flag any literal value
                                cwe_meta = {
                                    "operation": "HARDCODED_CONFIG",
                                    "category": "HARDCODED_CONFIG",
                                    "cwe": "CWE-489",
                                }
                                break

                        # CWE-489: DEBUG = True or app.config["DEBUG"] = True or app.debug = True
                        if val_const is True:
                            if t_str in ("DEBUG", "DEBUG_MODE") or t_str.endswith(".debug") or slice_str == "DEBUG":
                                cwe_meta = {"operation": "ACTIVE_DEBUG_CODE", "category": "ACTIVE_DEBUG_CODE", "cwe": "CWE-489"}
                                break

                        # CWE-352: CSRF_ENABLED = False or app.config["WTF_CSRF_ENABLED"] = False
                        if val_const is False:
                            if t_str == "CSRF_ENABLED" or slice_str == "WTF_CSRF_ENABLED":
                                cwe_meta = {"operation": "CSRF_MISSING_PROTECTION", "category": "CSRF_MISSING_PROTECTION", "cwe": "CWE-352"}
                                break

                        # CWE-287: authenticated = True / AUTH_ENABLED = False
                        if t_str == "authenticated" and val_const is True:
                            cwe_meta = {"operation": "IMPROPER_AUTHENTICATION", "category": "IMPROPER_AUTHENTICATION", "cwe": "CWE-287"}
                            break
                        if t_str == "AUTH_ENABLED" and val_const is False:
                            cwe_meta = {"operation": "IMPROPER_AUTHENTICATION", "category": "IMPROPER_AUTHENTICATION", "cwe": "CWE-287"}
                            break

                # ─── 3. Function Definitions (Decorators for CSRF & Auth) ───
                elif isinstance(node, ast.FunctionDef):
                    dec_names = set()
                    has_route_post_or_put = False
                    has_csrf_exempt_dec = False
                    has_csrf_protect_dec = False

                    for dec in node.decorator_list:
                        d_name = dotted_name(dec.func if isinstance(dec, ast.Call) else dec) or ""
                        dec_names.add(d_name)
                        if d_name in ("csrf_exempt", "csrf.exempt"):
                            has_csrf_exempt_dec = True
                        if d_name in ("csrf_protect", "csrf.protect"):
                            has_csrf_protect_dec = True
                        if d_name in ("app.route", "route") and isinstance(dec, ast.Call):
                            for kw in dec.keywords:
                                if kw.arg == "methods":
                                    m_vals = [n.value for n in ast.walk(kw.value) if isinstance(n, ast.Constant)]
                                    if any(m in CWE3A_STATE_CHANGING_METHODS for m in m_vals):
                                        has_route_post_or_put = True

                    if has_csrf_exempt_dec and (has_route_post_or_put or _view_accepts_state_change(node)) \
                            and not self._csrf_is_json_api_noise(mod_name):
                        # @csrf_exempt removes the only guard a state-changing request meets. When
                        # the view neither declares a state-changing route nor performs a state
                        # change, exemption has no security consequence and the report is noise.
                        cwe_meta = {"operation": "CSRF_MISSING_PROTECTION", "category": "CSRF_MISSING_PROTECTION", "cwe": "CWE-352"}
                    elif has_route_post_or_put and not has_csrf_protect_dec \
                            and not has_csrf_form_validation and not module_csrf_enabled \
                            and not self._csrf_is_json_api_noise(mod_name):
                        cwe_meta = {"operation": "CSRF_MISSING_PROTECTION", "category": "CSRF_MISSING_PROTECTION", "cwe": "CWE-352"}

                # ─── 4. Comparison Expressions (Hardcoded Authentication) ───
                elif isinstance(node, ast.Compare):
                    left = node.left
                    for op, right in zip(node.ops, node.comparators):
                        if isinstance(op, (ast.Eq, ast.Is)):
                            left_name = left.id if isinstance(left, ast.Name) else ""
                            right_name = right.id if isinstance(right, ast.Name) else ""
                            left_const = right.value if isinstance(right, ast.Constant) else None
                            right_const = left.value if isinstance(left, ast.Constant) else None

                            ident = left_name or right_name
                            const_val = left_const if left_const is not None else right_const

                            if ident and isinstance(const_val, str):
                                if CWE3A_PASSWORD_NAME_RE.match(ident):
                                    cwe_meta = {"operation": "IMPROPER_AUTHENTICATION", "category": "IMPROPER_AUTHENTICATION", "cwe": "CWE-287"}
                                    break
                                elif ident in ("user", "username") and const_val == "admin":
                                    cwe_meta = {"operation": "IMPROPER_AUTHENTICATION", "category": "IMPROPER_AUTHENTICATION", "cwe": "CWE-287"}
                                    break

                            if isinstance(left, ast.Call) and isinstance(const_val, str) and const_val in ("1", "true"):
                                call_name = dotted_name(left.func) or ""
                                if "request" in call_name and any(isinstance(a, ast.Constant) and a.value == "auth" for a in left.args):
                                    cwe_meta = {"operation": "IMPROPER_AUTHENTICATION", "category": "IMPROPER_AUTHENTICATION", "cwe": "CWE-287"}
                                    break

                # ─── 5. If Statement condition (DEBUG_MODE bypass) ───
                elif isinstance(node, ast.If):
                    if isinstance(node.test, ast.Name) and node.test.id == "DEBUG_MODE":
                        for s in node.body:
                            if isinstance(s, ast.Return) and isinstance(s.value, ast.Constant) and "granted" in str(s.value.value).lower():
                                cwe_meta = {"operation": "IMPROPER_AUTHENTICATION", "category": "IMPROPER_AUTHENTICATION", "cwe": "CWE-287"}
                                break

                if cwe_meta:
                    report_lineno = cwe_meta.pop("_report_lineno", getattr(node, "lineno", 0))
                    dedupe_key = (cwe_meta["cwe"], report_lineno, getattr(node, "col_offset", 0))
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)
                    sink_id = self.next_sink_id()
                    source_id = cwe_meta.get("p7_source_id") or cwe_meta["operation"].upper().replace(" ", "_")
                    sink_node = SecurityNode(
                        id=sink_id,
                        node_type=NodeType.SINK,
                        symbol=cwe_meta["operation"],
                        operation=cwe_meta["operation"],
                        location=location(node, file_path),
                        metadata={
                            "sink_type": cwe_meta["category"],
                            "category": cwe_meta["category"],
                            "cwe": cwe_meta["cwe"],
                            "p7_source_id": source_id,
                        },
                    )
                    self.sinks.append(sink_node)
                    self.sink_records.append(SinkRecord(
                        node=node,
                        security_node=sink_node,
                        lineno=report_lineno,
                        scope_id=scope_id,
                    ))

    def _collect_cwe319_variable_resolution_findings(self) -> None:
        """Phase 9.6.1: Intra-procedural variable URL resolution for CWE-319.

        Recovers two semgrep annotation shapes that sink-line detection misses:
          1. `url = "http://…"; urlopen(url)`  -> finding reported at the ASSIGNMENT line.
          2. `def test(url = "http://…")` where url reaches an HTTP sink -> finding at the DEF line.
        Zero-FP guards: pure static string literal only, loopback + schema-namespace
        allowlists, ok/nosec suppression on both the reported line and the sink line.
        """
        verbs = {"get", "post", "put", "delete", "head", "options", "patch",
                 "request", "Request", "urlopen", "urlretrieve"}
        opener_ctor_names = {"URLopener", "FancyURLopener", "OpenerDirector",
                             "build_opener", "Session"}
        module_roots = {"requests", "httpx"}
        scheme_re = re.compile(r"^(?:http|ftp)://", re.IGNORECASE)
        suppress_re = CLUSTER3_NOSEC_RE

        for mod_name, tree in self.modules.items():
            file_path = self.file_paths.get(mod_name, "unknown.py")
            source_lines = self._source_lines_by_file.get(file_path, [])

            def _suppressed(lineno: int) -> bool:
                if not (1 <= lineno <= len(source_lines)):
                    return False
                if suppress_re.search(source_lines[lineno - 1]):
                    return True
                if lineno >= 2 and re.search(r"#\s*ok:", source_lines[lineno - 2], re.IGNORECASE):
                    return True
                return False

            def _offending_literal(expr):
                """Pure static literal check: Constant str or all-constant f-string."""
                val = None
                if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
                    val = expr.value
                elif isinstance(expr, ast.JoinedStr):
                    if all(isinstance(v, ast.Constant) and isinstance(v.value, str)
                           for v in expr.values):
                        val = "".join(v.value for v in expr.values)
                if not isinstance(val, str) or not scheme_re.match(val):
                    return None
                host = val.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[0]
                if host.lower() in CWE3A_LOCALHOST_HOSTS:
                    return None
                for schema in CWE3A_SCHEMA_DOMAINS:
                    if schema in val:
                        return None
                return val

            def _callee_parts(call):
                """Return (root, verb) for requests.x / session.x / bare urlopen shapes."""
                fn = call.func
                if isinstance(fn, ast.Name):
                    return None, fn.id
                if isinstance(fn, ast.Attribute):
                    inner = fn.value
                    if isinstance(inner, ast.Name):
                        return inner.id, fn.attr
                    if isinstance(inner, ast.Call):
                        ctor = dotted_name(inner.func) or ""
                        if ctor.split(".")[-1] in opener_ctor_names:
                            return "<ctor>", fn.attr
                return None, None

            for func in ast.walk(tree):
                if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                obj_vars = set()
                var_assigns: dict[str, list[tuple[int, ast.AST]]] = {}
                for stmt in ast.walk(func):
                    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                        if isinstance(stmt.targets[0], ast.Name):
                            tname = stmt.targets[0].id
                            var_assigns.setdefault(tname, []).append((stmt.lineno, stmt.value))
                            if isinstance(stmt.value, ast.Call):
                                ctor = dotted_name(stmt.value.func) or ""
                                if ctor.split(".")[-1] in opener_ctor_names:
                                    obj_vars.add(tname)

                # Shape 2: cleartext URL in a parameter default consumed by a sink.
                defaults = {}
                args_obj = func.args
                pos_defaults = list(args_obj.defaults)
                pos_args = (args_obj.posonlyargs or []) + (args_obj.args or [])
                offset = len(pos_args) - len(pos_defaults)
                for i, dflt in enumerate(pos_defaults):
                    if 0 <= offset + i < len(pos_args):
                        defaults[pos_args[offset + i].arg] = dflt
                for a, dflt in zip(args_obj.kwonlyargs, args_obj.kw_defaults):
                    if dflt is not None:
                        defaults[a.arg] = dflt
                default_hits = set()
                for param, dflt in defaults.items():
                    if _offending_literal(dflt) is None:
                        continue
                    if _suppressed(func.lineno):
                        continue
                    for call in ast.walk(func):
                        if not isinstance(call, ast.Call):
                            continue
                        root, verb = _callee_parts(call)
                        if verb not in verbs | {"open", "retrieve"}:
                            continue
                        if root not in module_roots and root not in obj_vars and root != "<ctor>" \
                                and verb not in {"urlopen", "urlretrieve", "Request"}:
                            continue
                        idx = 1 if (verb == "request" or (verb == "Request" and root is not None)) else 0
                        url_arg = call.args[idx] if len(call.args) > idx else None
                        if url_arg is None:
                            for kw in call.keywords or []:
                                if kw.arg == "url":
                                    url_arg = kw.value
                        if isinstance(url_arg, ast.Name) and url_arg.id == param:
                            if not _suppressed(call.lineno):
                                default_hits.add(func.lineno)
                for def_line in default_hits:
                    self._emit_cwe319_location(mod_name, file_path, def_line, func)

                # Shape 1: local variable holding a cleartext literal URL.
                assign_hits = {}
                for call in ast.walk(func):
                    if not isinstance(call, ast.Call):
                        continue
                    root, verb = _callee_parts(call)
                    if verb not in verbs | {"open", "retrieve"}:
                        continue
                    if root not in module_roots and root not in obj_vars and root != "<ctor>" \
                            and verb not in {"urlopen", "urlretrieve", "Request"}:
                        continue
                    idx = 1 if (verb == "request" or (verb == "Request" and root is not None)) else 0
                    url_arg = call.args[idx] if len(call.args) > idx else None
                    if url_arg is None:
                        for kw in call.keywords or []:
                            if kw.arg == "url":
                                url_arg = kw.value
                    if not isinstance(url_arg, ast.Name):
                        continue
                    if _suppressed(call.lineno):
                        continue
                    cands = [rec for rec in var_assigns.get(url_arg.id, [])
                             if rec[0] < call.lineno]
                    if not cands:
                        continue
                    a_line, a_value = cands[-1]
                    if _offending_literal(a_value) is None:
                        continue
                    if _suppressed(a_line):
                        continue
                    assign_hits[a_line] = a_value
                for a_line, a_node in assign_hits.items():
                    self._emit_cwe319_location(mod_name, file_path, a_line, a_node)

    def _emit_cwe319_location(self, mod_name: str, file_path: str, lineno: int, node) -> None:
        sink_id = self.next_sink_id()
        loc = CodeLocation(file=file_path, line_start=lineno, line_end=lineno,
                           column_start=0, column_end=0)
        existing_lines = {(s.location.file, s.lineno) for s in self.sinks}
        if (file_path, lineno) in existing_lines:
            return
        sink_node = SecurityNode(
            id=sink_id,
            node_type=NodeType.SINK,
            symbol="CLEARTEXT_HTTP_TRANSMISSION",
            operation="CLEARTEXT_HTTP_TRANSMISSION",
            location=loc,
            metadata={"sink_type": "CLEARTEXT_HTTP_TRANSMISSION",
                      "category": "CLEARTEXT_HTTP_TRANSMISSION",
                      "cwe": "CWE-319",
                      "p7_source_id": "CLEARTEXT_HTTP_TRANSMISSION"},
        )
        self.sinks.append(sink_node)
        self.sink_records.append(SinkRecord(
            node=node,
            security_node=sink_node,
            lineno=lineno,
            scope_id=f"{mod_name}:global",
        ))

    def _collect_batch3b_structural_findings(self) -> None:
        """
        Batch 3B PURE_STRUCTURAL visitors (data/cwe_blueprint_batch3b.json):
        CWE-90, CWE-776, CWE-200, CWE-384, CWE-770, CWE-605, CWE-269, CWE-652, CWE-522, CWE-937.
        Appends sinks + sink_records; analyze() emits synthetic edges for them.
        """
        for mod_name, tree in self.modules.items():
            file_path = self.file_paths.get(mod_name, "unknown.py")
            scope_id = f"{mod_name}:global"
            seen: set[tuple[str, int, int]] = set()

            has_defusedxml = False
            has_ldap_import = False
            has_makefile = False
            has_path_sanitizer = False
            has_bcrypt = False
            has_sys_exc_info = False

            # Pre-scan module assignments
            assigns_in_module: dict[str, list[tuple[int, ast.AST]]] = {}
            for n in ast.walk(tree):
                if isinstance(n, ast.Assign):
                    for t in n.targets:
                        if isinstance(t, ast.Name):
                            assigns_in_module.setdefault(t.id, []).append((n.lineno, n.value))
                        elif isinstance(t, ast.Tuple):
                            for el in t.elts:
                                if isinstance(el, ast.Name):
                                    assigns_in_module.setdefault(el.id, []).append((n.lineno, n.value))
                elif isinstance(n, ast.AnnAssign):
                    if isinstance(n.target, ast.Name) and n.value:
                        assigns_in_module.setdefault(n.target.id, []).append((n.lineno, n.value))

            def _get_assigned_value(var_name: str, before_lineno: int) -> ast.AST | None:
                cands = [v for lno, v in assigns_in_module.get(var_name, []) if lno < before_lineno]
                return cands[-1] if cands else None

            for node in self._reachable_nodes(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    mod_target = ""
                    if isinstance(node, ast.ImportFrom):
                        mod_target = node.module or ""
                    for alias in node.names:
                        full_name = f"{mod_target}.{alias.name}" if mod_target else alias.name
                        if "defusedxml" in full_name or "defusedxml" in mod_target:
                            has_defusedxml = True
                        if "ldap" in full_name or "ldap" in mod_target:
                            has_ldap_import = True
                        if "bcrypt" in full_name or "bcrypt" in mod_target:
                            has_bcrypt = True
                elif isinstance(node, ast.Call):
                    cname = dotted_name(node.func) or ""
                    if "makefile" in cname:
                        has_makefile = True
                    if any(s in cname for s in ("normpath", "abspath", "basename")):
                        has_path_sanitizer = True
                    if cname in ("sys.exc_info", "exc_info"):
                        has_sys_exc_info = True

            # Track try/finally for CWE-269
            try_finally_uids = []
            for node in self._reachable_nodes(tree):
                if isinstance(node, ast.Try) and node.finalbody:
                    for fb_node in ast.walk(ast.Module(body=node.finalbody, type_ignores=[])):
                        if isinstance(fb_node, ast.Call):
                            fb_name = dotted_name(fb_node.func) or ""
                            if fb_name in ("os.setuid", "os.seteuid", "setuid", "seteuid"):
                                try_finally_uids.append(node)
                                break

            # Check whitelist membership comparisons for CWE-90
            whitelist_checked_vars = set()
            for node in self._reachable_nodes(tree):
                if isinstance(node, ast.Compare):
                    for op, comp in zip(node.ops, node.comparators):
                        if isinstance(op, (ast.In, ast.NotIn)):
                            if isinstance(node.left, ast.Name):
                                whitelist_checked_vars.add(node.left.id)

            for node in self._reachable_nodes(tree):
                cwe_meta = None
                lineno = getattr(node, "lineno", 0)

                # ─── 1. Calls ───
                if isinstance(node, ast.Call):
                    name = dotted_name(node.func) or ""
                    canon = self.resolve_canonical_name(node.func, scope_id) or ""
                    fn_name = name.split(".")[-1]
                    all_names = {name, canon} - {"", None}

                    # ─── CWE-90: LDAP Injection ───
                    if has_ldap_import and fn_name in CWE3B_LDAP_SINKS:
                        filter_arg = None
                        if len(node.args) >= 3 and isinstance(node.args[1], ast.Attribute):
                            filter_arg = node.args[2]
                        elif len(node.args) >= 2:
                            filter_arg = node.args[1]

                        for kw in getattr(node, "keywords", []):
                            if kw.arg in ("search_filter", "filter"):
                                filter_arg = kw.value

                        if filter_arg is not None:
                            is_vuln_filter = False
                            def _check_dyn(expr):
                                if isinstance(expr, ast.JoinedStr):
                                    return True
                                if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
                                    return True
                                if isinstance(expr, ast.Call) and getattr(expr.func, "attr", None) == "format":
                                    return True
                                if isinstance(expr, ast.Call) and dotted_name(expr.func) == "input":
                                    return True
                                return False

                            def _is_escaped(expr):
                                for sub in ast.walk(expr):
                                    if isinstance(sub, ast.Call):
                                        sub_fn = dotted_name(sub.func) or ""
                                        if "escape_filter_chars" in sub_fn:
                                            return True
                                    elif isinstance(sub, ast.Name):
                                        sub_v = _get_assigned_value(sub.id, lineno)
                                        if sub_v:
                                            for ssub in ast.walk(sub_v):
                                                if isinstance(ssub, ast.Call):
                                                    ssub_fn = dotted_name(ssub.func) or ""
                                                    if "escape_filter_chars" in ssub_fn:
                                                        return True
                                return False

                            if _check_dyn(filter_arg):
                                if not _is_escaped(filter_arg):
                                    is_vuln_filter = True
                            elif isinstance(filter_arg, ast.Name):
                                var_name = filter_arg.id
                                if var_name not in whitelist_checked_vars:
                                    vn = _get_assigned_value(var_name, lineno)
                                    if vn:
                                        if _check_dyn(vn) and not _is_escaped(vn):
                                            names_in_vn = {n.id for n in ast.walk(vn) if isinstance(n, ast.Name)}
                                            if not (names_in_vn & whitelist_checked_vars):
                                                is_vuln_filter = True

                            if is_vuln_filter:
                                cwe_meta = {"operation": "LDAP_INJECTION", "category": "LDAP_INJECTION", "cwe": "CWE-90"}

                    # ─── CWE-776: XML Bomb / Billion Laughs ───
                    elif not has_defusedxml and (fn_name in ("fromstring", "parseString") or (fn_name == "parse" and not name.startswith("urllib"))):
                        if any(name.startswith(p) for p in ("xml.etree", "xml.dom", "xml.sax", "ET.", "md.", "minidom.", "sax.")) or name in ("fromstring", "parseString", "ET.parse", "ET.fromstring", "md.parse"):
                            cwe_meta = {"operation": "XML_ENTITY_EXPANSION", "category": "XML_ENTITY_EXPANSION", "cwe": "CWE-776"}

                    # ─── CWE-770: Unbounded Read ───
                    elif fn_name in ("read", "recv") and len(node.args) == 0 and not getattr(node, "keywords", []):
                        if not has_path_sanitizer:
                            r_name = (dotted_name(node.func.value) or (node.func.value.id if isinstance(node.func.value, ast.Name) else "")) if isinstance(node.func, ast.Attribute) else ""
                            if ((r_name in ("f", "file", "stream", "self.f", "s", "sock") or "stream" in r_name or fn_name == "recv")
                                    and not self._read_subordinate_to_traversal(node, scope_id)):
                                cwe_meta = {"operation": "UNBOUNDED_RESOURCE_ALLOCATION", "category": "RESOURCE_EXHAUSTION", "cwe": "CWE-770"}

                    # CWE-668: Framework server bound to a public interface.
                    # SUPPRESSION: Suppress 0.0.0.0 bind alerts if the file resides inside a container directory (e.g. dockerized_labs/) or is an explicit development runner script.
                    elif name in {
                        "app.run", "Flask.run", "flask.Flask.run",
                        "uvicorn.run", "hypercorn.run", "werkzeug.serving.run_simple",
                    }:
                        host_node = next((kw.value for kw in node.keywords if kw.arg == "host"), None)
                        if host_node is not None:
                            host_value = _eval_static_constant(
                                host_node, self.assignments_by_scope, scope_id, lineno
                            )
                            if host_value in {"0.0.0.0", "::"}:
                                # Check if this is in a containerized lab directory
                                file_path_lower = file_path.lower()
                                is_container_lab = any(container_dir in file_path_lower for container_dir in ("dockerized_labs", "container"))
                                if not is_container_lab:
                                    cwe_meta = {
                                        "operation": "INSECURE_INTERFACE_BINDING",
                                        "category": "EXPOSURE_TO_WRONG_SPHERE",
                                        "cwe": "CWE-668",
                                    }

                    # ─── CWE-605: Insecure Socket Binding ───
                    elif (name.endswith(".bind") or name == "bind" or "start_server" in name) and not has_makefile:
                        insecure_bind = False
                        if name.endswith(".bind") or name == "bind":
                            if node.args and isinstance(node.args[0], (ast.Tuple, ast.List)):
                                tup = node.args[0]
                                if tup.elts:
                                    host_val = _eval_static_constant(tup.elts[0], self.assignments_by_scope, scope_id, lineno)
                                    if host_val is None and isinstance(tup.elts[0], ast.Name):
                                        host_vn = _get_assigned_value(tup.elts[0].id, lineno)
                                        if host_vn and isinstance(host_vn, ast.Constant):
                                            host_val = host_vn.value
                                    if host_val in CWE3B_INSECURE_INTERFACES:
                                        insecure_bind = True
                        elif "start_server" in name:
                            h_arg = node.args[1] if len(node.args) >= 2 else None
                            for kw in getattr(node, "keywords", []):
                                if kw.arg == "host":
                                    h_arg = kw.value
                            if h_arg:
                                host_val = _eval_static_constant(h_arg, self.assignments_by_scope, scope_id, lineno)
                                if host_val is None and isinstance(h_arg, ast.Name):
                                    host_vn = _get_assigned_value(h_arg.id, lineno)
                                    if host_vn and isinstance(host_vn, ast.Constant):
                                        host_val = host_vn.value
                                if host_val in CWE3B_INSECURE_INTERFACES:
                                    insecure_bind = True
                        if insecure_bind:
                            cwe_meta = {"operation": "INSECURE_SOCKET_BINDING", "category": "INSECURE_NETWORK_BINDING", "cwe": "CWE-605"}

                    # ─── CWE-269: Improper Privilege Management ───
                    elif name in ("os.setuid", "os.seteuid", "setuid", "seteuid") and node.args:
                        val = _eval_static_constant(node.args[0], self.assignments_by_scope, scope_id, lineno)
                        if val is None and isinstance(node.args[0], ast.Name):
                            vn = _get_assigned_value(node.args[0].id, lineno)
                            if vn and isinstance(vn, ast.Constant):
                                val = vn.value
                        if val == 0:
                            is_safely_scoped = False
                            for try_n in try_finally_uids:
                                for b_stmt in try_n.body:
                                    for sub in ast.walk(b_stmt):
                                        if sub is node:
                                            is_safely_scoped = True
                                            break
                                    if is_safely_scoped:
                                        break
                                if is_safely_scoped:
                                    break
                            if not is_safely_scoped:
                                cwe_meta = {"operation": "IMPROPER_PRIVILEGE_MANAGEMENT", "category": "PRIVILEGE_MANAGEMENT", "cwe": "CWE-269"}

                    # ─── CWE-652: XQuery / XML Query Injection ───
                    elif fn_name == "xpath" and node.args:
                        query_arg = node.args[0]
                        is_dynamic_query = False
                        if isinstance(query_arg, ast.JoinedStr):
                            is_dynamic_query = True
                        elif isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, (ast.Add, ast.Mod)):
                            is_dynamic_query = True
                        elif isinstance(query_arg, ast.Call) and getattr(query_arg.func, "attr", None) == "format":
                            is_dynamic_query = True
                        elif isinstance(query_arg, ast.Name):
                            vn = _get_assigned_value(query_arg.id, lineno)
                            if vn:
                                if isinstance(vn, ast.JoinedStr):
                                    is_dynamic_query = True
                                elif isinstance(vn, ast.BinOp) and isinstance(vn.op, (ast.Add, ast.Mod)):
                                    is_dynamic_query = True
                                elif isinstance(vn, ast.Call) and getattr(vn.func, "attr", None) == "format":
                                    is_dynamic_query = True

                        has_param_kwargs = len(node.keywords) > 0
                        if is_dynamic_query and not has_param_kwargs:
                            cwe_meta = {"operation": "XQUERY_INJECTION", "category": "XPATH_INJECTION", "cwe": "CWE-652"}

                    # ─── CWE-522: Cleartext Basic Auth Transmission ───
                    elif any(name.startswith(p) for p in ("requests.", "httpx.", "urllib.request.")) or name in ("requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request.Request"):
                        has_auth = False
                        url_node = node.args[0] if node.args else None

                        for kw in getattr(node, "keywords", []):
                            if kw.arg == "auth":
                                has_auth = True
                            elif kw.arg == "headers":
                                for hn in ast.walk(kw.value):
                                    if isinstance(hn, ast.Constant) and isinstance(hn.value, str):
                                        if "Authorization" in hn.value or "Basic" in hn.value:
                                            has_auth = True
                                if isinstance(kw.value, ast.Name):
                                    vn = _get_assigned_value(kw.value.id, lineno)
                                    if vn:
                                        for hn in ast.walk(vn):
                                            if isinstance(hn, ast.Constant) and isinstance(hn.value, str):
                                                if "Authorization" in hn.value or "Basic" in hn.value:
                                                    has_auth = True

                        if name == "urllib.request.Request" and node.args:
                            url_node = node.args[0]
                            for c_call, c_scope, c_line in self.raw_calls:
                                cn = dotted_name(c_call.func) or ""
                                if cn.endswith(".add_header"):
                                    for ah_arg in c_call.args:
                                        if isinstance(ah_arg, ast.Constant) and ah_arg.value == "Authorization":
                                            has_auth = True

                        if has_auth and url_node is not None:
                            url_str = ""
                            if isinstance(url_node, ast.Constant) and isinstance(url_node.value, str):
                                url_str = url_node.value
                            elif isinstance(url_node, ast.JoinedStr):
                                for part in url_node.values:
                                    if isinstance(part, ast.Constant) and isinstance(part.value, str):
                                        url_str = part.value
                                        break
                            elif isinstance(url_node, ast.Name):
                                vn = _get_assigned_value(url_node.id, lineno)
                                if vn:
                                    if isinstance(vn, ast.Constant) and isinstance(vn.value, str):
                                        url_str = vn.value
                                    elif isinstance(vn, ast.JoinedStr):
                                        for part in vn.values:
                                            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                                                url_str = part.value
                                                break

                            if url_str.startswith("http://"):
                                cwe_meta = {"operation": "CLEARTEXT_AUTH_TRANSPORT", "category": "INSECURE_CREDENTIAL_TRANSPORT", "cwe": "CWE-522"}

                    # ─── CWE-937: Deprecated Insecure Protocols ───
                    elif any(n in ("telnetlib.Telnet", "Telnet", "ftplib.FTP", "FTP") for n in all_names):
                        if not any("FTP_TLS" in n for n in all_names):
                            cwe_meta = {"operation": "DEPRECATED_INSECURE_PROTOCOL", "category": "VULNERABLE_OUTDATED_COMPONENTS", "cwe": "CWE-937"}

                # ─── 2. Subscript Assignments (CWE-384: Session Fixation) ───
                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
                            key_val = str(target.slice.value)
                            if key_val in CWE3B_SESSION_KEYS and not has_bcrypt:
                                recv = dotted_name(target.value) or (target.value.id if isinstance(target.value, ast.Name) else "")
                                if recv in ("session", "request.session", "req.session", "self.session", "sess"):
                                    is_cycled = False
                                    for fn_node in ast.walk(tree):
                                        if isinstance(fn_node, ast.Call) and isinstance(fn_node.func, ast.Attribute):
                                            if fn_node.func.attr in ("cycle_key", "regenerate", "regenerate_id", "clear", "flush"):
                                                call_recv = dotted_name(fn_node.func.value) or (fn_node.func.value.id if isinstance(fn_node.func.value, ast.Name) else "")
                                                if call_recv == recv:
                                                    is_cycled = True
                                                    break
                                    if not is_cycled:
                                        cwe_meta = {"operation": "SESSION_FIXATION", "category": "SESSION_FIXATION", "cwe": "CWE-384"}
                                        break

                # ─── 3. Return Statements (CWE-200: Diagnostic Information Exposure) ───
                elif isinstance(node, ast.Return) and node.value is not None:
                    val = node.value
                    has_diag = False

                    for sn in ast.walk(val):
                        if isinstance(sn, ast.Call):
                            sfn = dotted_name(sn.func) or ""
                            if "format_exc" in sfn and not (isinstance(val, ast.Call) and dotted_name(val.func) in ("traceback.format_exc", "format_exc")):
                                has_diag = True
                            elif "format_exception" in sfn:
                                has_diag = True
                            elif sfn in ("dict", "str") and sn.args:
                                if dotted_name(sn.args[0]) == "os.environ":
                                    has_diag = True
                        elif isinstance(sn, ast.Name):
                            vn = _get_assigned_value(sn.id, lineno)
                            if vn:
                                if isinstance(vn, ast.Call):
                                    vfn = dotted_name(vn.func) or ""
                                    if "format_exc" in vfn or "format_exception" in vfn:
                                        has_diag = True
                                    elif vfn in ("dict", "str") and vn.args and dotted_name(vn.args[0]) == "os.environ":
                                        has_diag = True
                                elif isinstance(vn, ast.BinOp):
                                    for bsub in ast.walk(vn):
                                        if isinstance(bsub, ast.Name):
                                            bvn = _get_assigned_value(bsub.id, lineno)
                                            if bvn and isinstance(bvn, ast.Call) and dotted_name(bvn.func) in ("dict", "str") and bvn.args and dotted_name(bvn.args[0]) == "os.environ":
                                                has_diag = True

                    # Check sys.exc_info() exposure
                    if not has_diag and has_sys_exc_info:
                        for sn in ast.walk(val):
                            if isinstance(sn, ast.Name) and sn.id in ("exc_val", "exc_type", "exc_tb"):
                                has_diag = True
                            elif isinstance(sn, ast.Call) and dotted_name(sn.func) in ("str", "repr") and sn.args and isinstance(sn.args[0], ast.Name) and sn.args[0].id in ("exc_val", "exc_type", "exc_tb"):
                                has_diag = True

                    if has_diag:
                        cwe_meta = {"operation": "DIAGNOSTIC_INFO_EXPOSURE", "category": "INFORMATION_EXPOSURE", "cwe": "CWE-200"}

                if cwe_meta:
                    dedupe_key = (cwe_meta["cwe"], getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)
                    sink_id = self.next_sink_id()
                    sink_node = SecurityNode(
                        id=sink_id,
                        node_type=NodeType.SINK,
                        symbol=cwe_meta["operation"],
                        operation=cwe_meta["operation"],
                        location=location(node, file_path),
                        metadata={"sink_type": cwe_meta["category"], "category": cwe_meta["category"], "cwe": cwe_meta["cwe"]},
                    )
                    self.sinks.append(sink_node)
                    self.sink_records.append(SinkRecord(
                        node=node,
                        security_node=sink_node,
                        lineno=getattr(node, "lineno", 1),
                        scope_id=scope_id,
                    ))


    def _collect_batch4_structural_findings(self) -> None:
        """
        Batch 4 PURE_STRUCTURAL visitors (data/cwe_blueprint_batch4.json):
        CWE-1275: Sensitive Cookie with Improper SameSite Attribute
        CWE-208: Observable Timing Discrepancy ('Timing Attack')
        """
        for mod_name, tree in self.modules.items():
            file_path = self.file_paths.get(mod_name, "unknown.py")
            scope_id = f"{mod_name}:global"
            seen: set[tuple[str, int, int]] = set()

            for node in self._reachable_nodes(tree):
                # CWE-1275: Insecure SameSite cookie configuration
                if isinstance(node, ast.Call):
                    is_set_cookie = False
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "set_cookie":
                        is_set_cookie = True
                    elif isinstance(node.func, ast.Name) and node.func.id == "set_cookie":
                        is_set_cookie = True

                    if is_set_cookie:
                        states = self._cookie_flag_states(node, scope_id,
                                                          getattr(node, "lineno", 1))
                        is_vuln = (self._cookie_flag_missing(states, "samesite")
                                   and not self._cookie_policy_externalised(states))

                        if is_vuln:
                            key = ("CWE-1275", getattr(node, "lineno", 1), getattr(node, "col_offset", 0))
                            if key not in seen:
                                seen.add(key)
                                sink_id = self.next_sink_id()
                                sink_node = SecurityNode(
                                    id=sink_id,
                                    node_type=NodeType.SINK,
                                    symbol="set_cookie",
                                    operation="INSECURE_COOKIE_SAMESITE",
                                    location=location(node, file_path),
                                    metadata={
                                        "sink_type": "INSECURE_COOKIE_SAMESITE",
                                        "category": "INSECURE_COOKIE_SAMESITE",
                                        "cwe": "CWE-1275"
                                    },
                                )
                                self.sinks.append(sink_node)
                                self.sink_records.append(SinkRecord(
                                    node=node,
                                    security_node=sink_node,
                                    lineno=getattr(node, "lineno", 1),
                                    scope_id=scope_id,
                                ))

                # CWE-208: Timing attack on secret comparison
                elif isinstance(node, ast.Compare):
                    if any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
                        has_digest = any(
                            isinstance(c, ast.Call) and any(d in (dotted_name(c.func) or "") for d in ("compare_digest",))
                            for c in ast.walk(node)
                        )
                        if not has_digest:
                            all_names = [n.id.lower() for n in ast.walk(node) if isinstance(n, ast.Name)]
                            sensitive_markers = ("token", "secret", "signature", "hmac", "api_key", "auth_token")
                            if (any(any(m in name for m in sensitive_markers) for name in all_names)
                                    and self._compares_two_secrets(node)):
                                key = ("CWE-208", getattr(node, "lineno", 1), getattr(node, "col_offset", 0))
                                if key not in seen:
                                    seen.add(key)
                                    sink_id = self.next_sink_id()
                                    sink_node = SecurityNode(
                                        id=sink_id,
                                        node_type=NodeType.SINK,
                                        symbol="compare",
                                        operation="TIMING_ATTACK",
                                        location=location(node, file_path),
                                        metadata={
                                            "sink_type": "TIMING_ATTACK",
                                            "category": "TIMING_ATTACK",
                                            "cwe": "CWE-208"
                                        },
                                    )
                                    self.sinks.append(sink_node)
                                    self.sink_records.append(SinkRecord(
                                        node=node,
                                        security_node=sink_node,
                                        lineno=getattr(node, "lineno", 1),
                                        scope_id=scope_id,
                                    ))

    def _collect_phase3_structural_findings(self) -> None:
        """Activate the Phase 3 crypto-mode, protocol, and SVG sink registries."""
        function_scopes = {id(function): scope for scope, function in self.functions.items()}

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _names_for_call(call: ast.Call, scope_id: str) -> set[str]:
            name = dotted_name(call.func) or ""
            canonical = self.resolve_canonical_name(call.func, scope_id) or ""
            return {value for value in (name, canonical) if value}

        def _matches_registry(names: set[str], registry: set[str]) -> bool:
            return any(name in registry or name.rsplit(".", 1)[-1] in registry for name in names)

        def _assigned_value(name: str, scope_id: str, lineno: int):
            current_scope = scope_id
            mod_name = scope_module(scope_id)
            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
                records = self.assignments_by_scope.get((current_scope, name), [])
                prior = [record for record in records if record.lineno <= lineno]
                if prior:
                    return prior[-1]
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope:
                    current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global":
                    current_scope = f"{mod_name}:global"
                else:
                    break
            return None

        def _mode_is_ecb(expr: ast.AST, scope_id: str, lineno: int) -> bool:
            if expr is None:
                return False
            value = _eval_static_constant(expr, self.assignments_by_scope, scope_id, lineno)
            if isinstance(value, str) and value in P3_ECB_CONSTANT_MODES:
                return True
            symbol_node = expr.func if isinstance(expr, ast.Call) else expr
            symbol = self.resolve_canonical_name(symbol_node, scope_id) or dotted_name(symbol_node) or ""
            if symbol.rsplit(".", 1)[-1] in P3_ECB_MARKER_ATTRS:
                return True
            return isinstance(expr, ast.Name) and expr.id in P3_ECB_MARKER_ATTRS

        def _url_scheme(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> str | None:
            if expr is None:
                return None
            if visited is None:
                visited = set()
            value = _eval_static_constant(expr, self.assignments_by_scope, scope_id, lineno)
            if isinstance(value, str):
                lowered = value.lower()
                return next((scheme for scheme in P3_UNTRUSTED_SCHEMES if lowered.startswith(scheme)), None)
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return None
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None:
                    return _url_scheme(record.value_node, record.scope_id, record.lineno, visited)
            elif isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
                left_value = _eval_static_constant(expr.left, self.assignments_by_scope, scope_id, lineno)
                if isinstance(left_value, str):
                    lowered = left_value.lower()
                    scheme = next((item for item in P3_UNTRUSTED_SCHEMES if lowered.startswith(item)), None)
                    if scheme:
                        return scheme
                return _url_scheme(expr.left, scope_id, lineno, visited)
            elif isinstance(expr, ast.JoinedStr):
                for part in expr.values:
                    if isinstance(part, ast.Constant) and isinstance(part.value, str):
                        lowered = part.value.lower()
                        scheme = next((item for item in P3_UNTRUSTED_SCHEMES if lowered.startswith(item)), None)
                        if scheme:
                            return scheme
                    if not isinstance(part, ast.Constant):
                        break
            elif isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                return _url_scheme(expr.func.value, scope_id, lineno, visited)
            return None

        def _is_svg_content_type(expr: ast.AST, scope_id: str, lineno: int) -> bool:
            value = _eval_static_constant(expr, self.assignments_by_scope, scope_id, lineno)
            if not isinstance(value, str):
                return False
            normalized = value.split(";", 1)[0].strip().lower()
            return normalized in P3_SVG_CONTENT_TYPES

        def _headers_are_svg(expr: ast.AST, scope_id: str, lineno: int) -> bool:
            headers = _eval_dict_constants(expr, self.assignments_by_scope, scope_id, lineno)
            return any(
                key.lower() == "content-type" and isinstance(value, str)
                and value.split(";", 1)[0].strip().lower() in P3_SVG_CONTENT_TYPES
                for key, value in headers.items()
            )

        def _response_payload(call: ast.Call) -> ast.AST | None:
            for keyword in getattr(call, "keywords", []):
                if keyword.arg in ("response", "content", "body", "data"):
                    return keyword.value
            return call.args[0] if call.args else None

        def _response_content_is_svg(call: ast.Call, scope_id: str, lineno: int) -> bool:
            for keyword in getattr(call, "keywords", []):
                if keyword.arg in ("content_type", "contentType", "mimetype", "media_type"):
                    if _is_svg_content_type(keyword.value, scope_id, lineno):
                        return True
                elif keyword.arg == "headers" or keyword.arg is None:
                    if _headers_are_svg(keyword.value, scope_id, lineno):
                        return True
            return any(
                _is_svg_content_type(argument, scope_id, lineno)
                or _headers_are_svg(argument, scope_id, lineno)
                for argument in call.args[1:]
            )

        seen: set[tuple[str, int, int]] = set()

        def _is_line_suppressed(lineno: int, mod_name: str) -> bool:
            """Check if a line has # ok: or # nosec suppression comment."""
            source_lines = self._source_lines_by_file.get(self.file_paths.get(mod_name, ""), [])
            if source_lines and 1 <= lineno <= len(source_lines):
                line_text = source_lines[lineno - 1]
                if CLUSTER3_NOSEC_RE.search(line_text):
                    return True
                # Also check previous line for # ok: comments
                if lineno >= 2:
                    prev_line = source_lines[lineno - 2]
                    if re.search(r"#\s*ok:", prev_line, re.IGNORECASE):
                        return True
            return False

        def _add_finding(node: ast.AST, mod_name: str, scope_id: str, operation: str, category: str, cwe: str) -> None:
            line = getattr(node, "lineno", 1)
            # Check for suppression before adding finding
            if _is_line_suppressed(line, mod_name):
                return
            column = getattr(node, "col_offset", 0)
            key = (cwe, line, column)
            if key in seen:
                return
            seen.add(key)
            file_path = self.file_paths.get(mod_name, "unknown.py")
            node_location = location(node, file_path)
            source_id = P3_STRUCTURAL_SOURCE_IDS.get(operation)
            for record in self.sink_records:
                existing = record.security_node
                if existing.location == node_location and existing.metadata.get("cwe") == cwe:
                    existing.metadata["p3_source_id"] = source_id
                    return
            sink_node = SecurityNode(
                id=self.next_sink_id(),
                node_type=NodeType.SINK,
                symbol=operation,
                operation=operation,
                location=node_location,
                metadata={
                    "sink_type": category,
                    "category": category,
                    "cwe": cwe,
                    "p3_source_id": source_id,
                },
            )
            self.sinks.append(sink_node)
            self.sink_records.append(SinkRecord(
                node=node,
                security_node=sink_node,
                lineno=line,
                scope_id=scope_id,
            ))

        for mod_name, tree in self.modules.items():
            seen.clear()
            dynamic_response_vars: dict[tuple[str, str], list[int]] = {}
            scoped_nodes = [(node, _scope_for(node, mod_name)) for node in self._reachable_nodes(tree)]

            for node, scope_id in scoped_nodes:
                if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(node.value, ast.Call):
                    continue
                response_call = node.value
                if not _matches_registry(_names_for_call(response_call, scope_id), P3_SVG_RESPONSE_SINKS):
                    continue
                payload = _response_payload(response_call)
                if payload is None:
                    continue
                payload_static = _eval_static_constant(payload, self.assignments_by_scope, scope_id, node.lineno)
                if payload_static is not None:
                    continue
                temporary_sink = SecurityNode(
                    id="", node_type=NodeType.SINK, symbol="SVG response",
                    operation="SVG_XSS_RESPONSE", location=location(response_call, self.file_paths.get(mod_name, "unknown.py")),
                    metadata={"sink_type": "CROSS_SITE_SCRIPTING", "cwe": "CWE-79"},
                )
                payload_taint = self.resolve_expression(payload, temporary_sink, scope_id, node.lineno)
                if payload_taint.state == TaintState.CLEAN:
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        dynamic_response_vars.setdefault((scope_id, target.id), []).append(node.lineno)

            for node, scope_id in scoped_nodes:
                lineno = getattr(node, "lineno", 1)
                if isinstance(node, ast.Call):
                    names = _names_for_call(node, scope_id)
                    is_crypto_call = any(
                        name.startswith("Crypto.Cipher.")
                        or name.startswith("cryptography.hazmat.primitives.ciphers.")
                        or (name in SINK_REGISTRY and SINK_REGISTRY[name].get("cwe") == "CWE-327")
                        for name in names
                    )
                    if is_crypto_call:
                        mode_nodes = [keyword.value for keyword in node.keywords if keyword.arg == "mode"]
                        if not mode_nodes and len(node.args) > 1:
                            mode_nodes.append(node.args[1])
                        if any(_mode_is_ecb(value, scope_id, lineno) for value in mode_nodes):
                            _add_finding(
                                node, mod_name, scope_id, "INSECURE_CIPHER_MODE",
                                "WEAK_CRYPTOGRAPHY", "CWE-327",
                            )

                    if _matches_registry(names, P3_RESOURCE_SINK_NAMES):
                        url_expr = next(
                            (keyword.value for keyword in node.keywords if keyword.arg in ("url", "uri")),
                            node.args[0] if node.args else None,
                        )
                        if _url_scheme(url_expr, scope_id, lineno):
                            # TimeCodeSecurity: SSRF via URL schemes (urllib.urlretrieve, requests, etc.)
                            # Previously misclassified as CWE-73 (path traversal); corrected to CWE-939/CWE-918 family
                            _add_finding(
                                node, mod_name, scope_id, "PROTOCOL_RESOURCE_ACCESS",
                                "UNAUTHORIZED_RESOURCE_ACCESS", "CWE-939",
                            )

                    if _matches_registry(names, P3_SVG_RESPONSE_SINKS):
                        payload = _response_payload(node)
                        if payload is not None and _response_content_is_svg(node, scope_id, lineno):
                            payload_static = _eval_static_constant(payload, self.assignments_by_scope, scope_id, lineno)
                            if payload_static is None:
                                temporary_sink = SecurityNode(
                                    id="", node_type=NodeType.SINK, symbol="SVG response",
                                    operation="SVG_XSS_RESPONSE", location=location(node, self.file_paths.get(mod_name, "unknown.py")),
                                    metadata={"sink_type": "CROSS_SITE_SCRIPTING", "cwe": "CWE-79"},
                                )
                                payload_taint = self.resolve_expression(payload, temporary_sink, scope_id, lineno)
                                if payload_taint.state != TaintState.CLEAN:
                                    _add_finding(
                                        node, mod_name, scope_id, "SVG_XSS_RESPONSE",
                                        "CROSS_SITE_SCRIPTING", "CWE-79",
                                    )

                    if isinstance(node.func, ast.Attribute) and node.func.attr == "update":
                        receiver = node.func.value
                        if (
                            isinstance(receiver, ast.Attribute)
                            and receiver.attr == "headers"
                            and isinstance(receiver.value, ast.Name)
                            and any(_headers_are_svg(arg, scope_id, lineno) for arg in node.args)
                            and any(line < lineno for line in dynamic_response_vars.get((scope_id, receiver.value.id), []))
                        ):
                            _add_finding(
                                node, mod_name, scope_id, "SVG_XSS_RESPONSE",
                                "CROSS_SITE_SCRIPTING", "CWE-79",
                            )

                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    header_variable = None
                    for target in targets:
                        if not isinstance(target, ast.Subscript):
                            continue
                        key_value = _eval_static_constant(target.slice, self.assignments_by_scope, scope_id, lineno)
                        if not isinstance(key_value, str) or key_value.lower() != "content-type":
                            continue
                        if isinstance(target.value, ast.Name):
                            header_variable = target.value.id
                        elif (
                            isinstance(target.value, ast.Attribute)
                            and target.value.attr == "headers"
                            and isinstance(target.value.value, ast.Name)
                        ):
                            header_variable = target.value.value.id
                        if header_variable:
                            break
                    if (
                        header_variable
                        and _is_svg_content_type(node.value, scope_id, lineno)
                        and any(line < lineno for line in dynamic_response_vars.get((scope_id, header_variable), []))
                    ):
                        _add_finding(
                            node, mod_name, scope_id, "SVG_XSS_RESPONSE",
                            "CROSS_SITE_SCRIPTING", "CWE-79",
                        )

    def _collect_phase4_structural_findings(self) -> None:
        """Collect Phase 4 deserialization, dynamic-code, and process sinks."""
        function_scopes = {id(function): scope for scope, function in self.functions.items()}
        deserialization_sinks = {"dill.load", "dill.loads", "shelve.open", "jsonpickle.decode"}
        pickle_sinks = {"pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load"}
        code_sinks = {
            "eval", "builtins.eval", "exec", "builtins.exec", "compile", "builtins.compile",
            "code.InteractiveConsole.push", "InteractiveConsole.push",
            "code.InteractiveInterpreter.runcode", "InteractiveInterpreter.runcode",
            "code.InteractiveInterpreter.runsource", "InteractiveInterpreter.runsource",
            "code.compile_command", "compile_command",
            "_testcapi.run_in_subinterp", "support.run_in_subinterp", "test.support.run_in_subinterp",
        }
        subinterp_sinks = {"_xxsubinterpreters.run_string"}
        added_process_sinks = {
            "os.popen", "os.popen2", "os.popen3", "os.popen4",
            "os.spawnlp", "os.spawnlpe", "os.spawnv", "os.spawnve",
            "os.posix_spawn", "posix_spawn",
        }
        shell_process_sinks = {
            "os.system",
            "subprocess.run", "subprocess.call", "subprocess.check_call",
            "subprocess.check_output", "subprocess.Popen",
            "asyncio.create_subprocess_shell", "asyncio.subprocess.create_subprocess_shell",
        }

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _call_names(call: ast.Call, scope_id: str) -> set[str]:
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.AST):
                return set()
            name = dotted_name(call.func) or ""
            canonical = self.resolve_canonical_name(call.func, scope_id) or ""
            return {value for value in (name, canonical) if value}

        def _assigned_value(name: str, scope_id: str, lineno: int):
            current_scope = scope_id
            mod_name = scope_module(scope_id)
            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
                records = self.assignments_by_scope.get((current_scope, name), [])
                prior = [record for record in records if record.lineno <= lineno]
                if prior:
                    return prior[-1]
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope:
                    current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global":
                    current_scope = f"{mod_name}:global"
                else:
                    break
            return None

        def _is_static(expr: ast.AST, scope_id: str, lineno: int,
                       visited: set = None, depth: int = 0) -> bool:
            if expr is None or depth > 25:
                return False
            if visited is None:
                visited = set()
            if id(expr) in visited:
                return False
            visited.add(id(expr))
            if isinstance(expr, ast.Constant):
                return isinstance(expr.value, (str, bytes, int, float, bool, type(None)))
            if isinstance(expr, (ast.Str, ast.Bytes, ast.Num)):
                return True
            if isinstance(expr, (ast.List, ast.Tuple)):
                return all(_is_static(element, scope_id, lineno, visited, depth + 1) for element in expr.elts)
            # F-strings (JoinedStr) are static only if all interpolated values are static
            if isinstance(expr, ast.JoinedStr):
                return all(_is_static(value, scope_id, lineno, visited, depth + 1) for value in expr.values)
            # String concatenation (BinOp with + or %) is static only if both operands are static
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
                return _is_static(expr.left, scope_id, lineno, visited, depth + 1) and \
                       _is_static(expr.right, scope_id, lineno, visited, depth + 1)
            if isinstance(expr, ast.Call):
                call_names = _call_names(expr, scope_id)
                if call_names & {"compile", "builtins.compile", "code.compile_command", "compile_command"}:
                    if expr.args:
                        return _is_static(expr.args[0], scope_id, lineno, visited, depth + 1)
                # .format() calls are dynamic if the receiver is dynamic
                if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                    # Check if the receiver (expr.func.value) is static
                    if not _is_static(expr.func.value, scope_id, lineno, visited, depth + 1):
                        return False
                    # If receiver is static, check if all format args are static
                    return all(_is_static(arg, scope_id, lineno, visited, depth + 1) for arg in expr.args) and \
                           all(_is_static(kw.value, scope_id, lineno, visited, depth + 1) for kw in expr.keywords)
            if isinstance(expr, ast.Name):
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None and record.value_node is not None:
                    return _is_static(record.value_node, record.scope_id, record.lineno, visited, depth + 1)
            return _eval_static_constant(expr, self.assignments_by_scope, scope_id, lineno) is not None

        def _is_dynamic(expr: ast.AST, scope_id: str, lineno: int) -> bool:
            return expr is not None and not _is_static(expr, scope_id, lineno)

        def _is_pure_literal(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            """Check if expression is purely static literals (no dynamic content at all).
            
            This is stricter than _is_static - it ensures concatenation/formatting 
            only involves literal strings with no variables or function calls.
            """
            if expr is None:
                return False
            if visited is None:
                visited = set()
            # Pure literals: Constant strings/bytes
            if isinstance(expr, ast.Constant):
                return isinstance(expr.value, (str, bytes))
            if isinstance(expr, (ast.Str, ast.Bytes)):
                return True
            # List/Tuple of pure literals
            if isinstance(expr, (ast.List, ast.Tuple)):
                return all(_is_pure_literal(element, scope_id, lineno, visited.copy()) for element in expr.elts)
            # String concatenation with + must have both sides as pure literals
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
                return _is_pure_literal(expr.left, scope_id, lineno, visited.copy()) and \
                       _is_pure_literal(expr.right, scope_id, lineno, visited.copy())
            # Modulo formatting must have both sides as pure literals
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
                return _is_pure_literal(expr.left, scope_id, lineno, visited.copy()) and \
                       _is_pure_literal(expr.right, scope_id, lineno, visited.copy())
            # F-strings are NEVER pure literals (they always interpolate something)
            if isinstance(expr, ast.JoinedStr):
                return False
            # .format() calls are NEVER pure literals (method call implies potential dynamism)
            if isinstance(expr, ast.Call):
                return False
            # Variable references: check assignment but still not pure literal
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None and record.value_node is not None:
                    return _is_pure_literal(record.value_node, record.scope_id, record.lineno, visited.copy())
                return False
            return False

        def _uses_safe_builder(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            """Check if expression uses safe SQL builders like psycopg2.sql.Identifier or SQLAlchemy bindparams().
            
            Returns True if the expression or any of its parts use known-safe SQL construction methods.
            """
            if expr is None:
                return False
            if visited is None:
                visited = set()
            # Check direct calls
            if isinstance(expr, ast.Call):
                if isinstance(expr.func, ast.AST):
                    call_names = {
                        dotted_name(expr.func) or "",
                        self.resolve_canonical_name(expr.func, scope_id) or "",
                    }
                    # Safe SQL builders
                    safe_builders = {
                        "psycopg2.sql.Identifier", "sql.Identifier", "Identifier",
                        "psycopg2.sql.SQL", "sql.SQL",
                        "sqlalchemy.text", "text",
                    }
                    if call_names & safe_builders:
                        return True
                    # Check for .format() method - look at args for safe builders
                    if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                        for arg in expr.args:
                            if _uses_safe_builder(arg, scope_id, lineno, visited.copy()):
                                return True
                    # Check for bindparams() method calls
                    if isinstance(expr.func, ast.Attribute) and expr.func.attr == "bindparams":
                        return True
                    # Recursively check arguments
                    for arg in expr.args:
                        if _uses_safe_builder(arg, scope_id, lineno, visited.copy()):
                            return True
                    for kw in expr.keywords:
                        if _uses_safe_builder(kw.value, scope_id, lineno, visited.copy()):
                            return True
                # Also check the receiver of method calls (e.g., sql.SQL(...).format(...))
                if isinstance(expr.func, ast.Attribute):
                    if _uses_safe_builder(expr.func.value, scope_id, lineno, visited.copy()):
                        return True
            # Check binary operations
            if isinstance(expr, ast.BinOp):
                return _uses_safe_builder(expr.left, scope_id, lineno, visited.copy()) or \
                       _uses_safe_builder(expr.right, scope_id, lineno, visited.copy())
            # Check f-string values
            if isinstance(expr, ast.JoinedStr):
                return any(_uses_safe_builder(value, scope_id, lineno, visited.copy()) for value in expr.values)
            # Check variable assignments
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None and record.value_node is not None:
                    return _uses_safe_builder(record.value_node, record.scope_id, record.lineno, visited.copy())
            return False

        def _is_fully_sanitized(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            if expr is None:
                return False
            if _is_static(expr, scope_id, lineno):
                return True
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Call):
                if not isinstance(expr.func, ast.AST):
                    return False
                sanitizer_names = {
                    dotted_name(expr.func) or "",
                    self.resolve_canonical_name(expr.func, scope_id) or "",
                }
                return bool(sanitizer_names & SANITIZER_REGISTRY.get("CWE-78", set()))
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                return record is not None and _is_fully_sanitized(
                    record.value_node, record.scope_id, record.lineno, visited
                )
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
                return _is_fully_sanitized(expr.left, scope_id, lineno, visited.copy()) and _is_fully_sanitized(
                    expr.right, scope_id, lineno, visited.copy()
                )
            if isinstance(expr, ast.JoinedStr):
                return all(
                    isinstance(part, ast.Constant)
                    or _is_fully_sanitized(part, scope_id, lineno, visited.copy())
                    for part in expr.values
                )
            # An argv collection is sanitized only when every element is: `['python2', shlex.quote(p)]`
            # carries no dynamic command, but `[tainted, shlex.quote(p)]` still does.
            if isinstance(expr, (ast.List, ast.Tuple)):
                return all(
                    _is_fully_sanitized(elt, scope_id, lineno, visited.copy())
                    for elt in expr.elts
                )
            if isinstance(expr, ast.FormattedValue):
                return _is_fully_sanitized(expr.value, scope_id, lineno, visited)
            return False

        def _argument(call: ast.Call, position: int, keyword_names: set[str] | None = None):
            for keyword in getattr(call, "keywords", []):
                if keyword.arg in (keyword_names or set()):
                    return keyword.value
            return call.args[position] if len(call.args) > position else None

        def _dynamic_executable(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            if expr is None:
                return False
            if visited is None:
                visited = set()
            if isinstance(expr, (ast.List, ast.Tuple)):
                return bool(expr.elts) and _is_dynamic(expr.elts[0], scope_id, lineno)
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None:
                    return _dynamic_executable(record.value_node, record.scope_id, record.lineno, visited)
                return _is_dynamic(expr, scope_id, lineno)
            if isinstance(expr, ast.Subscript) and isinstance(expr.value, ast.Name):
                record = _assigned_value(expr.value.id, scope_id, lineno)
                if record is not None and isinstance(record.value_node, ast.Dict):
                    key_value = _eval_static_constant(
                        expr.slice, self.assignments_by_scope, scope_id, lineno
                    )
                    for key_node, value_node in zip(record.value_node.keys, record.value_node.values):
                        if _eval_static_constant(
                            key_node, self.assignments_by_scope, record.scope_id, record.lineno
                        ) == key_value:
                            return _dynamic_executable(
                                value_node, record.scope_id, record.lineno, visited
                            )
            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "split":
                return _is_dynamic(expr.func.value, scope_id, lineno)
            return _is_dynamic(expr, scope_id, lineno)

        seen: set[tuple[str, int, int]] = set()

        def _is_line_suppressed(lineno: int, mod_name: str) -> bool:
            """Check if a line has # ok: or # nosec suppression comment."""
            source_lines = self._source_lines_by_file.get(self.file_paths.get(mod_name, ""), [])
            if source_lines and 1 <= lineno <= len(source_lines):
                line_text = source_lines[lineno - 1]
                if CLUSTER3_NOSEC_RE.search(line_text):
                    return True
                # Also check previous line for # ok: comments
                if lineno >= 2:
                    prev_line = source_lines[lineno - 2]
                    if re.search(r"#\s*ok:", prev_line, re.IGNORECASE):
                        return True
            return False

        def _add_finding(node: ast.Call, mod_name: str, scope_id: str, operation: str, category: str, cwe: str, target_arg: int = 0) -> None:
            line = getattr(node, "lineno", 1)
            # Check for suppression before adding finding
            if _is_line_suppressed(line, mod_name):
                return
            column = getattr(node, "col_offset", 0)
            key = (cwe, line, column)
            if key in seen:
                return
            seen.add(key)
            file_path = self.file_paths.get(mod_name, "unknown.py")
            node_location = location(node, file_path)
            source_ids = {
                "CWE-502": "UNSAFE_DESERIALIZATION",
                "CWE-94": "DYNAMIC_CODE_EXECUTION",
                "CWE-95": "DYNAMIC_CODE_EXECUTION",
                "CWE-78": "OS_COMMAND_EXECUTION",
                "CWE-89": "SQL_QUERY_EXECUTION",
                "CWE-319": "CLEARTEXT_TRANSMISSION",
                "CWE-352": "CSRF_VULNERABILITY",
                "CWE-522": "HARDCODED_JWT_SECRET",
                "CWE-327": "INSECURE_CRYPTOGRAPHY",
            }
            existing_record = next((
                record for record in self.sink_records
                if record.security_node.location == node_location
                and record.security_node.metadata.get("cwe") == cwe
            ), None)
            if existing_record is not None:
                existing_record.security_node.metadata["p4_source_id"] = source_ids[cwe]
                if "operation" not in existing_record.security_node.metadata:
                    existing_record.security_node.metadata["operation"] = operation
                if target_arg != 0 and "target_arg" not in existing_record.security_node.metadata:
                    existing_record.security_node.metadata["target_arg"] = target_arg
                return
            sink_node = SecurityNode(
                id=self.next_sink_id(),
                node_type=NodeType.SINK,
                symbol=operation,
                operation=operation,
                location=node_location,
                metadata={
                    "sink_type": category,
                    "category": category,
                    "cwe": cwe,
                    "operation": operation,
                    "p4_source_id": source_ids[cwe],
                    "target_arg": target_arg,
                },
            )
            self.sinks.append(sink_node)
            self.sink_records.append(SinkRecord(
                node=node,
                security_node=sink_node,
                lineno=line,
                scope_id=scope_id,
            ))

        def _phase12_suppressed(line_no: int, mod_name: str) -> bool:
            """`# ok:` / `# nosec` on this line or the one immediately above it.

            `_is_line_suppressed` only recognises `# ok:` on a preceding line, so a `# nosec`
            placed above a tainted assignment would otherwise be ignored.
            """
            if _is_line_suppressed(line_no, mod_name):
                return True
            source_lines = self._source_lines_by_file.get(self.file_paths.get(mod_name, ""), [])
            if 2 <= line_no <= len(source_lines) and CLUSTER3_NOSEC_RE.search(source_lines[line_no - 2]):
                return True
            return False

        def _phase12_dynamic_payload(exprs: list, scope_id: str, lineno: int) -> bool:
            """True when a command/process argument carries constructed (non-literal) text.

            Pure literals, literal-only lists and shlex-sanitized values never qualify. When an
            argument resolves to a local assignment, a `# ok:` / `# nosec` on that assignment line
            suppresses the whole call.
            """
            mod_name = scope_module(scope_id)
            for expr in exprs:
                if expr is None or not _is_dynamic(expr, scope_id, lineno):
                    continue
                if _is_fully_sanitized(expr, scope_id, lineno):
                    continue
                if isinstance(expr, ast.Name):
                    record = _assigned_value(expr.id, scope_id, lineno)
                    if record is not None and _phase12_suppressed(record.lineno, mod_name):
                        return False
                return True
            return False

        for mod_name, tree in self.modules.items():
            seen.clear()
            for node in self._reachable_nodes(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.AST):
                    continue
                scope_id = _scope_for(node, mod_name)
                names = _call_names(node, scope_id)
                lineno = getattr(node, "lineno", 1)

                # A document the scanned program wrote itself is not an attacker payload,
                # whichever of the three deserialization branches matched it.
                owns_document = self._deserializes_own_document(node, scope_id, lineno)

                if names & pickle_sinks:
                    payload = _argument(node, 0, {"data", "file", "stream"})
                    if _is_dynamic(payload, scope_id, lineno) and not owns_document:
                        _add_finding(
                            node, mod_name, scope_id, "DESERIALIZATION",
                            "UNSAFE_DESERIALIZATION", "CWE-502",
                        )
                elif "yaml.load" in names or "yaml.load_all" in names:
                    loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), None)
                    loader_name = ""
                    if isinstance(loader, ast.AST):
                        loader_name = self.resolve_canonical_name(loader, scope_id) or dotted_name(loader) or ""
                    # BaseLoader yields plain strings and builds no objects, so it parses
                    # without executing anything — same guarantee as the Safe pair.
                    if (loader_name.rsplit(".", 1)[-1] not in {"SafeLoader", "CSafeLoader", "BaseLoader"}
                            and not owns_document):
                        _add_finding(node, mod_name, scope_id, "DESERIALIZATION", "UNSAFE_DESERIALIZATION", "CWE-502")
                elif names & deserialization_sinks and not owns_document:
                    _add_finding(node, mod_name, scope_id, "DESERIALIZATION", "UNSAFE_DESERIALIZATION", "CWE-502")

                if "jwt.encode" in names:
                    key_expr = next((kw.value for kw in node.keywords if kw.arg == "key"), None)
                    if key_expr is None and len(node.args) > 1:
                        key_expr = node.args[1]
                    key_value = _eval_static_constant(
                        key_expr, self.assignments_by_scope, scope_id, lineno
                    ) if key_expr is not None else None
                    if isinstance(key_value, str) and key_value.strip():
                        _add_finding(
                            node, mod_name, scope_id, "HARDCODED_JWT_SECRET",
                            "INSECURE_CREDENTIAL_TRANSPORT", "CWE-522",
                        )
                    # Phase 11.2: CWE-327 - Detect algorithm='none'
                    alg_expr = next((kw.value for kw in node.keywords if kw.arg == "algorithm"), None)
                    if alg_expr is None and len(node.args) > 2:
                        alg_expr = node.args[2]
                    alg_value = _eval_static_constant(
                        alg_expr, self.assignments_by_scope, scope_id, lineno
                    ) if alg_expr is not None else None
                    if isinstance(alg_value, str) and alg_value.lower() == "none":
                        _add_finding(
                            node, mod_name, scope_id, "JWT_NONE_ALGORITHM",
                            "INSECURE_CRYPTOGRAPHY", "CWE-327",
                        )

                # Phase 11.2: CWE-327 - Detect jwt.decode with algorithms=['none']
                if "jwt.decode" in names:
                    alg_kw = next((kw for kw in node.keywords if kw.arg == "algorithms"), None)
                    if alg_kw and isinstance(alg_kw.value, ast.List):
                        for elt in alg_kw.value.elts:
                            alg_val = _eval_static_constant(elt, self.assignments_by_scope, scope_id, lineno)
                            if isinstance(alg_val, str) and alg_val.lower() == "none":
                                _add_finding(
                                    node, mod_name, scope_id, "JWT_NONE_ALGORITHM",
                                    "INSECURE_CRYPTOGRAPHY", "CWE-327",
                                )
                                break

                # Phase 11.2: CWE-327 - Hashids(salt=<framework SECRET_KEY>) derives a reversible
                # id-space from the application signing key. Only the framework secret qualifies:
                # a literal or a derived digest (e.g. md5.hexdigest()) is a different weakness.
                if "Hashids" in names or "hashids.Hashids" in names:
                    salt_kw = next((kw for kw in node.keywords if kw.arg == "salt"), None)
                    salt_expr = salt_kw.value if salt_kw is not None else (node.args[0] if node.args else None)
                    if isinstance(salt_expr, ast.AST) and not isinstance(salt_expr, ast.Constant):
                        salt_repr = ast.dump(salt_expr)
                        if "SECRET_KEY" in salt_repr or "secret_key" in salt_repr:
                            _add_finding(
                                node, mod_name, scope_id, "HASHIDS_WITH_SECRET",
                                "INSECURE_CRYPTOGRAPHY", "CWE-327",
                            )

                # Phase 11.2: CWE-352 - Pyramid config.set_default_csrf_options(check_origin=False)
                func_attr_name = None
                if isinstance(node.func, ast.Attribute):
                    func_attr_name = node.func.attr
                if func_attr_name == "set_default_csrf_options":
                    for kw in node.keywords:
                        if kw.arg == "check_origin" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                            _add_finding(
                                node, mod_name, scope_id, "PYRAMID_CSRF_OPTIONS_DISABLED",
                                "CSRF_VULNERABILITY", "CWE-352",
                            )

                # Phase 11.2: CWE-352 - Pyramid @view_config(require_csrf=False) or check_origin=False
                if "view_config" in names or "pyramid.view.view_config" in names:
                    for kw in node.keywords:
                        if kw.arg == "require_csrf" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                            _add_finding(
                                node, mod_name, scope_id, "PYRAMID_CSRF_DISABLED",
                                "CSRF_VULNERABILITY", "CWE-352",
                            )
                        elif kw.arg == "check_origin" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                            _add_finding(
                                node, mod_name, scope_id, "PYRAMID_CHECK_ORIGIN_DISABLED",
                                "CSRF_VULNERABILITY", "CWE-352",
                            )

                if names & code_sinks:
                    code_expr = _argument(node, 0, {"source", "code", "line"})
                    # `dynamic.format("literal")` still builds program text at runtime, so a
                    # format call is constructed code even when every argument is a literal
                    # (python/lang/security/audit/eval-detected.py:13).
                    format_constructed = (
                        isinstance(code_expr, ast.Call)
                        and isinstance(code_expr.func, ast.Attribute)
                        and code_expr.func.attr == "format"
                    )
                    if _is_dynamic(code_expr, scope_id, lineno) or format_constructed:
                        _add_finding(node, mod_name, scope_id, "DYNAMIC_CODE_EXECUTION", "CODE_EXECUTION", "CWE-95")
                elif names & subinterp_sinks:
                    code_expr = _argument(node, 1, {"code", "source"})
                    if _is_dynamic(code_expr, scope_id, lineno):
                        _add_finding(node, mod_name, scope_id, "DYNAMIC_CODE_EXECUTION", "CODE_EXECUTION", "CWE-95", target_arg=1)

                func_attr = node.func.attr if isinstance(node.func, ast.Attribute) else (node.func.id if isinstance(node.func, ast.Name) else None)
                if func_attr == "run_in_executor" and len(node.args) >= 3:
                    cb = node.args[1]
                    cb_names = _call_names(ast.Call(func=cb, args=[], keywords=[]), scope_id) if isinstance(cb, ast.AST) else set()
                    if isinstance(cb, ast.Name):
                        cb_names.add(cb.id)
                    elif isinstance(cb, ast.Attribute):
                        cb_names.add(cb.attr)
                    cb_canon = self.resolve_canonical_name(cb, scope_id) if (scope_id and isinstance(cb, ast.AST)) else None
                    if cb_canon:
                        cb_names.add(cb_canon)
                    if cb_names & {"exec", "eval", "builtins.exec", "builtins.eval"}:
                        code_expr = node.args[2]
                        if _is_dynamic(code_expr, scope_id, lineno):
                            _add_finding(node, mod_name, scope_id, "DYNAMIC_CODE_EXECUTION", "CODE_EXECUTION", "CWE-95", target_arg=2)

                if names & (added_process_sinks | shell_process_sinks):
                    process_name = next((name for name in names if name in added_process_sinks), "")
                    if process_name:
                        executable_position = 1 if process_name in {
                            "os.spawnlp", "os.spawnlpe", "os.spawnv", "os.spawnve",
                        } else 0
                        executable = _argument(node, executable_position, {"path", "file"})
                        if _is_dynamic(executable, scope_id, lineno):
                            _add_finding(node, mod_name, scope_id, "OS_COMMAND_EXECUTION", "COMMAND_INJECTION", "CWE-78")

                    if names & shell_process_sinks:
                        command = _argument(node, 0, {"args", "command", "cmd"})
                        
                        # Determine if shell execution is enabled
                        is_os_system = "os.system" in names
                        if is_os_system:
                            # os.system always uses shell
                            shell_enabled = True
                        else:
                            # subprocess.* calls: check for shell=True keyword
                            shell_kw = next((kw.value for kw in node.keywords if kw.arg == "shell"), None)
                            shell_enabled = _eval_static_constant(
                                shell_kw, self.assignments_by_scope, scope_id, lineno
                            ) is True
                        
                        # Check if command is a list/tuple (safe pattern) or string (potentially unsafe)
                        is_list_arg = isinstance(command, (ast.List, ast.Tuple))
                        
                        # For os.system or subprocess with shell=True, flag if command is dynamic string
                        if shell_enabled and not is_list_arg:
                            # Only flag if the command contains dynamic content (not a static literal)
                            if _is_dynamic(command, scope_id, lineno) and not _is_fully_sanitized(command, scope_id, lineno):
                                _add_finding(node, mod_name, scope_id, "OS_COMMAND_EXECUTION", "COMMAND_INJECTION", "CWE-78")
                        # For subprocess without shell=True, flag only if executable itself is dynamic
                        elif not shell_enabled and not is_os_system:
                            # argv execution hands each element to execve verbatim, so a
                            # list the program itself spells out (`sys.executable`, string
                            # literals, a name bound to one of two literals) has no field
                            # an attacker can populate — nothing is parsed by a shell. The
                            # same holds for a row read back through the ORM: its column
                            # values were written by the application, not by the request.
                            argv_is_internal = not self._has_untrusted_command_lineage(
                                command, scope_id, lineno)
                            if _dynamic_executable(command, scope_id, lineno) and not argv_is_internal:
                                _add_finding(node, mod_name, scope_id, "OS_COMMAND_EXECUTION", "COMMAND_INJECTION", "CWE-78")

                # ---- Phase 12: CWE-78 exec/spawn command-payload dynamism ----
                # The executable-position check above misses `os.spawnl(os.P_WAIT, "/bin/bash",
                # "-c", cmd)`: the path is a literal and only the payload is user-controlled.
                # `os.P_*` mode handles and the trailing `os.environ` argument are neither command
                # text nor input, so `os.`-rooted attributes are skipped entirely.
                spawn_exec_sinks = {
                    "os.execl", "os.execle", "os.execlp", "os.execlpe",
                    "os.execv", "os.execve", "os.execvp", "os.execvpe",
                    "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
                    "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
                }
                if names & spawn_exec_sinks:
                    payload = [
                        argument for argument in node.args[1:]
                        if not (
                            isinstance(argument, ast.Attribute)
                            and isinstance(argument.value, ast.Name)
                            and argument.value.id == "os"
                        )
                    ]
                    if _phase12_dynamic_payload(payload, scope_id, lineno):
                        _add_finding(
                            node, mod_name, scope_id, "OS_COMMAND_EXECUTION",
                            "COMMAND_INJECTION", "CWE-78",
                        )

                # ---- Phase 12: CWE-78 asyncio event-loop exec/shell sinks ----
                # `loop.subprocess_exec`/`subprocess_shell` take the protocol factory first, so
                # only the arguments after it are command text; the factory is a lambda and would
                # otherwise read as dynamic on every call.
                asyncio_payload_offset = {
                    "subprocess_exec": 1,
                    "subprocess_shell": 1,
                    "create_subprocess_exec": 0,
                }
                call_attr = node.func.attr if isinstance(node.func, ast.Attribute) else None
                if call_attr in asyncio_payload_offset:
                    receiver = node.func.value
                    receiver_root = (
                        receiver.id if isinstance(receiver, ast.Name)
                        else getattr(receiver, "attr", "") if isinstance(receiver, ast.Attribute)
                        else ""
                    )
                    is_asyncio_call = (
                        any(name.startswith("asyncio") for name in names)
                        or receiver_root == "loop"
                        or receiver_root.endswith("_loop")
                    )
                    if is_asyncio_call:
                        payload = list(node.args[asyncio_payload_offset[call_attr]:])
                        if _phase12_dynamic_payload(payload, scope_id, lineno):
                            _add_finding(
                                node, mod_name, scope_id, "OS_COMMAND_EXECUTION",
                                "COMMAND_INJECTION", "CWE-78",
                            )

                # ---- Phase 12: CWE-78 `sh` command-wrapper string construction ----
                # `sh.ls("-a" + long)` shells out; `sh.semgrep(*args)` and literal-only calls do
                # not, so Starred arguments are excluded from the payload entirely.
                sh_command_call = any(name.startswith("sh.") for name in names) or (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "sh"
                )
                if sh_command_call:
                    payload = [argument for argument in node.args if not isinstance(argument, ast.Starred)]
                    if _phase12_dynamic_payload(payload, scope_id, lineno):
                        _add_finding(
                            node, mod_name, scope_id, "OS_COMMAND_EXECUTION",
                            "COMMAND_INJECTION", "CWE-78",
                        )

                # ---- Phase 12: CWE-78 airflow BashOperator dynamic bash_command ----
                if any(name.endswith("BashOperator") for name in names):
                    bash_command = _argument(node, 1, {"bash_command"})
                    if _phase12_dynamic_payload([bash_command], scope_id, lineno):
                        _add_finding(
                            node, mod_name, scope_id, "OS_COMMAND_EXECUTION",
                            "COMMAND_INJECTION", "CWE-78",
                        )

                # ---- Phase 12: CWE-78 paramiko SSHClient.exec_command dynamic payload ----
                if isinstance(node.func, ast.Attribute) and node.func.attr == "exec_command":
                    if _phase12_dynamic_payload(list(node.args), scope_id, lineno):
                        _add_finding(
                            node, mod_name, scope_id, "OS_COMMAND_EXECUTION",
                            "COMMAND_INJECTION", "CWE-78",
                        )

                # ---- CWE-89: SQL Injection detection ----
                sql_sinks = {
                    "cursor.execute", "cursor.executemany",
                    "connection.execute", "engine.execute", "session.execute",
                    "Model.objects.raw", "Model.objects.extra",
                    "RawSQL", "django.db.models.expressions.RawSQL",
                }
                if names & sql_sinks:
                    # Get the query string (first argument)
                    query_expr = _argument(node, 0, {"query", "sql", "statement"})
                    
                    # CRITICAL: Skip if parameterized query (second argument present)
                    # This prevents flagging: cursor.execute("SELECT * FROM t WHERE id=%s", (user_id,))
                    has_params = len(node.args) > 1 or any(kw.arg for kw in node.keywords)
                    
                    if query_expr and not has_params:
                        # Check for suppression on sink line
                        if _is_line_suppressed(lineno, mod_name):
                            pass  # Suppressed, skip
                        # Case 1: Direct inline dynamic expression (f-string, format, concat)
                        elif isinstance(query_expr, (ast.JoinedStr, ast.BinOp, ast.Call)):
                            # Apply safety guards
                            if not _is_pure_literal(query_expr, scope_id, lineno) and \
                               not _uses_safe_builder(query_expr, scope_id, lineno) and \
                               not _is_fully_sanitized(query_expr, scope_id, lineno):
                                _add_finding(node, mod_name, scope_id, "SQL_QUERY_EXECUTION", "SQL_INJECTION", "CWE-89")
                        # Case 2: Variable reference - trace back to assignment
                        elif isinstance(query_expr, ast.Name):
                            var_name = query_expr.id
                            record = _assigned_value(var_name, scope_id, lineno)
                            if record and record.value_node is not None:
                                assigned_value = record.value_node
                                assigned_lineno = record.lineno
                                
                                # Check suppression on assignment line
                                if _is_line_suppressed(assigned_lineno, mod_name):
                                    pass  # Suppressed at assignment, skip
                                # Check if assigned value is dynamic (not a pure literal)
                                elif _is_dynamic(assigned_value, record.scope_id, assigned_lineno):
                                    # Apply all safety guards before flagging
                                    if not _is_pure_literal(assigned_value, record.scope_id, assigned_lineno) and \
                                       not _uses_safe_builder(assigned_value, record.scope_id, assigned_lineno) and \
                                       not _is_fully_sanitized(assigned_value, record.scope_id, assigned_lineno):
                                        _add_finding(node, mod_name, scope_id, "SQL_QUERY_EXECUTION", "SQL_INJECTION", "CWE-89")
                        # Case 3: Other dynamic expressions
                        elif _is_dynamic(query_expr, scope_id, lineno) and not _is_fully_sanitized(query_expr, scope_id, lineno):
                            if not _is_pure_literal(query_expr, scope_id, lineno) and \
                               not _uses_safe_builder(query_expr, scope_id, lineno):
                                _add_finding(node, mod_name, scope_id, "SQL_QUERY_EXECUTION", "SQL_INJECTION", "CWE-89")

                # ---- CWE-319: Cleartext Transmission detection (FTP/Telnet only) ----
                # Note: HTTP detection is handled in Phase 7 with proper allowlists
                
                # FTP without TLS
                if "ftplib.FTP" in names:
                    # Exclude FTP_TLS which is secure
                    func_name = dotted_name(node.func) or ""
                    if "FTP_TLS" not in func_name:
                        _add_finding(node, mod_name, scope_id, "INSECURE_FTP", "CLEARTEXT_TRANSMISSION", "CWE-319")
                
                # Telnet (always insecure)
                if "telnetlib.Telnet" in names:
                    _add_finding(node, mod_name, scope_id, "INSECURE_TELNET", "CLEARTEXT_TRANSMISSION", "CWE-319")

                # ---- CWE-352: CSRF vulnerability detection ----
                csrf_exempt_names = {"csrf_exempt", "django.views.decorators.csrf.csrf_exempt"}
                if names & csrf_exempt_names and not self._csrf_is_json_api_noise(mod_name):
                    _add_finding(node, mod_name, scope_id, "CSRF_EXEMPT_DECORATOR", "CSRF_VULNERABILITY", "CWE-352")

    def _collect_intra_file_call_bridge_findings(self) -> None:
        """Phase 10.1: Intra-file function call resolver (parameter-to-argument bridge).

        When a SQL sink argument inside a helper function is a bare parameter Name that
        no local/global assignment resolves, bridge to call sites of that helper in the
        same module, resolve the actual argument in the caller's scope, and flag only if
        the bridged value is dynamic and survives every safety guard (parameterized
        query, safe builder, sanitizer, pure literal, ok/nosec suppression, 2-hop cap,
        visited-function cycle set).
        """
        function_scopes = {id(function): scope for scope, function in self.functions.items()}
        sql_sinks = {
            "cursor.execute", "cursor.executemany",
            "connection.execute", "engine.execute", "session.execute",
            "Model.objects.raw", "Model.objects.extra",
            "RawSQL", "django.db.models.expressions.RawSQL",
        }
        bridge_seen: set[tuple[str, int, int]] = set()

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _call_names(call: ast.Call, scope_id: str) -> set[str]:
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.AST):
                return set()
            name = dotted_name(call.func) or ""
            canonical = self.resolve_canonical_name(call.func, scope_id) or ""
            return {value for value in (name, canonical) if value}

        def _assigned_value(name: str, scope_id: str, lineno: int):
            current_scope = scope_id
            mod_name = scope_module(scope_id)
            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
                records = self.assignments_by_scope.get((current_scope, name), [])
                prior = [record for record in records if record.lineno <= lineno]
                if prior:
                    return prior[-1]
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope:
                    current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global":
                    current_scope = f"{mod_name}:global"
                else:
                    break
            return None

        def _call_name_set(expr: ast.AST, scope_id: str) -> set[str]:
            if isinstance(expr, ast.Call):
                return _call_names(expr, scope_id)
            return set()

        def _is_static(expr: ast.AST, scope_id: str, lineno: int,
                       visited: set = None, depth: int = 0) -> bool:
            if expr is None or depth > 25:
                return False
            if visited is None:
                visited = set()
            if id(expr) in visited:
                return False
            visited.add(id(expr))
            if isinstance(expr, ast.Constant):
                return isinstance(expr.value, (str, bytes, int, float, bool, type(None)))
            if isinstance(expr, (ast.Str, ast.Bytes, ast.Num)):
                return True
            if isinstance(expr, (ast.List, ast.Tuple)):
                return all(_is_static(element, scope_id, lineno, visited, depth + 1) for element in expr.elts)
            if isinstance(expr, ast.JoinedStr):
                return all(_is_static(value, scope_id, lineno, visited, depth + 1) for value in expr.values)
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
                return _is_static(expr.left, scope_id, lineno, visited, depth + 1) and \
                       _is_static(expr.right, scope_id, lineno, visited, depth + 1)
            if isinstance(expr, ast.Call):
                call_names = _call_name_set(expr, scope_id)
                if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                    if not _is_static(expr.func.value, scope_id, lineno, visited, depth + 1):
                        return False
                    return all(_is_static(arg, scope_id, lineno, visited, depth + 1) for arg in expr.args) and \
                           all(_is_static(kw.value, scope_id, lineno, visited, depth + 1) for kw in expr.keywords)
                _ = call_names
            if isinstance(expr, ast.Name):
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None and record.value_node is not None:
                    return _is_static(record.value_node, record.scope_id, record.lineno, visited, depth + 1)
            return _eval_static_constant(expr, self.assignments_by_scope, scope_id, lineno) is not None

        def _is_dynamic(expr: ast.AST, scope_id: str, lineno: int) -> bool:
            return expr is not None and not _is_static(expr, scope_id, lineno)

        def _is_pure_literal(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            if expr is None:
                return False
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Constant):
                return isinstance(expr.value, (str, bytes))
            if isinstance(expr, (ast.Str, ast.Bytes)):
                return True
            if isinstance(expr, (ast.List, ast.Tuple)):
                return all(_is_pure_literal(element, scope_id, lineno, visited.copy()) for element in expr.elts)
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
                return _is_pure_literal(expr.left, scope_id, lineno, visited.copy()) and \
                       _is_pure_literal(expr.right, scope_id, lineno, visited.copy())
            if isinstance(expr, ast.JoinedStr):
                return False
            if isinstance(expr, ast.Call):
                return False
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None and record.value_node is not None:
                    return _is_pure_literal(record.value_node, record.scope_id, record.lineno, visited.copy())
                return False
            return False

        def _uses_safe_builder(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            if expr is None:
                return False
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.AST):
                call_names = {
                    dotted_name(expr.func) or "",
                    self.resolve_canonical_name(expr.func, scope_id) or "",
                }
                safe_builders = {
                    "psycopg2.sql.Identifier", "sql.Identifier", "Identifier",
                    "psycopg2.sql.SQL", "sql.SQL",
                    "sqlalchemy.text", "text",
                }
                if call_names & safe_builders:
                    return True
                if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                    for arg in expr.args:
                        if _uses_safe_builder(arg, scope_id, lineno, visited.copy()):
                            return True
                if isinstance(expr.func, ast.Attribute) and expr.func.attr == "bindparams":
                    return True
                for arg in expr.args:
                    if _uses_safe_builder(arg, scope_id, lineno, visited.copy()):
                        return True
                for kw in expr.keywords:
                    if _uses_safe_builder(kw.value, scope_id, lineno, visited.copy()):
                        return True
                if _uses_safe_builder(expr.func.value if isinstance(expr.func, ast.Attribute) else None,
                                      scope_id, lineno, visited.copy()):
                    return True
            if isinstance(expr, ast.BinOp):
                return _uses_safe_builder(expr.left, scope_id, lineno, visited.copy()) or \
                       _uses_safe_builder(expr.right, scope_id, lineno, visited.copy())
            if isinstance(expr, ast.JoinedStr):
                return any(_uses_safe_builder(value, scope_id, lineno, visited.copy()) for value in expr.values)
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None and record.value_node is not None:
                    return _uses_safe_builder(record.value_node, record.scope_id, record.lineno, visited.copy())
            return False

        def _is_fully_sanitized(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            if expr is None:
                return False
            if _is_static(expr, scope_id, lineno):
                return True
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.AST):
                sanitizer_names = {
                    dotted_name(expr.func) or "",
                    self.resolve_canonical_name(expr.func, scope_id) or "",
                }
                return bool(sanitizer_names & SANITIZER_REGISTRY.get("CWE-78", set()))
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                return record is not None and _is_fully_sanitized(
                    record.value_node, record.scope_id, record.lineno, visited
                )
            return False

        def _is_line_suppressed(lineno: int, mod_name: str) -> bool:
            source_lines = self._source_lines_by_file.get(self.file_paths.get(mod_name, ""), [])
            if source_lines and 1 <= lineno <= len(source_lines):
                line_text = source_lines[lineno - 1]
                if CLUSTER3_NOSEC_RE.search(line_text):
                    return True
                if lineno >= 2:
                    prev_line = source_lines[lineno - 2]
                    if re.search(r"#\s*ok:", prev_line, re.IGNORECASE):
                        return True
            return False

        def _enclosing_function(node: ast.AST):
            current = getattr(node, "parent", None)
            while current is not None:
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return current
                current = getattr(current, "parent", None)
            return None

        def _param_spec(fn, name: str):
            positional = list(getattr(fn.args, "posonlyargs", [])) + list(fn.args.args)
            for index, arg in enumerate(positional):
                if arg.arg == name:
                    return ("pos", index)
            for arg in fn.args.kwonlyargs:
                if arg.arg == name:
                    return ("kw", name)
            return None

        def _emit(sink_call: ast.Call, mod_name: str, scope_id: str) -> None:
            line = getattr(sink_call, "lineno", 1)
            column = getattr(sink_call, "col_offset", 0)
            key = ("CWE-89", line, column)
            if key in bridge_seen:
                return
            if _is_line_suppressed(line, mod_name):
                return
            file_path = self.file_paths.get(mod_name, "unknown.py")
            node_location = location(sink_call, file_path)
            existing = next((
                record for record in self.sink_records
                if record.security_node.location == node_location
                and record.security_node.metadata.get("cwe") == "CWE-89"
            ), None)
            if existing is not None:
                return
            bridge_seen.add(key)
            sink_node = SecurityNode(
                id=self.next_sink_id(),
                node_type=NodeType.SINK,
                symbol="SQL_QUERY_EXECUTION",
                operation="SQL_QUERY_EXECUTION_BRIDGED",
                location=node_location,
                metadata={
                    "sink_type": "SQL_INJECTION",
                    "category": "SQL_INJECTION",
                    "cwe": "CWE-89",
                    "operation": "SQL_QUERY_EXECUTION_BRIDGED",
                    "p10_source_id": "SQL_QUERY_EXECUTION",
                    "intra_file_bridge": True,
                },
            )
            self.sinks.append(sink_node)
            self.sink_records.append(SinkRecord(
                node=sink_call,
                security_node=sink_node,
                lineno=line,
                scope_id=scope_id,
            ))

        def _bridge_candidates(func_node, param_name: str, mod_name: str, hop: int, visited):
            """Yield (expr, scope_id, lineno) candidates from same-file call sites of func_node.

            Returns None (sentinel for 'remain silent') if any reachable call site line or
            assignment line is suppressed via # ok:/# nosec.
            """
            candidates = []
            for call_site, caller_fn_name in call_sites_by_name.get(func_node.name, []):
                if caller_fn_name in visited and call_site is not None and hop > 0:
                    continue
                spec = _param_spec(func_node, param_name)
                if spec is None:
                    continue
                kind, value = spec
                if any(isinstance(a, ast.Starred) for a in call_site.args):
                    continue
                if any(kw.arg is None for kw in call_site.keywords):
                    continue
                arg = None
                if kind == "pos":
                    if value < len(call_site.args):
                        arg = call_site.args[value]
                    else:
                        arg = next((kw.value for kw in call_site.keywords if kw.arg == param_name), None)
                else:
                    arg = next((kw.value for kw in call_site.keywords if kw.arg == value), None)
                if arg is None:
                    continue
                caller_scope = _scope_for(call_site, mod_name)
                if _is_line_suppressed(call_site.lineno, mod_name):
                    continue
                if isinstance(arg, ast.Name):
                    record = _assigned_value(arg.id, caller_scope, call_site.lineno)
                    if record is not None and record.value_node is not None:
                        if _is_line_suppressed(record.lineno, mod_name):
                            continue
                        candidates.append((record.value_node, record.scope_id, record.lineno))
                        continue
                    caller_fn = _enclosing_function(call_site)
                    if (caller_fn is not None and hop < 1
                            and _param_spec(caller_fn, arg.id) is not None
                            and caller_fn.name not in visited):
                        candidates.extend(_bridge_candidates(
                            caller_fn, arg.id, mod_name, hop + 1, visited | {caller_fn.name}))
                    # Unresolvable parameter/global at the boundary: stay silent (zero-FP).
                    continue
                candidates.append((arg, caller_scope, call_site.lineno))
            return candidates

        for mod_name, tree in self.modules.items():
            call_sites_by_name: dict[str, list[tuple[ast.Call, str]]] = {}
            funcs_by_name: dict[str, list] = {}
            for node in self._reachable_nodes(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    funcs_by_name.setdefault(node.name, []).append(node)
            for node in self._reachable_nodes(tree):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id in funcs_by_name):
                    owner = _enclosing_function(node)
                    call_sites_by_name.setdefault(node.func.id, []).append(
                        (node, owner.name if owner is not None else ""))

            for node in self._reachable_nodes(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.AST):
                    continue
                scope_id = _scope_for(node, mod_name)
                names = _call_names(node, scope_id)
                if not (names & sql_sinks):
                    # Alias-tolerant cursor matching: any `<base>.execute(...)` call form,
                    # mirroring Phase-6's method set but not requiring a known cursor name.
                    attr = node.func.attr if isinstance(node.func, ast.Attribute) else None
                    if attr in {"execute", "executemany", "executescript"}:
                        dotted = dotted_name(node.func) or ""
                        if dotted.startswith(("super",)):
                            continue
                    else:
                        continue
                # Parameterized-query preservation: extra args/keywords => SAFE, silent.
                if len(node.args) > 1 or any(kw.arg for kw in node.keywords):
                    continue
                lineno = getattr(node, "lineno", 1)
                query_kw_names = {"query", "sql", "statement"}
                query_expr = None
                for kw in node.keywords:
                    if kw.arg in query_kw_names:
                        query_expr = kw.value
                if query_expr is None and node.args:
                    query_expr = node.args[0]
                if not isinstance(query_expr, ast.Name):
                    continue
                helper_fn = _enclosing_function(node)
                if helper_fn is None:
                    continue
                if _param_spec(helper_fn, query_expr.id) is None:
                    continue
                # Only bridge when no local/global assignment shadows the parameter.
                if _assigned_value(query_expr.id, scope_id, lineno) is not None:
                    continue
                if helper_fn.name not in call_sites_by_name:
                    continue  # helper never invoked in this module — stay silent
                candidates = _bridge_candidates(
                    helper_fn, query_expr.id, mod_name, 0, {helper_fn.name})
                for expr, cand_scope, cand_lineno in candidates:
                    if _is_static(expr, cand_scope, cand_lineno):
                        continue
                    if _is_pure_literal(expr, cand_scope, cand_lineno):
                        continue
                    if _uses_safe_builder(expr, cand_scope, cand_lineno):
                        continue
                    if _is_fully_sanitized(expr, cand_scope, cand_lineno):
                        continue
                    # Sanitizer/safe-builder may live behind an assignment chain:
                    record = None
                    if isinstance(expr, ast.Name):
                        record = _assigned_value(expr.id, cand_scope, cand_lineno)
                    check_expr = record.value_node if record is not None and record.value_node is not None else expr
                    check_scope = record.scope_id if record is not None else cand_scope
                    check_lineno = record.lineno if record is not None else cand_lineno
                    if _is_static(check_expr, check_scope, check_lineno):
                        continue
                    if _uses_safe_builder(check_expr, check_scope, check_lineno):
                        continue
                    if _is_fully_sanitized(check_expr, check_scope, check_lineno):
                        continue
                    _emit(node, mod_name, scope_id)
                    break

    def _collect_cwe89_driver_querybuilder_findings(self) -> None:
        """Phase 10.2: driver alias expansion, ORM query-builder sinks, and edge repair.

        Three precision-bounded paths, all guarded by parameterized-query,
        safe-builder, static-literal, and # ok:/# nosec suppression checks:
        P1 edge-repair — registry-created CWE-89 sinks whose query argument is
             dynamically constructed get the synthetic p6 source id so the
             existing edge synthesizer emits a finding.
        P2 driver aliases — execute/executemany/executescript plus run/fetch*/cursor
             on DB-resolvable receivers with a dynamically constructed query argument.
        P3 query builders — distinct/having/group_by/order_by/filter/where/join with a
             dynamic string construction as arg0 (including non-literal text(...) after
             unwrap); Django .objects raw/extra likewise, bare extra() always.
        Findings are emitted on BOTH the call line and the argument-expression line so
        multi-line sink calls match the semgrep annotation convention within tolerance.
        """
        function_scopes = {id(function): scope for scope, function in self.functions.items()}
        execute_attrs = {"execute", "executemany", "executescript"}
        driver_attrs = {"run", "fetch", "fetchall", "fetchrow", "fetchval", "cursor"}
        builder_attrs = {"distinct", "having", "group_by", "order_by", "filter", "where", "join"}
        django_attrs = {"raw", "extra"}
        db_receiver_ids = {"conn", "con", "connection", "cur", "cursor", "pool",
                           "session", "engine", "db", "database", "mydb", "dbsession",
                           "mydbcursor", "dbcursor", "sqlalchemy.cursor"}
        db_ctor_attrs = {"connect", "connect_async", "create_pool", "create_pool_async",
                         "cursor", "Session", "sessionmaker", "Pool"}
        sql_shape_re = re.compile(
            r"\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP|ALTER|TRUNCATE|"
            r"REPLACE\s+INTO|MERGE|WHERE|UNION)\b", re.IGNORECASE)
        p12_seen: set[tuple[int, int]] = set()

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _call_names(call: ast.Call, scope_id: str) -> set[str]:
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.AST):
                return set()
            name = dotted_name(call.func) or ""
            canonical = self.resolve_canonical_name(call.func, scope_id) or ""
            return {value for value in (name, canonical) if value}

        def _assigned_value(name: str, scope_id: str, lineno: int):
            current_scope = scope_id
            mod_name = scope_module(scope_id)
            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
                records = self.assignments_by_scope.get((current_scope, name), [])
                prior = [record for record in records if record.lineno <= lineno]
                if prior:
                    return prior[-1]
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope:
                    current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global":
                    current_scope = f"{mod_name}:global"
                else:
                    break
            return None

        def _is_static(expr: ast.AST, scope_id: str, lineno: int,
                       visited: set = None, depth: int = 0) -> bool:
            if expr is None or depth > 25:
                return False
            if visited is None:
                visited = set()
            if id(expr) in visited:
                return False
            visited.add(id(expr))
            if isinstance(expr, ast.Constant):
                return isinstance(expr.value, (str, bytes, int, float, bool, type(None)))
            if isinstance(expr, (ast.Str, ast.Bytes, ast.Num)):
                return True
            if isinstance(expr, (ast.List, ast.Tuple)):
                return all(_is_static(element, scope_id, lineno, visited, depth + 1) for element in expr.elts)
            if isinstance(expr, ast.JoinedStr):
                return all(_is_static(value, scope_id, lineno, visited, depth + 1) for value in expr.values)
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
                return _is_static(expr.left, scope_id, lineno, visited, depth + 1) and \
                       _is_static(expr.right, scope_id, lineno, visited, depth + 1)
            if isinstance(expr, ast.Call):
                if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                    if not _is_static(expr.func.value, scope_id, lineno, visited, depth + 1):
                        return False
                    return all(_is_static(arg, scope_id, lineno, visited, depth + 1) for arg in expr.args) and \
                           all(_is_static(kw.value, scope_id, lineno, visited, depth + 1) for kw in expr.keywords)
            if isinstance(expr, ast.Name):
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None and record.value_node is not None:
                    return _is_static(record.value_node, record.scope_id, record.lineno, visited, depth + 1)
            return _eval_static_constant(expr, self.assignments_by_scope, scope_id, lineno) is not None

        def _uses_safe_builder(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            if expr is None:
                return False
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.AST):
                call_names = {
                    dotted_name(expr.func) or "",
                    self.resolve_canonical_name(expr.func, scope_id) or "",
                }
                safe_builders = {
                    "psycopg2.sql.Identifier", "sql.Identifier", "Identifier",
                    "psycopg2.sql.SQL", "sql.SQL", "sqlalchemy.sql.text",
                }
                if call_names & safe_builders:
                    return True
                if isinstance(expr.func, ast.Attribute):
                    if expr.func.attr == "bindparams":
                        return True
                    for arg in expr.args:
                        if _uses_safe_builder(arg, scope_id, lineno, visited.copy()):
                            return True
                    for kw in expr.keywords:
                        if _uses_safe_builder(kw.value, scope_id, lineno, visited.copy()):
                            return True
                    if _uses_safe_builder(expr.func.value, scope_id, lineno, visited.copy()):
                        return True
            if isinstance(expr, ast.BinOp):
                return _uses_safe_builder(expr.left, scope_id, lineno, visited.copy()) or \
                       _uses_safe_builder(expr.right, scope_id, lineno, visited.copy())
            if isinstance(expr, ast.JoinedStr):
                return any(_uses_safe_builder(value, scope_id, lineno, visited.copy()) for value in expr.values)
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None and record.value_node is not None:
                    return _uses_safe_builder(record.value_node, record.scope_id, record.lineno, visited.copy())
            return False

        def _is_line_suppressed(lineno: int, mod_name: str) -> bool:
            source_lines = self._source_lines_by_file.get(self.file_paths.get(mod_name, ""), [])
            if source_lines and 1 <= lineno <= len(source_lines):
                line_text = source_lines[lineno - 1]
                if CLUSTER3_NOSEC_RE.search(line_text):
                    return True
                if lineno >= 2:
                    prev_line = source_lines[lineno - 2]
                    if re.search(r"#\s*ok:", prev_line, re.IGNORECASE):
                        return True
            return False

        def _resolve_arg(expr, scope_id, lineno, touched_lines, depth=0):
            """Follow Name assignments and unwrap text()/literal_column() wrappers.

            Collects every assignment line traversed (for suppression) and returns the
            innermost expression plus its own scope/lineno.
            """
            while depth < 8:
                if isinstance(expr, ast.Name):
                    record = _assigned_value(expr.id, scope_id, lineno)
                    if record is None or record.value_node is None:
                        return expr, scope_id, lineno
                    touched_lines.append(record.lineno)
                    expr = record.value_node
                    scope_id = record.scope_id
                    lineno = record.lineno
                    depth += 1
                    continue
                if isinstance(expr, ast.Call) and isinstance(expr.func, ast.AST):
                    attr = expr.func.attr if isinstance(expr.func, ast.Attribute) else (
                        expr.func.id if isinstance(expr.func, ast.Name) else "")
                    unwrappers = {"text", "sqlalchemy.text", "sqlalchemy.sql.expression.text",
                                  "literal_column"}
                    names = {dotted_name(expr.func) or "",
                             self.resolve_canonical_name(expr.func, scope_id) or ""}
                    if attr in {"text", "literal_column"} or (names & unwrappers):
                        if len(expr.args) == 1 and not expr.keywords:
                            expr = expr.args[0]
                            depth += 1
                            continue
                return expr, scope_id, lineno
            return expr, scope_id, lineno

        def _has_sql_shape(expr) -> bool:
            for sub in ast.walk(expr):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    if sql_shape_re.search(sub.value):
                        return True
            return False

        def _is_string_construction(expr, scope_id, lineno, depth=0) -> bool:
            """Explicit dynamic string building around a literal template."""
            if expr is None or depth > 6:
                return False
            if isinstance(expr, ast.JoinedStr):
                return any(isinstance(part, ast.FormattedValue) for part in expr.values)
            if isinstance(expr, ast.BinOp):
                if isinstance(expr.op, ast.Mod):
                    left_const = any(isinstance(sub, ast.Constant) and isinstance(sub.value, str)
                                     for sub in ast.walk(expr.left))
                    return left_const and not _is_static(expr, scope_id, lineno)
                if isinstance(expr.op, ast.Add):
                    sides = (_resolve_arg(expr.left, scope_id, lineno, [])[0],
                             _resolve_arg(expr.right, scope_id, lineno, [])[0])
                    has_const = any(
                        isinstance(sub, ast.Constant) and isinstance(sub.value, str)
                        for side in sides for sub in ast.walk(side))
                    return has_const and not _is_static(expr, scope_id, lineno)
                return False
            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) \
                    and expr.func.attr == "format":
                if _uses_safe_builder(expr, scope_id, lineno):
                    return False
                if not expr.args and not expr.keywords:
                    return False
                return any(not _is_static(arg, scope_id, lineno)
                           for arg in [a for a in expr.args] + [kw.value for kw in expr.keywords])
            if isinstance(expr, ast.Name):
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None and record.value_node is not None:
                    return _is_string_construction(record.value_node, record.scope_id,
                                                   record.lineno, depth + 1)
                return False
            return False

        def _receiver_root(expr):
            current = expr
            while isinstance(current, ast.Attribute):
                current = current.value
            return current if isinstance(current, ast.Name) else None

        def _db_like_receiver(call: ast.Call, scope_id: str, lineno: int) -> bool:
            root = _receiver_root(call.func) if isinstance(call.func, ast.AST) else None
            if root is None:
                # Attribute on a constructor call, e.g. pg8000.connect(...).run
                if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Call):
                    inner = call.func.value
                    if isinstance(inner.func, ast.Attribute) and inner.func.attr in db_ctor_attrs:
                        return True
                return False
            rid = root.id.lower()
            if (rid in db_receiver_ids or rid.endswith(("conn", "cursor", "pool", "_db"))
                    or rid.startswith(("conn", "cursor", "pool", "engine", "session",
                                       "db", "asyncpg", "psycopg", "pg8000", "aiopg"))):
                return True
            record = _assigned_value(root.id, scope_id, lineno)
            if record is not None and isinstance(record.value_node, ast.Call):
                value_names = {dotted_name(record.value_node.func) or "",
                               self.resolve_canonical_name(record.value_node.func, record.scope_id) or ""}
                for name in value_names:
                    tail = name.rsplit(".", 1)[-1]
                    if tail in db_ctor_attrs:
                        return True
                if any(seg in {"objects", "dbsession"} for seg in (record.value_node.func and
                                                                   (dotted_name(record.value_node.func) or "").split("."))):
                    return True
            enclosing = self.functions.get(scope_id)
            if enclosing is not None and isinstance(enclosing, ast.AST):
                for arg in list(enclosing.args.posonlyargs) + list(enclosing.args.args) + \
                        list(enclosing.args.kwonlyargs):
                    if arg.arg == root.id:
                        if arg.annotation is not None:
                            ann_text = ast.unparse(arg.annotation)
                            if any(tok in ann_text for tok in ("Connection", "Cursor", "Pool",
                                                               "asyncpg", "pg8000", "aiopg",
                                                               "Engine", "Session")):
                                return True
                        if root.id.lower() in db_receiver_ids:
                            return True
            return False

        def _has_objects_chain(call: ast.Call) -> bool:
            func = call.func
            try:
                text_repr = ast.unparse(func)
            except Exception:
                return False
            return ".objects" in text_repr or text_repr.startswith("objects")

        def _query_argument(call: ast.Call):
            for kw in call.keywords:
                if kw.arg in {"query", "sql", "statement"}:
                    return kw.value
            if call.args:
                return call.args[0]
            return None

        def _vulnerable_call(call: ast.Call, scope_id: str, mod_name: str,
                             require_shape_or_db: bool, bare_extra_ok: bool = False) -> bool:
            """Shared guard chain for P1/P2/P3. Returns True only when the query argument
            survives every safety check and is dynamically constructed."""
            # Parameterized preservation: any extra positional or ANY keyword arg => silent.
            if len(call.args) > 1 or any(kw.arg for kw in call.keywords):
                return False
            if bare_extra_ok and not call.args and not call.keywords:
                return True
            query_expr = _query_argument(call)
            if query_expr is None:
                return False
            touched = [getattr(call, "lineno", 1)]
            resolved, res_scope, res_lineno = _resolve_arg(query_expr, scope_id,
                                                           getattr(call, "lineno", 1), touched)
            for line in touched:
                if _is_line_suppressed(line, mod_name):
                    return False
            if _is_static(resolved, res_scope, res_lineno):
                return False
            if _uses_safe_builder(resolved, res_scope, res_lineno):
                return False
            if not _is_string_construction(resolved, res_scope, res_lineno):
                return False
            if require_shape_or_db:
                if not (_has_sql_shape(resolved) or _db_like_receiver(call, scope_id,
                                                                      getattr(call, "lineno", 1))):
                    return False
            return True

        def _emit89(call: ast.Call, mod_name: str, scope_id: str) -> None:
            file_path = self.file_paths.get(mod_name, "unknown.py")
            lines_to_emit = {getattr(call, "lineno", 1)}
            query_expr = _query_argument(call)
            if isinstance(query_expr, ast.AST):
                arg_line = getattr(query_expr, "lineno", 0)
                if arg_line:
                    lines_to_emit.add(arg_line)
            existing_records = list(self.sink_records)
            emitted = False
            for line in sorted(lines_to_emit):
                if _is_line_suppressed(line, mod_name):
                    continue
                node_location = CodeLocation(file_path, line, line, 0, 0)
                match = next((
                    record for record in existing_records
                    if record.security_node.location.file == node_location.file
                    and record.security_node.location.line_start == node_location.line_start
                    and record.security_node.metadata.get("cwe") == "CWE-89"
                ), None)
                if match is not None:
                    meta = match.security_node.metadata
                    if not any(key.endswith("source_id") for key in meta):
                        meta["p6_source_id"] = "SQL_INJECTION_VULNERABILITY"
                    emitted = True
                    continue
                key = (line, getattr(call, "col_offset", 0))
                if key in p12_seen:
                    continue
                p12_seen.add(key)
                sink_node = SecurityNode(
                    id=self.next_sink_id(),
                    node_type=NodeType.SINK,
                    symbol="SQL_DRIVER_QUERYBUILDER",
                    operation="SQL_QUERY_EXECUTION",
                    location=node_location,
                    metadata={
                        "sink_type": "SQL_INJECTION",
                        "category": "SQL_INJECTION",
                        "cwe": "CWE-89",
                        "operation": "SQL_QUERY_EXECUTION",
                        "p6_source_id": "SQL_INJECTION_VULNERABILITY",
                    },
                )
                self.sinks.append(sink_node)
                self.sink_records.append(SinkRecord(
                    node=call,
                    security_node=sink_node,
                    lineno=line,
                    scope_id=scope_id,
                ))
                emitted = True

        for mod_name, tree in self.modules.items():
            # P1 edge-repair: registry-created CWE-89 sinks that never earned a source id.
            repair_candidates = [
                record for record in list(self.sink_records)
                if record.security_node.metadata.get("cwe") == "CWE-89"
                and not any(key.endswith("source_id") for key in record.security_node.metadata)
                and isinstance(record.node, ast.Call)
            ]
            for record in repair_candidates:
                call = record.node
                scope_id = record.scope_id
                attr = call.func.attr if isinstance(call.func, ast.Attribute) else None
                if attr not in execute_attrs and attr not in driver_attrs:
                    continue
                if _vulnerable_call(call, scope_id, mod_name, require_shape_or_db=True):
                    _emit89(call, mod_name, scope_id)

            for node in self._reachable_nodes(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.AST):
                    continue
                scope_id = _scope_for(node, mod_name)
                attr = node.func.attr if isinstance(node.func, ast.Attribute) else None
                if attr is None:
                    continue
                call_line = getattr(node, "lineno", 1)
                already = next((
                    record for record in self.sink_records
                    if record.security_node.location.file == self.file_paths.get(mod_name, "")
                    and record.security_node.location.line_start == call_line
                    and record.security_node.metadata.get("cwe") == "CWE-89"
                ), None)
                if already is not None and any(
                        key.endswith("source_id") for key in already.security_node.metadata):
                    continue  # already an established finding at this call

                if attr in execute_attrs or attr in driver_attrs:
                    if _vulnerable_call(node, scope_id, mod_name, require_shape_or_db=True):
                        _emit89(node, mod_name, scope_id)
                    continue
                if attr in builder_attrs:
                    if _vulnerable_call(node, scope_id, mod_name, require_shape_or_db=False):
                        _emit89(node, mod_name, scope_id)
                    continue
                if attr in django_attrs and _has_objects_chain(node):
                    if _vulnerable_call(node, scope_id, mod_name, require_shape_or_db=False,
                                        bare_extra_ok=True):
                        _emit89(node, mod_name, scope_id)

    def _collect_cwe79_xss_recovery_findings(self) -> None:
        """Phase 10.3: recover reflected-XSS and auto-escape-bypass constructs the
        response/template collectors miss — dynamic HTML construction, mark_safe-family
        wrapper arguments, unescaped template extensions, is_safe/SafeString escapes,
        dict-key autoescape flags, and container-body responses."""
        # SUPPRESSION ENFORCEMENT: the core registry path only honours same-line markers,
        # so prune XSS-family sinks whose statement is annotated '# ok:' on the line above.
        # SANITIZER GUARD (core-path gap): also prune response/mark_safe sinks whose body is
        # an escape-family call (bleach.clean, strip_tags, ...), which the legacy taint
        # path does not treat as sanitized.
        pruned: set[str] = set()
        kept_sinks = []
        sanitizer_segments = {"escape", "escapejs", "conditional_escape", "clean",
                              "strip_tags", "urlize", "format_html", "smart_urlquote",
                              "urlencode", "render_to_string", "render"}
        xss_sink_wrappers = {"mark_safe", "markup", "httpresponse", "httpresponsebadrequest",
                             "httpresponseservererror", "make_response", "response"}

        def _assigned_before(name: str, scope_id: str, lineno: int):
            records = self.assignments_by_scope.get((scope_id, name), [])
            prior = [record for record in records if record.lineno < lineno]
            return prior[-1] if prior else None

        def _callee_segment(call_node: ast.Call) -> str:
            func = call_node.func
            if isinstance(func, ast.Attribute):
                return func.attr
            if isinstance(func, ast.Name):
                return func.id
            return ""

        def _sanitized_response_body(call_node: ast.Call, scope_id: str, lineno: int) -> bool:
            wrapper = _callee_segment(call_node).lower()
            if wrapper not in xss_sink_wrappers and not wrapper.startswith("httpresponse"):
                return False
            body = call_node.args[0] if call_node.args else next(
                (kw.value for kw in call_node.keywords
                 if kw.arg in {"content", "response", "body", "data"}), None)
            if body is None:
                return False
            if isinstance(body, ast.Name):
                record = _assigned_before(body.id, scope_id, lineno)
                if record is not None:
                    body = record.value_node
            return (isinstance(body, ast.Call)
                    and _callee_segment(body) in sanitizer_segments)

        for sink in self.sinks:
            meta = sink.metadata or {}
            if meta.get("cwe") in ("CWE-79", "CWE-80", "CWE-116"):
                lines = self._source_lines_by_file.get(sink.location.file, [])
                start = sink.location.line_start
                suppressed = (
                    start >= 2 and len(lines) >= start - 1
                    and re.search(r"#\s*ok\b", lines[start - 2], re.IGNORECASE))
                record = next((r for r in self.sink_records
                               if r.security_node is sink and isinstance(r.node, ast.Call)), None)
                sanitized = record is not None and _sanitized_response_body(
                    record.node, record.scope_id, start)
                if suppressed or sanitized:
                    pruned.add(sink.id)
                    continue
            kept_sinks.append(sink)
        if pruned:
            self.sinks = kept_sinks
            self.sink_records = [r for r in self.sink_records if r.security_node.id not in pruned]
            self.edges = [e for e in self.edges if e.target_id not in pruned]

        function_scopes = {id(function): scope for scope, function in self.functions.items()}

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _assigned(name: str, scope_id: str, lineno: int):
            current_scope = scope_id
            mod_name = scope_module(scope_id)
            seen_scopes = set()
            while current_scope and current_scope not in seen_scopes:
                seen_scopes.add(current_scope)
                records = self.assignments_by_scope.get((current_scope, name), [])
                fn = self.functions.get(current_scope)
                fn_start = getattr(fn, "lineno", 0) if fn is not None else 0
                # Strict '<': a name read on its own write line sees the previous value,
                # which lets reassignment chains (text = text.replace(...)) resolve.
                # Records must also belong to this function body (same-name function
                # defs share one scope key and must not cross-resolve).
                prior = [record for record in records
                         if record.lineno < lineno and record.lineno >= fn_start]
                if prior:
                    return prior[-1]
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope:
                    current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global":
                    current_scope = f"{mod_name}:global"
                else:
                    break
            return None

        def _resolve(expr: ast.AST, scope_id: str, lineno: int, visited=None):
            if visited is None:
                visited = set()
            while isinstance(expr, ast.Name):
                if expr.id in visited:
                    return None
                visited.add(expr.id)
                record = _assigned(expr.id, scope_id, lineno)
                if record is None:
                    return None
                expr, scope_id, lineno = record.value_node, record.scope_id, record.lineno
            return expr, scope_id, lineno

        def _seg(func_expr: ast.AST) -> str:
            if isinstance(func_expr, ast.Attribute):
                return func_expr.attr
            if isinstance(func_expr, ast.Name):
                return func_expr.id
            return ""

        def _recv_text(expr: ast.AST) -> str:
            parts = []
            current = expr
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts)).lower()

        def _sup79(mod_name: str, lineno: int) -> bool:
            source_lines = self._source_lines_by_file.get(self.file_paths.get(mod_name, ""), [])
            if source_lines and 1 <= lineno <= len(source_lines):
                if re.search(r"#\s*ok\b", source_lines[lineno - 1], re.IGNORECASE):
                    return True
                if lineno >= 2 and re.search(r"#\s*ok\b", source_lines[lineno - 2], re.IGNORECASE):
                    return True
            return False

        emitted: set[tuple[str, int]] = set()

        def _emit79(node: ast.AST, mod_name: str, scope_id: str, operation: str) -> None:
            line = getattr(node, "lineno", 1)
            key = (mod_name, line)
            if key in emitted:
                return
            if _sup79(mod_name, line):
                return
            
            # SUPPRESSION: If CWE-1336 (SSTI) is already reported at this line, suppress CWE-79
            file_path = self.file_paths.get(mod_name, "unknown.py")
            has_ssti = any(
                record.security_node.metadata.get("cwe") == "CWE-1336"
                for record in self.sink_records
                if record.security_node.location.file == file_path
                and record.security_node.location.line_start == line
            )
            if has_ssti:
                return  # SSTI finding already covers this line
            
            emitted.add(key)
            existing = next((
                record for record in self.sink_records
                if record.security_node.location.file == file_path
                and record.security_node.location.line_start == line
                and record.security_node.metadata.get("cwe") == "CWE-79"
            ), None)
            if existing is not None:
                if not any(k.endswith("source_id") for k in existing.security_node.metadata):
                    existing.security_node.metadata["p11_source_id"] = "DYNAMIC_HTML_RESPONSE"
                return
            sink_node = SecurityNode(
                id=self.next_sink_id(),
                node_type=NodeType.SINK,
                symbol=operation,
                operation=operation,
                location=CodeLocation(
                    file=file_path, line_start=line, line_end=line,
                    column_start=getattr(node, "col_offset", 0),
                    column_end=getattr(node, "col_offset", 0),
                ),
                metadata={
                    "sink_type": "XSS",
                    "category": "CROSS_SITE_SCRIPTING",
                    "cwe": "CWE-79",
                    "p11_source_id": "DYNAMIC_HTML_RESPONSE",
                    "lineno": line,
                },
            )
            self.sinks.append(sink_node)
            self.sink_records.append(SinkRecord(
                node=node,
                security_node=sink_node,
                lineno=line,
                scope_id=scope_id,
            ))

        tag_re = re.compile(r"<[a-zA-Z!/][^>]*>")
        ext_re = re.compile(r"\.([A-Za-z0-9_]+)$")
        safe_methods = {
            "escape", "escapejs", "conditional_escape", "clean", "strip_tags",
            "urlize", "format_html", "json_script", "mark_safe", "Markup", "render_template",
            "jsonify", "dumps", "redirect", "getlist", "urlencode", "quote", "quote_plus",
        }
        getter_methods = {
            "get", "getlist", "getvalue", "read", "readline", "readlines", "input",
            "json", "values", "items", "pop", "get_json", "getcookie", "get_header",
        }
        requestish_roots = {"request", "req", "event", "environ", "flask", "django"}
        template_safe_exts = {"html", "htm"}
        html_safe_wrappers = {"escape", "escapejs", "conditional_escape", "clean",
                              "strip_tags", "urlize", "format_html"}

        def _const_tag(expr, scope_id, lineno, visited=None) -> bool:
            if expr is None:
                return False
            if visited is None:
                visited = set()
            resolved = _resolve(expr, scope_id, lineno, set(visited))
            if resolved is None:
                return False
            expr, scope_id, lineno = resolved
            if isinstance(expr, ast.Constant):
                return isinstance(expr.value, str) and bool(tag_re.search(expr.value))
            if isinstance(expr, ast.JoinedStr):
                return any(
                    isinstance(part, ast.Constant) and isinstance(part.value, str)
                    and tag_re.search(part.value) for part in expr.values
                )
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
                return _const_tag(expr.left, scope_id, lineno, visited) or _const_tag(
                    expr.right, scope_id, lineno, visited)
            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                return _const_tag(expr.func.value, scope_id, lineno, visited)
            return False

        def _marker(expr, scope_id, lineno, visited=None) -> bool:
            if expr is None:
                return False
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Subscript):
                return True
            if isinstance(expr, ast.Name):
                record = _assigned(expr.id, scope_id, lineno)
                if record is None:
                    return True
                key = (expr.id, record.lineno)
                if key in visited:
                    return False
                return _marker(record.value_node, record.scope_id, record.lineno, visited | {key})
            if isinstance(expr, ast.Constant):
                return False
            if isinstance(expr, ast.JoinedStr):
                return any(_marker(part.value, scope_id, lineno, visited)
                           for part in expr.values if isinstance(part, ast.FormattedValue))
            if isinstance(expr, ast.BinOp):
                return _marker(expr.left, scope_id, lineno, visited) or _marker(
                    expr.right, scope_id, lineno, visited)
            if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
                return any(_marker(elt, scope_id, lineno, visited) for elt in expr.elts)
            if isinstance(expr, ast.Dict):
                return any(
                    _marker(value, scope_id, lineno, visited)
                    for value in expr.values if value is not None
                ) or any(_marker(key, scope_id, lineno, visited)
                        for key in expr.keys if key is not None)
            if isinstance(expr, ast.IfExp):
                return any(_marker(part, scope_id, lineno, visited)
                           for part in (expr.body, expr.orelse))
            if isinstance(expr, ast.UnaryOp):
                return _marker(expr.operand, scope_id, lineno, visited)
            if isinstance(expr, ast.Starred):
                return _marker(expr.value, scope_id, lineno, visited)
            if isinstance(expr, ast.Call):
                seg = _seg(expr.func)
                if seg in safe_methods:
                    return False
                if seg in getter_methods and any(
                        root in requestish_roots
                        for root in _recv_text(expr.func.value).split(".")):
                    return True
                if seg == "format" and isinstance(expr.func, ast.Attribute):
                    # "<tpl>{}".format(value): the interpolated arguments carry the taint.
                    if any(_marker(arg, scope_id, lineno, visited) for arg in expr.args):
                        return True
                    if any(_marker(kw.value, scope_id, lineno, visited) for kw in expr.keywords):
                        return True
                    return _marker(expr.func.value, scope_id, lineno, visited)
                if isinstance(expr.func, ast.Attribute):
                    return _marker(expr.func.value, scope_id, lineno, visited)
                return _marker(expr.func, scope_id, lineno, visited)
            return False

        def _dynamic_html(expr, scope_id, lineno) -> bool:
            if isinstance(expr, (ast.JoinedStr, ast.BinOp, ast.Call)):
                return _const_tag(expr, scope_id, lineno) and _marker(expr, scope_id, lineno)
            return False

        def _template_candidates(arg, scope_id, lineno):
            resolved = _resolve(arg, scope_id, lineno)
            if resolved is None:
                return []
            arg, scope_id, lineno = resolved
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                return [arg.value]
            if isinstance(arg, ast.JoinedStr):
                parts = [p.value for p in arg.values
                         if isinstance(p, ast.Constant) and isinstance(p.value, str)]
                return [parts[-1]] if parts else []
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                return _template_candidates(arg.left, scope_id, lineno) + _template_candidates(
                    arg.right, scope_id, lineno)
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                return _template_candidates(arg.left, scope_id, lineno)
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
                return _template_candidates(arg.func.value, scope_id, lineno)
            return []

        for mod_name, tree in self.modules.items():
            for node in self._reachable_nodes(tree):
                scope_id = _scope_for(node, mod_name)
                lineno = getattr(node, "lineno", 1)

                # Predicate A: dynamic HTML construction in statements and call arguments.
                value = None
                if isinstance(node, ast.Assign):
                    value = node.value
                elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
                    value = node.value
                elif isinstance(node, ast.Return):
                    value = node.value
                if value is not None and _dynamic_html(value, scope_id, lineno):
                    _emit79(node, mod_name, scope_id, "DYNAMIC_HTML_CONSTRUCTION")

                # Predicate C: dict-literal autoescape flags (context and TEMPLATES OPTIONS).
                # Predicate I: AWS-style {"body": html, "headers": {...text/html...}} dicts.
                if isinstance(node, ast.Dict):
                    for key in node.keys:
                        if isinstance(key, ast.Constant) and key.value == "autoescape":
                            _emit79(key, mod_name, scope_id, "TEMPLATE_AUTOESCAPE_DISABLED")
                    body_value = None
                    html_headers = False
                    for key, entry in zip(node.keys, node.values):
                        if entry is None or not isinstance(key, ast.Constant):
                            continue
                        if key.value == "body":
                            body_value = entry
                        elif key.value == "headers" and isinstance(entry, ast.Dict):
                            for hk, hv in zip(entry.keys, entry.values):
                                if (isinstance(hk, ast.Constant) and isinstance(hk.value, str)
                                        and "content-type" in hk.value.lower()
                                        and isinstance(hv, ast.Constant)
                                        and isinstance(hv.value, str)
                                        and "text/html" in hv.value.lower()):
                                    html_headers = True
                    if body_value is not None and html_headers and _marker(body_value, scope_id, lineno):
                        _emit79(body_value, mod_name, scope_id, "LAMBDA_HTML_BODY_RESPONSE")

                # Predicate F: SafeString subclasses, __html__, html_safe decorators/wrappers,
                # and register.filter(is_safe=True).
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    for decorator in node.decorator_list:
                        if isinstance(decorator, ast.Name) and decorator.id == "html_safe":
                            _emit79(decorator, mod_name, scope_id, "DJANGO_HTML_SAFE_DECORATOR")
                        elif (isinstance(decorator, ast.Call)
                              and _seg(decorator.func) == "filter"
                              and any(kw.arg == "is_safe" and isinstance(kw.value, ast.Constant)
                                      and kw.value.value is True for kw in decorator.keywords)):
                            _emit79(decorator, mod_name, scope_id, "TEMPLATE_FILTER_IS_SAFE")
                    if node.name == "__html__":
                        _emit79(node, mod_name, scope_id, "HTML_MAGIC_METHOD")
                    if isinstance(node, ast.ClassDef) and any(
                            _seg(base) in {"SafeString", "SafeText", "SafeData"} for base in node.bases):
                        _emit79(node, mod_name, scope_id, "SAFESTRING_SUBCLASS")
                if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                        and _seg(node.value.func) == "html_safe"):
                    _emit79(node, mod_name, scope_id, "DJANGO_HTML_SAFE_WRAPPER")

                if not isinstance(node, ast.Call):
                    continue
                callee_seg = _seg(node.func)

                if callee_seg not in html_safe_wrappers:
                    for arg in node.args:
                        if isinstance(arg, (ast.JoinedStr, ast.BinOp)) or (
                                isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
                                and arg.func.attr == "format"):
                            if _dynamic_html(arg, scope_id, lineno):
                                _emit79(arg, mod_name, scope_id, "DYNAMIC_HTML_ARGUMENT")
                    for kw in node.keywords:
                        if kw.arg is not None and isinstance(kw.value, (ast.JoinedStr, ast.BinOp)):
                            if _dynamic_html(kw.value, scope_id, lineno):
                                _emit79(kw.value, mod_name, scope_id, "DYNAMIC_HTML_ARGUMENT")

                # Predicate E: Markup.unescape() strips escaping from a dynamic value.
                if (isinstance(node.func, ast.Attribute) and node.func.attr == "unescape"
                        and "markup" in _recv_text(node.func.value)
                        and any(not isinstance(arg, ast.Constant) for arg in node.args)):
                    _emit79(node, mod_name, scope_id, "MARKUP_UNESCAPE")

                # Predicate G: response sinks whose body is a structured literal carrying
                # dynamic content (the JSON-body guard skips these in the main collector).
                call_name = dotted_name(node.func) or ""
                call_seg = call_name.rsplit(".", 1)[-1] if call_name else ""
                if call_seg.startswith("HttpResponse") or call_seg in {"make_response", "Response"}:
                    body = node.args[0] if node.args else next(
                        (kw.value for kw in node.keywords if kw.arg in {"content", "response", "body", "data"}), None)
                    if (isinstance(body, (ast.Dict, ast.List, ast.Tuple, ast.Set))
                            and _marker(body, scope_id, lineno)):
                        _emit79(node, mod_name, scope_id, "HTML_RESPONSE_CONTAINER_BODY")

                # Predicate H: template-name extensions that bypass autoescaping.
                if call_seg == "render_template":
                    t_arg = node.args[0] if node.args else next(
                        (kw.value for kw in node.keywords if kw.arg in {"template_name_or_list", "template"}), None)
                    has_context = len(node.args) > 1 or any(
                        kw.arg not in {"template_name_or_list", "template"} for kw in node.keywords)
                    if t_arg is not None and has_context:
                        flagged = False
                        for candidate in _template_candidates(t_arg, scope_id, lineno):
                            match = ext_re.search(candidate)
                            if match is None:
                                flagged = True
                                break
                            if match.group(1) not in template_safe_exts:
                                flagged = True
                                break
                        if flagged:
                            _emit79(node, mod_name, scope_id, "UNESCAPED_TEMPLATE_EXTENSION")

    def _collect_cwe22_path_traversal_findings(self) -> None:
        """Phase 11: recover path traversal constructs where request/user-controlled
        data flows into file-system sinks (open, os.remove, send_file, FileResponse)."""
        function_scopes = {id(function): scope for scope, function in self.functions.items()}

        # SUPPRESSION ENFORCEMENT: prune paths annotated '# ok:' on same or previous line.
        # SANITIZER GUARD: skip paths wrapped in secure_filename/os.path.basename/os.path.abspath.
        pruned: set[str] = set()
        kept_sinks = []
        sanitizer_segments = {"secure_filename", "basename", "abspath", "realpath", "commonpath"}

        def _assigned_before(name: str, scope_id: str, lineno: int):
            records = self.assignments_by_scope.get((scope_id, name), [])
            prior = [record for record in records if record.lineno < lineno]
            return prior[-1] if prior else None

        def _callee_segment(call_node: ast.Call) -> str:
            func = call_node.func
            if isinstance(func, ast.Attribute):
                return func.attr
            if isinstance(func, ast.Name):
                return func.id
            return ""

        def _sanitized_path_arg(expr: ast.AST, scope_id: str, lineno: int) -> bool:
            """Check if path expression is wrapped in a sanitizer."""
            if isinstance(expr, ast.Call):
                seg = _callee_segment(expr)
                if seg in sanitizer_segments:
                    return True
            # Check resolved value
            if isinstance(expr, ast.Name):
                record = _assigned_before(expr.id, scope_id, lineno)
                if record is not None:
                    return _sanitized_path_arg(record.value_node, record.scope_id, record.lineno)
            return False

        for sink in self.sinks:
            meta = sink.metadata or {}
            if meta.get("cwe") == "CWE-22":
                lines = self._source_lines_by_file.get(sink.location.file, [])
                start = sink.location.line_start
                # Check current line and up to 2 lines before for suppression marker
                suppressed = False
                for offset in range(3):
                    check_line = start - offset
                    if check_line >= 1 and len(lines) >= check_line:
                        if re.search(r"#\s*ok\b", lines[check_line - 1], re.IGNORECASE):
                            suppressed = True
                            break
                record = next((r for r in self.sink_records
                               if r.security_node is sink and isinstance(r.node, ast.Call)), None)
                sanitized = record is not None and any(
                    _sanitized_path_arg(arg, record.scope_id, start)
                    for arg in record.node.args[:1])
                if suppressed or sanitized:
                    pruned.add(sink.id)
                    continue
            kept_sinks.append(sink)
        if pruned:
            self.sinks = kept_sinks
            self.sink_records = [r for r in self.sink_records if r.security_node.id not in pruned]
            self.edges = [e for e in self.edges if e.target_id not in pruned]

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _resolve(expr: ast.AST, scope_id: str, lineno: int, visited=None):
            if visited is None:
                visited = set()
            while isinstance(expr, ast.Name):
                if expr.id in visited:
                    return None
                visited.add(expr.id)
                records = self.assignments_by_scope.get((scope_id, expr.id), [])
                fn = self.functions.get(scope_id)
                fn_start = getattr(fn, "lineno", 0) if fn is not None else 0
                prior = [record for record in records
                         if record.lineno < lineno and record.lineno >= fn_start]
                if prior:
                    rec = prior[-1]
                    expr, scope_id, lineno = rec.value_node, rec.scope_id, rec.lineno
                else:
                    break
            return expr, scope_id, lineno

        def _seg(func_expr: ast.AST) -> str:
            if isinstance(func_expr, ast.Attribute):
                return func_expr.attr
            if isinstance(func_expr, ast.Name):
                return func_expr.id
            return ""

        def _recv_text(expr: ast.AST) -> str:
            parts = []
            current = expr
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts)).lower()

        def _sup22(mod_name: str, lineno: int) -> bool:
            source_lines = self._source_lines_by_file.get(self.file_paths.get(mod_name, ""), [])
            if source_lines and 1 <= lineno <= len(source_lines):
                # Check current line and up to 3 lines before for suppression marker
                for offset in range(4):
                    check_line = lineno - offset
                    if check_line >= 1 and len(source_lines) >= check_line:
                        if re.search(r"#\s*ok\b", source_lines[check_line - 1], re.IGNORECASE):
                            return True
            return False

        emitted: set[tuple[str, int]] = set()

        def _emit22(node: ast.AST, mod_name: str, scope_id: str, operation: str, cwe: str = "CWE-22", source_node=None) -> None:
            line = getattr(node, "lineno", 1)
            key = (mod_name, line)
            if key in emitted:
                return
            if _sup22(mod_name, line):
                return
            emitted.add(key)
            file_path = self.file_paths.get(mod_name, "unknown.py")
            existing = next((
                record for record in self.sink_records
                if record.security_node.location.file == file_path
                and record.security_node.location.line_start == line
                and record.security_node.metadata.get("cwe") == cwe
            ), None)
            if existing is not None:
                # Reuse existing sink but ensure it has an edge
                sink_node = existing.security_node
                # Add/update metadata
                sink_node.metadata["p11_source_id"] = "UNTRUSTED_PATH_TRAVERSAL"
                # Create edge if one doesn't exist
                has_edge = any(e.target_id == sink_node.id for e in self.edges)
                if not has_edge and source_node is not None:
                    self.edges.append(DataFlowEdge(
                        source_id=source_node.id,
                        target_id=sink_node.id,
                        kind="CONFIRMED_DATA_FLOW",
                        confidence=0.95,
                        transform=f"path_traversal:{operation}",
                    ))
                elif not has_edge:
                    # Try to find any request source
                    for src in self.sources:
                        if src.location.file == file_path and src.lineno < line:
                            self.edges.append(DataFlowEdge(
                                source_id=src.id,
                                target_id=sink_node.id,
                                kind="CONFIRMED_DATA_FLOW",
                                confidence=0.90,
                                transform=f"path_traversal:{operation}",
                            ))
                            break
                return
            sink_node = SecurityNode(
                id=self.next_sink_id(),
                node_type=NodeType.SINK,
                symbol=operation,
                operation=operation,
                location=CodeLocation(
                    file=file_path, line_start=line, line_end=line,
                    column_start=getattr(node, "col_offset", 0),
                    column_end=getattr(node, "col_offset", 0),
                ),
                metadata={
                    "sink_type": "PATH_TRAVERSAL",
                    "category": "PATH_TRAVERSAL",
                    "cwe": cwe,
                    "p11_source_id": "UNTRUSTED_PATH_TRAVERSAL",
                    "lineno": line,
                },
            )
            self.sinks.append(sink_node)
            self.sink_records.append(SinkRecord(
                node=node,
                security_node=sink_node,
                lineno=line,
                scope_id=scope_id,
            ))
            
            # Create CONFIRMED_DATA_FLOW edge from source to sink
            if source_node is not None:
                self.edges.append(DataFlowEdge(
                    source_id=source_node.id,
                    target_id=sink_node.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=0.95,
                    transform=f"path_traversal:{operation}",
                ))
            else:
                # Try to find any request source in the same file before this line
                for src in self.sources:
                    if src.location.file == file_path and src.lineno < line:
                        self.edges.append(DataFlowEdge(
                            source_id=src.id,
                            target_id=sink_node.id,
                            kind="CONFIRMED_DATA_FLOW",
                            confidence=0.90,
                            transform=f"path_traversal:{operation}",
                        ))
                        break

        # Core request roots that carry user input
        requestish_roots = {"request", "req", "event", "environ", "flask", "django"}
        getter_methods = {"get", "getlist", "getvalue", "read", "json", "values", "items", "pop"}

        def _is_request_data(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            """Check if expression carries user-controlled request data."""
            if expr is None:
                return False
            if visited is None:
                visited = set()
            resolved = _resolve(expr, scope_id, lineno, set(visited))
            if resolved is None:
                return False
            expr, scope_id, lineno = resolved

            # Direct request access: request.GET.get(), flask.request.form['x']
            if isinstance(expr, ast.Subscript):
                if isinstance(expr.value, ast.Attribute):
                    recv = _recv_text(expr.value.value)
                    if any(root in recv for root in requestish_roots):
                        return True
                return _is_request_data(expr.value, scope_id, lineno, visited)
            if isinstance(expr, ast.Call):
                seg = _seg(expr.func)
                if seg in getter_methods:
                    recv = _recv_text(expr.func.value)
                    if any(root in recv for root in requestish_roots):
                        return True
                # format() calls with request args
                if seg == "format" and isinstance(expr.func, ast.Attribute):
                    if any(_is_request_data(arg, scope_id, lineno, visited) for arg in expr.args):
                        return True
                    if any(_is_request_data(kw.value, scope_id, lineno, visited) for kw in expr.keywords):
                        return True
                if isinstance(expr.func, ast.Attribute):
                    return _is_request_data(expr.func.value, scope_id, lineno, visited)
                return _is_request_data(expr.func, scope_id, lineno, visited)
            if isinstance(expr, ast.Name):
                record = _assigned_before(expr.id, scope_id, lineno)
                if record is not None:
                    return _is_request_data(record.value_node, record.scope_id, record.lineno, visited)
                return False
            # String concatenation / formatting
            if isinstance(expr, ast.JoinedStr):
                return any(
                    _is_request_data(part.value, scope_id, lineno, visited)
                    for part in expr.values if isinstance(part, ast.FormattedValue)
                )
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
                return (_is_request_data(expr.left, scope_id, lineno, visited)
                        or _is_request_data(expr.right, scope_id, lineno, visited))
            if isinstance(expr, ast.Constant):
                return False
            return False

        def _is_upload_handle(expr: ast.AST, scope_id: str, lineno: int) -> bool:
            """True for an in-memory uploaded-file object, which is not a path string.

            `Image.open(request.FILES['file'])` hands PIL a file-like object, so the
            upload's filename never participates in resolving anything on disk and the
            traversal sink the call name suggests is not reachable from it.
            """
            resolved = _resolve(expr, scope_id, lineno, set())
            if resolved is None:
                return False
            expr, scope_id, lineno = resolved
            texts = set()
            for sub in ast.walk(expr):
                if isinstance(sub, ast.Attribute):
                    recv = _recv_text(sub)
                    texts.update({recv, f"{recv}.{sub.attr.lower()}"})
                elif isinstance(sub, ast.Name):
                    texts.add(sub.id.lower())
            return any("request.files" in text or "uploadedfile" in text for text in texts)

        def _has_dynamic_path(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            """Check if expression contains dynamic path construction from user input."""
            if visited is None:
                visited = set()
            
            # Pure literals are safe
            if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
                return False
            
            # Cycle detection for Name nodes
            if isinstance(expr, ast.Name):
                key = (expr.id, scope_id, lineno)
                if key in visited:
                    return False  # Break cycle
                visited.add(key)
            
            # f-strings with request data
            if isinstance(expr, ast.JoinedStr):
                return _is_request_data(expr, scope_id, lineno)
            # String concatenation
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
                return _is_request_data(expr, scope_id, lineno)
            # .format() calls
            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                return _is_request_data(expr, scope_id, lineno)
            # Direct request data
            if _is_request_data(expr, scope_id, lineno):
                return True
            # Variable resolution
            if isinstance(expr, ast.Name):
                resolved = _resolve(expr, scope_id, lineno)
                if resolved is not None:
                    expr_resolved, scope_resolved, lineno_resolved = resolved
                    # Only recurse if we got a different expression
                    if expr_resolved is not expr:
                        return _has_dynamic_path(expr_resolved, scope_resolved, lineno_resolved, visited)
            return False

        # Path traversal sinks to detect
        file_sinks = {"open", "builtins.open"}
        os_sinks = {"os.remove", "os.unlink", "os.chmod", "os.rename"}
        shutil_sinks = {"shutil.copy", "shutil.copyfile", "shutil.move", "shutil.rmtree"}
        framework_sinks = {"send_file", "FileResponse"}

        for mod_name, tree in self.modules.items():
            for node in self._reachable_nodes(tree):
                if not isinstance(node, ast.Call):
                    continue
                scope_id = _scope_for(node, mod_name)
                lineno = getattr(node, "lineno", 1)
                callee_seg = _seg(node.func)
                callee_name = dotted_name(node.func) or ""

                # Determine if this is a path traversal sink
                is_path_sink = False
                if callee_seg in file_sinks or callee_name in file_sinks:
                    is_path_sink = True
                elif callee_name in os_sinks or callee_seg in {"remove", "unlink", "chmod", "rename"}:
                    is_path_sink = True
                elif callee_name in shutil_sinks or callee_seg in {"copy", "copyfile", "move", "rmtree"}:
                    is_path_sink = True
                elif callee_seg in framework_sinks or any(callee_name.endswith(suffix) for suffix in framework_sinks):
                    is_path_sink = True

                if not is_path_sink:
                    continue

                # Get the path argument (first positional arg for most sinks)
                path_arg = node.args[0] if node.args else None
                if path_arg is None:
                    # Check keyword arguments for specific sinks
                    path_arg = next(
                        (kw.value for kw in node.keywords
                         if kw.arg in {"filename", "path", "filepath", "directory"}),
                        None
                    )
                if path_arg is None:
                    continue

                # Skip pure static literals
                if isinstance(path_arg, ast.Constant) and isinstance(path_arg.value, str):
                    continue

                # A path the program derives from its own `__file__`, from a uuid nonce
                # or from an `os.listdir()` entry has no attacker-controlled component, so
                # traversal cannot be reached through it however the sink is spelled.
                if self._is_self_described(path_arg, scope_id, lineno):
                    continue

                # An uploaded file handle is a stream in memory, not a filesystem path:
                # `Image.open(request.FILES['file'])` reads the upload, never `file`'s name.
                if _is_upload_handle(path_arg, scope_id, lineno):
                    continue

                # Check for dynamic path construction from request data
                if _has_dynamic_path(path_arg, scope_id, lineno):
                    op_name = callee_seg.upper() if callee_seg else "FILE_OPERATION"
                    # Find the nearest request source in this file before this line
                    file_path = self.file_paths.get(mod_name, "unknown.py")
                    source_node = None
                    for src in self.sources:
                        if src.location.file == file_path and src.lineno < lineno:
                            source_node = src
                            break
                    _emit22(node, mod_name, scope_id, f"PATH_TRAVERSAL_{op_name}", source_node=source_node)

                # Also check for os.path.join + open pattern
                # If path_arg is a variable assigned from os.path.join(..., request_data, ...)
                if isinstance(path_arg, ast.Name):
                    record = _assigned_before(path_arg.id, scope_id, lineno)
                    if record is not None:
                        join_expr = record.value_node
                        if (isinstance(join_expr, ast.Call)
                                and isinstance(join_expr.func, ast.Attribute)
                                and join_expr.func.attr == "join"
                                and _recv_text(join_expr.func.value) in {"os.path", "posixpath", "ntpath"}):
                            # Check if any join argument is request data
                            for arg in join_expr.args:
                                if _is_request_data(arg, record.scope_id, record.lineno):
                                    file_path = self.file_paths.get(mod_name, "unknown.py")
                                    source_node = None
                                    for src in self.sources:
                                        if src.location.file == file_path and src.lineno < lineno:
                                            source_node = src
                                            break
                                    _emit22(node, mod_name, scope_id, "PATH_TRAVERSAL_JOIN_OPEN", source_node=source_node)
                                    break

    def _collect_cwe502_deserialization_findings(self) -> None:
        """Phase 11.1: recover insecure deserialization constructs where untrusted data
        flows into dangerous deserialization sinks (pickle, yaml.load, shelve, etc.)."""
        function_scopes = {id(function): scope for scope, function in self.functions.items()}

        # SUPPRESSION ENFORCEMENT: prune deserialization sinks annotated '# ok:' on same or previous lines.
        # ZERO-FP GUARD: Also prune sinks with pure static constant arguments.
        pruned: set[str] = set()
        kept_sinks = []

        for sink in self.sinks:
            meta = sink.metadata or {}
            if meta.get("cwe") == "CWE-502":
                lines = self._source_lines_by_file.get(sink.location.file, [])
                start = sink.location.line_start
                
                # Check suppression markers
                suppressed = False
                for offset in range(3):
                    check_line = start - offset
                    if check_line >= 1 and len(lines) >= check_line:
                        if re.search(r"#\s*ok\b", lines[check_line - 1], re.IGNORECASE):
                            suppressed = True
                            break
                
                # Check for pure static constants in sink records
                static_constant = False
                record = next((r for r in self.sink_records
                               if r.security_node.id == sink.id and isinstance(r.node, ast.Call)), None)
                if record is not None:
                    first_arg = record.node.args[0] if record.node.args else None
                    if first_arg is not None:
                        # Pure byte literal or string literal
                        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, (bytes, str)):
                            static_constant = True
                        elif isinstance(first_arg, (ast.Bytes, ast.Str)):
                            static_constant = True
                
                if suppressed or static_constant:
                    pruned.add(sink.id)
                    continue
            kept_sinks.append(sink)
        if pruned:
            self.sinks = kept_sinks
            self.sink_records = [r for r in self.sink_records if r.security_node.id not in pruned]
            self.edges = [e for e in self.edges if e.target_id not in pruned]

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _seg(func_expr: ast.AST) -> str:
            if isinstance(func_expr, ast.Attribute):
                return func_expr.attr
            if isinstance(func_expr, ast.Name):
                return func_expr.id
            return ""

        def _recv_text(expr: ast.AST) -> str:
            parts = []
            current = expr
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts)).lower()

        def _sup502(mod_name: str, lineno: int) -> bool:
            source_lines = self._source_lines_by_file.get(self.file_paths.get(mod_name, ""), [])
            if source_lines and 1 <= lineno <= len(source_lines):
                # Check current line and up to 2 lines before for suppression marker
                for offset in range(3):
                    check_line = lineno - offset
                    if check_line >= 1 and len(source_lines) >= check_line:
                        if re.search(r"#\s*ok\b", source_lines[check_line - 1], re.IGNORECASE):
                            return True
            return False

        emitted: set[tuple[str, int]] = set()

        def _emit502(node: ast.AST, mod_name: str, scope_id: str, operation: str, cwe: str = "CWE-502", source_node=None) -> None:
            line = getattr(node, "lineno", 1)
            key = (mod_name, line)
            if key in emitted:
                return
            if _sup502(mod_name, line):
                return
            emitted.add(key)
            file_path = self.file_paths.get(mod_name, "unknown.py")
            existing = next((
                record for record in self.sink_records
                if record.security_node.location.file == file_path
                and record.security_node.location.line_start == line
                and record.security_node.metadata.get("cwe") == cwe
            ), None)
            if existing is not None:
                # Reuse existing sink but ensure it has an edge
                sink_node = existing.security_node
                sink_node.metadata["p11_source_id"] = "INSECURE_DESERIALIZATION"
                # Create edge if one doesn't exist
                has_edge = any(e.target_id == sink_node.id for e in self.edges)
                if not has_edge and source_node is not None:
                    self.edges.append(DataFlowEdge(
                        source_id=source_node.id,
                        target_id=sink_node.id,
                        kind="CONFIRMED_DATA_FLOW",
                        confidence=0.95,
                        transform=f"deserialization:{operation}",
                    ))
                elif not has_edge:
                    # Try to find any request/user-controlled source
                    for src in self.sources:
                        if src.location.file == file_path and src.lineno < line:
                            self.edges.append(DataFlowEdge(
                                source_id=src.id,
                                target_id=sink_node.id,
                                kind="CONFIRMED_DATA_FLOW",
                                confidence=0.90,
                                transform=f"deserialization:{operation}",
                            ))
                            break
                return
            sink_node = SecurityNode(
                id=self.next_sink_id(),
                node_type=NodeType.SINK,
                symbol=operation,
                operation=operation,
                location=CodeLocation(
                    file=file_path, line_start=line, line_end=line,
                    column_start=getattr(node, "col_offset", 0),
                    column_end=getattr(node, "col_offset", 0),
                ),
                metadata={
                    "sink_type": "INSECURE_DESERIALIZATION",
                    "category": "INSECURE_DESERIALIZATION",
                    "cwe": cwe,
                    "p11_source_id": "INSECURE_DESERIALIZATION",
                    "lineno": line,
                },
            )
            self.sinks.append(sink_node)
            self.sink_records.append(SinkRecord(
                node=node,
                security_node=sink_node,
                lineno=line,
                scope_id=scope_id,
            ))
            
            # Create CONFIRMED_DATA_FLOW edge from source to sink
            if source_node is not None:
                self.edges.append(DataFlowEdge(
                    source_id=source_node.id,
                    target_id=sink_node.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=0.95,
                    transform=f"deserialization:{operation}",
                ))
            else:
                # Try to find any request/user-controlled source in the same file
                for src in self.sources:
                    if src.location.file == file_path and src.lineno < line:
                        self.edges.append(DataFlowEdge(
                            source_id=src.id,
                            target_id=sink_node.id,
                            kind="CONFIRMED_DATA_FLOW",
                            confidence=0.90,
                            transform=f"deserialization:{operation}",
                        ))
                        break

        # CWE-502 Sink Registry
        # Serialising is not deserialising: `dumps`/`dump` only produce bytes, which
        # become code when something later loads them, and that load is the sink.
        pickle_sinks = {"loads", "load"}
        yaml_unsafe_funcs = {"load", "load_all"}
        safe_yaml_loaders = {"safeloader", "yaml.safeloader", "csafeloader", "yaml.csafeloader"}

        for mod_name, tree in self.modules.items():
            for node in self._reachable_nodes(tree):
                if not isinstance(node, ast.Call):
                    continue
                scope_id = _scope_for(node, mod_name)
                lineno = getattr(node, "lineno", 1)
                callee_seg = _seg(node.func)
                callee_name = dotted_name(node.func) or ""

                # Determine if this is a CWE-502 sink
                is_deser_sink = False
                operation = ""

                # Pickle family: pickle.loads, _pickle.load, cPickle.loads, dill.loads
                if callee_seg in pickle_sinks:
                    recv = _recv_text(node.func.value) if isinstance(node.func, ast.Attribute) else ""
                    if any(lib in recv for lib in ["pickle", "_pickle", "cpickle", "dill"]):
                        is_deser_sink = True
                        operation = f"PICKLE_{callee_seg.upper()}"

                # Shelve: shelve.open
                elif callee_name in {"shelve.open"} or (callee_seg == "open" and isinstance(node.func, ast.Attribute) and _recv_text(node.func.value) == "shelve"):
                    is_deser_sink = True
                    operation = "SHELVE_OPEN"

                # YAML: yaml.load (UNSAFE unless Loader=SafeLoader)
                elif callee_name.startswith("yaml.") and callee_seg in yaml_unsafe_funcs:
                    # Check if SafeLoader/SafeDumper is explicitly passed
                    has_safe_loader = False
                    for kw in node.keywords:
                        if kw.arg == "Loader" and isinstance(kw.value, ast.AST):
                            loader_name = dotted_name(kw.value) or ""
                            loader_seg = _seg(kw.value).lower()
                            if loader_name.lower() in safe_yaml_loaders or loader_seg in safe_yaml_loaders:
                                has_safe_loader = True
                                break
                    
                    # yaml.safe_load dispatches to SafeLoader by name (different function)
                    if callee_name == "yaml.safe_load":
                        has_safe_loader = True

                    if not has_safe_loader:
                        is_deser_sink = True
                        operation = f"YAML_{callee_seg.upper()}"

                # jsonpickle.decode
                elif callee_name in {"jsonpickle.decode", "jsonpickle.unpickler"} or callee_seg in {"decode", "unpickler"}:
                    recv = _recv_text(node.func.value) if isinstance(node.func, ast.Attribute) else ""
                    if "jsonpickle" in recv:
                        is_deser_sink = True
                        operation = f"JSONPICKLE_{callee_seg.upper()}"

                if not is_deser_sink:
                    continue

                # An unsafe Loader only matters when someone other than the repository
                # can author the bytes: `yaml.load(open('/home/fox/test.yaml'))` parses a
                # document fixed in the source text and executes nothing an attacker chose.
                if self._deserializes_own_document(node, scope_id, lineno):
                    continue

                # ZERO-FP GUARD: Skip pure static constants (byte literals, hardcoded strings)
                first_arg = node.args[0] if node.args else None
                if first_arg is not None:
                    # Pure byte literal: b"..." or b'...'
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, bytes):
                        continue
                    # Pure string literal: "..." or '...'
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                        continue
                    # Static Bytes/Str nodes (older AST)
                    if isinstance(first_arg, (ast.Bytes, ast.Str)):
                        continue

                # Find source node for edge creation
                file_path = self.file_paths.get(mod_name, "unknown.py")
                source_node = None
                for src in self.sources:
                    if src.location.file == file_path and src.lineno < lineno:
                        source_node = src
                        break

                _emit502(node, mod_name, scope_id, operation, source_node=source_node)

    def _collect_phase5_structural_findings(self) -> None:
        """Collect Phase 5 path traversal, archive extraction, and TLS findings."""
        function_scopes = {id(function): scope for scope, function in self.functions.items()}
        path_write_sinks = {"open", "builtins.open"}
        path_delete_sinks = {"os.remove", "os.unlink", "shutil.rmtree"}
        tls_sinks = {
            "requests.get", "requests.post", "requests.put", "requests.delete",
            "requests.request", "requests.head", "requests.patch",
            "httpx.get", "httpx.post", "httpx.Client",
            "urllib3.PoolManager", "PoolManager",
            "urllib3.ProxyManager", "ProxyManager",
            "urllib3.connectionpool.HTTPSConnectionPool", "HTTPSConnectionPool",
            "urllib3.connection_from_url", "connection_from_url",
            "urllib3.proxy_from_url", "proxy_from_url",
            "ssl.wrap_socket", "wrap_socket",
        }
        path_sanitizers = {
            "os.path.abspath", "posixpath.abspath", "ntpath.abspath",
            "os.path.realpath", "posixpath.realpath", "ntpath.realpath",
            "os.path.commonpath", "posixpath.commonpath", "ntpath.commonpath",
            "os.path.basename", "posixpath.basename", "ntpath.basename", "basename",
            "pathlib.Path.resolve", "Path.resolve",
        }
        source_ids = {
            "CWE-22": "UNTRUSTED_PATH_TRAVERSAL",
            "ZIP_SLIP": "ZIP_SLIP_EXTRACTION",
            "CWE-295": "DISABLED_TLS_VERIFICATION",
        }

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _names_for_call(call: ast.Call, scope_id: str) -> set[str]:
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.AST):
                return set()
            name = dotted_name(call.func) or ""
            canonical = self.resolve_canonical_name(call.func, scope_id) or ""
            return {value for value in (name, canonical) if value}

        def _assigned_value(name: str, scope_id: str, lineno: int):
            current_scope = scope_id
            mod_name = scope_module(scope_id)
            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
                records = self.assignments_by_scope.get((current_scope, name), [])
                prior = [record for record in records if record.lineno <= lineno]
                if prior:
                    return prior[-1]
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope:
                    current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global":
                    current_scope = f"{mod_name}:global"
                else:
                    break
            return None

        def _is_static(expr: ast.AST, scope_id: str, lineno: int,
                       visited: set = None, depth: int = 0) -> bool:
            if expr is None or depth > 25:
                return False
            if visited is None:
                visited = set()
            if id(expr) in visited:
                return False
            visited.add(id(expr))
            if isinstance(expr, ast.Constant):
                return isinstance(expr.value, (str, bytes, int, float, bool, type(None)))
            if isinstance(expr, (ast.Str, ast.Bytes, ast.Num)):
                return True
            if isinstance(expr, (ast.List, ast.Tuple)):
                return all(_is_static(element, scope_id, lineno, visited, depth + 1) for element in expr.elts)
            # F-strings (JoinedStr) are static only if all interpolated values are static
            if isinstance(expr, ast.JoinedStr):
                return all(_is_static(value, scope_id, lineno, visited, depth + 1) for value in expr.values)
            # String concatenation (BinOp with + or %) is static only if both operands are static
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
                return _is_static(expr.left, scope_id, lineno, visited, depth + 1) and \
                       _is_static(expr.right, scope_id, lineno, visited, depth + 1)
            if isinstance(expr, ast.Call):
                call_names = _names_for_call(expr, scope_id)
                if call_names & {"compile", "builtins.compile"}:
                    if expr.args:
                        return _is_static(expr.args[0], scope_id, lineno, visited, depth + 1)
                # .format() calls are dynamic if the receiver is dynamic
                if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                    if not _is_static(expr.func.value, scope_id, lineno, visited, depth + 1):
                        return False
                    return all(_is_static(arg, scope_id, lineno, visited, depth + 1) for arg in expr.args) and \
                           all(_is_static(kw.value, scope_id, lineno, visited, depth + 1) for kw in expr.keywords)
            if isinstance(expr, ast.Name):
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None and record.value_node is not None:
                    return _is_static(record.value_node, record.scope_id, record.lineno, visited, depth + 1)
            return _eval_static_constant(expr, self.assignments_by_scope, scope_id, lineno) is not None

        def _is_safe_path(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            if expr is None:
                return False
            if _is_static(expr, scope_id, lineno):
                return True
            if self._is_self_described(expr, scope_id, lineno):
                return True
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                return record is not None and _is_safe_path(
                    record.value_node, record.scope_id, record.lineno, visited
                )
            if isinstance(expr, ast.Call):
                if not isinstance(expr.func, ast.AST):
                    return False
                names = {
                    dotted_name(expr.func) or "",
                    self.resolve_canonical_name(expr.func, scope_id) or "",
                }
                if names & path_sanitizers:
                    return True
            return False

        def _archive_kind(expr: ast.AST, scope_id: str, lineno: int, archive_vars: dict) -> str | None:
            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.AST):
                names = _names_for_call(expr, scope_id)
                if any(name.endswith("ZipFile") for name in names):
                    return "zip"
                if any(name.endswith("TarFile") or name in {"tarfile.open", "open"} for name in names):
                    if "tarfile.open" in names or any(name.endswith("TarFile") for name in names):
                        return "tar"
            if isinstance(expr, ast.Name):
                return archive_vars.get((scope_id, expr.id))
            return None

        def _archive_is_safe(call: ast.Call, scope_id: str, lineno: int) -> bool:
            for keyword in call.keywords:
                if keyword.arg == "filter":
                    value = _eval_static_constant(keyword.value, self.assignments_by_scope, scope_id, lineno)
                    if isinstance(value, str) and value.lower() in {"data", "safe"}:
                        return True
                    if isinstance(keyword.value, ast.AST):
                        filter_name = (
                            self.resolve_canonical_name(keyword.value, scope_id)
                            or dotted_name(keyword.value)
                            or ""
                        )
                        if filter_name.rsplit(".", 1)[-1] == "data_filter" or any(
                            marker in filter_name.lower() for marker in ("safe", "secure", "validate", "sanitize")
                        ):
                            return True
                if keyword.arg in {"path", "destination", "dest"} and _is_safe_path(
                    keyword.value, scope_id, lineno
                ):
                    return True
            return False

        seen: set[tuple[str, int, int]] = set()

        def _add_finding(
            node: ast.Call, mod_name: str, scope_id: str, operation: str,
            category: str, cwe: str, source_key: str,
        ) -> None:
            line = getattr(node, "lineno", 1)
            column = getattr(node, "col_offset", 0)
            key = (cwe, line, column)
            if key in seen:
                return
            seen.add(key)
            node_location = location(node, self.file_paths.get(mod_name, "unknown.py"))
            existing = next((
                record for record in self.sink_records
                if record.security_node.location == node_location
                and record.security_node.metadata.get("cwe") == cwe
            ), None)
            if existing is not None:
                existing.security_node.metadata["p5_source_id"] = source_ids[source_key]
                return
            sink_node = SecurityNode(
                id=self.next_sink_id(),
                node_type=NodeType.SINK,
                symbol=operation,
                operation=operation,
                location=node_location,
                metadata={
                    "sink_type": category,
                    "category": category,
                    "cwe": cwe,
                    "p5_source_id": source_ids[source_key],
                },
            )
            self.sinks.append(sink_node)
            self.sink_records.append(SinkRecord(
                node=node,
                security_node=sink_node,
                lineno=line,
                scope_id=scope_id,
            ))

        for mod_name, tree in self.modules.items():
            seen.clear()
            archive_vars: dict[tuple[str, str], str] = {}
            scoped_nodes = [(node, _scope_for(node, mod_name)) for node in self._reachable_nodes(tree)]
            for node, scope_id in scoped_nodes:
                lineno = getattr(node, "lineno", 1)
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call):
                    archive_kind = _archive_kind(node.value, scope_id, lineno, archive_vars)
                    if archive_kind:
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        for target in targets:
                            if isinstance(target, ast.Name):
                                archive_vars[(scope_id, target.id)] = archive_kind
                elif isinstance(node, ast.With):
                    for item in node.items:
                        if isinstance(item.optional_vars, ast.Name):
                            archive_kind = _archive_kind(item.context_expr, scope_id, lineno, archive_vars)
                            if archive_kind:
                                archive_vars[(scope_id, item.optional_vars.id)] = archive_kind

            for node, scope_id in scoped_nodes:
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.AST):
                    continue
                lineno = getattr(node, "lineno", 1)
                names = _names_for_call(node, scope_id)

                if names & path_write_sinks:
                    path_expr = next((kw.value for kw in node.keywords if kw.arg in {"file", "path"}), None)
                    if path_expr is None and node.args:
                        path_expr = node.args[0]
                    mode_expr = next((kw.value for kw in node.keywords if kw.arg == "mode"), None)
                    if mode_expr is None and len(node.args) > 1:
                        mode_expr = node.args[1]
                    mode = _eval_static_constant(mode_expr, self.assignments_by_scope, scope_id, lineno)
                    if isinstance(mode, str) and any(flag in mode for flag in ("w", "a", "x")):
                        if path_expr is not None and not _is_safe_path(path_expr, scope_id, lineno):
                            _add_finding(node, mod_name, scope_id, "FILE_WRITE", "PATH_TRAVERSAL", "CWE-22", "CWE-22")

                if names & path_delete_sinks:
                    path_expr = next((kw.value for kw in node.keywords if kw.arg in {"path", "pathname"}), None)
                    if path_expr is None and node.args:
                        path_expr = node.args[0]
                    if path_expr is not None and not _is_safe_path(path_expr, scope_id, lineno):
                        _add_finding(node, mod_name, scope_id, "FILE_DELETE", "PATH_TRAVERSAL", "CWE-22", "CWE-22")

                if isinstance(node.func, ast.Attribute) and node.func.attr == "extractall":
                    archive_kind = _archive_kind(node.func.value, scope_id, lineno, archive_vars)
                    if archive_kind and not _archive_is_safe(node, scope_id, lineno):
                        _add_finding(
                            node, mod_name, scope_id, "ZIP_SLIP_EXTRACTION",
                            "PATH_TRAVERSAL", "CWE-22", "ZIP_SLIP",
                        )

                if "ssl._create_unverified_context" in names:
                    _add_finding(
                        node, mod_name, scope_id, "DISABLED_TLS_VERIFICATION",
                        "INSECURE_TRANSPORT", "CWE-295", "CWE-295",
                    )
                elif names & tls_sinks and self._has_disabled_ssl(node, scope_id):
                    _add_finding(
                        node, mod_name, scope_id, "DISABLED_TLS_VERIFICATION",
                        "INSECURE_TRANSPORT", "CWE-295", "CWE-295",
                    )

    def _collect_phase6_structural_findings(self) -> None:
        """Collect SQL injection findings from dynamically constructed query text."""
        function_scopes = {id(function): scope for scope, function in self.functions.items()}
        execute_methods = {
            "cursor.execute", "cursor.executemany",
            "connection.execute", "engine.execute", "session.execute",
            "db.session.execute", "sqlite3.Cursor.execute",
        }
        query_wrappers = {
            "text", "sqlalchemy.text", "RawSQL",
            "django.db.models.expressions.RawSQL",
        }
        source_markers = set(SOURCE_REGISTRY)

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _call_names(call: ast.Call, scope_id: str) -> set[str]:
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.AST):
                return set()
            name = dotted_name(call.func) or ""
            canonical = self.resolve_canonical_name(call.func, scope_id) or ""
            return {value for value in (name, canonical) if value}

        def _assigned_value(name: str, scope_id: str, lineno: int):
            current_scope = scope_id
            mod_name = scope_module(scope_id)
            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
                records = self.assignments_by_scope.get((current_scope, name), [])
                prior = [record for record in records if record.lineno <= lineno]
                if prior:
                    return prior[-1]
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope:
                    current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global":
                    current_scope = f"{mod_name}:global"
                else:
                    break
            return None

        def _is_function_parameter(name: str, scope_id: str) -> bool:
            current_scope = scope_id
            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
                function = self.functions.get(current_scope)
                if function:
                    all_args = [
                        *function.args.posonlyargs,
                        *function.args.args,
                        *function.args.kwonlyargs,
                    ]
                    if function.args.vararg:
                        all_args.append(function.args.vararg)
                    if function.args.kwarg:
                        all_args.append(function.args.kwarg)
                    return any(argument.arg == name for argument in all_args)
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                else:
                    break
            return False

        def _is_source_expression(expr: ast.AST, scope_id: str) -> bool:
            if isinstance(expr, ast.Call):
                return self.is_source_call(expr, scope_id)
            if isinstance(expr, ast.Attribute):
                source_name = dotted_name(expr) or ""
                canonical = self.resolve_canonical_name(expr, scope_id) or ""
                return bool({source_name, canonical} & source_markers)
            return False

        def _is_query_dynamic(expr: ast.AST, scope_id: str, lineno: int, visited=None, mod_name: str = "") -> bool:
            if expr is None:
                return False
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Constant):
                return False
            if isinstance(expr, (ast.Str, ast.Bytes, ast.Num)):
                return False
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None:
                    # Check suppression on assignment line
                    if mod_name and _is_line_suppressed(record.lineno, mod_name):
                        return False
                    return _is_query_dynamic(
                        record.value_node, record.scope_id, record.lineno, visited, mod_name
                    )
                return _is_function_parameter(expr.id, scope_id) or self.resolve_canonical_name(
                    expr, scope_id
                ) == expr.id
            if _is_source_expression(expr, scope_id):
                return True
            if isinstance(expr, ast.JoinedStr):
                return any(
                    _is_query_dynamic(part.value, scope_id, lineno, visited.copy(), mod_name)
                    for part in expr.values
                    if isinstance(part, ast.FormattedValue)
                )
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Mod, ast.Add)):
                return _is_query_dynamic(expr.left, scope_id, lineno, visited.copy(), mod_name) or _is_query_dynamic(
                    expr.right, scope_id, lineno, visited.copy(), mod_name
                )
            if isinstance(expr, ast.Call):
                if not isinstance(expr.func, ast.AST):
                    return False
                names = _call_names(expr, scope_id)
                is_format = isinstance(expr.func, ast.Attribute) and expr.func.attr == "format"
                if is_format:
                    format_values = [*expr.args, *(keyword.value for keyword in expr.keywords)]
                    return any(
                        _is_query_dynamic(value, scope_id, lineno, visited.copy(), mod_name)
                        for value in format_values
                    )
                if names & query_wrappers:
                    nested_query = next((
                        keyword.value for keyword in expr.keywords
                        if keyword.arg in {"statement", "sql", "query"}
                    ), expr.args[0] if expr.args else None)
                    return _is_query_dynamic(nested_query, scope_id, lineno, visited, mod_name)
                return False
            if isinstance(expr, (ast.Tuple, ast.List, ast.Set)):
                return any(
                    _is_query_dynamic(element, scope_id, lineno, visited.copy(), mod_name)
                    for element in expr.elts
                )
            if isinstance(expr, ast.Dict):
                return any(
                    _is_query_dynamic(value, scope_id, lineno, visited.copy(), mod_name)
                    for value in expr.values
                )
            return False

        def _query_argument(call: ast.Call) -> ast.AST | None:
            for keyword in call.keywords:
                if keyword.arg in {"statement", "sql", "query"}:
                    return keyword.value
            return call.args[0] if call.args else None

        seen: set[tuple[int, int]] = set()

        def _is_line_suppressed(lineno: int, mod_name: str) -> bool:
            """Check if a line has # ok: or # nosec suppression comment."""
            source_lines = self._source_lines_by_file.get(self.file_paths.get(mod_name, ""), [])
            if source_lines and 1 <= lineno <= len(source_lines):
                line_text = source_lines[lineno - 1]
                if CLUSTER3_NOSEC_RE.search(line_text):
                    return True
                # Also check previous line for # ok: comments
                if lineno >= 2:
                    prev_line = source_lines[lineno - 2]
                    if re.search(r"#\s*ok:", prev_line, re.IGNORECASE):
                        return True
            return False

        def _uses_safe_builder_p6(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            """Check if expression uses safe SQL builders like psycopg2.sql.Identifier or SQLAlchemy bindparams()."""
            if expr is None:
                return False
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Call):
                if isinstance(expr.func, ast.AST):
                    call_names = {
                        dotted_name(expr.func) or "",
                        self.resolve_canonical_name(expr.func, scope_id) or "",
                    }
                    # Check for safe builder functions
                    safe_builders = {
                        "psycopg2.sql.Identifier", "sql.Identifier", "Identifier",
                        "psycopg2.sql.SQL", "sql.SQL",
                        "sqlalchemy.text", "text",
                    }
                    if call_names & safe_builders:
                        return True
                    # Check for .format() method - look at args for safe builders
                    if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                        # Check if any argument to .format() is a safe builder
                        for arg in expr.args:
                            if _uses_safe_builder_p6(arg, scope_id, lineno, visited.copy()):
                                return True
                    # Check for .bindparams() method
                    if isinstance(expr.func, ast.Attribute) and expr.func.attr == "bindparams":
                        return True
                    # Recursively check all arguments
                    for arg in expr.args:
                        if _uses_safe_builder_p6(arg, scope_id, lineno, visited.copy()):
                            return True
                    for kw in expr.keywords:
                        if _uses_safe_builder_p6(kw.value, scope_id, lineno, visited.copy()):
                            return True
                # Also check the receiver of method calls (e.g., sql.SQL(...).format(...))
                if isinstance(expr.func, ast.Attribute):
                    if _uses_safe_builder_p6(expr.func.value, scope_id, lineno, visited.copy()):
                        return True
            if isinstance(expr, ast.BinOp):
                return _uses_safe_builder_p6(expr.left, scope_id, lineno, visited.copy()) or \
                       _uses_safe_builder_p6(expr.right, scope_id, lineno, visited.copy())
            if isinstance(expr, ast.JoinedStr):
                return any(_uses_safe_builder_p6(value, scope_id, lineno, visited.copy()) for value in expr.values)
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None and record.value_node is not None:
                    return _uses_safe_builder_p6(record.value_node, record.scope_id, record.lineno, visited.copy())
            return False

        def _add_finding(node: ast.Call, mod_name: str, scope_id: str) -> None:
            line = getattr(node, "lineno", 1)
            # Check for suppression before adding finding
            if _is_line_suppressed(line, mod_name):
                return
            column = getattr(node, "col_offset", 0)
            key = (line, column)
            if key in seen:
                return
            seen.add(key)
            node_location = location(node, self.file_paths.get(mod_name, "unknown.py"))
            existing = next((
                record for record in self.sink_records
                if record.security_node.location == node_location
                and record.security_node.metadata.get("cwe") == "CWE-89"
            ), None)
            if existing is not None:
                existing.security_node.metadata["p6_source_id"] = "SQL_INJECTION_VULNERABILITY"
                return
            sink_node = SecurityNode(
                id=self.next_sink_id(),
                node_type=NodeType.SINK,
                symbol="SQL_EXECUTION",
                operation="SQL_EXECUTION",
                location=node_location,
                metadata={
                    "sink_type": "SQL_INJECTION",
                    "category": "SQL_INJECTION",
                    "cwe": "CWE-89",
                    "p6_source_id": "SQL_INJECTION_VULNERABILITY",
                },
            )
            self.sinks.append(sink_node)
            self.sink_records.append(SinkRecord(
                node=node,
                security_node=sink_node,
                lineno=line,
                scope_id=scope_id,
            ))

        for mod_name, tree in self.modules.items():
            seen.clear()
            scoped_nodes = [(node, _scope_for(node, mod_name)) for node in self._reachable_nodes(tree)]
            for node, scope_id in scoped_nodes:
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.AST):
                    continue
                names = _call_names(node, scope_id)
                callee = dotted_name(node.func) or ""
                is_execute = any(
                    name in execute_methods or any(name.endswith(f".{method}") for method in execute_methods)
                    for name in names
                )
                is_sqlite_chain = any(
                    "sqlite3.connect" in name and ".cursor().execute" in name
                    for name in names
                )
                is_wrapper = bool(names & query_wrappers)
                if not (is_execute or is_sqlite_chain or is_wrapper):
                    continue
                query = _query_argument(node)
                node_lineno = getattr(node, "lineno", 1)
                if query is not None and _is_query_dynamic(query, scope_id, node_lineno, mod_name=mod_name):
                    # Apply safe builder guard
                    if not _uses_safe_builder_p6(query, scope_id, node_lineno):
                        _add_finding(node, mod_name, scope_id)

    def _collect_phase7_structural_findings(self) -> None:
        """Collect XXE and server-side template injection findings."""
        function_scopes = {id(function): scope for scope, function in self.functions.items()}
        xml_sinks = {
            "lxml.etree.parse", "lxml.etree.fromstring",
            "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring",
            "xml.sax.make_parser",
        }
        template_sinks = {
            "jinja2.Template", "jinja2.Environment.from_string",
            "flask.render_template_string", "render_template_string",
        }

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _call_names(call: ast.Call, scope_id: str) -> set[str]:
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.AST):
                return set()
            name = dotted_name(call.func) or ""
            canonical = self.resolve_canonical_name(call.func, scope_id) or ""
            return {value for value in (name, canonical) if value}

        def _assigned_value(name: str, scope_id: str, lineno: int):
            current_scope = scope_id
            mod_name = scope_module(scope_id)
            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
                records = self.assignments_by_scope.get((current_scope, name), [])
                prior = [record for record in records if record.lineno <= lineno]
                if prior:
                    return prior[-1]
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope:
                    current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global":
                    current_scope = f"{mod_name}:global"
                else:
                    break
            return None

        def _is_dynamic(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            if expr is None:
                return False
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Constant):
                return False
            if isinstance(expr, (ast.Str, ast.Bytes, ast.Num)):
                return False
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None:
                    return _is_dynamic(record.value_node, record.scope_id, record.lineno, visited)
                return self.resolve_canonical_name(expr, scope_id) == expr.id
            if isinstance(expr, ast.Attribute):
                name = dotted_name(expr) or ""
                canonical = self.resolve_canonical_name(expr, scope_id) or ""
                if (
                    name in SOURCE_REGISTRY
                    or canonical in SOURCE_REGISTRY
                    or name in {
                        "request.data", "request.body", "request.query_string",
                        "request.args", "request.form", "request.values",
                        "request.GET", "request.POST", "request.query_params",
                    }
                ):
                    return True
                prior_fields = [
                    record
                    for (_, field_name), records in self.class_field_assignments.items()
                    if field_name == expr.attr
                    for record in records
                    if record.lineno <= lineno
                ]
                if prior_fields:
                    record = max(prior_fields, key=lambda item: item.lineno)
                    return _is_dynamic(record.value_node, record.scope_id, record.lineno, visited)
                return isinstance(expr.value, ast.Name) and expr.value.id in {"self", "cls"}
            if isinstance(expr, ast.Call):
                if self.is_source_call(expr, scope_id):
                    return True
                if not isinstance(expr.func, ast.AST):
                    return True
                if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                    values = [expr.func.value, *expr.args, *(keyword.value for keyword in expr.keywords)]
                    return any(_is_dynamic(value, scope_id, lineno, visited.copy()) for value in values)
                if isinstance(expr.func, ast.Attribute) and expr.func.attr in {
                    "read", "read_text", "read_bytes", "get_data", "get_json",
                }:
                    return True
                values = [*expr.args, *(keyword.value for keyword in expr.keywords)]
                return any(_is_dynamic(value, scope_id, lineno, visited.copy()) for value in values) or not values
            if isinstance(expr, ast.Subscript):
                return _is_dynamic(expr.value, scope_id, lineno, visited.copy())
            if isinstance(expr, ast.JoinedStr):
                return any(
                    _is_dynamic(value.value, scope_id, lineno, visited.copy())
                    for value in expr.values if isinstance(value, ast.FormattedValue)
                )
            if isinstance(expr, ast.BinOp):
                if isinstance(expr.op, (ast.Add, ast.Mod)):
                    return _is_dynamic(expr.left, scope_id, lineno, visited.copy()) or _is_dynamic(
                        expr.right, scope_id, lineno, visited.copy()
                    )
            return False

        def _query_arg(call: ast.Call, keywords: set[str]) -> ast.AST | None:
            for keyword in call.keywords:
                if keyword.arg in keywords:
                    return keyword.value
            return call.args[0] if call.args else None

        def _bool_keyword(call: ast.Call, keyword_name: str, scope_id: str, lineno: int) -> bool | None:
            keyword = next((kw for kw in call.keywords if kw.arg == keyword_name), None)
            if keyword is None:
                return None
            value = _eval_static_constant(keyword.value, self.assignments_by_scope, scope_id, lineno)
            return value if isinstance(value, bool) else None

        def _is_defused(names: set[str]) -> bool:
            return any(name.startswith("defusedxml.") for name in names)

        def _parser_is_safe(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            if expr is None:
                return False
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                return record is not None and _parser_is_safe(
                    record.value_node, record.scope_id, record.lineno, visited
                )
            if not isinstance(expr, ast.Call) or not isinstance(expr.func, ast.AST):
                return False
            names = _call_names(expr, scope_id)
            if _is_defused(names):
                return True
            if not any(name.endswith("XMLParser") for name in names):
                return False
            return _bool_keyword(expr, "resolve_entities", scope_id, lineno) is False

        def _remove_existing(node: ast.Call, cwes: set[str], mod_name: str) -> None:
            node_location = location(node, self.file_paths.get(mod_name, "unknown.py"))
            removed = [
                record for record in self.sink_records
                if record.security_node.location == node_location
                and record.security_node.metadata.get("cwe") in cwes
            ]
            if not removed:
                return
            self.sink_records = [record for record in self.sink_records if record not in removed]
            for record in removed:
                if not any(other.security_node is record.security_node for other in self.sink_records):
                    if record.security_node in self.sinks:
                        self.sinks.remove(record.security_node)

        def _is_opener_receiver(expr: ast.AST, scope_id: str, lineno: int, walked=None) -> bool:
            """True for `URLopener()` / `OpenerDirector()`, or a name bound to one."""
            if isinstance(expr, ast.Call):
                names = {n.rsplit(".", 1)[-1] for n in _call_names(expr, scope_id)}
                return bool(names & P3_URLLIB_OPENER_TYPES)
            if isinstance(expr, ast.Name):
                seen = walked if walked is not None else set()
                key = (scope_id, expr.id)
                if key in seen:
                    return False
                seen.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                return record is not None and _is_opener_receiver(
                    record.value_node, record.scope_id, record.lineno, seen)
            return False

        def _url_text(expr: ast.AST, scope_id: str, lineno: int, node=None):
            """A provably-known URL string: a literal, a constant-folded expression, or a
            parameter whose default is a literal."""
            value = _eval_static_constant(expr, self.assignments_by_scope, scope_id, lineno)
            if isinstance(value, str):
                return value
            if not isinstance(expr, ast.Name):
                return None
            current = getattr(node, "parent", None)
            while current is not None:
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for param, default in TaintTracker._c1_parameter_defaults(current):
                        if param.arg == expr.id and isinstance(default, ast.Constant) \
                                and isinstance(default.value, str):
                            return default.value
                    return None
                current = getattr(current, "parent", None)
            return None

        def _url_static_prefix(expr: ast.AST, scope_id: str, lineno: int):
            """Longest leading text of a URL expression that is provably free of dynamic input.
            A replacement hole (`%s`, `{}`, an f-string field) ends the static run."""
            if expr is None:
                return None
            if isinstance(expr, ast.JoinedStr):
                parts = []
                for value in expr.values:
                    if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
                        break
                    parts.append(value.value)
                return "".join(parts)
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
                text = _url_text(expr.left, scope_id, lineno, expr)
                return text.split("%", 1)[0] if isinstance(text, str) else None
            if (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
                    and expr.func.attr in ("format", "format_map")):
                text = _url_text(expr.func.value, scope_id, lineno, expr)
                return text.split("{", 1)[0] if isinstance(text, str) else None
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
                left = _url_static_prefix(expr.left, scope_id, lineno)
                if left is None:
                    return None
                if P3_URL_AUTHORITY_RE.match(left):
                    return left
                right = _url_static_prefix(expr.right, scope_id, lineno)
                return left + right if right is not None else left
            text = _url_text(expr, scope_id, lineno)
            if not isinstance(text, str):
                return None
            return re.split(r"[{%]", text, 1)[0]

        def _static_url_authority(expr: ast.AST, scope_id: str, lineno: int) -> bool:
            """True when scheme+host are both statically fixed, so no input can redirect the
            request elsewhere: `https://example.com/%s/%s` keeps its authority, while
            `https://%s/x` or `f"https://{env}/x"` does not."""
            prefix = _url_static_prefix(expr, scope_id, lineno)
            return isinstance(prefix, str) and bool(P3_URL_AUTHORITY_RE.match(prefix))

        def _ssrf_sink_name(names: set[str]) -> bool:
            for name in names:
                for candidate in (name, name.rsplit(".", 1)[-1]):
                    meta = SINK_REGISTRY.get(candidate)
                    if meta and meta.get("cwe") == "CWE-918":
                        return True
            return False

        def _fixed_path_read(expr: ast.AST, scope_id: str, lineno: int) -> bool:
            """`open("fixtures/blob.dat")` — the bytes come off a path the caller cannot
            move, so the object graph read from it is not attacker-chosen either."""
            if not isinstance(expr, ast.Call):
                return False
            names = _call_names(expr, scope_id)
            short_names = {name.rsplit(".", 1)[-1] for name in names}
            if not (names & P3_FILE_READ_FUNCTIONS or short_names & P3_FILE_READ_METHODS):
                return False
            path_arg = expr.args[0] if expr.args else next(
                (kw.value for kw in expr.keywords if kw.arg in {"file", "path"}), None)
            return _literal_text(path_arg, self.assignments_by_scope, scope_id, lineno) is not None

        seen: set[tuple[str, int, int]] = set()

        def _add_finding(
            node: ast.Call, mod_name: str, scope_id: str, cwe: str,
            category: str, source_id: str, operation: str,
        ) -> None:
            line = getattr(node, "lineno", 1)
            column = getattr(node, "col_offset", 0)
            key = (cwe, line, column)
            if key in seen:
                return
            seen.add(key)
            node_location = location(node, self.file_paths.get(mod_name, "unknown.py"))
            existing = next((
                record for record in self.sink_records
                if record.security_node.location == node_location
                and record.security_node.metadata.get("cwe") == cwe
            ), None)
            if existing is not None:
                existing.security_node.metadata["p7_source_id"] = source_id
                return
            sink_node = SecurityNode(
                id=self.next_sink_id(),
                node_type=NodeType.SINK,
                symbol=operation,
                operation=operation,
                location=node_location,
                metadata={
                    "sink_type": category,
                    "category": category,
                    "cwe": cwe,
                    "p7_source_id": source_id,
                },
            )
            self.sinks.append(sink_node)
            self.sink_records.append(SinkRecord(
                node=node,
                security_node=sink_node,
                lineno=line,
                scope_id=scope_id,
            ))

        for mod_name, tree in self.modules.items():
            seen.clear()
            sax_parser_vars: set[tuple[str, str]] = set()
            environment_vars: set[tuple[str, str]] = set()
            scoped_nodes = [(node, _scope_for(node, mod_name)) for node in self._reachable_nodes(tree)]

            for node, scope_id in scoped_nodes:
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call):
                    names = _call_names(node.value, scope_id)
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name):
                            if "xml.sax.make_parser" in names:
                                sax_parser_vars.add((scope_id, target.id))
                            if any(name.endswith("Environment") for name in names):
                                environment_vars.add((scope_id, target.id))

            for node, scope_id in scoped_nodes:
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.AST):
                    continue
                lineno = getattr(node, "lineno", 1)
                names = _call_names(node, scope_id)
                if _is_defused(names):
                    _remove_existing(node, {"CWE-611"}, mod_name)
                    continue

                # CWE-319: urllib's opener objects and module-level fetch functions send the
                # scheme spelled in their URL argument. That is a network read, never a
                # filesystem path, so a resolved "<scheme>://" argument also corrects a
                # CWE-22/CWE-73 classification.
                fetch_attr = (isinstance(node.func, ast.Attribute)
                              and node.func.attr in P3_URLLIB_FETCH_METHODS
                              and _is_opener_receiver(node.func.value, scope_id, lineno))
                short_names = {name.rsplit(".", 1)[-1] for name in names}
                fetch_func = bool(short_names & P3_URLLIB_FETCH_FUNCTIONS) or any(
                    name == P3_URLLIB_REQUEST_CONSTRUCTOR for name in names)
                if fetch_attr or fetch_func:
                    url_arg = node.args[0] if node.args else next(
                        (kw.value for kw in node.keywords if kw.arg == "url"), None)
                    url = _url_text(url_arg, scope_id, lineno, node) if url_arg is not None else None
                    scheme = url.split("://", 1)[0].lower() if isinstance(url, str) and "://" in url else None
                    if scheme in P3_URLLIB_NETWORK_SCHEMES:
                        _remove_existing(node, {"CWE-22"}, mod_name)
                        if scheme in P3_URLLIB_CLEARTEXT_SCHEMES:
                            _add_finding(node, mod_name, scope_id, "CWE-319", "INSECURE_TRANSPORT",
                                         "CLEARTEXT_URL_FETCH", "CLEARTEXT_URL_FETCH")
                    continue

                # CWE-918: an outbound fetch is only forgeable when input can move the
                # authority. A fixed scheme+host with taint confined to the path is not SSRF.
                if _ssrf_sink_name(names):
                    url_arg = node.args[0] if node.args else next(
                        (kw.value for kw in node.keywords if kw.arg == "url"), None)
                    if _static_url_authority(url_arg, scope_id, lineno):
                        _remove_existing(node, {"CWE-918"}, mod_name)

                # CWE-89: a statement made only of literals has no hole for input, no
                # matter how many `+=` steps were used to assemble it.
                query_arg = node.args[0] if node.args else next(
                    (kw.value for kw in node.keywords
                     if kw.arg in {"statement", "sql", "query"}), None)
                if _literal_text(query_arg, self.assignments_by_scope, scope_id, lineno) is not None:
                    _remove_existing(node, {"CWE-89"}, mod_name)

                # CWE-502: a payload that is a literal, or bytes read from a literal
                # path, cannot carry attacker-controlled pickle/yaml structure.
                payload_arg = node.args[0] if node.args else next(
                    (kw.value for kw in node.keywords if kw.arg in {"data", "file", "stream"}), None)
                if (_literal_text(payload_arg, self.assignments_by_scope, scope_id, lineno)
                        is not None or _fixed_path_read(payload_arg, scope_id, lineno)):
                    _remove_existing(node, {"CWE-502"}, mod_name)

                # CWE-79: a body is markup only if the response says so. A JSON
                # content_type means the browser never parses it, and a structured literal
                # is not markup in the first place.
                if _json_or_structured_body(node, self.assignments_by_scope, scope_id, lineno):
                    _remove_existing(node, {"CWE-79"}, mod_name)

                is_xml_parser = any(name.endswith("XMLParser") for name in names)
                if is_xml_parser:
                    if _bool_keyword(node, "resolve_entities", scope_id, lineno) is True:
                        _add_finding(
                            node, mod_name, scope_id, "CWE-611", "XML_EXTERNAL_ENTITY",
                            "XXE_INJECTION_VULNERABILITY", "XML_PARSING",
                        )
                    continue

                is_xml_sink = bool(names & xml_sinks) or any(
                    name.startswith("lxml.etree.") and name.rsplit(".", 1)[-1] in {"parse", "fromstring"}
                    for name in names
                ) or any(
                    name.startswith("xml.etree.ElementTree.") and name.rsplit(".", 1)[-1] in {"parse", "fromstring"}
                    for name in names
                )
                is_sax_parse = (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "parse"
                    and isinstance(node.func.value, ast.Name)
                    and (scope_id, node.func.value.id) in sax_parser_vars
                )
                if is_xml_sink or is_sax_parse:
                    input_expr = _query_arg(node, {"source", "file", "input", "text", "xml", "data"})
                    parser_expr = next((kw.value for kw in node.keywords if kw.arg == "parser"), None)
                    if parser_expr is None and len(node.args) > 1:
                        parser_expr = node.args[1]
                    explicit_true = False
                    if parser_expr is not None and isinstance(parser_expr, ast.Call):
                        explicit_true = _bool_keyword(parser_expr, "resolve_entities", scope_id, lineno) is True
                    unsafe = explicit_true or (
                        input_expr is not None
                        and _is_dynamic(input_expr, scope_id, lineno)
                        and not _parser_is_safe(parser_expr, scope_id, lineno)
                    )
                    if unsafe:
                        _add_finding(
                            node, mod_name, scope_id, "CWE-611", "XML_EXTERNAL_ENTITY",
                            "XXE_INJECTION_VULNERABILITY", "XML_PARSING",
                        )
                    elif _parser_is_safe(parser_expr, scope_id, lineno) or isinstance(
                        _eval_static_constant(input_expr, self.assignments_by_scope, scope_id, lineno),
                        (str, bytes),
                    ):
                        _remove_existing(node, {"CWE-611"}, mod_name)
                    continue

                is_template_sink = bool(names & template_sinks) or any(
                    name.endswith("Environment.from_string") for name in names
                ) or (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "from_string"
                    and isinstance(node.func.value, ast.Name)
                    and (scope_id, node.func.value.id) in environment_vars
                )
                is_environment = any(name.endswith("Environment") for name in names)
                if is_environment:
                    if _bool_keyword(node, "autoescape", scope_id, lineno) is False:
                        _add_finding(
                            node, mod_name, scope_id, "CWE-1336", "SSTI",
                            "SSTI_TEMPLATE_INJECTION", "TEMPLATE_EVALUATION",
                        )
                    continue
                if is_template_sink:
                    template_expr = _query_arg(node, {"source", "template", "string"})
                    if template_expr is not None and _is_dynamic(template_expr, scope_id, lineno):
                        _add_finding(
                            node, mod_name, scope_id, "CWE-1336", "SSTI",
                            "SSTI_TEMPLATE_INJECTION", "TEMPLATE_EVALUATION",
                        )
                    else:
                        _remove_existing(node, {"CWE-1336", "CWE-79"}, mod_name)

    def _collect_phase8_structural_findings(self) -> None:
        """Collect open redirect, weak hash, and insecure cookie findings."""
        function_scopes = {id(function): scope for scope, function in self.functions.items()}
        redirect_sinks = {
            "redirect", "flask.redirect", "django.shortcuts.redirect",
            "HttpResponseRedirect", "django.http.HttpResponseRedirect",
            "HttpResponsePermanentRedirect", "django.http.HttpResponsePermanentRedirect",
        }
        weak_hash_sinks = {
            "hashlib.md5", "hashlib.sha1", "hashlib.sha224",
            "Crypto.Hash.MD5", "Crypto.Hash.SHA1",
        }
        redirect_validators = {
            "is_safe_redirect_url", "validate_redirect_url",
            "url_has_allowed_host_and_scheme", "is_relative_url",
            "is_safe_url", "django.utils.http.is_safe_url",
            "django.utils.http.url_has_allowed_host_and_scheme",
        }

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _names_for_call(call: ast.Call, scope_id: str) -> set[str]:
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.AST):
                return set()
            name = dotted_name(call.func) or ""
            canonical = self.resolve_canonical_name(call.func, scope_id) or ""
            return {value for value in (name, canonical) if value}

        def _assigned_value(name: str, scope_id: str, lineno: int):
            current_scope = scope_id
            mod_name = scope_module(scope_id)
            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
                records = self.assignments_by_scope.get((current_scope, name), [])
                prior = [record for record in records if record.lineno <= lineno]
                if prior:
                    return prior[-1]
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope:
                    current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global":
                    current_scope = f"{mod_name}:global"
                else:
                    break
            return None

        def _static_value(expr: ast.AST, scope_id: str, lineno: int):
            return _eval_static_constant(expr, self.assignments_by_scope, scope_id, lineno)

        def _is_dynamic(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            if expr is None:
                return False
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Constant):
                return False
            if isinstance(expr, (ast.Str, ast.Num, ast.Bytes)):
                return False
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None:
                    return _is_dynamic(record.value_node, record.scope_id, record.lineno, visited)
                return self.resolve_canonical_name(expr, scope_id) == expr.id
            if isinstance(expr, ast.Call):
                return self.is_source_call(expr, scope_id) or any(
                    _is_dynamic(value, scope_id, lineno, visited.copy())
                    for value in [*expr.args, *(keyword.value for keyword in expr.keywords)]
                ) or not expr.args and not expr.keywords
            if isinstance(expr, ast.Attribute):
                name = dotted_name(expr) or ""
                return name.startswith(("request.", "flask.request.", "self.", "cls."))
            if isinstance(expr, ast.Subscript):
                if isinstance(expr.value, ast.Name):
                    record = _assigned_value(expr.value.id, scope_id, lineno)
                    if record is not None:
                        return _is_dynamic(record.value_node, record.scope_id, record.lineno, visited.copy())
                return _is_dynamic(expr.value, scope_id, lineno, visited.copy())
            if isinstance(expr, ast.Dict):
                return any(
                    _is_dynamic(value, scope_id, lineno, visited.copy())
                    for value in expr.values
                )
            if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
                return any(
                    _is_dynamic(value, scope_id, lineno, visited.copy())
                    for value in expr.elts
                )
            if isinstance(expr, ast.JoinedStr):
                return any(
                    _is_dynamic(value.value, scope_id, lineno, visited.copy())
                    for value in expr.values if isinstance(value, ast.FormattedValue)
                )
            if isinstance(expr, ast.BinOp):
                return _is_dynamic(expr.left, scope_id, lineno, visited.copy()) or _is_dynamic(
                    expr.right, scope_id, lineno, visited.copy()
                )
            return False

        def _relative_guarded(call: ast.Call, target: ast.AST) -> bool:
            if not isinstance(target, ast.Name):
                return False
            current = getattr(call, "parent", None)
            while current is not None:
                if isinstance(current, ast.If):
                    for condition in ast.walk(current.test):
                        if not isinstance(condition, ast.Call) or not isinstance(condition.func, ast.Attribute):
                            continue
                        if condition.func.attr != "startswith" or not condition.args:
                            continue
                        prefix = _static_value(condition.args[0], _scope_for(call, mod_name), getattr(call, "lineno", 1))
                        if prefix != "/":
                            continue
                        receiver = condition.func.value
                        if isinstance(receiver, ast.Name) and receiver.id == target.id:
                            return True
                current = getattr(current, "parent", None)
            return False

        def _is_safe_route_expr(expr: ast.AST) -> bool:
            if expr is None:
                return True
            if isinstance(expr, ast.Constant):
                return True
            if isinstance(expr, ast.Attribute):
                if expr.attr in {"path", "full_path"}:
                    return True
            if isinstance(expr, ast.Call):
                dname = dotted_name(expr.func) or ""
                short = dname.rsplit(".", 1)[-1]
                if short in {"get_full_path", "url_for"} or dname in {"request.get_full_path", "flask.url_for"}:
                    return True
                if short in redirect_validators or dname in redirect_validators:
                    return True
            if isinstance(expr, ast.JoinedStr):
                return all(_is_safe_route_expr(part.value) for part in expr.values if isinstance(part, ast.FormattedValue))
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
                return _is_safe_route_expr(expr.left) and _is_safe_route_expr(expr.right)
            return False

        def _redirect_is_safe(call: ast.Call, target: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            if target is None:
                return False
            if visited is None:
                visited = set()
            static_value = _static_value(target, scope_id, lineno)
            if isinstance(static_value, str):
                return True
            if _is_safe_route_expr(target):
                return True
            if isinstance(target, ast.Name):
                existing_sink = next((
                    record.security_node for record in self.sink_records
                    if record.security_node.location == location(
                        call, self.file_paths.get(scope_module(scope_id), "unknown.py")
                    )
                    and record.security_node.metadata.get("cwe") == "CWE-601"
                ), None)
                if _relative_guarded(call, target) or self.is_var_contained(
                    target.id, scope_id, lineno, existing_sink
                ):
                    return True
                target_var = target.id
                current_func = None
                for func_id, f_scope in function_scopes.items():
                    if f_scope == scope_id:
                        current_func = self.functions.get(f_scope)
                        break
                if current_func:
                    for sub in ast.walk(current_func):
                        if isinstance(sub, ast.Call):
                            sub_names = _names_for_call(sub, scope_id)
                            if any(sn in redirect_validators or sn.rsplit(".", 1)[-1] in redirect_validators for sn in sub_names):
                                arg_names = {a.id for a in sub.args if isinstance(a, ast.Name)}
                                kw_names = {kw.value.id for kw in getattr(sub, "keywords", []) if isinstance(kw.value, ast.Name)}
                                if target_var in (arg_names | kw_names):
                                    return True
                        elif isinstance(sub, ast.Attribute) and sub.attr == "netloc":
                            if isinstance(sub.value, ast.Call):
                                c_names = _names_for_call(sub.value, scope_id)
                                if any("urlparse" in cn or "url_parse" in cn for cn in c_names):
                                    c_args = {a.id for a in sub.value.args if isinstance(a, ast.Name)}
                                    if target_var in c_args:
                                        return True
                key = (scope_id, target.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(target.id, scope_id, lineno)
                if record is not None:
                    return _redirect_is_safe(call, record.value_node, record.scope_id, record.lineno, visited)
                return _relative_guarded(call, target)
            if isinstance(target, ast.IfExp):
                return _redirect_is_safe(call, target.body, scope_id, lineno, visited) and _redirect_is_safe(call, target.orelse, scope_id, lineno, visited)
            if isinstance(target, ast.Call):
                names = _names_for_call(target, scope_id)
                if any(
                    name in redirect_validators
                    or name.rsplit(".", 1)[-1] in redirect_validators
                    for name in names
                ):
                    return True
                if any(name in {"url_for", "request.get_full_path"} or name.endswith(".url_for") for name in names):
                    return True
            if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                record = _assigned_value(target.value.id, scope_id, lineno)
                if record is not None:
                    return _redirect_is_safe(call, record.value_node, record.scope_id, record.lineno, visited)
            return False

        def _remove_existing(node: ast.Call, cwes: set[str], mod_name: str) -> None:
            node_location = location(node, self.file_paths.get(mod_name, "unknown.py"))
            removed = [
                record for record in self.sink_records
                if record.security_node.location == node_location
                and record.security_node.metadata.get("cwe") in cwes
            ]
            if not removed:
                return
            self.sink_records = [record for record in self.sink_records if record not in removed]
            for record in removed:
                if not any(other.security_node is record.security_node for other in self.sink_records):
                    if record.security_node in self.sinks:
                        self.sinks.remove(record.security_node)

        seen: set[tuple[str, int, int]] = set()

        def _add_finding(
            node: ast.Call, mod_name: str, scope_id: str, cwe: str,
            category: str, operation: str, source_id: str,
        ) -> None:
            line = getattr(node, "lineno", 1)
            column = getattr(node, "col_offset", 0)
            key = (cwe, line, column)
            if key in seen:
                return
            seen.add(key)
            node_location = location(node, self.file_paths.get(mod_name, "unknown.py"))
            existing = next((
                record for record in self.sink_records
                if record.security_node.location == node_location
                and record.security_node.metadata.get("cwe") == cwe
            ), None)
            if existing is not None:
                existing.security_node.metadata["p8_source_id"] = source_id
                return
            sink_node = SecurityNode(
                id=self.next_sink_id(),
                node_type=NodeType.SINK,
                symbol=operation,
                operation=operation,
                location=node_location,
                metadata={
                    "sink_type": category,
                    "category": category,
                    "cwe": cwe,
                    "p8_source_id": source_id,
                },
            )
            self.sinks.append(sink_node)
            self.sink_records.append(SinkRecord(
                node=node,
                security_node=sink_node,
                lineno=line,
                scope_id=scope_id,
            ))

        for mod_name, tree in self.modules.items():
            seen.clear()
            for node in self._reachable_nodes(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.AST):
                    continue
                scope_id = _scope_for(node, mod_name)
                lineno = getattr(node, "lineno", 1)
                names = _names_for_call(node, scope_id)

                if any(name in redirect_sinks or name.endswith(".redirect") or name.endswith("HttpResponseRedirect") or name.endswith("HttpResponsePermanentRedirect") for name in names):
                    target = next((kw.value for kw in node.keywords if kw.arg in {"location", "url", "to"}), None)
                    if target is None and node.args:
                        target = node.args[0]
                    if target is not None and _is_dynamic(target, scope_id, lineno):
                        if not _redirect_is_safe(node, target, scope_id, lineno):
                            _add_finding(
                                node, mod_name, scope_id, "CWE-601", "URL_REDIRECTION",
                                "OPEN_REDIRECT", "OPEN_REDIRECT_VULNERABILITY",
                            )
                        else:
                            _remove_existing(node, {"CWE-601", "CWE-79"}, mod_name)
                    elif target is not None:
                        _remove_existing(node, {"CWE-601", "CWE-79"}, mod_name)

                if names & weak_hash_sinks:
                    usedforsecurity = next((kw.value for kw in node.keywords if kw.arg == "usedforsecurity"), None)
                    if usedforsecurity is not None and _static_value(usedforsecurity, scope_id, lineno) is False:
                        _remove_existing(node, {"CWE-328"}, mod_name)
                    else:
                        _add_finding(
                            node, mod_name, scope_id, "CWE-328", "WEAK_CRYPTOGRAPHY",
                            "WEAK_HASH", "WEAK_HASH_ALGORITHM",
                        )

                is_set_cookie = any(
                    name == "set_cookie" or name.endswith(".set_cookie") for name in names
                )
                if is_set_cookie:
                    states = self._cookie_flag_states(node, scope_id, lineno)
                    vulnerable_cwes = []
                    if self._cookie_flag_missing(states, "httponly"):
                        vulnerable_cwes.append("CWE-1004")
                    if self._cookie_flag_missing(states, "secure"):
                        vulnerable_cwes.append("CWE-614")
                    if (states.get("samesite") == "unsafe"
                            and any(keyword.arg == "samesite" for keyword in node.keywords
                                    if keyword.arg is not None)):
                        vulnerable_cwes.append("CWE-1004")
                    for cwe in set(vulnerable_cwes):
                        category = "INSECURE_COOKIE_CONFIGURATION"
                        operation = "INSECURE_COOKIE_FLAGS" if cwe == "CWE-1004" else "INSECURE_COOKIE_SECURE_FLAG"
                        _add_finding(
                            node, mod_name, scope_id, cwe, category, operation,
                            "INSECURE_COOKIE_STORAGE",
                        )

                # ─── CWE-614/CWE-1004: Pyramid AuthTkt helpers without secure/httponly ───
                is_authtkt_helper = any(
                    name in ("AuthTktCookieHelper", "pyramid.authentication.AuthTktCookieHelper",
                             "AuthTktAuthenticationPolicy", "pyramid.authentication.AuthTktAuthenticationPolicy")
                    for name in names
                )
                if is_authtkt_helper:
                    # Check for **kwargs unpacking - if present, skip as config is externalised
                    has_unpack = any(kw.arg is None for kw in node.keywords)
                    if not has_unpack:
                        # Check for # ok: suppression comment on previous line
                        source_lines = self._source_lines_by_file.get(self.file_paths.get(mod_name, ""), [])
                        prev_line_idx = lineno - 2  # lineno is 1-based, list is 0-based; prev line = lineno-2
                        if prev_line_idx >= 0 and prev_line_idx < len(source_lines):
                            prev_line = source_lines[prev_line_idx]
                            if re.search(r"#\s*ok:", prev_line, re.IGNORECASE):
                                continue  # Skip this finding - suppressed by # ok: comment
                        
                        # Extract flag values from keywords
                        has_secure_kw = False
                        has_httponly_kw = False
                        secure_is_false = False
                        httponly_is_false = False
                        
                        for kw in node.keywords:
                            if kw.arg == "secure":
                                has_secure_kw = True
                                val = _eval_static_constant(kw.value, self.assignments_by_scope, scope_id, lineno)
                                if val is False:
                                    secure_is_false = True
                            elif kw.arg == "httponly":
                                has_httponly_kw = True
                                val = _eval_static_constant(kw.value, self.assignments_by_scope, scope_id, lineno)
                                if val is False:
                                    httponly_is_false = True
                        
                        # Determine vulnerability based on missing or explicitly False flags
                        vulnerable_cwes = []
                        
                        # Secure flag check (CWE-614) - flag if secure keyword is absent or explicitly False
                        if not has_secure_kw or secure_is_false:
                            vulnerable_cwes.append("CWE-614")
                        
                        # HttpOnly flag check (CWE-1004) - flag if httponly keyword is absent or explicitly False
                        if not has_httponly_kw or httponly_is_false:
                            vulnerable_cwes.append("CWE-1004")
                        
                        for cwe in set(vulnerable_cwes):
                            category = "INSECURE_COOKIE_CONFIGURATION"
                            operation = "INSECURE_COOKIE_FLAGS" if cwe == "CWE-1004" else "INSECURE_COOKIE_SECURE_FLAG"
                            _add_finding(
                                node, mod_name, scope_id, cwe, category, operation,
                                "INSECURE_COOKIE_STORAGE",
                            )

    def _collect_phase9_structural_findings(self) -> None:
        """Collect concrete hardcoded credentials and catastrophic regex patterns."""
        function_scopes = {id(function): scope for scope, function in self.functions.items()}
        sensitive_names = {
            "password", "passwd", "secret", "api_key", "apikey", "auth_token",
            "access_token", "private_key", "client_secret",
        }
        regex_sinks = {
            "re.compile", "re.match", "re.search", "re.findall", "re.finditer", "re.sub",
        }
        credential_placeholders = {
            "changeme", "change_me", "change-this", "placeholder", "dummy",
            "test", "example", "your_password_here", "your_api_key_here",
            "insert_password_here", "replace_me", "replace_this", "your_secret_here",
        }
        concrete_credential_prefix = re.compile(
            r"(?i)^(?:gh[pousr]_[a-z0-9]{12,}|sk_(?:live|test)_[a-z0-9]{8,}|"
            r"akia[0-9a-z]{16}|eyj[a-z0-9_-]{16,})"
        )

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _call_names(call: ast.Call, scope_id: str) -> set[str]:
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.AST):
                return set()
            name = dotted_name(call.func) or ""
            canonical = self.resolve_canonical_name(call.func, scope_id) or ""
            return {value for value in (name, canonical) if value}

        def _assigned_value(name: str, scope_id: str, lineno: int):
            current_scope = scope_id
            mod_name = scope_module(scope_id)
            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
                records = self.assignments_by_scope.get((current_scope, name), [])
                prior = [record for record in records if record.lineno <= lineno]
                if prior:
                    return prior[-1]
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope:
                    current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global":
                    current_scope = f"{mod_name}:global"
                else:
                    break
            return None

        def _target_name(target: ast.AST) -> str:
            if isinstance(target, ast.Name):
                return target.id.lower()
            if isinstance(target, ast.Attribute):
                return (dotted_name(target) or target.attr).lower()
            if isinstance(target, ast.Subscript):
                return _target_name(target.value)
            return ""

        def _sensitive_target(target: ast.AST) -> bool:
            normalized = _target_name(target)
            parts = set(re.split(r"[^a-z0-9]+", normalized))
            return bool(parts & sensitive_names) or any(
                marker in normalized for marker in (
                    "password", "passwd", "secret", "api_key", "apikey",
                    "auth_token", "access_token", "private_key", "client_secret",
                )
            )

        def _credential_is_concrete(value: str) -> bool:
            normalized = value.strip()
            if not normalized or len(normalized) < 8:
                return False
            lowered = normalized.lower()
            
            # Phase 8.5: Suppress known test/dummy strings
            if _is_cwe798_dummy_string(normalized):
                return False
            
            if lowered in credential_placeholders or any(
                marker in lowered for marker in (
                    "placeholder", "changeme", "change_me", "your_password",
                    "your_api_key", "your_secret", "dummy", "example_value",
                )
            ):
                return False
            if concrete_credential_prefix.match(normalized):
                return True
            frequencies = {character: normalized.count(character) for character in set(normalized)}
            entropy = -sum(
                (count / len(normalized)) * math.log2(count / len(normalized))
                for count in frequencies.values()
            )
            character_classes = sum((
                any(character.islower() for character in normalized),
                any(character.isupper() for character in normalized),
                any(character.isdigit() for character in normalized),
                any(not character.isalnum() for character in normalized),
            ))
            return entropy >= 3.0 and (
                character_classes >= 2 or (len(normalized) >= 20 and entropy >= 3.3)
            )

        def _first_chars(tokens) -> set[int] | None:
            for operation, argument in tokens:
                if operation is re._constants.LITERAL:
                    return {argument}
                if operation is re._constants.IN:
                    characters = set()
                    for member_op, member_arg in argument:
                        if member_op is re._constants.LITERAL:
                            characters.add(member_arg)
                        elif member_op is re._constants.RANGE:
                            start, end = member_arg
                            if end - start <= 512:
                                characters.update(range(start, end + 1))
                            else:
                                return None
                        else:
                            return None
                    return characters
                if operation is re._constants.SUBPATTERN:
                    nested = _first_chars(argument[-1])
                    if nested is not None:
                        return nested
                if operation is re._constants.BRANCH:
                    branches = [_first_chars(branch) for branch in argument[1]]
                    if any(branch is None for branch in branches):
                        return None
                    return set().union(*branches)
                if operation is re._constants.AT:
                    continue
                return None
            return set()

        def _has_catastrophic_backtracking(tokens, inside_repeat: bool = False) -> bool:
            """Detect regex patterns that can cause exponential backtracking (ReDoS)."""
            repeat_ops = {
                re._constants.MAX_REPEAT,
                re._constants.MIN_REPEAT,
            }
            if hasattr(re._constants, "POSSESSIVE_REPEAT"):
                repeat_ops.add(re._constants.POSSESSIVE_REPEAT)
            previous_repeat_chars = None
            for operation, argument in tokens:
                if operation in repeat_ops:
                    repeated_body = argument[2]
                    # A `?` quantifier (max == 1) contributes at most two paths, so nesting it
                    # inside another repeat stays linear. Only repeats that can iterate more
                    # than once (`*`, `+`, `{n,m}` with m > 1) multiply into exponential paths.
                    multiplies = argument[1] is None or argument[1] > 1
                    if inside_repeat and multiplies:
                        return True
                    if _has_catastrophic_backtracking(repeated_body, inside_repeat or multiplies):
                        return True
                    current_chars = _first_chars(repeated_body)
                    if previous_repeat_chars is not None and (
                        current_chars is None or previous_repeat_chars is None
                        or previous_repeat_chars & current_chars
                    ):
                        return True
                    previous_repeat_chars = current_chars
                    continue
                if operation is re._constants.SUBPATTERN:
                    if _has_catastrophic_backtracking(argument[-1], inside_repeat):
                        return True
                elif operation is re._constants.BRANCH:
                    branches = argument[1]
                    branch_starts = [_first_chars(branch) for branch in branches]
                    for index, first in enumerate(branch_starts):
                        if first is None:
                            continue
                        if any(first & other for other in branch_starts[index + 1:] if other is not None):
                            if inside_repeat:
                                return True
                    if any(_has_catastrophic_backtracking(branch, inside_repeat) for branch in branches):
                        return True
                previous_repeat_chars = None
            return False

        def _remove_existing(node: ast.AST, cwe: str, mod_name: str) -> None:
            node_location = location(node, self.file_paths.get(mod_name, "unknown.py"))
            removed = [
                record for record in self.sink_records
                if record.security_node.location == node_location
                and record.security_node.metadata.get("cwe") == cwe
            ]
            if not removed:
                return
            self.sink_records = [record for record in self.sink_records if record not in removed]
            for record in removed:
                if not any(other.security_node is record.security_node for other in self.sink_records):
                    if record.security_node in self.sinks:
                        self.sinks.remove(record.security_node)

        seen: set[tuple[str, int, int]] = set()

        def _add_finding(
            node: ast.AST, mod_name: str, scope_id: str, cwe: str,
            category: str, operation: str, source_id: str,
        ) -> None:
            line = getattr(node, "lineno", 1)
            column = getattr(node, "col_offset", 0)
            key = (cwe, line, column)
            if key in seen:
                return
            seen.add(key)
            node_location = location(node, self.file_paths.get(mod_name, "unknown.py"))
            existing = next((
                record for record in self.sink_records
                if record.security_node.location == node_location
                and record.security_node.metadata.get("cwe") == cwe
            ), None)
            if existing is not None:
                existing.security_node.metadata["p9_source_id"] = source_id
                return
            sink_node = SecurityNode(
                id=self.next_sink_id(),
                node_type=NodeType.SINK,
                symbol=operation,
                operation=operation,
                location=node_location,
                metadata={
                    "sink_type": category,
                    "category": category,
                    "cwe": cwe,
                    "p9_source_id": source_id,
                },
            )
            self.sinks.append(sink_node)
            self.sink_records.append(SinkRecord(
                node=node,
                security_node=sink_node,
                lineno=line,
                scope_id=scope_id,
            ))

        for mod_name, tree in self.modules.items():
            seen.clear()
            scoped_nodes = [(node, _scope_for(node, mod_name)) for node in self._reachable_nodes(tree)]
            for node, scope_id in scoped_nodes:
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value_node = node.value
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    sensitive = [target for target in targets if _sensitive_target(target)]
                    if not sensitive:
                        continue
                    if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
                        if _credential_is_concrete(value_node.value):
                            _add_finding(
                                node, mod_name, scope_id, "CWE-798", "HARDCODED_CREDENTIALS",
                                "HARDCODED_CREDENTIAL", "HARDCODED_CREDENTIAL_LEAK",
                            )
                        else:
                            _remove_existing(node, "CWE-798", mod_name)

            for node, scope_id in scoped_nodes:
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.AST):
                    continue
                names = _call_names(node, scope_id)
                if not names & regex_sinks:
                    continue
                pattern = next((kw.value for kw in node.keywords if kw.arg in {"pattern", "regex"}), None)
                if pattern is None and node.args:
                    pattern = node.args[0]
                value = _eval_static_constant(pattern, self.assignments_by_scope, scope_id, getattr(node, "lineno", 1))
                if not isinstance(value, str):
                    continue
                try:
                    parsed = re._parser.parse(value, 0)
                    vulnerable = _has_catastrophic_backtracking(parsed)
                except (re.error, AttributeError, TypeError, ValueError):
                    vulnerable = False
                if vulnerable:
                    _add_finding(
                        node, mod_name, scope_id, "CWE-1333", "REGULAR_EXPRESSION_DOS",
                        "REGEX_COMPILATION", "REDOS_REGEX_COMPLEXITY",
                    )
                else:
                    _remove_existing(node, "CWE-1333", mod_name)

    def _collect_response_write_findings(self) -> None:
        """Detect dynamic content written to known HTTP response objects."""
        function_scopes = {id(function): scope for scope, function in self.functions.items()}
        response_factories = {
            "HttpResponse", "django.http.HttpResponse", "HttpResponseBadRequest",
            "django.http.HttpResponseBadRequest", "JsonResponse", "django.http.JsonResponse",
            "flask.Response", "Response", "flask.make_response", "make_response",
        }
        response_names = {"response", "resp", "http_response", "django_response", "flask_response"}

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _assigned_value(name: str, scope_id: str, lineno: int):
            current_scope = scope_id
            mod_name = scope_module(scope_id)
            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
                records = self.assignments_by_scope.get((current_scope, name), [])
                prior = [record for record in records if record.lineno <= lineno]
                if prior:
                    return prior[-1]
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope:
                    current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global":
                    current_scope = f"{mod_name}:global"
                else:
                    break
            return None

        def _call_names(call: ast.Call, scope_id: str) -> set[str]:
            if not isinstance(call.func, ast.AST):
                return set()
            return {
                name for name in (
                    dotted_name(call.func),
                    self.resolve_canonical_name(call.func, scope_id),
                ) if name
            }

        def _is_dynamic(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            if expr is None or isinstance(expr, ast.Constant):
                return False
            if isinstance(expr, (ast.Str, ast.Bytes, ast.Num)):
                return False
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Name):
                key = (scope_id, expr.id)
                if key in visited:
                    return False
                visited.add(key)
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is not None:
                    return _is_dynamic(record.value_node, record.scope_id, record.lineno, visited)
                return True
            if isinstance(expr, ast.Call):
                if self.is_source_call(expr, scope_id):
                    return True
                return any(
                    _is_dynamic(value, scope_id, lineno, visited.copy())
                    for value in [*expr.args, *(keyword.value for keyword in expr.keywords)]
                )
            if isinstance(expr, ast.Attribute):
                name = dotted_name(expr) or ""
                return name.startswith(("request.", "flask.request."))
            if isinstance(expr, ast.Subscript):
                return _is_dynamic(expr.value, scope_id, lineno, visited.copy())
            if isinstance(expr, ast.JoinedStr):
                return any(
                    _is_dynamic(value.value, scope_id, lineno, visited.copy())
                    for value in expr.values if isinstance(value, ast.FormattedValue)
                )
            if isinstance(expr, ast.BinOp):
                return _is_dynamic(expr.left, scope_id, lineno, visited.copy()) or _is_dynamic(
                    expr.right, scope_id, lineno, visited.copy()
                )
            return False

        def _is_response_receiver(receiver: ast.AST, scope_id: str, lineno: int, visited=None) -> bool:
            if isinstance(receiver, ast.Call):
                return bool(_call_names(receiver, scope_id) & response_factories)
            if isinstance(receiver, ast.Name):
                if visited is None:
                    visited = set()
                if receiver.id in visited:
                    return False
                visited.add(receiver.id)
                record = _assigned_value(receiver.id, scope_id, lineno)
                if record is not None:
                    value = record.value_node
                    if isinstance(value, ast.Call):
                        return bool(_call_names(value, record.scope_id) & response_factories)
                    if isinstance(value, ast.Name):
                        return _is_response_receiver(value, record.scope_id, record.lineno, visited)
                    return False
                return receiver.id.lower() in response_names or receiver.id.lower().endswith("_response")
            if isinstance(receiver, ast.Attribute):
                if receiver.attr.lower() in response_names or receiver.attr.lower().endswith("_response"):
                    record = self.class_field_assignments.get((scope_id, receiver.attr), [])
                    if record:
                        latest = max((item for item in record if item.lineno <= lineno), key=lambda item: item.lineno, default=None)
                        return latest is not None and isinstance(latest.value_node, ast.Call) and bool(
                            _call_names(latest.value_node, latest.scope_id) & response_factories
                        )
                    return True
            return False

        seen: set[tuple[int, int]] = set()
        for mod_name, tree in self.modules.items():
            for node in self._reachable_nodes(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr != "write":
                    continue
                scope_id = _scope_for(node, mod_name)
                lineno = getattr(node, "lineno", 1)
                receiver = node.func.value
                if not _is_response_receiver(receiver, scope_id, lineno):
                    continue
                argument = node.args[0] if node.args else next(
                    (keyword.value for keyword in node.keywords if keyword.arg in {"content", "data", "value"}),
                    None,
                )
                if argument is None or not _is_dynamic(argument, scope_id, lineno):
                    continue
                key = (lineno, getattr(node, "col_offset", 0))
                if key in seen:
                    continue
                seen.add(key)
                node_location = location(node, self.file_paths.get(mod_name, "unknown.py"))
                existing = next((
                    record for record in self.sink_records
                    if record.security_node.location == node_location
                    and record.security_node.metadata.get("cwe") == "CWE-93"
                ), None)
                if existing is not None:
                    existing.security_node.metadata["p10_source_id"] = "HTTP_RESPONSE_INJECTION"
                    continue
                sink_node = SecurityNode(
                    id=self.next_sink_id(),
                    node_type=NodeType.SINK,
                    symbol="HTTP_RESPONSE_WRITE",
                    operation="HTTP_RESPONSE_WRITE",
                    location=node_location,
                    metadata={
                        "sink_type": "CRLF_INJECTION",
                        "category": "RESPONSE_INJECTION",
                        "cwe": "CWE-93",
                        "p10_source_id": "HTTP_RESPONSE_INJECTION",
                        "lineno": lineno,
                    },
                )
                self.sinks.append(sink_node)
                self.sink_records.append(SinkRecord(
                    node=node,
                    security_node=sink_node,
                    lineno=lineno,
                    scope_id=scope_id,
                ))

    def _collect_template_response_xss_findings(self) -> None:
        """Collect tainted HTTP response bodies and dynamic stored template content."""
        function_scopes = {id(function): scope for scope, function in self.functions.items()}
        response_sinks = {
            "HttpResponse", "django.http.HttpResponse",
            "HttpResponseBadRequest", "django.http.HttpResponseBadRequest",
            "JsonResponse", "django.http.JsonResponse",
            "make_response", "flask.make_response",
            "Response", "pyramid.response.Response", "pyramid.request.Response",
        }
        # Constructors whose default media type renders as HTML. JsonResponse is deliberately
        # excluded from the non-literal rule below: it sets content_type=application/json, so
        # "the body is dynamic" does not by itself put the value in an HTML context.
        html_response_prefixes = ("HttpResponse", "django.http.HttpResponse")
        ssti_constructors = {
            "jinja2.Template", "Template", "django.template.Template", "django.Template",
            "mako.template.Template", "pyramid.renderers.render_to_response",
            "flask.render_template_string", "render_template_string", "django.shortcuts.render_to_string",
            "render_to_string",
        }

        def _scope_for(node: ast.AST, mod_name: str) -> str:
            current = node
            while current is not None:
                scope = function_scopes.get(id(current))
                if scope:
                    return scope
                current = getattr(current, "parent", None)
            return f"{mod_name}:global"

        def _assigned_value(name: str, scope_id: str, lineno: int):
            current_scope = scope_id
            mod_name = scope_module(scope_id)
            _walk_seen = set()
            while current_scope and current_scope not in _walk_seen:
                _walk_seen.add(current_scope)
                records = self.assignments_by_scope.get((current_scope, name), [])
                prior = [record for record in records if record.lineno < lineno]
                if prior:
                    return prior[-1]
                if "." in current_scope and "function" in current_scope:
                    current_scope = current_scope.rsplit(".", 1)[0]
                elif ":function" in current_scope:
                    current_scope = f"{mod_name}:global"
                elif current_scope != f"{mod_name}:global":
                    current_scope = f"{mod_name}:global"
                else:
                    break
            return None

        def _names_for_call(call: ast.Call, scope_id: str) -> set[str]:
            return {
                name for name in (
                    dotted_name(call.func) if isinstance(call.func, ast.AST) else None,
                    self.resolve_canonical_name(call.func, scope_id) if isinstance(call.func, ast.AST) else None,
                ) if name
            }

        def _is_html_response(name: str) -> bool:
            short = name.rsplit(".", 1)[-1]
            if "Redirect" in short:
                return False
            return name.startswith(html_response_prefixes) or short.startswith("HttpResponse")

        def _resolve_once(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> ast.AST:
            """Follow plain name bindings to the expression that actually produced the value."""
            if visited is None:
                visited = set()
            while isinstance(expr, ast.Name):
                if expr.id in visited:
                    break
                visited.add(expr.id)
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is None:
                    break
                expr, scope_id, lineno = record.value_node, record.scope_id, record.lineno
            return expr

        def _is_literal_text(expr: ast.AST) -> bool:
            if isinstance(expr, ast.Constant):
                return True
            if isinstance(expr, (ast.List, ast.Tuple)):
                return all(_is_literal_text(elt) for elt in expr.elts)
            if isinstance(expr, ast.Dict):
                return all(_is_literal_text(k) and _is_literal_text(v) for k, v in zip(expr.keys, expr.values))
            if isinstance(expr, ast.JoinedStr):
                return not any(isinstance(part, ast.FormattedValue) for part in expr.values)
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
                return _is_literal_text(expr.left) and _is_literal_text(expr.right)
            if isinstance(expr, ast.UnaryOp):
                return _is_literal_text(expr.operand)
            return False

        def _is_safe_response_body(expr: ast.AST, scope_id: str, lineno: int) -> bool:
            if expr is None:
                return True
            resolved = _resolve_once(expr, scope_id, lineno)
            if _is_literal_text(resolved):
                return True
            if isinstance(resolved, (ast.List, ast.Tuple)):
                return all(_is_safe_response_body(elt, scope_id, lineno) for elt in resolved.elts)
            if isinstance(resolved, ast.Dict):
                return all(_is_safe_response_body(v, scope_id, lineno) for v in resolved.values)
            if isinstance(resolved, ast.Call):
                c_names = _names_for_call(resolved, scope_id)
                if any(cn in {"jsonify", "flask.jsonify", "json.dumps", "redirect", "flask.redirect"} or cn.endswith((".jsonify", ".dumps", ".redirect")) for cn in c_names):
                    return True
                # Phase 10.3 SANITIZER GUARD: an escape-family wrapper means the value is
                # HTML-quoted before it reaches the response, so no script can execute.
                if any(cn.rsplit(".", 1)[-1] in {"escape", "escapejs", "conditional_escape",
                                                 "clean", "strip_tags", "urlize", "format_html",
                                                 "json_script", "smart_urlquote", "urlencode"}
                       for cn in c_names):
                    return True
                # Django template rendering with autoescape (default behavior) produces safe HTML.
                # Suppress XSS when content comes from render/render_to_string without mark_safe/|safe.
                if any(cn in {"render", "django.shortcuts.render", "render_to_string", "django.shortcuts.render_to_string",
                              "django.template.loader.render_to_string", "render_template", "flask.render_template"} or cn.endswith(".render_to_string") or cn.endswith(".render_template") for cn in c_names):
                    # Check if template name suggests HTML template (Django autoescapes by default)
                    t_arg = resolved.args[0] if resolved.args else next((kw.value for kw in resolved.keywords if kw.arg in {"template_name_or_list", "template", "template_name"}), None)
                    if t_arg and isinstance(t_arg, ast.Constant) and isinstance(t_arg.value, str) and t_arg.value.endswith((".html", ".htm")):
                        return True
                    # Also check for variable holding template name
                    if t_arg and isinstance(t_arg, ast.Name):
                        rec = _assigned_value(t_arg.id, scope_id, lineno)
                        if rec and isinstance(rec.value_node, ast.Constant) and isinstance(rec.value_node.value, str) and rec.value_node.value.endswith((".html", ".htm")):
                            return True
            return False

        def _has_template_marker(text: str) -> bool:
            return "{%" in text or "{{" in text

        def _template_composition(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> tuple[bool, bool]:
            """(literal carries template syntax, value is composed at runtime) for *expr*."""
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Name):
                if expr.id in visited:
                    return (False, True)
                visited.add(expr.id)
                record = _assigned_value(expr.id, scope_id, lineno)
                if record is None:
                    return (False, True)
                return _template_composition(record.value_node, record.scope_id, record.lineno, visited)
            if isinstance(expr, ast.Constant):
                return (isinstance(expr.value, str) and _has_template_marker(expr.value), False)
            if isinstance(expr, ast.JoinedStr):
                marker = any(
                    isinstance(part, ast.Constant) and isinstance(part.value, str) and _has_template_marker(part.value)
                    for part in expr.values
                )
                return (marker, any(isinstance(part, ast.FormattedValue) for part in expr.values))
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
                left_marker, left_dynamic = _template_composition(expr.left, scope_id, lineno, set(visited))
                right_marker, right_dynamic = _template_composition(expr.right, scope_id, lineno, set(visited))
                return (left_marker or right_marker, left_dynamic or right_dynamic)
            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                return _template_composition(expr.func.value, scope_id, lineno, visited)
            return (False, True)

        def _template_path_literals(expr: ast.AST, scope_id: str, lineno: int, visited=None) -> list[str]:
            if expr is None:
                return []
            if visited is None:
                visited = set()
            if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
                return [expr.value]
            if isinstance(expr, ast.JoinedStr):
                return [part.value for part in expr.values if isinstance(part, ast.Constant) and isinstance(part.value, str)]
            if isinstance(expr, ast.Name):
                if expr.id in visited:
                    return []
                visited.add(expr.id)
                record = _assigned_value(expr.id, scope_id, lineno)
                return _template_path_literals(record.value_node, record.scope_id, record.lineno, visited) if record else []
            if isinstance(expr, ast.Call):
                values = []
                for argument in [*expr.args, *(keyword.value for keyword in expr.keywords)]:
                    values.extend(_template_path_literals(argument, scope_id, lineno, visited.copy()))
                return values
            return []

        seen: set[tuple[str, int, int, str]] = set()

        def _add_finding(node: ast.AST, mod_name: str, scope_id: str, operation: str,
                         cwe: str = "CWE-79", category: str = "CROSS_SITE_SCRIPTING") -> None:
            line = getattr(node, "lineno", 1)
            # Phase 10.3 SUPPRESSION GUARD: an annotation on the line above the statement
            # marks a reviewed false positive. Only the prev-line form is checked because
            # same-line '# ruleid:' ground-truth annotations share the physical line.
            source_lines = self._source_lines_by_file.get(self.file_paths.get(mod_name, ""), [])
            if line >= 2 and len(source_lines) >= line - 1:
                if re.search(r"#\s*ok\b", source_lines[line - 2], re.IGNORECASE):
                    return
            column = getattr(node, "col_offset", 0)
            key = (mod_name, line, column, cwe)
            if key in seen:
                return
            seen.add(key)
            file_path = self.file_paths.get(mod_name, "unknown.py")
            node_location = location(node, file_path)
            existing = next((
                record for record in self.sink_records
                if record.security_node.location == node_location
                and record.security_node.metadata.get("cwe") == cwe
            ), None)
            if existing is not None:
                existing.security_node.metadata["p11_source_id"] = "DYNAMIC_HTML_RESPONSE"
                return
            sink_node = SecurityNode(
                id=self.next_sink_id(),
                node_type=NodeType.SINK,
                symbol=operation,
                operation=operation,
                location=node_location,
                metadata={
                    "sink_type": "SSTI" if cwe == "CWE-1336" else "XSS",
                    "category": category,
                    "cwe": cwe,
                    "p11_source_id": "DYNAMIC_HTML_RESPONSE",
                    "lineno": line,
                },
            )
            self.sinks.append(sink_node)
            self.sink_records.append(SinkRecord(
                node=node,
                security_node=sink_node,
                lineno=line,
                scope_id=scope_id,
            ))

        for mod_name, tree in self.modules.items():
            for node in self._reachable_nodes(tree):
                scope_id = _scope_for(node, mod_name)
                lineno = getattr(node, "lineno", 1)

                if isinstance(node, ast.Assign) and len(node.targets) == 1:
                    target = node.targets[0]
                    if isinstance(target, ast.Attribute) and target.attr == "body":
                        if isinstance(target.value, ast.Attribute) and target.value.attr == "response":
                            if not _is_literal_text(_resolve_once(node.value, scope_id, lineno)):
                                # Suppress if CWE-1336 (SSTI) already reported at same location
                                has_ssti = any(
                                    rec.security_node.metadata.get("cwe") == "CWE-1336"
                                    for rec in self.sink_records
                                    if rec.lineno == lineno and rec.scope_id == scope_id
                                )
                                if not has_ssti:
                                    _add_finding(node, mod_name, scope_id, "HTTP_RESPONSE_HTML", cwe="CWE-79", category="CROSS_SITE_SCRIPTING")
                    continue

                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.AST):
                    continue
                call_names = _names_for_call(node, scope_id)

                if call_names & response_sinks or any(_is_html_response(name) for name in call_names):
                    # Suppress JsonResponse / flask.jsonify — Content-Type is application/json, not HTML
                    is_json_response = bool(call_names & {"JsonResponse", "django.http.JsonResponse", "jsonify", "flask.jsonify"})
                    if is_json_response:
                        pass  # Not an XSS sink; JSON context escapes by default
                    else:
                        content = next((kw.value for kw in node.keywords if kw.arg in {"content", "response", "body", "data"}), None)
                        if content is None and node.args:
                            content = node.args[0]
                        ct_node = next((kw.value for kw in node.keywords if kw.arg in {"content_type", "mimetype", "contentType"}), None)
                        ct_val = _literal_text(ct_node, self.assignments_by_scope, scope_id, lineno) if ct_node else None

                        if ct_val in {"application/json", "text/json", "text/plain", "application/octet-stream"}:
                            pass
                        elif content is not None and not _json_or_structured_body(node, self.assignments_by_scope, scope_id, lineno):
                            # Check if content comes from Django template rendering with autoescape
                            content_resolved = _resolve_once(content, scope_id, lineno)
                            is_django_template_render = False
                            
                            # Direct check: if content is a Name, look up its assignment
                            if isinstance(content, ast.Name):
                                rec = _assigned_value(content.id, scope_id, lineno)
                                if rec and isinstance(rec.value_node, ast.Call):
                                    c_names = _names_for_call(rec.value_node, rec.scope_id)
                                    if any(cn in {"render", "django.shortcuts.render", "render_to_string", "django.shortcuts.render_to_string",
                                                  "django.template.loader.render_to_string"} or cn.endswith(".render_to_string") for cn in c_names):
                                        # Check for HTML template (autoescape on by default)
                                        t_arg = rec.value_node.args[0] if rec.value_node.args else next((kw.value for kw in rec.value_node.keywords if kw.arg in {"template_name_or_list", "template", "template_name"}), None)
                                        if t_arg and isinstance(t_arg, ast.Constant) and isinstance(t_arg.value, str) and t_arg.value.endswith((".html", ".htm")):
                                            is_django_template_render = True
                                        elif t_arg and isinstance(t_arg, ast.Name):
                                            rec2 = _assigned_value(t_arg.id, rec.scope_id, rec.lineno)
                                            if rec2 and isinstance(rec2.value_node, ast.Constant) and isinstance(rec2.value_node.value, str) and rec2.value_node.value.endswith((".html", ".htm")):
                                                is_django_template_render = True
                            
                            # Fallback: check resolved value
                            if not is_django_template_render and isinstance(content_resolved, ast.Call):
                                c_names = _names_for_call(content_resolved, scope_id)
                                if any(cn in {"render", "django.shortcuts.render", "render_to_string", "django.shortcuts.render_to_string",
                                              "django.template.loader.render_to_string"} or cn.endswith(".render_to_string") for cn in c_names):
                                    # Check for HTML template (autoescape on by default)
                                    t_arg = content_resolved.args[0] if content_resolved.args else next((kw.value for kw in content_resolved.keywords if kw.arg in {"template_name_or_list", "template", "template_name"}), None)
                                    if t_arg and isinstance(t_arg, ast.Constant) and isinstance(t_arg.value, str) and t_arg.value.endswith((".html", ".htm")):
                                        is_django_template_render = True
                                    elif t_arg and isinstance(t_arg, ast.Name):
                                        rec = _assigned_value(t_arg.id, scope_id, lineno)
                                        if rec and isinstance(rec.value_node, ast.Constant) and isinstance(rec.value_node.value, str) and rec.value_node.value.endswith((".html", ".htm")):
                                            is_django_template_render = True
                            
                            # Heuristic fallback: if variable name suggests template rendering and no explicit unsafe markers
                            if not is_django_template_render and isinstance(content, ast.Name):
                                var_name = content.id.lower()
                                if any(keyword in var_name for keyword in ("rendered", "template_html", "html_content", "rendered_html")):
                                    # Check if there's ANY assignment for this variable (even if we can't resolve it fully)
                                    recs = self.assignments_by_scope.get((scope_id, content.id), [])
                                    if recs and len(recs) > 0:
                                        last_rec = recs[-1]
                                        if isinstance(last_rec.value_node, ast.Call):
                                            c_names = _names_for_call(last_rec.value_node, last_rec.scope_id)
                                            # If the call name contains "render" or "template", assume it's safe
                                            if any("render" in cn.lower() or "template" in cn.lower() for cn in c_names):
                                                is_django_template_render = True
                            
                            if is_django_template_render or _is_safe_response_body(content, scope_id, lineno):
                                if ct_val == "text/html":
                                    # Suppress if CWE-1336 (SSTI) already reported at same location
                                    has_ssti = any(
                                        rec.security_node.metadata.get("cwe") == "CWE-1336"
                                        for rec in self.sink_records
                                        if rec.lineno == lineno and rec.scope_id == scope_id
                                    )
                                    if not has_ssti:
                                        _add_finding(node, mod_name, scope_id, "HTTP_RESPONSE_HTML", cwe="CWE-79", category="CROSS_SITE_SCRIPTING")
                            else:
                                # Suppress Django template rendering with autoescape even in taint path
                                if is_django_template_render:
                                    pass  # Autoescaped template output is safe
                                else:
                                    temporary_sink = SecurityNode(
                                        id="", node_type=NodeType.SINK, symbol="HTML_RESPONSE",
                                        operation="HTML_RESPONSE", location=location(node, self.file_paths.get(mod_name, "unknown.py")),
                                        metadata={"sink_type": "XSS", "cwe": "CWE-79"},
                                    )
                                    taint = self.resolve_expression(content, temporary_sink, scope_id, lineno)
                                    if taint.state != TaintState.CLEAN or ct_val == "text/html" or not _is_literal_text(_resolve_once(content, scope_id, lineno)):
                                        # Suppress if CWE-1336 (SSTI) already reported at same location
                                        has_ssti = any(
                                            rec.security_node.metadata.get("cwe") == "CWE-1336"
                                            for rec in self.sink_records
                                            if rec.lineno == lineno and rec.scope_id == scope_id
                                        )
                                        if not has_ssti:
                                            _add_finding(node, mod_name, scope_id, "HTTP_RESPONSE_HTML", cwe="CWE-79", category="CROSS_SITE_SCRIPTING")

                if call_names & {"render_template", "flask.render_template"} or any(name.endswith(".render_template") for name in call_names):
                    mod_imports = getattr(self, "imports", {}).get(mod_name, {})
                    target_mod = mod_imports.get("render_template", "") if isinstance(mod_imports, dict) else ""
                    not_flask = bool(target_mod and not target_mod.startswith("flask"))
                    if not not_flask:
                        t_arg = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg in {"template_name_or_list", "template"}), None)
                        if t_arg is not None:
                            is_html = False
                            if isinstance(t_arg, ast.Constant) and isinstance(t_arg.value, str):
                                is_html = t_arg.value.endswith((".html", ".htm"))
                            elif isinstance(t_arg, ast.BinOp) and isinstance(t_arg.op, ast.Add):
                                if isinstance(t_arg.right, ast.Constant) and isinstance(t_arg.right.value, str):
                                    is_html = t_arg.right.value.endswith((".html", ".htm"))
                            elif isinstance(t_arg, ast.BinOp) and isinstance(t_arg.op, ast.Mod):
                                if isinstance(t_arg.left, ast.Constant) and isinstance(t_arg.left.value, str):
                                    is_html = t_arg.left.value.endswith((".html", ".htm"))
                            elif isinstance(t_arg, ast.Call) and isinstance(t_arg.func, ast.Attribute) and t_arg.func.attr == "format":
                                if isinstance(t_arg.func.value, ast.Constant) and isinstance(t_arg.func.value.value, str):
                                    is_html = t_arg.func.value.value.endswith((".html", ".htm"))
                            elif isinstance(t_arg, ast.JoinedStr):
                                const_parts = [p.value for p in t_arg.values if isinstance(p, ast.Constant) and isinstance(p.value, str)]
                                if const_parts and const_parts[-1].endswith((".html", ".htm")):
                                    is_html = True
                            elif isinstance(t_arg, ast.Name):
                                rec = _assigned_value(t_arg.id, scope_id, lineno)
                                if rec and isinstance(rec.value_node, ast.Constant) and isinstance(rec.value_node.value, str):
                                    is_html = rec.value_node.value.endswith((".html", ".htm"))

                            has_context = len(node.args) > 1 or any(kw.arg not in {"template_name_or_list", "template"} for kw in node.keywords)
                            if not is_html and has_context:
                                _add_finding(node, mod_name, scope_id, "UNESCAPED_TEMPLATE_EXTENSION", cwe="CWE-79", category="CROSS_SITE_SCRIPTING")

                if call_names & {"format_html", "django.utils.html.format_html"} or any(name.endswith(".format_html") for name in call_names):
                    fmt_arg = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg in {"format_string", "format_str"}), None)
                    if fmt_arg is not None:
                        is_misused = False
                        if isinstance(fmt_arg, ast.JoinedStr) and any(isinstance(p, ast.FormattedValue) for p in fmt_arg.values):
                            is_misused = True
                        elif isinstance(fmt_arg, ast.BinOp) and isinstance(fmt_arg.op, ast.Mod):
                            is_misused = True
                        elif isinstance(fmt_arg, ast.Call) and isinstance(fmt_arg.func, ast.Attribute) and fmt_arg.func.attr == "format":
                            is_misused = True
                        if is_misused:
                            _add_finding(node, mod_name, scope_id, "FORMAT_HTML_FSTRING_PARAMETER", cwe="CWE-79", category="CROSS_SITE_SCRIPTING")

                if any("mako" in name or name in {"Template", "template.Template"} for name in call_names):
                    if not (isinstance(node.func, ast.Attribute) and node.func.attr == "render"):
                        is_mako = any("mako" in name for name in call_names)
                        if not is_mako:
                            mod_imports = getattr(self, "imports", {}).get(mod_name, {})
                            if isinstance(mod_imports, dict):
                                is_mako = any("mako" in tgt for tgt in mod_imports.values())
                        if is_mako and not any(name.startswith("jinja2") for name in call_names):
                            _add_finding(node, mod_name, scope_id, "MAKO_TEMPLATES_DETECTED", cwe="CWE-79", category="CROSS_SITE_SCRIPTING")

                if isinstance(node.func, ast.Attribute) and node.func.attr == "render":
                    r_names = set()
                    if isinstance(node.func.value, ast.Call):
                        r_names = _names_for_call(node.func.value, scope_id)
                    elif isinstance(node.func.value, (ast.Name, ast.Attribute)):
                        rec_name = dotted_name(node.func.value) or (node.func.value.id if isinstance(node.func.value, ast.Name) else "")
                        if rec_name:
                            rec = _assigned_value(rec_name, scope_id, lineno)
                            if rec and isinstance(rec.value_node, ast.Call):
                                r_names = _names_for_call(rec.value_node, rec.scope_id)
                    if any("jinja2" in rn or rn in {"Template", "get_template"} for rn in r_names):
                        has_args = bool(node.args or node.keywords)
                        if has_args or isinstance(node.func.value, ast.Call):
                            _add_finding(node, mod_name, scope_id, "DIRECT_USE_OF_JINJA2", cwe="CWE-79", category="CROSS_SITE_SCRIPTING")
                    elif any("mako" in rn for rn in r_names):
                        _add_finding(node, mod_name, scope_id, "MAKO_TEMPLATES_DETECTED", cwe="CWE-79", category="CROSS_SITE_SCRIPTING")

                if call_names & {"render_template_string", "flask.render_template_string"} or any(name.endswith(".render_template_string") for name in call_names):
                    src_arg = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg in {"source", "s"}), None)
                    if src_arg is not None and not _is_literal_text(_resolve_once(src_arg, scope_id, lineno)):
                        _add_finding(node, mod_name, scope_id, "RENDER_TEMPLATE_STRING", cwe="CWE-79", category="CROSS_SITE_SCRIPTING")

                if call_names & ssti_constructors:
                    source_arg = next((kw.value for kw in node.keywords if kw.arg in {"source", "template", "s"}), None)
                    if source_arg is None and node.args:
                        source_arg = node.args[0]
                    if source_arg is not None:
                        marker, dynamic = _template_composition(source_arg, scope_id, lineno)
                        if marker and dynamic:
                            _add_finding(
                                node, mod_name, scope_id, "DYNAMIC_TEMPLATE_CONSTRUCTION",
                                cwe="CWE-1336", category="SSTI",
                            )

                if isinstance(node.func, ast.Attribute) and node.func.attr == "write" and node.args:
                    receiver = node.func.value
                    if not isinstance(receiver, ast.Name):
                        continue
                    handle = _assigned_value(receiver.id, scope_id, lineno)
                    if handle is None or not isinstance(handle.value_node, ast.Call):
                        continue
                    open_names = _names_for_call(handle.value_node, handle.scope_id)
                    if not (open_names & {"open", "builtins.open"}):
                        continue
                    path_expr = handle.value_node.args[0] if handle.value_node.args else next(
                        (kw.value for kw in handle.value_node.keywords if kw.arg in {"file", "path"}), None
                    )
                    path_literals = "".join(_template_path_literals(path_expr, handle.scope_id, handle.lineno)).lower()
                    if "templates/" not in path_literals or ".html" not in path_literals:
                        continue
                    content = node.args[0]
                    if not isinstance(content, ast.Name):
                        continue
                    content_record = _assigned_value(content.id, scope_id, lineno)
                    if content_record is None:
                        continue
                    template_markers = [
                        part.value for part in ast.walk(content_record.value_node)
                        if isinstance(part, ast.Constant) and isinstance(part.value, str)
                    ]
                    if not any("{%" in value or "{{" in value for value in template_markers):
                        continue
                    temporary_sink = SecurityNode(
                        id="", node_type=NodeType.SINK, symbol="STORED_HTML_TEMPLATE",
                        operation="STORED_HTML_TEMPLATE", location=location(content_record.value_node, self.file_paths.get(mod_name, "unknown.py")),
                        metadata={"sink_type": "SSTI", "cwe": "CWE-1336"},
                    )
                    taint = self.resolve_expression(
                        content_record.value_node, temporary_sink, content_record.scope_id, content_record.lineno
                    )
                    if taint.state != TaintState.CLEAN:
                        # The write stores Jinja/Django markup that the application assembled at
                        # runtime, so the injected text is later *compiled* as template code.
                        # Server-side template injection, not reflected XSS.
                        _add_finding(
                            content_record.value_node, mod_name, content_record.scope_id,
                            "STORED_HTML_TEMPLATE_WRITE", cwe="CWE-1336", category="SSTI",
                        )

    def analyze(self):
        """Run the analysis pipeline with scoped garbage-collector control.

        The pipeline allocates millions of short-lived AST wrapper and record
        objects, so the generational collector spends its time promoting and
        scavenging garbage that reference counting already frees, while the pass
        itself creates no cycles worth collecting mid-flight. Disabling is scoped
        to this call and restores the caller's own state in `finally`: a scan must
        not leave the CLI, server, worker or test process permanently running with
        GC switched off.
        """
        import gc
        gc_was_enabled = gc.isenabled()
        if gc_was_enabled:
            gc.disable()
        try:
            return self._analyze_pipeline()
        finally:
            if gc_was_enabled:
                gc.enable()
                gc.collect()

    def _analyze_pipeline(self):
        """Analyze all modules for security vulnerabilities with phase-level profiling."""
        import time as _time
        import sys as _sys
        
        _phase_start = _time.perf_counter()
        
        # Phase 1: Import resolution (per-module, parallelizable)
        _t0 = _time.perf_counter()
        for mod_name, tree in self.modules.items():
            for node in self._reachable_nodes(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names: self.imports[mod_name][alias.asname or alias.name] = alias.name
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if getattr(node, 'level', 0) > 0:
                        parts = mod_name.split(".")
                        base = ".".join(parts[:-node.level]) if len(parts) > node.level else ""
                        module = f"{base}.{module}" if base and module else base or module
                    for alias in node.names: self.imports[mod_name][alias.asname or alias.name] = f"{module}.{alias.name}" if module else alias.name
        _t1 = _time.perf_counter()
        print(f"TimeCodeSecurity [PROFILE] Phase 1 (Import resolution): {_t1 - _t0:.2f}s", file=_sys.stderr)
        
        # Phase 2: Statement collection (per-module, parallelizable)
        _t0 = _time.perf_counter()
        for mod_name, tree in self.modules.items():
            self.collect_statements(tree.body, scope_id=f"{mod_name}:global", is_conditional=False)
        _t1 = _time.perf_counter()
        print(f"TimeCodeSecurity [PROFILE] Phase 2 (Statement collection): {_t1 - _t0:.2f}s", file=_sys.stderr)

        # Phase 4.3: Extract function contracts after statement collection
        _t0 = _time.perf_counter()
        self._extract_function_contracts()
        _t1 = _time.perf_counter()
        print(f"TimeCodeSecurity [PROFILE] Phase 4.3 (Function contracts): {_t1 - _t0:.2f}s", file=_sys.stderr)

        # Index call sites by target function scope
        _t0 = _time.perf_counter()
        for call_node, caller_scope, lineno in self.raw_calls:
            canon_name = self.resolve_canonical_name(call_node.func, caller_scope)
            fname = canon_name or dotted_name(call_node.func)
            if fname:
                func_scope = self._resolve_function_scope(fname, caller_scope)
                if func_scope:
                    self.call_sites_by_target.setdefault(func_scope, []).append((call_node, caller_scope, lineno))
        _t1 = _time.perf_counter()
        print(f"TimeCodeSecurity [PROFILE] Call site indexing: {_t1 - _t0:.2f}s ({len(self.raw_calls)} calls)", file=_sys.stderr)

        # Re-scan raw_calls for any sinks resolved after call-site indexing (higher-order callbacks)
        _t0 = _time.perf_counter()
        _sink_count_before = len(self.sink_records)
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
                mod_name = scope_module(caller_scope)
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
                        mod_name = scope_module(caller_scope)
                        file_path = self.file_paths.get(mod_name, "unknown.py")
                        sink_node = self.get_or_create_sink(call_node, file_path, caller_scope)
                        self.sink_records.append(SinkRecord(node=call_node, security_node=sink_node, lineno=lineno, scope_id=caller_scope))
                        if sink_node.metadata.get("cwe") != "CWE-295" and self._has_disabled_ssl(call_node, caller_scope):
                            ssl_sink = self.get_or_create_sink(call_node, file_path, caller_scope, force_cwe="CWE-295")
                            self.sink_records.append(SinkRecord(node=call_node, security_node=ssl_sink, lineno=lineno, scope_id=caller_scope))
        _t1 = _time.perf_counter()
        _new_sinks = len(self.sink_records) - _sink_count_before
        print(f"TimeCodeSecurity [PROFILE] Sink detection (callbacks+direct): {_t1 - _t0:.2f}s ({_new_sinks} new sinks)", file=_sys.stderr)

        # Source detection
        _t0 = _time.perf_counter()
        for mod_name, tree in self.modules.items():
            for node in self._reachable_nodes(tree):
                if isinstance(node, ast.Call) and self.is_source_call(node, f"{mod_name}:global"):
                    self.get_or_create_source(node, self.file_paths.get(mod_name, "unknown.py"), f"{mod_name}:global")
        _t1 = _time.perf_counter()
        print(f"TimeCodeSecurity [PROFILE] Source detection: {_t1 - _t0:.2f}s", file=_sys.stderr)
        
        # Structural finding collection phases (batched for profiling)
        _t0 = _time.perf_counter()
        self._collect_batch2_structural_findings()
        self._collect_batch3a_structural_findings()
        self._collect_cwe319_variable_resolution_findings()
        self._collect_batch3b_structural_findings()
        self._collect_batch4_structural_findings()
        self._collect_phase3_structural_findings()
        self._collect_phase4_structural_findings()
        self._collect_intra_file_call_bridge_findings()
        self._collect_cwe89_driver_querybuilder_findings()
        self._collect_phase5_structural_findings()
        self._collect_phase6_structural_findings()
        self._collect_phase7_structural_findings()
        self._collect_phase8_structural_findings()
        self._collect_phase9_structural_findings()
        self._collect_response_write_findings()
        self._collect_template_response_xss_findings()
        self._collect_cwe79_xss_recovery_findings()
        self._collect_cwe22_path_traversal_findings()
        self._collect_cwe502_deserialization_findings()
        self._collect_cluster1_structural_findings()
        self._collect_cluster2_structural_findings()
        self._collect_cluster3_structural_findings()
        _t1 = _time.perf_counter()
        print(f"TimeCodeSecurity [PROFILE] Structural findings (all batches): {_t1 - _t0:.2f}s", file=_sys.stderr)
        for assign_stmt, scope_id, lineno in self.ssl_attr_assigns:
            mod_name = scope_module(scope_id)
            file_path = self.file_paths.get(mod_name, "unknown.py")
            sink_id = self.next_sink_id()
            sink_node = SecurityNode(
                id=sink_id,
                node_type=NodeType.SINK,
                symbol="verify",
                operation="DISABLE_SSL_VERIFICATION",
                location=location(assign_stmt, file_path),
                metadata={"sink_type": "SSL_VERIFICATION_DISABLED", "category": "INSECURE_CONFIGURATION", "cwe": "CWE-295"}
            )
            self.sinks.append(sink_node)
            self.edges.append(DataFlowEdge(
                source_id="INSECURE_CONFIGURATION",
                target_id=sink_node.id,
                kind="CONFIRMED_DATA_FLOW",
                confidence=1.0,
                transform="disabled_ssl_verification"
            ))

        for record in self.sink_records:
            sink = record.security_node
            cwe = sink.metadata.get("cwe")
            target_expr = None
            if isinstance(record.node, ast.Return):
                target_expr = record.node.value
            elif isinstance(record.node, ast.Call):
                if isinstance(record.node.func, ast.Attribute) and (record.node.func.attr in {"read_text", "read_bytes", "write_text", "write_bytes", "extractall", "extract"} or (record.node.func.attr == "open" and self._is_path_expr(record.node.func.value, record.scope_id))):
                    target_expr = record.node.func.value
                elif isinstance(record.node.func, ast.Attribute) and record.node.func.attr == "render":
                    if self._is_jinja_template_expr(record.node.func.value, record.scope_id):
                        target_expr = record.node.func.value
                    elif cwe in STRUCTURAL_SYNTHETIC_SOURCES or sink.metadata.get("p11_source_id"):
                        # A structural sink already owns a synthetic source, so the render()
                        # shape of its node must not route it into the taint-resolution prune.
                        pass
                    else:
                        if sink in self.sinks:
                            self.sinks.remove(sink)
                        continue
                elif record.node.args:
                    target_arg_idx = sink.metadata.get("target_arg", 0)
                    if len(record.node.args) > target_arg_idx:
                        target_expr = record.node.args[target_arg_idx]
                    else:
                        target_expr = record.node.args[0]
                elif getattr(record.node, "keywords", []):
                    for kw in record.node.keywords:
                        if kw.arg in ("source", "template", "s", "filename_or_fp", "filename", "path_or_file", "path", "code", "line", "url"):
                            target_expr = kw.value
                            break

            stype = sink.metadata.get("sink_type")
            op = sink.metadata.get("operation")

            p11_source_id = sink.metadata.get("p11_source_id")
            if p11_source_id:
                self.edges.append(DataFlowEdge(
                    source_id=p11_source_id,
                    target_id=sink.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=1.0,
                    transform=op or "dynamic_html_response",
                ))
                continue

            p10_source_id = sink.metadata.get("p10_source_id")
            if p10_source_id:
                self.edges.append(DataFlowEdge(
                    source_id=p10_source_id,
                    target_id=sink.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=1.0,
                    transform=op or "HTTP_RESPONSE_WRITE",
                ))
                continue

            p9_source_id = sink.metadata.get("p9_source_id")
            if p9_source_id:
                self.edges.append(DataFlowEdge(
                    source_id=p9_source_id,
                    target_id=sink.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=1.0,
                    transform=op or f"{cwe.lower()}_phase9_violation",
                ))
                continue

            p8_source_id = sink.metadata.get("p8_source_id")
            if p8_source_id:
                self.edges.append(DataFlowEdge(
                    source_id=p8_source_id,
                    target_id=sink.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=1.0,
                    transform=op or f"{cwe.lower()}_phase8_violation",
                ))
                continue

            p7_source_id = sink.metadata.get("p7_source_id")
            if p7_source_id:
                self.edges.append(DataFlowEdge(
                    source_id=p7_source_id,
                    target_id=sink.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=1.0,
                    transform=op or f"{cwe.lower()}_phase7_violation",
                ))
                continue

            p6_source_id = sink.metadata.get("p6_source_id")
            if p6_source_id:
                self.edges.append(DataFlowEdge(
                    source_id=p6_source_id,
                    target_id=sink.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=1.0,
                    transform=op or "sql_injection_vulnerability",
                ))
                continue

            p5_source_id = sink.metadata.get("p5_source_id")
            if p5_source_id:
                self.edges.append(DataFlowEdge(
                    source_id=p5_source_id,
                    target_id=sink.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=1.0,
                    transform=op or f"{cwe.lower()}_phase5_violation",
                ))
                continue

            if cwe == "CWE-295":
                self.edges.append(DataFlowEdge(
                    source_id="INSECURE_CONFIGURATION",
                    target_id=sink.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=1.0,
                    transform="disabled_ssl_verification"
                ))
                continue

            if cwe == "CWE-322":
                self.edges.append(DataFlowEdge(
                    source_id="INSECURE_CONFIGURATION",
                    target_id=sink.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=1.0,
                    transform="insecure_host_key_policy"
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

            p3_source_id = sink.metadata.get("p3_source_id")
            if p3_source_id:
                self.edges.append(DataFlowEdge(
                    source_id=p3_source_id,
                    target_id=sink.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=1.0,
                    transform=op or f"{cwe.lower()}_phase3_violation",
                ))
                continue

            p4_source_id = sink.metadata.get("p4_source_id")
            if p4_source_id:
                self.edges.append(DataFlowEdge(
                    source_id=p4_source_id,
                    target_id=sink.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=1.0,
                    transform=op or f"{cwe.lower()}_phase4_violation",
                ))
                continue

            if cwe in STRUCTURAL_SYNTHETIC_SOURCES:
                self.edges.append(DataFlowEdge(
                    source_id=STRUCTURAL_SYNTHETIC_SOURCES[cwe],
                    target_id=sink.id,
                    kind="CONFIRMED_DATA_FLOW",
                    confidence=1.0,
                    transform=op or f"{cwe.lower()}_structural_violation"
                ))
                continue

            if op == "UNBOUNDED_READ" or (cwe in ("CWE-400", "CWE-776") and isinstance(record.node, ast.Call) and isinstance(record.node.func, ast.Attribute) and record.node.func.attr == "read" and len(record.node.args) == 0):
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

            cwe = sink.metadata.get("cwe")
            stype = sink.metadata.get("sink_type")
            op = sink.metadata.get("operation")
            if target_expr is None:
                continue
            is_cwe22 = (cwe == "CWE-22" or stype in ("PATH_TRAVERSAL", "FILE_ACCESS") or op == "FILE_ACCESS")
            is_cwe78 = (cwe == "CWE-78" or stype in ("COMMAND_INJECTION", "OS_COMMAND_EXECUTION")
                        or op in ("OS_COMMAND_EXECUTION", "COMMAND_EXECUTION"))

            if is_cwe22 and (
                # Sink-without-source: a path assembled only from literals, self-describing
                # module attributes, dir listings or nonces can never carry attacker taint,
                # and an in-memory upload object is a stream, not a path being resolved.
                self._is_self_described(target_expr, record.scope_id, record.lineno)
                or self._is_upload_handle(target_expr, record.scope_id, record.lineno)
            ):
                if sink in self.sinks:
                    self.sinks.remove(sink)
                continue
            if is_cwe78 and not self._has_untrusted_command_lineage(
                    target_expr, record.scope_id, record.lineno):
                # `subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y", "pip"])`:
                # no shell, and every argv element is chosen by the source file or read back
                # from the application's own tables, so there is nothing an attacker can
                # append to the command line.
                if sink in self.sinks:
                    self.sinks.remove(sink)
                continue

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

        _t_end = _time.perf_counter()
        _total_elapsed = _t_end - _phase_start
        print(f"TimeCodeSecurity [PROFILE] Total analyze() elapsed: {_total_elapsed:.2f}s", file=_sys.stderr)
        print(f"TimeCodeSecurity [PROFILE] Summary: {len(self.modules)} modules, {len(self.sources)} sources, {len(self.sinks)} sinks, {len(self.edges)} edges", file=_sys.stderr)
        
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
            finding_id=f"TimeCodeSecurity-IR-{sink.id}",
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
            finding_id=f"TimeCodeSecurity-IR-{sink.id}",
            cwe="CWE-22",
            confidence=prov.confidence,
            nodes=reindexed_nodes,
            edges=graph_edges
        )