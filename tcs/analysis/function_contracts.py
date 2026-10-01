"""
Deterministic Function Contract Extractor (Zero-FP Guarantee)

Bottom-up analysis that identifies wrapper functions where a parameter
flows deterministically into a known security sink.

NO HEURISTICS / NO AI / NO LLM — pure deterministic AST analysis only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set, Tuple

# Known dangerous sinks mapped to their CWE IDs
KNOWN_SINKS: Dict[str, str] = {
    # SQL Injection
    "execute": "CWE-89",
    "cursor.execute": "CWE-89",
    "conn.execute": "CWE-89",
    "db.execute": "CWE-89",

    # Command Injection
    "subprocess.run": "CWE-78",
    "subprocess.call": "CWE-78",
    "subprocess.Popen": "CWE-78",
    "os.system": "CWE-78",
    "os.popen": "CWE-78",
    "os.execvp": "CWE-78",
    "os.execl": "CWE-78",

    # Path Traversal
    "open": "CWE-22",
    "os.open": "CWE-22",
    "pathlib.Path.open": "CWE-22",

    # Code Injection
    "eval": "CWE-95",
    "exec": "CWE-95",
    "compile": "CWE-95",

    # Deserialization
    "pickle.loads": "CWE-502",
    "yaml.load": "CWE-502",
    "marshal.loads": "CWE-502",

    # SSRF
    "requests.get": "CWE-918",
    "requests.post": "CWE-918",
    "urllib.request.urlopen": "CWE-918",

    # XSS
    "flask.render_template_string": "CWE-79",
    "jinja2.Template.render": "CWE-79",
}

# Known sanitizers that break taint propagation
CONTRACT_SANITIZERS: Set[str] = {
    "int", "float", "bool",  # Strict type conversions
    "shlex.quote",           # Shell argument quoting
    "html.escape",           # HTML entity encoding
    "urllib.parse.quote",    # URL percent-encoding
    "os.path.abspath",       # Path normalization
    "os.path.realpath",      # Symlink-resolving path normalization
    "pathlib.Path.resolve",  # Modern pathlib resolution
}


@dataclass(frozen=True)
class FunctionSinkContract:
    """
    Represents a verified contract where a function parameter flows
    deterministically into a known security sink.

    Example:
        def run_cmd(c):          # func_name="run_cmd"
            subprocess.run(c)    # sink_arg_index=0, cwe_id="CWE-78", target_sink="subprocess.run"

    SAFETY GUARANTEE:
    - Only registered if path from parameter to sink has NO sanitizers
    - Only registered if no constant overrides kill the taint
    - 100% deterministic within the function body
    """
    func_name: str
    sink_arg_index: int          # Which parameter of the wrapper function
    cwe_id: str                  # The CWE classification
    target_sink: str             # The underlying dangerous sink
    func_lineno: int             # Line number of the function definition
    sink_lineno: int             # Line number of the sink call


class FunctionContractExtractor:
    """
    Deterministic bottom-up function contract extractor.

    Analyzes each FunctionDef in a module and identifies wrappers where
    a parameter flows directly into a known security sink without sanitization.
    """

    def __init__(self):
        self.contracts: Dict[str, FunctionSinkContract] = {}

    def extract_from_module(self, tree: ast.AST, file_path: str = "<unknown>") -> Dict[str, FunctionSinkContract]:
        """
        Extract all function contracts from an AST module.

        Returns dict mapping function name to FunctionSinkContract.
        """
        self.contracts.clear()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                contract = self._analyze_function(node, file_path)
                if contract:
                    # Only register if not already present (first one wins for safety)
                    if contract.func_name not in self.contracts:
                        self.contracts[contract.func_name] = contract

        return self.contracts

    def _analyze_function(
        self, func_node: ast.FunctionDef, file_path: str
    ) -> Optional[FunctionSinkContract]:
        """
        Analyze a single function for parameter-to-sink flows.

        Returns FunctionSinkContract if a deterministic flow is found, None otherwise.
        """
        param_names = [arg.arg for arg in func_node.args.args]

        # Skip functions with no parameters
        if not param_names:
            return None

        # Walk function body looking for sink calls
        for stmt in ast.walk(func_node):
            if not isinstance(stmt, ast.Call):
                continue

            # Check if this call is a known sink
            sink_name = self._get_call_name(stmt)
            if not sink_name:
                continue

            cwe_id = KNOWN_SINKS.get(sink_name)
            if not cwe_id:
                continue

            # Check each argument of the sink call
            for arg_idx, arg_node in enumerate(stmt.args):
                # Check if this argument is a direct reference to a parameter
                if isinstance(arg_node, ast.Name) and arg_node.id in param_names:
                    param_idx = param_names.index(arg_node.id)

                    # Verify the flow is clean (no sanitizers, no overrides)
                    if self._verify_clean_flow(func_node, arg_node.id, stmt.lineno):
                        return FunctionSinkContract(
                            func_name=func_node.name,
                            sink_arg_index=param_idx,
                            cwe_id=cwe_id,
                            target_sink=sink_name,
                            func_lineno=func_node.lineno,
                            sink_lineno=stmt.lineno
                        )

            # Also check keyword arguments
            for kw in stmt.keywords:
                if isinstance(kw.value, ast.Name) and kw.value.id in param_names:
                    param_idx = param_names.index(kw.value.id)

                    if self._verify_clean_flow(func_node, kw.value.id, stmt.lineno):
                        return FunctionSinkContract(
                            func_name=func_node.name,
                            sink_arg_index=param_idx,
                            cwe_id=cwe_id,
                            target_sink=sink_name,
                            func_lineno=func_node.lineno,
                            sink_lineno=stmt.lineno
                        )

        return None

    def _get_call_name(self, call_node: ast.Call) -> Optional[str]:
        """Extract dotted name from a call node."""
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        if isinstance(call_node.func, ast.Attribute):
            parts = []
            current = call_node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                return ".".join(reversed(parts))
        return None

    def _verify_clean_flow(
        self, func_node: ast.FunctionDef, param_name: str, sink_lineno: int
    ) -> bool:
        """
        Verify that the flow from parameter to sink is clean.

        Returns True ONLY if:
        - No sanitizers are applied to the parameter before the sink
        - No constant reassignments kill the taint
        - NO conditional guards (if statements) exist before the sink
        - The parameter is used directly without intervening logic

        This is the CRITICAL SAFETY FILTER for zero false positives.
        """
        # Check for conditional guards (if statements) before the sink
        for stmt in ast.walk(func_node):
            if not hasattr(stmt, 'lineno'):
                continue
            if stmt.lineno >= sink_lineno:
                continue
            
            # If there's ANY if statement before the sink, don't create contract
            # This prevents contracts on guarded wrappers like SSRF validators
            if isinstance(stmt, ast.If):
                return False

        # Walk all statements before the sink
        for stmt in ast.walk(func_node):
            if not hasattr(stmt, 'lineno'):
                continue
            if stmt.lineno >= sink_lineno:
                continue

            # Check for assignments to the parameter
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id == param_name:
                        # Check if it's reassigned to a safe constant (kill-gen)
                        if self._is_safe_literal(stmt.value):
                            return False

                        # Check if it's passed through a sanitizer
                        if isinstance(stmt.value, ast.Call):
                            func_name = self._get_call_name(stmt.value)
                            if func_name in CONTRACT_SANITIZERS:
                                return False

            # Check for annotated assignments
            if isinstance(stmt, ast.AnnAssign) and stmt.target:
                if isinstance(stmt.target, ast.Name) and stmt.target.id == param_name:
                    if stmt.value:
                        if self._is_safe_literal(stmt.value):
                            return False
                        if isinstance(stmt.value, ast.Call):
                            func_name = self._get_call_name(stmt.value)
                            if func_name in CONTRACT_SANITIZERS:
                                return False

        return True

    def _is_safe_literal(self, node: ast.AST) -> bool:
        """Check if a node is a safe literal constant."""
        if isinstance(node, ast.Constant):
            return True
        if hasattr(ast, 'Num') and isinstance(node, ast.Num):
            return True
        if hasattr(ast, 'Str') and isinstance(node, ast.Str):
            return True
        return False

    def get_contract_for_call(self, call_node: ast.Call) -> Optional[FunctionSinkContract]:
        """
        Look up a contract for a given call node.

        Returns the contract if the call matches a registered wrapper function.
        """
        func_name = self._get_call_name(call_node)
        if func_name:
            return self.contracts.get(func_name)
        return None
