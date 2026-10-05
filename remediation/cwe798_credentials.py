"""
TimeCodeSecurity - Vector D CWE-798 Hardcoded Credentials Transformer.
Implements deterministic AST-guided remediation replacing hardcoded credentials with os.environ.get().
"""

from typing import Any, Dict, Optional, Tuple
import ast
import re

from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus


# Sensitive variable name patterns indicating credentials
SENSITIVE_PATTERNS = [
    r'api[_-]?key',
    r'secret[_-]?key',
    r'password',
    r'passwd',
    r'token',
    r'auth[_-]?token',
    r'access[_-]?key',
    r'private[_-]?key',
    r'credential',
]

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_PATTERNS]


def is_sensitive_variable(var_name: str) -> bool:
    """Check if variable name matches sensitive credential patterns."""
    return any(pattern.search(var_name) for pattern in COMPILED_PATTERNS)


class Cwe798CredentialsTransformer(BaseRemediationTransformer):
    """
    Deterministic AST transformer for CWE-798 (Hardcoded Credentials).
    Replaces hardcoded string literals assigned to sensitive variables with os.environ.get().
    """

    @property
    def rule(self) -> RemediationRule:
        return RemediationRule.CREDENTIAL_ENVIRON_GET

    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        """Check if finding is a hardcoded credential assignment."""
        line_number = finding.get("line_number", 0)
        assign_node = self._find_credential_assignment(tree, line_number)
        return assign_node is not None

    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        """Replace hardcoded credential with os.environ.get() pattern."""
        line_number = finding.get("line_number", 0)
        
        assign_node = self._find_credential_assignment(tree, line_number)
        if not assign_node:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("Credential assignment not found",))

        # Get the variable name
        var_name = None
        if isinstance(assign_node, ast.Assign):
            for target in assign_node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    break
        elif isinstance(assign_node, ast.AnnAssign):
            if isinstance(assign_node.target, ast.Name):
                var_name = assign_node.target.id
        
        if not var_name:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("Could not extract variable name",))

        # Generate environment variable name (uppercase with underscores)
        env_var_name = var_name.upper()
        
        # Create os.environ.get() call
        environ_get_call = ast.Call(
            func=ast.Attribute(
                value=ast.Attribute(
                    value=ast.Name(id="os", ctx=ast.Load()),
                    attr="environ",
                    ctx=ast.Load()
                ),
                attr="get",
                ctx=ast.Load()
            ),
            args=[
                ast.Constant(value=env_var_name),
                ast.Constant(value="")
            ],
            keywords=[]
        )

        # Replace the value in the assignment
        if isinstance(assign_node, ast.Assign):
            assign_node.value = environ_get_call
        elif isinstance(assign_node, ast.AnnAssign) and assign_node.value:
            assign_node.value = environ_get_call

        try:
            patched_source = ast.unparse(tree)
            snippet = self.patched_statement_snippet(tree, source_code, line_number) or ""
            
            return (PatchStatus.SUCCESS, patched_source, snippet, ())
        except Exception as e:
            return (PatchStatus.FAILED_SYNTAX, None, None, (f"AST unparse failed: {e}",))

    def _find_credential_assignment(
        self,
        tree: ast.AST,
        line_number: int
    ) -> Optional[ast.AST]:
        """Locate assignment to sensitive variable at or near the given line."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                # Check if it's an assignment with a string literal value
                has_string_value = False
                if isinstance(node, ast.Assign):
                    has_string_value = isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
                elif isinstance(node, ast.AnnAssign) and node.value:
                    has_string_value = isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
                
                if not has_string_value:
                    continue
                
                # Extract variable name
                var_name = None
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id
                            break
                elif isinstance(node, ast.AnnAssign):
                    if isinstance(node.target, ast.Name):
                        var_name = node.target.id
                
                # Check if variable name is sensitive
                if var_name and is_sensitive_variable(var_name):
                    node_lineno = getattr(node, "lineno", 0)
                    node_end = getattr(node, "end_lineno", node_lineno)
                    if node_lineno <= line_number <= node_end or node_lineno == line_number:
                        return node
        return None
