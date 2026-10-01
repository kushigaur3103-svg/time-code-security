"""
TimeCodeSecurity (TCS) - Vector D CWE-1188 Insecure Network Binding Transformer.
Implements deterministic AST-guided remediation changing host="0.0.0.0" to host="127.0.0.1".
"""

from typing import Any, Dict, Optional, Tuple
import ast

from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus


class Cwe1188NetworkBindingTransformer(BaseRemediationTransformer):
    """
    Deterministic AST transformer for CWE-1188 (Insecure Default Network Binding).
    Replaces host="0.0.0.0" with host="127.0.0.1" in server/socket calls.
    """

    @property
    def rule(self) -> RemediationRule:
        return RemediationRule.NETWORK_BINDING_LOCALHOST

    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        """Check if finding has host="0.0.0.0" argument."""
        line_number = finding.get("line_number", 0)
        call_node = self._find_wildcard_bind_call(tree, line_number)
        return call_node is not None

    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        """Replace host="0.0.0.0" with host="127.0.0.1"."""
        line_number = finding.get("line_number", 0)
        
        call_node = self._find_wildcard_bind_call(tree, line_number)
        if not call_node:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("Wildcard bind call not found",))

        # Find and replace host="0.0.0.0" keyword
        for kw in call_node.keywords:
            if kw.arg == "host" and isinstance(kw.value, ast.Constant) and kw.value.value == "0.0.0.0":
                kw.value = ast.Constant(value="127.0.0.1")
                break
        else:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("host='0.0.0.0' not found",))

        try:
            patched_source = ast.unparse(tree)
            snippet = self.patched_statement_snippet(tree, source_code, line_number) or ""
            
            return (PatchStatus.SUCCESS, patched_source, snippet, ())
        except Exception as e:
            return (PatchStatus.FAILED_SYNTAX, None, None, (f"AST unparse failed: {e}",))

    def _find_wildcard_bind_call(
        self,
        tree: ast.AST,
        line_number: int
    ) -> Optional[ast.Call]:
        """Locate call with host="0.0.0.0" at or near the given line."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for host="0.0.0.0" keyword
                for kw in node.keywords:
                    if kw.arg == "host" and isinstance(kw.value, ast.Constant) and kw.value.value == "0.0.0.0":
                        node_lineno = getattr(node, "lineno", 0)
                        node_end = getattr(node, "end_lineno", node_lineno)
                        if node_lineno <= line_number <= node_end or node_lineno == line_number:
                            return node
        return None
