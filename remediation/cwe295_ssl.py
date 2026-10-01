"""
TimeCodeSecurity (TCS) - Vector D CWE-295 Disabled SSL Verification Transformer.
Implements deterministic AST-guided remediation for verify=False in requests.
"""

from typing import Any, Dict, Optional, Tuple
import ast

from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus


class Cwe295SslVerificationTransformer(BaseRemediationTransformer):
    """
    Deterministic AST transformer for CWE-295 (Disabled SSL Verification).
    Removes or changes verify=False to verify=True in requests calls.
    """

    @property
    def rule(self) -> RemediationRule:
        return RemediationRule.SSL_VERIFY_ENABLE

    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        """Check if finding is requests call with verify=False."""
        line_number = finding.get("line_number", 0)
        call_node = self._find_verify_false_call(tree, line_number)
        return call_node is not None

    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        """Change verify=False to verify=True."""
        line_number = finding.get("line_number", 0)
        
        call_node = self._find_verify_false_call(tree, line_number)
        if not call_node:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("requests call not found",))

        # Find and replace verify=False keyword
        for kw in call_node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                kw.value = ast.Constant(value=True)
                break
        else:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("verify=False not found",))

        try:
            patched_source = ast.unparse(tree)
            snippet_lines = source_code.split('\n')
            if 0 < line_number <= len(snippet_lines):
                snippet = snippet_lines[line_number - 1]
            else:
                snippet = ""
            
            return (PatchStatus.SUCCESS, patched_source, snippet, ())
        except Exception as e:
            return (PatchStatus.FAILED_SYNTAX, None, None, (f"AST unparse failed: {e}",))

    def _find_verify_false_call(
        self,
        tree: ast.AST,
        line_number: int
    ) -> Optional[ast.Call]:
        """Locate requests call with verify=False at or near the given line."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                is_requests_call = False
                
                if isinstance(func, ast.Attribute):
                    if isinstance(func.value, ast.Name) and func.value.id == "requests":
                        if func.attr in ("get", "post", "put", "delete", "patch", "head", "options"):
                            is_requests_call = True
                
                if is_requests_call:
                    # Check for verify=False keyword
                    for kw in node.keywords:
                        if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                            node_lineno = getattr(node, "lineno", 0)
                            node_end = getattr(node, "end_lineno", node_lineno)
                            if node_lineno <= line_number <= node_end or node_lineno == line_number:
                                return node
        return None
