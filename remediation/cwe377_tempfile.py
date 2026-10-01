"""
TimeCodeSecurity (TCS) - Vector D CWE-377 Insecure Temporary File Transformer.
Implements deterministic AST-guided remediation replacing tempfile.mktemp() with NamedTemporaryFile().
"""

from typing import Any, Dict, Optional, Tuple
import ast

from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus


class Cwe377TempfileTransformer(BaseRemediationTransformer):
    """
    Deterministic AST transformer for CWE-377 (Insecure Temporary File).
    Replaces tempfile.mktemp() with tempfile.NamedTemporaryFile().
    """

    @property
    def rule(self) -> RemediationRule:
        return RemediationRule.TEMPFILE_SECURE

    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        """Check if finding is tempfile.mktemp() call."""
        line_number = finding.get("line_number", 0)
        call_node = self._find_mktemp_call(tree, line_number)
        return call_node is not None

    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        """Replace tempfile.mktemp() with tempfile.NamedTemporaryFile()."""
        line_number = finding.get("line_number", 0)
        
        call_node = self._find_mktemp_call(tree, line_number)
        if not call_node:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("tempfile.mktemp call not found",))

        # Replace function attribute from mktemp to NamedTemporaryFile
        if isinstance(call_node.func, ast.Attribute):
            call_node.func.attr = "NamedTemporaryFile"
        else:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("Unexpected AST structure",))

        try:
            patched_source = ast.unparse(tree)
            snippet = self.patched_statement_snippet(tree, source_code, line_number) or ""
            
            return (PatchStatus.SUCCESS, patched_source, snippet, ())
        except Exception as e:
            return (PatchStatus.FAILED_SYNTAX, None, None, (f"AST unparse failed: {e}",))

    def _find_mktemp_call(
        self,
        tree: ast.AST,
        line_number: int
    ) -> Optional[ast.Call]:
        """Locate tempfile.mktemp() call at or near the given line."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute):
                    if func.attr == "mktemp":
                        if isinstance(func.value, ast.Name) and func.value.id == "tempfile":
                            node_lineno = getattr(node, "lineno", 0)
                            node_end = getattr(node, "end_lineno", node_lineno)
                            if node_lineno <= line_number <= node_end or node_lineno == line_number:
                                return node
        return None
