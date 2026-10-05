"""
TimeCodeSecurity - Vector D CWE-489 Debug Flag Transformer.
Implements deterministic AST-guided remediation for debug mode in production.
"""

from typing import Any, Dict, Optional, Tuple
import ast

from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus


class Cwe489DebugFlagTransformer(BaseRemediationTransformer):
    """
    Deterministic AST transformer for CWE-489 (Debug Flag Enabled).
    Replaces app.run(debug=True) with debug=False or environment-based check.
    """

    @property
    def rule(self) -> RemediationRule:
        return RemediationRule.DEBUG_FLAG_DISABLE

    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        """Check if finding is app.run(debug=True) call."""
        line_number = finding.get("line_number", 0)
        call_node = self._find_debug_run_call(tree, line_number)
        return call_node is not None

    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        """Replace debug=True with debug=False."""
        line_number = finding.get("line_number", 0)
        
        call_node = self._find_debug_run_call(tree, line_number)
        if not call_node:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("app.run() call not found",))

        # Find and replace debug=True keyword
        for kw in call_node.keywords:
            if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                kw.value = ast.Constant(value=False)
                break
        else:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("debug=True not found",))

        try:
            patched_source = ast.unparse(tree)
            snippet = self.patched_statement_snippet(tree, source_code, line_number) or ""
            
            return (PatchStatus.SUCCESS, patched_source, snippet, ())
        except Exception as e:
            return (PatchStatus.FAILED_SYNTAX, None, None, (f"AST unparse failed: {e}",))

    def _find_debug_run_call(
        self,
        tree: ast.AST,
        line_number: int
    ) -> Optional[ast.Call]:
        """Locate app.run(debug=True) call at or near the given line."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "run":
                    # Check for debug=True keyword
                    for kw in node.keywords:
                        if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            node_lineno = getattr(node, "lineno", 0)
                            node_end = getattr(node, "end_lineno", node_lineno)
                            if node_lineno <= line_number <= node_end or node_lineno == line_number:
                                return node
        return None
