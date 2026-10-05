"""
TimeCodeSecurity - Vector D CWE-95 Dynamic Code Execution Transformer.
Implements deterministic AST-guided remediation replacing eval() with ast.literal_eval().
"""

from typing import Any, Dict, Optional, Tuple
import ast

from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus


class Cwe95EvalTransformer(BaseRemediationTransformer):
    """
    Deterministic AST transformer for CWE-95 (Dynamic Code Evaluation).
    Replaces eval() calls with ast.literal_eval() for safe literal parsing.
    """

    @property
    def rule(self) -> RemediationRule:
        return RemediationRule.EVAL_LITERAL_REPLACE

    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        """Check if finding is eval() call."""
        line_number = finding.get("line_number", 0)
        call_node = self._find_eval_call(tree, line_number)
        return call_node is not None

    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        """Replace eval() with ast.literal_eval()."""
        line_number = finding.get("line_number", 0)
        
        call_node = self._find_eval_call(tree, line_number)
        if not call_node:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("eval call not found",))

        # Replace function name from eval to ast.literal_eval
        # Create ast.literal_eval attribute access
        call_node.func = ast.Attribute(
            value=ast.Name(id="ast", ctx=ast.Load()),
            attr="literal_eval",
            ctx=ast.Load()
        )

        try:
            patched_source = ast.unparse(tree)
            snippet = self.patched_statement_snippet(tree, source_code, line_number) or ""
            
            return (PatchStatus.SUCCESS, patched_source, snippet, ())
        except Exception as e:
            return (PatchStatus.FAILED_SYNTAX, None, None, (f"AST unparse failed: {e}",))

    def _find_eval_call(
        self,
        tree: ast.AST,
        line_number: int
    ) -> Optional[ast.Call]:
        """Locate eval() call at or near the given line."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == "eval":
                    node_lineno = getattr(node, "lineno", 0)
                    node_end = getattr(node, "end_lineno", node_lineno)
                    if node_lineno <= line_number <= node_end or node_lineno == line_number:
                        return node
        return None
