"""
TimeCodeSecurity (TCS) - Vector D CWE-327 Weak Cryptographic Hash Transformer.
Implements deterministic AST-guided remediation replacing md5/sha1 with sha256.
"""

from typing import Any, Dict, Optional, Tuple
import ast

from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus


class Cwe327WeakHashTransformer(BaseRemediationTransformer):
    """
    Deterministic AST transformer for CWE-327 (Weak Cryptographic Hash).
    Replaces hashlib.md5() and hashlib.sha1() with hashlib.sha256().
    """

    @property
    def rule(self) -> RemediationRule:
        return RemediationRule.WEAK_HASH_REPLACE

    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        """Check if finding is a hashlib.md5() or hashlib.sha1() call."""
        line_number = finding.get("line_number", 0)
        call_node = self._find_weak_hash_call(tree, line_number)
        return call_node is not None

    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        """Replace weak hash function with sha256."""
        line_number = finding.get("line_number", 0)
        
        call_node = self._find_weak_hash_call(tree, line_number)
        if not call_node:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("Weak hash call not found",))

        # Replace the function attribute with sha256
        if isinstance(call_node.func, ast.Attribute):
            call_node.func.attr = "sha256"
        else:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("Unexpected AST structure",))

        try:
            patched_source = ast.unparse(tree)
            snippet = self.patched_statement_snippet(tree, source_code, line_number) or ""
            
            return (PatchStatus.SUCCESS, patched_source, snippet, ())
        except Exception as e:
            return (PatchStatus.FAILED_SYNTAX, None, None, (f"AST unparse failed: {e}",))

    def _find_weak_hash_call(
        self,
        tree: ast.AST,
        line_number: int
    ) -> Optional[ast.Call]:
        """Locate hashlib.md5() or hashlib.sha1() call at or near the given line."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute):
                    if func.attr in ("md5", "sha1"):
                        # Verify it's hashlib.md5 or hashlib.sha1
                        if isinstance(func.value, ast.Name) and func.value.id == "hashlib":
                            node_lineno = getattr(node, "lineno", 0)
                            node_end = getattr(node, "end_lineno", node_lineno)
                            if node_lineno <= line_number <= node_end or node_lineno == line_number:
                                return node
        return None
