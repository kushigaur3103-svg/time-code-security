"""
TimeCodeSecurity (TCS) - Vector D CWE-614/CWE-1275 Cookie Security Transformer.
Implements deterministic AST-guided remediation for insecure cookie configurations:
Ensures response.set_cookie() calls include secure=True, httponly=True, samesite='Lax'.
"""

from typing import Any, Dict, List, Optional, Tuple
import ast

from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus


class Cwe614CookieSecureTransformer(BaseRemediationTransformer):
    """
    Deterministic AST transformer for CWE-614/CWE-1275 (Insecure Cookie Flags).
    Appends missing security attributes to set_cookie() calls.
    """

    @property
    def rule(self) -> RemediationRule:
        return RemediationRule.COOKIE_SECURE_FLAGS

    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        """Check if the finding is a set_cookie call that can be safely patched."""
        line_number = finding.get("line_number", 0)
        call_node = self._find_set_cookie_call(tree, line_number)
        return call_node is not None

    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        """Add missing security flags to set_cookie() calls."""
        line_number = finding.get("line_number", 0)
        
        # Find the set_cookie call
        call_node = self._find_set_cookie_call(tree, line_number)
        if not call_node:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("set_cookie call not found",))

        # Check which flags are missing
        existing_keywords = {kw.arg: kw.value for kw in call_node.keywords if kw.arg}
        
        missing_flags = []
        if "secure" not in existing_keywords:
            missing_flags.append(("secure", ast.Constant(value=True)))
        if "httponly" not in existing_keywords:
            missing_flags.append(("httponly", ast.Constant(value=True)))
        if "samesite" not in existing_keywords:
            missing_flags.append(("samesite", ast.Constant(value="Lax")))

        if not missing_flags:
            return (PatchStatus.SUCCESS, source_code, "", ("Cookie already has all security flags",))

        # Add missing keyword arguments
        for arg_name, arg_value in missing_flags:
            new_keyword = ast.keyword(arg=arg_name, value=arg_value)
            call_node.keywords.append(new_keyword)

        # Regenerate source code
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

    def _find_set_cookie_call(
        self,
        tree: ast.AST,
        line_number: int
    ) -> Optional[ast.Call]:
        """Locate set_cookie() call at or near the given line number."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_attr = getattr(node.func, "attr", None)
                if func_attr == "set_cookie":
                    node_lineno = getattr(node, "lineno", 0)
                    node_end = getattr(node, "end_lineno", node_lineno)
                    if node_lineno <= line_number <= node_end or node_lineno == line_number:
                        return node
        return None
