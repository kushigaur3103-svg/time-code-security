"""
TimeCodeSecurity - Vector D CWE-1336 Jinja2 Template Injection Transformer.
Implements deterministic AST-guided remediation for missing autoescape in Jinja2 environments.
"""

from typing import Any, Dict, Optional, Tuple
import ast

from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus


class Cwe1336JinjaAutoescapeTransformer(BaseRemediationTransformer):
    """
    Deterministic AST transformer for CWE-1336 (Template Injection).
    Adds autoescape=True to jinja2.Environment() instantiation if missing.
    """

    @property
    def rule(self) -> RemediationRule:
        return RemediationRule.TEMPLATE_AUTOESCAPE

    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        """Check if finding is a jinja2.Environment() call without autoescape."""
        line_number = finding.get("line_number", 0)
        call_node = self._find_jinja_env_call(tree, line_number)
        return call_node is not None

    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        """Add autoescape=True to jinja2.Environment() calls."""
        line_number = finding.get("line_number", 0)
        
        call_node = self._find_jinja_env_call(tree, line_number)
        if not call_node:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("jinja2.Environment call not found",))

        # Check if autoescape is already present
        existing_keywords = {kw.arg for kw in call_node.keywords if kw.arg}
        if "autoescape" in existing_keywords:
            return (PatchStatus.SUCCESS, source_code, "", ("autoescape already configured",))

        # Add autoescape=True keyword argument
        autoescape_const = ast.Constant(value=True)
        new_keyword = ast.keyword(arg="autoescape", value=autoescape_const)
        call_node.keywords.append(new_keyword)

        try:
            patched_source = ast.unparse(tree)
            snippet = self.patched_statement_snippet(tree, source_code, line_number) or ""
            
            return (PatchStatus.SUCCESS, patched_source, snippet, ())
        except Exception as e:
            return (PatchStatus.FAILED_SYNTAX, None, None, (f"AST unparse failed: {e}",))

    def _find_jinja_env_call(
        self,
        tree: ast.AST,
        line_number: int
    ) -> Optional[ast.Call]:
        """Locate jinja2.Environment() call at or near the given line."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Match both jinja2.Environment and Environment (if imported)
                func = node.func
                is_jinja_env = False
                
                if isinstance(func, ast.Attribute):
                    if func.attr == "Environment":
                        # Check if it's jinja2.Environment
                        if isinstance(func.value, ast.Name) and func.value.id == "jinja2":
                            is_jinja_env = True
                elif isinstance(func, ast.Name):
                    if func.id == "Environment":
                        is_jinja_env = True
                
                if is_jinja_env:
                    node_lineno = getattr(node, "lineno", 0)
                    node_end = getattr(node, "end_lineno", node_lineno)
                    if node_lineno <= line_number <= node_end or node_lineno == line_number:
                        return node
        return None
