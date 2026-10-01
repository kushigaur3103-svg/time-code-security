"""
TimeCodeSecurity (TCS) - Vector D CWE-502 Unsafe YAML Deserialization Transformer.
Implements deterministic AST-guided remediation replacing yaml.load() with yaml.safe_load().
"""

from typing import Any, Dict, Optional, Tuple
import ast

from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus


class Cwe502YamlSafeLoaderTransformer(BaseRemediationTransformer):
    """
    Deterministic AST transformer for CWE-502 (Unsafe Deserialization).
    Replaces yaml.load(data) with yaml.safe_load(data) or adds Loader=yaml.SafeLoader.
    """

    @property
    def rule(self) -> RemediationRule:
        return RemediationRule.YAML_SAFE_LOADER

    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        """Check if finding is a yaml.load() call without safe loader."""
        line_number = finding.get("line_number", 0)
        call_node = self._find_yaml_load_call(tree, line_number)
        return call_node is not None

    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        """Replace yaml.load() with yaml.safe_load() or add SafeLoader."""
        line_number = finding.get("line_number", 0)
        
        call_node = self._find_yaml_load_call(tree, line_number)
        if not call_node:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("yaml.load call not found",))

        # Check if already using SafeLoader
        existing_keywords = {kw.arg: kw.value for kw in call_node.keywords if kw.arg}
        if "Loader" in existing_keywords:
            loader_value = existing_keywords["Loader"]
            if isinstance(loader_value, ast.Attribute):
                if loader_value.attr == "SafeLoader":
                    return (PatchStatus.SUCCESS, source_code, "", ("Already using SafeLoader",))

        # Strategy: Replace function name from load to safe_load
        if isinstance(call_node.func, ast.Attribute):
            call_node.func.attr = "safe_load"
            
            # Remove Loader keyword if present (not needed for safe_load)
            call_node.keywords = [kw for kw in call_node.keywords if kw.arg != "Loader"]
        else:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("Unexpected AST structure",))

        try:
            patched_source = ast.unparse(tree)
            snippet = self.patched_statement_snippet(tree, source_code, line_number) or ""
            
            return (PatchStatus.SUCCESS, patched_source, snippet, ())
        except Exception as e:
            return (PatchStatus.FAILED_SYNTAX, None, None, (f"AST unparse failed: {e}",))

    def _find_yaml_load_call(
        self,
        tree: ast.AST,
        line_number: int
    ) -> Optional[ast.Call]:
        """Locate yaml.load() call at or near the given line."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute):
                    if func.attr == "load":
                        # Verify it's yaml.load
                        if isinstance(func.value, ast.Name) and func.value.id == "yaml":
                            node_lineno = getattr(node, "lineno", 0)
                            node_end = getattr(node, "end_lineno", node_lineno)
                            if node_lineno <= line_number <= node_end or node_lineno == line_number:
                                return node
        return None
