"""
TimeCodeSecurity (TCS) - Vector D Base Remediation Transformer Interface.
Defines the abstract base contract for deterministic, AST-guided vulnerability
remediation transformers.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple
import ast

from remediation.contracts import RemediationRule, PatchStatus


class BaseRemediationTransformer(ABC):
    """
    Abstract base class for deterministic AST-guided vulnerability remediation transformers.
    All transformers must operate strictly statically, without executing target code,
    importing target packages, or using LLMs.
    """

    @property
    @abstractmethod
    def rule(self) -> RemediationRule:
        """The categorical remediation rule handled by this transformer."""
        ...

    @abstractmethod
    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        """
        Determines whether the given AST and finding can be deterministically transformed.
        Must check AST structure and ensure no unsupported patterns (e.g. dynamic table names) exist.
        """
        ...

    @abstractmethod
    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        """
        Executes the AST-guided transformation.
        Returns:
            (patch_status, patched_source, patched_snippet, limitations)
        If transformation succeeds:
            returns (PatchStatus.SUCCESS, patched_source, patched_snippet, limitations)
        If pattern is unsupported (e.g. dynamic table/column name):
            returns (PatchStatus.UNSUPPORTED_CWE, None, None, limitations)
        If transformation fails:
            returns (PatchStatus.FAILED_SYNTAX / FAILED_VERIFICATION, None, None, limitations)
        """
        ...

    @staticmethod
    def patched_statement_snippet(
        tree: ast.AST,
        source_code: str,
        line_number: int
    ) -> Optional[str]:
        """
        Renders the patched text of the statement covering line_number after the
        AST has been mutated, preserving the original indentation.

        Transformers mutate `tree` in place, so unparsing the enclosing statement
        yields the replacement block that editors must write over the vulnerable
        statement. Returns None when no statement covers the requested line.
        """
        candidates = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.stmt)
            and getattr(node, "lineno", 0)
            and node.lineno <= line_number <= (node.end_lineno or node.lineno)
        ]
        if not candidates:
            return None

        # Deepest (smallest span) enclosing statement
        stmt = min(candidates, key=lambda n: (n.end_lineno or n.lineno) - n.lineno)

        try:
            rendered = ast.unparse(stmt)
        except Exception:
            return None

        original_lines = source_code.split("\n")
        if 0 < line_number <= len(original_lines):
            indent = original_lines[line_number - 1][: len(original_lines[line_number - 1]) - len(original_lines[line_number - 1].lstrip())]
        else:
            indent = ""

        rendered_lines = rendered.split("\n")
        out = [f"{indent}{rendered_lines[0]}"]
        for extra in rendered_lines[1:]:
            out.append(f"{indent}{extra}" if extra.strip() else extra)
        return "\n".join(out)
