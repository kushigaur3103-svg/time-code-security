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
