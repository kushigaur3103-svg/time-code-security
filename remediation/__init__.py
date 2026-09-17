"""
TimeCodeSecurity (TCS) - Vector D Remediation Engine Package.
"""

from remediation.contracts import (
    PatchStatus,
    RemediationRule,
    RemediationRecord,
    FIXTURE_SEMANTIC_CONTRACTS,
)
from remediation.base import BaseRemediationTransformer
from remediation.cwe89_sqli import Cwe89ParameterizeTransformer
from remediation.cwe78_cmdi import Cwe78CmdInjectionTransformer
from remediation.cwe22_path_traversal import Cwe22PathTraversalTransformer
from remediation.dispatcher import RuleDispatcher
from remediation.verification import RemediationVerifier
from remediation.patch_engine import RemediationEngine
from remediation.orchestrator import (
    ProjectRemediationResult,
    format_remediation_section,
    remediate_project,
)

__all__ = [
    "PatchStatus",
    "RemediationRule",
    "RemediationRecord",
    "FIXTURE_SEMANTIC_CONTRACTS",
    "BaseRemediationTransformer",
    "Cwe89ParameterizeTransformer",
    "Cwe78CmdInjectionTransformer",
    "Cwe22PathTraversalTransformer",
    "RuleDispatcher",
    "RemediationVerifier",
    "RemediationEngine",
    "ProjectRemediationResult",
    "format_remediation_section",
    "remediate_project",
]
