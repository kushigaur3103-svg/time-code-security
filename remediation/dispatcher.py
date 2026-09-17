"""
TimeCodeSecurity (TCS) - Vector D Remediation Rule Dispatcher.
Deterministically maps CWE identifiers and RemediationRules to corresponding
AST transformers.
"""

from typing import Any, Dict, Optional, Union
from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus
from remediation.cwe89_sqli import Cwe89ParameterizeTransformer
from remediation.cwe78_cmdi import Cwe78CmdInjectionTransformer
from remediation.cwe22_path_traversal import Cwe22PathTraversalTransformer


class RuleDispatcher:
    """
    Deterministic rule dispatcher.
    Maps CWE identifiers and RemediationRules to corresponding AST transformers.
    Returns None for unsupported CWEs or rules.
    """

    def __init__(self):
        self._cwe89_transformer = Cwe89ParameterizeTransformer()
        self._cwe78_transformer = Cwe78CmdInjectionTransformer()
        self._cwe22_transformer = Cwe22PathTraversalTransformer()
        self._rule_map: Dict[RemediationRule, BaseRemediationTransformer] = {
            RemediationRule.SQLI_PARAMETERIZE: self._cwe89_transformer,
            RemediationRule.CMD_INJECTION_SPLIT: self._cwe78_transformer,
            RemediationRule.PATH_TRAVERSAL_RESOLVE: self._cwe22_transformer,
        }
        self._cwe_map: Dict[str, BaseRemediationTransformer] = {
            "CWE-89": self._cwe89_transformer,
            "CWE-78": self._cwe78_transformer,
            "CWE-22": self._cwe22_transformer,
        }

    def get_transformer(
        self,
        cwe: Optional[str] = None,
        rule: Optional[Union[RemediationRule, str]] = None
    ) -> Optional[BaseRemediationTransformer]:
        """
        Retrieves the registered transformer for the given CWE or rule.
        Returns None if unsupported.
        """
        if rule is not None:
            try:
                rule_enum = RemediationRule(rule) if isinstance(rule, str) else rule
                if rule_enum in self._rule_map:
                    return self._rule_map[rule_enum]
            except ValueError:
                return None

        if cwe is not None:
            norm_cwe = str(cwe).strip().upper()
            if norm_cwe in self._cwe_map:
                return self._cwe_map[norm_cwe]

        return None
