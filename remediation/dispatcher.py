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
from remediation.cwe614_cookie import Cwe614CookieSecureTransformer
from remediation.cwe1336_jinja import Cwe1336JinjaAutoescapeTransformer
from remediation.cwe327_weak_hash import Cwe327WeakHashTransformer
from remediation.cwe502_yaml import Cwe502YamlSafeLoaderTransformer
from remediation.cwe798_credentials import Cwe798CredentialsTransformer


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
        self._cwe614_transformer = Cwe614CookieSecureTransformer()
        self._cwe1336_transformer = Cwe1336JinjaAutoescapeTransformer()
        self._cwe327_transformer = Cwe327WeakHashTransformer()
        self._cwe502_transformer = Cwe502YamlSafeLoaderTransformer()
        self._cwe798_transformer = Cwe798CredentialsTransformer()
        
        self._rule_map: Dict[RemediationRule, BaseRemediationTransformer] = {
            RemediationRule.SQLI_PARAMETERIZE: self._cwe89_transformer,
            RemediationRule.CMD_INJECTION_SPLIT: self._cwe78_transformer,
            RemediationRule.PATH_TRAVERSAL_RESOLVE: self._cwe22_transformer,
            RemediationRule.COOKIE_SECURE_FLAGS: self._cwe614_transformer,
            RemediationRule.TEMPLATE_AUTOESCAPE: self._cwe1336_transformer,
            RemediationRule.WEAK_HASH_REPLACE: self._cwe327_transformer,
            RemediationRule.YAML_SAFE_LOADER: self._cwe502_transformer,
            RemediationRule.CREDENTIAL_ENVIRON_GET: self._cwe798_transformer,
        }
        self._cwe_map: Dict[str, BaseRemediationTransformer] = {
            "CWE-89": self._cwe89_transformer,
            "CWE-78": self._cwe78_transformer,
            "CWE-22": self._cwe22_transformer,
            "CWE-614": self._cwe614_transformer,
            "CWE-1275": self._cwe614_transformer,
            "CWE-1336": self._cwe1336_transformer,
            "CWE-327": self._cwe327_transformer,
            "CWE-502": self._cwe502_transformer,
            "CWE-798": self._cwe798_transformer,
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
