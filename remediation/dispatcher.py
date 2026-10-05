"""
TimeCodeSecurity - Vector D Remediation Rule Dispatcher.
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
from remediation.cwe916_password_hash import Cwe916PasswordHashTransformer
from remediation.cwe502_yaml import Cwe502YamlSafeLoaderTransformer
from remediation.cwe798_credentials import Cwe798CredentialsTransformer
from remediation.cwe489_debug import Cwe489DebugFlagTransformer
from remediation.cwe295_ssl import Cwe295SslVerificationTransformer
from remediation.cwe377_tempfile import Cwe377TempfileTransformer
from remediation.cwe95_eval import Cwe95EvalTransformer
from remediation.cwe1188_binding import Cwe1188NetworkBindingTransformer


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
        self._cwe916_transformer = Cwe916PasswordHashTransformer()
        self._cwe502_transformer = Cwe502YamlSafeLoaderTransformer()
        self._cwe798_transformer = Cwe798CredentialsTransformer()
        self._cwe489_transformer = Cwe489DebugFlagTransformer()
        self._cwe295_transformer = Cwe295SslVerificationTransformer()
        self._cwe377_transformer = Cwe377TempfileTransformer()
        self._cwe95_transformer = Cwe95EvalTransformer()
        self._cwe1188_transformer = Cwe1188NetworkBindingTransformer()
        
        self._rule_map: Dict[RemediationRule, BaseRemediationTransformer] = {
            RemediationRule.SQLI_PARAMETERIZE: self._cwe89_transformer,
            RemediationRule.CMD_INJECTION_SPLIT: self._cwe78_transformer,
            RemediationRule.PATH_TRAVERSAL_RESOLVE: self._cwe22_transformer,
            RemediationRule.COOKIE_SECURE_FLAGS: self._cwe614_transformer,
            RemediationRule.TEMPLATE_AUTOESCAPE: self._cwe1336_transformer,
            RemediationRule.WEAK_HASH_REPLACE: self._cwe327_transformer,
            RemediationRule.PASSWORD_HASH_KDF: self._cwe916_transformer,
            RemediationRule.YAML_SAFE_LOADER: self._cwe502_transformer,
            RemediationRule.CREDENTIAL_ENVIRON_GET: self._cwe798_transformer,
            RemediationRule.DEBUG_FLAG_DISABLE: self._cwe489_transformer,
            RemediationRule.SSL_VERIFY_ENABLE: self._cwe295_transformer,
            RemediationRule.TEMPFILE_SECURE: self._cwe377_transformer,
            RemediationRule.EVAL_LITERAL_REPLACE: self._cwe95_transformer,
            RemediationRule.NETWORK_BINDING_LOCALHOST: self._cwe1188_transformer,
        }
        self._cwe_map: Dict[str, BaseRemediationTransformer] = {
            "CWE-89": self._cwe89_transformer,
            "CWE-78": self._cwe78_transformer,
            "CWE-22": self._cwe22_transformer,
            "CWE-614": self._cwe614_transformer,
            "CWE-1275": self._cwe614_transformer,
            # Alias: CWE-668 (Exposure of Resource to Wrong Sphere) shares the
            # cookie-flags root cause.
            "CWE-668": self._cwe614_transformer,
            "CWE-1336": self._cwe1336_transformer,
            # Alias: CWE-116 (Improper Encoding/Escaping of Output) covers the
            # Jinja2 autoescape remediation.
            "CWE-116": self._cwe1336_transformer,
            "CWE-327": self._cwe327_transformer,
            # Alias: CWE-916 / CWE-759 (weak or unsalted password hashing) needs a
            # slow KDF; the sha256 swap would not clear these findings.
            "CWE-916": self._cwe916_transformer,
            "CWE-759": self._cwe916_transformer,
            "CWE-502": self._cwe502_transformer,
            "CWE-798": self._cwe798_transformer,
            "CWE-489": self._cwe489_transformer,
            "CWE-295": self._cwe295_transformer,
            "CWE-377": self._cwe377_transformer,
            "CWE-95": self._cwe95_transformer,
            "CWE-1188": self._cwe1188_transformer,
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
