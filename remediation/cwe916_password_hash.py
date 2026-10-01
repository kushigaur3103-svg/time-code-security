"""
TimeCodeSecurity (TCS) - Vector D CWE-916 Weak Password Hash Transformer.
Implements deterministic AST-guided remediation replacing fast password hashes
(md5/sha1/sha256/sha512) with the memory-hard hashlib.scrypt KDF.

CWE-916 is about insufficient computational effort for password storage, so the
md5->sha256 swap used by the CWE-327 transformer cannot clear it: sha256 remains
a fast hash. scrypt is the minimal deterministic rewrite that removes the finding.
"""

from typing import Any, Dict, Optional, Tuple
import ast

from remediation.base import BaseRemediationTransformer
from remediation.contracts import RemediationRule, PatchStatus

WEAK_HASH_ATTRS = ("md5", "sha1", "sha256", "sha512")
SALT_PLACEHOLDER = "change-me-static-salt"


class Cwe916PasswordHashTransformer(BaseRemediationTransformer):
    """
    Deterministic AST transformer for CWE-916 (and its CWE-759 unsalted variant).
    Rewrites hashlib.<weak>(<password>) into
    hashlib.scrypt(<password>, salt=b"...", n=16384, r=8, p=1), dropping a
    trailing .hexdigest() since scrypt already returns bytes.
    """

    @property
    def rule(self) -> RemediationRule:
        return RemediationRule.PASSWORD_HASH_KDF

    def can_transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> bool:
        return self._find_weak_hash_call(tree, int(finding.get("line_number", 0))) is not None

    def transform(
        self,
        tree: ast.AST,
        finding: Dict[str, Any],
        source_code: str
    ) -> Tuple[PatchStatus, Optional[str], Optional[str], Tuple[str, ...]]:
        line_number = int(finding.get("line_number", 0))

        call_node = self._find_weak_hash_call(tree, line_number)
        if not call_node:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("Weak password hash call not found",))

        if not call_node.args:
            return (PatchStatus.UNSUPPORTED_CWE, None, None, ("Hash call has no password argument",))

        password_arg = call_node.args[0]

        call_node.func = ast.Attribute(
            value=ast.Name(id="hashlib", ctx=ast.Load()),
            attr="scrypt",
            ctx=ast.Load(),
        )
        call_node.args = [password_arg]
        call_node.keywords = [
            ast.keyword(arg="salt", value=ast.Constant(value=SALT_PLACEHOLDER.encode())),
            ast.keyword(arg="n", value=ast.Constant(value=16384)),
            ast.keyword(arg="r", value=ast.Constant(value=8)),
            ast.keyword(arg="p", value=ast.Constant(value=1)),
        ]

        parent = self._find_digest_parent(tree, call_node)
        if parent is not None:
            self._replace_node(tree, parent, call_node)

        try:
            patched_source = ast.unparse(ast.fix_missing_locations(tree))
        except Exception as e:
            return (PatchStatus.FAILED_SYNTAX, None, None, (f"AST unparse failed: {e}",))

        snippet = self.patched_statement_snippet(tree, source_code, line_number) or ""

        limitations = (
            "A static placeholder salt is emitted; derive a per-user salt with "
            "os.urandom(16) and store it alongside the hash before production use.",
        )
        return (PatchStatus.SUCCESS, patched_source, snippet, limitations)

    def _find_weak_hash_call(
        self,
        tree: ast.AST,
        line_number: int
    ) -> Optional[ast.Call]:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute) or func.attr not in WEAK_HASH_ATTRS:
                continue
            if not (isinstance(func.value, ast.Name) and func.value.id == "hashlib"):
                continue
            node_lineno = getattr(node, "lineno", 0)
            node_end = getattr(node, "end_lineno", node_lineno)
            if node_lineno <= line_number <= node_end or node_lineno == line_number:
                return node
        return None

    def _find_digest_parent(self, tree: ast.AST, call_node: ast.Call) -> Optional[ast.Call]:
        """Return a wrapping .hexdigest()/.digest() call whose value is the hash call."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in ("hexdigest", "digest")
                and func.value is call_node
            ):
                return node
        return None

    def _replace_node(self, tree: ast.AST, old_node: ast.Call, new_node: ast.AST) -> None:
        for parent in ast.walk(tree):
            for field, value in ast.iter_fields(parent):
                if value is old_node:
                    setattr(parent, field, new_node)
                    return
                if isinstance(value, list):
                    for i, item in enumerate(value):
                        if item is old_node:
                            value[i] = new_node
                            return
