"""
TimeCodeSecurity (TCS) - Vector D Deterministic AST Remediation Engine.
Orchestrates:
1. Finding intake
2. AST parse & rule dispatch
3. AST transformation & source splicing
4. Syntax & compilation validation gate (D-1)
5. Vector B closed-loop re-scan verification gate (D-2)
6. Unified diff generation
7. Frozen RemediationRecord production
"""

from typing import Any, Dict, List, Optional, Tuple
import ast
import difflib

from remediation.contracts import (
    PatchStatus,
    RemediationRule,
    RemediationRecord,
)
from remediation.dispatcher import RuleDispatcher
from remediation.verification import RemediationVerifier


class RemediationEngine:
    """
    Production deterministic AST remediation engine.
    Applies AST-guided vulnerability patches and enforces strict verification gates.
    """

    def __init__(
        self,
        dispatcher: Optional[RuleDispatcher] = None,
        verifier: Optional[RemediationVerifier] = None
    ):
        self.dispatcher = dispatcher or RuleDispatcher()
        self.verifier = verifier or RemediationVerifier()

    def remediate(
        self,
        finding: Dict[str, Any],
        source_code: str,
        file_path: Optional[str] = None
    ) -> RemediationRecord:
        """
        Executes the end-to-end deterministic remediation pipeline for a given finding.
        Never mutates the input source_code in place.
        """
        finding_id = str(finding.get("id", "TCS-REM-000"))
        cwe = str(finding.get("cwe", "UNKNOWN_CWE"))
        line_number = int(finding.get("line_number", 0))
        original_file = str(file_path or finding.get("file", "source.py"))
        original_snippet = str(finding.get("code_snippet", ""))

        # Rule mapping fallback for reporting non-SUCCESS states
        default_rule = RemediationRule.SQLI_PARAMETERIZE
        if cwe == "CWE-78":
            default_rule = RemediationRule.CMD_INJECTION_SPLIT
        elif cwe == "CWE-22":
            default_rule = RemediationRule.PATH_TRAVERSAL_RESOLVE

        # 1. Syntax check on original input source
        try:
            tree = ast.parse(source_code, filename=original_file)
        except (SyntaxError, ValueError) as se:
            return RemediationRecord(
                finding_id=finding_id,
                cwe=cwe,
                remediation_rule=default_rule,
                original_file=original_file,
                line_number=line_number,
                patch_status=PatchStatus.FAILED_SYNTAX,
                original_code_snippet=original_snippet,
                patched_code_snippet="",
                unified_diff="",
                verification_passed=False,
                limitations=(f"Original source code contains syntax error: {se}",)
            )

        # 2. Rule Dispatcher
        transformer = self.dispatcher.get_transformer(cwe=cwe)
        if not transformer:
            return RemediationRecord(
                finding_id=finding_id,
                cwe=cwe,
                remediation_rule=default_rule,
                original_file=original_file,
                line_number=line_number,
                patch_status=PatchStatus.UNSUPPORTED_CWE,
                original_code_snippet=original_snippet,
                patched_code_snippet="",
                unified_diff="",
                verification_passed=False,
                limitations=(f"Automated remediation for {cwe} is not supported in Phase 2",)
            )

        # 3. AST Transformation & Structural Validation
        status, patched_source, patched_snippet, limitations = transformer.transform(tree, finding, source_code)
        if status != PatchStatus.SUCCESS or patched_source is None:
            return RemediationRecord(
                finding_id=finding_id,
                cwe=cwe,
                remediation_rule=transformer.rule,
                original_file=original_file,
                line_number=line_number,
                patch_status=status,
                original_code_snippet=original_snippet,
                patched_code_snippet=patched_snippet or "",
                unified_diff="",
                verification_passed=False,
                limitations=limitations or ("Code construct or SQL pattern is unsupported for automated parameterization",)
            )

        # 5. Syntax Gate (D-1)
        try:
            patched_tree = ast.parse(patched_source, filename=original_file)
            compile(patched_tree, original_file, "exec")
        except (SyntaxError, ValueError) as se:
            return RemediationRecord(
                finding_id=finding_id,
                cwe=cwe,
                remediation_rule=transformer.rule,
                original_file=original_file,
                line_number=line_number,
                patch_status=PatchStatus.FAILED_SYNTAX,
                original_code_snippet=original_snippet,
                patched_code_snippet=patched_snippet or "",
                unified_diff="",
                verification_passed=False,
                limitations=(f"Patched code failed syntax or compile validation: {se}",)
            )

        # 6. Vector B Closed-Loop Re-Scan Verification Gate (D-2)
        verify_passed, verify_err = self.verifier.verify(
            original_file=original_file,
            original_source=source_code,
            patched_source=patched_source,
            target_finding=finding
        )
        if not verify_passed:
            return RemediationRecord(
                finding_id=finding_id,
                cwe=cwe,
                remediation_rule=transformer.rule,
                original_file=original_file,
                line_number=line_number,
                patch_status=PatchStatus.FAILED_VERIFICATION,
                original_code_snippet=original_snippet,
                patched_code_snippet=patched_snippet or "",
                unified_diff="",
                verification_passed=False,
                limitations=(f"Re-scan verification failed: {verify_err}",)
            )

        # 7. Unified Diff Generation
        orig_lines = source_code.splitlines(keepends=True)
        patched_lines = patched_source.splitlines(keepends=True)
        norm_file = original_file.replace("\\", "/")
        diff_lines = list(difflib.unified_diff(
            orig_lines,
            patched_lines,
            fromfile=f"a/{norm_file}",
            tofile=f"b/{norm_file}"
        ))
        diff_str = "".join(diff_lines)

        # 8. Success Record
        return RemediationRecord(
            finding_id=finding_id,
            cwe=cwe,
            remediation_rule=transformer.rule,
            original_file=original_file,
            line_number=line_number,
            patch_status=PatchStatus.SUCCESS,
            original_code_snippet=original_snippet,
            patched_code_snippet=patched_snippet or "",
            unified_diff=diff_str,
            verification_passed=True,
            limitations=limitations,
            patched_source=patched_source
        )
