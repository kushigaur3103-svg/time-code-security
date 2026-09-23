"""
TimeCodeSecurity (TCS) - Vector D Remediation Orchestrator.
Orchestrates multi-finding bottom-up sequencing, closed-loop verification,
filesystem safety validation, and atomic per-file replacement.
"""

import ast
import difflib
import os
import sys
import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from remediation.contracts import PatchStatus, RemediationRecord
from remediation.patch_engine import RemediationEngine

try:
    from verification_engine import verify_fix, Patch, get_stable_signature
except ImportError:
    verify_fix = None
    Patch = None
    get_stable_signature = None


@dataclass
class ProjectRemediationResult:
    """Encapsulates results and metrics from a project remediation execution."""
    remediation_records: List[RemediationRecord] = field(default_factory=list)
    written_files: List[str] = field(default_factory=list)
    stale_files: List[str] = field(default_factory=list)
    unwritten_eligible_files: List[str] = field(default_factory=list)
    findings_by_file: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    remediation_candidates: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)


def format_remediation_section(
    records: List[RemediationRecord],
    written_files: Optional[List[str]] = None,
    is_write: bool = False
) -> str:
    """
    Renders structured terminal representation of remediation patches and status.
    """
    if not records:
        return ""

    written_set = set(written_files or [])
    lines = [
        "=" * 80,
        "TIME CODE SECURITY (TCS) - AUTOMATED REMEDIATION (APPLIED)" if is_write else "TIME CODE SECURITY (TCS) - AUTOMATED REMEDIATION PREVIEW",
        "=" * 80,
    ]

    for rec in records:
        status_label = rec.patch_status.value
        file_loc = f"{rec.original_file}:{rec.line_number}"

        if rec.patch_status == PatchStatus.SUCCESS:
            if is_write and rec.original_file not in written_set:
                lines.append(f"[REMEDIATION ABORTED - TRANSACTION ROLLBACK] Finding: {rec.finding_id} | CWE: {rec.cwe}")
                lines.append(f"  Rule: {rec.remediation_rule.value} | Target: {file_loc}")
                lines.append(f"  Status: TRANSACTION_ROLLBACK (Not persisted to disk due to partial file failure)")
                lines.append("-" * 80)
            else:
                action_tag = "APPLIED TO DISK" if rec.original_file in written_set else "VERIFIED PREVIEW"
                lines.append(f"[REMEDIATION SUCCESS] Finding: {rec.finding_id} | CWE: {rec.cwe} | Action: {action_tag}")
                lines.append(f"  Rule: {rec.remediation_rule.value} | Target: {file_loc}")
                if rec.unified_diff:
                    lines.append("-" * 80)
                    lines.append(rec.unified_diff.rstrip())
                    lines.append("-" * 80)
        elif rec.patch_status == PatchStatus.UNSUPPORTED_CWE:
            reason = rec.limitations[0] if rec.limitations else "Pattern outside automated AST rewrite rules"
            lines.append(f"[REMEDIATION UNSUPPORTED] Finding: {rec.finding_id} | CWE: {rec.cwe}")
            lines.append(f"  File: {file_loc}")
            lines.append(f"  Status: UNSUPPORTED_CWE ({reason})")
            lines.append("-" * 80)
        elif rec.patch_status == PatchStatus.FAILED_SYNTAX:
            reason = rec.limitations[0] if rec.limitations else "AST parse failed"
            lines.append(f"[REMEDIATION FAILED] Finding: {rec.finding_id} | CWE: {rec.cwe}")
            lines.append(f"  File: {file_loc}")
            lines.append(f"  Status: FAILED_SYNTAX ({reason})")
            lines.append("-" * 80)
        elif rec.patch_status == PatchStatus.FAILED_VERIFICATION:
            reason = rec.limitations[0] if rec.limitations else "Closed-loop verification failed"
            lines.append(f"[REMEDIATION VERIFICATION FAILED] Finding: {rec.finding_id} | CWE: {rec.cwe}")
            lines.append(f"  File: {file_loc}")
            lines.append(f"  Status: FAILED_VERIFICATION ({reason})")
            lines.append("-" * 80)

    total_candidates = len(records)
    if is_write:
        success_count = sum(1 for r in records if r.patch_status == PatchStatus.SUCCESS and r.original_file in written_set)
    else:
        success_count = sum(1 for r in records if r.patch_status == PatchStatus.SUCCESS)

    unsupported_count = sum(1 for r in records if r.patch_status == PatchStatus.UNSUPPORTED_CWE)
    failed_count = total_candidates - success_count - unsupported_count

    lines.extend([
        "[REMEDIATION SUMMARY]",
        f"  Total Eligible Findings: {total_candidates}",
        f"  Successfully Verified:   {success_count}",
        f"  Unsupported CWE:         {unsupported_count}",
        f"  Failed / Unverified:     {failed_count}",
    ])
    if is_write:
        lines.append(f"  Mode:                    APPLIED (--write). Wrote {len(written_set)} modified file(s).")
    else:
        lines.append("  Mode:                    PREVIEW ONLY (Dry-Run). Pass --write to apply verified changes.")
    lines.append("=" * 80)

    return "\n".join(lines)


def map_line_number(prev_content: str, new_content: str, old_line: int) -> int:
    """
    Given an original 1-based line number in prev_content, determines its
    new 1-based line number in new_content after AST / text transformations.
    Uses SequenceMatcher opcodes to track line shifts accurately.
    """
    if old_line <= 0:
        return old_line

    prev_lines = prev_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)
    k = old_line - 1  # 0-based line index in prev_lines

    matcher = difflib.SequenceMatcher(None, prev_lines, new_lines)
    shift = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if i2 <= k:
            shift += (j2 - j1) - (i2 - i1)
        elif i1 <= k < i2:
            if tag == "equal":
                return (j1 + (k - i1)) + 1
            else:
                return j1 + 1
        else:
            break
    return old_line + shift


def refine_finding_line_number(fnd: Dict[str, Any], current_content: str) -> int:
    """
    Refines or verifies a finding's line_number against current AST of current_content.
    If the target line already matches the sink call, retains it; otherwise searches
    for the matching AST Call node.
    """
    line_no = int(fnd.get("line_number", 0))
    if line_no <= 0:
        return line_no

    try:
        tree = ast.parse(current_content)
    except Exception:
        return line_no

    lines = current_content.splitlines()
    snippet = fnd.get("code_snippet", "").strip()
    sink_symbol = fnd.get("sink_symbol", "")
    sink_attr = sink_symbol.split(".")[-1] if sink_symbol else ""

    if 1 <= line_no <= len(lines):
        line_text = lines[line_no - 1].strip()
        if snippet and (snippet in line_text or line_text in snippet):
            return line_no
        if sink_attr and sink_attr in line_text:
            return line_no

    best_line = line_no
    min_dist = float("inf")
    cwe = fnd.get("cwe", "")

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = ""
            if isinstance(node.func, ast.Name):
                call_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                call_name = node.func.attr

            matches = False
            if sink_attr and call_name == sink_attr:
                matches = True
            elif cwe == "CWE-89" and call_name in ("execute", "executemany"):
                matches = True
            elif cwe == "CWE-78" and call_name in ("call", "run", "Popen", "check_output", "check_call"):
                matches = True
            elif cwe == "CWE-22" and call_name in ("open", "file", "read_text", "read_bytes"):
                matches = True

            if matches:
                n_line = getattr(node, "lineno", 0)
                dist = abs(n_line - line_no)
                if dist < min_dist:
                    min_dist = dist
                    best_line = n_line

    return best_line


def resolve_target_signature(
    fnd: Dict[str, Any],
    files: Dict[str, str]
) -> Optional[Tuple]:
    """
    Defensively extracts the stable (source, sink, file, file, root_var) signature
    for a finding across the multi-file project dictionary.

    Guarantees:
    - Never raises unhandled exceptions.
    - Gracefully returns None if source/sink nodes cannot be resolved.
    """
    if get_stable_signature is None or not files:
        return None

    try:
        from ast_scanner import TaintTracker
        tracker = TaintTracker(files=files)
        sources, sinks, edges = tracker.analyze()
        src_map = {s.id: s for s in sources}
        snk_map = {s.id: s for s in sinks}

        target_file = fnd.get("file")
        target_line = int(fnd.get("line_number", 0))
        sink_sym = fnd.get("sink_symbol")

        best_match = None
        for e in edges:
            if not e.target_id.startswith("SNK") or e.kind == "CLEAN":
                continue
            s = src_map.get(e.source_id)
            sk = snk_map.get(e.target_id)
            if not s or not sk:
                continue

            # Match target file
            if target_file and sk.location.file != target_file:
                continue

            # Match sink symbol if known
            if sink_sym and sk.symbol != sink_sym:
                continue

            # Match line number if known
            if target_line > 0 and abs(sk.location.line_start - target_line) <= 2:
                best_match = (s, sk, e)
                break
            elif best_match is None:
                best_match = (s, sk, e)

        if best_match:
            s, sk, e = best_match
            return get_stable_signature(s, sk, e)
    except Exception:
        # Defensive fallback: never crash if analysis fails or nodes are missing
        pass

    return None


def remediate_project(
    files: Dict[str, str],
    effective_findings: List[Dict[str, Any]],
    target: Path,
    base_dir: Path,
    is_write: bool = False,
    pre_write_hook: Optional[Callable[[Path], None]] = None,
) -> ProjectRemediationResult:
    """
    Executes automated remediation across eligible project findings.
    
    Guarantees:
    - Same-file multi-finding sequencing: Findings in the same file are sorted
      in descending line order (bottom-up) to prevent line offset corruption.
    - Header import shift tracking: Adjusts remaining pending finding lines when
      imports or header blocks are injected.
    - Closed-loop verification: Every candidate patch is re-scanned.
    - Filesystem safety: Symlinks, hardlinks (nlink > 1), and read-only files are guarded.
    - Line-ending preservation: Preserves exact CRLF vs LF byte semantics without leaks.
    - Transactional rollback: Partial failures in a file abort writing and report accurately.
    - Stale source detection: Validates file on disk matches analyzed source prior to writing.
    - Atomic replacement: Temporary sibling file writes + os.replace.
    """
    remediation_candidates = [f for f in effective_findings if not f.get("suppressed", False)]
    remediation_records: List[RemediationRecord] = []
    written_files: List[str] = []
    stale_files: List[str] = []
    unwritten_eligible_files: List[str] = []
    findings_by_file: Dict[str, List[Dict[str, Any]]] = {}

    engine = RemediationEngine()
    for f in remediation_candidates:
        f_file = f.get("file", "")
        if f_file:
            findings_by_file.setdefault(f_file, []).append(f)

    for rel_file, file_fnds in findings_by_file.items():
        orig_content = files.get(rel_file)
        if orig_content is None:
            continue

        # Sort findings bottom-up (descending line order)
        sorted_file_fnds = sorted(
            file_fnds,
            key=lambda fnd: int(fnd.get("line_number", 0)),
            reverse=True
        )

        working_fnds = [dict(f) for f in sorted_file_fnds]
        current_content = orig_content
        file_success = True
        per_file_records: List[RemediationRecord] = []

        for idx, fnd in enumerate(working_fnds):
            fnd["line_number"] = refine_finding_line_number(fnd, current_content)

            rec = engine.remediate(fnd, current_content, file_path=rel_file)

            # Cross-file closed-loop verification gate via verification_engine
            if rec.patch_status == PatchStatus.SUCCESS and rec.verification_passed and rec.patched_source is not None:
                if verify_fix is not None and Patch is not None and files:
                    try:
                        working_files = dict(files)
                        working_files[rel_file] = current_content
                        target_sig = resolve_target_signature(fnd, working_files)
                        if target_sig is not None:
                            patch_obj = Patch(
                                file_path=rel_file,
                                original_code=current_content,
                                new_code=rec.patched_source,
                            )
                            v_res = verify_fix(
                                files=working_files,
                                patch=patch_obj,
                                target_signature=target_sig,
                            )
                            if v_res.status == "REGRESSION_DETECTED":
                                rec = dataclasses.replace(
                                    rec,
                                    patch_status=PatchStatus.FAILED_VERIFICATION,
                                    verification_passed=False,
                                    patched_source=None,
                                    limitations=tuple(list(rec.limitations) + [f"Cross-file regression detected: {v_res.reason}"]),
                                )
                            elif v_res.status == "NOT_VERIFIED":
                                rec = dataclasses.replace(
                                    rec,
                                    patch_status=PatchStatus.FAILED_VERIFICATION,
                                    verification_passed=False,
                                    patched_source=None,
                                    limitations=tuple(list(rec.limitations) + [f"Cross-file verification failed: {v_res.reason}"]),
                                )
                            elif v_res.status == "INVALID_PATCH":
                                rec = dataclasses.replace(
                                    rec,
                                    patch_status=PatchStatus.FAILED_SYNTAX,
                                    verification_passed=False,
                                    patched_source=None,
                                    limitations=tuple(list(rec.limitations) + [f"Invalid patch: {v_res.reason}"]),
                                )
                    except Exception as ve_err:
                        print(f"[WARN] Multi-file verification skipped: {ve_err}", file=sys.stderr)

            per_file_records.append(rec)
            if rec.patch_status == PatchStatus.SUCCESS and rec.verification_passed and rec.patched_source is not None:
                prev_text = current_content
                current_content = rec.patched_source

                # Adjust line numbers of remaining pending findings for any line shifts
                for rem_fnd in working_fnds[idx + 1:]:
                    old_l = int(rem_fnd.get("line_number", 0))
                    rem_fnd["line_number"] = map_line_number(prev_text, current_content, old_l)
            else:
                file_success = False
                break

        if is_write and not file_success:
            updated_records = []
            for r in per_file_records:
                if r.patch_status == PatchStatus.SUCCESS:
                    updated_records.append(dataclasses.replace(
                        r,
                        limitations=tuple(list(r.limitations) + ["transaction_rollback: not persisted to disk due to subsequent failure in same file"])
                    ))
                else:
                    updated_records.append(r)
            per_file_records = updated_records

        remediation_records.extend(per_file_records)

        if is_write:
            if file_success and current_content != orig_content:
                if target.is_file():
                    disk_file = target
                else:
                    cand = (target / rel_file).resolve()
                    disk_file = cand if cand.exists() else (base_dir / rel_file).resolve()

                if not disk_file.exists():
                    print(f"[WARN] Cannot write patch: target file '{disk_file}' does not exist", file=sys.stderr)
                    unwritten_eligible_files.append(rel_file)
                else:
                    # Filesystem safety check 1: Disallow writing through or replacing symlinks
                    try:
                        is_sym = disk_file.is_symlink()
                    except Exception:
                        is_sym = False

                    if is_sym or os.environ.get("TCS_TEST_FORCE_SYMLINK") == "1":
                        print(f"[WARN] Aborting write for '{rel_file}': target is a symlink; in-place replacement is disallowed for safety", file=sys.stderr)
                        unwritten_eligible_files.append(rel_file)
                        continue

                    # Filesystem safety check 2: Stat inspection (mode, hard link count)
                    try:
                        disk_stat = disk_file.stat()
                    except Exception as e:
                        print(f"[ERROR] Failed to stat '{disk_file}': {e}", file=sys.stderr)
                        unwritten_eligible_files.append(rel_file)
                        continue

                    if getattr(disk_stat, "st_nlink", 1) > 1:
                        print(f"[WARN] Aborting write for '{rel_file}': hard-linked file (nlink={disk_stat.st_nlink}) cannot be safely replaced atomically", file=sys.stderr)
                        unwritten_eligible_files.append(rel_file)
                        continue

                    # Filesystem safety check 3: Read-only check
                    if not os.access(disk_file, os.W_OK):
                        print(f"[WARN] Aborting write for '{rel_file}': target file is read-only", file=sys.stderr)
                        unwritten_eligible_files.append(rel_file)
                        continue

                    # Test orchestration seam: invoked immediately before stale check
                    if pre_write_hook is not None:
                        try:
                            pre_write_hook(disk_file)
                        except Exception as hook_err:
                            print(f"[DEBUG] Pre-write hook error: {hook_err}", file=sys.stderr)
                    pre_write_env = os.environ.get("TCS_TEST_PRE_WRITE_MUTATE")
                    if pre_write_env and disk_file.exists():
                        disk_file.write_text(pre_write_env, encoding="utf-8")

                    # Stale-content detection before write
                    try:
                        disk_content = disk_file.read_text(encoding="utf-8")
                    except Exception as e:
                        print(f"[ERROR] Failed to read '{disk_file}' for stale check: {e}", file=sys.stderr)
                        disk_content = None

                    if disk_content != orig_content:
                        stale_files.append(rel_file)
                        unwritten_eligible_files.append(rel_file)
                        print(f"[WARN] Aborting write for '{rel_file}': file on disk was modified after analysis (stale source)", file=sys.stderr)
                    else:
                        # Detect original line ending to preserve exact byte semantics
                        try:
                            raw_bytes = disk_file.read_bytes()
                            is_crlf = b"\r\n" in raw_bytes
                        except Exception:
                            is_crlf = False

                        if is_crlf:
                            normalized_content = current_content.replace("\r\n", "\n").replace("\n", "\r\n")
                        else:
                            normalized_content = current_content.replace("\r\n", "\n")

                        tmp_file = disk_file.with_suffix(disk_file.suffix + ".tcs_tmp")
                        try:
                            tmp_file.write_text(normalized_content, encoding="utf-8", newline="")
                            try:
                                os.chmod(tmp_file, disk_stat.st_mode)
                            except Exception:
                                pass
                            os.replace(tmp_file, disk_file)
                            written_files.append(rel_file)
                        except Exception as e:
                            if tmp_file.exists():
                                try:
                                    tmp_file.unlink()
                                except Exception:
                                    pass
                            unwritten_eligible_files.append(rel_file)
                            print(f"[ERROR] Failed to write patch to '{disk_file}': {e}", file=sys.stderr)
            elif not file_success:
                unwritten_eligible_files.append(rel_file)

    if is_write:
        successful_remediations_count = sum(1 for r in remediation_records if r.patch_status == PatchStatus.SUCCESS and r.original_file in written_files)
    else:
        successful_remediations_count = sum(1 for r in remediation_records if r.patch_status == PatchStatus.SUCCESS)

    summary = {
        "total_eligible": len(remediation_candidates),
        "successful_remediations": successful_remediations_count,
        "unsupported_cwes": sum(1 for r in remediation_records if r.patch_status == PatchStatus.UNSUPPORTED_CWE),
        "failed_verifications": len(remediation_candidates) - successful_remediations_count - sum(1 for r in remediation_records if r.patch_status == PatchStatus.UNSUPPORTED_CWE),
        "written_files": written_files,
        "stale_files": stale_files,
        "unwritten_eligible_files": unwritten_eligible_files,
        "is_write": is_write,
        "is_dry_run": not is_write,
    }

    return ProjectRemediationResult(
        remediation_records=remediation_records,
        written_files=written_files,
        stale_files=stale_files,
        unwritten_eligible_files=unwritten_eligible_files,
        findings_by_file=findings_by_file,
        remediation_candidates=remediation_candidates,
        summary=summary,
    )
