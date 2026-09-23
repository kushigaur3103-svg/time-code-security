from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple
from ast_scanner import TaintTracker

@dataclass
class Patch:
    file_path: str
    original_code: str
    new_code: str

@dataclass
class VerificationResult:
    status: str
    reason: str
    patched_files: Dict[str, str] = None
    regression_findings: List[str] = None
    limitations: List[str] = None

def get_stable_signature(source_node, sink_node, edge):
    # Extract the root variable names from the path to distinguish parallel flows reliably (e.g. app.py:x vs app.py:y)
    # The path usually looks like "SRC-001 -> app.py:x -> ..."
    parts = (edge.transform or "").split(" -> ")
    root_vars = [p for p in parts if ":" in p and not p.startswith("return")]
    root_var = root_vars[0] if root_vars else "unknown"
    return (source_node.symbol, sink_node.symbol, source_node.location.file, sink_node.location.file, root_var)

def verify_fix(files: Dict[str, str], patch: Patch, target_signature: Tuple) -> VerificationResult:
    limitations = [
        "OOP dispatch blindspots remain",
        "No field sensitivity for collections",
        "Single-file patch assumption per verification cycle",
        "Dynamic imports unverified"
    ]
    
    if patch.original_code == patch.new_code:
        return VerificationResult("NOT_VERIFIED", "No-op patch (identical source code)", None, None, limitations)
        
    if patch.file_path not in files:
        return VerificationResult("INVALID_PATCH", f"Target file {patch.file_path} not found", None, None, limitations)
        
    if patch.original_code not in files[patch.file_path]:
        return VerificationResult("INVALID_PATCH", "Original snippet not found in target file", None, None, limitations)

    # 1. Isolate and apply patch (In-memory only)
    patched_files = files.copy()
    patched_files[patch.file_path] = files[patch.file_path].replace(patch.original_code, patch.new_code, 1)

    # 2. Syntax/AST Validation
    for path, code in patched_files.items():
        try:
            ast.parse(code, filename=path)
        except SyntaxError as e:
            return VerificationResult("INVALID_PATCH", f"SyntaxError in {path}: {e}", None, None, limitations)

    # 3. Baseline Scan
    orig_tracker = TaintTracker(files=files)
    orig_src, orig_snk, orig_edges = orig_tracker.analyze()
    orig_src_map = {s.id: s for s in orig_src}
    orig_snk_map = {s.id: s for s in orig_snk}
    orig_signatures = set()
    for e in orig_edges:
        s, sk = orig_src_map.get(e.source_id), orig_snk_map.get(e.target_id)
        if s and sk and e.kind != "CLEAN" and e.target_id.startswith("SNK"):
            orig_signatures.add(get_stable_signature(s, sk, e))

    # 4. Re-scan Patched Code
    patch_tracker = TaintTracker(files=patched_files)
    patch_src, patch_snk, patch_edges = patch_tracker.analyze()
    patch_src_map = {s.id: s for s in patch_src}
    patch_snk_map = {s.id: s for s in patch_snk}
    patch_signatures = set()
    for e in patch_edges:
        s, sk = patch_src_map.get(e.source_id), patch_snk_map.get(e.target_id)
        if s and sk and e.kind != "CLEAN" and e.target_id.startswith("SNK"):
            patch_signatures.add(get_stable_signature(s, sk, e))

    # 5. Check Target Removal
    if target_signature in patch_signatures:
        return VerificationResult("NOT_VERIFIED", "Target vulnerability remains reachable", patched_files, None, limitations)

    # 6. Check Regressions
    regressions = patch_signatures - orig_signatures
    if regressions:
        return VerificationResult("REGRESSION_DETECTED", "Patch introduced new vulnerabilities", patched_files, list(regressions), limitations)

    # 7. Verdict
    return VerificationResult("VERIFIED_FIX", "Vulnerability securely remediated with no regressions", patched_files, None, limitations)