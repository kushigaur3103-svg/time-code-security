#!/usr/bin/env python3
"""
TimeCodeSecurity (TCS) Git-Staged Scanner Module.

Provides pre-commit and staged scanning capabilities with full cross-file
semantic equivalence.
Reads files directly from Git Index Stage 0 (:0:<path>) without dirty working-tree drift.
Extracts transitive dependency closures statically via AST imports with zero broad rglob walks.
Filters findings to report only those affecting staged files (loaded != affected).
"""

import sys
import os
import ast
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any

# Resilience constants aligned with tcs_cli.py
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_LINE_LENGTH_CHARS = 10000
BINARY_PREFIX_BYTES = 8192


def get_git_repo_root(cwd: Optional[Path] = None) -> Optional[Path]:
    """
    Resolves the root directory of the current Git repository.
    Returns None if the directory is not inside a git repository or git fails.
    """
    check_dir = cwd if cwd is not None else Path.cwd()
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(check_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        if res.returncode == 0 and res.stdout.strip():
            return Path(res.stdout.strip()).resolve()
    except Exception:
        pass
    return None


def get_staged_git_files(
    repo_root: Path
) -> Tuple[List[str], List[str], List[Tuple[str, str]], List[str]]:
    """
    Queries git index for staged changes using NUL-delimited status.
    Returns:
        (staged_python_files, deleted_files, renamed_files, non_python_staged)
        All paths are normalized POSIX relative strings.
    """
    try:
        res = subprocess.run(
            ["git", "diff", "--cached", "--name-status", "-z"],
            cwd=str(repo_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False
        )
    except Exception:
        return [], [], [], []

    if res.returncode != 0:
        return [], [], [], []

    raw = res.stdout
    parts = raw.split(b"\x00")

    staged_py: List[str] = []
    staged_d: List[str] = []
    staged_r: List[Tuple[str, str]] = []
    non_py: List[str] = []

    idx = 0
    while idx < len(parts):
        token = parts[idx].decode("utf-8", errors="replace").strip()
        if not token:
            idx += 1
            continue
        status = token[0]
        if status in ("A", "C", "M"):
            if idx + 1 < len(parts):
                path = parts[idx + 1].decode("utf-8", errors="replace").replace("\\", "/")
                if path.endswith(".py"):
                    staged_py.append(path)
                else:
                    non_py.append(path)
                idx += 2
            else:
                idx += 1
        elif status == "D":
            if idx + 1 < len(parts):
                path = parts[idx + 1].decode("utf-8", errors="replace").replace("\\", "/")
                staged_d.append(path)
                idx += 2
            else:
                idx += 1
        elif status.startswith("R"):
            if idx + 2 < len(parts):
                old_p = parts[idx + 1].decode("utf-8", errors="replace").replace("\\", "/")
                new_p = parts[idx + 2].decode("utf-8", errors="replace").replace("\\", "/")
                staged_r.append((old_p, new_p))
                if new_p.endswith(".py"):
                    staged_py.append(new_p)
                else:
                    non_py.append(new_p)
                idx += 3
            else:
                idx += 1
        else:
            if idx + 1 < len(parts):
                idx += 2
            else:
                idx += 1

    return staged_py, staged_d, staged_r, non_py


def read_git_index_blob(repo_root: Path, rel_path: str) -> Optional[str]:
    """
    Extracts the EXACT content of a file from Git index stage 0 (:0:<path>).
    Enforces:
    - 5MB size ceiling
    - Binary blob rejection (NUL bytes in prefix)
    - Max line length resilience (10,000 characters)
    Returns decoded UTF-8 string or None if unreadable / skipped.
    """
    posix_path = rel_path.replace("\\", "/")
    try:
        res = subprocess.run(
            ["git", "show", f":0:{posix_path}"],
            cwd=str(repo_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False
        )
    except Exception:
        return None

    if res.returncode == 0:
        if b"\x00" in res.stdout[:BINARY_PREFIX_BYTES]:
            return None
        if len(res.stdout) > MAX_FILE_SIZE_BYTES:
            return None
        text = res.stdout.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if len(line) > MAX_LINE_LENGTH_CHARS:
                return None
        return text
    return None


class StaticImportDeclaration:
    def __init__(self, module: str, level: int, names: List[str]):
        self.module = module
        self.level = level
        self.names = names

    def __repr__(self):
        return f"StaticImport(mod='{self.module}', lvl={self.level}, names={self.names})"


def extract_static_imports(code: str) -> List[StaticImportDeclaration]:
    """
    Extracts all import declarations statically via AST walking.
    Handles 'import x', 'import x as y', 'from x import y', and relative imports.
    """
    imports: List[StaticImportDeclaration] = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return imports

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(StaticImportDeclaration(module=alias.name, level=0, names=[alias.asname or alias.name]))
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            names = [alias.asname or alias.name for alias in node.names]
            imports.append(StaticImportDeclaration(module=mod, level=getattr(node, "level", 0), names=names))
    return imports


def resolve_candidate_module_paths(importing_file_rel: str, imp: StaticImportDeclaration) -> List[str]:
    """
    Computes exact candidate module filepaths for an import declaration WITHOUT any filesystem walking.
    Handles:
    - from db import execute_helper (level 0)
    - import db (level 0)
    - from package.db import execute_helper (level 0)
    - import package.db (level 0)
    - from .db import execute_helper (level 1)
    - from .subpackage.db import execute_helper (level 1)
    - from ..common.db import execute_helper (level 2)
    """
    candidates: List[str] = []
    file_dir = Path(importing_file_rel).parent

    mod_rel_path = imp.module.replace(".", "/") if imp.module else ""

    if imp.level > 0:
        # Relative import
        base_dir = file_dir
        for _ in range(imp.level - 1):
            base_dir = base_dir.parent

        if mod_rel_path:
            cand1 = (base_dir / f"{mod_rel_path}.py").as_posix()
            cand2 = (base_dir / mod_rel_path / "__init__.py").as_posix()
            candidates.extend([cand1, cand2])
        else:
            # e.g., from . import db
            for name in imp.names:
                cand1 = (base_dir / f"{name}.py").as_posix()
                cand2 = (base_dir / name / "__init__.py").as_posix()
                candidates.extend([cand1, cand2])
    else:
        # Absolute import: check relative to importing file dir, and relative to repo root
        search_roots = [file_dir, Path(".")]

        for root in search_roots:
            cand1 = (root / f"{mod_rel_path}.py").as_posix()
            cand2 = (root / mod_rel_path / "__init__.py").as_posix()
            candidates.extend([cand1, cand2])

        # If it's a dotted import (e.g. from db.util import helper), also check top component
        top_comp = imp.module.split(".")[0]
        if top_comp != imp.module:
            for root in search_roots:
                candidates.append((root / f"{top_comp}.py").as_posix())
                candidates.append((root / top_comp / "__init__.py").as_posix())

    # Normalize clean paths (strip leading ./ or .)
    normalized: List[str] = []
    for c in candidates:
        norm = Path(c).as_posix()
        if norm.startswith("./"):
            norm = norm[2:]
        if norm and norm != "." and norm not in normalized:
            normalized.append(norm)
    return normalized


class GitIndexReader:
    """
    Batched Git Index Reader utilizing persistent 'git cat-file --batch'
    to eliminate per-file process spawning overhead on Windows.
    Enforces 5MB size limit, binary prefix rejection, and max line length resilience.
    """
    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self._proc: Optional[subprocess.Popen] = None

    def __enter__(self):
        try:
            self._proc = subprocess.Popen(
                ["git", "cat-file", "--batch"],
                cwd=str(self.repo_root),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        except Exception:
            self._proc = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if self._proc:
            try:
                if self._proc.stdin:
                    self._proc.stdin.close()
                self._proc.wait(timeout=1)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

    def read_blob(self, rel_path: str) -> Optional[str]:
        if not self._proc or not self._proc.stdin or not self._proc.stdout:
            return read_git_index_blob(self.repo_root, rel_path)

        posix_path = rel_path.replace("\\", "/")
        query = f":0:{posix_path}\n".encode("utf-8")
        try:
            self._proc.stdin.write(query)
            self._proc.stdin.flush()
            header = self._proc.stdout.readline()
            if not header or b"missing" in header:
                return None
            parts = header.split()
            if len(parts) < 3:
                return None
            size = int(parts[2])
            raw = self._proc.stdout.read(size)
            self._proc.stdout.read(1)  # trailing newline delimiter

            if size > MAX_FILE_SIZE_BYTES:
                return None
            if b"\x00" in raw[:BINARY_PREFIX_BYTES]:
                return None
            text = raw.decode("utf-8", errors="replace")
            for line in text.splitlines():
                if len(line) > MAX_LINE_LENGTH_CHARS:
                    return None
            return text
        except Exception:
            return read_git_index_blob(self.repo_root, rel_path)


def build_staged_dependency_closure(
    repo_root: Path,
    staged_py: List[str],
    staged_deleted: Optional[List[str]] = None,
    unstaged_source_policy: str = "index",
    use_batch: bool = True
) -> Tuple[Dict[str, str], Set[str], List[str]]:
    """
    Static Dependency Closure:
    1. Staged root files loaded strictly from Git index stage 0 (using batched git cat-file).
    2. Transitive candidate paths computed directly from AST import declarations.
    3. Lookups perform direct single-path index queries (Zero broad rglob!).
    4. Detects imports referencing files staged for deletion or unresolvable relative imports.
    Returns:
        (files_for_tracker, staged_set, unresolved_dependencies)
    """
    if os.environ.get("TCS_DISABLE_GIT_BATCH") == "1":
        use_batch = False

    files: Dict[str, str] = {}
    staged_set: Set[str] = set(staged_py)
    unresolved_dependencies: List[str] = []
    staged_deleted_set: Set[str] = {p.replace("\\", "/") for p in staged_deleted} if staged_deleted else set()

    with GitIndexReader(repo_root) as reader:
        def _get_blob(p: str) -> Optional[str]:
            if use_batch:
                return reader.read_blob(p)
            return read_git_index_blob(repo_root, p)

        # 1. Load staged files from Git index stage 0
        for sf in staged_py:
            content = _get_blob(sf)
            if content is not None:
                files[sf] = content

        to_process = list(files.keys())
        visited_files = set(to_process)

        while to_process:
            curr_file = to_process.pop(0)
            curr_code = files.get(curr_file, "")
            imports = extract_static_imports(curr_code)

            for imp in imports:
                candidates = resolve_candidate_module_paths(curr_file, imp)
                found_dep = False

                # Check if candidate matches a module staged for deletion
                deleted_target = None
                if staged_deleted_set:
                    for cand in candidates:
                        if cand in staged_deleted_set:
                            deleted_target = cand
                            break

                if deleted_target is not None:
                    unresolved_dependencies.append(
                        f"{curr_file}: imports '{imp.module}' which is staged for deletion ({deleted_target})"
                    )
                    continue

                for cand in candidates:
                    if cand in visited_files:
                        found_dep = True
                        break

                    dep_content = None
                    if unstaged_source_policy == "index":
                        dep_content = _get_blob(cand)
                    elif unstaged_source_policy == "working_tree":
                        cand_path = repo_root / cand
                        if cand_path.is_file():
                            try:
                                dep_content = cand_path.read_text(encoding="utf-8", errors="replace")
                            except Exception:
                                dep_content = None

                    if dep_content is not None:
                        visited_files.add(cand)
                        files[cand] = dep_content
                        to_process.append(cand)
                        found_dep = True
                        break

                if not found_dep and imp.module:
                    # Distinguish standard library / third-party packages from local broken relative imports
                    if imp.level > 0 or imp.module.startswith("."):
                        unresolved_dependencies.append(f"{curr_file}: unresolved relative import '{imp.module}'")

    return files, staged_set, unresolved_dependencies


def filter_findings_for_staged(findings: List[Dict[str, Any]], staged_set: Set[str]) -> List[Dict[str, Any]]:
    """
    Negative Space Filter:
    Only findings whose ProofGraph touches at least one staged file are reported.
    Enforces invariant: loaded_for_analysis != affected_by_change
    """
    affected: List[Dict[str, Any]] = []
    for f in findings:
        pg = f.get("proof_graph")
        if not pg:
            if f.get("file") in staged_set or f.get("source_file") in staged_set:
                affected.append(f)
            continue

        nodes = pg.get("nodes", [])
        graph_files = {n.get("file_path") for n in nodes if n.get("file_path")}
        if graph_files.intersection(staged_set):
            affected.append(f)
    return affected


def recompute_summary_metrics(
    original_summary: Dict[str, Any],
    filtered_findings: List[Dict[str, Any]],
    total_files: int,
    lines_scanned: int
) -> Dict[str, Any]:
    """
    Recomputes summary counts, score, and risk level after findings have been filtered
    for staged changes.
    """
    active_findings = [f for f in filtered_findings if not f.get("suppressed", False)]
    suppressed_findings = [f for f in filtered_findings if f.get("suppressed", False)]

    total_vulnerabilities = len(filtered_findings)
    active_vulnerabilities = len(active_findings)
    suppressed_vulnerabilities = len(suppressed_findings)

    critical_count = sum(1 for f in active_findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in active_findings if f.get("severity") == "HIGH")
    medium_count = sum(1 for f in active_findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in active_findings if f.get("severity") == "LOW")

    security_score = max(0, 100 - (critical_count * 25 + high_count * 15 + medium_count * 5))

    if active_vulnerabilities == 0:
        risk_level = "CLEAN"
        risk_message = "NO VULNERABILITIES DETECTED within current TCS analysis scope (24 supported CWE classes)."
    elif critical_count > 0:
        risk_level = "CRITICAL"
        risk_message = "CRITICAL RISK: Arbitrary code execution or high-impact injection detected."
    elif high_count > 0:
        risk_level = "HIGH"
        risk_message = "HIGH RISK: Injection or data traversal vulnerabilities detected."
    elif medium_count > 0:
        risk_level = "MEDIUM"
        risk_message = "MEDIUM RISK: Potential data-flow flaws detected."
    else:
        risk_level = "LOW"
        risk_message = "LOW RISK: Minor security notices."

    summary = dict(original_summary)
    summary.update({
        "total_files": total_files,
        "lines_scanned": lines_scanned,
        "total_vulnerabilities": total_vulnerabilities,
        "active_vulnerabilities": active_vulnerabilities,
        "suppressed_vulnerabilities": suppressed_vulnerabilities,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "security_score": security_score,
        "score_label": "Security Health Score",
        "risk_level": risk_level,
        "risk_message": risk_message
    })
    return summary
