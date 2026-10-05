"""Infrastructure-as-Code security auditor for TimeCodeSecurity.

Zero-dependency, deterministic analysis of two IaC artefact families:

* Dockerfiles -- CWE-250 / CWE-269 when a container's run instruction executes
  without a preceding non-root ``USER`` instruction.
* GitHub Actions workflows -- CWE-1357 / CWE-353 when a remote action step is
  referenced by a mutable tag or branch instead of an immutable commit SHA.

Findings are derived from parsed instruction nodes and structured ``uses:``
references. There is no whole-file pattern matching and no path allow-listing.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ── Dockerfile ────────────────────────────────────────────────────────────
RUN_INSTRUCTIONS = frozenset({"CMD", "ENTRYPOINT"})
# Values that keep the process running with full privileges.
ROOT_USER_VALUES = frozenset({"root", "0", "root:root", "0:0"})
CONTINUATION = "\\"

# ── GitHub Actions ────────────────────────────────────────────────────────
WORKFLOW_DIR_PARTS = frozenset({".github"})
WORKFLOW_SUBDIR = "workflows"
WORKFLOW_SUFFIXES: Tuple[str, ...] = (".yml", ".yaml")
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<value>[^\s#]+)\s*(?:#.*)?$")
# An immutable reference is a full 40-character commit SHA.
PINNED_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
LOCAL_ACTION_PREFIXES: Tuple[str, ...] = ("./", "../", "/", "docker://")


def is_dockerfile_path(path: str) -> bool:
    """True for ``Dockerfile``, ``Dockerfile.<variant>`` and ``<name>.dockerfile``."""
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.startswith("dockerfile") or name.endswith(".dockerfile")


def is_workflow_path(path: str) -> bool:
    """True for YAML documents inside a ``.github/workflows`` directory."""
    normalized = str(path).replace("\\", "/").lower()
    if not normalized.endswith(WORKFLOW_SUFFIXES):
        return False
    parts = normalized.split("/")
    for index, part in enumerate(parts[:-1]):
        if part in WORKFLOW_DIR_PARTS and index + 1 < len(parts) - 1:
            if parts[index + 1] == WORKFLOW_SUBDIR:
                return True
    return False


def is_iac_path(path: str) -> bool:
    return is_dockerfile_path(path) or is_workflow_path(path)


# ══════════════════════════════════════════════════════════════════════════
# Dockerfile analysis
# ══════════════════════════════════════════════════════════════════════════
def _parse_dockerfile_instructions(source: str) -> List[Tuple[int, str, str]]:
    """Return ``[(start_line, INSTRUCTION, arguments)]`` honouring line continuations."""
    instructions: List[Tuple[int, str, str]] = []
    logical: List[str] = []
    start_line = 0

    for lineno, raw in enumerate(source.splitlines(), start=1):
        line = raw.strip()
        if not logical:
            if not line or line.startswith("#"):
                continue
            start_line = lineno
        else:
            if not line or line.startswith("#"):
                # A comment or blank line inside a continuation ends the instruction.
                instructions.append(_split_instruction(start_line, " ".join(logical)))
                logical = []
                continue

        if line.endswith(CONTINUATION) and not line.endswith("\\\\"):
            logical.append(line[:-1].strip())
            continue

        logical.append(line)
        instructions.append(_split_instruction(start_line, " ".join(logical)))
        logical = []

    if logical:
        instructions.append(_split_instruction(start_line, " ".join(logical)))
    return [(line, kw, args) for line, kw, args in instructions if kw]


def _split_instruction(start_line: int, text: str) -> Tuple[int, str, str]:
    keyword, _, arguments = text.partition(" ")
    return start_line, keyword.strip().upper(), arguments.strip()


def _declares_non_root_user(instructions: Sequence[Tuple[int, str, str]]) -> bool:
    """True when the effective USER instruction drops root privileges.

    A variable reference (``USER ${APP_USER}``) cannot be resolved statically and is
    treated as an intentional privilege drop rather than guessed at.
    """
    effective: Optional[str] = None
    for _line, keyword, arguments in instructions:
        if keyword != "USER":
            continue
        value = arguments.split()[0].lower() if arguments.split() else ""
        effective = value
    if effective is None:
        return False
    if effective in ROOT_USER_VALUES:
        return False
    return True


def audit_dockerfile(file_path: str, source: str) -> List[Dict[str, Any]]:
    """Emit CWE-250 / CWE-269 findings for a Dockerfile that runs as root."""
    instructions = _parse_dockerfile_instructions(source)
    if not instructions:
        return []
    if _declares_non_root_user(instructions):
        return []

    cmd_lines = [line for line, kw, _ in instructions if kw == "CMD"]
    entrypoint_lines = [line for line, kw, _ in instructions if kw == "ENTRYPOINT"]
    if not cmd_lines and not entrypoint_lines:
        # Nothing is executed by the image itself; no privilege exposure to report.
        return []

    total_lines = max(1, len(source.splitlines()))
    findings: List[Dict[str, Any]] = []

    # CWE-250: the container's start command runs with root privileges.
    run_line = cmd_lines[-1] if cmd_lines else entrypoint_lines[-1]
    findings.append({
        "file": file_path,
        "line": max(1, min(run_line, total_lines)),
        "cwe": "CWE-250",
        "severity": "HIGH",
        "category": "EXECUTION_WITH_UNNECESSARY_PRIVILEGES",
        "message": (
            "CWE-250: Container service runs as root; missing non-root USER instruction."
            " Add USER <non-root> before the run instruction so a container escape does"
            " not inherit UID 0"
        ),
    })

    # CWE-269: an ENTRYPOINT executes before any privilege drop can take effect.
    if entrypoint_lines:
        findings.append({
            "file": file_path,
            "line": max(1, min(entrypoint_lines[-1], total_lines)),
            "cwe": "CWE-269",
            "severity": "HIGH",
            "category": "IMPROPER_PRIVILEGE_MANAGEMENT",
            "message": (
                "CWE-269: Container service runs as root; missing non-root USER instruction."
                " The ENTRYPOINT executes with UID 0 because no USER instruction precedes it"
            ),
        })

    return findings


# ══════════════════════════════════════════════════════════════════════════
# GitHub Actions workflow analysis
# ══════════════════════════════════════════════════════════════════════════
def _is_remote_action(action_name: str) -> bool:
    return not action_name.startswith(LOCAL_ACTION_PREFIXES)


def audit_workflow(file_path: str, source: str) -> List[Dict[str, Any]]:
    """Emit CWE-1357 / CWE-353 findings for actions pinned to a mutable reference."""
    findings: List[Dict[str, Any]] = []

    for lineno, raw in enumerate(source.splitlines(), start=1):
        match = USES_RE.match(raw)
        if not match:
            continue
        value = match.group("value").strip().strip("'\"")
        action_name, separator, reference = value.rpartition("@")
        if not separator or not action_name or not reference:
            continue
        if not _is_remote_action(action_name):
            continue
        if PINNED_SHA_RE.match(reference):
            continue

        message = (
            f"GitHub Action step is pinned to a mutable tag instead of an immutable"
            f" commit SHA: {action_name}@{reference}. Pin to the full 40-character"
            f" commit SHA so an upstream tag move cannot silently change the code that runs"
        )
        for cwe, category in (
            ("CWE-1357", "RELIANCE_ON_UNTRUSTED_COMPONENT"),
            ("CWE-353", "MISSING_REFERENCE_INTEGRITY"),
        ):
            findings.append({
                "file": file_path,
                "line": lineno,
                "cwe": cwe,
                "severity": "MEDIUM",
                "category": category,
                "message": f"{cwe}: {message}",
            })

    return findings


def audit_iac_file(file_path: str, source: str) -> List[Dict[str, Any]]:
    """Dispatch a single IaC document to the appropriate auditor."""
    if is_dockerfile_path(file_path):
        return audit_dockerfile(file_path, source)
    if is_workflow_path(file_path):
        return audit_workflow(file_path, source)
    return []


def audit_iac_files(files: Dict[str, str]) -> List[Dict[str, Any]]:
    """Audit a mapping of ``{file_path: source}`` IaC documents deterministically."""
    findings: List[Dict[str, Any]] = []
    for file_path in sorted(files):
        findings.extend(audit_iac_file(file_path, files[file_path]))
    return sorted(findings, key=lambda item: (item["file"], item["line"], item["cwe"]))
