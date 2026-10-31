"""
Inline Suppression Resolver for TimeCodeSecurity.
Deterministically parses in-source suppression directives and applies
non-destructive suppression flags to AST scan findings.

Supported syntax:
    # tcs:ignore CWE-89
    # tcs:ignore CWE-89: justification text
    # tcs:ignore cwe-89
    # tcs:ignore all
    # tcs:ignore all: justification text
    # tcs:ignore CWE-89, CWE-78: justification text
    # tcs: ignore[CWE-611]
    # tcs: ignore[ALL]: justification text

The bracketed form is scoped to the one line it sits on: it silences a finding only when the
finding's own line is that line and only for the CWE names inside the brackets. The older
unbracketed form keeps its historical scope (same line, or the comment block immediately above
a statement), because `app.py` and `tcs_cli.py` already ship that behaviour.
"""

import io
import re
import tokenize
from typing import Dict, List, Optional, Set, Any, Tuple


# Regex pattern to identify tcs:ignore comment directives
TCS_IGNORE_PATTERN = re.compile(r'#\s*tcs\s*:\s*ignore\b\s*(.*)', re.IGNORECASE)

# Bracketed, exact-line form: `# tcs: ignore[CWE-611]` or `# tcs: ignore[ALL]`.
TCS_IGNORE_BRACKET_PATTERN = re.compile(
    r'#\s*tcs\s*:\s*ignore\s*\[([^\]]*)\]\s*(.*)', re.IGNORECASE)


def normalize_cwe_target(val: str) -> Optional[str]:
    """
    Normalizes a directive target string (e.g. 'cwe-89', '89', 'all') to standard format.
    Returns: 'CWE-<NUM>', 'ALL', or None if unrecognized.
    """
    v = val.strip().upper()
    if not v:
        return None
    if v == "ALL":
        return "ALL"
    if v.startswith("CWE-"):
        num_part = v[4:].strip()
        if num_part.isdigit():
            return f"CWE-{num_part}"
        return v
    if v.startswith("CWE"):
        num_part = v[3:].strip("-")
        if num_part.isdigit():
            return f"CWE-{num_part}"
    if v.isdigit():
        return f"CWE-{v}"
    return None


def parse_directive_payload(payload: str) -> Optional[Dict[str, Any]]:
    """
    Parses the text following '# tcs:ignore'.
    Returns a dict with 'targets' (Set[str]) and 'justification' (Optional[str]),
    or None if malformed.
    """
    payload = payload.strip()
    if not payload:
        return None

    justification: Optional[str] = None
    if ":" in payload:
        targets_part, just_part = payload.split(":", 1)
        justification = just_part.strip() or None
    else:
        targets_part = payload

    targets_part = targets_part.strip()
    if not targets_part:
        return None

    raw_items = [t.strip() for t in re.split(r'[,;]+', targets_part) if t.strip()]
    if not raw_items:
        return None

    normalized_targets: Set[str] = set()
    for item in raw_items:
        norm = normalize_cwe_target(item)
        if norm:
            normalized_targets.add(norm)

    if not normalized_targets:
        return None

    return {
        "targets": normalized_targets,
        "justification": justification
    }


def extract_file_directives(source_code: str) -> Dict[int, List[Dict[str, Any]]]:
    """
    Extracts all valid tcs:ignore directives from source_code indexed by 1-based line number.
    Uses Python tokenize to ignore string literals that happen to contain '# tcs:ignore'.
    Falls back to line-by-line scanning if tokenization encounters a syntax error.
    """
    directives_by_line: Dict[int, List[Dict[str, Any]]] = {}
    comments: List[Tuple[int, str]] = []

    try:
        reader = io.StringIO(source_code).readline
        tokens = tokenize.generate_tokens(reader)
        for tok in tokens:
            if tok.type == tokenize.COMMENT:
                comments.append((tok.start[0], tok.string))
    except Exception:
        for idx, line in enumerate(source_code.splitlines(), start=1):
            if "#" in line:
                comments.append((idx, line[line.index("#"):]))

    for line_num, comment_str in comments:
        bracket = TCS_IGNORE_BRACKET_PATTERN.search(comment_str)
        if bracket:
            parsed = parse_directive_payload(bracket.group(1))
            if parsed:
                tail = bracket.group(2).strip()
                if tail.startswith(":") and tail[1:].strip():
                    parsed["justification"] = tail[1:].strip()
                parsed["line"] = line_num
                parsed["exact_line"] = True
                directives_by_line.setdefault(line_num, []).append(parsed)
            continue
        m = TCS_IGNORE_PATTERN.search(comment_str)
        if not m:
            continue
        parsed = parse_directive_payload(m.group(1))
        if parsed:
            parsed["line"] = line_num
            parsed["exact_line"] = False
            directives_by_line.setdefault(line_num, []).append(parsed)

    return directives_by_line


def find_matching_directive(
    sink_line: int,
    cwe: str,
    directives_by_line: Dict[int, List[Dict[str, Any]]],
    source_lines: List[str]
) -> Optional[Dict[str, Any]]:
    """
    Finds an applicable directive for a sink at sink_line targeting the given CWE.
    Checks:
      1. Same-line (sink_line)
      2. Previous-line (sink_line - 1)
      3. Upward contiguous comment block immediately preceding the sink statement.
    Stops search upward immediately if any code statement is encountered.
    """
    norm_cwe = cwe.upper()

    # 1. Check same line
    if sink_line in directives_by_line:
        for d in directives_by_line[sink_line]:
            if "ALL" in d["targets"] or norm_cwe in d["targets"]:
                return d

    # 2. Check previous lines (moving upward from sink_line - 1)
    curr_line = sink_line - 1
    max_steps = 10
    steps = 0

    while curr_line >= 1 and steps < max_steps:
        steps += 1
        line_content = source_lines[curr_line - 1] if curr_line - 1 < len(source_lines) else ""
        stripped = line_content.strip()

        # If line has directives, check them. A bracketed directive is scoped to its own
        # line only, so it is not allowed to travel upward onto a later statement.
        if curr_line in directives_by_line:
            for d in directives_by_line[curr_line]:
                if d.get("exact_line"):
                    continue
                if "ALL" in d["targets"] or norm_cwe in d["targets"]:
                    return d
            curr_line -= 1
            continue

        # If empty or blank line, allow bridging comment block to statement
        if not stripped:
            curr_line -= 1
            continue

        # If ordinary comment, continue scanning upward
        if stripped.startswith("#"):
            curr_line -= 1
            continue

        # Encountered actual code statement: stop searching
        break

    return None


def resolve_line_suppressions(
    findings: List[Dict[str, Any]],
    normalized_files: Dict[str, str]
) -> List[Dict[str, Any]]:
    """Mark findings silenced by an exact-line `# tcs: ignore[CWE-XXX]` directive.

    Only the bracketed form is consulted here, and only on the finding's own line: a
    `# tcs: ignore[CWE-611]` written next to a statement cannot hide a finding on the line
    above or below it. Files without the substring `tcs` are never tokenized, so a tree
    that uses no directives pays one case-folded scan per file and nothing else.
    """
    if not findings:
        return findings

    exact_directives: Dict[str, Dict[int, List[Dict[str, Any]]]] = {}
    for fpath, content in normalized_files.items():
        if "tcs" not in content.lower():
            continue
        by_line: Dict[int, List[Dict[str, Any]]] = {}
        for line, entries in extract_file_directives(content).items():
            kept = [entry for entry in entries if entry.get("exact_line")]
            if kept:
                by_line[line] = kept
        if by_line:
            exact_directives[fpath] = by_line

    for finding in findings:
        line = finding.get("line")
        directives = exact_directives.get(str(finding.get("file", "")))
        if not directives or not isinstance(line, int):
            continue
        cwe = str(finding.get("cwe", "")).upper()
        for directive in directives.get(line, []):
            if "ALL" in directive["targets"] or cwe in directive["targets"]:
                finding["suppressed"] = True
                finding["suppression_justification"] = directive.get("justification")
                finding["suppression_kind"] = "inSourceLine"
                break

    return findings


def resolve_suppressions(
    findings: List[Dict[str, Any]],
    normalized_files: Dict[str, str]
) -> List[Dict[str, Any]]:
    """
    Evaluates in-source suppression directives against detected findings.
    Modifies findings non-destructively by attaching suppression status and justification.
    """
    # Pre-extract directives per file
    file_directives: Dict[str, Dict[int, List[Dict[str, Any]]]] = {}
    file_lines: Dict[str, List[str]] = {}

    for fpath, content in normalized_files.items():
        file_directives[fpath] = extract_file_directives(content)
        file_lines[fpath] = content.splitlines()

    for finding in findings:
        fpath = finding.get("file", "")
        sink_line = int(finding.get("line_number") or 1)
        cwe = str(finding.get("cwe", ""))

        dirs = file_directives.get(fpath, {})
        lines = file_lines.get(fpath, [])

        matched = find_matching_directive(sink_line, cwe, dirs, lines)

        if matched is not None:
            finding["suppressed"] = True
            finding["suppression_justification"] = matched.get("justification")
            finding["suppression_kind"] = "inSource"
            finding["active"] = False
        else:
            finding["suppressed"] = False
            finding["suppression_justification"] = None
            finding["suppression_kind"] = None
            finding["active"] = True

    return findings
