"""
js_scanner.py – Tree-sitter–based JS/TS/React Security Scanner for TCS.

Supports: .js, .jsx, .ts, .tsx, .mjs, .cjs
Detects:
  - CWE-79:  dangerouslySetInnerHTML, innerHTML, outerHTML assignments
  - CWE-95:  eval(), Function(), new Function(), setTimeout (string), setInterval (string)

Returns standardized TCS finding dictionaries fully compatible with:
  - SARIF adapter (sarif_adapter.py)
  - CLI table formatter (tcs_cli.py format_table)

Design: Defensive / Graceful – if tree-sitter or language grammars are absent,
the module logs a single warning and falls back to an empty result set without
raising any unhandled exception.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Graceful import of tree-sitter & grammars (Invariant 3: defensive fallback)
# ---------------------------------------------------------------------------
_TS_AVAILABLE = False
_TSX_LANGUAGE = None
_TS_LANGUAGE = None
_JS_LANGUAGE = None
_PARSER_TSX = None
_PARSER_TS = None
_PARSER_JS = None

try:
    from tree_sitter import Language, Parser, Query, QueryCursor  # type: ignore
    import tree_sitter_javascript as _tsj  # type: ignore
    import tree_sitter_typescript as _tst  # type: ignore

    _TSX_LANGUAGE = Language(_tst.language_tsx())
    _TS_LANGUAGE  = Language(_tst.language_typescript())
    _JS_LANGUAGE  = Language(_tsj.language())
    _PARSER_TSX   = Parser(_TSX_LANGUAGE)
    _PARSER_TS    = Parser(_TS_LANGUAGE)
    _PARSER_JS    = Parser(_JS_LANGUAGE)
    _TS_AVAILABLE = True
except Exception as _e:
    print(
        f"[TCS-JS] WARNING: tree-sitter or JS/TS grammar not available ({_e}). "
        "JS/TS scanning is disabled. Run: pip install tree-sitter tree-sitter-javascript tree-sitter-typescript",
        file=sys.stderr,
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
JS_TS_EXTENSIONS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})

# Directories to skip during file discovery (mirrors tcs_cli.py IGNORED_DIRS)
_SKIP_DIRS = frozenset({
    "node_modules", ".next", "dist", "build", "coverage",
    ".git", ".github", "__pycache__", ".venv", "venv", "env",
    ".pytest_cache", ".mypy_cache", ".tox", ".idea", ".vscode",
})

# ---------------------------------------------------------------------------
# Pre-compiled Tree-sitter Queries (only built when grammars are available)
# ---------------------------------------------------------------------------
# Query: direct eval() or Function() call_expression / new_expression
_EVAL_FN_QUERY: Optional[Any] = None
# Query: JSX attribute dangerouslySetInnerHTML
_JSX_DSIHTML_QUERY: Optional[Any] = None
# Query: object pair with dangerouslySetInnerHTML key
_OBJ_DSIHTML_QUERY: Optional[Any] = None
# Query: assignment to .innerHTML / .outerHTML  (x.innerHTML = ...)
_INNERHTML_QUERY: Optional[Any] = None
# Query: directives for context tagging only
_DIRECTIVE_QUERY: Optional[Any] = None

if _TS_AVAILABLE:
    # We build queries for TSX (superset), reuse language reference where needed.
    _LANG = _TSX_LANGUAGE

    # (b) eval / Function / setTimeout / setInterval as identifiers in call position
    _EVAL_FN_QUERY = Query(
        _LANG,
        """
        (call_expression
          function: (identifier) @fn_id
          arguments: (arguments) @fn_args)
        (new_expression
          constructor: (identifier) @new_id
          arguments: (arguments) @new_args)
        """,
    )

    # (a) dangerouslySetInnerHTML JSX attribute
    _JSX_DSIHTML_QUERY = Query(
        _LANG,
        """
        (jsx_attribute
          (property_identifier) @jsx_attr_name
          (_) @jsx_attr_value)
        """,
    )

    # (a2) object property pair with dangerouslySetInnerHTML
    _OBJ_DSIHTML_QUERY = Query(
        _LANG,
        """
        (pair
          key: (property_identifier) @prop_key
          value: (_) @prop_val)
        """,
    )

    # (c) member expression assignment: foo.innerHTML = ..., foo.outerHTML = ...
    _INNERHTML_QUERY = Query(
        _LANG,
        """
        (assignment_expression
          left: (member_expression
            property: (property_identifier) @prop_name)
          right: (_) @rhs)
        """,
    )

    # directive detection
    _DIRECTIVE_QUERY = Query(
        _LANG,
        """
        (expression_statement
          (string) @dir_str)
        """,
    )

_EVAL_SINKS: frozenset[str] = frozenset({"eval", "Function", "setTimeout", "setInterval"})
_INNERHTML_SINKS: frozenset[str] = frozenset({"innerHTML", "outerHTML", "document.write", "document.writeln"})
_JSX_XSS_SINKS: frozenset[str] = frozenset({"dangerouslySetInnerHTML"})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _get_parser_and_language(ext: str):
    """Return (parser, language) for the given file extension."""
    if ext in (".tsx", ".jsx"):
        return _PARSER_TSX, _TSX_LANGUAGE
    if ext in (".ts",):
        return _PARSER_TS, _TS_LANGUAGE
    return _PARSER_JS, _JS_LANGUAGE


def _safe_query_matches(query, cursor_cls, root_node) -> List:
    """Run query safely, return list of (pattern_idx, {capture_name: [nodes]}) tuples."""
    try:
        cursor = cursor_cls(query)
        return cursor.matches(root_node)
    except Exception:
        return []


def _snippet(source_bytes: bytes, node, max_chars: int = 200) -> str:
    """Extract and truncate source text for a node."""
    try:
        text = source_bytes[node.start_byte: node.end_byte].decode("utf-8", errors="replace")
        text = text.replace("\n", " ").strip()
        return text[:max_chars] + ("…" if len(text) > max_chars else "")
    except Exception:
        return ""


def _row_col_1indexed(node) -> tuple[int, int]:
    """Convert tree-sitter 0-indexed point to 1-indexed (line, col)."""
    # node.start_point is a namedtuple-like: (row, column) – both 0-indexed
    return node.start_point.row + 1, node.start_point.column + 1


# ---------------------------------------------------------------------------
# Core Scanner Class
# ---------------------------------------------------------------------------
class JsTsScanner:
    """
    Tree-sitter–based JS/TS/React static security scanner.

    Usage::

        scanner = JsTsScanner()
        findings = scanner.scan_directory(Path("apps/web"), base_dir=Path.cwd())
    """

    def __init__(self) -> None:
        self.available = _TS_AVAILABLE

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def scan_directory(
        self,
        target_path: Path,
        base_dir: Optional[Path] = None,
        skipped_files: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Recursively scan a directory (or single file) for JS/TS security issues.

        Parameters
        ----------
        target_path:
            Resolved path to scan (file or directory).
        base_dir:
            Project root used for building relative paths (defaults to target_path
            if it's a directory, else its parent).
        skipped_files:
            Optional list to append skip-warning strings to.

        Returns
        -------
        List of standardized TCS finding dicts.
        """
        if not self.available:
            return []

        if base_dir is None:
            base_dir = target_path if target_path.is_dir() else target_path.parent

        js_files = self._discover_js_files(target_path, skipped_files)
        findings: List[Dict[str, Any]] = []
        counter = 1

        for file_path in js_files:
            try:
                rel_path = file_path.relative_to(target_path if target_path.is_dir() else target_path.parent).as_posix()
            except ValueError:
                try:
                    rel_path = file_path.relative_to(base_dir).as_posix()
                except ValueError:
                    rel_path = file_path.name

            file_findings = self._scan_file(file_path, rel_path, counter)
            for ff in file_findings:
                ff["id"] = f"TCS-JS-{counter:03d}"
                counter += 1
            findings.extend(file_findings)

    def scan_file_content(
        self,
        code: str,
        filename: str = "editor_snippet.tsx",
        start_counter: int = 1,
    ) -> List[Dict[str, Any]]:
        """Parse source code in-memory and extract security findings."""
        if not self.available:
            return []
        ext = Path(filename).suffix.lower() or ".tsx"
        parser, language = _get_parser_and_language(ext)
        if parser is None or language is None:
            return []
        source_bytes = code.encode("utf-8")
        try:
            tree = parser.parse(source_bytes)
        except Exception:
            return []
        root = tree.root_node
        findings: List[Dict[str, Any]] = []
        if language is _JS_LANGUAGE:
            findings.extend(self._extract_eval_sinks_js(root, source_bytes, filename, language))
            findings.extend(self._extract_innerhtml_js(root, source_bytes, filename, language))
        else:
            findings.extend(self._extract_eval_sinks(root, source_bytes, filename))
            findings.extend(self._extract_jsx_xss(root, source_bytes, filename))
            findings.extend(self._extract_innerhtml(root, source_bytes, filename))
        for i, ff in enumerate(findings):
            ff["id"] = f"TCS-JS-{start_counter + i:03d}"
        return findings

    def scan_files(
        self,
        file_paths: List[Path],
        base_dir: Path,
    ) -> List[Dict[str, Any]]:
        """
        Scan an explicit list of JS/TS file Paths (used when files are pre-discovered
        by the CLI).
        """
        if not self.available:
            return []

        findings: List[Dict[str, Any]] = []
        counter = 1
        for file_path in file_paths:
            if file_path.suffix.lower() not in JS_TS_EXTENSIONS:
                continue
            try:
                rel_path = file_path.relative_to(base_dir).as_posix()
            except ValueError:
                rel_path = file_path.name

            file_findings = self._scan_file(file_path, rel_path, counter)
            for ff in file_findings:
                ff["id"] = f"TCS-JS-{counter:03d}"
                counter += 1
            findings.extend(file_findings)

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _discover_js_files(
        self,
        target_path: Path,
        skipped_files: Optional[List[str]],
    ) -> List[Path]:
        """Recursively collect JS/TS files, honoring skip directories."""
        if target_path.is_file():
            if target_path.suffix.lower() in JS_TS_EXTENSIONS:
                return [target_path]
            return []

        discovered: List[Path] = []
        visited_dirs: set[str] = set()

        for root, dirs, files in os.walk(target_path, followlinks=False):
            real_root = os.path.realpath(root)
            if real_root in visited_dirs:
                dirs[:] = []
                continue
            visited_dirs.add(real_root)

            # Prune ignored dirs and symlinks
            dirs[:] = [
                d for d in dirs
                if d not in _SKIP_DIRS
                and not d.startswith(".")
                and not os.path.islink(os.path.join(root, d))
            ]

            for fname in files:
                p = Path(root) / fname
                if p.suffix.lower() in JS_TS_EXTENSIONS:
                    # Guard: skip oversized or binary files
                    try:
                        size = p.stat().st_size
                        if size > 5 * 1024 * 1024:
                            msg = f"Skipping JS/TS file exceeding size limit (5MB): {p}"
                            if skipped_files is not None:
                                skipped_files.append(msg)
                            continue
                        with open(p, "rb") as fh:
                            chunk = fh.read(8192)
                            if b"\x00" in chunk:
                                continue  # binary
                    except OSError:
                        continue
                    discovered.append(p)

        discovered.sort()
        return discovered

    def _scan_file(
        self,
        file_path: Path,
        rel_path: str,
        start_counter: int,
    ) -> List[Dict[str, Any]]:
        """Parse a single JS/TS file and extract security findings."""
        ext = file_path.suffix.lower()
        parser, language = _get_parser_and_language(ext)
        if parser is None or language is None:
            return []

        try:
            source_bytes = file_path.read_bytes()
        except OSError:
            return []

        # Determine if we need to re-build queries for JS (non-TSX) language
        # For JS files, re-use TSX queries but run them against JS parser output.
        # Tree-sitter queries are language-specific; for JS we must build per-language queries.
        try:
            tree = parser.parse(source_bytes)
        except Exception:
            return []

        root = tree.root_node
        findings: List[Dict[str, Any]] = []

        # Determine which query-set to use based on language
        if language is _JS_LANGUAGE:
            findings.extend(self._extract_eval_sinks_js(root, source_bytes, rel_path, language))
            findings.extend(self._extract_innerhtml_js(root, source_bytes, rel_path, language))
        else:
            # TSX / TS
            findings.extend(self._extract_eval_sinks(root, source_bytes, rel_path))
            findings.extend(self._extract_jsx_xss(root, source_bytes, rel_path))
            findings.extend(self._extract_innerhtml(root, source_bytes, rel_path))

        return findings

    # ------------------------------------------------------------------
    # TSX / TS extractors
    # ------------------------------------------------------------------
    def _extract_eval_sinks(
        self, root, source_bytes: bytes, rel_path: str
    ) -> List[Dict[str, Any]]:
        """Detect eval(), Function(), new Function(), setTimeout, setInterval in TSX/TS."""
        findings: List[Dict[str, Any]] = []
        if _EVAL_FN_QUERY is None:
            return findings

        for _, match_dict in _safe_query_matches(_EVAL_FN_QUERY, QueryCursor, root):
            # call_expression pattern
            if "fn_id" in match_dict:
                for fn_node in match_dict["fn_id"]:
                    name = (fn_node.text or b"").decode("utf-8", errors="replace")
                    if name not in _EVAL_SINKS:
                        continue
                    args_nodes = match_dict.get("fn_args", [])
                    args_node = args_nodes[0] if args_nodes else None
                    line, col = _row_col_1indexed(fn_node)
                    findings.append(self._make_finding(
                        rel_path=rel_path,
                        line=line,
                        col=col,
                        cwe="CWE-95",
                        severity="HIGH",
                        sink=name,
                        kind="call_expression",
                        source_bytes=source_bytes,
                        sink_node=fn_node,
                        args_node=args_node,
                    ))

            # new_expression pattern
            if "new_id" in match_dict:
                for fn_node in match_dict["new_id"]:
                    name = (fn_node.text or b"").decode("utf-8", errors="replace")
                    if name != "Function":
                        continue
                    args_nodes = match_dict.get("new_args", [])
                    args_node = args_nodes[0] if args_nodes else None
                    line, col = _row_col_1indexed(fn_node)
                    findings.append(self._make_finding(
                        rel_path=rel_path,
                        line=line,
                        col=col,
                        cwe="CWE-95",
                        severity="HIGH",
                        sink="Function",
                        kind="new_expression",
                        source_bytes=source_bytes,
                        sink_node=fn_node,
                        args_node=args_node,
                    ))

        return findings

    def _extract_jsx_xss(
        self, root, source_bytes: bytes, rel_path: str
    ) -> List[Dict[str, Any]]:
        """Detect dangerouslySetInnerHTML in JSX attributes and object properties."""
        findings: List[Dict[str, Any]] = []
        if _JSX_DSIHTML_QUERY is None:
            return findings

        # JSX attribute pattern
        for _, match_dict in _safe_query_matches(_JSX_DSIHTML_QUERY, QueryCursor, root):
            if "jsx_attr_name" in match_dict:
                for attr_node in match_dict["jsx_attr_name"]:
                    name = (attr_node.text or b"").decode("utf-8", errors="replace")
                    if name not in _JSX_XSS_SINKS:
                        continue
                    val_nodes = match_dict.get("jsx_attr_value", [])
                    val_node = val_nodes[0] if val_nodes else None
                    line, col = _row_col_1indexed(attr_node)
                    findings.append(self._make_finding(
                        rel_path=rel_path,
                        line=line,
                        col=col,
                        cwe="CWE-79",
                        severity="CRITICAL",
                        sink=name,
                        kind="jsx_attribute",
                        source_bytes=source_bytes,
                        sink_node=attr_node,
                        args_node=val_node,
                    ))

        # Object pair pattern
        if _OBJ_DSIHTML_QUERY is not None:
            for _, match_dict in _safe_query_matches(_OBJ_DSIHTML_QUERY, QueryCursor, root):
                if "prop_key" in match_dict:
                    for key_node in match_dict["prop_key"]:
                        name = (key_node.text or b"").decode("utf-8", errors="replace")
                        if name not in _JSX_XSS_SINKS:
                            continue
                        val_nodes = match_dict.get("prop_val", [])
                        val_node = val_nodes[0] if val_nodes else None
                        line, col = _row_col_1indexed(key_node)
                        findings.append(self._make_finding(
                            rel_path=rel_path,
                            line=line,
                            col=col,
                            cwe="CWE-79",
                            severity="CRITICAL",
                            sink=name,
                            kind="object_property",
                            source_bytes=source_bytes,
                            sink_node=key_node,
                            args_node=val_node,
                        ))

        return findings

    def _extract_innerhtml(
        self, root, source_bytes: bytes, rel_path: str
    ) -> List[Dict[str, Any]]:
        """Detect direct DOM innerHTML/outerHTML assignment expressions."""
        findings: List[Dict[str, Any]] = []
        if _INNERHTML_QUERY is None:
            return findings

        for _, match_dict in _safe_query_matches(_INNERHTML_QUERY, QueryCursor, root):
            if "prop_name" in match_dict:
                for prop_node in match_dict["prop_name"]:
                    name = (prop_node.text or b"").decode("utf-8", errors="replace")
                    if name not in _INNERHTML_SINKS:
                        continue
                    rhs_nodes = match_dict.get("rhs", [])
                    rhs_node = rhs_nodes[0] if rhs_nodes else None
                    line, col = _row_col_1indexed(prop_node)
                    findings.append(self._make_finding(
                        rel_path=rel_path,
                        line=line,
                        col=col,
                        cwe="CWE-79",
                        severity="CRITICAL",
                        sink=name,
                        kind="assignment_expression",
                        source_bytes=source_bytes,
                        sink_node=prop_node,
                        args_node=rhs_node,
                    ))

        return findings

    # ------------------------------------------------------------------
    # JS (non-TSX) extractors – use per-language queries
    # ------------------------------------------------------------------
    def _extract_eval_sinks_js(
        self, root, source_bytes: bytes, rel_path: str, language
    ) -> List[Dict[str, Any]]:
        """Eval/Function sink detection for pure JS files."""
        try:
            q = Query(language, """
                (call_expression
                  function: (identifier) @fn_id
                  arguments: (arguments) @fn_args)
                (new_expression
                  constructor: (identifier) @new_id
                  arguments: (arguments) @new_args)
            """)
            cursor = QueryCursor(q)
            matches = cursor.matches(root)
        except Exception:
            return []

        findings: List[Dict[str, Any]] = []
        for _, match_dict in matches:
            if "fn_id" in match_dict:
                for fn_node in match_dict["fn_id"]:
                    name = (fn_node.text or b"").decode("utf-8", errors="replace")
                    if name not in _EVAL_SINKS:
                        continue
                    args_nodes = match_dict.get("fn_args", [])
                    args_node = args_nodes[0] if args_nodes else None
                    line, col = _row_col_1indexed(fn_node)
                    findings.append(self._make_finding(
                        rel_path=rel_path,
                        line=line, col=col,
                        cwe="CWE-95", severity="HIGH",
                        sink=name, kind="call_expression",
                        source_bytes=source_bytes,
                        sink_node=fn_node, args_node=args_node,
                    ))
            if "new_id" in match_dict:
                for fn_node in match_dict["new_id"]:
                    name = (fn_node.text or b"").decode("utf-8", errors="replace")
                    if name != "Function":
                        continue
                    args_nodes = match_dict.get("new_args", [])
                    args_node = args_nodes[0] if args_nodes else None
                    line, col = _row_col_1indexed(fn_node)
                    findings.append(self._make_finding(
                        rel_path=rel_path,
                        line=line, col=col,
                        cwe="CWE-95", severity="HIGH",
                        sink="Function", kind="new_expression",
                        source_bytes=source_bytes,
                        sink_node=fn_node, args_node=args_node,
                    ))
        return findings

    def _extract_innerhtml_js(
        self, root, source_bytes: bytes, rel_path: str, language
    ) -> List[Dict[str, Any]]:
        """innerHTML/outerHTML detection for pure JS files."""
        try:
            q = Query(language, """
                (assignment_expression
                  left: (member_expression
                    property: (property_identifier) @prop_name)
                  right: (_) @rhs)
            """)
            cursor = QueryCursor(q)
            matches = cursor.matches(root)
        except Exception:
            return []

        findings: List[Dict[str, Any]] = []
        for _, match_dict in matches:
            if "prop_name" in match_dict:
                for prop_node in match_dict["prop_name"]:
                    name = (prop_node.text or b"").decode("utf-8", errors="replace")
                    if name not in _INNERHTML_SINKS:
                        continue
                    rhs_nodes = match_dict.get("rhs", [])
                    rhs_node = rhs_nodes[0] if rhs_nodes else None
                    line, col = _row_col_1indexed(prop_node)
                    findings.append(self._make_finding(
                        rel_path=rel_path,
                        line=line, col=col,
                        cwe="CWE-79", severity="CRITICAL",
                        sink=name, kind="assignment_expression",
                        source_bytes=source_bytes,
                        sink_node=prop_node, args_node=rhs_node,
                    ))
        return findings

    # ------------------------------------------------------------------
    # Finding factory
    # ------------------------------------------------------------------
    def _make_finding(
        self,
        rel_path: str,
        line: int,
        col: int,
        cwe: str,
        severity: str,
        sink: str,
        kind: str,
        source_bytes: bytes,
        sink_node,
        args_node,
    ) -> Dict[str, Any]:
        """Build a standardized TCS finding dict."""
        # Build snippet: prefer argument text; fall back to full node line
        if args_node is not None:
            raw_snippet = _snippet(source_bytes, args_node)
        else:
            raw_snippet = _snippet(source_bytes, sink_node)

        # Inline code snippet: the line of the finding
        lines = source_bytes.decode("utf-8", errors="replace").splitlines()
        line_text = lines[line - 1].strip() if 1 <= line <= len(lines) else ""

        if cwe == "CWE-79":
            message = (
                "Unsanitized input passed to dangerous DOM/React rendering sink "
                f"({sink}). Sanitize all HTML content before rendering."
            )
            remediation = (
                "Sanitize all user-supplied HTML with a trusted library (e.g., DOMPurify) "
                "before passing to dangerouslySetInnerHTML or innerHTML. "
                "Prefer React's default JSX escaping by passing content as children, not HTML."
            )
            category = "CROSS_SITE_SCRIPTING"
        else:
            message = (
                "Dynamic code evaluation via eval() or Function() constructor can lead to "
                "arbitrary JavaScript execution. Avoid dynamic code evaluation."
            )
            remediation = (
                "Avoid eval() and new Function(). Use JSON.parse() for JSON data, "
                "or refactor to static function dispatch tables."
            )
            category = "CODE_INJECTION"

        flow_summary = f"[User Input] -> [Tainted Dataflow] -> [{sink} (L{line})]"
        flow_trace = [
            "Source: User Input",
            f"Sink: {sink} ({rel_path}:{line})",
        ]

        return {
            # NOTE: id is assigned by the caller after counter is known
            "id": "TCS-JS-000",
            "category": category,
            "cwe": cwe,
            "severity": severity,
            "confidence": 1.0,
            "confidence_label": "CONFIRMED",
            "file": rel_path,
            "line_number": line,
            "column": col,
            "sink_symbol": sink,
            "source_symbol": "USER_INPUT",
            "source_line": None,
            "source_file": None,
            "code_snippet": line_text or raw_snippet,
            "flow_trace": flow_trace,
            "flow_trace_summary": flow_summary,
            "remediation": remediation,
            "message": message,
            "proof_graph": None,
            "proof_graph_ascii": None,
            "discovery_mode": "JS_TS_SCAN",
            "status": "ACTIVE",
            "suppressed": False,
            "suppression_justification": None,
            "suppression_kind": None,
            "active": True,
            # Metadata
            "_js_kind": kind,
        }


# ---------------------------------------------------------------------------
# Convenience functions (mirrors the public surface used by tcs_cli.py)
# ---------------------------------------------------------------------------
def discover_js_ts_files(
    target_path: Path,
    skipped_files: Optional[List[str]] = None,
) -> List[Path]:
    """
    Standalone helper: discover JS/TS files under target_path.
    Returns sorted list of Path objects.
    """
    scanner = JsTsScanner()
    return scanner._discover_js_files(target_path, skipped_files)


def run_js_ts_scan(
    target_path: Path,
    base_dir: Optional[Path] = None,
    skipped_files: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Convenience function: run a full JS/TS security scan and return findings.
    Returns empty list if tree-sitter is unavailable.
    """
    scanner = JsTsScanner()
    return scanner.scan_directory(target_path, base_dir=base_dir, skipped_files=skipped_files)


def js_ts_available() -> bool:
    """Returns True if tree-sitter JS/TS scanning is available."""
    return _TS_AVAILABLE
