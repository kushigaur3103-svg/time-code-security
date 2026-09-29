"""HTML / Jinja / Django template security auditor for TimeCodeSecurity (TCS).

Performs concrete HTML-node analysis over server-side templates using the standard
library ``html.parser``. Two rules are implemented:

* CWE-353 -- Missing Subresource Integrity (SRI) on externally hosted subresources.
* CWE-352 -- State-changing ``<form>`` without a CSRF token in its body.

Both rules are deterministic: findings are derived from parsed tag nodes, their
attribute maps, and the raw character data contained between an opening and
closing ``<form>`` tag. No path allow-listing and no text pattern matching over
whole files is performed.
"""

from __future__ import annotations

from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Sequence, Tuple

TEMPLATE_SUFFIXES: Tuple[str, ...] = (".html", ".htm", ".jinja", ".dtl")

# A subresource is externally hosted when its URL carries an explicit scheme or is
# protocol-relative. Local and framework-static assets are out of scope for SRI.
EXTERNAL_URL_PREFIXES: Tuple[str, ...] = ("http://", "https://", "//")

# HTML form methods that mutate server state and therefore require CSRF protection.
STATE_CHANGING_FORM_METHODS = frozenset({"post", "put", "patch", "delete"})

# Django/Jinja CSRF token markers. ``csrfmiddlewaretoken`` covers the rendered
# <input type="hidden"> form of the token as well as the template tag itself.
CSRF_TOKEN_MARKERS: Tuple[str, ...] = ("csrf_token", "csrfmiddlewaretoken")


def is_template_path(path: str) -> bool:
    """Return True when *path* carries a server-side template suffix."""
    lowered = str(path).lower()
    return lowered.endswith(TEMPLATE_SUFFIXES)


def _normalize_attrs(attrs: Sequence[Tuple[str, Optional[str]]]) -> Dict[str, str]:
    """Fold an HTMLParser attribute list into a lowercase-keyed string map."""
    normalized: Dict[str, str] = {}
    for key, value in attrs:
        if key is None:
            continue
        normalized[key.lower()] = value if value is not None else ""
    return normalized


def _is_external_url(url: Optional[str]) -> bool:
    if not url:
        return False
    return url.strip().startswith(EXTERNAL_URL_PREFIXES)


class TemplateSecurityAuditor(HTMLParser):
    """Collects CWE-353 and CWE-352 findings from a single template document."""

    def __init__(self, file_path: str) -> None:
        super().__init__(convert_charrefs=True)
        self.file_path = file_path
        self.findings: List[Dict[str, Any]] = []
        # Each frame is [start_line, csrf_token_seen] for an open state-changing form.
        self._form_frames: List[List[Any]] = []
        self._reported: set = set()

    # ── emission ──────────────────────────────────────────────────────────
    def _emit(self, line: int, cwe: str, severity: str, category: str, message: str) -> None:
        identity = (line, cwe, category)
        if identity in self._reported:
            return
        self._reported.add(identity)
        self.findings.append({
            "file": self.file_path,
            "line": max(1, int(line)),
            "cwe": cwe,
            "severity": severity,
            "category": category,
            "message": message,
        })

    # ── CWE-353: Subresource Integrity ────────────────────────────────────
    def _check_subresource_integrity(self, line: int, tag: str, attr_map: Dict[str, str], url_attr: str) -> None:
        url = attr_map.get(url_attr)
        if not _is_external_url(url):
            return
        if attr_map.get("integrity", "").strip():
            return

        crossorigin = attr_map.get("crossorigin", "").strip()
        crossorigin_note = (
            f'crossorigin="{crossorigin}"' if crossorigin else "crossorigin attribute absent"
        )
        self._emit(
            line=line,
            cwe="CWE-353",
            severity="MEDIUM",
            category="MISSING_SUBRESOURCE_INTEGRITY",
            message=(
                f"CWE-353: Missing Subresource Integrity (SRI) on external <{tag} {url_attr}>"
                f" loading {url.strip()} ({crossorigin_note}); add integrity=<hash> so the"
                f" browser can reject a tampered CDN response"
            ),
        )

    # ── HTMLParser hooks ──────────────────────────────────────────────────
    def handle_starttag(self, tag: str, attrs) -> None:
        line = self.getpos()[0]
        attr_map = _normalize_attrs(attrs)
        lowered = tag.lower()

        if lowered == "script":
            self._check_subresource_integrity(line, "script", attr_map, "src")
        elif lowered == "link":
            if "stylesheet" in attr_map.get("rel", "").lower():
                self._check_subresource_integrity(line, "link", attr_map, "href")
        elif lowered == "form":
            if attr_map.get("method", "").strip().lower() in STATE_CHANGING_FORM_METHODS:
                self._form_frames.append([line, False])

    def handle_startendtag(self, tag: str, attrs) -> None:
        # Self-closing form/script tags still carry the same attributes.
        self.handle_starttag(tag, attrs)

    def handle_data(self, data: str) -> None:
        if not self._form_frames or not data:
            return
        for marker in CSRF_TOKEN_MARKERS:
            if marker in data:
                # Attribute the token to the form that actually encloses it. Marking every
                # open frame let one {% csrf_token %} exonerate unrelated forms that were
                # left open by malformed or nested markup.
                self._form_frames[-1][1] = True
                return

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or not self._form_frames:
            return
        line, has_csrf = self._form_frames.pop()
        if has_csrf:
            return
        self._emit(
            line=line,
            cwe="CWE-352",
            severity="HIGH",
            category="CSRF_MISSING_PROTECTION",
            message=(
                "CWE-352: Cross-Site Request Forgery - state-changing <form> submitted without a"
                " CSRF token; render {% csrf_token %} inside the form body"
            ),
        )

    def close(self) -> None:
        """Flush forms left open by malformed markup, then release parser state."""
        super().close()
        while self._form_frames:
            line, has_csrf = self._form_frames.pop()
            if has_csrf:
                continue
            self._emit(
                line=line,
                cwe="CWE-352",
                severity="HIGH",
                category="CSRF_MISSING_PROTECTION",
                message=(
                    "CWE-352: Cross-Site Request Forgery - state-changing <form> submitted without a"
                    " CSRF token; render {% csrf_token %} inside the form body"
                ),
            )


def audit_template(file_path: str, source: str) -> List[Dict[str, Any]]:
    """Audit a single template document and return its findings."""
    auditor = TemplateSecurityAuditor(file_path)
    try:
        auditor.feed(source)
    except Exception:
        # A malformed template must never abort a scan; partial findings are kept.
        pass
    auditor.close()
    return auditor.findings


def audit_templates(files: Dict[str, str]) -> List[Dict[str, Any]]:
    """Audit a mapping of ``{file_path: source}`` templates, sorted deterministically."""
    findings: List[Dict[str, Any]] = []
    for file_path in sorted(files):
        findings.extend(audit_template(file_path, files[file_path]))
    return sorted(findings, key=lambda item: (item["file"], item["line"], item["cwe"]))
