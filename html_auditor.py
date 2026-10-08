"""HTML / Jinja / Django template security auditor for TimeCodeSecurity.

Performs concrete HTML-node analysis over server-side templates using the standard
library ``html.parser``. Three rules are implemented:

* CWE-353 -- Missing Subresource Integrity (SRI) on externally hosted subresources.
* CWE-352 -- State-changing ``<form>`` without a CSRF token in its body.
* CWE-79 -- Django ``{{ value|safe }}`` output: the ``safe`` filter turns off the
  auto-escaping that otherwise protects every template variable.

The rules are deterministic: findings are derived from parsed tag nodes, their
attribute maps, and the raw character data contained between an opening and
closing ``<form>`` tag. No path allow-listing is performed. The CSRF and SRI rules read
parsed nodes only; the ``|safe`` rule scans the character text of those nodes, because the
Django expression is markup content rather than a tag or attribute.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Sequence, Tuple

TEMPLATE_SUFFIXES: Tuple[str, ...] = (".html", ".htm", ".jinja", ".jinja2", ".j2", ".dtl")

# A subresource is externally hosted when its URL carries an explicit scheme or is
# protocol-relative. Local and framework-static assets are out of scope for SRI.
EXTERNAL_URL_PREFIXES: Tuple[str, ...] = ("http://", "https://", "//")

# HTML form methods that mutate server state and therefore require CSRF protection.
STATE_CHANGING_FORM_METHODS = frozenset({"post", "put", "patch", "delete"})

# Django/Jinja CSRF token markers. ``csrfmiddlewaretoken`` covers the rendered
# <input type="hidden"> form of the token as well as the template tag itself.
CSRF_TOKEN_MARKERS: Tuple[str, ...] = ("csrf_token", "csrfmiddlewaretoken")

# Django's ``safe`` filter declares a variable to be trusted HTML and stops the template engine
# from escaping it, which is exactly how a stored or reflected XSS reaches the browser.
UNESCAPED_OUTPUT_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\|\s*safe\s*\}\}")

# Text inside these tags is sample code shown to the reader, not markup the template renders, so
# a ``|safe`` written there documents a vulnerability instead of creating one.
VERBATIM_TAGS = frozenset({"pre", "code", "textarea", "samp", "kbd"})

# Expressions that never carry client HTML: Django's own CSRF token, and ``form.<field>`` widget
# renders, whose markup the framework builds and escapes itself, so ``|safe`` on them is a no-op.
ALWAYS_SAFE_EXPRESSION_ROOTS = frozenset({"csrf_token", "csrfmiddlewaretoken"})

# .. except when the render reaches into bound data: ``form.field.value`` *is* the submitted
# request text, and marking that safe reproduces it raw, so those expressions stay reported.
FORM_USER_DATA_SEGMENTS = frozenset({"value", "data", "initial"})

UNESCAPED_OUTPUT_MESSAGE = (
    "CWE-79: Unescaped dynamic content marked safe or rendered directly in HTTP response"
)


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
    """Collects CWE-353, CWE-352 and CWE-79 findings from a single template document."""

    def __init__(self, file_path: str) -> None:
        super().__init__(convert_charrefs=True)
        self.file_path = file_path
        self.findings: List[Dict[str, Any]] = []
        # Each frame is [start_line, csrf_token_seen] for an open state-changing form.
        self._form_frames: List[List[Any]] = []
        # How deep inside <pre>/<code>/<textarea> the parser currently sits.
        self._verbatim_depth = 0
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

    # ── CWE-79: Django "safe" output ──────────────────────────────────────
    @staticmethod
    def _is_trusted_expression(expression: str) -> bool:
        """True when a ``|safe`` expression cannot carry client-controlled markup."""
        root = re.match(r"[A-Za-z_][A-Za-z0-9_]*", expression)
        if not root:
            return False
        name = root.group(0).lower()
        if name in ALWAYS_SAFE_EXPRESSION_ROOTS:
            return True
        if name != "form":
            return False
        segments = [segment.lower() for segment in expression.split(".")]
        return not any(segment in FORM_USER_DATA_SEGMENTS for segment in segments[1:])

    def _check_unescaped_output(self, line: int, data: str) -> None:
        """Report ``{{ value|safe }}``: the filter switches off the escaping that protects
        every other template variable, so the value lands in the page as raw HTML."""
        if self._verbatim_depth:
            return
        for match in UNESCAPED_OUTPUT_RE.finditer(data):
            expression = match.group(1).strip()
            if self._is_trusted_expression(expression):
                continue
            self._emit(
                line=line + data[:match.start()].count("\n"),
                cwe="CWE-79",
                severity="HIGH",
                category="CROSS_SITE_SCRIPTING",
                message=UNESCAPED_OUTPUT_MESSAGE,
            )

    # ── HTMLParser hooks ──────────────────────────────────────────────────
    def handle_starttag(self, tag: str, attrs, self_closing: bool = False) -> None:
        line = self.getpos()[0]
        attr_map = _normalize_attrs(attrs)
        lowered = tag.lower()

        if lowered in VERBATIM_TAGS and not self_closing:
            self._verbatim_depth += 1

        if lowered == "script":
            self._check_subresource_integrity(line, "script", attr_map, "src")
        elif lowered == "link":
            if "stylesheet" in attr_map.get("rel", "").lower():
                self._check_subresource_integrity(line, "link", attr_map, "href")
        elif lowered == "form":
            if attr_map.get("method", "").strip().lower() in STATE_CHANGING_FORM_METHODS:
                self._form_frames.append([line, False])

        if self._form_frames and lowered in ("input", "button"):
            # The token also arrives pre-rendered as <input type="hidden"
            # name="csrfmiddlewaretoken" value="...">. Attribute values are never handed to
            # handle_data, so without this check a protected form is reported as vulnerable.
            if attr_map.get("name", "").strip().lower() in CSRF_TOKEN_MARKERS:
                self._form_frames[-1][1] = True

    def handle_startendtag(self, tag: str, attrs) -> None:
        # Self-closing form/script tags still carry the same attributes. A self-closing
        # <code/> opens no region, so it must not bump the depth counter.
        self.handle_starttag(tag, attrs, self_closing=True)

    def handle_data(self, data: str) -> None:
        if not data:
            return
        # getpos() is the offset where this character run began, so a run spanning several
        # lines is anchored by counting the newlines that precede the match inside it.
        self._check_csrf_token(self.getpos()[0], data)
        self._check_unescaped_output(self.getpos()[0], data)

    def _check_csrf_token(self, line: int, data: str) -> None:
        if not self._form_frames:
            return
        # Django's tag is case-preserving but template authors do write `{% CSRF_TOKEN %}`,
        # and a case-sensitive match then exonerates nothing: a protected form gets reported.
        lowered = data.lower()
        for marker in CSRF_TOKEN_MARKERS:
            if marker in lowered:
                # Attribute the token to the form that actually encloses it. Marking every
                # open frame let one {% csrf_token %} exonerate unrelated forms that were
                # left open by malformed or nested markup.
                self._form_frames[-1][1] = True
                return

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in VERBATIM_TAGS:
            # An unclosed <pre> would otherwise keep the counter positive and hide every
            # finding below it, so the depth is clamped at zero.
            self._verbatim_depth = max(0, self._verbatim_depth - 1)
        if lowered != "form" or not self._form_frames:
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
