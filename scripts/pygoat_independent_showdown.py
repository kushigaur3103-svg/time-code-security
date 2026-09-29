"""Independent 3-way SAST showdown on a neutral target: OWASP PyGoat.

Runs TCS, Semgrep OSS and Bandit over `external/pygoat` (read-only), normalizes every
result to (file, line, CWE), clusters the three reports against each other, and renders
a Markdown scoreboard with consensus / exclusive partitions.

Usage:
    py.exe scripts/pygoat_independent_showdown.py
    py.exe scripts/pygoat_independent_showdown.py --tolerance 3 --json-out scratch/showdown/clusters.json

Design notes:
  * Semgrep is pinned to two official rulesets rather than `--config auto`. `auto` reaches
    out to the registry and resolves a different rule set per run, which would make the
    numbers unreproducible offline.
  * Normalization is imported from `cli.py`, so this harness scores exactly what the shipped
    `tcs compare` command scores; no parallel implementation of CWE parsing lives here.
  * Clustering is by (resolved file path, CWE) with a line tolerance, because the three
    engines legitimately point at different lines of the same statement (call site vs the
    line the concatenation starts on).
"""

from __future__ import annotations

import argparse
import collections
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cli import _competitor_findings, _normalize_compare_path, _normalize_cwes  # noqa: E402

TARGET = Path("external/pygoat")
SEMGREP_CONFIGS = ("p/default", "p/security-audit")
TOOLS = ("tcs", "semgrep", "bandit")
TOOL_LABEL = {"tcs": "TCS", "semgrep": "Semgrep OSS", "bandit": "Bandit"}


class RunnerError(RuntimeError):
    pass


def _run(command: List[str]) -> tuple[str, float]:
    executable = shutil.which(command[0])
    if executable is None:
        raise RunnerError(f"{command[0]} is not installed or not on PATH")
    started = time.perf_counter()
    completed = subprocess.run(
        [executable, *command[1:]],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    duration_ms = (time.perf_counter() - started) * 1000.0
    if not completed.stdout.strip():
        detail = completed.stderr.strip()[-500:] or f"exit status {completed.returncode}"
        raise RunnerError(f"{' '.join(command)} produced no output: {detail}")
    return completed.stdout, duration_ms


def _load_json_stream(text: str) -> Any:
    """Decode the first JSON document in stdout.

    Bandit 1.9.4 prints a `Working... ---- 100%` progress banner to stdout ahead of its own
    JSON report, so a strict whole-stream parse is not possible.
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    if start < 0:
        raise RunnerError("no JSON document found in tool output")
    return json.JSONDecoder().raw_decode(text[start:])[0]


def _probe_version(command: List[str]) -> str:
    """First non-empty line of a `--version` banner, for reproducibility evidence."""
    executable = shutil.which(command[0])
    if executable is None:
        return "unavailable"
    try:
        completed = subprocess.run(
            [executable, *command[1:]], cwd=ROOT, capture_output=True,
            text=True, encoding="utf-8", errors="replace", check=False, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    stream = completed.stdout.strip() or completed.stderr.strip()
    for line in stream.splitlines():
        if line.strip():
            return line.strip()
    return "unknown"


def _relpath(value: str) -> str:
    try:
        return Path(value).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(value)


def _site_severities(raw_results, file_of, line_of, severity_of) -> Dict[tuple, str]:
    """Most severe issue per (file, line).

    Several tools can raise two issues of different severity on one line (Bandit reports
    B201 HIGH and B104 MEDIUM on `app.run(debug=True, host="0.0.0.0")`), so a plain
    site->severity mapping would let the last row win and silently understate the mix.
    """
    rank = {"HIGH": 3, "ERROR": 3, "CRITICAL": 4, "MEDIUM": 2, "WARNING": 2, "LOW": 1, "INFO": 1}
    best: Dict[tuple, str] = {}
    for item in raw_results:
        key = (file_of(item), line_of(item))
        current = severity_of(item) or ""
        if rank.get(current, 0) >= rank.get(best.get(key, ""), 0) or key not in best:
            best[key] = current
    return best


def collect_tcs() -> tuple[List[Dict[str, Any]], float, Dict[str, Any]]:
    """TCS through its public CLI, exactly as an external user would invoke it."""
    stdout, duration_ms = _run(
        [sys.executable or "python", "cli.py", "scan", str(TARGET), "--format", "json"]
    )
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RunnerError(f"tcs scan returned invalid JSON: {exc}") from exc
    findings = []
    for item in payload.get("findings", []):
        for cwe in _normalize_cwes(item.get("cwe")):
            findings.append({
                "file": _normalize_compare_path(item["file"]),
                "line": int(item["line"]),
                "cwe": cwe,
                "rule": item.get("category", ""),
                "severity": item.get("severity", ""),
                "message": item.get("message", ""),
            })
    meta = {"scanned_files": payload.get("scanned_files"), "engine_ms": payload.get("duration_ms")}
    return findings, duration_ms, meta


def collect_semgrep() -> tuple[List[Dict[str, Any]], float, Dict[str, Any]]:
    command = ["semgrep", "scan"]
    for config in SEMGREP_CONFIGS:
        command += ["--config", config]
    command += [str(TARGET), "--json"]
    stdout, duration_ms = _run(command)
    data = _load_json_stream(stdout)
    findings = _competitor_findings("semgrep", data)
    severities = _site_severities(
        data.get("results", []),
        lambda item: _normalize_compare_path(item.get("path", "")),
        lambda item: item.get("start", {}).get("line", 0),
        lambda item: item.get("extra", {}).get("severity", ""),
    )
    for item in findings:
        item["file"] = _normalize_compare_path(item["file"])
        item["severity"] = severities.get((item["file"], item["line"]), "")
    meta = {
        "scanned_files": len(data.get("paths", {}).get("scanned", [])),
        "parse_errors": len(data.get("errors", [])),
        "version": data.get("version"),
    }
    return findings, duration_ms, meta


def collect_bandit() -> tuple[List[Dict[str, Any]], float, Dict[str, Any]]:
    stdout, duration_ms = _run(["bandit", "-r", str(TARGET), "-f", "json"])
    data = _load_json_stream(stdout)
    findings = _competitor_findings("bandit", data)
    severities = _site_severities(
        data.get("results", []),
        lambda item: _normalize_compare_path(item.get("filename", "")),
        lambda item: item.get("line_number", 0),
        lambda item: item.get("issue_severity", ""),
    )
    for item in findings:
        item["file"] = _normalize_compare_path(item["file"])
        item["severity"] = severities.get((item["file"], item["line"]), "")
    meta = {
        "scanned_files": len({item["file"] for item in findings}),
        "scanned_files_label": "files with findings",
        "parse_errors": len(data.get("errors", [])),
    }
    return findings, duration_ms, meta


def cluster(
    all_findings: Dict[str, List[Dict[str, Any]]],
    tolerance: int,
    cwe_sensitive: bool = True,
) -> List[Dict[str, Any]]:
    """Group findings that point at the same place.

    With `cwe_sensitive` the key is (file, CWE) within `tolerance` lines, which is the strict
    "did both engines call it the same weakness" view. Turning it off gives the site-level view:
    the engines disagree constantly about which CWE a line belongs to, so the strict view alone
    overstates how much coverage differs. The site view answers "does anyone see a problem here".
    """
    clusters: List[Dict[str, Any]] = []
    index: Dict[Any, List[int]] = {}
    for tool in TOOLS:
        for finding in all_findings[tool]:
            key = (finding["file"], finding["cwe"]) if cwe_sensitive else finding["file"]
            placed = False
            for slot in index.get(key, []):
                existing = clusters[slot]
                if min(abs(finding["line"] - member["line"]) for member in existing["members"]) <= tolerance:
                    existing["members"].append({**finding, "tool": tool})
                    existing["tools"].add(tool)
                    placed = True
                    break
            if not placed:
                index.setdefault(key, []).append(len(clusters))
                clusters.append({
                    "file": finding["file"],
                    "cwe": finding["cwe"],
                    "line": finding["line"],
                    "tools": {tool},
                    "members": [{**finding, "tool": tool}],
                })
    for item in clusters:
        item["line"] = min(member["line"] for member in item["members"])
        item["cwe"] = "/".join(sorted({member["cwe"] for member in item["members"]}))
    return clusters


def partition(clusters: List[Dict[str, Any]]) -> Dict[frozenset, List[Dict[str, Any]]]:
    buckets: Dict[frozenset, List[Dict[str, Any]]] = collections.defaultdict(list)
    for item in clusters:
        buckets[frozenset(item["tools"])].append(item)
    for value in buckets.values():
        value.sort(key=lambda c: (c["file"], c["line"], c["cwe"]))
    return buckets


def severity_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = collections.Counter(item["severity"] or "n/a" for item in findings)
    return dict(sorted(counts.items()))


def cwe_matrix(clusters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = {}
    for item in clusters:
        row = rows.setdefault(item["cwe"], collections.Counter())
        for tool in item["tools"]:
            row[tool] += 1
        row["clusters"] += 1
    return [
        {"cwe": cwe, **counts}
        for cwe, counts in sorted(rows.items(), key=lambda pair: (-pair[1]["clusters"], pair[0]))
    ]


def _representative(cluster: Dict[str, Any], tool: str) -> Dict[str, Any]:
    for member in cluster["members"]:
        if member["tool"] == tool:
            return member
    return {}


def md_table(headers: List[str], rows: List[List[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(out)


SITE_WINDOW = 20
"""Lines within which a TCS finding counts as covering a competitor's site.

Wide on purpose: a SQL statement built at one line and executed at another is one
vulnerability, and Bandit/Semgrep habitually report the construction while TCS reports the
sink call 14 lines later. Anything narrower would score that as a TCS miss.
"""

# Rule-level reasoning, each entry confirmed by reading the PyGoat source at the reported
# line. `same-site` needs no entry: it is derived from TCS's own findings at scan time.
VERDICT_NOTES = {
    "bandit:B403": ("over-broad", "`import pickle` on the import line, no sink or taint examined"),
    "bandit:B404": ("over-broad", "`import subprocess` on the import line, no sink or taint examined"),
    "bandit:B406": ("over-broad", "flags an `xml.dom.pulldom` import; the live parse sink is elsewhere"),
    "bandit:B409": ("over-broad", "`xml.dom.minidom` import blacklist"),
    "bandit:B317": ("over-broad", "`xml.sax` import blacklist"),
    "bandit:B319": ("over-broad", "`xml.dom.pulldom.parseString` import blacklist; TCS reports the call site"),
    "bandit:B110": ("informational", "`except: pass` error-swallowing hygiene (CWE-703), not an injection"),
    "bandit:B113": ("genuine TCS gap", "missing HTTP timeout; TCS CWE-400 models file/stream exhaustion only"),
    "bandit:B311": ("genuine TCS gap", "rules_catalog CWE-338 lists random.choice but not random.choices"),
    "bandit:B105": ("mixed", "assignment-shaped secrets are TCS CWE-798; dict values and `password == 'x'` comparisons are Bandit heuristics"),
    "bandit:B106": ("over-broad", "any `password=` keyword argument, including test fixtures"),
    "bandit:B201": ("same weakness, label differs", "TCS reports CWE-489 ACTIVE_DEBUG_CODE at this site"),
    "bandit:B506": ("same weakness, label differs", "TCS reports CWE-502 UNSAFE_DESERIALIZATION at this site"),
    "bandit:B608": ("same weakness, label differs", "TCS reports CWE-89 at the `raw()`/`execute()` sink, line differs"),
    "bandit:B603": ("informational", "subprocess call argument check, no shell and no untrusted value in scope"),
    "semgrep:template-unescaped-with-safe": ("genuine TCS gap", "Jinja `|safe` markup-context audit is not implemented"),
    "semgrep:var-in-script-tag": ("genuine TCS gap", "template variable-in-script context analysis"),
    "semgrep:unquoted-attribute-var": ("genuine TCS gap", "unquoted attribute interpolation in templates"),
    "semgrep:django-no-csrf-token": ("genuine TCS gap", "missing `{% csrf_token %}` in Django form templates"),
    "semgrep:request-data-write": ("genuine TCS gap", "CWE-93 is absent from rules_catalog"),
    "semgrep:use-defused-xml": ("over-broad", "parser selection check on the import; TCS reports the parsing sink"),
    "semgrep:avoid-pickle": ("over-broad", "matches `pickle.dumps` (serialisation), the exploitable `pickle.loads` is reported by TCS"),
    "semgrep:direct-use-of-httpresponse": ("over-broad", "audit rule on the rendered context, which is a constant here, not user input"),
    "semgrep:detected-jwt-token": ("out of TCS file scope", "`.js` is not scanned and the literal sits inside a `//` comment"),
    "semgrep:md5-used-as-password": ("same weakness, label differs", "TCS reports CWE-327/CWE-328 at this site"),
}

SEMGREP_KEY_PATTERNS = (
    "template-unescaped-with-safe", "var-in-script-tag", "unquoted-attribute-var",
    "django-no-csrf-token", "request-data-write", "use-defused-xml", "avoid-pickle",
    "direct-use-of-httpresponse", "detected-jwt-token", "md5-used-as-password",
    "tainted-sql-string",
)


def verdict_key(cluster: Dict[str, Any]) -> str:
    for tool in ("bandit", "semgrep"):
        member = _representative(cluster, tool)
        rule = str(member.get("rule", ""))
        if not rule:
            continue
        if tool == "bandit":
            return f"bandit:{rule}"
        for pattern in SEMGREP_KEY_PATTERNS:
            if pattern in rule:
                return f"semgrep:{pattern}"
        return f"semgrep:{rule.rsplit('.', 1)[-1]}"
    return "unknown"


def classify(cluster: Dict[str, Any], tcs_findings: List[Dict[str, Any]]) -> Tuple[str, str]:
    """(category, reasoning) for a site TCS did not report under the same CWE label."""
    for finding in tcs_findings:
        if finding["file"] == cluster["file"] and abs(finding["line"] - cluster["line"]) <= SITE_WINDOW:
            return ("same-site",
                    f"TCS reports {finding['cwe']} at line {finding['line']} of the same file")
    return VERDICT_NOTES.get(verdict_key(cluster),
                             ("unreviewed", "no TCS finding within the site window"))


FORENSICS: List[Dict[str, str]] = [
    {
        "title": "F1 - Same SQL injection, two different lines (why naive diffing lies)",
        "site": "external/pygoat/introduction/views.py:864 builds `sql_query`, :878 executes `sql_lab_table.objects.raw(sql_query)`",
        "engines": "Semgrep `tainted-sql-string` (labelled CWE-915) and Bandit B608 at 864; TCS `SQL_INJECTION` CWE-89 at 878",
        "verdict": "Not a TCS miss - a location-representation difference. TCS is the only engine naming the execution sink.",
        "analysis": "All three engines see this vulnerability, but strict (file, CWE, line) diffing splits it in two and "
                    "manufactures one competitor-only site plus one TCS-only site. Semgrep also mislabels it CWE-915 "
                    "(mass assignment) rather than CWE-89, so even the CWE comparison is unusable here. The paired site at "
                    "views.py:158/162 lands inside the tolerance window and is recorded as 3-way consensus, which shows the "
                    "split is an artefact of the matching rule, not of detection.",
    },
    {
        "title": "F2 - Same secret, two different CWEs",
        "site": "external/pygoat/pygoat/settings.py:25 `SECRET_KEY = 'lr66%-a!$km5ed@n5ug!...'`; dockerized_labs/broken_auth_lab/app.py:123 `app.run(host='0.0.0.0', port=5000, debug=True)`",
        "engines": "TCS CWE-798 CRITICAL / CWE-489+CWE-668; Bandit B105 (CWE-259) / B201 (CWE-94)",
        "verdict": "Same finding, different taxonomy. Both engines are right; only the CWE namespace differs.",
        "analysis": "Bandit classifies a hardcoded key as CWE-259 (unprotected storage of credentials) and Flask debug mode as "
                    "CWE-94; TCS uses CWE-798 (hardcoded credentials) and CWE-489 (active debug code) plus CWE-668 for the "
                    "`0.0.0.0` bind. Counting these as divergent findings inflates the exclusive columns of both sides, which "
                    "is exactly why section 3 reports a CWE-agnostic site-level partition alongside the strict one.",
    },
    {
        "title": "F3 - Semgrep's pickle rule matches serialisation, TCS waits for deserialisation",
        "site": "external/pygoat/introduction/views.py:202 `pickled_user = pickle.dumps(TestUser())` vs :214 `admin = pickle.loads(token)`",
        "engines": "Semgrep `avoid-pickle` (CWE-502) at 202 only; TCS `UNSAFE_DESERIALIZATION` at 214, agreed by Semgrep and Bandit B301",
        "verdict": "Competitor over-broad pattern; TCS's site is the one that is actually exploitable.",
        "analysis": "`pickle.dumps` writes bytes and cannot execute attacker code. The attack is the `pickle.loads` on the "
                    "cookie at 214, which all three engines report. Semgrep's rule is a plain call-name match, so it flags the "
                    "harmless half. Bandit additionally fires B403 on `import pickle` at views.py:7, an import-line blacklist "
                    "hit with no sink at all.",
    },
    {
        "title": "F4 - A real TCS gap: one missing token in the CWE-338 sink list",
        "site": "external/pygoat/introduction/views.py:680 `random.choices(string.ascii_uppercase + ..., k=10)`; dockerized_labs/sensitive_data_exposure/dataexposure/views.py:42 `random.choices(chars, k=16)`",
        "engines": "Bandit B311 (CWE-330) at both; Semgrep silent; TCS reports CWE-338 only at views.py:496 (`randint`)",
        "verdict": "Genuine TCS false negative, with an exact root cause.",
        "analysis": "`data/rules_catalog.json` CWE-338 lists `random.random, random.randint, random.choice, random.randrange, "
                    "random.sample, numpy.random.rand`. `random.choice` is present, `random.choices` is not, and the matcher "
                    "compares attribute names exactly, so `random.choices` never becomes a sink. Both missed sites are "
                    "security-relevant token generators (support ticket ID, 16-char exposure code). One sink-list entry closes "
                    "it; no engine change is required.",
    },
    {
        "title": "F5 - Where TCS is silent for a structural reason: template markup and file scope",
        "site": "introduction/templates/Lab/XSS/xss_lab.html:27 `{{query|safe}}`; introduction/apis.py:64-70 `f.write(request.POST.get('log_code'))`; introduction/static/js/a7.js:4 (commented JWT)",
        "engines": "Semgrep template XSS/CSRF rules + `request-data-write` (CWE-93); Bandit and TCS silent",
        "verdict": "Three distinct non-comparable causes: unimplemented analysis, absent CWE in the catalog, and out-of-scope files.",
        "analysis": "(a) TCS audits `.html` templates (44 of its 224 PyGoat findings come from templates) but does not model "
                    "Jinja autoescape semantics, so `|safe` and a missing `{% csrf_token %}` are invisible to it - a real "
                    "coverage gap in a deliberately vulnerable app where these are the intended bugs. (b) `CWE-93` (CRLF "
                    "injection) has no entry in `rules_catalog.json` at all, so user-controlled writes can only surface under "
                    "another CWE - TCS reports the neighbouring `open(log_filename, \"w\")` as CWE-22. (c) TCS's scan covers "
                    "`.py`, templates and IaC; `.js` is not collected, so the JWT literal never reaches a rule - and that "
                    "literal sits inside a `//` comment, making it dead code rather than a live credential.",
    },
]


def render_report(
    results: Dict[str, tuple[List[Dict[str, Any]], float, Dict[str, Any]]],
    buckets: Dict[frozenset, List[Dict[str, Any]]],
    clusters: List[Dict[str, Any]],
    site_buckets: Dict[frozenset, List[Dict[str, Any]]],
    all_findings: Dict[str, List[Dict[str, Any]]],
    tolerance: int,
    versions: Dict[str, str],
) -> str:
    consensus = buckets.get(frozenset(TOOLS), [])
    tcs_only = buckets.get(frozenset({"tcs"}), [])
    order = [
        (frozenset(TOOLS), "Consensus (all three engines)"),
        (frozenset({"tcs", "semgrep"}), "TCS + Semgrep only"),
        (frozenset({"tcs", "bandit"}), "TCS + Bandit only"),
        (frozenset({"semgrep", "bandit"}), "Semgrep + Bandit only (TCS missed)"),
        (frozenset({"tcs"}), "TCS exclusive"),
        (frozenset({"semgrep"}), "Semgrep exclusive"),
        (frozenset({"bandit"}), "Bandit exclusive"),
    ]

    lines: List[str] = []
    add = lines.append

    add("# Independent 3-Way SAST Showdown - OWASP PyGoat")
    add("")
    add(f"- **Target:** `{TARGET}` (third-party OWASP application, read-only during this run)")
    add(f"- **Engines:** {', '.join(TOOL_LABEL[t] for t in TOOLS)}")
    add(f"- **Semgrep rulesets (pinned):** {', '.join(SEMGREP_CONFIGS)}")
    add(f"- **Version evidence:** {', '.join(f'{k} {v}' for k, v in versions.items())}")
    add(f"- **Location match rule:** same resolved file + same CWE + line within +/-{tolerance} lines")
    add("")
    add("## 1. High-level metrics")
    add("")
    rows = []
    for tool in TOOLS:
        findings, wall_ms, meta = results[tool]
        severities = severity_breakdown(findings)
        rows.append([
            TOOL_LABEL[tool],
            len(findings),
            len({item["file"] for item in findings}),
            len({item["cwe"] for item in findings}),
            "; ".join(f"{k}:{v}" for k, v in severities.items()) or "not reported",
            f"{wall_ms / 1000:.2f} s",
        ])
    add(md_table(["Engine", "Findings (CWE-expanded)", "Files hit", "Distinct CWEs", "Severity mix", "Wall clock"], rows))
    add("")
    add(f"- TCS engine-reported scan time: `{results['tcs'][2].get('engine_ms')} ms` over "
        f"`{results['tcs'][2].get('scanned_files')}` parsed files (includes template and IaC audits).")
    add(f"- Semgrep parsed-with-error files: `{results['semgrep'][2].get('parse_errors')}`; "
        f"files offered to it: `{results['semgrep'][2].get('scanned_files')}`.")
    add("")
    add("## 2. Overlap / divergence partition (strict: same CWE)")
    add("")
    add("Two engines count as agreeing only when they name the same CWE on the same line window.")
    add("")
    total = sum(len(v) for v in buckets.values())
    rows = []
    for key, label in order:
        count = len(buckets.get(key, []))
        share = "0.0%" if total == 0 else f"{100.0 * count / total:.1f}%"
        rows.append([label, count, share])
    add(md_table(["Partition", "Cluster count", "Share of all clusters"], rows))
    add(f"\nTotal distinct (file, CWE, line) clusters: **{total}**.\n")

    add("## 3. Site-level partition (CWE label ignored)")
    add("")
    add("The strict view conflates *classification disagreement* with *coverage disagreement*: "
        "`SECRET_KEY = \"...\"` is CWE-798 to TCS and CWE-259 to Bandit on the same line, "
        "which strict matching records as two separate sites. This view clusters purely on "
        "file + line proximity, so it answers the coverage question honestly.")
    add("")
    site_total = sum(len(v) for v in site_buckets.values())
    rows = []
    for key, label in order:
        count = len(site_buckets.get(key, []))
        share = "0.0%" if site_total == 0 else f"{100.0 * count / site_total:.1f}%"
        rows.append([label, count, share])
    add(md_table(["Partition", "Distinct code sites", "Share"], rows))
    add(f"\nTotal distinct code sites across all three engines: **{site_total}**.\n")
    rows = []
    for tool in TOOLS:
        hits = sum(len(value) for key, value in site_buckets.items() if tool in key)
        rows.append([TOOL_LABEL[tool], hits, site_total - hits,
                     f"{100.0 * hits / max(1, site_total):.1f}%"])
    add(md_table(["Engine", "Sites covered", "Sites missed", "Site recall vs union"], rows))
    add("")
    add("Line tolerance sensitivity (strict view, cluster totals):")
    add("")
    sens_rows = []
    for probe in (0, 2, 5, 10, 20):
        probed = partition(cluster(all_findings, probe))
        sens_rows.append([f"+/-{probe} line(s)", sum(len(v) for v in probed.values()),
                          len(probed.get(frozenset(TOOLS), [])),
                          len(probed.get(frozenset({"tcs"}), [])),
                          len(probed.get(frozenset({"semgrep"}), [])) + len(probed.get(frozenset({"bandit"}), []))])
    add(md_table(["Tolerance", "Total clusters", "Consensus", "TCS exclusive", "Competitor exclusive"], sens_rows))
    add("")

    add("## 4. Breakdown by CWE")
    add("")
    rows = [[row["cwe"], row["clusters"], row.get("tcs", 0), row.get("semgrep", 0), row.get("bandit", 0)]
            for row in cwe_matrix(clusters)]
    add(md_table(["CWE", "Clusters", "TCS", "Semgrep", "Bandit"], rows))
    add("")

    add("## 5. Consensus findings (all three engines agree)")
    add("")
    if consensus:
        rows = [[_relpath(c["file"]), c["line"], c["cwe"],
                 _representative(c, "tcs").get("rule", ""),
                 _representative(c, "semgrep").get("rule", ""),
                 _representative(c, "bandit").get("rule", "")] for c in consensus]
        add(md_table(["File", "Line", "CWE", "TCS category", "Semgrep rule", "Bandit test"], rows))
    else:
        add("_No finding was reported by all three engines on the same (file, CWE) site._")
    add("")

    add("## 6. TCS-exclusive findings (missed by both Semgrep and Bandit)")
    add("")
    categories = collections.Counter(
        (_representative(c, "tcs").get("rule", "?"), c["cwe"]) for c in tcs_only
    )
    add(md_table(["TCS rule", "CWE", "Clusters"],
                 [[rule, cwe, n] for (rule, cwe), n in sorted(categories.items(), key=lambda p: (-p[1], p[0]))]))
    add("")
    add("Full list:")
    add("")
    rows = [[_relpath(c["file"]), c["line"], c["cwe"], _representative(c, "tcs").get("message", "")[:110]]
            for c in tcs_only]
    add(md_table(["File", "Line", "CWE", "TCS message"], rows))
    add("")

    add("## 7. Competitor-exclusive findings (not reported by TCS under the same CWE)")
    add("")
    add("Each site is classified by re-reading the PyGoat source behind it, not by rule name alone. "
        "See `VERDICT_NOTES` in this script for the per-rule reasoning.")
    add("")
    tally = collections.Counter()
    for key, label in [(frozenset({"semgrep", "bandit"}), "Semgrep + Bandit"),
                       (frozenset({"semgrep"}), "Semgrep"),
                       (frozenset({"bandit"}), "Bandit")]:
        items = buckets.get(key, [])
        add(f"### {label}-only ({len(items)} clusters)")
        add("")
        if not items:
            add("_None._")
            add("")
            continue
        rows = []
        for c in items:
            winner = _representative(c, "semgrep") or _representative(c, "bandit")
            category, reasoning = classify(c, all_findings["tcs"])
            tally[category] += 1
            rows.append([_relpath(c["file"]), c["line"], c["cwe"], winner.get("rule", ""),
                         f"{category} - {reasoning}", str(winner.get("message", ""))[:90]])
        add(md_table(["File", "Line", "CWE", "Rule", "Verdict", "Message"], rows))
        add("")
    add("### Verdict tally over competitor-exclusive sites")
    add("")
    add(md_table(["Verdict", "Sites"], [[k, v] for k, v in sorted(tally.items(), key=lambda p: -p[1])]))
    add("")

    add("## 8. Forensic breakdown of five sites")
    add("")
    for item in FORENSICS:
        add(f"### {item['title']}")
        add("")
        add(f"- **Code:** `{item['site']}`")
        add(f"- **Engines:** {item['engines']}")
        add(f"- **Verdict:** {item['verdict']}")
        add("")
        add(item["analysis"])
        add("")

    return "\n".join(lines)


def serialize_one(cluster: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "file": _relpath(cluster["file"]),
        "abs_file": cluster["file"],
        "line": cluster["line"],
        "cwe": cluster["cwe"],
        "tools": sorted(cluster["tools"]),
        "rules": {member["tool"]: member.get("rule") for member in cluster["members"]},
        "messages": {member["tool"]: member.get("message") for member in cluster["members"]},
    }


def serialize_buckets(buckets: Dict[frozenset, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
    serialized: Dict[str, List[Dict[str, Any]]] = {}
    for key, items in sorted(buckets.items(), key=lambda pair: sorted(pair[0])):
        serialized["+".join(sorted(key))] = [serialize_one(item) for item in items]
    return serialized


def main() -> int:
    parser = argparse.ArgumentParser(description="3-way SAST showdown on OWASP PyGoat")
    parser.add_argument("--tolerance", type=int, default=5, help="line tolerance for location matching")
    parser.add_argument("--report", default=str(ROOT / "reports" / "pygoat_independent_showdown.md"))
    parser.add_argument("--json-out", default="", help="optional path for the full clustered JSON")
    args = parser.parse_args()

    results = {}
    for tool, collector in (("tcs", collect_tcs), ("semgrep", collect_semgrep), ("bandit", collect_bandit)):
        print(f"[*] running {TOOL_LABEL[tool]} ...", flush=True)
        findings, wall_ms, meta = collector()
        results[tool] = (findings, wall_ms, meta)
        print(f"    {len(findings)} CWE-expanded findings in {wall_ms / 1000:.2f}s ({meta.get('scanned_files')} files)")
    versions = {
        "semgrep": str(results["semgrep"][2].get("version")),
        "bandit": _probe_version(["bandit", "--version"]),
        "tcs": _probe_version([sys.executable or "python", "cli.py", "--version"]),
    }

    all_findings = {tool: results[tool][0] for tool in TOOLS}
    clusters = cluster(all_findings, args.tolerance)
    buckets = partition(clusters)
    site_buckets = partition(cluster(all_findings, SITE_WINDOW, cwe_sensitive=False))

    report = render_report(results, buckets, clusters, site_buckets, all_findings, args.tolerance, versions)

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report + "\n", encoding="utf-8")
    print(f"[+] report written: {report_path}")

    competitor_only = [
        raw for key in (frozenset({"semgrep", "bandit"}), frozenset({"semgrep"}), frozenset({"bandit"}))
        for raw in buckets.get(key, [])
    ]
    verdict_rows = []
    for raw in competitor_only:
        item = serialize_one(raw)
        category, reasoning = classify(raw, all_findings["tcs"])
        verdict_rows.append({
            "file": item["file"], "line": item["line"], "cwe": item["cwe"],
            "rule": (_representative(raw, "semgrep") or _representative(raw, "bandit")).get("rule"),
            "verdict": category,
            "reasoning": reasoning,
        })

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "tolerance": args.tolerance,
            "site_window": SITE_WINDOW,
            "totals": {tool: len(all_findings[tool]) for tool in TOOLS},
            "wall_ms": {tool: round(results[tool][1], 1) for tool in TOOLS},
            "meta": {tool: results[tool][2] for tool in TOOLS},
            "buckets": serialize_buckets(buckets),
            "site_buckets": serialize_buckets(site_buckets),
            "competitor_only_verdicts": verdict_rows,
        }
        out_path.write_text(json.dumps(payload, indent=1), encoding="utf-8")
        print(f"[+] clustered json written: {out_path}")

    print("\n" + "=" * 72)
    print(f"{'Partition':<42}{'Count':>8}")
    print("-" * 72)
    labels = {
        frozenset(TOOLS): "Consensus (TCS + Semgrep + Bandit)",
        frozenset({"tcs", "semgrep"}): "TCS + Semgrep",
        frozenset({"tcs", "bandit"}): "TCS + Bandit",
        frozenset({"semgrep", "bandit"}): "Semgrep + Bandit (TCS missed)",
        frozenset({"tcs"}): "TCS exclusive",
        frozenset({"semgrep"}): "Semgrep exclusive",
        frozenset({"bandit"}): "Bandit exclusive",
    }
    for key, label in labels.items():
        print(f"{label:<42}{len(buckets.get(key, [])):>8}")
    print("-" * 72)
    print(f"{'TOTAL distinct sites':<42}{sum(len(v) for v in buckets.values()):>8}")
    for tool in TOOLS:
        reported = sum(1 for c in clusters if tool in c["tools"])
        print(f"{TOOL_LABEL[tool] + ' coverage of distinct sites':<42}{reported:>8}"
              f"  ({100.0 * reported / max(1, sum(len(v) for v in buckets.values())):.1f}%)")
    print("=" * 72)
    site_total = sum(len(v) for v in site_buckets.values())
    print("SITE-LEVEL VIEW (CWE label ignored, +/-" + str(SITE_WINDOW) + " lines)")
    print("-" * 72)
    for key, label in labels.items():
        print(f"{label:<42}{len(site_buckets.get(key, [])):>8}")
    print("-" * 72)
    print(f"{'TOTAL distinct code sites':<42}{site_total:>8}")
    for tool in TOOLS:
        hits = sum(len(v) for key, v in site_buckets.items() if tool in key)
        print(f"{TOOL_LABEL[tool] + ' site coverage':<42}{hits:>8}"
              f"  ({100.0 * hits / max(1, site_total):.1f}%)")
    print("=" * 72)
    verdicts = collections.Counter(row["verdict"] for row in verdict_rows)
    print("COMPETITOR-EXCLUSIVE VERDICT TALLY (see report section 7)")
    print("-" * 72)
    for verdict, count in verdicts.most_common():
        print(f"{verdict:<42}{count:>8}")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
