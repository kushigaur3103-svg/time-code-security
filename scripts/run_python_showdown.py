"""Muqabla 2: independent 3-way showdown (TCS vs Semgrep vs Bandit) on third-party-labelled
Python ground truth.

NIST SARD publishes zero Python test cases, so this benchmark runs on the two corpora whose labels
are written by the competitors themselves (mirrored read-only by scripts/setup_python_benchmark.py):

  * external/semgrep_rules_python  -> upstream `# ruleid:` (vulnerable line) / `# ok:` (must-not-fire
    line) annotations, with each rule's CWE read from its own YAML metadata.
  * external/bandit_corpus         -> per-example expected issue counts asserted by Bandit's own
    functional tests, plus `# nosec` line-level negative markers.

Every subprocess writes its report to a file on disk (never a live pipe), so a chatty child cannot
deadlock the harness. Engine and corpus files are opened read-only throughout.

Usage::

    py.exe scripts/run_python_showdown.py            # labels -> run -> score -> report
    py.exe scripts/run_python_showdown.py --stage labels
    py.exe scripts/run_python_showdown.py --tcs-mode api --corpus bandit   # in-process TCS sweep
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = ROOT / "external"
ARTIFACTS = ROOT / "scratch" / "showdown"
BASELINE_DIR = "before_d1d2"
REPORT = ROOT / "reports" / "python_ground_truth_showdown.md"

CORPORA = {
    "semgrep_rules": {
        "dir": EXTERNAL / "semgrep_rules_python",
        "code": EXTERNAL / "semgrep_rules_python" / "python",
        "label": "Semgrep upstream rule tests (line-level)",
    },
    "bandit": {
        "dir": EXTERNAL / "bandit_corpus",
        "code": EXTERNAL / "bandit_corpus" / "examples",
        "label": "Bandit examples (file-level + nosec lines)",
    },
}

ANNOT = re.compile(r"^\s*(?P<code>.*?)(?<!\\)#\s*(?P<kind>ruleid|ok|tadpol|todo|fixme)\s*:?\s*(?P<rule>[\w.\-]+)\s*$")
NOSEC = re.compile(r"#\s*nosec\b")
CWE_TEXT = re.compile(r"CWE-(\d{2,5})", re.I)


# ─────────────────────────────────────────── helpers ───────────────────────────────────────────
def norm(path: str) -> str:
    """Repo-relative, forward-slashed, case-folded key so all three tools agree on a file."""
    p = Path(str(path).strip('"'))
    try:
        p = p.resolve().relative_to(ROOT)
    except Exception:  # noqa: BLE001
        pass
    return str(p).replace("\\", "/").lower()


def run_to_file(cmd: list[str], out: Path, err: Path, cwd: Path = ROOT,
                timeout: int = 7200, env: dict | None = None) -> tuple[int, float]:
    """Execute a tool with stdout/stderr bound to files on disk; return (exit code, seconds)."""
    started = time.perf_counter()
    with open(out, "wb") as fo, open(err, "wb") as fe:
        try:
            proc = subprocess.run(cmd, stdout=fo, stderr=fe, cwd=str(cwd), timeout=timeout,
                                  env=env)
            code = proc.returncode
        except subprocess.TimeoutExpired:
            code = -1
    return code, (time.perf_counter() - started) * 1000.0


def utf8_env() -> dict:
    """Semgrep writes its JSON report with the OS locale codec, so on Windows a single cp1252-
    unencodable byte anywhere in the corpus aborts the whole run (exit 2, empty report). Running
    the child in UTF-8 mode fixes the serialisation without changing what it analyses."""
    return {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}


def read_json(path: Path) -> dict:
    """Tool reports embed raw source snippets, which are not guaranteed to be valid UTF-8;
    decode leniently rather than aborting the run on one byte."""
    if not path.exists():
        return {}
    text = path.read_bytes().decode("utf-8", errors="replace")
    return json.loads(text or "{}")


def corpus_fingerprint(corpus_dir: Path) -> str:
    digest = hashlib.sha256()
    for f in sorted((p for p in corpus_dir.rglob("*") if p.is_file()
                     and p.name != ".provenance.json"),
                    key=lambda p: str(p.relative_to(corpus_dir)).replace("\\", "/")):
        digest.update(str(f.relative_to(corpus_dir)).replace("\\", "/").encode())
        digest.update(b"\0")
        digest.update(f.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def verify_integrity() -> dict:
    """Prove the mirrored corpora were not touched during the benchmark."""
    result = {}
    manifest_path = EXTERNAL / "python_benchmark_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    for key, spec in CORPORA.items():
        recorded = (manifest.get(key) or {}).get("sha256_corpus")
        actual = corpus_fingerprint(spec["dir"])
        result[key] = {"recorded": recorded, "actual": actual,
                       "unchanged": recorded == actual if recorded else "unknown"}
    return result


# ─────────────────────────────────────── ground truth ─────────────────────────────────────────
@dataclass
class Assertion:
    corpus: str
    kind: str            # "pos" (must be found) | "neg" (must not be found)
    file: str            # normalised path
    line: int
    granularity: str     # "line" | "file"
    rule: str = ""
    cwes: list = field(default_factory=list)


def rule_cwes_from_yamls(corpus_dir: Path) -> dict[str, list[str]]:
    """rule id -> declared CWE list, read from upstream's own rule metadata."""
    mapping: dict[str, list[str]] = {}
    for path in corpus_dir.rglob("*.yaml"):
        try:
            import yaml
            doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            continue
        for rule in (doc or {}).get("rules", []) or []:
            if not isinstance(rule, dict) or "id" not in rule:
                continue
            cwes: set[str] = set()
            raw = (rule.get("metadata") or {}).get("cwe")
            for blob in (raw if isinstance(raw, list) else [raw]):
                for m in CWE_TEXT.finditer(str(blob or "")):
                    cwes.add("CWE-" + m.group(1))
            mapping.setdefault(str(rule["id"]), sorted(cwes))
    return mapping


def target_line(lines: list[str], annotation_index: int, has_code: bool) -> int | None:
    """Upstream puts `# ruleid:` on the offending line, or on the line just above it."""
    if has_code:
        return annotation_index + 1
    for j in range(annotation_index + 1, min(annotation_index + 6, len(lines))):
        stripped = lines[j].strip()
        if not stripped or stripped.startswith("#"):
            continue
        return j + 1
    return None


def semgrep_assertions(corpus: str, code_dir: Path, rule_map: dict) -> list[Assertion]:
    out: list[Assertion] = []
    for path in sorted(code_dir.rglob("*.py")):
        key = norm(path)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for idx, line in enumerate(lines):
            match = ANNOT.match(line)
            if not match or match.group("kind") not in ("ruleid", "ok"):
                continue
            rule = match.group("rule")
            target = target_line(lines, idx, bool(match.group("code").strip()))
            if target is None:
                continue
            out.append(Assertion(
                corpus=corpus,
                kind="pos" if match.group("kind") == "ruleid" else "neg",
                file=key, line=target, granularity="line", rule=rule,
                cwes=rule_map.get(rule, []),
            ))
    return out


def bandit_expectations(functional_py: Path) -> dict[str, int]:
    """file -> expected issue count, straight out of Bandit's own functional test literals."""
    tree = ast.parse(functional_py.read_text(encoding="utf-8", errors="replace"))
    expected: dict[str, int] = {}
    for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        locals_map: dict[str, ast.AST] = {}
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                locals_map[node.targets[0].id] = node.value
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "check_example" and len(node.args) >= 2):
                continue
            name = node.args[0]
            if not isinstance(name, ast.Constant) or not isinstance(name.value, str):
                continue
            value = locals_map.get(getattr(node.args[1], "id", "")) or node.args[1]
            try:
                expect = ast.literal_eval(value)
            except Exception:  # noqa: BLE001
                continue
            severity = expect.get("SEVERITY") if isinstance(expect, dict) else None
            if isinstance(severity, dict):
                expected[name.value] = sum(int(v) for v in severity.values() if isinstance(v, int))
    return expected


def bandit_assertions(corpus: str, examples_dir: Path, functional_py: Path) -> list[Assertion]:
    expected = bandit_expectations(functional_py)
    out: list[Assertion] = []
    for path in sorted(examples_dir.rglob("*.py")):
        key = norm(path)
        count = expected.get(path.name)
        if count is None:
            continue
        out.append(Assertion(corpus=corpus, kind="pos" if count > 0 else "neg", file=key,
                             line=0, granularity="file", rule=f"bandit-expected-issues={count}",
                             cwes=[]))
        for idx, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if NOSEC.search(line):
                out.append(Assertion(corpus=corpus, kind="neg", file=key, line=idx,
                                     granularity="line", rule="nosec", cwes=[]))
    return out


# ─────────────────────────────────────────── tool runs ───────────────────────────────────────
def findings_from_tcs_cli(corpus_dir: Path, tag: str,
                          per_file_timeout: int = 30) -> tuple[list[dict], dict]:
    """One CLI invocation per file: a whole-directory run is unusable on these corpora (see the
    crash audit in the report), and per-file isolation is the only way to score every file that
    the engine can actually analyse without hiding the failures. A hung invocation is killed at
    `per_file_timeout` seconds and recorded as a failed invocation, never silently skipped."""
    out_dir = ARTIFACTS / f"tcs_{tag}"
    out_dir.mkdir(parents=True, exist_ok=True)
    findings: list[dict] = []
    durations: list[float] = []
    errors: list[dict] = []
    files = sorted(p for p in corpus_dir.rglob("*.py"))
    for position, path in enumerate(files, 1):
        rel = str(path.relative_to(ROOT)).replace("\\", "/")
        stdout = out_dir / f"{position:04d}.json"
        stderr = out_dir / f"{position:04d}.err"
        code, ms = run_to_file([sys.executable, "cli.py", "scan", rel, "--scope", "python",
                                "--format", "json"], stdout, stderr,
                               timeout=per_file_timeout)
        durations.append(ms)
        try:
            if code == -1:
                raise RuntimeError(f"TIMEOUT after {per_file_timeout}s (killed)")
            payload = read_json(stdout)
            rows = payload.get("findings", [])
            if not rows and code != 0:
                raise ValueError(stdout.stat().st_size and "invalid json" or "empty output")
        except Exception as exc:  # noqa: BLE001
            tail = stderr.read_text(encoding="utf-8", errors="replace").strip().splitlines()
            kind = "TIMEOUT" if code == -1 else (tail[-1][:160] if tail else str(exc))
            errors.append({"file": norm(path), "exit": code, "error": kind[:160]})
            continue
        for row in rows:
            findings.append({"tool": "TCS", "file": norm(row.get("file", rel)),
                             "line": int(row.get("line") or 0), "cwe": row.get("cwe"),
                             "native": row.get("message", "")})
        if position % 60 == 0:
            print(f"    tcs {position}/{len(files)} files, {len(findings)} findings", flush=True)
    stats = {"invocations": len(files), "crashed": len(errors), "errors": errors,
             "timeouts": sum(1 for e in errors if e["error"].startswith("TIMEOUT")),
             "ms_total": sum(durations), "ms_median_per_file": statistics.median(durations)
             if durations else 0.0, "per_file_timeout_s": per_file_timeout,
             "mode": "cli-per-file"}
    return findings, stats


def findings_from_tcs_api(corpus_dir: Path) -> tuple[list[dict], dict]:
    """Same engine, one process, per-file isolation via try/except (used only for the duration
    comparison against the per-invocation CLI sweep)."""
    sys.path.insert(0, str(ROOT))
    from ast_scanner import TaintTracker  # noqa: PLC0415
    from cli import consolidate_findings, get_rule  # noqa: PLC0415
    findings: list[dict] = []
    errors: list[dict] = []
    started = time.perf_counter()
    for path in sorted(corpus_dir.rglob("*.py")):
        try:
            tracker = TaintTracker(files={norm(path): path.read_text(encoding="utf-8",
                                                                      errors="replace")})
            _s, sinks, edges = tracker.analyze()
            by_id = {s.id: s for s in sinks}
            raw_findings = []
            seen: set[tuple[str, int, str]] = set()
            for edge in edges:
                sink = by_id.get(edge.target_id)
                if sink is None:
                    continue
                cwe = (sink.metadata or {}).get("cwe")
                if not cwe and edge.proof_graph is not None:
                    cwe = edge.proof_graph.cwe
                cwe = cwe or "UNKNOWN_CWE"
                rule = get_rule(cwe)
                confidence_label = "CONFIRMED" if edge.kind == "CONFIRMED_DATA_FLOW" else "POTENTIAL"
                severity = rule.get_severity(confidence_label).upper() if rule else "HIGH"
                location = sink.location
                finding = {
                    "file": norm(path),
                    "line": location.line_start,
                    "cwe": cwe,
                    "severity": severity,
                    "category": (sink.metadata or {}).get("category") or (rule.category if rule else "Security"),
                    "message": f"{cwe}: {(sink.metadata or {}).get('operation') or sink.symbol}",
                }
                identity = (finding["file"], finding["line"], finding["cwe"])
                if identity not in seen:
                    seen.add(identity)
                    raw_findings.append(finding)
            # Apply same consolidation as CLI production pipeline
            consolidated = consolidate_findings(raw_findings)
            findings.extend([{"tool": "TCS", **f, "native": f.get("message", "")} for f in consolidated])
        except Exception as exc:  # noqa: BLE001
            errors.append({"file": norm(path), "error": f"{type(exc).__name__}: {exc}"[:160]})
    ms = (time.perf_counter() - started) * 1000.0
    return findings, {"mode": "api-single-process", "ms_total": ms, "crashed": len(errors),
                      "errors": errors, "invocations": 1, "timeouts": 0,
                      "ms_median_per_file": ms / max(len(findings), 1)}


def findings_from_semgrep(corpus_dir: Path, tag: str) -> tuple[list[dict], dict]:
    out = ARTIFACTS / f"semgrep_{tag}.json"
    err = ARTIFACTS / f"semgrep_{tag}.err"
    cmd = ["semgrep", "scan", "--config", "p/default", "--config", "p/security-audit",
           str(corpus_dir.relative_to(ROOT)), "--json", "--metrics=off", "--quiet",
           "--no-git-ignore", "-o", str(out)]
    code, ms = run_to_file(cmd, out, err, env=utf8_env())
    payload = read_json(out)
    findings = semgrep_findings(read_json(out))
    stats = {"exit": code, "ms_total": ms, "results": len(findings),
             "errors": len(read_json(out).get("errors", []) or []),
             "child_utf8_mode": True,
             "files_scanned": len((read_json(out).get("paths") or {}).get("scanned", []) or []),
             "stderr_tail": err.read_text(encoding="utf-8", errors="replace").strip()
                            .splitlines()[-3:] if err.exists() else []}
    return findings, stats


def semgrep_findings(payload: dict) -> list[dict]:
    """Semgrep nests the rule metadata under `extra.metadata`, and its `cwe` field is a list of
    human strings like "CWE-78: Improper Neutralization…", so all CWEs named there are collected."""
    findings: list[dict] = []
    for res in payload.get("results", []):
        meta = (res.get("extra") or {}).get("metadata") or res.get("metadata") or {}
        cwes = sorted({"CWE-" + m.group(1)
                       for m in CWE_TEXT.finditer(json.dumps(meta.get("cwe") or ""))})
        check = str(res.get("check_id", ""))
        findings.append({"tool": "Semgrep", "file": norm(res.get("path", "")),
                         "line": int((res.get("start") or {}).get("line") or 0),
                         "cwe": (cwes or [None])[0], "cwes": cwes,
                         "native": check.rsplit(".", 1)[-1], "check_id": check})
    return findings


def refresh_semgrep_from_artifacts(payload: dict) -> dict:
    """Re-parse the Semgrep reports already on disk (the tool's own output from this run) instead of
    re-invoking it, so a harness-side extraction fix can be applied without re-running the sweep."""
    for corpus in payload["findings"]:
        report = ARTIFACTS / f"semgrep_{corpus}.json"
        if not report.exists():
            continue
        parsed = read_json(report)
        findings = semgrep_findings(parsed)
        payload["findings"][corpus]["Semgrep"] = findings
        st = payload["stats"].get("Semgrep", {}).get(corpus)
        if st is not None:
            st["results"] = len(findings)
            st["with_cwe"] = sum(1 for f in findings if f["cwes"])
            st["refreshed_from_artifact"] = True
    return payload


def findings_from_bandit(corpus_dir: Path, tag: str) -> tuple[list[dict], dict]:
    out = ARTIFACTS / f"bandit_{tag}.json"
    err = ARTIFACTS / f"bandit_{tag}.err"
    cmd = ["bandit", "-q", "-r", str(corpus_dir.relative_to(ROOT)), "-f", "json",
           "-o", str(out)]
    code, ms = run_to_file(cmd, out, err, env=utf8_env())
    payload = read_json(out)
    findings = []
    for res in payload.get("results", []):
        cwe = ((res.get("issue_cwe") or {}).get("id"))
        findings.append({"tool": "Bandit", "file": norm(res.get("filename", "")),
                         "line": int(res.get("line_number") or 0),
                         "cwe": f"CWE-{cwe}" if isinstance(cwe, int) else None,
                         "native": res.get("test_id"),
                         "text": res.get("issue_text", "")})
    stats = {"exit": code, "ms_total": ms, "results": len(findings),
             "node_errors": len(payload.get("errors", []) or [])}
    return findings, stats


# ─────────────────────────────────────────── scoring ──────────────────────────────────────────
@dataclass
class Score:
    tool: str
    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0
    cwe_mismatch: int = 0     # right line, wrong weakness class
    cluster_tp: int = 0       # TP only because the CWE is in the same equivalence cluster
    unscored: int = 0         # findings that hit neither a pos nor a neg assertion
    cluster_reclaimed: list = field(default_factory=list)


# MITRE abstraction-level divergence: the same primitive named at different levels of the same
# family, scored as a hit instead of double-penalised as FN + out-of-label. Members are chosen from
# the observed line-hit mismatches, and every cluster is a family the two vendors demonstrably label
# differently for one construct (e.g. `os.chmod(0o777)` -> Semgrep CWE-276, Bandit CWE-732).
# Deliberately absent: CWE-94/CWE-95 (dynamic compilation vs direct evaluation) and CWE-502/CWE-94
# (deserialisation vs code injection) are distinct weakness classes, and folding them would erase a
# real classification error rather than a naming one.
CWE_EQUIVALENCE_CLUSTERS: tuple[frozenset[str], ...] = (
    frozenset({"CWE-326", "CWE-327", "CWE-328", "CWE-759", "CWE-916"}),  # crypto strength/algorithm
    frozenset({"CWE-276", "CWE-277", "CWE-732"}),                        # permission assignment
    frozenset({"CWE-614", "CWE-1004", "CWE-1275"}),                      # cookie attribute flags
    frozenset({"CWE-312", "CWE-319", "CWE-522", "CWE-523"}),             # credentials in cleartext
    frozenset({"CWE-295", "CWE-322"}),                                   # peer identity unverified
    frozenset({"CWE-79", "CWE-80", "CWE-116"}),                          # output escaping / XSS
    frozenset({"CWE-22", "CWE-23", "CWE-36", "CWE-73"}),                 # external path/name control
    frozenset({"CWE-77", "CWE-78", "CWE-88"}),                           # command / argument injection
)


def _cluster_of(cwe: str | None) -> frozenset[str] | None:
    """The equivalence family a CWE belongs to, or None when it stands alone."""
    if not cwe:
        return None
    for cluster in CWE_EQUIVALENCE_CLUSTERS:
        if cwe in cluster:
            return cluster
    return None


def _cwe_match_kind(finding: dict, cwes: list) -> str:
    """'exact' when the tool names the declared class, 'cluster' when it names a same-family alias,
    'none' otherwise. No CWE declared by the label degrades to 'exact' (line-only matching)."""
    if not cwes:
        return "exact"
    named = {finding.get("cwe")} | set(finding.get("cwes") or [])
    if named & set(cwes):
        return "exact"
    declared = {c for c in cwes if _cluster_of(c)}
    got = {c for c in named if c and _cluster_of(c)}
    if any(_cluster_of(a) & _cluster_of(b) for a in declared for b in got):
        return "cluster"
    return "none"


def _cwe_ok(finding: dict, cwes: list) -> bool:
    """True when the tool names the weakness the label declares (no CWE declared = any hit)."""
    return _cwe_match_kind(finding, cwes) != "none"


def score_tool(assertions: list[Assertion], findings: list[dict], tool: str,
               tolerance: int = 1, cwe_strict: bool = True) -> tuple[Score, list[dict]]:
    score = Score(tool=tool)
    misses: list[dict] = []
    cluster_reclaimed = score.cluster_reclaimed
    used: set[int] = set()
    by_file: dict[str, list[tuple[int, dict]]] = {}
    for idx, finding in enumerate(findings):
        by_file.setdefault(finding["file"], []).append((idx, finding))

    for a_idx, assertion in enumerate(assertions):
        rows = by_file.get(assertion.file, [])
        if assertion.granularity == "line":
            window = range(assertion.line - tolerance, assertion.line + tolerance + 1)
            hit = [i for i, f in rows if f["line"] in window]
        else:
            hit = [i for i, f in rows]
        if assertion.kind == "pos":
            kinds = [(i, _cwe_match_kind(findings[i], assertion.cwes)) for i in hit]
            matched = [i for i, kind in kinds if kind != "none" or not cwe_strict]
            if matched:
                score.tp += 1
                used.update(matched)
                if cwe_strict and not any(k == "exact" for _, k in kinds):
                    score.cluster_tp += 1
                    cluster_reclaimed.append({"assertion": asdict(assertion),
                                              "line_matched": [{k: findings[i].get(k)
                                                                 for k in ("line", "cwe", "native")}
                                                                for i in hit]})
            else:
                score.fn += 1
                if hit:  # right place, wrong (or missing) weakness class
                    score.cwe_mismatch += 1
                misses.append({"kind": "FN", "assertion": asdict(assertion),
                               "line_matched": [{k: findings[i].get(k)
                                                 for k in ("line", "cwe", "native")}
                                                for i in hit]})
        else:
            if hit:
                score.fp += 1
                used.update(hit)
                misses.append({"kind": "FP", "assertion": asdict(assertion),
                               "false_positive": [{k: findings[i].get(k)
                                                  for k in ("line", "cwe", "native")}
                                                 for i in hit]})
            else:
                score.tn += 1
    score.unscored = len([i for i in range(len(findings)) if i not in used])
    return score, misses


def prf(score: Score) -> tuple[float, float, float]:
    precision = score.tp / (score.tp + score.fp) if score.tp + score.fp else 0.0
    recall = score.tp / (score.tp + score.fn) if score.tp + score.fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


# ────────────────────────────────────────── aggregation ─────────────────────────────────────────
TOOL_ORDER = ["TCS", "Semgrep", "Bandit"]


def _as_assertion(row: dict) -> Assertion:
    return Assertion(**row)


def _fn_taxonomy(assertions: list[Assertion], findings: list[dict], misses: list[dict]) -> dict:
    """Split missed positives by *why* they were missed, using only the tool's own output."""
    by_file: dict[str, int] = {}
    named_rules: set[str] = set()
    named_cwes: set[str] = set()
    for f in findings:
        by_file[f["file"]] = by_file.get(f["file"], 0) + 1
        if f.get("native"):
            named_rules.add(str(f["native"]))
        named_cwes.update(f.get("cwes") or [])
        if f.get("cwe"):
            named_cwes.add(f["cwe"])
    tax = {"line_hit_wrong_cwe": 0, "output_on_file_other_line": 0, "no_output_on_file": 0,
           "class_never_reported_by_tool": 0, "class_reported_elsewhere": 0}
    for miss in misses:
        if miss["kind"] != "FN":
            continue
        assertion = miss["assertion"]
        if miss["line_matched"]:
            tax["line_hit_wrong_cwe"] += 1
        elif by_file.get(assertion["file"]):
            tax["output_on_file_other_line"] += 1
        else:
            tax["no_output_on_file"] += 1
        known = bool(set(assertion["cwes"]) & named_cwes) or (
            bool(assertion["rule"]) and assertion["rule"] in named_rules)
        tax["class_reported_elsewhere" if known else "class_never_reported_by_tool"] += 1
    return tax


def _score_set(assertions: list[Assertion], findings_by_tool: dict,
               cwe_strict: bool = True) -> dict:
    out: dict[str, dict] = {}
    for tool in TOOL_ORDER:
        findings = findings_by_tool.get(tool) or []
        score, misses = score_tool(assertions, findings, tool, cwe_strict=cwe_strict)
        precision, recall, f1 = prf(score)
        out[tool] = {"score": asdict(score), "precision": precision, "recall": recall,
                     "f1": f1, "findings": len(findings),
                     "with_cwe": sum(1 for f in findings if f.get("cwes") or f.get("cwe")),
                     "fn_taxonomy": _fn_taxonomy(assertions, findings, misses),
                     "misses": misses}
    return out


def _merged(payload: dict) -> tuple[list[Assertion], dict]:
    assertions: list[Assertion] = []
    findings: dict[str, list[dict]] = {tool: [] for tool in TOOL_ORDER}
    for corpus, rows in payload["assertions"].items():
        assertions.extend(_as_assertion(r) for r in rows)
        for tool in TOOL_ORDER:
            findings[tool].extend(payload["findings"][corpus].get(tool) or [])
    return assertions, findings


def score_all(payload: dict) -> dict:
    """Score each corpus against its own labels, then the merged label set, then per CWE.
    `*_line` repeats the same matching ignoring the declared weakness class, as a sensitivity
    check on how much of the ranking depends on each tool publishing CWE metadata."""
    per_corpus = {}
    for corpus, rows in payload["assertions"].items():
        assertions = [_as_assertion(r) for r in rows]
        findings = payload["findings"][corpus]
        per_corpus[corpus] = {"assertions": len(assertions),
                              "pos": sum(1 for a in assertions if a.kind == "pos"),
                              "neg": sum(1 for a in assertions if a.kind == "neg"),
                              "scores": _score_set(assertions, findings),
                              "scores_line_only": _score_set(assertions, findings,
                                                             cwe_strict=False)}
    assertions, findings = _merged(payload)
    return {"per_corpus": per_corpus,
            "combined": {"assertions": len(assertions),
                         "pos": sum(1 for a in assertions if a.kind == "pos"),
                         "neg": sum(1 for a in assertions if a.kind == "neg"),
                         "scores": _score_set(assertions, findings),
                         "scores_line_only": _score_set(assertions, findings, cwe_strict=False)},
            "per_cwe": per_cwe_rows(assertions, findings)}


def per_cwe_rows(assertions: list[Assertion], findings: dict) -> list[dict]:
    """One row per CWE the labels declare, over every corpus (zero cherry-picking)."""
    buckets: dict[str, list[Assertion]] = {}
    for assertion in assertions:
        for cwe in assertion.cwes:
            buckets.setdefault(cwe, []).append(assertion)
    rows = []
    for cwe in sorted(buckets, key=lambda c: int(c.split("-")[1])):
        subset = buckets[cwe]
        row = {"cwe": cwe,
               "pos": sum(1 for a in subset if a.kind == "pos"),
               "neg": sum(1 for a in subset if a.kind == "neg"),
               "tools": {}}
        for tool in TOOL_ORDER:
            score, _ = score_tool(subset, findings.get(tool) or [], tool)
            precision, recall, _ = prf(score)
            row["tools"][tool] = {"tp": score.tp, "fn": score.fn, "fp": score.fp,
                                  "tn": score.tn, "precision": precision, "recall": recall}
        rows.append(row)
    return rows


def audit_categories(scores: dict) -> dict:
    """Group the misses by what the tool actually reported, so the audit names real rules."""
    out: dict[str, dict] = {}
    for tool, block in scores.items():
        fps: dict[str, int] = {}
        fns_nolocal: dict[str, int] = {}
        fns_cwe: dict[str, int] = {}
        for miss in block["misses"]:
            assertion = miss["assertion"]
            key = f'{assertion["corpus"]}:{assertion["rule"] or "-"}'
            if miss["kind"] == "FP":
                for row in miss["false_positive"]:
                    fps[f'{key} -> {row.get("native") or row.get("cwe") or "?"}'] = \
                        fps.get(f'{key} -> {row.get("native") or row.get("cwe") or "?"}', 0) + 1
            elif miss["line_matched"]:
                for row in miss["line_matched"]:
                    tag = f'{key} -> {row.get("native") or row.get("cwe") or "?"}'
                    fns_cwe[tag] = fns_cwe.get(tag, 0) + 1
            else:
                fns_nolocal[key] = fns_nolocal.get(key, 0) + 1
        out[tool] = {"fp": fps, "fn_no_line_hit": fns_nolocal, "fn_line_only": fns_cwe}
    return out


def _pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(cell for cell in row) + " |" for row in rows]
    return "\n".join(lines)


def master_rows(scoring: dict, scope: str, key: str = "scores") -> list[list[str]]:
    block = scoring[scope] if scope in scoring else scoring["per_corpus"][scope]
    out = []
    for tool in TOOL_ORDER:
        s = block[key][tool]["score"]
        out.append([tool, str(s["tp"]), str(s["cluster_tp"]), str(s["fp"]), str(s["tn"]),
                    str(s["fn"]),
                    _pct(block[key][tool]["precision"]),
                    _pct(block[key][tool]["recall"]),
                    _pct(block[key][tool]["f1"]),
                    str(s["cwe_mismatch"]), str(s["unscored"])])
    return out


def duration_rows(payload: dict, scope: str) -> str:
    if scope != "combined":
        return ""
    rows = []
    for tool in TOOL_ORDER:
        parts = payload["stats"].get(tool, {})
        ms = sum(v.get("ms_total", 0.0) for v in parts.values())
        detail = ", ".join(f"{k} {v.get('ms_total', 0.0) / 1000:.1f}s" for k, v in parts.items())
        rows.append([tool, f"{ms / 1000.0:.1f} s", detail or "-"])
    return _table(["Tool", "Wall clock (all corpora)", "Split"], rows)


def _tcs_errors(payload: dict) -> list[dict]:
    """Every TCS invocation that ended without usable JSON, tagged with its corpus."""
    out = []
    for corpus, st in payload["stats"].get("TCS", {}).items():
        for err in st.get("errors") or []:
            out.append({**err, "corpus": corpus})
    return out


def _timeouts(payload: dict) -> list[dict]:
    return [e for e in _tcs_errors(payload) if str(e.get("error", "")).startswith("TIMEOUT")]


def _aborts(payload: dict) -> list[dict]:
    return [e for e in _tcs_errors(payload)
            if not str(e.get("error", "")).startswith("TIMEOUT")]


def _tcs_findings_per_file(payload: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rows in payload["findings"].values():
        for finding in rows.get("TCS", []):
            counts[finding["file"]] = counts.get(finding["file"], 0) + 1
    return counts


def _tcs_finding_set(payload: dict) -> set[tuple]:
    return {(corpus, finding["file"], finding["line"], finding["cwe"], finding["native"])
            for corpus, rows in payload["findings"].items() for finding in rows.get("TCS", [])}


def _tcs_delta(baseline: dict, payload: dict) -> tuple[list, list]:
    """(added, removed) TCS findings between two sweeps. A removal on a file that the baseline
    sweep already scanned successfully is a regression; removals elsewhere are not expressible."""
    failed = {e["file"] for e in _tcs_errors(baseline)}
    base, now = _tcs_finding_set(baseline), _tcs_finding_set(payload)
    added = sorted(now - base)
    removed = sorted(k for k in base - now if k[1] not in failed)
    return added, removed


def load_baseline() -> dict | None:
    """The pre-fix sweep, if its artefact is still on disk. §7 quotes it to state what the
    defects cost before they were fixed; without it §7 only reports the current run."""
    path = ARTIFACTS / BASELINE_DIR / "raw_results.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def load_baseline_scoring() -> dict | None:
    path = ARTIFACTS / BASELINE_DIR / "scoring.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


SCORE_FIELDS = [("TP", ("score", "tp"), str), ("FP", ("score", "fp"), str),
                ("TN", ("score", "tn"), str), ("FN", ("score", "fn"), str),
                ("Precision", ("precision",), _pct), ("Recall", ("recall",), _pct),
                ("F1", ("f1",), _pct),
                ("Findings outside any label", ("score", "unscored"), str)]


def _score_cell(scoring: dict, tool: str, path: tuple):
    node = scoring["combined"]["scores"][tool]
    for part in path:
        node = node[part]
    return node


def _forced_fn_stats(scoring: dict, payload: dict) -> tuple[int, int, int, int]:
    """(missed positives, of those the ones on files the engine lost, files lost, killed by timeout).
    A labelled line in a file the sweep could not scan is an FN no engine capability can recover."""
    misses = [m for m in scoring["combined"]["scores"]["TCS"]["misses"] if m["kind"] == "FN"]
    errors = _tcs_errors(payload)
    failed = {e["file"] for e in errors}
    hangs = sum(1 for e in errors if str(e["error"]).startswith("TIMEOUT"))
    return (len(misses), sum(1 for m in misses if m["assertion"]["file"] in failed),
            len(failed), hangs)


def _scoring_delta_line(current: dict, baseline: dict | None) -> str:
    """Cell-by-cell comparison of the merged CWE-strict score rows between two sweeps."""
    if baseline is None:
        return ("* Scores: no baseline scoring artefact is on disk, so §2 is reported without a "
                "before/after comparison.")
    same, changed = 0, []
    for tool in TOOL_ORDER:
        for label, path, fmt in SCORE_FIELDS:
            try:
                x, y = _score_cell(baseline, tool, path), _score_cell(current, tool, path)
            except KeyError:
                continue
            if x != y:
                changed.append(f"{tool} {label} {fmt(x)}→{fmt(y)}")
            same += 1
    return (f"* Scores: {same - len(changed)} of {same} tool × metric cells in the merged CWE-strict "
            f"table are identical across the two sweeps." +
            (f" The differences are {'; '.join(changed)}." if changed else
             " No score moved at all.") +
            " What changed is that the files now returning nothing do so because the engine answered "
            "rather than because it was killed.")


def count_guarded_scope_walks() -> int:
    """Scope walks in ast_scanner.py that carry the D1 cycle guard."""
    return (ROOT / "ast_scanner.py").read_text(encoding="utf-8").count("_walk_seen = set()")


def count_scope_walk_sites() -> list[int]:
    """Lines repeating the `if "." in scope and "function" in scope: scope = scope.rsplit(".", 1)[0]`
    idiom in ast_scanner.py — read-only census of the copies that share the non-terminating shape."""
    text = (ROOT / "ast_scanner.py").read_text(encoding="utf-8").splitlines()
    pattern = re.compile(r'"\." in (\w+) and "function" in \1')
    return [i + 1 for i, line in enumerate(text) if pattern.search(line)]


def _all_findings(payload: dict, tool: str) -> list[dict]:
    return [f for rows in payload["findings"].values() for f in rows.get(tool, [])]


def emitted_cwes(payload: dict, tool: str) -> set[str]:
    out: set[str] = set()
    for finding in _all_findings(payload, tool):
        out.update(finding.get("cwes") or [])
        if finding.get("cwe"):
            out.add(finding["cwe"])
    return out


def never_emitted_classes(payload: dict, tool: str) -> list[tuple[str, int]]:
    """Labelled CWE classes with positive cases that `tool` never reports anywhere, ranked by the
    number of labelled lines they account for. Derived from the run's own artefacts."""
    emitted = emitted_cwes(payload, tool)
    labelled: dict[str, int] = {}
    for rows in payload["assertions"].values():
        for row in rows:
            if row["kind"] == "pos":
                for cwe in row["cwes"]:
                    labelled[cwe] = labelled.get(cwe, 0) + 1
    missing = [(cwe, n) for cwe, n in labelled.items() if cwe not in emitted]
    return sorted(missing, key=lambda cn: (-cn[1], cn[0]))


def tcs_miss_rows(scoring: dict, payload: dict, limit: int = 12) -> list[list[str]]:
    """Auto-cited evidence for the biggest TCS miss classes: the rule, how many labelled lines were
    missed, one real site with its source text, and whether TCS ever emits the labelled CWE at all."""
    emitted_cwe = emitted_cwes(payload, "TCS")
    by_rule: dict[str, list[dict]] = {}
    for miss in scoring["combined"]["scores"]["TCS"]["misses"]:
        if miss["kind"] == "FN":
            by_rule.setdefault(miss["assertion"]["rule"] or "(unruled)", []).append(miss)
    rows = []
    for rule, misses in sorted(by_rule.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:limit]:
        assertion = misses[0]["assertion"]
        source = "-"
        try:
            lines = (ROOT / assertion["file"]).read_text(encoding="utf-8",
                                                          errors="replace").splitlines()
            if 0 < assertion["line"] <= len(lines):
                source = lines[assertion["line"] - 1].strip()[:70]
        except OSError:
            pass
        declared = {c for m in misses for c in m["assertion"]["cwes"]}
        if not declared:
            covered = "no CWE declared by the rule"
        elif declared & emitted_cwe:
            covered = "CWE emitted elsewhere: " + ", ".join(sorted(declared & emitted_cwe))
        else:
            covered = "TCS never emits " + ", ".join(sorted(declared))
        rows.append([rule, str(len(misses)), ",".join(sorted(declared)) or "-",
                     f"{Path(assertion['file']).name}:{assertion['line']}", source, covered])
    return rows


def render_report(payload: dict, scoring: dict) -> str:
    audits = audit_categories(scoring["combined"]["scores"])
    md: list[str] = []
    md.append("# Muqabla 2 — Python ground-truth showdown: TCS vs Semgrep vs Bandit\n")
    md.append(
        "> **Provenance correction (read this first).** The task asked for 100% of the NIST SAMATE / "
        "SARD *Python* test cases. NIST SARD publishes **zero** Python cases. Measured against the live "
        "language filter `https://samate.nist.gov/SARD/test-cases/search?language[]=<lang>`: "
        "PHP 291,048 · C 45,437 · Java 32,356 · C++ 25,795 · **Python — \"No test cases found\"**. The "
        "public test-suite archive (all 80 zips) ships Juliet for C/C++, Java and C# only. "
        "`external/juliet_samate/` therefore does not exist and was never created. "
        "This benchmark keeps the requested methodology but runs it on the largest Python corpora that "
        "carry *independent* per-line ground truth, authored by the two competitors themselves — the "
        "tools being scored wrote the labels, which is a real limitation and is stated in §6.\n")

    md.append("## 1. Corpora, labels and integrity\n")
    prov = []
    manifest_path = EXTERNAL / "python_benchmark_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    for key, entry in manifest.items():
        if key == "generated_at":
            continue
        prov.append([key, str(entry.get("commit", ""))[:12], str(entry.get("files_mirrored", "")),
                     f"{(entry.get('bytes_total', 0) or 0) / 1048576:.2f} MB",
                     str(entry.get("url", ""))])
    md.append(_table(["Corpus", "Commit", "Files", "Bytes", "Source"], prov) + "\n")
    labels = []
    for corpus, block in scoring["per_corpus"].items():
        labels.append([corpus, str(block["assertions"]), str(block["pos"]), str(block["neg"]),
                       CORPORA[corpus]["label"]])
    md.append(_table(["Corpus", "Assertions", "Positive (must find)",
                      "Negative (must not fire)", "Label semantics"], labels) + "\n")
    md.append(f"CWEs declared by the labels: **{len(scoring['per_cwe'])}** "
              f"({', '.join(r['cwe'] for r in scoring['per_cwe'])}) — every one of them is scored, "
              "none selected.\n")
    md.append("Corpus mutation check (SHA-256 over each mirrored tree, before vs after the run):\n")
    integ = []
    for key, block in payload["integrity_after"].items():
        integ.append([key, "UNCHANGED" if block["unchanged"] is True else
                     ("RECORDED LATER" if block["unchanged"] == "unknown" else "CHANGED"),
                     str(block["actual"])[:16] + "…"])
    md.append(_table(["Corpus", "Result", "sha256"], integ) + "\n")

    md.append("## 2. Master comparison table (merged label set, CWE-strict)\n")
    headers = ["Tool", "TP", "TP via same-family cluster", "FP", "TN", "FN", "Precision", "Recall",
               "F1", "FN w/ line hit (CWE miss)", "Findings outside any label"]
    md.append(_table(headers, master_rows(scoring, "combined")) + "\n")
    md.append("### Per corpus\n")
    for corpus in scoring["per_corpus"]:
        md.append(f"**{corpus}** — {CORPORA[corpus]['label']}\n")
        md.append(_table(headers, master_rows(scoring, corpus)) + "\n")
    md.append("### Wall-clock\n")
    md.append(duration_rows(payload, "combined") + "\n")

    md.append("### Sensitivity — line-only matching (declared CWE ignored)\n")
    md.append(_table(headers, master_rows(scoring, "combined", "scores_line_only")) + "\n")
    md.append("### Same-family CWE equivalence clusters applied to the strict score\n")
    md.append("Clusters applied (each is one MITRE family the vendors name at different abstraction "
               "levels):\n\n" +
              _table(["cluster", "members"],
                     [[f"#{i + 1}", ", ".join(sorted(c))]
                      for i, c in enumerate(CWE_EQUIVALENCE_CLUSTERS)]) + "\n\n" +
              "Deliberately **not** folded, because they are distinct weakness classes rather than "
              "naming variants: CWE-94 (dynamic compilation/import loading) vs CWE-95 (direct "
              "evaluation), CWE-502 (untrusted deserialisation) vs CWE-94/95, CWE-89 (SQL) vs "
              "CWE-862 (missing authorisation), CWE-918 (SSRF) vs CWE-79 (XSS), CWE-319 (cleartext "
              "transmission) vs CWE-22/73 (path control). Folding any of those would convert a real "
              "classification error into a scored true positive.\n\n" +
              cluster_rows(scoring))
    md.append("### CWE metadata actually published by each tool on these corpora\n")
    cov = [[tool, str(scoring["combined"]["scores"][tool]["findings"]),
            str(scoring["combined"]["scores"][tool]["with_cwe"]),
            _pct(scoring["combined"]["scores"][tool]["with_cwe"] /
                 max(scoring["combined"]["scores"][tool]["findings"], 1))]
           for tool in TOOL_ORDER]
    md.append(_table(["Tool", "Findings", "Carrying a CWE", "Coverage"], cov) + "\n")

    md.append("## 3. Per-CWE breakdown (100% of declared CWEs)\n")
    for tool in TOOL_ORDER:
        rows = []
        for r in scoring["per_cwe"]:
            t = r["tools"][tool]
            rows.append([r["cwe"], str(r["pos"]), str(r["neg"]), str(t["tp"]), str(t["fn"]),
                         str(t["fp"]), str(t["tn"]), _pct(t["recall"]), _pct(t["precision"])])
        md.append(f"### {tool}\n")
        md.append(_table(["CWE", "Pos", "Neg", "TP", "FN", "FP", "TN", "Recall", "Precision"],
                         rows) + "\n")

    md.append("## 4. Failure audit\n")
    md.append("### 4.1 Where each tool fires on labels that must stay silent (false positives)\n")
    for tool in TOOL_ORDER:
        top = sorted(audits[tool]["fp"].items(), key=lambda kv: -kv[1])[:10]
        md.append(f"**{tool}** — {len(audits[tool]['fp'])} distinct labelled-negative sites.\n")
        md.append(_table(["labelled negative site (corpus:rule)", "FP hits"],
                         [[k, str(v)] for k, v in top]) + "\n")
    md.append("### 4.2 Positive labels each tool does not report at all\n")
    for tool in TOOL_ORDER:
        top = sorted(audits[tool]["fn_no_line_hit"].items(), key=lambda kv: -kv[1])[:10]
        md.append(f"**{tool}** — {sum(audits[tool]['fn_no_line_hit'].values())} "
                  f"missed positives over {len(audits[tool]['fn_no_line_hit'])} sites.\n")
        md.append(_table(["corpus:rule", "missed lines"], [[k, str(v)] for k, v in top]) + "\n")
    md.append("### 4.3 Right line, wrong weakness class (CWE-strict demotions)\n")
    for tool in TOOL_ORDER:
        rows = [[f"{m['assertion']['corpus']}:{m['assertion']['file']}:{m['assertion']['line']}",
                 ",".join(m["assertion"]["cwes"]) or "-",
                 "; ".join(f"{r.get('native')}[{r.get('cwe')}]" for r in m["line_matched"]) or "-"]
                for m in scoring["combined"]["scores"][tool]["misses"]
                if m["kind"] == "FN" and m["line_matched"]][:12]
        md.append(f"**{tool}**\n")
        md.append(_table(["site", "labelled CWE", "tool reported"], rows) + "\n")

    md.append("### 4.4 Missed-positive taxonomy (why each FN happened, from the tool's own output)\n")
    tax_rows = []
    for tool in TOOL_ORDER:
        tax = scoring["combined"]["scores"][tool]["fn_taxonomy"]
        tax_rows.append([tool, str(tax["no_output_on_file"]), str(tax["output_on_file_other_line"]),
                         str(tax["line_hit_wrong_cwe"]),
                         str(tax["class_never_reported_by_tool"]),
                         str(tax["class_reported_elsewhere"])])
    md.append(_table(["Tool", "Silent on the whole file", "Spoke about the file, wrong line",
                      "Right line, wrong CWE", "Class/rule never reported by this tool anywhere",
                      "Class/rule reported elsewhere"], tax_rows) + "\n")
    md.append("### 4.5 Weakness classes with zero recall (capability gaps, not placement misses)\n")
    zero = []
    for tool in TOOL_ORDER:
        gaps = [r["cwe"] for r in scoring["per_cwe"]
                if r["pos"] and r["tools"][tool]["tp"] == 0]
        zero.append([tool, str(len(gaps)), ", ".join(gaps[:22]) + (" …" if len(gaps) > 22 else "")])
    md.append(_table(["Tool", "CWEs with 0 TP among positive labels", "Classes"], zero) + "\n")

    md.append("## 5. Tool execution health\n")
    health = []
    for tool in TOOL_ORDER:
        for corpus, st in payload["stats"].get(tool, {}).items():
            health.append([tool, corpus, st.get("mode", "single subprocess run"),
                           str(st.get("invocations", 1)), str(st.get("crashed", 0)),
                           str(st.get("exit", "-")),
                           f"{st.get('ms_median_per_file', 0) or 0:.1f} ms"
                           if st.get("ms_median_per_file") else "-"])
    md.append(_table(["Tool", "Corpus", "Mode", "Invocations", "Failed invocations",
                      "Exit", "Median/file"], health) + "\n")
    crashes = []
    for corpus, st in payload["stats"].get("TCS", {}).items():
        for err in st.get("errors", []) or []:
            crashes.append([corpus, err.get("file", "?"), str(err.get("error", ""))[:120]])
    if crashes:
        md.append("TCS invocations that aborted (counted as misses, not excluded):\n")
        md.append(_table(["Corpus", "File", "Error"], crashes) + "\n")

    md.append("## 6. Methodology and honest limitations\n")
    md.append(
        "* Scoring unit is the **assertion** (one labelled line, or one labelled file for Bandit "
        "examples), not the source file. Line matching uses a ±1 window; memory-of-comment placement "
        "differs between `# ruleid:` on the offending line and on the line above.\n"
        "* Matching is **CWE-strict**: a finding on the labelled line whose CWE is not in the rule's "
        "declared CWE list is counted as FN and separately tallied as a CWE-miss. Where the upstream "
        "rule YAML declares no CWE at all, the assertion degrades to line-only matching (counted "
        "separately below) rather than being dropped.\n"
        "* `Findings outside any label` are real reports on unlabelled lines. They are *not* counted as "
        "FP, because the corpora only label the lines the rule authors cared about; treating the "
        "remainder as ground-negative would inflate precision for every tool.\n"
        "* The negative labels are written by the tool vendors (Semgrep for its own rules, Bandit for "
        "its own examples), so a vendor tool is graded against its own definition of safe. Cross-tool "
        "read-across in §2/§3 is the part that is genuinely adversarial.\n"
        "* Semgrep was run with `p/default` + `p/security-audit`, i.e. **not** the mirrored per-rule "
        "test annotations, so its raw rule set and the label set are not identical; findings on lines "
        "the test file annotates `# ok:` for rule A but rule B catches are FP by construction.\n"
        "* Upstream ships autofix variants (`*.fixed.py`) that keep the original `# ruleid:` "
        "annotations even though the fix has already rewritten the flagged expression — measured at "
        "153 assertions (65 positive) of the Semgrep corpus, e.g. "
        "`wtf-csrf-disabled.fixed.py:6` is annotated `ruleid` on a line that now reads "
        "`app.config['WTF_CSRF_ENABLED'] = True`. Those labels are retained verbatim: pruning them "
        "would be cherry-picking, and they penalise Semgrep on its own corpus too.\n"
        "* TCS is invoked through the real CLI once per file (`cli.py scan <file> --scope python "
        "--format json`) so a single engine crash cannot silently remove a whole corpus; the in-process "
        "API sweep is used only for the timing comparison.\n"
        "* Semgrep and Bandit children run with `PYTHONUTF8=1`. Without it Semgrep's own report writer "
        "(`output.py:_save_output` → `Path.open(mode=\"w\")`, cp1252 on Windows) aborts the entire scan "
        "with `UnicodeEncodeError` as soon as one corpus file contains a byte it cannot encode: measured "
        "on the Bandit corpus, exit code 2 and a 0-byte report, i.e. a *silently empty* result set. That "
        "is a defect in the competitor tool's harness, not in its analysis, and the first sweep of this "
        "benchmark recorded it before the fix.\n"
        "* Both mirrored corpora were opened read-only during this benchmark, and §1's SHA-256 "
        "before/after check is the proof that nothing in them was edited to improve a score. The "
        "defects in §7 were surfaced by the first sweep of this harness and then fixed under the "
        "repository's gate protocol; the numbers reported here are from the post-fix sweep, so §5 "
        "and §7 describe what the fixes changed rather than what is still broken.\n")

    baseline = load_baseline()
    hangs_now, aborts_now = _timeouts(payload), _aborts(payload)
    base_hangs = _timeouts(baseline) if baseline else []
    base_aborts = _aborts(baseline) if baseline else []
    clean = not (hangs_now or aborts_now)
    budget = next((st.get("per_file_timeout_s") for st in payload["stats"]["TCS"].values()), "?")
    md.append("## 7. Engine defects surfaced by this benchmark "
              f"({'resolved and re-verified by this sweep' if clean else 'still open'})\n")
    md.append(
        (f"The first sweep of this harness ran against an unmodified engine; its artefacts are kept at "
         f"`scratch/showdown/{BASELINE_DIR}/` and every baseline figure below is read from them. "
         if baseline else
         "No baseline artefact is present, so only the current sweep is reported. ") +
        "Each defect is reproducible from the artefacts in `scratch/showdown/`.\n")
    if baseline:
        now_files = _tcs_findings_per_file(payload)
        md.append(_table(
            ["corpus", "file", "baseline outcome", "exit", "baseline error", "TCS findings now"],
            [[err["corpus"], err["file"],
              "killed at the timeout" if str(err["error"]).startswith("TIMEOUT") else "aborted",
              str(err["exit"]), str(err["error"])[:60], str(now_files.get(err["file"], 0))]
             for err in sorted(base_hangs + base_aborts, key=lambda e: (e["corpus"], e["file"]))]) + "\n")
    md.append(
        f"**D1 — unbounded scope walk (hang).** {len(base_hangs)} file(s) exceeded the {budget}s "
        f"per-file budget and were killed in the baseline sweep; this sweep killed "
        f"{len(hangs_now)} file(s) under the same budget.\n")
    md.append(
        "*Mechanism (measured): the scope-walk loop alternates between stripping the last `.` and "
        "restoring `mod:global`. For a module key whose path contains both a dot and the substring "
        "`function` — e.g. "
        "`external/…/is-function-without-parentheses.py` — branch 1 (`. in scope and 'function' in "
        "scope`) strips `.py:global`, branch 3 restores it, and the cycle never terminates because no "
        "assignment record is found on the way. The `visited` set only guards re-entrancy per "
        "(scope, name); it does not bound this inner walk. Identical source under a key without that "
        "shape completes instantly, so the trigger is the module-key spelling, not the code — a "
        "directory scan that contains one such file hangs indefinitely.\n"
        f"* The same four-branch idiom is replicated at **{len(count_scope_walk_sites())} sites** in "
        f"`ast_scanner.py`; the fix bounds **{count_guarded_scope_walks()} walks**. That count is "
        "deliberately larger than the idiom census because it covers every `while` loop that rewrites "
        "its cursor through the scope-parent chain, including the walks that take only part of the "
        "chain. Each now records the cursors it has already visited and exits on a repeat instead of "
        "oscillating.\n"
        "* Why the guard cannot change a result: the `rsplit` branch strictly shortens the cursor and "
        "`<mod>:global` is the only non-shortening step, so the reachable cursor set is finite and a "
        "walk that visits a new cursor at each step must terminate — a repeated cursor therefore "
        "implies a cycle, not a long chain. Every lookup inside these walks is read-only, so breaking "
        "on a repeat can only turn a hang into the loop's own exit path.\n")
    md.append(
        "**D2 — an uncaught exception aborted the whole scan.** "
        f"{len(base_aborts)} file(s) ended with a non-zero exit and no JSON in the baseline sweep; "
        f"{len(aborts_now)} did in this one.\n")
    if baseline:
        md.append(_table(["file", "baseline error"],
                         [[a["file"], str(a["error"])[:110]] for a in base_aborts]) + "\n")
    md.append(
        "* `ast_scanner.py:_collect_calls_in_expr` referenced `file_path`, which is not a parameter and "
        "is never bound (`NameError`); it fires whenever a call passes `**kwargs` inline "
        "(`kw.arg is None`), so any directory scan containing such a file returned no findings at all. "
        "The same function also referenced an unbound `call_lineno` at three sites, so patching only "
        "`file_path` moves the crash one line later; both are now bound from `self.file_paths` and the "
        "caller's `lineno`.\n"
        "* `cli.py scan` propagated `ValueError: source code string cannot contain null bytes` for "
        "binary-ish files instead of skipping them, killing the run. `ast.parse` raises that as a "
        "`ValueError`, which is not a `SyntaxError`, so the per-file `except SyntaxError` in "
        "`TaintTracker.__init__` never caught it. That clause now also covers `ValueError` and "
        "`UnicodeDecodeError` and records the reason in `skipped_files`, which the CLI prints as a "
        "warning before continuing, so one malformed file no longer removes every other module from "
        "the scan.\n"
        "* Residual gap this section does not fix: with the `NameError` gone, "
        "`python/django/security/injection/mass-assignment.py` parses and analyses cleanly but still "
        "emits no CWE-915 finding, because the `**request.POST` kwargs-expansion edge is not wired to "
        "the mass-assignment sink even though the sinks at its two labelled lines are registered. That "
        "is a sink/edge-model change rather than a crash fix, and adding a matcher without a sound "
        "model is out of scope here.\n")
    if baseline:
        base_ms = sum(st["ms_total"] for st in baseline["stats"]["TCS"].values())
        now_ms = sum(st["ms_total"] for st in payload["stats"]["TCS"].values())
        added, removed = _tcs_delta(baseline, payload)
        prev_failed = {e["file"] for e in _tcs_errors(baseline)}
        on_prev_failed = sum(1 for row in added if row[1] in prev_failed)
        md.append(
            "**Effect of the fixes on this benchmark.**\n"
            f"* TCS wall clock over {sum(st['invocations'] for st in payload['stats']['TCS'].values())} "
            f"CLI invocations: {base_ms / 1000:.1f} s → {now_ms / 1000:.1f} s "
            f"({(now_ms - base_ms) / base_ms * 100:+.1f}%). The saving is the killed timeouts; the "
            "per-file median moved the other way, partly because the guard runs on every scope walk of "
            "every file and partly because the two sweeps did not run under the same machine load.\n"
            f"* Findings: {len(_tcs_finding_set(baseline))} → {len(_tcs_finding_set(payload))} distinct "
            f"sites, i.e. {len(added)} added and **{len(removed)} removed on files the baseline sweep "
            "already scanned successfully** — the regression count this section exists to measure. "
            f"{on_prev_failed} of the {len(added)} additions land on the "
            f"{len(prev_failed)} files that the baseline sweep lost.\n"
            + _scoring_delta_line(scoring, load_baseline_scoring()) + "\n")
        md.append(_table(["corpus", "invocations", "killed by timeout", "aborted",
                          "ms total", "median ms/file"],
                         [[f"{tag}/{corpus}", str(st['invocations']),
                           str(st.get('timeouts', 0)), str(st['crashed']),
                           f"{st['ms_total']:.0f}", f"{st['ms_median_per_file']:.1f}"]
                          for tag, pl in (("baseline", baseline), ("this sweep", payload))
                          for corpus, st in sorted(pl["stats"]["TCS"].items())]) + "\n")
    md.append("## 8. TCS missed positives: auto-cited evidence and AST root causes\n")
    md.append("Table is generated from the scoring artefacts (no hand-picked examples). "
              "`misses` counts labelled `# ruleid:` lines TCS did not report, CWE-strict.\n")
    md.append(_table(["labelled rule", "misses", "labelled CWE(s)", "example site",
                      "source at that line", "class coverage"],
                     tcs_miss_rows(scoring, payload)) + "\n")
    tcs_block = scoring["combined"]["scores"]["TCS"]
    tax = tcs_block["fn_taxonomy"]
    fn_total = tcs_block["score"]["fn"]
    fn_misses = [m for m in tcs_block["misses"] if m["kind"] == "FN"]
    rule_misses: dict[str, int] = {}
    for miss in fn_misses:
        key = miss["assertion"]["rule"] or "(unruled)"
        rule_misses[key] = rule_misses.get(key, 0) + 1
    never = never_emitted_classes(payload, "TCS")
    now_forced = _forced_fn_stats(scoring, payload)
    base_forced = (_forced_fn_stats(load_baseline_scoring(), baseline)
                   if baseline and load_baseline_scoring() else None)

    def n_rule(rule: str) -> str:
        return str(rule_misses.get(rule, 0))

    md.append(
        "Analyst commentary on the shapes above (every count in this section is computed from the "
        "scoring artefacts, and each claim is checkable at the cited site):\n\n"
        f"1. **Pattern-present, value-not-tainted.** "
        f"`dangerous-system-call` ({n_rule('dangerous-system-call')} missed labelled lines) misses are "
        "`os.system(f\"ls -la {event['dir']}\")` style calls: the "
        "sink exists and the argument is an f-string, but the interpolated expression is a plain "
        "dict subscript on a locally-built mapping. TCS's CWE-78 path is taint-edge driven, so with "
        "no reachable `TAINT_SOURCE_PATTERNS` producer for `event` it emits nothing, whereas the "
        "upstream rule is a pure syntactic pattern (any interpolation into an `os.system` argument). "
        "This is the single largest structural reason TCS trails a pattern matcher on this corpus: "
        f"{tax['no_output_on_file']} of the {fn_total} CWE-strict missed positives "
        f"({_pct(tax['no_output_on_file'] / fn_total)}) are `no_output_on_file`, i.e. the engine "
        "produced no finding anywhere in that file, while only "
        f"{tax['line_hit_wrong_cwe']} are `line_hit_wrong_cwe`.\n"
        f"2. **{len(never)} of the {len(scoring['per_cwe'])} labelled weakness classes TCS never "
        f"emits at all** (measured: the CWE string appears on zero TCS findings across both corpora), "
        f"accounting for {sum(n for _, n in never)} labelled positive lines. Largest: "
        + ", ".join(f"{cwe} ({n} labelled lines)" for cwe, n in never[:6]) +
        ". Two of the shapes in the table above sit here: `nan-injection` is CWE-704 (type coercion) "
        "and `insecure-file-permissions` is CWE-276 (incorrect permission assignment) — both need new "
        "sink/check definitions, not better taint propagation. `default-mutable-dict`, "
        "`default-mutable-list` and `attr-mutable-initializer` are a different gap: their upstream "
        "rules declare **no CWE at all**, so they are scored line-only and never appear in the CWE "
        "coverage tables. (The §4.4 taxonomy's `class never reported` figure is larger — "
        f"{tax['class_never_reported_by_tool']} — because it also counts those CWE-less rules, which "
        "cannot appear in the CWE list above by definition.)\n"
        "   * Not to be confused with `weak-ssl-version` (" + n_rule('weak-ssl-version') + " missed "
        "lines, CWE-326), which is **not** an unimplemented class: TCS does emit CWE-326, at "
        "`insufficient-rsa-key-size.py:23/28` and `weak_cryptographic_key_sizes.py:29/46/55/59`, "
        "i.e. on weak *key-size* comparisons. The missed lines are weak *protocol-version* argument "
        "values — `ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv2)`, "
        "`SSL.Context(method=SSL.SSLv2_METHOD)`, the same two keywords passed to arbitrary callees, "
        "and a default parameter value `def open_ssl_socket(version=ssl.PROTOCOL_SSLv2)`. The gap is "
        "an unsafe-constant argument-value model for `ssl_version`/`method`, not a missing CWE.\n"
        f"3. **Context-of-use sinks without a model.** `raw-html-format` "
        f"({n_rule('raw-html-format')} missed lines) flags a value being "
        "concatenated/formatted into something later rendered as HTML (`context['html'] = link % "
        "text`). TCS's CWE-79 sinks are response/render call sites; it has no HTML-context taint for "
        "assignments into a template context mapping, so the `BinOp`/`str.format` results are "
        "tainted-but-unsunk.\n"
        f"4. **Configuration-value defects.** `flask-wtf-csrf-disabled` "
        f"({n_rule('flask-wtf-csrf-disabled')} missed lines) flags the config-mapping write "
        "`app.config['WTF_CSRF_ENABLED'] = False` (and the attribute form "
        "`app.config.WTF_CSRF_ENABLED = False`) in `wtf-csrf-disabled.py`, while the labelled line in "
        "the retained autofix variant `wtf-csrf-disabled.fixed.py:6` reads `= True` — the same "
        "annotation-vs-source staleness recorded in §6. Either way TCS's CSRF work (view decorators, "
        "`@csrf.exempt`) does not cover config-mapping writes, and the subscript-store path is "
        "exactly where M3 (nested subscript key taint) has reach but no sink is registered.\n"
        f"5. **Blocked by execution rather than by analysis.** " +
        (f"In the baseline sweep {base_forced[2]} file(s) were lost before returning JSON "
         f"({base_forced[3]} killed by the scope-walk hang, {base_forced[2] - base_forced[3]} aborted "
         f"on an exception), and they carried {base_forced[1]} of that sweep's {base_forced[0]} missed "
         f"positives ({_pct(base_forced[1] / base_forced[0])}) as forced FNs — labelled lines no engine "
         f"capability could have recovered, including both CWE-915 mass-assignment sites. This sweep "
         f"lost {now_forced[2]} file(s) and reports {now_forced[1]} forced FNs; the per-file timeout "
         "exists precisely so that a defect of that class shows up as a measured miss instead of "
         "silently vanishing. The residual miss on mass-assignment is the kwargs-edge gap recorded in "
         "§7, not a crash.\n"
         if base_forced else
         f"This sweep lost {now_forced[2]} file(s) before returning JSON, so {now_forced[1]} of the "
         f"{now_forced[0]} missed positives are forced FNs rather than analysis failures; the per-file "
         "timeout exists precisely so that a defect of that class shows up as a measured miss instead "
         "of silently vanishing.\n"))

    md.append("## 9. Verdict\n")
    scores = scoring["combined"]["scores"]

    def ranking(metric: str) -> str:
        return " > ".join(f"{t} {_pct(scores[t][metric])}"
                          for t in sorted(TOOL_ORDER, key=lambda x: -scores[x][metric]))

    def position(metric: str) -> int:
        return sorted(TOOL_ORDER, key=lambda x: -scores[x][metric]).index("TCS") + 1

    def ordinal(n: int) -> str:
        return {1: "first", 2: "second", 3: "third"}.get(n, f"{n}th")

    def leader(metric: str) -> str:
        return max(TOOL_ORDER, key=lambda t: scores[t][metric])

    md.append(
        f"* On independent labels the ranking by F1 is {ranking('f1')}.\n"
        f"* By precision: {ranking('precision')} — TCS is "
        f"{ordinal(position('precision'))} of {len(TOOL_ORDER)} "
        f"({_pct(scores['TCS']['precision'])}), behind "
        f"{leader('precision')}'s {_pct(scores[leader('precision')]['precision'])}. "
        f"By recall: {ranking('recall')} — TCS is "
        f"{ordinal(position('recall'))} of {len(TOOL_ORDER)} "
        f"({_pct(scores['TCS']['recall'])}). TCS is therefore "
        f"{ordinal(position('precision'))} on precision and {ordinal(position('recall'))} on recall, "
        "the expected signature of a taint-engine scored on a "
        "corpus of syntactic patterns: it reports few findings and most of them are right, and it "
        f"simply does not have checks for {len(never)} of the {len(scoring['per_cwe'])} labelled "
        "classes (see §8).\n"
        "* TCS's own benchmark reports 100% precision and recall on 552 cases; those labels are "
        "authored in this repository and describe the cases the engine was built to solve. On this "
        f"benchmark the labels are written by the two competitors and cover "
        f"{len(scoring['per_cwe'])} weakness classes, of which TCS implements a subset — the "
        f"{_pct(scores['TCS']['recall'])} recall figure is the honest measure of that gap, and the "
        "two numbers are not in conflict.\n")

    return "\n".join(md)


def load_payload() -> dict:
    path = ARTIFACTS / "raw_results.json"
    if not path.exists():
        raise SystemExit(f"{path} is missing; run --stage run first")
    return json.loads(path.read_text(encoding="utf-8"))


MASTER_HEADERS = ["Tool", "TP", "TP via same-family cluster", "FP", "TN", "FN", "Precision",
                  "Recall", "F1", "FN w/ line hit (CWE miss)", "Findings outside any label"]


def cluster_rows(scoring: dict, limit: int = 30) -> str:
    """Every TP that only the equivalence clusters rescued, with both CWE strings, so a reader can
    audit each fold instead of taking the aggregate on trust."""
    rows, total = [], 0
    for tool in TOOL_ORDER:
        block = scoring["combined"]["scores"][tool]
        total += len(block["score"]["cluster_reclaimed"])
        for row in block["score"]["cluster_reclaimed"][:limit]:
            a = row["assertion"]
            rows.append([tool, a["corpus"] + ":" + (a["rule"] or "-"),
                         f"{Path(a['file']).name}:{a['line']}",
                         ",".join(sorted(a["cwes"])) or "-",
                         "; ".join(f"{r.get('native')}[{r.get('cwe')}]"
                                   for r in row["line_matched"]) or "-"])
    if not rows:
        return ("No positive label needed a cluster to match: every recovered TP names the declared "
                "CWE exactly.\n")
    return (f"{total} positive label(s) matched only through a same-family CWE cluster "
            f"(first {len(rows)} listed):\n\n" +
            _table(["tool", "corpus:rule", "site", "labelled CWE", "tool reported"], rows) + "\n")


def print_master_table(scoring: dict) -> None:
    print("\n== MASTER TABLE — merged label set, CWE-strict ==")
    print(_table(MASTER_HEADERS, master_rows(scoring, "combined")))
    for corpus in scoring["per_corpus"]:
        print(f"\n== {corpus} — {CORPORA[corpus]['label']} ==")
        print(_table(MASTER_HEADERS, master_rows(scoring, corpus)))
    print("\n== sensitivity: line-only matching (declared CWE ignored) ==")
    print(_table(MASTER_HEADERS, master_rows(scoring, "combined", "scores_line_only")))
    print("\n== CWE metadata published by each tool (merged findings) ==")
    print(_table(["Tool", "Findings", "Carrying a CWE", "%"],
                 [[t, str(scoring["combined"]["scores"][t]["findings"]),
                   str(scoring["combined"]["scores"][t]["with_cwe"]),
                   _pct(scoring["combined"]["scores"][t]["with_cwe"] /
                        max(scoring["combined"]["scores"][t]["findings"], 1))]
                  for t in TOOL_ORDER]))
    print("\n== missed-positive taxonomy ==")
    print(_table(["Tool", "Silent on file", "File but wrong line", "Line but wrong CWE",
                  "Class never reported", "Class reported elsewhere"],
                 [[t, str(scoring["combined"]["scores"][t]["fn_taxonomy"]["no_output_on_file"]),
                   str(scoring["combined"]["scores"][t]["fn_taxonomy"]["output_on_file_other_line"]),
                   str(scoring["combined"]["scores"][t]["fn_taxonomy"]["line_hit_wrong_cwe"]),
                   str(scoring["combined"]["scores"][t]["fn_taxonomy"]
                       ["class_never_reported_by_tool"]),
                   str(scoring["combined"]["scores"][t]["fn_taxonomy"]
                       ["class_reported_elsewhere"])] for t in TOOL_ORDER]))
    print("\n== wall clock ==")
    print(duration_rows(scoring["_payload"], "combined"))


def score_and_report(payload: dict, stage: str) -> int:
    payload = refresh_semgrep_from_artifacts(payload)
    scoring = score_all(payload)
    scoring["_payload"] = payload
    (ARTIFACTS / "scoring.json").write_text(
        json.dumps({k: v for k, v in scoring.items() if k != "_payload"}, indent=1),
        encoding="utf-8")
    print_master_table(scoring)
    if stage in ("all", "report", "score"):
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        REPORT.write_text(render_report(payload, scoring), encoding="utf-8")
        print(f"\nReport: {REPORT.relative_to(ROOT)}")
        print(f"Scoring: {(ARTIFACTS / 'scoring.json').relative_to(ROOT)}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stage", default="all",
                        choices=["all", "labels", "run", "score", "report"])
    parser.add_argument("--tcs-mode", default="cli", choices=["cli", "api"],
                        help="cli = one real `cli.py scan` invocation per file")
    parser.add_argument("--corpus", default="all", choices=["all", *CORPORA])
    parser.add_argument("--tcs-timeout", type=int, default=30,
                        help="seconds before a hung TCS CLI invocation is killed and recorded")
    parser.add_argument("--reuse-competitors", action="store_true",
                        help="re-sweep only TCS and reuse the Semgrep/Bandit findings already on disk "
                             "(their analysis cannot change when only the engine changed)")
    args = parser.parse_args(argv)

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    integrity_before = verify_integrity()
    keys = list(CORPORA) if args.corpus == "all" else [args.corpus]

    print("== ground truth ==")
    all_assertions: dict[str, list[Assertion]] = {}
    for key in keys:
        spec = CORPORA[key]
        if key == "semgrep_rules":
            rule_map = rule_cwes_from_yamls(spec["dir"])
            assertions = semgrep_assertions(key, spec["code"], rule_map)
            named = sum(1 for a in assertions if a.cwes)
            print(f"  {key}: {len(assertions)} assertions "
                  f"({sum(1 for a in assertions if a.kind == 'pos')} pos / "
                  f"{sum(1 for a in assertions if a.kind == 'neg')} neg), "
                  f"{named} CWE-resolved, {len(rule_map)} rules mapped")
        else:
            assertions = bandit_assertions(key, spec["code"],
                                           spec["dir"] / "tests/functional/test_functional.py")
            print(f"  {key}: {len(assertions)} assertions "
                  f"({sum(1 for a in assertions if a.kind == 'pos')} pos / "
                  f"{sum(1 for a in assertions if a.kind == 'neg')} neg)")
        all_assertions[key] = assertions
    if args.stage == "labels":
        return 0
    if args.stage in ("score", "report"):
        return score_and_report(load_payload(), args.stage)

    print("\n== tool runs ==", flush=True)
    results: dict[str, dict[str, list[dict]]] = {}
    stats: dict[str, dict] = {}
    prior = load_payload() if args.reuse_competitors else {}

    def dump() -> dict:
        payload = {"integrity_before": integrity_before,
                   "integrity_after": verify_integrity(), "stats": stats,
                   "assertions": {k: [asdict(a) for a in v]
                                  for k, v in all_assertions.items()},
                   "findings": {k: dict(v) for k, v in results.items()}}
        (ARTIFACTS / "raw_results.json").write_text(json.dumps(payload, indent=1),
                                                    encoding="utf-8")
        return payload

    for key in keys:
        corpus_dir = CORPORA[key]["dir"]
        results[key] = {}
        if args.tcs_mode == "cli":
            tcs, tstats = findings_from_tcs_cli(corpus_dir, key, args.tcs_timeout)
        else:
            tcs, tstats = findings_from_tcs_api(corpus_dir)
        results[key]["TCS"] = tcs
        stats.setdefault("TCS", {})[key] = tstats
        dump()
        print(f"  TCS     {key}: {len(tcs)} findings, {tstats['ms_total']:.0f} ms "
              f"({tstats['crashed']} failed, {tstats.get('timeouts', 0)} killed by timeout)",
              flush=True)
        for tool in ("Semgrep", "Bandit"):
            if args.reuse_competitors and prior.get("findings", {}).get(key, {}).get(tool) is not None:
                results[key][tool] = prior["findings"][key][tool]
                stats.setdefault(tool, {})[key] = prior["stats"][tool][key]
                print(f"  {tool:<7} {key}: {len(results[key][tool])} findings (reused artefact)",
                      flush=True)
                continue
            if tool == "Semgrep":
                sem, sstats = findings_from_semgrep(corpus_dir, key)
                results[key]["Semgrep"] = sem
                stats.setdefault("Semgrep", {})[key] = sstats
                dump()
                print(f"  Semgrep {key}: {len(sem)} findings, {sstats['ms_total']:.0f} ms", flush=True)
            else:
                ban, bstats = findings_from_bandit(corpus_dir, key)
                results[key]["Bandit"] = ban
                stats.setdefault("Bandit", {})[key] = bstats
                dump()
                print(f"  Bandit  {key}: {len(ban)} findings, {bstats['ms_total']:.0f} ms", flush=True)

    payload = dump()
    print(f"\nRaw artifacts: {ARTIFACTS.relative_to(ROOT)}/raw_results.json", flush=True)
    if args.stage == "run":
        return 0
    return score_and_report(payload, args.stage)


if __name__ == "__main__":
    sys.exit(main())
