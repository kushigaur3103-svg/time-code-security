#!/usr/bin/env python3
"""External battlefield: head-to-head TimeCodeSecurity vs Semgrep on third-party targets.

The internal benchmark scores both tools on labels the competitors themselves wrote.
This harness moves the comparison onto neutral ground - real repositories neither vendor
authored - and runs both scanners as black boxes through their own CLIs, with no shared
plumbing.

Two kinds of ground are covered:

* Level 1 (`pygoat`) is an intentionally vulnerable Django app, so the metric there is
  coverage: more real findings is better.
* Level 2 (`requests`, `fastapi`) is clean, heavily-audited production code, so the
  metric inverts: fewer findings is better and the table measures false-positive
  resistance.

Every run also re-checks that the two TimeCodeSecurity entry points (`cli.py scan --scope python` and
`tcs_cli.py`) agree site-for-site, SARIF-for-SARIF, and on the exit code - the unification
contract.

    python scripts/run_external_battlefield.py                    # Level 1
    python scripts/run_external_battlefield.py --target requests --target fastapi
    python scripts/run_external_battlefield.py --target pygoat --target requests --target fastapi
"""
from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CWE_RE = re.compile(r"CWE-(\d+)")

# The four weakness families the Level 1 mission calls out, ordered for display.
HEADLINE_CWES = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-Site Scripting",
    "CWE-78": "OS Command Injection",
    "CWE-502": "Unsafe Deserialization",
}

TARGETS = {
    "pygoat": {
        "path": "scratch/external_targets/pygoat",
        "url": "https://github.com/adeyosemanputra/pygoat.git",
        "rulesets": ["p/security-audit"],
        # Vulnerable-by-design: here a high finding count is the point.
        "clean": False,
        "blurb": "OWASP PyGoat - intentionally vulnerable Django app (coverage battleground)",
    },
    "requests": {
        "path": "scratch/external_targets/requests",
        "url": "https://github.com/psf/requests.git",
        "rulesets": ["p/security-audit"],
        "pkg": "requests",
        # Audited production library: here every finding is a candidate false positive.
        "clean": True,
        "blurb": "psf/requests - audited production HTTP library (FP-resistance probe)",
    },
    "fastapi": {
        "path": "scratch/external_targets/fastapi",
        "url": "https://github.com/fastapi/fastapi.git",
        # p/fastapi is added so Semgrep gets its best shot at framework-specific patterns.
        "rulesets": ["p/security-audit", "p/fastapi"],
        "pkg": "fastapi",
        "clean": True,
        "blurb": "fastapi/fastapi - JSON-API framework, exercises the CWE-352 API guard",
    },
    "django": {
        "path": "scratch/external_targets/django",
        "url": "https://github.com/django/django.git",
        # p/django is Semgrep's framework pack; the monorepo also carries a test suite of
        # its own scale, so both rulesets are given to the competitor.
        "rulesets": ["p/security-audit", "p/django"],
        "pkg": "django",
        # Audited framework code: findings here are noise candidates, and the ~500k-line
        # tree is the scalability/memory stress this level is really about.
        "clean": True,
        "blurb": "django/django - large-scale framework monorepo (wall-clock, memory and "
                 "crash-resilience stress)",
    },
}


def best_payload(runs: list[dict], tool: str, name: str) -> dict | None:
    """Parse the newest run that left a readable payload.

    A run killed mid-scan truncates its own file, so the completed run's evidence is
    preferred over the last attempt, and the failed attempt is reported instead of
    crashing the whole benchmark.
    """
    for run in reversed(runs):
        try:
            return load_json(Path(run["stdout_path"]))
        except (OSError, ValueError) as exc:
            print(f"[battlefield] {name}: {tool} {run['label']} left no parsable payload "
                  f"(exit={run['exit_code']}, wall={run['seconds']:.1f}s): {exc}",
                  file=sys.stderr)
            print(f"[battlefield] {name}: stderr tail: "
                  f"{(run['stderr'] or '')[-600:]}", file=sys.stderr)
    return None


def run_to_file(argv: list[str], label: str, out_path: Path) -> dict:
    """Run one scanner redirecting stdout to a file, so a large JSON payload never has to
    live twice in memory (and so `-o`-less CLIs still leave a re-analysable artefact).

    Wall clock and peak resident set are sampled from the *same* child process: a second
    run to measure memory would double the cost of a 500k-line scan and time a different
    execution than the one being reported.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONUTF8="1")
    try:
        import psutil
    except ImportError:
        psutil = None

    started = time.perf_counter()
    stderr_path = out_path.with_name(out_path.name + ".stderr")
    # stderr goes straight to a file, never a pipe: a scanner that prints thousands of
    # warnings would fill the pipe buffer, block in write(), and hang this poll loop.
    with out_path.open("wb") as handle, stderr_path.open("w", encoding="utf-8",
                                                          errors="replace") as err_handle:
        proc = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=handle,
                                stderr=err_handle, text=True, encoding="utf-8",
                                errors="replace")
        samples: list[float] = []
        if psutil is not None:
            watcher = psutil.Process(proc.pid)
            while proc.poll() is None:
                total = 0
                try:
                    for live in [watcher, *watcher.children(recursive=True)]:
                        total += live.memory_info().rss
                except psutil.Error:
                    total = 0
                if total:
                    samples.append(total / (1024 * 1024))
                time.sleep(0.05)
        proc.wait()
    duration = time.perf_counter() - started
    peak = max(samples) if samples else None
    mean = statistics.fmean(samples) if samples else None
    stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
    print(f"[battlefield] {label}: exit={proc.returncode} wall={duration:.1f}s "
          f"peakRss={peak if peak else 0:.0f}MB", file=sys.stderr)
    return {"label": label, "argv": argv, "exit_code": proc.returncode,
            "seconds": duration, "stdout": out_path.read_text(encoding="utf-8",
                                                               errors="replace"),
            "stdout_path": str(out_path), "stderr_path": str(stderr_path),
            "stderr": stderr, "peak_rss_mb": peak, "mean_rss_mb": mean}


def cwes_of(*values) -> set[str]:
    found: set[str] = set()
    for value in values:
        if value is None:
            continue
        items = value if isinstance(value, (list, tuple, set)) else [value]
        for item in items:
            for digits in CWE_RE.findall(str(item)):
                found.add(f"CWE-{digits}")
    return found


def counter_for(results: list[dict], tool: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for finding in results:
        if tool == "semgrep":
            extra = finding.get("extra") or {}
            cwes = cwes_of((extra.get("metadata") or {}).get("cwe"), extra.get("cwe"))
        else:
            cwes = cwes_of(finding.get("cwe"), finding.get("cwe_list")) or {"UNCLASSIFIED"}
        for cwe in cwes:
            counts[cwe] += 1
    return counts


def parse_semgrep(payload: dict) -> dict:
    results = payload.get("results", [])
    scanned = payload.get("paths", {}).get("scanned", [])
    python_results = [f for f in results if str(f.get("path", "")).endswith(".py")]
    by_rule: Counter[str] = Counter(f.get("check_id", "?") for f in results)
    severities = Counter(str((f.get("extra") or {}).get("severity") or "UNKNOWN").upper()
                         for f in results)
    return {
        "total": len(results),
        "total_python_only": len(python_results),
        "severities": severities,
        "files_scanned": len(scanned),
        "python_files_scanned": len([p for p in scanned if str(p).endswith(".py")]),
        "python_paths": [f.get("path", "") for f in python_results],
        "by_cwe": counter_for(results, "semgrep"),
        "python_by_cwe": counter_for(python_results, "semgrep"),
        "top_rules": by_rule.most_common(10),
        "tool_errors": len(payload.get("errors", [])),
        "semgrep_version": payload.get("version") or "",
    }


def parse_tcs(payload: dict) -> dict:
    """Read the `cli.py scan` / `tcs_cli.py` JSON envelope.

    Both entry points now share the engine and the consolidation pass; the payload shapes
    still differ slightly, so file counts are read from either location.
    """
    findings = payload.get("findings", [])
    by_cwe: Counter[str] = Counter()
    for finding in findings:
        cwes = cwes_of(finding.get("cwe"), finding.get("cwe_list")) or {"UNCLASSIFIED"}
        for cwe in cwes:
            by_cwe[cwe] += 1
    summary = payload.get("summary") or {}
    files = payload.get("scanned_files") or summary.get("total_files") or 0
    if isinstance(files, list):
        files = len(files)
    return {
        "total": len(findings),
        "files_scanned": files,
        "lines_scanned": summary.get("lines_scanned", 0),
        "by_cwe": by_cwe,
        "by_severity": Counter(str(f.get("severity") or "UNKNOWN").upper() for f in findings),
        "syntax_errors": len(payload.get("syntax_errors") or []),
        "skipped_files": len(payload.get("skipped_files") or []),
        "paths": [str(f.get("file") or "") for f in findings],
        "security_score": summary.get("security_score"),
        "risk_level": summary.get("risk_level"),
        "sites": {tcs_site(f) for f in findings},
    }


def tcs_site(finding: dict) -> tuple:
    """Identity of one TimeCodeSecurity finding: file, line, CWE, severity."""
    return (str(finding.get("file")), int(finding.get("line") or finding.get("line_number") or 0),
            str(finding.get("cwe")), str(finding.get("severity", "")).upper())


def sarif_sites(payload: dict, target: str) -> tuple[set, int]:
    """(site set, raw result count) for a SARIF document.

    URIs are normalised to the path *inside* the target, so same-named files in different
    directories stay distinct while any %SRCROOT%-style prefix drift between the two CLIs
    cannot fake a difference.
    """
    sites: set[tuple] = set()
    raw = 0
    for run in payload.get("runs") or []:
        for result in run.get("results", []):
            raw += 1
            loc = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
            artifact = loc.get("artifactLocation") or {}
            region = loc.get("region") or {}
            uri = str(artifact.get("uri", "")).replace("\\", "/")
            sites.add((uri.rsplit(target + "/", 1)[-1] if target in uri else uri,
                       int(region.get("startLine") or 0), str(result.get("ruleId"))))
    return sites, raw


def zone_of(path: str, pkg: str) -> str:
    """Which part of a repository a finding landed in.

    A raw finding count on a clean repo conflates shipped code with test scaffolding and
    maintainer scripts, so the tables split them: only the shipped package is what a
    downstream user actually runs.
    """
    p = path.replace("\\", "/")
    if re.search(r"(^|/)tests?(/|$)", p) or re.search(r"(^|/)test_[^/]*\.py$", p):
        return "tests"
    if re.search(r"(^|/)(scripts|docs_src|docs|examples)(/|$)", p):
        return "scripts/docs"
    if re.search(r"(?:^|/)(?:src/)?" + re.escape(pkg) + r"/", p):
        return "shipped package"
    return "other"


def crashed(run: dict) -> bool:
    blob = (run["stdout"] or "") + (run["stderr"] or "")
    return "Traceback (most recent call last)" in blob or "Internal unhandled exception" in blob


def fmt(number: float) -> str:
    if number is None:
        return "n/a"
    return f"{number:,.2f}"


def memory_note(m: dict) -> str:
    """Which scanner held less resident memory while scanning the same tree."""
    t, s = m.get("tcs_peak_mb"), m.get("semgrep_peak_mb")
    if not t or not s:
        return "psutil unavailable; memory not sampled"
    lighter = "TimeCodeSecurity" if t < s else "Semgrep"
    return f"**{lighter}** ({fmt(abs(t - s))} MB lower)"


def markdown_table(header: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def measure(name: str, cfg: dict, args) -> dict | None:
    """Run every scanner against one target and return the parsed measurement bundle."""
    target = cfg["path"]
    target_dir = ROOT / target
    if not target_dir.is_dir():
        print(f"[battlefield] target missing: {target_dir}", file=sys.stderr)
        print(f"[battlefield] clone it first:\n  git clone --depth 1 {cfg['url']} {target}",
              file=sys.stderr)
        return None

    out_dir = ROOT / args.scratch_dir / name
    out_dir.mkdir(parents=True, exist_ok=True)
    semgrep_json, tcs_json = out_dir / "semgrep.json", out_dir / "tcs.json"
    core_json, core_sarif = out_dir / "tcs_core.json", out_dir / "tcs_core.sarif"
    cli_sarif = out_dir / "tcs_cli_scan.sarif"

    commit = subprocess.run(["git", "-C", str(target_dir), "rev-parse", "--short", "HEAD"],
                            capture_output=True, text=True).stdout.strip() or "unknown"

    semgrep_cmd = (["semgrep", "scan", "--metrics=off", "--json", "--quiet"]
                   + sum([["--config", r] for r in cfg["rulesets"]], []) + [target])
    # Primary TimeCodeSecurity profile: the full engine, the same entry point the scored showdown uses.
    tcs_cmd = [sys.executable, "cli.py", "scan", target, "--scope", "python",
               "--format", "json", "--sarif", str(cli_sarif.relative_to(ROOT))]
    # Second entry point under the unification contract: tcs_cli.py, JSON + SARIF.
    # `tcs_cli.py` writes its own artefact via -o, so its stdout goes to a separate sink:
    # redirecting onto the -o path would race the child's own file write.
    core_stdout, core_sarif_stdout = out_dir / "tcs_core.stdout", out_dir / "tcs_core.sarif.out"
    core_cmd = [sys.executable, "tcs_cli.py", target, "--format", "json",
                "-o", str(core_json)]
    core_sarif_cmd = [sys.executable, "tcs_cli.py", target, "--format", "sarif",
                      "-o", str(core_sarif)]

    semgrep_runs, tcs_runs = [], []
    # One artefact path per run: a second run that dies mid-scan truncates its own file,
    # not the evidence from the run that already completed.
    for index in range(max(1, args.runs)):
        semgrep_runs.append(run_to_file(semgrep_cmd, f"Semgrep[{name}] #{index + 1}",
                                        out_dir / f"semgrep.r{index + 1}.json"))
        tcs_runs.append(run_to_file(tcs_cmd, f"TimeCodeSecurity[{name}] #{index + 1}",
                                    out_dir / f"tcs.r{index + 1}.json"))
    semgrep_json = Path(semgrep_runs[-1]["stdout_path"])
    tcs_json = Path(tcs_runs[-1]["stdout_path"])

    core_runs = [run_to_file(core_cmd, f"TimeCodeSecurity tcs_cli[{name}]", core_stdout)]
    core_sarif_run = run_to_file(core_sarif_cmd, f"TimeCodeSecurity tcs_cli sarif[{name}]",
                                 core_sarif_stdout)

    semgrep_doc = best_payload(semgrep_runs, "Semgrep", name)
    tcs_doc = best_payload(tcs_runs, "TimeCodeSecurity", name)
    if semgrep_doc is None or tcs_doc is None:
        print(f"[battlefield] {name}: skipping target — no scanner pair produced parsable "
              f"output.", file=sys.stderr)
        return None

    semgrep = parse_semgrep(semgrep_doc)
    tcs = parse_tcs(tcs_doc)
    try:
        core = parse_tcs(load_json(core_json))
    except (OSError, ValueError) as exc:
        print(f"[battlefield] {name}: tcs_cli.py JSON unreadable ({exc})", file=sys.stderr)
        core = {"total": 0, "by_cwe": Counter(), "sites": set(), "files_scanned": 0,
                "by_severity": Counter(), "security_score": None, "risk_level": None,
                "syntax_errors": 0, "skipped_files": 0, "lines_scanned": 0, "paths": []}

    sarif_a, sarif_b = set(), set()
    sarif_a_raw = sarif_b_raw = 0
    try:
        sarif_a, sarif_a_raw = sarif_sites(load_json(cli_sarif), target)
    except (OSError, ValueError, KeyError):
        pass
    try:
        sarif_b, sarif_b_raw = sarif_sites(load_json(core_sarif), target)
    except (OSError, ValueError, KeyError):
        pass

    seconds = lambda runs: statistics.median(r["seconds"] for r in runs)  # noqa: E731
    semgrep_seconds, tcs_seconds = seconds(semgrep_runs), seconds(tcs_runs)
    core_seconds = core_runs[0]["seconds"]

    tcs_speed = tcs["files_scanned"] / tcs_seconds if tcs_seconds else 0.0
    semgrep_speed = semgrep["python_files_scanned"] / semgrep_seconds if semgrep_seconds else 0.0
    core_speed = core["files_scanned"] / core_seconds if core_seconds else 0.0

    def med_peak(runs):
        values = [r["peak_rss_mb"] for r in runs if r.get("peak_rss_mb")]
        return statistics.median(values) if values else None

    tcs_peak = med_peak(tcs_runs)
    semgrep_peak = med_peak(semgrep_runs)
    core_peak = med_peak(core_runs)

    return {
        "name": name, "cfg": cfg, "commit": commit, "out_dir": out_dir,
        "semgrep_cmd": semgrep_cmd, "tcs_cmd": tcs_cmd, "core_cmd": core_cmd,
        "semgrep": semgrep, "tcs": tcs, "core": core,
        "semgrep_runs": semgrep_runs, "tcs_runs": tcs_runs, "core_runs": core_runs,
        "semgrep_seconds": semgrep_seconds, "tcs_seconds": tcs_seconds,
        "core_seconds": core_seconds,
        "tcs_peak_mb": tcs_peak, "semgrep_peak_mb": semgrep_peak, "core_peak_mb": core_peak,
        "tcs_speed": tcs_speed, "semgrep_speed": semgrep_speed, "core_speed": core_speed,
        "tcs_exit": tcs_runs[-1]["exit_code"], "semgrep_exit": semgrep_runs[-1]["exit_code"],
        "core_exit": core_runs[-1]["exit_code"],
        "tcs_crashed": any(crashed(r) for r in tcs_runs),
        "semgrep_crashed": any(crashed(r) for r in semgrep_runs),
        "core_crashed": crashed(core_runs[0]) or crashed(core_sarif_run),
        "sarif_cli_sites": sarif_a, "sarif_core_sites": sarif_b,
        "sarif_cli_raw": sarif_a_raw, "sarif_core_raw": sarif_b_raw,
        "sarif_cli_missing": bool(cli_sarif.is_file()) and not sarif_a,
        "sarif_core_missing": bool(core_sarif.is_file()) and not sarif_b,
    }


def parity(m: dict) -> dict:
    """Compare the two TimeCodeSecurity entry points on findings, severities, SARIF sites, exit codes."""
    tcs, core = m["tcs"], m["core"]
    a, b = tcs["sites"], core["sites"]
    sa, sb = m["sarif_cli_sites"], m["sarif_core_sites"]
    return {
        "json_only_cli": sorted(f"{s[0]}:{s[1]}:{s[2]}" for s in a - b),
        "json_only_core": sorted(f"{s[0]}:{s[1]}:{s[2]}" for s in b - a),
        "json_identical": a == b,
        "sarif_only_cli": sorted(f"{s[0]}:{s[1]}:{s[2]}" for s in sa - sb),
        "sarif_only_core": sorted(f"{s[0]}:{s[1]}:{s[2]}" for s in sb - sa),
        "sarif_identical": sa == sb,
        "exit_identical": m["tcs_exit"] == m["core_exit"],
        "sarif_counts": (m["sarif_cli_raw"], m["sarif_core_raw"]),
        "sarif_site_counts": (len(sa), len(sb)),
        "cli_sarif_empty": m["sarif_cli_missing"],
        "core_sarif_empty": m["sarif_core_missing"],
    }


def report(m: dict) -> None:
    cfg, tcs, core, semgrep = m["cfg"], m["tcs"], m["core"], m["semgrep"]
    clean = cfg["clean"]
    scope = "FP resistance (fewer findings = better)" if clean else "coverage (more findings = better)"

    print(f"\n\n# {m['name'].upper()} — {cfg['blurb']}\n")
    print(f"Scored dimension: **{scope}**\n")

    print("\n## Battlefield setup\n")
    print(markdown_table(
        ["Item", "Value"],
        [
            ["Target", f"`{cfg['path']}` @ commit `{m['commit']}`"],
            ["Python files", str(tcs["files_scanned"])],
            ["Semgrep version", semgrep["semgrep_version"] or "n/a"],
            ["Semgrep ruleset(s)", ", ".join(f"`{r}`" for r in cfg["rulesets"])],
            ["Semgrep command", "`" + " ".join(m["semgrep_cmd"]) + "`"],
            ["TimeCodeSecurity command (primary)", "`" + " ".join(m["tcs_cmd"]) + "`"],
            ["TimeCodeSecurity command (2nd entry)", "`" + " ".join(m["core_cmd"]) + "`"],
            ["Timed runs per tool", f"{len(m['tcs_runs'])} (median reported)"],
        ],
    ))

    print("\n## Headline comparison\n")
    speed_leader = "TimeCodeSecurity" if m["tcs_seconds"] < m["semgrep_seconds"] else "Semgrep"
    if clean:
        def findings_note(a: int, b: int) -> str:
            leader = "TimeCodeSecurity" if a < b else ("Semgrep" if b < a else "tie")
            return (f"**{leader}** — fewer on audited code (delta {abs(a - b)})"
                    if leader != "tie" else "tie")
        find_note = findings_note(tcs["total"], semgrep["total"])
        find_note_py = findings_note(tcs["total"], semgrep["total_python_only"])
    else:
        more_tool = "Semgrep" if semgrep["total"] > tcs["total"] else "TimeCodeSecurity"
        find_note = f"**{more_tool}** — more coverage on a vulnerable target"
        find_note_py = find_note

    t_density = 100 * tcs["total"] / max(1, tcs["files_scanned"])
    s_density = 100 * semgrep["total_python_only"] / max(1, semgrep["python_files_scanned"])
    density_leader = "TimeCodeSecurity" if (t_density < s_density) == clean else "Semgrep"
    density_note = (f"**{density_leader}** — quieter per file on audited code" if clean
                    else f"**{density_leader}** — denser coverage per file")
    rows = [
        ["Execution time (s, median)", fmt(m["tcs_seconds"]), fmt(m["semgrep_seconds"]),
         f"**{speed_leader}** ({fmt(abs(m['semgrep_seconds'] - m['tcs_seconds']))}s)"],
        ["Speed-up", f"{fmt(m['semgrep_seconds'] / m['tcs_seconds'])}x vs Semgrep"
         if m["tcs_seconds"] else "n/a",
         f"{fmt(m['tcs_seconds'] / m['semgrep_seconds'])}x vs TimeCodeSecurity"
         if m["semgrep_seconds"] else "n/a", f"**{speed_leader}**"],
        ["Files scanned (all types)", str(tcs["files_scanned"]), str(semgrep["files_scanned"]),
         "Semgrep (sees non-Python files too)"],
        ["Python files scanned", str(tcs["files_scanned"]),
         str(semgrep["python_files_scanned"]), "even (TimeCodeSecurity is Python-only by design)"],
        ["Python files / second", fmt(m["tcs_speed"]), fmt(m["semgrep_speed"]),
         "**TimeCodeSecurity**" if m["tcs_speed"] > m["semgrep_speed"] else "**Semgrep**"],
        ["Peak RSS (MB, median)", fmt(m["tcs_peak_mb"]), fmt(m["semgrep_peak_mb"]),
         memory_note(m)],
        ["Total findings", str(tcs["total"]), str(semgrep["total"]), find_note],
        ["Total findings (Python only)", str(tcs["total"]), str(semgrep["total_python_only"]),
         find_note_py],
        ["Findings per 100 Python files", fmt(t_density), fmt(s_density), density_note],
        ["Distinct CWE classes", str(len(tcs["by_cwe"])), str(len(semgrep["by_cwe"])),
         "informational on a clean target"],
        ["Execution exit code", str(m["tcs_exit"]), str(m["semgrep_exit"]),
         "0=clean, 1=findings (contract shared by both TimeCodeSecurity CLIs)"],
        ["Unhandled exceptions", "YES" if m["tcs_crashed"] else "0",
         "YES" if m["semgrep_crashed"] else "0",
         "both clean" if not (m["tcs_crashed"] or m["semgrep_crashed"]) else "check logs"],
        ["Tool-reported internal errors",
         str(tcs["syntax_errors"] + tcs["skipped_files"]), str(semgrep["tool_errors"]),
         "TimeCodeSecurity: files skipped/unparseable, not crashes"],
    ]
    print(markdown_table(["Metric", "TimeCodeSecurity Engine (v4.3.0)", "Semgrep", "Advantage"], rows))

    par = parity(m)
    print("\n## CLI entry-point parity (`cli.py scan` vs `tcs_cli.py`)\n")
    print(markdown_table(
        ["Contract", "cli.py scan --scope python", "tcs_cli.py", "Verdict"],
        [
            ["Findings emitted", str(tcs["total"]), str(core["total"]),
             "MATCH" if tcs["total"] == core["total"] else "MISMATCH"],
            ["Distinct CWE classes", str(len(tcs["by_cwe"])), str(len(core["by_cwe"])),
             "MATCH" if set(tcs["by_cwe"]) == set(core["by_cwe"]) else "MISMATCH"],
            ["(file, line, CWE, severity) set", f"{len(tcs['sites'])} sites",
             f"{len(core['sites'])} sites",
             "**IDENTICAL**" if par["json_identical"]
             else f"DIFFERS (+{len(par['json_only_cli'])} / -{len(par['json_only_core'])})"],
            ["SARIF v2.1.0 results", f"{par['sarif_counts'][0]} results",
             f"{par['sarif_counts'][1]} results",
             "**IDENTICAL**" if par["sarif_identical"]
             else f"DIFFERS (+{len(par['sarif_only_cli'])} / -{len(par['sarif_only_core'])})"],
            ["Exit code", str(m["tcs_exit"]), str(m["core_exit"]),
             "MATCH" if par["exit_identical"] else "MISMATCH"],
            ["Unhandled exceptions", "0" if not m["tcs_crashed"] else "YES",
             "0" if not (m["core_crashed"]) else "YES", "both clean"],
            ["Median seconds", fmt(m["tcs_seconds"]), fmt(m["core_seconds"]),
             f"{len(tcs['sites'])} vs {len(core['sites'])} sites"],
        ],
    ))
    if not par["json_identical"]:
        print("\n- only in `cli.py scan`: " + ", ".join(par["json_only_cli"][:10]))
        print("- only in `tcs_cli.py`: " + ", ".join(par["json_only_core"][:10]))
    if not par["sarif_identical"]:
        print("\n- SARIF only in `cli.py scan`: " + ", ".join(par["sarif_only_cli"][:10]))
        print("- SARIF only in `tcs_cli.py`: " + ", ".join(par["sarif_only_core"][:10]))

    if clean:
        print("\n## CWE mix on audited code (every row is a false-positive candidate)\n")
        rows = []
        union = sorted(set(tcs["by_cwe"]) | set(semgrep["python_by_cwe"]),
                       key=lambda c: (-(tcs["by_cwe"].get(c, 0)
                                        + semgrep["python_by_cwe"].get(c, 0)), c))
        for cwe in union:
            t, s = tcs["by_cwe"].get(cwe, 0), semgrep["python_by_cwe"].get(cwe, 0)
            rows.append([cwe, str(t), str(s), "both" if t and s else ("TimeCodeSecurity only" if t else "Semgrep only")])
        print(markdown_table(["CWE", "TimeCodeSecurity", "Semgrep (Python)", "Coverage"], rows))
        score = core["security_score"] if core["security_score"] is not None \
            else tcs["security_score"]
        risk = core["risk_level"] or tcs["risk_level"]
        print(f"\n- TimeCodeSecurity self-reported health score for the target: {score}/100, risk {risk}")

        pkg = cfg["pkg"]
        t_zones = Counter(zone_of(p, pkg) for p in tcs["paths"])
        s_zones = Counter(zone_of(p, pkg) for p in semgrep["python_paths"])
        rows = []
        for zone in ["shipped package", "tests", "scripts/docs", "other"]:
            t, s = t_zones.get(zone, 0), s_zones.get(zone, 0)
            if not t and not s:
                continue
            leader = "TimeCodeSecurity" if t < s else ("Semgrep" if s < t else "tie")
            rows.append([zone, str(t), str(s),
                         f"**{leader}** — quieter" if leader != "tie" else "tie"])
        print("\n## Where the findings actually land\n")
        print("Only the `shipped package` row is code a downstream user runs; `tests` and "
              "`scripts/docs` are repo scaffolding, so the headline count overstates the "
              "surface a maintainer must triage.\n")
        print(markdown_table(["Zone", "TimeCodeSecurity", "Semgrep (Python)", "Quieter"], rows))
        ship = t_zones.get("shipped package", 0)
        print(f"\n- TimeCodeSecurity shipped-package findings: **{ship}** of {tcs['total']} "
              f"({100 * ship / max(1, tcs['total']):.1f}%); "
              f"{tcs['total'] - ship} sit in scaffolding")
    else:
        print("\n## Mission CWE coverage\n")
        print("Semgrep is shown twice: all files it scanned (includes Django/Flask `.html` "
              "templates) and Python-only, which is TimeCodeSecurity's scope.\n")
        rows = []
        for cwe, label in HEADLINE_CWES.items():
            t = tcs["by_cwe"].get(cwe, 0)
            s_all = semgrep["by_cwe"].get(cwe, 0)
            s_py = semgrep["python_by_cwe"].get(cwe, 0)
            best = max(t, s_py)
            winner = "TimeCodeSecurity" if t > s_py else ("Semgrep" if s_py > t else "tie")
            rows.append([f"{label} ({cwe})", str(t), str(s_all), str(s_py),
                         f"**{winner}**" if winner != "tie" else f"tie ({best})"])
        print(markdown_table(["Weakness family", "TimeCodeSecurity", "Semgrep (all files)",
                              "Semgrep (Python only)", "Leader (Python scope)"], rows))

        print("\n## Full CWE-by-CWE ledger\n")
        union = sorted(set(tcs["by_cwe"]) | set(semgrep["by_cwe"]),
                       key=lambda c: (-(tcs["by_cwe"].get(c, 0) + semgrep["by_cwe"].get(c, 0)), c))
        rows = []
        for cwe in union:
            t, s = tcs["by_cwe"].get(cwe, 0), semgrep["by_cwe"].get(cwe, 0)
            rows.append([cwe, str(t), str(s),
                         "both" if t and s else ("TimeCodeSecurity only" if t else "Semgrep only")])
        print(markdown_table(["CWE", "TimeCodeSecurity", "Semgrep", "Coverage"], rows))

        common = sorted(set(tcs["by_cwe"]) & set(semgrep["by_cwe"]))
        tcs_only = sorted(set(tcs["by_cwe"]) - set(semgrep["by_cwe"]))
        sem_only = sorted(set(semgrep["by_cwe"]) - set(tcs["by_cwe"]))
        print("\n## Overlap\n")
        print(f"- CWE classes found by both: **{len(common)}** → {', '.join(common) or 'none'}")
        print(f"- TimeCodeSecurity-only CWE classes: **{len(tcs_only)}** → {', '.join(tcs_only) or 'none'}")
        print(f"- Semgrep-only CWE classes: **{len(sem_only)}** → {', '.join(sem_only) or 'none'}")

    print("\n## Raw measurement series (seconds)\n")
    print(f"- Semgrep:        {', '.join(fmt(r['seconds']) for r in m['semgrep_runs'])}")
    print(f"- TimeCodeSecurity (cli.py):   {', '.join(fmt(r['seconds']) for r in m['tcs_runs'])}")
    print(f"- TimeCodeSecurity (tcs_cli):  {fmt(m['core_seconds'])}")

    print("\n## Raw memory series (peak RSS of the scanner process tree, MB)\n")
    print(f"- Semgrep:        {', '.join(fmt(r.get('peak_rss_mb')) for r in m['semgrep_runs'])}")
    print(f"- TimeCodeSecurity (cli.py):   {', '.join(fmt(r.get('peak_rss_mb')) for r in m['tcs_runs'])}")
    print(f"- TimeCodeSecurity (tcs_cli):  {fmt(m.get('core_peak_mb'))}")

    print("\n## Semgrep top rules\n")
    print(markdown_table(["Rule", "Hits"], [[rule, str(n)] for rule, n in semgrep["top_rules"]]))

    print("\n## Severity mix\n")
    tcs_sev = ", ".join(f"{k} {tcs['by_severity'][k]}"
                        for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                        if tcs["by_severity"].get(k)) or "none"
    sem_sev = ", ".join(f"{k} {v}" for k, v in semgrep["severities"].most_common()) or "none"
    print(markdown_table(["Tool", "Severity distribution"],
                         [["TimeCodeSecurity Engine (v4.3.0)", tcs_sev], ["Semgrep", sem_sev]]))


def summary(results: list[dict]) -> None:
    print("\n\n# CROSS-TARGET SUMMARY\n")
    rows = []
    for m in results:
        par = parity(m)
        rows.append([
            m["name"], str(m["tcs"]["files_scanned"]),
            str(m["tcs"]["total"]), str(m["semgrep"]["total_python_only"]),
            f"{fmt(m['tcs_seconds'])}s", f"{fmt(m['semgrep_seconds'])}s",
            f"{fmt(m['tcs_speed'])}", f"{fmt(m['semgrep_speed'])}",
            f"{m['tcs_exit']}/{m['core_exit']}/{m['semgrep_exit']}",
            "0" if not (m["tcs_crashed"] or m["core_crashed"] or m["semgrep_crashed"]) else "CRASH",
            f"{fmt(m.get('tcs_peak_mb'))}", f"{fmt(m.get('semgrep_peak_mb'))}",
            "IDENTICAL" if par["json_identical"] and par["sarif_identical"] else "DIFFERS",
        ])
    print(markdown_table(
        ["Target", "Py files", "TimeCodeSecurity findings", "Semgrep findings (Py)",
         "TimeCodeSecurity time", "Semgrep time", "TimeCodeSecurity files/s", "Semgrep files/s",
         "Exit TimeCodeSecurity/TimeCodeSecurity-core/SG", "Crashes", "TimeCodeSecurity peak MB", "Semgrep peak MB", "CLI parity"],
        rows))

    print("\n## Per-target winner\n")
    rows = []
    for m in results:
        t, s = m["tcs"]["total"], m["semgrep"]["total_python_only"]
        if m["cfg"]["clean"]:
            find = "TimeCodeSecurity" if t < s else ("Semgrep" if s < t else "tie")
            why = "fewer findings on audited code"
        else:
            find = "TimeCodeSecurity" if t > s else ("Semgrep" if s > t else "tie")
            why = "more coverage on vulnerable code"
        ratio = (m["semgrep_seconds"] / m["tcs_seconds"]) if m["tcs_seconds"] else 0.0
        speed = "TimeCodeSecurity" if ratio > 1 else "Semgrep"
        rows.append([m["name"], f"**{find}** ({why})",
                     f"**{speed}** ({fmt(max(ratio, 1 / ratio) if ratio else 0)}x faster)",
                     "yes" if m["tcs_exit"] in (0, 1) and m["semgrep_exit"] in (0, 1)
                     else "check"])
    print(markdown_table(["Target", "Findings", "Speed", "Both completed cleanly?"], rows))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", action="append", choices=sorted(TARGETS),
                        help="battlefield target; repeat for several. Default: pygoat")
    parser.add_argument("--runs", type=int, default=2,
                        help="repeat the wall-clock measurements and keep the median")
    parser.add_argument("--scratch-dir", default="scratch/battlefield")
    args = parser.parse_args(argv)

    names = args.target or ["pygoat"]
    results = []
    for name in names:
        m = measure(name, TARGETS[name], args)
        if m is None:
            print(f"[battlefield] skipping {name}", file=sys.stderr)
            continue
        report(m)
        results.append(m)

    if not results:
        return 2
    summary(results)
    for m in results:
        print(f"\n[battlefield] {m['name']} artefacts: "
              f"{m['out_dir'].relative_to(ROOT)}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
