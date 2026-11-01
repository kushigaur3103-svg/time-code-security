"""Fail-loud lock for the four workflow controls added to `tcs scan`.

    python benchmark/gates/workflow_controls_probe.py

The controls are developer-facing filters that sit *outside* the AST rules:

1. `# tcs: ignore[CWE-XXX]` / `# tcs: ignore[ALL]` -- exact-line, exact-rule suppression.
2. `--diff [REF]` -- report only findings on lines added/modified versus REF (default HEAD).
3. `--min-confidence high|medium|low` -- display filter, detection unchanged.
4. `.tcs.yaml` -- root path exclusions and per-rule path overrides.

Every tier runs the shipped code and then re-runs the same check under a mutation that
models the obvious regression, so a rolled-back guard fails this probe instead of passing
silently. Exit 0 only when the shipped checks pass and all thirteen mutations are caught.

A seventh tier reads the shipped root `.tcs.yaml` and the two frozen baselines together: no
glob in the noise policy -- global or per rule -- may quiet a blessed finding under any
spelling of its path, and each exclusion this repository *refuses* to ship stays refused only
while a blessed key still sits in its reach.

An eighth tier scans that same shipped policy over a fresh tree and demands the exclusion do
its job where it says it does, and nowhere else: production XXE stays loud, a tests-tree XXE
goes quiet, and a second rule inside the same tests tree stays loud.

The fixture trees are written into a TemporaryDirectory at run time. Nothing is added under
`benchmark/`, which matters because the parity gate scans this tree and a planted sink here
would arrive as a NEW key.
"""
from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import cli  # noqa: E402
import diff_scan  # noqa: E402
import iac_auditor  # noqa: E402
import suppression_resolver  # noqa: E402
import tcs_config  # noqa: E402
from tcs_config import load_config, path_matches, without_root_prefix  # noqa: E402

SUPPRESSION_SRC = (
    "import os\n"
    "from flask import request\n"
    "\n"
    "def suppressed():\n"
    "    cmd = request.args.get('a')\n"
    "    os.system(cmd)  # tcs: ignore[CWE-78]\n"
    "\n"
    "def wrong_rule():\n"
    "    cmd = request.args.get('b')\n"
    "    os.system(cmd)  # tcs: ignore[CWE-328]\n"
)
PARSER_SRC = (
    "value = compute()  # tcs: ignore[CWE-611]\n"
    "other = compute()  # tcs: ignore[ALL]: reviewed\n"
    "text = 'x # tcs: ignore[CWE-22]'\n"
    "third = compute()  # tcs:ignore CWE-89\n"
    "fourth = compute()\n"
)
CONFIDENCE_SRC = (
    "import hashlib\n"
    "digest = hashlib.md5(b'x')\n"
    "\n"
    "def check(token, expected):\n"
    "    return token == expected\n"
)
DIFF_APP_BASE = (
    "import os\n"
    "from flask import request\n"
    "\n"
    "def old_route():\n"
    "    cmd = request.args.get('a')\n"
    "    os.system(cmd)\n"
    "\n"
    "def new_route():\n"
    "    cmd = request.args.get('b')\n"
    "    os.system(cmd)\n"
)
# The working-tree version appends one line to `new_route`; only that line is new.
DIFF_APP_CHANGED = DIFF_APP_BASE + "    os.system(cmd)\n"
DIFF_UTIL = "import os\n\ndef helper(path):\n    os.system(path)\n"
DIFF_UNTRACKED = "import os\n\ndef fresh(path):\n    os.system(path)\n"
CONFIG_YAML = (
    'exclude_paths: ["tests/**"]\n'
    "rules:\n"
    "  CWE-328:\n"
    '    exclude: ["**/demo/**"]\n'
)
CONFIG_APP = (
    "import os\n"
    "from flask import request\n"
    "\n"
    "def view():\n"
    "    cmd = request.args.get('x')\n"
    "    os.system(cmd)\n"
)
CONFIG_MD5 = "import hashlib\n\ndigest = hashlib.md5(b'x')\n"
# `dotted_param` of `cwe611_xml_entity_probe.py`: a resolved dotted parser name fed by a
# function parameter, which that gate proves LOUD at both seals. Nothing but a path policy can
# change its answer, so it is the right carrier for an exclusion tier.
CONFIG_XXE = (
    "import lxml.etree\n"
    "\n"
    "\n"
    "def parse_xml(payload):\n"
    "    return lxml.etree.fromstring(payload)\n"
)


@contextlib.contextmanager
def _chdir(path: Path):
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _run_cli(argv, cwd: Path) -> dict:
    """One in-process CLI run, returning the parsed JSON payload it printed."""
    out, err = io.StringIO(), io.StringIO()
    with _chdir(cwd), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        cli.main(argv)
    text = out.getvalue()
    start = text.find("{")
    if start < 0:
        raise SystemExit(3)
    return json.loads(text[start:])


def _keys(payload: dict) -> set:
    return {(finding["file"], finding["line"], finding["cwe"]) for finding in payload["findings"]}


def check_suppression_parser() -> list:
    failures = []
    directives = suppression_resolver.extract_file_directives(PARSER_SRC)

    first = directives.get(1, [{}])[0]
    if first.get("targets") != {"CWE-611"} or not first.get("exact_line"):
        failures.append(f"line 1 directive parsed as {first!r}")
    second = directives.get(2, [{}])[0]
    if second.get("targets") != {"ALL"} or second.get("justification") != "reviewed":
        failures.append(f"line 2 directive parsed as {second!r}")
    if 3 in directives:
        failures.append("a directive inside a string literal was treated as a comment")
    fourth = directives.get(4, [{}])[0]
    if fourth.get("exact_line") is not False:
        failures.append("the legacy directive lost its block scope")

    findings = [
        {"file": "m.py", "line": 1, "cwe": "CWE-611"},
        {"file": "m.py", "line": 1, "cwe": "CWE-89"},
        {"file": "m.py", "line": 2, "cwe": "CWE-1"},
        {"file": "m.py", "line": 3, "cwe": "CWE-611"},
        {"file": "m.py", "line": 5, "cwe": "CWE-89"},
    ]
    kept = {(item["line"], item["cwe"])
            for item in cli._apply_inline_suppressions(findings, {"m.py": PARSER_SRC})}
    want = {(1, "CWE-89"), (3, "CWE-611"), (5, "CWE-89")}
    if kept != want:
        failures.append(f"exact-line resolution kept {sorted(kept)} != {sorted(want)}")
    return failures


def check_suppression_e2e() -> list:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text(SUPPRESSION_SRC, encoding="utf-8")
        payload = _run_cli(["scan", ".", "--format", "json", "--workers", "1"], root)
        got = _keys(payload)
    want = {("app.py", 10, "CWE-78")}
    return [] if got == want else [f"suppression e2e {sorted(got)} != {sorted(want)}"]


def _build_diff_repo(root: Path) -> None:
    """Create a one-commit repository, then modify one line and add an untracked file.

    Each git call spells its argv as a literal list. This directory sits inside the parity
    scan root and a computed command line reports as CWE-78, so no helper may launder it.
    """
    (root / "app.py").write_text(DIFF_APP_BASE, encoding="utf-8")
    (root / "util.py").write_text(DIFF_UTIL, encoding="utf-8")
    init = subprocess.run(["git", "init", "-q", "."], cwd=str(root),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    staged = subprocess.run(["git", "add", "app.py", "util.py"], cwd=str(root),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    commit = subprocess.run(
        ["git", "-c", "user.email=probe@example.com", "-c", "user.name=probe",
         "commit", "-qm", "base"],
        cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if init.returncode or staged.returncode or commit.returncode:
        raise SystemExit(4)
    (root / "app.py").write_text(DIFF_APP_CHANGED, encoding="utf-8")
    (root / "untracked.py").write_text(DIFF_UNTRACKED, encoding="utf-8")


def check_diff() -> list:
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _build_diff_repo(root)
        intervals = diff_scan.changed_line_intervals(root, "HEAD")
        if intervals.get("app.py") != [(11, 11)]:
            failures.append(f"app.py intervals {intervals.get('app.py')} != [(11, 11)]")
        if intervals.get("untracked.py") != [(1, 4)]:
            failures.append(f"untracked intervals {intervals.get('untracked.py')} != [(1, 4)]")
        if "util.py" in intervals:
            failures.append("an unchanged file was reported as changed")

        findings = [
            {"file": "app.py", "line": 6, "cwe": "CWE-78"},
            {"file": "app.py", "line": 10, "cwe": "CWE-78"},
            {"file": "app.py", "line": 11, "cwe": "CWE-78"},
            {"file": "untracked.py", "line": 4, "cwe": "CWE-78"},
            {"file": "util.py", "line": 4, "cwe": "CWE-78"},
        ]
        with _chdir(root):
            kept = {(item["file"], item["line"])
                    for item in cli._scope_findings_to_diff(findings, intervals, root)}
        want = {("app.py", 11), ("untracked.py", 4)}
        if kept != want:
            failures.append(f"diff filter kept {sorted(kept)} != {sorted(want)}")

        payload = _run_cli(["scan", ".", "--diff", "HEAD", "--format", "json", "--workers", "1"],
                           root)
        got = _keys(payload)
        want_e2e = {("app.py", 11, "CWE-78"), ("untracked.py", 4, "CWE-78")}
        if got != want_e2e:
            failures.append(f"diff e2e {sorted(got)} != {sorted(want_e2e)}")
        if payload.get("diff_ref") != "HEAD":
            failures.append("diff_ref missing from the JSON payload")

        out, err = io.StringIO(), io.StringIO()
        with _chdir(root), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            bad_ref_exit = cli.main(["scan", ".", "--diff", "no-such-ref-xyz",
                                     "--format", "json", "--workers", "1"])
        if bad_ref_exit != 2:
            failures.append(f"unknown ref exited {bad_ref_exit} instead of 2")
    return failures


def check_confidence() -> list:
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "conf.py").write_text(CONFIDENCE_SRC, encoding="utf-8")
        default = _run_cli(["scan", ".", "--format", "json", "--workers", "1"], root)
        labels = {(finding["cwe"], finding["confidence"]) for finding in default["findings"]}
        if ("CWE-328", "HIGH") not in labels:
            failures.append(f"weak hash is not HIGH: {sorted(labels)}")
        if ("CWE-208", "LOW") not in labels:
            failures.append(f"timing compare is not LOW: {sorted(labels)}")

        medium = _run_cli(["scan", ".", "--format", "json", "--workers", "1",
                           "--min-confidence", "medium"], root)
        medium_keys = _keys(medium)
        if ("conf.py", 5, "CWE-208") in medium_keys:
            failures.append("medium filter kept a LOW finding")
        if ("conf.py", 2, "CWE-328") not in medium_keys:
            failures.append("medium filter dropped a HIGH finding")

        high = _run_cli(["scan", ".", "--format", "json", "--workers", "1",
                         "--min-confidence", "high"], root)
        if medium_keys != _keys(high):
            failures.append("high filter differs from medium on this fixture")
        if high.get("confidence_filter") != "high":
            failures.append("confidence_filter missing from the JSON payload")
        if any("confidence" not in finding for finding in default["findings"]):
            failures.append("a finding carries no confidence label")
    return failures


def check_config() -> list:
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".tcs.yaml").write_text(CONFIG_YAML, encoding="utf-8")
        (root / "src" / "demo").mkdir(parents=True)
        (root / "tests").mkdir()
        (root / "src" / "app.py").write_text(CONFIG_APP, encoding="utf-8")
        (root / "tests" / "test_app.py").write_text(CONFIG_APP, encoding="utf-8")
        (root / "src" / "demo" / "util.py").write_text(CONFIG_MD5, encoding="utf-8")
        (root / "src" / "util.py").write_text(CONFIG_MD5, encoding="utf-8")

        payload = _run_cli(["scan", ".", "--format", "json", "--workers", "1"], root)
        got = _keys(payload)
        want = {("src/app.py", 6, "CWE-78"), ("src/util.py", 3, "CWE-328")}
        if got != want:
            failures.append(f"config e2e {sorted(got)} != {sorted(want)}")

        loaded = load_config(root)
        if loaded is None:
            failures.append("load_config returned None for an existing .tcs.yaml")
        else:
            rows = [
                ("tests/test_x.py", "tests/**", True),
                ("a/tests/b.py", "tests", True),
                ("a/tests/b.py", "tests/**", False),
                ("src/demo/u.py", "**/demo/**", True),
                ("demo/u.py", "**/demo/**", True),
                ("src/demo/bay/u.py", "**/demo/**", True),
                ("src/demoX/u.py", "**/demo/**", False),
            ]
            for path_key, pattern, expected in rows:
                if path_matches(path_key, pattern) is not expected:
                    failures.append(f"path_matches({path_key!r}, {pattern!r}) != {expected}")

            strip_rows = [
                ("arena/tests/x.py", "arena", "tests/x.py"),
                ("arena/src/app.py", ".", "arena/src/app.py"),
                ("other/x.py", "arena", "other/x.py"),
                ("arena", "arena", ""),
                ("arena/", "arena", ""),
                ("/abs/x/docs/y.py", "/abs/x", "docs/y.py"),
                ("arena/tests/x.py", "arena/tests", "x.py"),
            ]
            for path_key, root_key, expected in strip_rows:
                if tcs_config.without_root_prefix(path_key, root_key) != expected:
                    failures.append(
                        f"without_root_prefix({path_key!r}, {root_key!r}) != {expected!r}")

            # Both spellings must match: the stripped form is what makes an anchored pattern
            # work below the root, the raw form is what keeps a pattern that *names* the root
            # working. Dropping either half silently changes which trees are excluded.
            scoped = tcs_config.TcsConfig(exclude_paths=("arena/docs/**",),
                                         rule_excludes={"CWE-22": ("tests/**",)})
            if not scoped.excludes_path("arena/docs/a.md", "arena"):
                failures.append("a pattern naming the scan root stopped matching")
            if not scoped.rule_excluded("CWE-22", "arena/tests/t.py", "arena"):
                failures.append("an anchored rule pattern stopped matching below the root")
            if scoped.rule_excluded("CWE-22", "arena/src/t.py", "arena"):
                failures.append("an anchored rule pattern matched outside its tree")

        # The defect this tier locks: aiming the scan at a subdirectory used to spell every
        # collected key with that directory as a prefix, so `tests/**` matched nothing and the
        # exclusion the user wrote was ignored -- silently, in the direction of coverage.
        nested = root / "arena"
        (nested / "src" / "demo").mkdir(parents=True)
        (nested / "tests").mkdir(parents=True)
        (nested / "src" / "app.py").write_text(CONFIG_APP, encoding="utf-8")
        (nested / "tests" / "test_app.py").write_text(CONFIG_APP, encoding="utf-8")
        (nested / "src" / "demo" / "util.py").write_text(CONFIG_MD5, encoding="utf-8")
        (nested / "src" / "util.py").write_text(CONFIG_MD5, encoding="utf-8")
        nested_keys = _keys(_run_cli(["scan", "arena", "--format", "json", "--workers", "1"],
                                     root))
        want_nested = {("arena/src/app.py", 6, "CWE-78"), ("arena/src/util.py", 3, "CWE-328")}
        if nested_keys != want_nested:
            failures.append(f"nested-root config e2e {sorted(nested_keys)} != "
                            f"{sorted(want_nested)}")

        (root / ".tcs.yaml").write_text("exclude_paths: 3\n", encoding="utf-8")
        try:
            load_config(root)
        except ValueError:
            pass
        else:
            failures.append("a malformed .tcs.yaml was accepted")
    return failures


def check_matching_law() -> list:
    """`_selects` tests the anchored subset only, so prove that equals testing everything.

    The shortcut is what keeps the root-relative pass from costing a second full pattern
    loop per finding; if the split ever stops being equivalent, this tier says so instead of
    quietly excluding fewer paths than `.tcs.yaml` declares.
    """
    failures = []
    patterns = ["tests/**", "**/tests/**", "docs", "a/b/**", "**/demo/**", "src/*.py",
                "arena/**", "*.py", "examples/pytorch/**", "**/.github/**"]
    paths = ["tests/x.py", "arena/tests/x.py", "a/b/c.py", "src/demo/u.py", "docs.md",
             "arena/src/app.py", "examples/pytorch/y.py", ".github/workflows/ci.py",
             "x/tests/y/z.py", "arena", "arena/docs/a.md"]
    roots = ["arena", ".", "arena/src", "", "/abs/x"]
    for pattern_set in [tuple(patterns), tuple(patterns[:4]), ("tests/**",), ("**/demo/**",)]:
        for path in paths:
            for root in roots:
                selected = tcs_config.TcsConfig(exclude_paths=pattern_set).excludes_path(path,
                                                                                         root)
                reference = (any(path_matches(path, pat) for pat in pattern_set)
                             or any(path_matches(without_root_prefix(path, root), pat)
                                    for pat in pattern_set))
                if selected != reference:
                    failures.append(f"anchored split disagrees for {pattern_set} "
                                    f"{path!r} root={root!r}: {selected} != {reference}")
    return failures


# Where the frozen Big-8 corpus actually lives now. The stored keys still carry the prefix of
# the machine that blessed them (`scratch/_p3_big/`), which is an artifact of that run and not
# a property of the files, so reachability is measured against the live tree instead.
BIG8_LIVE_PARENT = "benchmark_gates_data/corpus_big8"
BASELINE_KEYS = (("parity", "benchmark/gates/parity_before.keys"),
                 ("big8", "benchmark/gates/big8_before.keys"))
# Exclusion this repository refuses because a blessed finding sits inside it. The refusal is
# re-proved every run: if the blessed key ever leaves the tree, the note itself has to change.
REFUSED_EXCLUDES = {"CWE-208": "**/tests/**"}
# A rule whose blessed population is empty in both baselines gets no protection from them, so a
# path exclusion for it is unmeasurable: `MISSING=0` is exactly what deleting the rule produces.
# CWE-1357 is the sharp case -- `is_workflow_path` only ever returns True below a `.github`
# directory, so `**/.github/**` is not a narrowing of that rule, it is its removal.
SOLE_SOURCE = {"CWE-1357": ("**/.github/**", iac_auditor.is_workflow_path)}


def _baseline_rows() -> list:
    """[(label, file, line, cwe)] for every blessed key in both frozen baselines."""
    rows = []
    for label, relative in BASELINE_KEYS:
        for text in (Path(REPO_ROOT) / relative).read_text(encoding="utf-8").splitlines():
            line = text.strip()
            if not line or line.startswith("#") or line.startswith("{"):
                continue
            row = ast.literal_eval(line)
            if isinstance(row, dict):
                if "file" not in row:
                    continue
                file_key, file_line, cwe = row["file"], row["line"], row["cwe"]
            else:
                file_key, file_line, cwe = row[0], row[1], row[2]
            file_key = str(file_key).replace("\\", "/")
            if label == "big8":
                file_key = f"{BIG8_LIVE_PARENT}/{file_key.split('/')[-1]}"
            rows.append((label, file_key, int(file_line), str(cwe).upper()))
    return rows


def _arena_spellings(file_key: str):
    """Every way a blessed file can be spelled on a real command line.

    The frozen corpora store flattened leaves (`tests__generation__test_utils.py`) while the
    arena spells the same file as a `tests/` directory, so a directory glob that measures clean
    against the stored key would still delete the finding in a real scan. Both forms are tested,
    and so is the bare leaf: a glob is only allowed if it reaches a blessed key in no spelling.
    """
    yield file_key
    leaf = file_key.split("/")[-1]
    yield leaf
    if "__" in leaf:
        parts = leaf.split("__")
        parts[-1] = parts[-1].split(".")[0] + ".py"
        # Built by concatenation, not `"/".join(dirs + parts)`: the engine reads a join over a
        # path-shaped list as a query-builder template and reports CWE-89 on the harness itself.
        inner = "/".join(parts)
        yield inner
        yield f"{file_key[: -len(leaf)]}{inner}"


def _blessed_reach(rows, cwe: str, pattern: str) -> list:
    return [row for row in rows if row[3] == cwe
            and any(path_matches(spelling, pattern) for spelling in _arena_spellings(row[1]))]


def check_blessed_reach() -> list:
    """No glob in the shipped `.tcs.yaml` may quiet a blessed finding, in any spelling.

    This is the noise policy's own Zero-FN lock, and it is recomputed from the frozen baselines
    on every run rather than copied from a comment: a refusal note that has lost its blessed key
    fails the gate too, so a narrowing that became safe is as visible as one that never was.
    """
    failures = []
    config = load_config(Path(REPO_ROOT))
    if config is None:
        return ["the repository ships no .tcs.yaml, so the noise policy has nothing to lock"]
    rows = _baseline_rows()
    counts = {label: sum(1 for row in rows if row[0] == label) for label, _ in BASELINE_KEYS}
    if counts != {"parity": 425, "big8": 119}:
        failures.append(f"baseline row counts {counts} != {{'parity': 425, 'big8': 119}}")
    if "CWE-798" in config.rule_excludes:
        failures.append("CWE-798 carries a rule exclusion; secrets are never path-excluded")
    for pattern in config.exclude_paths:
        for row in rows:
            if any(path_matches(spelling, pattern) for spelling in _arena_spellings(row[1])):
                failures.append(f"global exclude {pattern} hides blessed "
                                f"{row[0]} {row[3]} {row[1]}:{row[2]}")
    for cwe, patterns in sorted(config.rule_excludes.items()):
        for pattern in patterns:
            for row in _blessed_reach(rows, cwe, pattern):
                failures.append(f"{cwe} exclude {pattern} hides blessed "
                                f"{row[0]} {row[3]} {row[1]}:{row[2]}")
    for cwe, pattern in sorted(REFUSED_EXCLUDES.items()):
        if pattern in (config.rule_excludes.get(cwe) or ()):
            failures.append(f"{cwe} ships the refused exclusion {pattern}")
        if not _blessed_reach(rows, cwe, pattern):
            failures.append(f"the refusal of {cwe} {pattern} has no blessed key behind it any more")
    for cwe in sorted(config.rule_excludes):
        if not any(row[3] == cwe for row in rows):
            failures.append(f"{cwe} has 0 blessed rows in either baseline, so its path "
                            f"exclusion {sorted(config.rule_excludes[cwe])} could never be "
                            "measured -- a rule with no frozen population gets no exclusion")
    for cwe, (pattern, predicate) in sorted(SOLE_SOURCE.items()):
        emittable = [".github/workflows/ci.yml", "sub/.github/workflows/ci.yaml",
                     "repo/.github/workflows/build.yml"]
        covered = [path for path in emittable if predicate(path)
                   and path_matches(path, pattern)]
        if len(covered) != len([path for path in emittable if predicate(path)]):
            failures.append(f"{cwe} exclude {pattern} does not span every path the rule can "
                            "read, so the sole-source proof is stale")
        if pattern in (config.rule_excludes.get(cwe) or ()):
            failures.append(f"{cwe} ships {pattern}, which covers 100% of the paths "
                            f"`iac_auditor.is_workflow_path` can ever return True for")
    return failures


def check_shipped_c611_exclude() -> list:
    """The shipped CWE-611 exclude applies, stops at the tests tree, and stays rule-scoped.

    `blessed reach` proves this glob cannot quiet a *frozen* key. This tier proves the other
    three things a row count cannot see: that the exclusion is applied at all (a policy that
    silently does nothing overstates coverage exactly like a missed finding), that it does not
    reach outside a `tests/` directory -- the false-negative direction, since production XXE is
    the finding this rule exists to catch -- and that it silences CWE-611 alone rather than the
    whole file, which would drop every other rule's finding inside a test tree.
    """
    failures = []
    shipped = (Path(REPO_ROOT) / ".tcs.yaml").read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".tcs.yaml").write_text(shipped, encoding="utf-8")
        (root / "src").mkdir()
        (root / "tests").mkdir()
        (root / "src" / "parse_xxe.py").write_text(CONFIG_XXE, encoding="utf-8")
        (root / "tests" / "parse_xxe.py").write_text(CONFIG_XXE, encoding="utf-8")
        # A second rule in the excluded tree: an exclusion that behaved like a file skip quietens
        # this too, and that is a missed finding rather than noise reduction.
        (root / "tests" / "util.py").write_text(CONFIG_MD5, encoding="utf-8")
        got = _keys(_run_cli(["scan", ".", "--format", "json", "--workers", "1"], root))
    if ("src/parse_xxe.py", 5, "CWE-611") not in got:
        failures.append("CWE-611 went silent on src/parse_xxe.py:5, so the shipped exclusion "
                        "reached outside a tests tree (false negative)")
    if any(cwe == "CWE-611" for path, _line, cwe in got if path.startswith("tests/")):
        failures.append("CWE-611 still reports inside tests/, so the shipped .tcs.yaml "
                        "exclusion is not being applied (a silently ignored policy)")
    if ("tests/util.py", 3, "CWE-328") not in got:
        failures.append("CWE-328 went silent on tests/util.py:3, so the CWE-611 exclusion acted "
                        "as a whole-file skip (false negative)")
    return failures


def _mutation(name: str):
    """Apply one regression, returning a restore callable."""
    if name == "suppression_call_removed":
        original = cli._apply_inline_suppressions
        cli._apply_inline_suppressions = lambda findings, sources: findings
        return lambda: setattr(cli, "_apply_inline_suppressions", original)
    if name == "bracket_matches_any_cwe":
        original = suppression_resolver.parse_directive_payload

        def widened(payload):
            parsed = original(payload)
            if parsed is None:
                return None
            return {**parsed, "targets": {"ALL"}}

        suppression_resolver.parse_directive_payload = widened
        return lambda: setattr(suppression_resolver, "parse_directive_payload", original)
    if name == "diff_filter_identity":
        original = cli._scope_findings_to_diff
        cli._scope_findings_to_diff = lambda findings, intervals, repo_root: findings
        return lambda: setattr(cli, "_scope_findings_to_diff", original)
    if name == "confidence_filter_noop":
        original = cli._filter_by_confidence
        cli._filter_by_confidence = lambda findings, minimum: findings
        return lambda: setattr(cli, "_filter_by_confidence", original)
    if name == "timing_rows_promoted":
        original = cli.LOW_CONFIDENCE_SINK_TYPES
        cli.LOW_CONFIDENCE_SINK_TYPES = frozenset()
        return lambda: setattr(cli, "LOW_CONFIDENCE_SINK_TYPES", original)
    if name == "config_rule_excludes_ignored":
        original = tcs_config.TcsConfig.rule_excluded
        tcs_config.TcsConfig.rule_excluded = lambda self, cwe, path_key, root=None: False
        return lambda: setattr(tcs_config.TcsConfig, "rule_excluded", original)
    if name == "config_root_prefix_strip_removed":
        original = staticmethod(tcs_config.TcsConfig._selects)

        def raw_only(patterns, path_key, root):
            if not patterns:
                return False
            return any(tcs_config.path_matches(str(path_key), pattern) for pattern in patterns)

        tcs_config.TcsConfig._selects = staticmethod(raw_only)
        return lambda: setattr(tcs_config.TcsConfig, "_selects", original)
    if name == "anchored_split_only_depth_free":
        original = tcs_config.anchored_patterns
        tcs_config.anchored_patterns = lambda patterns: tuple(
            pattern for pattern in patterns if str(pattern).startswith("**/"))
        return lambda: setattr(tcs_config, "anchored_patterns", original)
    if name == "shipped_config_widened_to_a_blessed_tree":
        original = load_config
        poisoned = tcs_config.TcsConfig(
            exclude_paths=("docs/**", "scratch/**"),
            rule_excludes={"CWE-208": ("**/examples/**", "**/tests/**"),
                           "CWE-798": ("tests/**",)})
        globals()["load_config"] = lambda root=None: poisoned
        return lambda: globals().__setitem__("load_config", original)
    if name == "blessed_reach_reads_the_flattened_leaf_only":
        original = _arena_spellings
        globals()["_arena_spellings"] = lambda file_key: iter([file_key])
        return lambda: globals().__setitem__("_arena_spellings", original)
    if name == "c611_exclude_widened_past_the_tests_tree":
        original = tcs_config.TcsConfig.rule_excluded

        def everywhere(self, cwe, path_key, root=None):
            return str(cwe).upper() == "CWE-611" or original(self, cwe, path_key, root)

        tcs_config.TcsConfig.rule_excluded = everywhere
        return lambda: setattr(tcs_config.TcsConfig, "rule_excluded", original)
    if name == "c611_rule_exclude_becomes_file_skip":
        original = tcs_config.TcsConfig.rule_excluded

        def rule_blind(self, cwe, path_key, root=None):
            merged = tuple(pattern for group in self.rule_excludes.values()
                           for pattern in group)
            return tcs_config.TcsConfig._selects(merged, path_key, root)

        tcs_config.TcsConfig.rule_excluded = rule_blind
        return lambda: setattr(tcs_config.TcsConfig, "rule_excluded", original)
    raise ValueError(name)


CHECKS = {
    "suppression parser": check_suppression_parser,
    "suppression e2e": check_suppression_e2e,
    "diff": check_diff,
    "confidence": check_confidence,
    "config": check_config,
    "matching law": check_matching_law,
    "blessed reach": check_blessed_reach,
    "shipped CWE-611 exclude": check_shipped_c611_exclude,
}
MUTATIONS = (
    ("suppression_call_removed", "suppression e2e"),
    ("bracket_matches_any_cwe", "suppression parser"),
    ("diff_filter_identity", "diff"),
    ("confidence_filter_noop", "confidence"),
    ("timing_rows_promoted", "confidence"),
    ("config_rule_excludes_ignored", "config"),
    ("config_root_prefix_strip_removed", "config"),
    ("anchored_split_only_depth_free", "config"),
    ("shipped_config_widened_to_a_blessed_tree", "blessed reach"),
    ("blessed_reach_reads_the_flattened_leaf_only", "blessed reach"),
    ("c611_exclude_widened_past_the_tests_tree", "shipped CWE-611 exclude"),
    ("c611_rule_exclude_becomes_file_skip", "shipped CWE-611 exclude"),
    ("config_rule_excludes_ignored", "shipped CWE-611 exclude"),
)


def main() -> int:
    failures = []
    for label, check in CHECKS.items():
        found = check()
        for failure in found:
            print("FAIL", failure)
        failures.extend(found)
    print(f"shipped controls: failures={len(failures)}")

    caught = 0
    for mutation, target in MUTATIONS:
        restore = _mutation(mutation)
        try:
            mutated = CHECKS[target]()
        finally:
            restore()
        hit = bool(mutated)
        caught += hit
        print(f"mutation {mutation:28s} -> {'CAUGHT' if hit else 'NOT CAUGHT'}")
    if failures or caught != len(MUTATIONS):
        print(f"VERDICT: FAIL - shipped failures={len(failures)}, "
              f"mutations caught={caught}/{len(MUTATIONS)}")
        return 1
    print("VERDICT: PASS - exact-line suppression, diff scoping, confidence filter and "
          ".tcs.yaml all hold, and every mutation is caught.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
