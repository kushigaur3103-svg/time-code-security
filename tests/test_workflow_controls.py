"""Unit locks for the workflow controls: suppression, diff scoping, confidence, `.tcs.yaml`.

The end-to-end wiring (a real CLI run over a temp tree, with one mutation per guard) lives
in `benchmark/gates/workflow_controls_probe.py`; this file pins the building blocks.
"""
from __future__ import annotations

import contextlib
import io
import json
import pathlib

import cli
import diff_scan
import suppression_resolver
from suppression_resolver import (
    extract_file_directives,
    find_matching_directive,
    resolve_line_suppressions,
)
from tcs_config import TcsConfig, load_config, path_matches, without_root_prefix


# ─── Feature 1: `# tcs: ignore[CWE-XXX]` ───

def test_bracket_directive_parses_targets_and_justification():
    source = "run()  # tcs: ignore[CWE-611, CWE-22]: reviewed by security\n"
    parsed = extract_file_directives(source)[1][0]
    assert parsed["targets"] == {"CWE-611", "CWE-22"}
    assert parsed["justification"] == "reviewed by security"
    assert parsed["exact_line"] is True


def test_all_directive_is_case_insensitive():
    parsed = extract_file_directives("run()  # TCS: Ignore[all]\n")[1][0]
    assert parsed["targets"] == {"ALL"}


def test_directive_in_a_string_literal_is_ignored():
    source = "text = 'x  # tcs: ignore[CWE-22]'\nrun()\n"
    assert extract_file_directives(source) == {}


def test_bracket_directive_only_covers_its_own_line():
    source = "# tcs: ignore[CWE-89]\nrun(query)\n"
    directives = extract_file_directives(source)
    assert find_matching_directive(2, "CWE-89", directives, source.splitlines()) is None


def test_bracket_directive_does_not_cross_to_a_later_line():
    findings = [{"file": "m.py", "line": 2, "cwe": "CWE-89"}]
    resolve_line_suppressions(findings, {"m.py": "# tcs: ignore[ALL]\nrun(query)\n"})
    assert not findings[0].get("suppressed")


def test_only_the_named_rule_is_suppressed():
    source = "run()  # tcs: ignore[CWE-611]\n"
    findings = [
        {"file": "m.py", "line": 1, "cwe": "CWE-611"},
        {"file": "m.py", "line": 1, "cwe": "CWE-89"},
    ]
    resolve_line_suppressions(findings, {"m.py": source})
    assert findings[0]["suppressed"] is True
    assert not findings[1].get("suppressed")


def test_legacy_directive_still_reaches_the_line_below():
    source = "# tcs:ignore CWE-89\nrun(query)\n"
    directives = extract_file_directives(source)
    matched = find_matching_directive(2, "CWE-89", directives, source.splitlines())
    assert matched is not None and matched["exact_line"] is False


def test_cli_suppression_drops_only_the_named_line(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import request\n\n"
        "def a():\n    c = request.args.get('x')\n"
        "    os.system(c)  # tcs: ignore[CWE-78]\n\n"
        "def b():\n    c = request.args.get('y')\n"
        "    os.system(c)  # tcs: ignore[CWE-328]\n",
        encoding="utf-8")
    payload = _scan(tmp_path)
    assert {(item["file"], item["line"], item["cwe"]) for item in payload["findings"]} == {
        ("app.py", 10, "CWE-78")}


# ─── Feature 2: `--diff [REF]` ───

def test_added_intervals_parse_hunk_headers():
    patch = (
        "diff --git a/x b/x\n"
        "@@ -1,2 +1,3 @@\n"
        "@@ -9 +10 @@\n"
        "@@ -20,3 +20,0 @@\n"
        "@@ -30,0 +31,2 @@\n"
    )
    assert diff_scan.added_intervals_from_patch(patch) == [(1, 3), (10, 10), (31, 32)]


def test_diff_scope_keeps_changed_lines_only(tmp_path):
    findings = [
        {"file": "app.py", "line": 3, "cwe": "CWE-78"},
        {"file": "app.py", "line": 4, "cwe": "CWE-78"},
        {"file": "app.py", "line": None, "cwe": "CWE-78"},
        {"file": "other.py", "line": 1, "cwe": "CWE-78"},
    ]
    with _chdir(tmp_path):
        kept = cli._scope_findings_to_diff(findings, {"app.py": [(4, 5)]}, tmp_path)
    assert [item["line"] for item in kept] == [4, None]


# ─── Feature 3: confidence ───

def test_confidence_filter_orders_low_medium_high():
    findings = [{"confidence": "LOW"}, {"confidence": "MEDIUM"}, {"confidence": "HIGH"}, {}]
    kept = cli._filter_by_confidence(findings, "medium")
    assert [item.get("confidence") for item in kept] == ["MEDIUM", "HIGH", None]
    assert cli._filter_by_confidence(findings, "high") == [{"confidence": "HIGH"}]
    assert cli._filter_by_confidence(findings, None) is findings


def test_confirmed_flow_is_high_and_timing_compare_is_low(tmp_path):
    (tmp_path / "conf.py").write_text(
        "import hashlib\ndigest = hashlib.md5(b'x')\n\n"
        "def check(token, expected):\n    return token == expected\n",
        encoding="utf-8")
    labels = {(item["cwe"], item["confidence"]) for item in _scan(tmp_path)["findings"]}
    assert ("CWE-328", "HIGH") in labels
    assert ("CWE-208", "LOW") in labels


# ─── Feature 4: `.tcs.yaml` ───

def test_path_matches_is_segment_aware():
    rows = [
        ("tests/test_x.py", "tests/**", True),
        ("a/tests/b.py", "tests", True),
        ("a/tests/b.py", "tests/**", False),
        ("src/demo/u.py", "**/demo/**", True),
        ("demo/u.py", "**/demo/**", True),
        ("src/demoX/u.py", "**/demo/**", False),
        ("src/app.py", "tests/**", False),
    ]
    assert [(path, pattern) for path, pattern, expected in rows
            if path_matches(path, pattern) is not expected] == []


def test_config_missing_file_is_inactive(tmp_path):
    assert load_config(tmp_path) is None


def test_config_rejects_unknown_keys(tmp_path):
    (tmp_path / ".tcs.yaml").write_text("exclude_pathz: ['tests/**']\n", encoding="utf-8")
    try:
        load_config(tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("a misspelled key must fail loudly, not silently scan everything")


def test_config_applies_path_and_rule_excludes(tmp_path):
    (tmp_path / ".tcs.yaml").write_text(
        'exclude_paths: ["tests/**"]\nrules:\n  CWE-328:\n'
        '    exclude: ["**/demo/**"]\n', encoding="utf-8")
    (tmp_path / "src" / "demo").mkdir(parents=True)
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "app.py").write_text(_COMMAND_SINK, encoding="utf-8")
    (tmp_path / "tests" / "test_app.py").write_text(_COMMAND_SINK, encoding="utf-8")
    (tmp_path / "src" / "demo" / "util.py").write_text(_MD5, encoding="utf-8")
    (tmp_path / "src" / "util.py").write_text(_MD5, encoding="utf-8")
    with _chdir(tmp_path):
        payload = _scan(tmp_path)
    assert {(item["file"], item["line"], item["cwe"]) for item in payload["findings"]} == {
        ("src/app.py", 6, "CWE-78"), ("src/util.py", 3, "CWE-328")}


def test_root_prefix_strip_table():
    assert [(key, root) for key, root, expected in [
        ("arena/tests/x.py", "arena", "tests/x.py"),
        ("arena/src/app.py", ".", "arena/src/app.py"),
        ("arena/src/app.py", "arena", "src/app.py"),
        ("other/x.py", "arena", "other/x.py"),
        ("arena", "arena", ""),
        ("/abs/x/docs/y.py", "/abs/x", "docs/y.py"),
    ] if without_root_prefix(key, root) != expected] == []


def test_config_excludes_apply_below_a_named_subdirectory(tmp_path):
    """`docs/**` must mean the same thing for `scan .` and for `scan arena`."""
    (tmp_path / ".tcs.yaml").write_text(
        'exclude_paths: ["tests/**"]\nrules:\n  CWE-328:\n'
        '    exclude: ["**/demo/**"]\n', encoding="utf-8")
    arena = tmp_path / "arena"
    (arena / "src" / "demo").mkdir(parents=True)
    (arena / "tests").mkdir(parents=True)
    (arena / "src" / "app.py").write_text(_COMMAND_SINK, encoding="utf-8")
    (arena / "tests" / "test_app.py").write_text(_COMMAND_SINK, encoding="utf-8")
    (arena / "src" / "demo" / "util.py").write_text(_MD5, encoding="utf-8")
    (arena / "src" / "util.py").write_text(_MD5, encoding="utf-8")
    nested = _scan(tmp_path, "arena")
    assert {(item["file"], item["line"], item["cwe"]) for item in nested["findings"]} == {
        ("arena/src/app.py", 6, "CWE-78"), ("arena/src/util.py", 3, "CWE-328")}

    # A pattern that names the root itself still matches: the raw key is tried too.
    scoped = TcsConfig(exclude_paths=("arena/docs/**",), rule_excludes={"CWE-22": ("tests/**",)})
    assert scoped.excludes_path("arena/docs/a.md", "arena") is True
    assert scoped.rule_excluded("CWE-22", "arena/tests/t.py", "arena") is True
    assert scoped.rule_excluded("CWE-22", "arena/src/t.py", "arena") is False


# ─── shipped noise policy ───

def test_shipped_policy_excludes_nothing_the_baselines_could_lose():
    """The `.tcs.yaml` in the repository root must never quiet a blessed finding's tree.

    Each of these patterns was asked for and refused: the blessed Big-8 keys live inside the
    directory it names, or the rule has no frozen population at all to measure the loss against.
    """
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    config = load_config(repo_root)
    assert config is not None, "the repository root must ship .tcs.yaml"
    assert tuple(config.exclude_paths) == ("docs/**", "scratch/**")
    assert "CWE-798" not in config.rule_excludes, "a committed secret is never path-excluded"
    forbidden = {
        "CWE-22": ("tests/**", "**/tests/**"),
        "CWE-338": ("tests/**", "**/tests/**",
                    "**/transformers/models/**", "**/models/**"),
        "CWE-208": ("**/tests/**", "tests/**"),
        "CWE-312": ("**/tests/**", "tests/**"),
        "CWE-770": ("**/tests/**",),
        "CWE-95": ("**/tests/**",),
        "CWE-400": ("**/tests/**",),
        "CWE-1357": ("**/.github/**", "**/.circleci/**", "tests/**"),
        "CWE-250": ("**/docker/**",),
        "CWE-269": ("**/docker/**",),
    }
    shipped = {cwe: tuple(patterns) for cwe, patterns in config.rule_excludes.items()}
    for cwe, patterns in forbidden.items():
        assert not set(patterns) & set(shipped.get(cwe, ())), f"{cwe} excludes {patterns}"


def test_shipped_policy_noise_rules_are_measured_zero_reach():
    """The rules that *do* exclude tests/examples are the ones with nothing blessed there."""
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    config = load_config(repo_root)
    for cwe in ("CWE-117", "CWE-502", "CWE-319", "CWE-434"):
        assert "**/examples/**" in set(config.rule_excludes[cwe]), f"{cwe} lost its examples exclude"
        assert "**/tests/**" in set(config.rule_excludes[cwe]), f"{cwe} lost its tests exclude"
    # CWE-611 is tests-only and must stay that way: its 16 blessed parity keys are XML parses in
    # `benchmark/corpus/cwe_*`, so an examples/scripts glob has never been measured for it.
    assert set(config.rule_excludes["CWE-611"]) == {"**/tests/**"}, "CWE-611 exclude drifted"


def test_shipped_cwe22_scaffolding_excludes_keep_the_package_prefix():
    """The two new CWE-22 globs are package-qualified, and only CWE-22 carries them.

    `**/transformers/benchmark/**` silences 3 arena rows. `**/benchmark/**` silences those 3 *and*
    deletes 7 of the 8 parity blessed CWE-22 keys, because `benchmark/corpus/` is where this
    repository keeps the corpus those keys were blessed from. So the `transformers/` segment is part
    of the safety claim and not a style choice -- `workflow_controls_probe.py`'s ninth tier proves it
    by scanning a real top-level `benchmark/` tree and demanding the traversal there survive.
    """
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    config = load_config(repo_root)
    scaffold = {"**/transformers/commands/**", "**/transformers/benchmark/**"}
    shipped = set(config.rule_excludes["CWE-22"])
    assert scaffold <= shipped, "CWE-22 lost a measured scaffolding exclude"
    loose = {pattern for pattern in shipped
             if ("benchmark" in pattern or "commands" in pattern) and pattern not in scaffold}
    assert not loose, f"CWE-22 carries an unqualified scaffolding glob: {sorted(loose)}"
    moved = {cwe for cwe, patterns in config.rule_excludes.items()
             if cwe != "CWE-22" and scaffold & set(patterns)}
    assert not moved, (f"the scaffolding globs leaked into {sorted(moved)}, whose blessed reach "
                       "was never measured")


def test_shipped_nonprod_excludes_are_root_anchored_and_rule_scoped():
    """`utils/**` is the anchored spelling, it sits under `rules`, and no glob is a secret-home skip.

    Measured on the frozen arena artifact: `**/utils/**` selects 165 rows over 11 rules and 28 of
    them live in `src/transformers/utils/` -- library code -- while the root-anchored `utils/**`
    selects the same 126 scaffolding rows and 0 production rows. Both measure 0 blessed reach in
    every spelling, so neither `aa_parity.py` nor `big8_ab.py` can tell the two apart, which is why
    the shape is pinned here and its behaviour is pinned in the gate's `shipped nonprod exclude`
    tier. The three exact-set rows are the mandate's item 2 refused at half: CWE-208 `**/tests/**`
    reaches 19 of 36 blessed keys and CWE-312 `**/tests/**` reaches its only Big-8 key
    (tests/models/markuplm/test_tokenization_markuplm.py:74), so those rules keep examples only.
    """
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    config = load_config(repo_root)
    assert not [pattern for pattern in config.exclude_paths
                if str(pattern).startswith("**/")], "a global must name a root-level tree"
    assert not [cwe for cwe, patterns in config.rule_excludes.items()
                if "**/utils/**" in set(patterns)], "the depth-free utils glob leaked into a rule"
    anchored = {cwe for cwe, patterns in config.rule_excludes.items()
                if "utils/**" in set(patterns)}
    assert {"CWE-22", "CWE-78", "CWE-117", "CWE-89", "CWE-94", "CWE-79", "CWE-918",
            "CWE-770", "CWE-1333"} <= anchored, f"missing `utils/**` in {sorted(anchored)}"
    for cwe in ("CWE-208", "CWE-312", "CWE-95"):
        assert set(config.rule_excludes[cwe]) == {"**/examples/**"}, f"{cwe} drifted"


def test_a_slice_of_a_refused_tree_is_refused_with_it():
    """`**/tests/trainer/**` measures 0 blessed reach and is still not allowed to ship.

    Its own reach is 0 for CWE-338 (3 arena rows) while its parent `**/tests/**` reaches 7 of the
    16 blessed CWE-338 keys. Reach is a property of the two frozen corpora, not of the tree, so a
    clean slice number is not a permission slip -- the refusal is inherited from the parent and
    re-proved by `workflow_controls_probe.py` (`refused_tree_slice_shipped` is CAUGHT on exactly
    that assertion). Here the same law is pinned from the config side.
    """
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    config = load_config(repo_root)
    assert "**/tests/trainer/**" not in set(config.rule_excludes.get("CWE-338") or ())
    slices = [pattern for patterns in config.rule_excludes.values() for pattern in patterns
              if "/tests/" in str(pattern) and not str(pattern).endswith("tests/**")]
    assert not slices, f"a subdirectory of a refused tests tree shipped: {sorted(slices)}"
    assert path_matches("src/transformers/tests/trainer/x.py", "**/tests/trainer/**")
    assert path_matches("src/transformers/tests/trainer/x.py", "**/tests/**"), (
        "the slice is no longer inside the refused parent, so the inherited refusal is stale")
    assert path_matches("src/transformers/tests/trainer/x.py", "**/tests/**"), (
        "the slice is no longer inside the refused parent, so the inherited refusal is stale")


def test_the_ml_models_tree_glob_is_refused_and_its_margin_is_the_prefix():
    """`**/transformers/models/**` measures 0 blessed reach and is still refused -- on three facts.

    Its yield is real (82 rows in 46 files of the frozen artifact, 58 live) and its own blessed
    reach is 0 of 16 CWE-338 keys, so neither baseline can see the loss. The refusal is therefore
    not a reach count: (a) the un-qualified parent `**/models/**` reaches the whisper Big-8 draw at
    `tests/models/whisper/test_modeling_whisper.py:97`, so the `transformers/` segment carries the
    whole margin and the two spellings must never be treated as one; (b) the glob is not bounded --
    the library root and a near-miss name must stay outside it; (c) a path match cannot express the
    proof CWE-338 asks of a draw, so shipping it deletes the credential question in a tree the same
    artifact reports CWE-312 and CWE-532 rows in. Pinned behaviourally by the twelfth check of
    `workflow_controls_probe.py`, whose three mutations each fail their own assertion.
    """
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    config = load_config(repo_root)
    shipped = set(config.rule_excludes.get("CWE-338") or ())
    assert "**/transformers/models/**" not in shipped, f"CWE-338 ships {shipped}"
    assert "**/models/**" not in shipped, "the refused parent spelling shipped instead"
    inside = ("src/transformers/models/jukebox/modeling_jukebox.py",
              "src/transformers/models/deprecated/tapex/tokenization_tapex.py",
              "src/transformers/models/flava/image_processing_flava.py",
              "src/transformers/models/bart/modeling_flax_bart.py")
    assert all(path_matches(one, "**/transformers/models/**") for one in inside), (
        "the refusal note describes paths the glob no longer selects")
    for outside in ("src/transformers/modeling_utils.py", "src/transformers/models_bert/x.py",
                    "setup.py"):
        assert not path_matches(outside, "**/transformers/models/**"), f"unbounded: {outside}"
    blessed = "tests/models/whisper/test_modeling_whisper.py"
    assert path_matches(blessed, "**/models/**"), (
        "the parent glob lost the blessed key that makes this tree refused")
    assert not path_matches(blessed, "**/transformers/models/**"), (
        "the qualified and unqualified spellings now answer alike, so the prefix is not a margin")


# ─── helpers ───

_COMMAND_SINK = (
    "import os\nfrom flask import request\n\n"
    "def view():\n    cmd = request.args.get('x')\n    os.system(cmd)\n")
_MD5 = "import hashlib\n\ndigest = hashlib.md5(b'x')\n"


@contextlib.contextmanager
def _chdir(path):
    import os
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _scan(root, target="."):
    out = io.StringIO()
    with _chdir(root), contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        cli.main(["scan", target, "--format", "json", "--workers", "1"])
    text = out.getvalue()
    return json.loads(text[text.find("{"):])
