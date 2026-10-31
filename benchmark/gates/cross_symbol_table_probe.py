"""Fail-loud lock: the cross-file engine's symbol table keeps facts, never ASTs.

    python benchmark/gates/cross_symbol_table_probe.py

The engine used to hold every parsed tree in `GlobalSymbolIndex._ast_cache` for the whole run.
It now streams: `GlobalSymbolIndex.build(on_indexed=...)` registers every module name first, then
parses one file at a time, hands the tree to `CrossFileTaintEngine._on_module_indexed` (summarise +
harvest compact facts), and releases it. Only modules whose facts show a call into a sink-bearing
contract, or whose assignments can reach a sanitizer, are re-read later.

Measured on the shipped code (this checkout, one process per arm):

    Big-8 corpus 8 files / 2.105 MB   facts 3.05 MB + contracts 0.67 MB + modules 0.40 MB
                                      = 4.12 MB table; peak RSS 41.4 MB (HEAD 85.9 MB);
                                      ast_cache 0 (HEAD 8); 0/0 findings, 1/1 suppressed
    benchmark   631 files / 0.734 MB  2.52 MB table; peak RSS 30.2 MB (HEAD 46.1 MB);
                                      engine+suppression 0.99 s (HEAD 1.04 s); 9/9 findings
    1541-file chunk-shaped tree       8.42 MB source -> 23.90 MB table, peak RSS 109.0 MB,
                                      ast_cache 0; 15 findings, 238 suppressed sites

TIER 1 parses a PEP 695 sample (the 3.12 syntax the e2e files use) and requires the fallback to
return a tree, with the alias name at column 0 and on its original line -- blanking the `type`
keyword instead of moving the name leaves it indented and the module-level statement fails.
TIER 2 runs two fixture cases and requires the exact findings, the exact suppression site, an
empty `_ast_cache`, and one harvested fact set per indexed module.
TIER 3 re-runs the same check under three mutations and requires each to be caught:
`no_facts` (streaming callback does nothing), `retain_trees` (callback also stores every tree),
and `no_fallback` (`_parse_source` loses its rewrite retry). Exit 0 only when the shipped engine
passes and all three mutations fail; 1 otherwise.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import cross_file_engine as xf  # noqa: E402
from cross_file_engine import CrossFileTaintEngine  # noqa: E402

FIXTURES = Path(REPO_ROOT) / "benchmark" / "fixtures" / "cross_file"
SAMPLE = (
    "from dataclasses import dataclass\n"
    "type Result[T] = list[T]\n"
    "\n"
    "def fetch[T](value: T) -> T:\n"
    "    return value\n"
    "\n"
    "class Box[T]:\n"
    "    pass\n"
)
CASES = {
    "case_01_multihop_sqli": (frozenset({("CWE-89", "views01.py", 6)}), frozenset()),
    "case_05_sanitizer_middle_layer": (frozenset(), frozenset({("views05.py", 9)})),
}


def _rel_map(case_dir: Path) -> dict:
    return {path.resolve(): path.relative_to(case_dir).as_posix()
            for path in case_dir.rglob("*.py")}


def check() -> list[str]:
    """Every contract this probe locks, as a list of failures (empty means all held)."""
    failures: list[str] = []

    rewritten = xf._rewrite_pep695(SAMPLE)
    tree = xf._parse_source("<pep695>", SAMPLE)
    if tree is None:
        failures.append("PEP-695 fallback returned no tree")
    else:
        alias = tree.body[1]
        if type(alias).__name__ != "Assign" or alias.lineno != 2:
            failures.append("PEP-695 alias lost its node or line")
        first = (rewritten or "").splitlines()
        if len(first) < 2 or first[1].startswith(" ") or not first[1].startswith("Result"):
            failures.append("PEP-695 alias name is not at column 0")

    for case_name, (want_findings, want_sites) in CASES.items():
        case_dir = FIXTURES / case_name
        rel_paths = _rel_map(case_dir)
        engine = CrossFileTaintEngine(case_dir)
        found = {
            (finding.cwe, rel_paths.get(Path(finding.caller_file).resolve(), ""),
             finding.caller_lineno)
            for finding in engine.run()
        }
        sites = {
            (rel_paths.get(Path(path).resolve(), ""), lineno)
            for path, lineno in engine.sanitized_sink_locations()
        }
        if found != want_findings:
            failures.append(f"{case_name} findings {sorted(found)} != {sorted(want_findings)}")
        if sites != want_sites:
            failures.append(f"{case_name} sites {sorted(sites)} != {sorted(want_sites)}")
        if engine.indexer._ast_cache:
            failures.append(f"{case_name} retained {len(engine.indexer._ast_cache)} ASTs")
        if set(engine.module_facts) != set(engine.indexer.modules):
            failures.append(f"{case_name} facts cover {len(engine.module_facts)} of "
                            f"{len(engine.indexer.modules)} modules")
    return failures


def _mutation(name: str):
    """Apply one regression, returning a restore callable."""
    if name == "no_facts":
        original = CrossFileTaintEngine._on_module_indexed
        CrossFileTaintEngine._on_module_indexed = lambda self, mod, path, tree: None
        return lambda: setattr(CrossFileTaintEngine, "_on_module_indexed", original)
    if name == "retain_trees":
        original = CrossFileTaintEngine._on_module_indexed

        def retain(self, mod, path, tree):
            original(self, mod, path, tree)
            self.indexer._ast_cache[mod] = tree

        CrossFileTaintEngine._on_module_indexed = retain
        return lambda: setattr(CrossFileTaintEngine, "_on_module_indexed", original)
    if name == "no_fallback":
        original_parse = xf._parse_source

        def default_only(path, source):
            try:
                return xf.ast.parse(source, filename=path)
            except Exception:
                return None

        xf._parse_source = default_only
        return lambda: setattr(xf, "_parse_source", original_parse)
    raise ValueError(name)


def main() -> int:
    failures = check()
    for failure in failures:
        print("FAIL", failure)
    print(f"shipped engine: failures={len(failures)}")
    caught = 0
    for mutation in ("no_facts", "retain_trees", "no_fallback"):
        restore = _mutation(mutation)
        try:
            mutated = check()
        finally:
            restore()
        caught += bool(mutated)
        print(f"mutation {mutation:12s} -> "
              f"{'CAUGHT: ' + mutated[0] if mutated else 'NOT CAUGHT'}")
    if failures or caught != 3:
        print(f"VERDICT: FAIL - shipped failures={len(failures)}, mutations caught={caught}/3")
        return 1
    print("VERDICT: PASS - no AST retained, facts cover every module, fixture keys exact, "
          "and all 3 mutations caught.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
