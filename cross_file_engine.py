"""
TimeCodeSecurity (TCS) - Phase 4: Inter-Procedural / Cross-File Taint Engine
Stitches global symbol index and function taint contracts to detect multi-file exploit paths.
"""

from __future__ import annotations

import ast
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from symbol_indexer import GlobalSymbolIndex, SymbolDefinition
from function_summarizer import FunctionSummarizer, FunctionSummary, ParamSinkEdge


# Common web entrypoint sources
TAINT_SOURCE_PATTERNS = {
    "request.GET", "request.POST", "request.data", "request.body",
    "request.args", "request.form", "request.params", "request.headers",
    "request.COOKIES", "request.query_params"
}


def _ordered_nodes(root: ast.AST):
    """Yield nodes in source (pre-order) sequence so assignment state is chronological."""
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _contracted_functions(tree: ast.AST):
    """Yield (node, qualname) pairs using the same keys FunctionSummarizer indexes by."""
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield stmt, stmt.name
        elif isinstance(stmt, ast.ClassDef):
            for item in stmt.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield item, f"{stmt.name}.{item.name}"


@dataclass(slots=True)
class CrossFileFinding:
    cwe: str
    caller_file: str
    caller_lineno: int
    caller_func: str
    callee_file: str
    callee_func: str
    callee_sink_name: str
    callee_sink_lineno: int
    tainted_param: str


class CrossFileTaintEngine:
    """Pass 2: Traces data flow across modules using precomputed contracts."""

    def __init__(self, root_dir: str | Path):
        self.root_dir = Path(root_dir).resolve()
        self.indexer = GlobalSymbolIndex(self.root_dir)
        self.summarizer: Optional[FunctionSummarizer] = None
        self.contracts: dict[tuple[str, str], FunctionSummary] = {}
        self.findings: list[CrossFileFinding] = []
        # ParamSinkEdge carries no file field, so transitively lifted edges record the
        # module that actually owns the sink here: (mod, qualname, param_idx, sink, lineno) -> path.
        self.sink_origins: dict[tuple[str, str, int, str, int], str] = {}

    def run(self) -> list[CrossFileFinding]:
        # 1. Build Index & Contracts
        self.indexer.build()
        self.summarizer = FunctionSummarizer(self.indexer)
        self.contracts = self.summarizer.build_all_summaries()
        self._propagate_transitive_sink_contracts()

        # 2. Analyze Callers across all modules
        for mod_name, mod_idx in self.indexer.modules.items():
            tree = self.indexer._ast_cache.get(mod_name)
            if not tree:
                continue
            self._analyze_module_calls(mod_name, mod_idx.file_path, tree)

        return self.findings

    def _propagate_transitive_sink_contracts(self) -> None:
        """Fixed-point lift of callee sink contracts into pass-through callers.

        A function that forwards one of its own parameters straight into a callee argument
        inherits that callee's sink obligations, so a 3-layer chain (controller -> service
        -> repo) becomes visible from the outermost call site. Only direct parameter
        forwarding propagates, which keeps the lift alias-free and terminating.
        """
        while True:
            changed = False
            for mod_name, mod_idx in self.indexer.modules.items():
                tree = self.indexer._ast_cache.get(mod_name)
                if not tree:
                    continue
                for func_node, qualname in _contracted_functions(tree):
                    summary = self.contracts.get((mod_name, qualname))
                    if summary is None or not summary.params:
                        continue
                    if self._lift_callee_sinks(mod_name, summary, func_node):
                        changed = True
            if not changed:
                return

    def _lift_callee_sinks(
        self,
        caller_mod: str,
        summary: FunctionSummary,
        func_node: ast.AST,
    ) -> bool:
        param_index = {name: idx for idx, name in enumerate(summary.params)}
        known = {
            (edge.param_idx, edge.sink_cwe, edge.sink_name, edge.lineno)
            for edge in summary.param_sinks
        }
        added = False

        for call in (n for n in ast.walk(func_node) if isinstance(n, ast.Call)):
            resolved = self._resolve_call_contract(caller_mod, call)
            if resolved is None:
                continue
            callee_mod, callee_summary = resolved
            if not callee_summary.param_sinks:
                continue

            for arg_idx, arg in enumerate(call.args):
                if not isinstance(arg, ast.Name):
                    continue
                caller_param_idx = param_index.get(arg.id)
                if caller_param_idx is None:
                    continue

                for edge in callee_summary.param_sinks:
                    if edge.param_idx != arg_idx:
                        continue
                    key = (caller_param_idx, edge.sink_cwe, edge.sink_name, edge.lineno)
                    if key in known:
                        continue
                    known.add(key)
                    summary.param_sinks.append(ParamSinkEdge(
                        param_idx=caller_param_idx,
                        param_name=summary.params[caller_param_idx],
                        sink_cwe=edge.sink_cwe,
                        sink_name=edge.sink_name,
                        lineno=edge.lineno,
                    ))
                    origin_key = (callee_mod, callee_summary.qualname,
                                  edge.param_idx, edge.sink_name, edge.lineno)
                    self.sink_origins[(
                        caller_mod, summary.qualname, caller_param_idx,
                        edge.sink_name, edge.lineno,
                    )] = self.sink_origins.get(origin_key, callee_summary.file_path)
                    added = True

        return added

    def sanitized_sink_locations(self) -> Set[tuple[str, int]]:
        """Call sites whose locally-assigned arguments were all neutralized by a
        cross-file sanitizer contract.

        Single-file scanners cannot see the callee contract, so they report these sites
        as injectable. The returned keys are (resolved file path, call lineno).
        """
        suppressed: Set[tuple[str, int]] = set()
        if not any(summary.is_sanitizer for summary in self.contracts.values()):
            return suppressed
        for mod_name, mod_idx in self.indexer.modules.items():
            tree = self.indexer._ast_cache.get(mod_name)
            if not tree:
                continue
            file_key = str(Path(mod_idx.file_path).resolve())
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    suppressed.update(self._sanitized_sites(mod_name, file_key, node))
        return suppressed

    def _sanitized_sites(
        self,
        mod_name: str,
        file_key: str,
        func_node: ast.AST,
    ) -> Set[tuple[str, int]]:
        sites: Set[tuple[str, int]] = set()
        assigned: Set[str] = set()
        sanitized: Set[str] = set()

        for node in _ordered_nodes(func_node):
            if isinstance(node, ast.Assign):
                summary = self._resolve_call_summary(mod_name, node.value)
                neutralized = bool(summary and summary.is_sanitizer)
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned.add(target.id)
                        if neutralized:
                            sanitized.add(target.id)
                        else:
                            sanitized.discard(target.id)

            elif isinstance(node, ast.Call):
                relevant = {
                    n.id
                    for n in ast.walk(node)
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in assigned
                }
                if relevant and relevant <= sanitized:
                    sites.add((file_key, node.lineno))

        return sites

    def _analyze_module_calls(self, mod_name: str, file_path: Path, tree: ast.AST) -> None:
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_function_body(mod_name, str(file_path), stmt.name, stmt)
            elif isinstance(stmt, ast.ClassDef):
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._analyze_function_body(mod_name, str(file_path), f"{stmt.name}.{item.name}", item)

    def _analyze_function_body(
        self,
        caller_mod: str,
        caller_file: str,
        caller_func_name: str,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        # Step A: Identify tainted variables inside caller function
        tainted_vars: set[str] = set()

        # Check function parameters (e.g. 'request')
        for arg in func_node.args.args:
            if arg.arg in ("request", "req"):
                tainted_vars.add(arg.arg)

        # Track local assignments from sources
        for stmt in func_node.body:
            if isinstance(stmt, ast.Assign):
                rhs_repr = ast.unparse(stmt.value) if hasattr(ast, "unparse") else ""
                is_source = any(src in rhs_repr for src in TAINT_SOURCE_PATTERNS)

                # Contract-aware propagation: a resolved callee summary is authoritative
                # for whether its return value carries the taint of an argument.
                summary = self._resolve_call_summary(caller_mod, stmt.value)
                if summary is not None:
                    if summary.is_sanitizer:
                        is_derived = False
                    else:
                        is_derived = self._returns_tainted_arg(
                            stmt.value, summary.tainted_returns, tainted_vars
                        )
                else:
                    is_derived = any(t_var in rhs_repr for t_var in tainted_vars)

                if is_source or is_derived:
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            tainted_vars.add(target.id)

            # Step B: Check external calls in this statement
            for call_node in [n for n in ast.walk(stmt) if isinstance(n, ast.Call)]:
                self._check_call_against_contracts(
                    caller_mod,
                    caller_file,
                    caller_func_name,
                    call_node,
                    tainted_vars,
                )

    def _resolve_call_contract(
        self,
        caller_mod: str,
        value: ast.expr,
    ) -> Optional[tuple[str, FunctionSummary]]:
        """Return (callee module, contract) for a direct call expression, or None."""
        if not isinstance(value, ast.Call):
            return None

        if isinstance(value.func, ast.Name):
            call_name = value.func.id
        elif isinstance(value.func, ast.Attribute):
            call_name = value.func.attr
        else:
            return None

        symbol_def = self.indexer.resolve_symbol(caller_mod, call_name)
        if not symbol_def:
            return None

        callee_mod = self.indexer.file_to_module.get(Path(symbol_def.file_path).resolve())
        if not callee_mod:
            return None

        summary = self.contracts.get((callee_mod, symbol_def.name))
        if summary is None:
            return None
        return callee_mod, summary

    def _resolve_call_summary(
        self,
        caller_mod: str,
        value: ast.expr,
    ) -> Optional[FunctionSummary]:
        """Return the contract for a direct call expression, or None if unresolved."""
        resolved = self._resolve_call_contract(caller_mod, value)
        return resolved[1] if resolved else None

    @staticmethod
    def _returns_tainted_arg(
        value: ast.Call,
        tainted_returns: Set[int],
        tainted_vars: Set[str],
    ) -> bool:
        """True when an argument in a taint-propagating parameter position is tainted."""
        for param_idx in tainted_returns:
            if param_idx >= len(value.args):
                continue
            arg_names = {n.id for n in ast.walk(value.args[param_idx]) if isinstance(n, ast.Name)}
            if arg_names & tainted_vars:
                return True
        return False

    def _check_call_against_contracts(
        self,
        caller_mod: str,
        caller_file: str,
        caller_func_name: str,
        call: ast.Call,
        tainted_vars: set[str],
    ) -> None:
        call_name = ""
        if isinstance(call.func, ast.Name):
            call_name = call.func.id
        elif isinstance(call.func, ast.Attribute):
            call_name = call.func.attr

        if not call_name:
            return

        # Resolve callee symbol
        symbol_def = self.indexer.resolve_symbol(caller_mod, call_name)
        if not symbol_def:
            return

        # Lookup contract
        callee_mod = self.indexer.file_to_module.get(Path(symbol_def.file_path).resolve())
        if not callee_mod:
            return

        summary = self.contracts.get((callee_mod, symbol_def.name))
        if not summary:
            return

        # Check if caller passed tainted arguments into callee's sink parameters
        for arg_idx, arg in enumerate(call.args):
            arg_repr = ast.unparse(arg) if hasattr(ast, "unparse") else ""
            is_tainted_arg = any(t in arg_repr for t in tainted_vars) or any(src in arg_repr for src in TAINT_SOURCE_PATTERNS)

            if is_tainted_arg:
                # Check target sinks
                for sink in summary.param_sinks:
                    if sink.param_idx == arg_idx:
                        self.findings.append(
                            CrossFileFinding(
                                cwe=sink.sink_cwe,
                                caller_file=caller_file,
                                caller_lineno=getattr(call, "lineno", 0),
                                caller_func=f"{caller_mod}.{caller_func_name}",
                                callee_file=self.sink_origins.get(
                                    (callee_mod, summary.qualname, sink.param_idx,
                                     sink.sink_name, sink.lineno),
                                    summary.file_path,
                                ),
                                callee_func=f"{callee_mod}.{summary.qualname}",
                                callee_sink_name=sink.sink_name,
                                callee_sink_lineno=sink.lineno,
                                tainted_param=sink.param_name,
                            )
                        )


if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[*] Starting TimeCodeSecurity Cross-File Taint Engine on: {target_dir}")
    t0 = time.perf_counter()

    engine = CrossFileTaintEngine(target_dir)
    findings = engine.run()
    elapsed = (time.perf_counter() - t0) * 1000

    print("\n=================================================================")
    print("        TIMECODESECURITY (TCS) - CROSS-FILE ANALYSIS REPORT       ")
    print("=================================================================")
    print(f"Execution Time:              {elapsed:.2f} ms")
    print(f"Total Cross-File Exploits:   {len(findings)}")
    print("-----------------------------------------------------------------")

    if findings:
        for i, f in enumerate(findings, 1):
            print(f"\n[{i}] VULNERABILITY: {f.cwe}")
            print(f"    Source Call-site: {f.caller_func} ({f.caller_file}:{f.caller_lineno})")
            print(f"    Flows Into:       {f.callee_func} (Param: '{f.tainted_param}')")
            print(f"    Exploit Sink:     {f.callee_sink_name} at {f.callee_file}:{f.callee_sink_lineno}")
    else:
        print("[+] No unhandled cross-file taint leaks detected.")