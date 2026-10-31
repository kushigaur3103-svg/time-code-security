"""
TimeCodeSecurity - Phase 4: Inter-Procedural / Cross-File Taint Engine
Stitches global symbol index and function taint contracts to detect multi-file exploit paths.
"""

from __future__ import annotations

import ast
import io
import sys
import time
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Set

from symbol_indexer import GlobalSymbolIndex
from function_summarizer import KNOWN_SANITIZERS, FunctionSummarizer, FunctionSummary, ParamSinkEdge


# Common web entrypoint sources
TAINT_SOURCE_PATTERNS = {
    "request.GET", "request.POST", "request.data", "request.body",
    "request.args", "request.form", "request.params", "request.headers",
    "request.COOKIES", "request.query_params"
}


# Framework event-bus vocabulary: a producer never calls a handler directly, so the
# dispatch method has to be re-read as a call of the registered subscriber.
SIGNAL_FACTORY_METHODS = {"Signal"}
SIGNAL_SUBSCRIBE_DECORATORS = {"receiver"}
SIGNAL_EMISSION_METHODS = {"send", "send_robust"}
TASK_DECORATOR_NAMES = {"shared_task", "task"}
TASK_DISPATCH_METHODS = {"delay", "apply_async"}
_DISPATCH_ATTRS = SIGNAL_EMISSION_METHODS | TASK_DISPATCH_METHODS


_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
# Concrete node types the sanitizer scan's two loops can ever read: _sanitized_sites tests
# ast.Assign / ast.Call on the loop node, and _instance_bindings tests ast.Assign on it. AnnAssign
# and AugAssign are carried as well so a node can only ever be kept by mistake - the loops below
# keep their isinstance guards, so a kept-by-mistake node is re-tested and ignored. Dropping a
# node the other way would cost a suppression, which is how a false negative is born.
_GATE_SITE_NODES = frozenset({ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Call})
_GATE_RECEIVER_NODES = frozenset({ast.Assign, ast.AnnAssign, ast.AugAssign})


def _ordered_nodes(root: ast.AST, skip_scopes: bool = False):
    """Yield nodes in source (pre-order) sequence so assignment state is chronological.

    With skip_scopes, nested function/class bodies are not descended into, keeping the
    traversal to the root node's own lexical scope.
    """
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        if skip_scopes and node is not root and isinstance(node, _SCOPES):
            continue
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


def _function_defs(tree: ast.AST):
    """Yield every FunctionDef/AsyncFunctionDef in a module by visiting statements only.

    A def can only ever sit in statement position, so skipping `ast.expr` and `ast.pattern`
    subtrees returns the same node set an isinstance filter over `ast.walk(tree)` produces,
    without paying for the expression nodes that make up most of a module's tree. Nested
    `match`/`try`/`with`/`if` bodies are still descended, and defs nested inside a def body
    are included, exactly as `ast.walk` would find them.
    """
    stack = [tree]
    while stack:
        node = stack.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.expr, ast.pattern)):
                continue
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield child
            stack.append(child)


def _has_assign_statement(root: ast.AST) -> bool:
    """Is there any assignment-shaped statement anywhere below `root`?

    `ast.Assign` only ever sits in statement position - a statement cannot hide inside an
    `ast.expr` / `ast.pattern` subtree (a lambda body is an expression) - so pruning those, exactly
    as _function_defs does, still answers yes for every body the full walk would have found an
    Assign in. A body answering no therefore cannot fill `assigned`, so it cannot yield a site.
    The test is deliberately assignment-shaped rather than Assign-only: an AnnAssign body costs
    one extra full walk that then finds nothing, which is cheap, whereas a false "no" would delete
    a suppression.
    """
    stack = [root]
    while stack:
        node = stack.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.expr, ast.pattern)):
                continue
            if type(child) in _GATE_RECEIVER_NODES:
                return True
            stack.append(child)
    return False


def _record_productive(root: ast.AST):
    """One pre-order walk of a body that records only the nodes the site loops can use.

    Returns (own_scope_assigns, productive):
      * `productive` is the same sequence _ordered_nodes(root) restricted to _GATE_SITE_NODES
        would have yielded, so replaying over it keeps the two walks' node order untouched.
      * `own_scope_assigns` carries the `depth == 0` entries, which is exactly what
        _ordered_nodes(root, skip_scopes=True) yields for assignments: a nested scope node is
        itself still own-scope, its children are not. `_sanitized_sites` needs the two separate
        because the engine builds the receiver map for the WHOLE body first and hands that finished
        map to every assignment it resolves; folding both loops into one chronological pass would
        show an earlier line a smaller map, which is a behaviour change, not a speed-up.
    """
    own_scope_assigns: List[ast.AST] = []
    productive: List[ast.AST] = []
    stack: List[tuple[ast.AST, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth == 0 and type(node) in _GATE_RECEIVER_NODES:
            own_scope_assigns.append(node)
        if type(node) in _GATE_SITE_NODES:
            productive.append(node)
        child_depth = depth + 1 if (node is not root and isinstance(node, _SCOPES)) else depth
        stack.extend((child, child_depth)
                     for child in reversed(list(ast.iter_child_nodes(node))))
    return own_scope_assigns, productive


def _dotted_prefix(expr: ast.expr) -> str:
    """Dotted spelling of a Name/Attribute expression chain, '' when it is anything else."""
    parts: List[str] = []
    current: ast.expr = expr
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return ""
    parts.append(current.id)
    return ".".join(reversed(parts))


def _name_uses(expr: ast.expr) -> Set[str]:
    """Names an expression reads, excluding the callee identifiers of the calls inside it.

    `int(record_id)` reads one value, `record_id`; without this the sanitizer's own name
    would count as a second input and block an argument that is provably cleaned.
    """
    excluded = set()
    for node in ast.walk(expr):
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
            excluded.update(id(child) for child in ast.walk(node.func))
    return {
        node.id
        for node in ast.walk(expr)
        if isinstance(node, ast.Name) and id(node) not in excluded
    }


def _callee_tail(func: ast.AST) -> str:
    """Trailing identifier of a callee expression, '' when it is not a Name/Attribute."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _func_descriptor(func: ast.AST) -> Optional[str]:
    """Source spelling of a callee (`cursor.execute`), None when unparse is unavailable/fails."""
    if not hasattr(ast, "unparse"):
        return None
    try:
        return ast.unparse(func)
    except Exception:
        return None


def _is_signal_factory(value: ast.AST) -> bool:
    """True for `x = Signal()` / `x = django.dispatch.Signal()` (Django, Blinker)."""
    if not isinstance(value, ast.Call):
        return False
    callee = value.func
    if isinstance(callee, ast.Name):
        return callee.id in SIGNAL_FACTORY_METHODS
    return isinstance(callee, ast.Attribute) and callee.attr in SIGNAL_FACTORY_METHODS


def _decorator_label(decorator: ast.AST) -> Optional[str]:
    """Trailing dotted component of a decorator, whether bare, dotted, or called."""
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


# ─── PEP 695 tolerance: 3.12 type-parameter syntax on a 3.11 ast ────────────────
# `ast.parse(..., feature_version=(3, 11))` cannot help here: feature_version can only *restrict*
# the grammar, never enable newer syntax, and on a 3.11 interpreter (3, 11) is already the default.
# So a file the default parse rejects gets one retry on a rewritten source that removes exactly the
# three PEP 695 constructs (`type X[T] =`, `def f[T](`, `class C[T](`/`:`) by overwriting those
# characters with spaces. Newlines are never touched, so every line number - and therefore every
# finding line - stays identical to the original file. The retry tree is used only when the rewritten
# source parses; otherwise the file is skipped exactly as it was before.
def _matching_bracket(tokens: List[tokenize.TokenInfo], open_index: int) -> Optional[int]:
    depth = 0
    for index in range(open_index, len(tokens)):
        text = tokens[index].string
        if text == "[":
            depth += 1
        elif text == "]":
            depth -= 1
            if depth == 0:
                return index
    return None


def _rewrite_pep695(source: str) -> Optional[str]:
    """Blank PEP 695 type-parameter tokens, preserving every line and column offset."""
    try:
        tokens = [t for t in tokenize.generate_tokens(io.StringIO(source).readline)
                  if t.type not in (tokenize.NL, tokenize.COMMENT, tokenize.ENCODING)]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None

    starts = [0]
    for line in source.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))

    def offset(position) -> int:
        row, col = position
        return starts[row - 1] + col

    words = ("def", "class", "type")
    # (start, end, replacement): a `type` alias moves its name to the start of the span rather
    # than blanking the `type ` prefix -- blanking would leave the name indented by five
    # columns and the module-level statement would be an `unexpected indent`. Moving the name
    # keeps the line's total width, so every token after the span keeps its column.
    edits: List[tuple[int, int, str]] = []
    total = len(tokens)
    for index, token in enumerate(tokens):
        if token.type != tokenize.NAME or token.string not in words:
            continue
        previous = tokens[index - 1] if index else None
        at_statement_start = (
            previous is None
            or previous.type in (tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT)
            or previous.string == ";"
        )
        if token.string == "def" and previous is not None and previous.string == "async":
            before_async = tokens[index - 2] if index >= 2 else None
            at_statement_start = (
                before_async is None
                or before_async.type in (tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT)
                or before_async.string == ";"
            )
        if not at_statement_start or index + 2 >= total:
            continue
        name_token = tokens[index + 1]
        if name_token.type != tokenize.NAME:
            continue
        marker = tokens[index + 2]
        if marker.string == "[":
            close = _matching_bracket(tokens, index + 2)
            if close is None or close + 1 >= total:
                continue
            after = tokens[close + 1].string
            if token.string == "type":
                if after != "=":
                    continue
                edits.append((offset(token.start), offset(name_token.end),
                              name_token.string))
                edits.append((offset(marker.start), offset(tokens[close].end), ""))
            elif token.string == "def":
                if after != "(":
                    continue
                edits.append((offset(marker.start), offset(tokens[close].end), ""))
            else:
                if after not in ("(", ":"):
                    continue
                edits.append((offset(marker.start), offset(tokens[close].end), ""))
        elif token.string == "type" and marker.string == "=":
            edits.append((offset(token.start), offset(name_token.end), name_token.string))

    if not edits:
        return None
    characters = list(source)
    for start, end, text in edits:
        position = start
        for character in text:
            while position < end and characters[position] in ("\n", "\r"):
                position += 1
            if position >= end:
                break
            characters[position] = character
            position += 1
        while position < end:
            if characters[position] not in ("\n", "\r"):
                characters[position] = " "
            position += 1
    return "".join(characters)


def _parse_source(path: str, source: str) -> Optional[ast.AST]:
    """Parse `source`, retrying once on a PEP 695-rewritten spelling; None when both fail."""
    try:
        return ast.parse(source, filename=path)
    except Exception:
        pass
    rewritten = _rewrite_pep695(source)
    if rewritten is None:
        return None
    try:
        return ast.parse(rewritten, filename=path)
    except Exception:
        return None


# ─── Compact symbol facts: the cross-file symbol table ─────────────────────────
# Nothing below retains an AST. The engine keeps, per module, only what the six cross-module
# passes ask of a tree: who a call names, how its receiver is spelled, which arguments are bare
# names (the only shape the parameter-forwarding lift can follow), the decorator shapes, the
# class bases, and the call spelling on the right-hand side of assignments (the only shape the
# sanitizer replay can start from). Source stays on disk; a module is re-parsed only when the
# caller analysis or the sanitizer audit actually has to run its AST.
_SITE_FUNC_OTHER = 0   # callee is neither a Name nor an Attribute
_SITE_FUNC_NAME = 1    # foo(...)
_SITE_FUNC_ATTR = 2    # <receiver>.foo(...)

_SITE_RECV_OTHER = 0   # receiver is neither a Name, a Name-call, nor an attribute chain
_SITE_RECV_NAME = 1    # receiver is a bare Name
_SITE_RECV_CTOR = 2    # receiver is ClassName(...) with a bare constructor
_SITE_RECV_ATTR = 3    # receiver is an attribute chain


class CallShape(NamedTuple):
    """Everything about a call that resolution reads, minus its line number.

    Shapes are pooled per run, so a repeated spelling (`self.db.execute(query)`) is one object
    shared by every site that writes it.
    """
    fkind: int
    fname: str
    rkind: int
    rname: str
    rprefix: str
    rprefix_bare: bool
    argn: tuple          # positional argument spellings: interned Name id or None
    kwn: tuple           # ((keyword, interned Name id or None), ...)


class DecoFacts(NamedTuple):
    """One decorator: its label, whether it is a call, and the shape of its first argument."""
    label: Optional[str]
    is_call: bool
    bare: Optional[str]   # resolvable name for a non-call decorator, None otherwise
    arg0kind: int         # 0 = Name, 1 = Attribute, 2 = other or absent
    arg0name: str
    arg0prefix: str
    arg0bare: bool


class WrapperShape(NamedTuple):
    """The provable decorator shape `_wrapper_sanitized_slots` accepts, precomputed at harvest."""
    ok: bool
    wparams: tuple        # wrapper positional parameter names
    flen: int             # forwarded argument count
    fargs: tuple          # per forwarded argument: (used names, is_call, callee tail)


class FuncFacts:
    """Facts for one contracted function: its contract, calls, receivers and decorators."""
    __slots__ = ("qual", "summary", "recv", "calls", "decos", "wrapper")

    def __init__(self, qual, summary, recv, calls, decos, wrapper):
        self.qual = qual
        self.summary = summary
        self.recv = recv
        self.calls = calls
        self.decos = decos
        self.wrapper = wrapper


class ModuleFacts:
    """The symbol-table row for one module; holds no AST and no source text."""
    __slots__ = ("funcs", "bases", "signals", "sink_lines", "assign_callees")

    def __init__(self, funcs, bases, signals, sink_lines, assign_callees):
        self.funcs = funcs
        self.bases = bases
        self.signals = signals
        self.sink_lines = sink_lines
        self.assign_callees = assign_callees


def _call_shape(call: ast.Call, pool: Dict[CallShape, CallShape]) -> CallShape:
    func = call.func
    if isinstance(func, ast.Name):
        fkind, fname = _SITE_FUNC_NAME, func.id
        rkind, rname, rprefix, rprefix_bare = _SITE_RECV_OTHER, "", "", False
    elif isinstance(func, ast.Attribute):
        fkind, fname = _SITE_FUNC_ATTR, func.attr
        value = func.value
        if isinstance(value, ast.Name):
            rkind, rname, rprefix, rprefix_bare = _SITE_RECV_NAME, value.id, "", False
        elif isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            rkind, rname, rprefix, rprefix_bare = _SITE_RECV_CTOR, value.func.id, "", False
        elif isinstance(value, ast.Attribute):
            rkind = _SITE_RECV_ATTR
            rname = value.attr
            rprefix = _dotted_prefix(value.value)
            rprefix_bare = isinstance(value.value, ast.Name)
        else:
            rkind, rname, rprefix, rprefix_bare = _SITE_RECV_OTHER, "", "", False
    else:
        fkind, fname = _SITE_FUNC_OTHER, ""
        rkind, rname, rprefix, rprefix_bare = _SITE_RECV_OTHER, "", "", False

    shape = CallShape(
        fkind, sys.intern(fname), rkind, sys.intern(rname), sys.intern(rprefix),
        rprefix_bare,
        tuple(sys.intern(a.id) if isinstance(a, ast.Name) else None for a in call.args),
        tuple((sys.intern(k.arg), sys.intern(k.value.id)
               if isinstance(k.value, ast.Name) else None)
              for k in call.keywords if k.arg),
    )
    pooled = pool.get(shape)
    if pooled is None:
        pool[shape] = shape
        return shape
    return pooled


def _deco_facts(decorator: ast.AST) -> DecoFacts:
    is_call = isinstance(decorator, ast.Call)
    label = _decorator_label(decorator)
    bare = label if not is_call else None
    kind, name, prefix, bare_inner = 2, "", "", False
    if is_call and decorator.args:
        argument = decorator.args[0]
        if isinstance(argument, ast.Name):
            kind, name = 0, argument.id
        elif isinstance(argument, ast.Attribute):
            kind, name = 1, argument.attr
            prefix = _dotted_prefix(argument.value)
            bare_inner = isinstance(argument.value, ast.Name)
    return DecoFacts(label, is_call, bare, kind, sys.intern(name), sys.intern(prefix), bare_inner)


def _wrapper_shape(node: ast.FunctionDef | ast.AsyncFunctionDef) -> Optional[WrapperShape]:
    """Precompute the decorator-wrapper result `_wrapper_sanitized_slots` used to walk for."""
    wrapper = None
    for stmt in node.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            wrapper = stmt
            break
    if wrapper is None:
        return None
    if wrapper.args.vararg or wrapper.args.kwarg or wrapper.args.kwonlyargs:
        return WrapperShape(False, (), 0, ())
    wrapper_params = tuple(sys.intern(a.arg) for a in wrapper.args.args)
    wrapped_names = {a.arg for a in node.args.args}
    forwarded = None
    for inner in ast.walk(wrapper):
        if (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name)
                and inner.func.id in wrapped_names):
            forwarded = inner
            break
    if forwarded is None or forwarded.keywords:
        return WrapperShape(False, (), 0, ())
    fargs = tuple(
        (tuple(sorted(sys.intern(name) for name in _name_uses(argument))),
         isinstance(argument, ast.Call),
         sys.intern(_callee_tail(argument.func)) if isinstance(argument, ast.Call) else "")
        for argument in forwarded.args
    )
    return WrapperShape(True, wrapper_params, len(forwarded.args), fargs)


def _harvest_module(mod_name: str, tree: ast.AST,
                    summaries: List[FunctionSummary],
                    pool: Dict[CallShape, CallShape]) -> ModuleFacts:
    """One walk of a freshly parsed module -> its symbol-table row; the tree is dropped after."""
    by_qual = {summary.qualname: summary for summary in summaries}
    sink_lines = {edge.lineno for summary in summaries for edge in summary.param_sinks}

    funcs: Dict[str, FuncFacts] = {}
    for node, qual in _contracted_functions(tree):
        summary = by_qual.get(qual)
        if summary is None:
            continue
        calls = [
            (getattr(call, "lineno", 0), _call_shape(call, pool))
            for call in ast.walk(node) if isinstance(call, ast.Call)
        ]
        recv = []
        for inner in _ordered_nodes(node, skip_scopes=True):
            if (isinstance(inner, ast.Assign) and isinstance(inner.value, ast.Call)
                    and isinstance(inner.value.func, ast.Name)):
                targets = tuple(sys.intern(t.id) for t in inner.targets
                                if isinstance(t, ast.Name))
                if targets:
                    recv.append((targets, sys.intern(inner.value.func.id)))
        funcs[qual] = FuncFacts(
            qual, summary, tuple(recv), tuple(calls),
            tuple(_deco_facts(d) for d in node.decorator_list),
            _wrapper_shape(node),
        )

    bases: Dict[str, tuple] = {}
    signals: List[str] = []
    assign_callees: Set[str] = set()
    sink_desc: Dict[int, list] = {}
    for inner in ast.walk(tree):
        if isinstance(inner, ast.Assign) and isinstance(inner.value, ast.Call):
            tail = _callee_tail(inner.value.func)
            if tail:
                assign_callees.add(tail)
        if isinstance(inner, ast.Call):
            lineno = getattr(inner, "lineno", 0)
            if lineno in sink_lines:
                descriptor = _func_descriptor(inner.func)
                if descriptor is not None:
                    entry = sink_desc.get(lineno)
                    if entry is None:
                        sink_desc[lineno] = [descriptor, {}]
                    else:
                        tail = _callee_tail(inner.func)
                        if tail and tail not in entry[1]:
                            entry[1][tail] = descriptor
    for stmt in tree.body:
        if isinstance(stmt, ast.ClassDef):
            named = []
            for base in stmt.bases:
                if isinstance(base, ast.Name):
                    named.append((True, sys.intern(base.id)))
                elif isinstance(base, ast.Attribute):
                    named.append((True, sys.intern(base.attr)))
                else:
                    named.append((False, ""))
            bases[stmt.name] = tuple(named)
        elif isinstance(stmt, ast.Assign) and _is_signal_factory(stmt.value):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    signals.append(target.id)

    return ModuleFacts(
        funcs,
        bases,
        tuple(signals),
        {lineno: (entry[0], dict(entry[1])) for lineno, entry in sink_desc.items()},
        frozenset(assign_callees),
    )


@dataclass(slots=True)
class TraceHop:
    """One labelled node in an exploit path: role is SOURCE, ROUTE or SINK."""
    role: str
    file_path: str
    lineno: int
    label: str


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
    flow_trace: List[TraceHop] = field(default_factory=list)


class CrossFileTaintEngine:
    """Pass 2: Traces data flow across modules using precomputed contracts.

    The engine no longer keeps the parsed trees: `GlobalSymbolIndex` is built in streaming mode
    (each module is indexed, summarised and harvested, then its tree is released), and every
    cross-module decision runs on the compact `ModuleFacts` table. Only two phases re-read source:
    the caller analysis, for the small set of modules whose facts show a call into a sink-bearing
    contract, and the sanitizer audit, for the modules whose assignments can reach a sanitizer.
    """

    def __init__(self, root_dir: str | Path,
                 reuse_trees: Optional[dict] = None):
        self.root_dir = Path(root_dir).resolve()
        # Scanner-parsed (source, tree) snapshots keyed by resolved absolute path string;
        # the indexer re-verifies each against disk before reuse (see GlobalSymbolIndex.build).
        self.reuse_trees = reuse_trees
        self.indexer = GlobalSymbolIndex(self.root_dir)
        self.summarizer: Optional[FunctionSummarizer] = None
        self.contracts: dict[tuple[str, str], FunctionSummary] = {}
        # Per-module compact symbol table: signatures, call sites, receivers, decorators, bases.
        self.module_facts: dict[str, ModuleFacts] = {}
        self.findings: list[CrossFileFinding] = []
        # ParamSinkEdge carries no file field, so transitively lifted edges record the
        # module that actually owns the sink here: (mod, qualname, param_idx, sink, lineno) -> path.
        self.sink_origins: dict[tuple[str, str, int, str, int], str] = {}
        # Forwarding call sites between the caller and the ultimate sink, outermost first:
        # (mod, qualname, param_idx, sink, lineno) -> [(file, lineno, callee label), ...].
        self.sink_route: dict[tuple[str, str, int, str, int], List[tuple[str, int, str]]] = {}
        # Cached per-callee decorator analysis: (mod, qualname) -> sanitised parameter indices.
        self._decorator_slots: dict[tuple[str, str], Set[int]] = {}
        # Event-bus catalog: (defining module, symbol) pairs for signals, their subscribers,
        # and Celery-style task functions reachable only through a dispatch method.
        self.signal_definitions: Set[tuple[str, str]] = set()
        self.signal_subscribers: dict[tuple[str, str], List[tuple[str, str]]] = {}
        self.task_definitions: Set[tuple[str, str]] = set()
        # Observational only (Phase-1 instrumentation): rounds actually executed by the
        # fixed-point loop below; never read by a decision.
        self._propagation_rounds = 0
        # Raw file path spelling -> owning module (None when the file is outside the indexed
        # tree). `file_to_module` is filled by indexer.build() and never mutated again, so one
        # path string always answers the same module; `Path.resolve()` is an OS call that would
        # otherwise repeat per call site. Negative hits are cached for the same reason.
        self._path_to_module_memo: dict[str, Optional[str]] = {}
        # Call-shape pool: identical call spellings share one CallShape object.
        self._shape_pool: Dict[CallShape, CallShape] = {}
        # Observational counters for the PROFILE line.
        self._summary_seconds = 0.0
        self._caller_modules = 0
        self._sanitizer_modules = 0
        self._sanitizer_sites_cache: Optional[frozenset] = None
        self._sanitizer_tails: Optional[frozenset] = None
        self._sanitizer_aliases: dict[str, frozenset] = {}

    def run(self) -> list[CrossFileFinding]:
        # Phase-1 instrumentation: disjoint stage clocks over the existing sequence.
        # Nothing here changes an algorithm, an iteration order, or a finding.
        _t0 = time.perf_counter()
        # 1. Build Index & Contracts. The indexer streams: it registers every module first (so
        # symbol resolution already sees the whole project), then parses one file at a time,
        # hands the tree to the callback below, and releases it before reading the next.
        self.summarizer = FunctionSummarizer(self.indexer)
        self.indexer.build(reuse_trees=self.reuse_trees, on_indexed=self._on_module_indexed)
        self.contracts = self.summarizer.summaries
        _t1 = time.perf_counter()
        self._propagate_transitive_sink_contracts()
        _t2 = time.perf_counter()
        self._build_event_catalog()
        _t3 = time.perf_counter()

        # 2. Analyze Callers. Only modules whose facts contain a call into a sink-bearing
        # contract (or a dispatch into a sink-bearing handler) can emit a finding, so only they
        # are re-read and run through the unchanged AST analysis.
        for mod_name, facts in self.module_facts.items():
            if not self._module_emits(mod_name, facts):
                continue
            mod_idx = self.indexer.modules.get(mod_name)
            if mod_idx is None:
                continue
            tree = self._tree_for(mod_name)
            if tree is None:
                continue
            self._analyze_module_calls(mod_name, mod_idx.file_path, tree)
            self._caller_modules += 1
            del tree
        _t4 = time.perf_counter()

        from symbol_indexer import resolver_stats_line
        print(f"TimeCodeSecurity [PROFILE] CrossEngine: IndexBuild={_t1 - _t0:.2f}s "
              f"Summaries={self._summary_seconds:.2f}s Propagate={_t2 - _t1:.2f}s "
              f"(rounds={self._propagation_rounds}) EventCatalog={_t3 - _t2:.2f}s "
              f"CallerAnalysis={_t4 - _t3:.2f}s (modules={self._caller_modules}) "
              f"TOTAL={_t4 - _t0:.2f}s "
              f"modules={len(self.indexer.modules)} contracts={len(self.contracts)} "
              f"facts={len(self.module_facts)} findings={len(self.findings)} "
              f"| {resolver_stats_line()}",
              file=sys.stderr)
        return self.findings

    def _on_module_indexed(self, mod_name: str, file_path: Path, tree: ast.AST) -> None:
        """Streaming hook: summarise one module, harvest its facts, and let the tree go."""
        started = time.perf_counter()
        summaries = self.summarizer.summarize_module(mod_name, file_path, tree)
        self._summary_seconds += time.perf_counter() - started
        self.module_facts[mod_name] = _harvest_module(
            mod_name, tree, summaries, self._shape_pool)

    def _tree_for(self, mod_name: str) -> Optional[ast.AST]:
        """Re-read one module's tree on demand; the scanner's snapshot is reused when it matches."""
        path = self.indexer.module_to_file.get(mod_name)
        if path is None:
            return None
        path_str = str(path)
        try:
            source = Path(path_str).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None
        cached = self.reuse_trees.get(path_str) if self.reuse_trees else None
        if cached is not None and cached[1] is not None and cached[0] == source:
            return cached[1]
        return _parse_source(path_str, source)

    # ─── Framework event bus: Django signals and Celery tasks ───
    def _build_event_catalog(self) -> None:
        """Index signal objects, their @receiver handlers, and @shared_task / @app.task workers.

        A producer never names these functions, it only calls `.send(...)` or `.delay(...)` on a
        handle, so without this catalog the call graph has no edge into the handler and the sinks
        behind it stay invisible across modules.
        """
        for mod_name, facts in self.module_facts.items():
            for name in facts.signals:
                self.signal_definitions.add((mod_name, name))
            for qual, func in facts.funcs.items():
                for decorator in func.decos:
                    if decorator.label is None:
                        continue
                    if (decorator.label in SIGNAL_SUBSCRIBE_DECORATORS
                            and decorator.is_call and decorator.arg0kind != 2):
                        signal_ref = self._resolve_reference_fact(
                            mod_name, decorator.arg0kind, decorator.arg0name,
                            decorator.arg0prefix, decorator.arg0bare)
                        if signal_ref is not None:
                            self.signal_definitions.add(signal_ref)
                            self.signal_subscribers.setdefault(signal_ref, []).append(
                                (mod_name, qual))
                    elif decorator.label in TASK_DECORATOR_NAMES:
                        self.task_definitions.add((mod_name, qual))

    def _resolve_name_reference(self, mod_name: str, name: str) -> tuple[str, str]:
        """(defining module, symbol) a bare reference spelling points at."""
        mod_idx = self.indexer.modules.get(mod_name)
        binding = mod_idx.imports.get(name) if mod_idx else None
        if binding is not None:
            target_mod = self.indexer._match_registered_module(binding.source_module)
            if target_mod:
                return (target_mod, binding.imported_name or name)
        return (mod_name, name)

    def _resolve_attr_reference(self, base: str, attr: str) -> tuple[str, str]:
        """(defining module, symbol) a dotted reference spelling points at."""
        return (self.indexer._match_registered_module(base) or base, attr)

    def _resolve_reference_fact(
        self,
        mod_name: str,
        kind: int,
        name: str,
        prefix: str,
        prefix_bare: bool,
    ) -> Optional[tuple[str, str]]:
        """Fact spelling of `_resolve_reference` for a name/attribute expression."""
        if kind == 0:
            return self._resolve_name_reference(mod_name, name)
        if kind == 1:
            if prefix_bare and prefix in ("self", "cls"):
                return None
            if not prefix:
                return None
            return self._resolve_attr_reference(prefix, name)
        return None

    def _resolve_reference(self, mod_name: str, expr: ast.AST) -> Optional[tuple[str, str]]:
        """(defining module, symbol) a receiver or decorator argument points at."""
        if isinstance(expr, ast.Name):
            return self._resolve_name_reference(mod_name, expr.id)
        if isinstance(expr, ast.Attribute):
            if isinstance(expr.value, ast.Name) and expr.value.id in ("self", "cls"):
                return None
            base = _dotted_prefix(expr.value)
            if not base:
                return None
            return self._resolve_attr_reference(base, expr.attr)
        return None

    def _resolve_event_emission(
        self,
        caller_mod: str,
        call: ast.Call,
    ) -> List[tuple[str, FunctionSummary, ast.Call]]:
        """Callee contracts hidden behind `signal.send(...)`, `signal.send_robust(...)` and
        `task.delay(...)` / `task.apply_async(...)`, resolved through the event catalog.

        Each entry also carries the call view to bind the contract against, because Celery's
        `apply_async` hands the payload over in `args=` / `kwargs=` envelopes instead of in
        its own signature.
        """
        if not isinstance(call.func, ast.Attribute):
            return []
        attr = call.func.attr
        if attr in SIGNAL_EMISSION_METHODS:
            ref = self._resolve_reference(caller_mod, call.func.value)
            targets = self.signal_subscribers.get(ref, []) if ref else []
        elif attr in TASK_DISPATCH_METHODS:
            ref = self._resolve_reference(caller_mod, call.func.value)
            targets = [ref] if ref and ref in self.task_definitions else []
        else:
            return []
        dispatch_call = self._dispatch_call(attr, call)
        resolved = []
        for target in targets:
            summary = self.contracts.get(target)
            if summary is not None:
                resolved.append((target[0], summary, dispatch_call))
        return resolved

    @staticmethod
    def _dispatch_call(attr: str, call: ast.Call) -> ast.Call:
        """Flatten `task.apply_async(args=[...], kwargs={...})` into the call it dispatches."""
        if attr != "apply_async":
            return call
        args: List[ast.expr] = []
        keywords: List[ast.keyword] = []
        for kw in call.keywords:
            if kw.arg == "args" and isinstance(kw.value, (ast.List, ast.Tuple)):
                args.extend(kw.value.elts)
            elif kw.arg == "kwargs" and isinstance(kw.value, ast.Dict):
                for key, value in zip(kw.value.keys, kw.value.values):
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        keywords.append(ast.keyword(arg=key.value, value=value))
        if not args and not keywords:
            return call
        dispatch = ast.Call(func=call.func, args=args, keywords=keywords)
        for field_name in ("lineno", "end_lineno", "col_offset", "end_col_offset"):
            setattr(dispatch, field_name, getattr(call, field_name, None))
        return dispatch

    def _propagate_transitive_sink_contracts(self) -> None:
        """Fixed-point lift of callee sink contracts into pass-through callers.

        A function that forwards one of its own parameters straight into a callee argument
        inherits that callee's sink obligations, so a 3-layer chain (controller -> service
        -> repo) becomes visible from the outermost call site. Only direct parameter
        forwarding propagates, which keeps the lift alias-free and terminating.
        """
        while True:
            self._propagation_rounds += 1
            changed = False
            for mod_name, facts in self.module_facts.items():
                for qual, func in facts.funcs.items():
                    summary = func.summary
                    if not summary.params:
                        continue
                    if self._lift_callee_sinks(mod_name, summary, func):
                        changed = True
            if not changed:
                return

    def _lift_callee_sinks(
        self,
        caller_mod: str,
        summary: FunctionSummary,
        func: FuncFacts,
    ) -> bool:
        param_index = {name: idx for idx, name in enumerate(summary.params)}
        known = {
            (edge.param_idx, edge.sink_cwe, edge.sink_name, edge.lineno)
            for edge in summary.param_sinks
        }
        added = False
        receivers = self._fact_receivers(caller_mod, summary.qualname, func)

        for call_lineno, call in func.calls:
            resolved = self._resolve_site_contract(caller_mod, call, receivers)
            if resolved is None:
                continue
            callee_mod, callee_summary = resolved
            if not callee_summary.param_sinks:
                continue
            # A slot the callee's decorator sanitises carries no sink obligation, so it must
            # not lift either; otherwise the same leak would reappear one layer further out.
            neutralized = self._decorator_sanitized_params(callee_mod, callee_summary)

            for arg_idx, arg_name in sorted(
                self._bind_site_args(
                    call,
                    callee_summary.params,
                    self._receiver_offset_site(caller_mod, call, callee_summary, receivers),
                ).items()
            ):
                if arg_idx in neutralized:
                    continue
                # Only a bare name forwards a parameter; the AST walk this replaces tested
                # isinstance(arg, ast.Name) for exactly the same reason.
                if arg_name is None:
                    continue
                caller_param_idx = param_index.get(arg_name)
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
                    lifted_key = (caller_mod, summary.qualname, caller_param_idx,
                                  edge.sink_name, edge.lineno)
                    self.sink_origins[lifted_key] = self.sink_origins.get(
                        origin_key, callee_summary.file_path
                    )
                    self.sink_route[lifted_key] = [
                        (summary.file_path, call_lineno,
                         f"{caller_mod}.{summary.qualname}")
                    ] + self.sink_route.get(origin_key, [])
                    added = True

        return added

    def _fact_receivers(
        self,
        caller_mod: str,
        caller_func: str,
        func: FuncFacts,
    ) -> Dict[str, tuple[str, str]]:
        """`_instance_bindings` over harvested facts: own-scope `var = ClassName(...)` bindings."""
        bindings: Dict[str, tuple[str, str]] = {}
        if "." in caller_func:
            owning_class = (caller_func.split(".", 1)[0], caller_mod)
            bindings["self"] = owning_class
            bindings["cls"] = owning_class
        for targets, ctor in func.recv:
            class_ref = self._class_of_name(ctor, caller_mod)
            if class_ref is None:
                continue
            for target in targets:
                bindings[target] = class_ref
        return bindings

    def _resolve_site_contract(
        self,
        caller_mod: str,
        site: CallShape,
        receivers: Optional[Dict[str, tuple[str, str]]] = None,
    ) -> Optional[tuple[str, FunctionSummary]]:
        """Fact spelling of `_resolve_call_contract` for one harvested call site."""
        if site.fkind == _SITE_FUNC_NAME:
            call_name = site.fname
        elif site.fkind == _SITE_FUNC_ATTR:
            resolved_method = self._resolve_site_method(site, caller_mod, receivers)
            if resolved_method is not None:
                return resolved_method
            resolved_module = self._resolve_site_module_attribute(site, caller_mod)
            if resolved_module is not None:
                return resolved_module
            call_name = site.fname
        else:
            return None

        symbol_def = self.indexer.resolve_symbol(caller_mod, call_name)
        if not symbol_def:
            return None

        callee_mod = self._resolve_file_module(symbol_def.file_path)
        if not callee_mod:
            return None

        summary = self.contracts.get((callee_mod, symbol_def.name))
        if summary is None:
            return None
        return callee_mod, summary

    def _resolve_site_method(
        self,
        site: CallShape,
        caller_mod: str,
        receivers: Optional[Dict[str, tuple[str, str]]],
    ) -> Optional[tuple[str, FunctionSummary]]:
        class_ref: Optional[tuple[str, str]] = None
        if site.rkind == _SITE_RECV_NAME:
            class_ref = ((receivers or {}).get(site.rname)
                         or self._class_of_name(site.rname, caller_mod))
        elif site.rkind == _SITE_RECV_CTOR:
            class_ref = self._class_of_name(site.rname, caller_mod)
        if class_ref is None:
            return None
        return self._resolve_inherited_method(class_ref, site.fname)

    def _resolve_site_module_attribute(
        self,
        site: CallShape,
        caller_mod: str,
    ) -> Optional[tuple[str, FunctionSummary]]:
        if site.rkind != _SITE_RECV_NAME:
            return None
        target_mod = self._imported_module_of(site.rname, caller_mod)
        if target_mod is None:
            return None
        summary = self.contracts.get((target_mod, site.fname))
        return None if summary is None else (target_mod, summary)

    def _bind_site_args(
        self,
        site: CallShape,
        param_names: List[str],
        arg_offset: int = 0,
    ) -> Dict[int, Optional[str]]:
        """`_bind_call_args` over facts: parameter index -> bare argument name (None otherwise)."""
        bound: Dict[int, Optional[str]] = {}
        for idx, name in enumerate(site.argn):
            param_idx = idx - arg_offset
            if 0 <= param_idx < len(param_names):
                bound[param_idx] = name
        param_to_idx = {name: idx for idx, name in enumerate(param_names)}
        for keyword, name in site.kwn:
            if keyword in param_to_idx:
                bound[param_to_idx[keyword]] = name
            else:
                slot = self._kwarg_slot_index(param_names, keyword)
                if slot is not None:
                    bound[slot] = name
        return bound

    def _receiver_offset_site(
        self,
        caller_mod: str,
        site: CallShape,
        summary: FunctionSummary,
        receivers: Optional[Dict[str, tuple[str, str]]] = None,
    ) -> int:
        """`_receiver_offset` over facts: 1 for an unbound `Class.method(receiver, ...)` call."""
        if not summary.takes_receiver or site.fkind != _SITE_FUNC_ATTR:
            return 0
        if site.rkind != _SITE_RECV_NAME:
            return 0
        if receivers and site.rname in receivers:
            return 0
        class_ref = self._class_of_name(site.rname, caller_mod)
        if class_ref is None:
            return 0
        resolved = self._resolve_inherited_method(class_ref, site.fname)
        return 1 if resolved is not None and resolved[1] is summary else 0

    def _module_emits(self, mod_name: str, facts: ModuleFacts) -> bool:
        """Could any call in this module reach a sink-bearing contract?

        Deliberately an over-approximation: every shape that can emit a finding resolves to a
        contract with a `param_sinks` edge, so answering no here proves the AST analysis has
        nothing to add. Answering yes only costs one re-parse.
        """
        for qual, func in facts.funcs.items():
            receivers = self._fact_receivers(mod_name, qual, func)
            for _lineno, site in func.calls:
                resolved = self._resolve_site_contract(mod_name, site, receivers)
                if resolved is not None and resolved[1].param_sinks:
                    return True
                if site.fkind != _SITE_FUNC_ATTR or site.fname not in _DISPATCH_ATTRS:
                    continue
                ref = self._resolve_reference_fact(
                    mod_name, site.rkind, site.rname, site.rprefix, site.rprefix_bare)
                if ref is None:
                    continue
                if site.fname in SIGNAL_EMISSION_METHODS:
                    targets = self.signal_subscribers.get(ref, ())
                else:
                    targets = (ref,) if ref in self.task_definitions else ()
                for target in targets:
                    summary = self.contracts.get(target)
                    if summary is not None and summary.param_sinks:
                        return True
        return False

    def sanitized_sink_locations(self) -> Set[tuple[str, int]]:
        """Call sites whose locally-assigned arguments were all neutralized by a
        cross-file sanitizer contract.

        Single-file scanners cannot see the callee contract, so they report these sites
        as injectable. The returned keys are (resolved file path, call lineno).
        """
        _t_s0 = time.perf_counter()
        try:
            if self._sanitizer_sites_cache is not None:
                return set(self._sanitizer_sites_cache)
            suppressed: Set[tuple[str, int]] = set()
            if not any(summary.is_sanitizer for summary in self.contracts.values()):
                print(f"TimeCodeSecurity [PROFILE] CrossSanitizers: scan={time.perf_counter() - _t_s0:.2f}s "
                      f"(no sanitizer contracts; 0 trees walked) sites=0", file=sys.stderr)
                return suppressed

            # A site needs an assignment whose right-hand side resolves to a sanitizer, so a
            # module whose assignment spellings share no name with any sanitizer contract
            # cannot contribute one. The spelling test is a superset of every resolution path
            # (direct name, import alias, module attribute, method tail), which is what keeps
            # this selection from ever skipping a module that could suppress a finding.
            selected = [
                mod_name for mod_name, facts in self.module_facts.items()
                if facts.assign_callees and self._may_hold_sanitizer_site(mod_name, facts)
            ]
            for mod_name in selected:
                mod_idx = self.indexer.modules.get(mod_name)
                if mod_idx is None:
                    continue
                tree = self._tree_for(mod_name)
                if tree is None:
                    continue
                file_key = str(Path(mod_idx.file_path).resolve())
                qualnames = {id(node): name for node, name in _contracted_functions(tree)}
                for node in _function_defs(tree):
                    suppressed.update(
                        self._sanitized_sites(
                            mod_name, file_key, node, qualnames.get(id(node), node.name)
                        )
                    )
                self._sanitizer_modules += 1
                del tree
            self._sanitizer_sites_cache = frozenset(suppressed)
            print(f"TimeCodeSecurity [PROFILE] CrossSanitizers: "
                  f"scan={time.perf_counter() - _t_s0:.2f}s "
                  f"(trees_walked={self._sanitizer_modules}/{len(self.indexer.modules)}) "
                  f"sites={len(suppressed)}", file=sys.stderr)
            return suppressed
        finally:
            # This pass is the last consumer of the path memo: run() returns before the caller
            # (cli.py) asks for sanitizer sites, so the cache is released here instead of at the
            # end of run() - releasing it earlier would make this phase re-issue every OS path
            # lookup it has just been handed the answer to.
            self._path_to_module_memo.clear()

    def _sanitizer_tail_set(self) -> frozenset:
        if self._sanitizer_tails is None:
            self._sanitizer_tails = frozenset(
                qual.rsplit(".", 1)[-1]
                for (_mod, qual), summary in self.contracts.items()
                if summary.is_sanitizer
            )
        return self._sanitizer_tails

    def _module_sanitizer_aliases(self, mod_name: str) -> frozenset:
        cached = self._sanitizer_aliases.get(mod_name)
        if cached is not None:
            return cached
        found = set()
        mod_idx = self.indexer.modules.get(mod_name)
        if mod_idx is not None:
            for local_name, binding in mod_idx.imports.items():
                target_mod = self.indexer._match_registered_module(binding.source_module)
                if not target_mod:
                    continue
                imported = binding.imported_name or local_name
                summary = self.contracts.get((target_mod, imported))
                if summary is not None and summary.is_sanitizer:
                    found.add(local_name)
        result = frozenset(found)
        self._sanitizer_aliases[mod_name] = result
        return result

    def _may_hold_sanitizer_site(self, mod_name: str, facts: ModuleFacts) -> bool:
        spellings = self._sanitizer_tail_set() | self._module_sanitizer_aliases(mod_name)
        return bool(facts.assign_callees & spellings)

    def _sanitized_sites(
        self,
        mod_name: str,
        file_key: str,
        func_node: ast.AST,
        caller_func: str,
    ) -> Set[tuple[str, int]]:
        sites: Set[tuple[str, int]] = set()
        if not _has_assign_statement(func_node):
            # `assigned` is only ever filled by an ast.Assign below, and a site needs a non-empty
            # `relevant` drawn from it, so a body without one has nothing to contribute. The
            # receiver map is skipped with it: the Assign branch is its only reader here.
            return sites
        assigned: Set[str] = set()
        sanitized: Set[str] = set()
        # One walk of the body for both loops instead of the two the same nodes used to pay.
        own_assigns, productive = _record_productive(func_node)
        receivers = self._instance_bindings(mod_name, caller_func, func_node, own_assigns=own_assigns)

        for node in productive:
            if isinstance(node, ast.Assign):
                summary = self._resolve_call_summary(mod_name, node.value, receivers)
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

        receivers = self._instance_bindings(caller_mod, caller_func_name, func_node)
        for stmt in func_node.body:
            if isinstance(stmt, ast.Assign):
                rhs_repr = ast.unparse(stmt.value) if hasattr(ast, "unparse") else ""
                is_source = any(src in rhs_repr for src in TAINT_SOURCE_PATTERNS)

                # Contract-aware propagation: a resolved callee summary is authoritative
                # for whether its return value carries the taint of an argument.
                summary = self._resolve_call_summary(caller_mod, stmt.value, receivers)
                if summary is not None:
                    if summary.is_sanitizer:
                        is_derived = False
                    else:
                        is_derived = self._returns_tainted_arg(
                            stmt.value, summary.params, summary.tainted_returns, tainted_vars,
                            self._receiver_offset(caller_mod, stmt.value, summary, receivers),
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
                    receivers,
                )
                for callee_mod, summary, dispatch_call in self._resolve_event_emission(
                    caller_mod, call_node
                ):
                    self._emit_contract_findings(
                        caller_mod,
                        caller_file,
                        caller_func_name,
                        dispatch_call,
                        callee_mod,
                        summary,
                        tainted_vars,
                        receivers,
                    )

    def _bind_call_args(
        self,
        call: ast.Call,
        param_names: List[str],
        arg_offset: int = 0,
    ) -> Dict[int, ast.AST]:
        """Maps parameter index -> argument AST expression for both args and kwargs.

        ``param_names`` comes from FunctionSummary.params, which drops the implicit
        ``self``/``cls`` receiver, so binding a normal method call needs no offset.
        ``arg_offset`` skips the leading positional argument of an unbound call; binding
        against SymbolDefinition.params (which keeps ``self``) would shift every
        parameter position by one instead.
        """
        bound: Dict[int, ast.AST] = {}
        # Positional
        for idx, arg in enumerate(call.args):
            param_idx = idx - arg_offset
            if 0 <= param_idx < len(param_names):
                bound[param_idx] = arg
        # Keywords
        param_to_idx = {name: idx for idx, name in enumerate(param_names)}
        for kw in call.keywords:
            if kw.arg and kw.arg in param_to_idx:
                bound[param_to_idx[kw.arg]] = kw.value
            elif kw.arg:
                slot = self._kwarg_slot_index(param_names, kw.arg)
                if slot is not None:
                    bound[slot] = kw.value
        return bound

    @staticmethod
    def _kwarg_slot_index(param_names: List[str], keyword: str) -> Optional[int]:
        """Contract slot for an incoming keyword that only a `**kwargs` parameter can receive.

        The summariser names those slots `<container>[<key>]`, so a signal payload keyword
        `payload=` binds onto `kwargs[payload]` and nothing else.
        """
        suffix = f"[{keyword}]"
        for idx, name in enumerate(param_names):
            if name.endswith(suffix):
                return idx
        return None

    def _receiver_offset(
        self,
        caller_mod: str,
        call: ast.Call,
        summary: FunctionSummary,
        receivers: Optional[Dict[str, tuple[str, str]]] = None,
    ) -> int:
        """1 when the callee is a method invoked unbound as `Class.method(receiver, ...)`.

        Contract parameter indices exclude the bound receiver, so the leading positional
        argument of an unbound call is the instance and must be skipped.
        """
        if not summary.takes_receiver or not isinstance(call.func, ast.Attribute):
            return 0
        receiver = call.func.value
        if not isinstance(receiver, ast.Name):
            return 0
        # A name already bound to an instance marks a bound call site; only a spelling that
        # resolves to a class symbol can hand the receiver over as an explicit first argument.
        if receivers and receiver.id in receivers:
            return 0
        class_ref = self._class_of_name(receiver.id, caller_mod)
        if class_ref is None:
            return 0
        # The contract may be declared on a base class, so comparing the receiver spelling with
        # the declaring class name loses every inherited unbound call. Re-resolving the
        # attribute on the receiver class and requiring the very same contract object proves
        # the call goes through that class, whether the method is owned or inherited.
        resolved = self._resolve_inherited_method(class_ref, call.func.attr)
        return 1 if resolved is not None and resolved[1] is summary else 0

    def _resolve_file_module(self, file_path) -> Optional[str]:
        """Owning module for a file path spelling, resolving the OS path at most once each.

        `file_to_module` is keyed by Path objects and is written only by indexer.build(), so
        the answer for a given spelling never changes during a run. The key is normalised with
        str() because callers hold either a str or a Path for the same file; misses (None) are
        cached too, since unindexed third-party paths are the common case.
        """
        key = str(file_path)
        memo = self._path_to_module_memo
        if key in memo:
            return memo[key]
        mod_name = self.indexer.file_to_module.get(Path(key).resolve())
        memo[key] = mod_name
        return mod_name

    def _resolve_call_contract(
        self,
        caller_mod: str,
        value: ast.expr,
        receivers: Optional[Dict[str, tuple[str, str]]] = None,
    ) -> Optional[tuple[str, FunctionSummary]]:
        """Return (callee module, contract) for a direct call expression, or None."""
        if not isinstance(value, ast.Call):
            return None

        if isinstance(value.func, ast.Name):
            call_name = value.func.id
        elif isinstance(value.func, ast.Attribute):
            resolved_method = self._resolve_method_contract(value.func, caller_mod, receivers)
            if resolved_method is not None:
                return resolved_method
            resolved_module = self._resolve_module_attribute_contract(value.func, caller_mod)
            if resolved_module is not None:
                return resolved_module
            call_name = value.func.attr
        else:
            return None

        symbol_def = self.indexer.resolve_symbol(caller_mod, call_name)
        if not symbol_def:
            return None

        callee_mod = self._resolve_file_module(symbol_def.file_path)
        if not callee_mod:
            return None

        summary = self.contracts.get((callee_mod, symbol_def.name))
        if summary is None:
            return None
        return callee_mod, summary

    def _resolve_method_contract(
        self,
        func: ast.Attribute,
        caller_mod: str,
        receivers: Optional[Dict[str, tuple[str, str]]],
    ) -> Optional[tuple[str, FunctionSummary]]:
        """Resolve `receiver.method(...)` against the owning class's contract.

        FunctionSummarizer indexes methods under the qualified name 'Class.method', which a
        call site never spells out, so the receiver's class must be recovered from the local
        bindings, an inline construction, or the named class itself (unbound call). Returns
        None when the receiver type is unknown, letting the caller fall back to bare names.
        """
        class_ref: Optional[tuple[str, str]] = None
        if isinstance(func.value, ast.Name):
            class_ref = (receivers or {}).get(func.value.id) or self._class_of_name(func.value.id, caller_mod)
        elif isinstance(func.value, ast.Call):
            class_ref = self._instantiated_class(func.value, caller_mod)
        if class_ref is None:
            return None

        class_name, class_mod = class_ref
        return self._resolve_inherited_method((class_name, class_mod), func.attr)

    def _resolve_inherited_method(
        self,
        class_ref: tuple[str, str],
        attr: str,
    ) -> Optional[tuple[str, FunctionSummary]]:
        """Find `attr`'s contract on the class or, failing that, on its base classes.

        Contracts are keyed by the declaring class, so a call through a subclass instance
        never spells out the qualified name the base was indexed under. The search is
        breadth-first from the concrete class, which makes an override on the subclass win
        over an unsafe inherited fallback, and a visited set bounds the walk on cyclic or
        repeated inheritance.
        """
        pending = [class_ref]
        seen: Set[tuple[str, str]] = set()
        while pending:
            name, mod = pending.pop(0)
            if (name, mod) in seen:
                continue
            seen.add((name, mod))

            summary = self.contracts.get((mod, f"{name}.{attr}"))
            if summary is not None:
                return mod, summary

            for parent in self._base_classes(name, mod):
                if parent not in seen:
                    pending.append(parent)
        return None

    def _base_classes(self, class_name: str, class_mod: str) -> List[tuple[str, str]]:
        """Resolve the base classes of `class_name` to (class, module) pairs, in source order."""
        facts = self.module_facts.get(class_mod)
        if facts is None:
            return []
        bases = facts.bases.get(class_name)
        if bases is None:
            return []

        parents: List[tuple[str, str]] = []
        for named, spelling in bases:
            # Only a bare or dotted name identifies an inheritable class; call and subscript
            # bases (Generic[T], metaclass kwargs) carry no statically named class.
            parent = self._class_of_name(spelling, class_mod) if named else None
            if parent is not None:
                parents.append(parent)
        return parents

    def _resolve_module_attribute_contract(
        self,
        func: ast.Attribute,
        caller_mod: str,
    ) -> Optional[tuple[str, FunctionSummary]]:
        """Resolve `alias.func(...)` where the alias names an imported module.

        `import service as db_svc` binds a namespace rather than a symbol, so the function
        behind `db_svc.execute_query` is invisible to symbol resolution, which only knows
        explicitly imported names. Recovering the module from the import table and looking the
        attribute up in its contracts keeps the aliased call as precise as the direct one.
        """
        if not isinstance(func.value, ast.Name):
            return None
        target_mod = self._imported_module_of(func.value.id, caller_mod)
        if target_mod is None:
            return None
        summary = self.contracts.get((target_mod, func.attr))
        return None if summary is None else (target_mod, summary)

    def _imported_module_of(self, name: str, caller_mod: str) -> Optional[str]:
        """Module a bare Name refers to when it was bound by `import x[.y] [as name]`."""
        mod_idx = self.indexer.modules.get(caller_mod)
        if mod_idx is None:
            return None
        binding = mod_idx.imports.get(name)
        if binding is None or binding.imported_name:
            return None
        return self.indexer._match_registered_module(binding.source_module)

    def _decorator_sanitized_params(self, callee_mod: str, summary: FunctionSummary) -> Set[int]:
        """Parameter indices that a validating decorator neutralises before the body runs.

        ``@validated def view(record_id)`` whose wrapper calls ``func(int(record_id))`` can
        never observe a raw value in that slot, so a tainted argument there is not injectable
        and the call site must not be reported. Only one shape is trusted, because it is the
        only one that is provable: the decorator declares a nested wrapper, that wrapper takes
        the decorated function's parameters positionally without ``*args``/``**kwargs``, and
        its call to the wrapped function passes, per position, either the parameter untouched
        or a known sanitizer applied to exactly that parameter. A passthrough decorator
        therefore stays transparent, which is what keeps a timed or logged sink reportable.
        """
        key = (callee_mod, summary.qualname)
        cached = self._decorator_slots.get(key)
        if cached is not None:
            return cached

        sanitized: Set[int] = set()
        facts = self.module_facts.get(callee_mod)
        func = facts.funcs.get(summary.qualname) if facts is not None else None
        if func is not None and summary.params:
            for decorator in func.decos:
                if decorator.bare is None:
                    continue
                symbol_def = self.indexer.resolve_symbol(callee_mod, decorator.bare)
                if symbol_def is None or symbol_def.kind not in ("function", "async_function"):
                    continue
                decorator_mod = self._resolve_file_module(symbol_def.file_path)
                if decorator_mod is None:
                    continue
                definition_facts = self.module_facts.get(decorator_mod)
                definition = (definition_facts.funcs.get(symbol_def.name)
                              if definition_facts is not None else None)
                if definition is None or definition.wrapper is None:
                    continue
                sanitized |= self._wrapper_slots(definition.wrapper, summary.params)
        self._decorator_slots[key] = sanitized
        return sanitized

    @staticmethod
    def _wrapper_slots(shape: WrapperShape, decorated_params: List[str]) -> Set[int]:
        """Slots the decorator's wrapper rebuilds through a sanitizer before calling through."""
        if not shape.ok:
            return set()
        if len(shape.wparams) != len(decorated_params):
            return set()
        if shape.flen != len(decorated_params):
            return set()
        slots: Set[int] = set()
        for index, (used, is_call, tail) in enumerate(shape.fargs):
            if set(used) - {shape.wparams[index]}:
                continue
            if is_call and tail in KNOWN_SANITIZERS:
                slots.add(index)
        return slots

    def _class_of_name(self, name: str, caller_mod: str) -> Optional[tuple[str, str]]:
        """(class name, defining module) when `name` resolves to an indexed class."""
        symbol_def = self.indexer.resolve_symbol(caller_mod, name)
        if symbol_def is None or symbol_def.kind != "class":
            return None
        class_mod = self._resolve_file_module(symbol_def.file_path)
        if class_mod is None:
            return None
        return symbol_def.name, class_mod

    def _instantiated_class(
        self,
        call: ast.Call,
        caller_mod: str,
    ) -> Optional[tuple[str, str]]:
        """Class of a freshly built object: `ClassName(...).method()`."""
        ctor = call.func
        if not isinstance(ctor, ast.Name):
            return None
        return self._class_of_name(ctor.id, caller_mod)

    def _instance_bindings(
        self,
        caller_mod: str,
        caller_func: str,
        func_node: ast.AST,
        own_assigns: Optional[list] = None,
    ) -> Dict[str, tuple[str, str]]:
        """Map receiver identifiers to (class name, defining module) inside one function.

        Collects `var = ClassName(...)` bindings in source order (a later rebinding wins) and,
        for methods, the implicit `self`/`cls` receiver derived from the qualified caller name.
        `own_assigns` is the already-recorded own-scope assignment list from _record_productive,
        which is the same sequence in the same order the walk below would have produced; passing
        it saves that walk. The map is still completed before the caller uses it, which is the
        whole reason the sanitizer scan records first and replays second.
        """
        bindings: Dict[str, tuple[str, str]] = {}
        if "." in caller_func:
            owning_class = (caller_func.split(".", 1)[0], caller_mod)
            bindings["self"] = owning_class
            bindings["cls"] = owning_class

        nodes = own_assigns if own_assigns is not None else _ordered_nodes(
            func_node, skip_scopes=True)
        for node in nodes:
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                continue
            ctor = node.value.func
            if not isinstance(ctor, ast.Name):
                continue
            class_ref = self._class_of_name(ctor.id, caller_mod)
            if class_ref is None:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = class_ref

        return bindings

    def _resolve_call_summary(
        self,
        caller_mod: str,
        value: ast.expr,
        receivers: Optional[Dict[str, tuple[str, str]]] = None,
    ) -> Optional[FunctionSummary]:
        """Return the contract for a direct call expression, or None if unresolved."""
        resolved = self._resolve_call_contract(caller_mod, value, receivers)
        return resolved[1] if resolved else None

    def _returns_tainted_arg(
        self,
        value: ast.Call,
        param_names: List[str],
        tainted_returns: Set[int],
        tainted_vars: Set[str],
        arg_offset: int = 0,
    ) -> bool:
        """True when an argument in a taint-propagating parameter position is tainted."""
        bound = self._bind_call_args(value, param_names, arg_offset)
        for param_idx in sorted(tainted_returns):
            arg = bound.get(param_idx)
            if arg is None:
                continue
            arg_names = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
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
        receivers: Dict[str, tuple[str, str]],
    ) -> None:
        # Resolve callee symbol and contract (module-level call or class instance method)
        resolved = self._resolve_call_contract(caller_mod, call, receivers)
        if not resolved:
            return
        callee_mod, summary = resolved
        self._emit_contract_findings(caller_mod, caller_file, caller_func_name, call,
                                     callee_mod, summary, tainted_vars, receivers)

    def _emit_contract_findings(
        self,
        caller_mod: str,
        caller_file: str,
        caller_func_name: str,
        call: ast.Call,
        callee_mod: str,
        summary: FunctionSummary,
        tainted_vars: set[str],
        receivers: Dict[str, tuple[str, str]],
    ) -> None:
        """Report every sink the callee reaches from an argument the caller passed tainted.

        Shared by direct calls and by event dispatch (`signal.send(...)` / `task.delay(...)`), so
        a handler reached through the bus gets the same binding rules and trace shape.
        """
        # Check if caller passed tainted arguments into callee's sink parameters
        neutralized = self._decorator_sanitized_params(callee_mod, summary)
        for arg_idx, arg in sorted(
            self._bind_call_args(call, summary.params, self._receiver_offset(caller_mod, call, summary, receivers)).items()
        ):
            if arg_idx in neutralized:
                continue
            arg_repr = ast.unparse(arg) if hasattr(ast, "unparse") else ""
            is_tainted_arg = any(t in arg_repr for t in tainted_vars) or any(src in arg_repr for src in TAINT_SOURCE_PATTERNS)

            if is_tainted_arg:
                # Check target sinks
                for sink in summary.param_sinks:
                    if sink.param_idx != arg_idx:
                        continue

                    trace_key = (callee_mod, summary.qualname, sink.param_idx,
                                 sink.sink_name, sink.lineno)
                    sink_file = self.sink_origins.get(trace_key, summary.file_path)
                    call_line = getattr(call, "lineno", 0)
                    flow_trace = [
                        TraceHop("SOURCE", caller_file, call_line,
                                 f"{caller_mod}.{caller_func_name}")
                    ]
                    flow_trace.extend(
                        TraceHop("ROUTE", route_file, route_line, route_func)
                        for route_file, route_line, route_func
                        in self.sink_route.get(trace_key, [])
                    )
                    flow_trace.append(
                        TraceHop("SINK", sink_file, sink.lineno,
                                 self._sink_descriptor(sink_file, sink.lineno, sink.sink_name))
                    )

                    self.findings.append(
                        CrossFileFinding(
                            cwe=sink.sink_cwe,
                            caller_file=caller_file,
                            caller_lineno=call_line,
                            caller_func=f"{caller_mod}.{caller_func_name}",
                            callee_file=sink_file,
                            callee_func=f"{callee_mod}.{summary.qualname}",
                            callee_sink_name=sink.sink_name,
                            callee_sink_lineno=sink.lineno,
                            tainted_param=sink.param_name,
                            flow_trace=flow_trace,
                        )
                    )

    def _sink_descriptor(self, file_path: str, lineno: int, fallback: str) -> str:
        """Recover how the sink was written (e.g. 'cursor.execute') from its source line."""
        mod_name = self._resolve_file_module(file_path)
        facts = self.module_facts.get(mod_name) if mod_name else None
        entry = facts.sink_lines.get(lineno) if facts is not None else None
        if entry is None:
            return fallback
        first, by_tail = entry
        return by_tail.get(fallback, first)


if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[*] Starting TimeCodeSecurity Cross-File Taint Engine on: {target_dir}")
    t0 = time.perf_counter()

    engine = CrossFileTaintEngine(target_dir)
    findings = engine.run()
    elapsed = (time.perf_counter() - t0) * 1000

    print("\n=================================================================")
    print("        TIMECODESECURITY - CROSS-FILE ANALYSIS REPORT       ")
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
