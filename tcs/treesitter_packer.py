"""Phase 1 of the resilient parser: a Tree-sitter CST -> CPython `ast` translator, standalone.

Nothing in the engine imports this module yet. `ast_scanner.py` does not know it exists, so the
current scanner's behaviour, findings and speed are untouched by construction.

Why Tree-sitter: its grammar parses *incomplete and future* Python (PEP 695 generics, PEP 701
nested f-strings, a half-typed function) and recovers with `ERROR` nodes instead of raising, so a
file no longer vanishes because of one line. This module turns that concrete syntax tree back into
ordinary `ast.AST` nodes, which means every existing consumer - `ast.walk`, `ast.NodeVisitor`, the
scanner's own collectors - can read it with no changes.

Three properties, in order of importance:

1. **Never panics.** `parse_to_ast` returns a valid, traversable `ast.Module` for *any* input,
   including garbage bytes, and is wrapped so that no exception can escape it. An unmodellable
   statement becomes `ast.Pass` at its own coordinates; an unmodellable expression becomes a
   `ast.Constant(None)` placeholder (or, if it has translatable children, those children are
   re-hosted in an `ast.Tuple` so their calls and attributes stay reachable to `ast.walk`).
2. **Exact coordinates.** Every node gets `lineno` / `col_offset` / `end_lineno` / `end_col_offset`
   from the CST span (Tree-sitter counts lines from 0, `ast` from 1), so a finding reported on a
   recovered file points at the same line it would have pointed at in a natively parsed file.
3. **Bounded memory.** The `Tree` is created inside one call and is a local of that call only - it
   is never stored on the module, in a cache, or on a class, so its CST is freed as soon as the
   conversion returns (the 0.26 Python binding has no `Tree.destroy()`; refcount release is the
   mechanism, and `destroy()` is called first when a newer binding does expose it). Only the grammar
   and one `Parser` are cached, and the parser is guarded by a lock because its internal scratch
   buffer is not reentrant.

Scope of the node set: module, function/class definitions (sync, async, decorated, PEP 695
generics), assignments (plain, chained, annotated, augmented), expression statements, return,
import/from, if/elif/else, for/while (+ else), try/except/else/finally, with, break/continue/pass/
raise/global/nonlocal/assert/delete, PEP 695 `type X = ...`; and expressions: calls (positional,
keyword, `*args`, `**kw`, generator-argument), attribute chains, subscripts and slices, names with
correct Load/Store/Del context, literals, implicit-concatenated strings, f-strings as `JoinedStr`
with the interpolated expressions preserved as real nodes, list/dict/set, comprehensions (list, set,
dict, generator), lambda, walrus, await, yield/yield from, starred, conditional, and
binary/unary/boolean/comparison operators. Anything still outside that set is degraded to a
placeholder, never to an exception.
"""
from __future__ import annotations

import ast
import threading
from typing import Any, List, Optional, Sequence, Tuple

__all__ = ["parse_to_ast", "tree_sitter_available", "SYNTAX_PLACEHOLDER_PREFIX"]

# Markers used when a fragment could not be modelled. They are strings in the AST only to make the
# degradation visible in a dump; the node types themselves are plain `ast` nodes.
SYNTAX_PLACEHOLDER_PREFIX = "<unsupported:"

_LANG: Any = None
_PARSER: Any = None
_PARSER_LOCK = threading.Lock()
_LOAD = ast.Load
_STORE = ast.Store
_DEL = ast.Del


class _Unavailable(Exception):
    """Tree-sitter is not installed / the grammar did not load."""


def _points(node) -> Tuple[int, int, int, int]:
    """(lineno, col_offset, end_lineno, end_col_offset) of a CST node.

    Tree-sitter names these `start_point`/`end_point` in some releases and `start_position`/
    `end_position` in others; both are tried so the module keeps working across versions.
    """
    for start_attr, end_attr in (("start_point", "end_point"),
                                 ("start_position", "end_position")):
        getter = getattr(node, start_attr, None)
        if getter is not None:
            start, end = tuple(getter), tuple(getattr(node, end_attr))
            return start[0] + 1, start[1], end[0] + 1, end[1]
    return 1, 0, 1, 0


def _text(node) -> str:
    raw = getattr(node, "text", None) or b""
    try:
        return raw.decode("utf-8", "replace")
    except Exception:
        return ""


def tree_sitter_available() -> bool:
    """True when the grammar loads. Callers that need certainty check this, not the parser."""
    try:
        _parser()
        return True
    except Exception:
        return False


def _parser():
    """One cached Parser over one cached Language; never holds a tree."""
    global _LANG, _PARSER
    if _PARSER is not None:
        return _PARSER
    try:
        import tree_sitter_python
        from tree_sitter import Language, Parser
    except Exception as exc:                      # ImportError, or a broken wheel
        raise _Unavailable(f"tree-sitter unavailable: {exc}") from exc
    language = getattr(tree_sitter_python, "language", None)
    if language is None:
        raise _Unavailable("tree_sitter_python.language is missing")
    cap = language()
    _LANG = cap if isinstance(cap, Language) else Language(cap)
    try:
        _PARSER = Parser(_LANG)
    except TypeError:
        p = Parser()
        p.set_language(_LANG)
        _PARSER = p
    return _PARSER


def _pos(node, out: ast.AST) -> ast.AST:
    """Stamp CST coordinates onto an `ast` node. Called for every node that has a span."""
    if node is None or out is None:
        return out
    lineno, col, end_lineno, end_col = _points(node)
    out.lineno = lineno
    out.col_offset = col
    out.end_lineno = end_lineno
    out.end_col_offset = end_col
    return out


def parse_to_ast(source_code, filename: str = "<unknown>") -> ast.Module:
    """Parse `source_code` into a traversable `ast.Module`. Never raises."""
    if isinstance(source_code, (bytes, bytearray)):
        data = bytes(source_code)
    elif isinstance(source_code, str):
        data = source_code.encode("utf-8", "surrogatepass")
    else:
        data = str(source_code).encode("utf-8", "replace")
    try:
        parser = None
        try:
            with _PARSER_LOCK:
                parser = _parser()
                tree = parser.parse(data)
                try:
                    module = _Translator(source=source_code, filename=filename).module(tree.root_node)
                finally:
                    # The CST is dropped here: only the converted `ast` survives this call, so no
                    # tree-sitter memory is retained once the function returns.
                    destroy = getattr(tree, "destroy", None)
                    if callable(destroy):
                        destroy()
                    del tree
        finally:
            parser = None
        module.filename = filename if isinstance(filename, str) else "<unknown>"
        return module
    except Exception:
        # Zero-panic contract: a caller must always get something `ast.walk` can traverse.
        fallback = ast.Module(body=[ast.Pass()], type_ignores=[])
        ast.fix_missing_locations(fallback)
        return fallback


class _Translator:
    """CST -> `ast`. Every method returns `ast` nodes or placeholders, never None, never raises."""

    def __init__(self, source, filename: str):
        self.source = source
        self.filename = filename

    # ─── module ───
    def module(self, root) -> ast.Module:
        body = self._statements(root)
        if not body:
            body = [ast.Pass()]
        module = ast.Module(body=body, type_ignores=[])
        _pos(root, module)
        ast.fix_missing_locations(module)
        return module

    def _block(self, node) -> List[ast.AST]:
        """A `block` node (or any node used as a suite) -> statement list, never empty."""
        if node is None:
            return [self._pass(None, 1, 0)]
        stmts = self._statements(node)
        return stmts or [self._pass(node)]

    def _statements(self, container) -> List[ast.AST]:
        out: List[ast.AST] = []
        for child in self._named(container):
            node = self._statement(child)
            if node is None:
                continue
            if isinstance(node, list):
                out.extend(node)
            else:
                out.append(node)
        return out

    def _named(self, node) -> List[Any]:
        try:
            return [c for c in node.named_children if c is not None and not c.is_missing
                    and c.type not in ("comment",)]
        except Exception:
            return []

    def _kids(self, node) -> List[Any]:
        try:
            return [c for c in node.children if c is not None and not c.is_missing]
        except Exception:
            return []

    def _pass(self, node, lineno: int = 1, col: int = 0) -> ast.Pass:
        out = ast.Pass()
        if node is None:
            out.lineno, out.col_offset = lineno, col
            out.end_lineno, out.end_col_offset = lineno, col + 4
        else:
            _pos(node, out)
        return out

    # ─── statements ───
    def _statement(self, node):
        handler = self._STMT.get(node.type)
        if handler is not None:
            try:
                made = handler(self, node)
            except Exception:
                # A handler that choked on a damaged node still must not cost the file its code:
                # salvage whatever statements are recognisable inside it.
                return self._error(node)
            self._absorb_errors(node, made)
            return made
        if node.type == "ERROR":
            return self._error(node)
        if node.is_missing:
            return None
        # Anything statement-shaped we do not model still has to keep its place in the block.
        return self._pass(node)

    def _absorb_errors(self, node, made) -> None:
        """Keep code that tree-sitter parked *beside* a recovered body.

        For `class C:\\n def m(): ...\\n bad(:` the grammar puts the damaged line in an ERROR node
        that is a sibling of the class body block, so the intact method would vanish with it. The
        statements inside that sibling are moved into the recovered statement's own body. Clean
        source has no ERROR nodes, so this never touches well-formed code or its ordering.
        """
        targets = [made] if isinstance(made, ast.AST) else list(made or [])
        bodies = []
        for target in targets:
            body = getattr(target, "body", None)
            if isinstance(body, list) and body and all(isinstance(stmt, ast.stmt) for stmt in body):
                bodies.append(body)
        if not bodies:
            return
        extra: List[ast.AST] = []
        for child in self._named(node):
            if child.type == "ERROR":
                extra.extend(self._salvage(child))
        if not extra:
            return
        for body in bodies:
            body.extend(extra)
            # Source order has to survive: the salvaged span usually precedes the body block.
            body.sort(key=lambda stmt: (getattr(stmt, "lineno", 0), getattr(stmt, "col_offset", 0)))

    def _salvage(self, node) -> List[ast.AST]:
        """Recover the recognisable statements inside a broken region; may legitimately be empty."""
        salvaged: List[ast.AST] = []
        for child in self._named(node):
            if child.type == "ERROR":
                salvaged.extend(self._salvage(child))
                continue
            handler = self._STMT.get(child.type)
            if handler is None or child.type in ("module", "block"):
                # A wrapper (block, argument list, ...) is not a statement of its own: look inside.
                salvaged.extend(self._salvage(child))
                continue
            try:
                # Route through `_statement`, not the bare handler, so a container recovered here
                # gets the same beside-body salvage as one recovered from a clean block.
                made = self._statement(child)
            except Exception:
                salvaged.extend(self._salvage(child))
                continue
            if made is None:
                continue
            salvaged.extend(made if isinstance(made, list) else [made])
        return salvaged

    def _error(self, node):
        # A fully lost region still has to leave a statement behind so the block stays valid.
        return self._salvage(node) or [self._pass(node)]

    def _stmt_module(self, root):
        return self._statements(root) or [self._pass(root)]

    def _expr_statement(self, node):
        inner = self._named(node)
        if not inner:
            return self._pass(node)
        child = inner[0]
        if child.type in ("assignment", "augmented_assignment"):
            return self._assignment(child)
        expr = self._expression(child, _LOAD)
        return _pos(node, ast.Expr(value=expr))

    def _assignment(self, node):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        annotation = node.child_by_field_name("type")
        operator = self._operator_token(node)
        if operator in _AUGOP and left is not None and right is not None:
            return _pos(node, ast.AugAssign(target=self._expression(left, _STORE),
                                            op=_AUGOP[operator](),
                                            value=self._expression(right, _LOAD)))
        if annotation is not None and left is not None:
            target = self._expression(left, _STORE)
            if isinstance(target, (ast.Name, ast.Attribute, ast.Subscript)):
                return _pos(node, ast.AnnAssign(
                    target=target, annotation=self._unwrap_type(annotation),
                    value=self._expression(right, _LOAD) if right is not None else None,
                    simple=1))
        if left is None or right is None:
            return self._pass(node)
        # `a = b = value` nests: tree-sitter puts the rest of the chain in `right`.
        targets = [self._target(left)]
        tail = right
        while tail is not None and tail.type == "assignment":
            nxt_left = tail.child_by_field_name("left")
            nxt_right = tail.child_by_field_name("right")
            if nxt_left is None or nxt_right is None:
                break
            targets.append(self._target(nxt_left))
            tail = nxt_right
        value = self._expression(tail, _LOAD) if tail is not None else _pos(node, ast.Constant(None))
        return _pos(node, ast.Assign(targets=targets, value=value))

    def _target(self, node):
        return self._expression(node, _STORE)

    def _function(self, node, decorators=None):
        name_node = node.child_by_field_name("name")
        params_node = node.child_by_field_name("parameters")
        body_node = node.child_by_field_name("body")
        returns = node.child_by_field_name("return_type")
        args = self._parameters(params_node)
        decorator_list = decorators or []
        body = self._block(body_node)
        name = _text(name_node).strip() or "_unnamed"
        returns_ast = self._unwrap_type(returns) if returns is not None else None
        is_async = any(c.type == "async" for c in self._kids(node))
        kind = ast.AsyncFunctionDef if is_async else ast.FunctionDef
        out = kind(name=name, args=args, body=body, decorator_list=decorator_list,
                   returns=returns_ast)
        if "type_params" in getattr(kind, "_attributes", ()):
            # PEP 695 type parameters are dropped (the grammar keeps them on the definition);
            # setting the field keeps the node constructible on 3.12+ consumers.
            out.type_params = []
        _pos(node, out)
        return out

    def _class(self, node, decorators=None):
        name_node = node.child_by_field_name("name")
        supers = node.child_by_field_name("superclasses")
        body_node = node.child_by_field_name("body")
        bases: List[ast.AST] = []
        keywords: List[ast.keyword] = []
        if supers is not None:
            for child in self._named(supers):
                if child.type == "keyword_argument":
                    keywords.append(self._keyword(child))
                    continue
                bases.append(self._expression(child, _LOAD))
        out = ast.ClassDef(name=_text(name_node).strip() or "_unnamed",
                           bases=bases, keywords=keywords,
                           body=self._block(body_node),
                           decorator_list=decorators or [])
        if "type_params" in getattr(ast.ClassDef, "_attributes", ()):
            out.type_params = []
        return _pos(node, out)

    def _decorated(self, node):
        decorators: List[ast.AST] = []
        inner = None
        for child in self._named(node):
            if child.type == "decorator":
                target = self._named(child)
                decorators.append(self._expression(target[-1], _LOAD) if target
                                 else _pos(child, ast.Constant(None)))
            elif child.type in self._STMT:
                inner = child
        if inner is None:
            return [self._pass(node)] + decorators
        made = self._STMT[inner.type](self, inner, decorators) if inner.type in (
            "function_definition", "class_definition") else self._statement(inner)
        return made if isinstance(made, list) else [made]

    def _return(self, node):
        value = self._named(node)
        return _pos(node, ast.Return(self._expression(value[0], _LOAD) if value else None))

    def _imported_names(self, node) -> List[ast.alias]:
        """Every named child in a name position: the module itself is not an imported alias."""
        names: List[ast.alias] = []
        for index, child in enumerate(self._kids(node)):
            if not child.is_named or child.is_missing:
                continue
            if self._field(node, index) == "module_name":
                continue
            names.append(self._alias(child))
        return names or [ast.alias(name="_", asname=None)]

    def _import(self, node):
        return _pos(node, ast.Import(names=self._imported_names(node)))

    def _future_import(self, node):
        return _pos(node, ast.ImportFrom(module="__future__",
                                        names=self._imported_names(node), level=0))

    def _import_from(self, node):
        module_node = node.child_by_field_name("module_name")
        names = self._imported_names(node)
        level, module = 0, None
        if module_node is not None:
            if module_node.type == "relative_import":
                prefix = module_node.child_by_field_name("import_prefix") or next(
                    (c for c in self._kids(module_node) if c.type == "import_prefix"), None)
                level = len(_text(prefix).strip()) if prefix is not None else 1
                dotted = next((c for c in self._named(module_node) if c.type == "dotted_name"), None)
                module = _text(dotted) if dotted is not None else None
            else:
                module = _text(module_node)
        return _pos(node, ast.ImportFrom(module=module, names=names, level=level))

    def _alias(self, child) -> ast.alias:
        if child.type == "aliased_import":
            real = child.child_by_field_name("name")
            alias = child.child_by_field_name("alias")
            name = _text(real).strip() or _text(child).split(" as ")[0].strip()
            return _pos(child, ast.alias(name=name, asname=_text(alias).strip() or None))
        if child.type == "wildcard_import":
            return _pos(child, ast.alias(name="*", asname=None))
        return _pos(child, ast.alias(name=_text(child).strip(), asname=None))

    def _if(self, node):
        condition = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        alternatives = [c for c in self._named(node)
                        if c.type in ("elif_clause", "else_clause")]
        out = ast.If(test=self._expression(condition, _LOAD) if condition is not None
                     else _pos(node, ast.Constant(None)),
                     body=self._block(consequence), orelse=[])
        tail = out
        for alt in alternatives:
            if alt.type == "elif_clause":
                nested = ast.If(
                    test=self._expression(alt.child_by_field_name("condition"), _LOAD),
                    body=self._block(alt.child_by_field_name("consequence")), orelse=[])
                _pos(alt, nested)
                tail.orelse = [nested]
                tail = nested
            else:
                tail.orelse = self._block(alt.child_by_field_name("body")
                                          or alt.child_by_field_name("consequence"))
        return _pos(node, out)

    def _for(self, node):
        # `async for` is a different node class in `ast`, not a flag on `ast.For`.
        kind = ast.AsyncFor if any(c.type == "async" for c in self._kids(node)) else ast.For
        return _pos(node, kind(
            target=self._expression(node.child_by_field_name("left"), _STORE),
            iter=self._expression(node.child_by_field_name("right"), _LOAD),
            body=self._block(node.child_by_field_name("body")),
            orelse=self._else_of(node)))

    def _while(self, node):
        return _pos(node, ast.While(test=self._expression(node.child_by_field_name("condition"), _LOAD),
                                    body=self._block(node.child_by_field_name("body")),
                                    orelse=self._else_of(node)))

    def _else_of(self, node) -> List[ast.AST]:
        alt = next((c for c in self._named(node) if c.type == "else_clause"), None)
        if alt is None:
            return []
        body = alt.child_by_field_name("body") or next(
            (c for c in self._named(alt) if c.type == "block"), None)
        return self._block(body)

    def _try(self, node):
        body = []
        handlers: List[ast.ExceptHandler] = []
        orelse: List[ast.AST] = []
        finalbody: List[ast.AST] = []
        star = False
        for child in self._named(node):
            if child.type == "block" and not body:
                body = self._block(child)
            elif child.type == "except_clause":
                handlers.append(self._except(child))
                # `except*` is a different node class (`ast.TryStar`), decided by that `*`.
                star = star or any(c.type == "*" for c in self._kids(child))
            elif child.type == "else_clause":
                orelse = self._else_of(child) or self._block(child.child_by_field_name("body"))
            elif child.type == "finally_clause":
                suite = child.child_by_field_name("body") or next(
                    (c for c in self._named(child) if c.type == "block"), None)
                finalbody = self._block(suite)
        kind = ast.TryStar if star and hasattr(ast, "TryStar") else ast.Try
        return _pos(node, kind(body=body or [self._pass(node)], handlers=handlers,
                               orelse=orelse, finalbody=finalbody))

    def _except(self, node) -> ast.ExceptHandler:
        value = node.child_by_field_name("value")
        exc = value
        alias = node.child_by_field_name("alias")
        if value is not None and value.type == "as_pattern":
            parts = self._named(value)
            exc = parts[0] if parts else None
            alias = value.child_by_field_name("alias")
        name = (_text(alias).strip() or None) if alias is not None else None
        block = next((c for c in self._named(node) if c.type == "block"), None)
        return _pos(node, ast.ExceptHandler(type=self._expression(exc, _LOAD) if exc is not None
                                            else None, name=name, body=self._block(block)))

    def _with(self, node):
        items: List[ast.withitem] = []
        for child in self._named(node):
            if child.type == "with_clause":
                for item in self._named(child):
                    items.append(self._with_item(item))
            elif child.type in ("with_item", "as_pattern"):
                items.append(self._with_item(child))
        if not items:
            items = [ast.withitem(context_expr=_pos(node, ast.Constant(None)),
                                  optional_vars=None)]
        # `async with` is its own class, not a flag on `ast.With`.
        kind = ast.AsyncWith if any(c.type == "async" for c in self._kids(node)) else ast.With
        return _pos(node, kind(items=items, body=self._block(node.child_by_field_name("body"))))

    def _with_item(self, node) -> ast.withitem:
        value = node.child_by_field_name("value") or (
            self._named(node)[0] if self._named(node) else None)
        if value is not None and value.type == "as_pattern":
            parts = self._named(value)
            context = parts[0] if parts else value
            alias = value.child_by_field_name("alias")
            return _pos(node, ast.withitem(context_expr=self._expression(context, _LOAD),
                                           optional_vars=self._expression(alias, _STORE)
                                           if alias is not None else None))
        return _pos(node, ast.withitem(
            context_expr=self._expression(value, _LOAD) if value is not None
            else _pos(node, ast.Constant(None)), optional_vars=None))

    def _break(self, node):
        return _pos(node, ast.Break())

    def _continue(self, node):
        return _pos(node, ast.Continue())

    def _pass_stmt(self, node):
        return self._pass(node)

    def _raise(self, node):
        cause_node = node.child_by_field_name("cause")
        parts = [c for c in self._named(node) if c is not cause_node]
        exc = self._expression(parts[0], _LOAD) if parts else None
        cause = self._expression(cause_node, _LOAD) if cause_node is not None else None
        return _pos(node, ast.Raise(exc=exc, cause=cause))

    def _global(self, node, nonlocal_=False):
        names = [_text(c).strip() for c in self._named(node) if c.type == "identifier"]
        kind = ast.Nonlocal if nonlocal_ else ast.Global
        return _pos(node, kind(names=names or ["_"]))

    def _assert(self, node):
        parts = self._named(node)
        test = self._expression(parts[0], _LOAD) if parts else _pos(node, ast.Constant(None))
        msg = self._expression(parts[1], _LOAD) if len(parts) > 1 else None
        return _pos(node, ast.Assert(test=test, msg=msg))

    def _delete(self, node):
        parts = self._named(node)
        if len(parts) == 1 and parts[0].type == "expression_list":
            parts = self._named(parts[0])
        targets = [self._expression(c, _DEL) for c in parts]
        if not targets:
            targets = [self._pass(node)]
        return _pos(node, ast.Delete(targets=targets))

    def _type_alias(self, node):
        # PEP 695 `type X = int`: modelled as `X = int` so downstream name tracking still sees it.
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None:
            return self._pass(node)
        target = self._expression(left, _STORE)
        while isinstance(target, ast.Subscript):
            # `type Alias[T] = ...`: the tracked name is `Alias`, the `[T]` is a type parameter.
            target = target.value
        if isinstance(target, (ast.Name, ast.Attribute)):
            target.ctx = _STORE()
        value = self._unwrap_type(right) if right is not None else _pos(node, ast.Constant(None))
        return _pos(node, ast.Assign(targets=[target], value=value))

    # ─── match (PEP 634) ───
    def _match(self, node):
        if not hasattr(ast, "Match"):
            return self._pass(node)
        subject = node.child_by_field_name("subject")
        cases: List[ast.AST] = []
        for child in self._named(node):
            if child.type == "case_clause":
                cases.append(self._case_clause(child))
            elif child.type == "block":
                for inner in self._named(child):
                    if inner.type == "case_clause":
                        cases.append(self._case_clause(inner))
        return _pos(node, ast.Match(subject=self._expression(subject, _LOAD), cases=cases))

    def _case_clause(self, node) -> ast.AST:
        pattern = None
        guard = None
        for child in self._named(node):
            if child.type == "case_pattern" and pattern is None:
                pattern = self._pattern(child)
            elif child.type == "if_clause":
                condition = child.child_by_field_name("condition") or self._param_name(child)
                guard = self._expression(condition, _LOAD)
        body = node.child_by_field_name("consequence") or node.child_by_field_name("body")
        return _pos(node, ast.match_case(pattern=pattern or ast.MatchAs(),
                                         guard=guard, body=self._block(body)))

    def _pattern(self, node) -> ast.AST:
        if node is None:
            return ast.MatchAs()
        handler = self._PATTERN.get(node.type)
        if handler is not None:
            try:
                return handler(self, node)
            except Exception:
                pass
        return ast.MatchAs()

    def _field(self, node, index):
        try:
            return node.field_name_for_child(index)
        except Exception:
            return None

    def _pattern_unwrap(self, node) -> ast.AST:
        """case_pattern / group_pattern are wrappers: translate what is inside them."""
        inner = self._named(node)
        return self._pattern(inner[0]) if inner else ast.MatchAs()

    def _pattern_value(self, node) -> ast.AST:
        # A one-word `dotted_name` in a pattern is a capture (`case direction`), and `_` is the
        # wildcard; only a real `a.b` chain is a value comparison.
        if node.type == "dotted_name":
            words = [c for c in self._kids(node) if c.type == "identifier"]
            if len(words) == 1:
                name = _text(words[0]).strip()
                return _pos(node, ast.MatchAs(name=None if name == "_" else name))
        return _pos(node, ast.MatchValue(value=self._expression(node, _LOAD)))

    def _pattern_sequence(self, node) -> ast.AST:
        return _pos(node, ast.MatchSequence(
            patterns=[self._pattern(c) for c in self._named(node)]))

    def _pattern_star(self, node) -> ast.AST:
        """`case [a, *rest]`: the star is a MatchStar inside MatchSequence.patterns."""
        inner = self._last_named(node)
        name = _text(inner if inner is not None else node).strip().lstrip("*").strip()
        return _pos(node, ast.MatchStar(name=name or None))

    def _pattern_or(self, node) -> ast.AST:
        return _pos(node, ast.MatchOr(
            patterns=[self._pattern(c) for c in self._named(node)]))

    def _pattern_as(self, node) -> ast.AST:
        parts = self._named(node)
        alias = node.child_by_field_name("alias")
        inner = parts[0] if parts else None
        if alias is None and len(parts) > 1:
            alias = parts[-1]
        name = _text(alias).strip() if alias is not None else ""
        return _pos(node, ast.MatchAs(pattern=self._pattern(inner), name=name or None))

    def _pattern_mapping(self, node) -> ast.AST:
        keys: List[ast.AST] = []
        patterns: List[ast.AST] = []
        rest = None
        pending: Optional[ast.AST] = None
        for index, child in enumerate(self._kids(node)):
            field = self._field(node, index)
            if field == "key":
                # MatchMapping keys are bare literals (`Constant`), not MatchValue wrappers.
                pending = self._expression(child, _LOAD)
            elif field == "value":
                keys.append(pending if pending is not None else _pos(child, ast.Constant(None)))
                patterns.append(self._pattern(child))
                pending = None
            elif child.type in ("splat_pattern", "double_starred_pattern"):
                inner = self._last_named(child)
                rest = (_text(inner if inner is not None else child).strip()
                        .lstrip("*").strip() or None)
        # The value slot of MatchMapping is named `patterns`, not `values`.
        return _pos(node, ast.MatchMapping(keys=keys, patterns=patterns, rest=rest))

    def _pattern_class(self, node) -> ast.AST:
        flat: List[Any] = []
        for child in self._named(node):
            if child.type == "case_pattern":
                inner = self._named(child)
                flat.append(inner[0] if inner else child)
            else:
                flat.append(child)
        patterns: List[ast.AST] = []
        kwd_attrs: List[str] = []
        kwd_patterns: List[ast.AST] = []
        for child in flat[1:]:
            if child.type != "keyword_pattern":
                patterns.append(self._pattern(child))
                continue
            key = (child.child_by_field_name("name") or child.child_by_field_name("key")
                   or self._param_name(child))
            value = (child.child_by_field_name("pattern") or child.child_by_field_name("value")
                     or self._last_named(child))
            kwd_attrs.append(_text(key).strip())
            kwd_patterns.append(self._pattern(value))
        cls = flat[0] if flat else None
        # MatchClass keyword arguments are two parallel lists (`kwd_attrs` / `kwd_patterns`).
        return _pos(node, ast.MatchClass(cls=self._expression(cls, _LOAD), patterns=patterns,
                                         kwd_attrs=kwd_attrs, kwd_patterns=kwd_patterns))

    def _pattern_capture(self, node) -> ast.AST:
        return _pos(node, ast.MatchAs(name=_text(node).strip() or None))

    def _pattern_wildcard(self, node) -> ast.AST:
        return _pos(node, ast.MatchAs())

    # ─── parameters ───
    def _parameters(self, node) -> ast.arguments:
        """`ast.arguments` with the buckets CPython uses.

        A parameter is positional-only only when the source actually writes `/`; the marker's
        position, not the parameter's, decides the bucket. Defaults are kept aligned to the tail of
        `posonlyargs + args` and keyword defaults to `kwonlyargs`, exactly as `ast.parse` does.
        """
        if node is None:
            return ast.arguments(posonlyargs=[], args=[], vararg=None, kwonlyargs=[],
                                 kw_defaults=[], kwarg=None, defaults=[])
        positional: List[Tuple[ast.arg, Optional[ast.AST]]] = []
        pos_only_count = 0
        kwonly: List[ast.arg] = []
        kw_defaults: List[Optional[ast.AST]] = []
        after_star = False
        vararg = None
        varkw = None
        for child in self._kids(node):
            kind = child.type
            if kind in ("(", ")", "comment"):
                continue
            if kind == "positional_separator":
                pos_only_count = len(positional)
                continue
            if kind == "keyword_separator":
                after_star = True
                continue
            if kind == "list_splat_pattern":
                target = child.child_by_field_name("argument") or self._last_named(child)
                if target is not None:
                    vararg = self._arg(target)
                after_star = True
                continue
            if kind == "dictionary_splat_pattern":
                target = child.child_by_field_name("pattern") or self._last_named(child)
                if target is not None:
                    varkw = self._arg(target)
                continue
            default = child.child_by_field_name("value")
            default_expr = self._expression(default, _LOAD) if default is not None else None
            if kind in ("typed_default_parameter", "default_parameter", "typed_parameter",
                        "identifier"):
                made = self._arg(child)
                if after_star:
                    kwonly.append(made)
                    kw_defaults.append(default_expr)
                else:
                    positional.append((made, default_expr))
                continue
            # Anything exotic (PEP 695 type parameters, patterns): keep it out of the signature
            # rather than crash on it.
        only_pos, rest = positional[:pos_only_count], positional[pos_only_count:]
        return ast.arguments(
            posonlyargs=[arg for arg, _ in only_pos],
            args=[arg for arg, _ in rest],
            vararg=vararg,
            kwonlyargs=kwonly,
            kw_defaults=kw_defaults,
            kwarg=varkw,
            defaults=[default for _, default in only_pos + rest if default is not None])

    def _last_named(self, node):
        named = self._named(node)
        return named[-1] if named else None

    def _param_name(self, node):
        """The identifier inside a parameter node, wherever the grammar put it."""
        for field in ("name", "pattern", "argument"):
            found = node.child_by_field_name(field)
            if found is not None:
                return found
        named = self._named(node)
        return named[0] if named else node

    def _arg(self, node) -> ast.arg:
        annotation = None
        name_node = node
        if node.type != "identifier":
            name_node = self._param_name(node)
            ann = node.child_by_field_name("type")
            annotation = self._unwrap_type(ann) if ann is not None else None
        name = _text(name_node).strip() or "_"
        out = ast.arg(arg=name, annotation=annotation)
        _pos(node, out)
        return out

    # ─── expressions ───
    def _unwrap_type(self, node):
        """tree-sitter wraps annotations in a `type` node; the value lives one level down."""
        if node is None:
            return None
        if node.type == "type":
            inner = self._named(node)
            if len(inner) == 1:
                return self._expression(inner[0], _LOAD)
            if not inner:
                return _pos(node, ast.Constant(None))
            return self._generic_expression(node, _LOAD)
        return self._expression(node, _LOAD)

    def _expression(self, node, ctx=_LOAD):
        if node is None:
            return _pos(None, ast.Constant(None))
        try:
            handler = self._EXPR.get(node.type)
            if handler is not None:
                return handler(self, node, ctx)
            if node.type == "ERROR":
                return self._placeholder(node)
            if node.type == "type":
                return self._unwrap_type(node) or self._placeholder(node)
            return self._generic_expression(node, ctx)
        except Exception:
            return self._placeholder(node)

    def _generic_expression(self, node, ctx):
        """Unknown construct: re-host whatever inside it we can translate."""
        kept: List[ast.AST] = []
        for child in self._named(node):
            if child.type in ("comment", "string_content", "string_start", "string_end"):
                continue
            kept.append(self._expression(child, ctx))
        if len(kept) == 1:
            # Keep the inner node's own coordinates: the wrapper span would shift `**kw` style
            # offsets away from where CPython reports the name.
            return kept[0]
        if kept:
            return _pos(node, ast.Tuple(elts=kept, ctx=_LOAD()))
        return self._placeholder(node)

    def _placeholder(self, node):
        out = ast.Constant(value=None)
        _pos(node, out)
        return out

    def _name(self, node, ctx):
        return _pos(node, ast.Name(id=_text(node).strip() or "_", ctx=ctx()))

    def _dotted(self, node, ctx=_LOAD):
        """`a.b.c` becomes the same Attribute chain CPython builds (only the outer node takes ctx)."""
        parts = [c for c in self._kids(node) if c.type == "identifier"]
        if not parts:
            names = [p for p in _text(node).strip().split(".") if p]
            if not names:
                return self._placeholder(node)
            out = _pos(node, ast.Name(id=names[0], ctx=_LOAD()))
            for name in names[1:]:
                out = ast.Attribute(value=out, attr=name, ctx=_LOAD())
            return _pos(node, out)
        out = _pos(parts[0], ast.Name(id=_text(parts[0]).strip(), ctx=_LOAD()))
        for child in parts[1:]:
            out = ast.Attribute(value=out, attr=_text(child).strip(), ctx=_LOAD())
        if isinstance(out, (ast.Name, ast.Attribute)):
            out.ctx = ctx()
        return _pos(node, out)

    def _attribute(self, node, ctx):
        value = node.child_by_field_name("object")
        attr = node.child_by_field_name("attribute")
        if value is None:
            parts = [c for c in self._kids(node) if c.type != "."]
            value, attr = (parts[0], parts[-1]) if len(parts) > 1 else (None, None)
        inner = self._expression(value, _LOAD) if value is not None else _pos(node, ast.Constant(None))
        out = ast.Attribute(value=inner, attr=(_text(attr).strip() or "_"), ctx=ctx())
        return _pos(node, out)

    def _subscript(self, node, ctx):
        value = node.child_by_field_name("value")
        sub = node.child_by_field_name("subscript")
        if sub is None:
            sub = next((c for c in self._named(node) if c.type != "slice"), None)
        slice_node = self._slice(sub) if sub is not None and sub.type == "slice" \
            else self._expression(sub, _LOAD)
        inner = self._expression(value, _LOAD) if value is not None else _pos(node, ast.Constant(None))
        return _pos(node, ast.Subscript(value=inner, slice=slice_node, ctx=ctx()))

    def _slice(self, node):
        slots: List[Optional[ast.AST]] = [None, None, None]
        slot = 0
        saw_colon = False
        for child in self._kids(node):
            if child.type == ":":
                saw_colon = True
                slot = min(slot + 1, 2)
            elif child.is_named and not child.is_missing:
                slots[slot] = self._expression(child, _LOAD)
        if not saw_colon:
            named = self._named(node)
            return self._expression(named[0], _LOAD) if named else self._placeholder(node)
        lower, upper, step = slots
        return _pos(node, ast.Slice(lower=lower, upper=upper, step=step))

    def _call(self, node, ctx):
        func = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        args: List[ast.AST] = []
        keywords: List[ast.keyword] = []
        # `sum(x for x in rows)`: the grammar makes the parentheses a generator_expression node,
        # and CPython models that single argument as a positional GeneratorExp.
        if arguments is not None and arguments.type == "generator_expression":
            args = [self._comprehension(arguments, _LOAD, ast.GeneratorExp)]
        for child in self._named(arguments) if (arguments is not None
                                                and arguments.type != "generator_expression") else []:
            if child.type == "keyword_argument":
                keywords.append(self._keyword(child))
            elif child.type in ("list_splat", "list_splat_pattern", "starred_expression"):
                args.append(_pos(child, ast.Starred(
                    value=self._expression(self._param_name(child), _LOAD), ctx=_LOAD())))
            elif child.type in ("dictionary_splat", "dictionary_splat_pattern"):
                keywords.append(_pos(child, ast.keyword(
                    arg=None, value=self._expression(self._param_name(child), _LOAD))))
            else:
                args.append(self._expression(child, _LOAD))
        callee = self._expression(func, _LOAD) if func is not None else _pos(node, ast.Name(
            id="_unnamed_call", ctx=_LOAD()))
        return _pos(node, ast.Call(func=callee, args=args, keywords=keywords))

    def _keyword(self, node) -> ast.keyword:
        key = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        return _pos(node, ast.keyword(arg=_text(key).strip() or None,
                                      value=self._expression(value, _LOAD)))

    def _operator_token(self, node):
        for child in self._kids(node):
            if not child.is_named and child.type not in ("(", ")", "[", "]", "{", "}", ","):
                return child.type
        return ""

    def _binary(self, node, ctx):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        op = self._operator_token(node)
        return _pos(node, ast.BinOp(left=self._expression(left, _LOAD),
                                    op=_BINOP.get(op, ast.Add)(),
                                    right=self._expression(right, _LOAD)))

    def _boolean(self, node, ctx):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        op = _BOOLOP.get(self._operator_token(node), ast.Or)()
        values = [self._expression(left, _LOAD), self._expression(right, _LOAD)]
        # CPython flattens `a or b or c` into one BoolOp; tree-sitter nests it, so re-flatten.
        first, last = values[0], values[-1]
        if isinstance(first, ast.BoolOp) and type(first.op) is type(op):
            values = list(first.values) + values[1:]
        elif isinstance(last, ast.BoolOp) and type(last.op) is type(op):
            values = values[:-1] + list(last.values)
        return _pos(node, ast.BoolOp(op=op, values=values))

    def _comparison(self, node, ctx):
        ops: List[ast.cmpop] = []
        parts: List[ast.AST] = []
        for child in self._kids(node):
            if child.is_named:
                parts.append(self._expression(child, _LOAD))
            elif child.type in _CMPOP:
                ops.append(_CMPOP[child.type]())
        if not parts:
            return self._placeholder(node)
        left = parts[0]
        comparators = parts[1:]
        if len(ops) != len(comparators):
            ops = (ops + [ast.NotEq() for _ in comparators])[:max(0, len(comparators))]
        return _pos(node, ast.Compare(left=left, ops=ops, comparators=comparators))

    def _unary(self, node, ctx):
        argument = node.child_by_field_name("argument")
        if argument is None:
            named = self._named(node)
            argument = named[-1] if named else None
        op_type = node.type
        if op_type == "not_operator":
            op = ast.Not()
        else:
            op = _UNOP.get(self._operator_token(node), ast.USub)()
        return _pos(node, ast.UnaryOp(op=op, operand=self._expression(argument, _LOAD)))

    def _constant(self, node, ctx):
        try:
            value = ast.literal_eval(_text(node).strip())
        except Exception:
            return self._placeholder(node)
        return _pos(node, ast.Constant(value=value))

    def _string(self, node, ctx):
        text = _text(node)
        if node.type == "concatenated_string":
            return self._concatenated(node, text)
        parts = self._named(node)
        if not any(c.type == "interpolation" for c in parts):
            try:
                return _pos(node, ast.Constant(value=ast.literal_eval(text)))
            except Exception:
                # An unterminated string still has to yield a node with the right span.
                return _pos(node, ast.Constant(value=text))
        values: List[ast.AST] = []
        for child in parts:
            if child.type == "interpolation":
                values.append(self._interpolation(child))
            elif child.type == "string_content" and _text(child):
                values.append(_pos(child, ast.Constant(value=_text(child))))
        return _pos(node, ast.JoinedStr(values=values or [_pos(node, ast.Constant(value=text))]))

    def _concatenated(self, node, text):
        """`"a" f"b{x}" 'c'`: CPython merges adjacent literals, so the values are merged too."""
        values: List[ast.AST] = []
        constants: List[ast.AST] = []
        for child in self._named(node):
            made = self._expression(child, _LOAD)
            if isinstance(made, ast.JoinedStr):
                values.extend(made.values)
            else:
                values.append(made)
            if isinstance(made, ast.Constant):
                constants.append(made)
        if constants and len(constants) == len(values):
            if all(isinstance(c.value, (bytes, bytearray)) for c in constants):
                return _pos(node, ast.Constant(value=b"".join(bytes(c.value) for c in constants)))
            if all(isinstance(c.value, str) for c in constants):
                return _pos(node, ast.Constant(value="".join(c.value for c in constants)))
        return _pos(node, ast.JoinedStr(values=values or [_pos(node, ast.Constant(value=text))]))

    def _interpolation(self, node) -> ast.FormattedValue:
        # Node objects are re-created per access, so identity cannot mark "the expression child";
        # the field name at the child index can.
        expr_index = -1
        kids = self._kids(node)
        for index, child in enumerate(kids):
            if self._field(node, index) == "expression":
                expr_index = index
                break
        expr = kids[expr_index] if expr_index >= 0 else self._first_named(node)
        conversion = -1
        format_spec = None
        for index, child in enumerate(kids):
            if index == expr_index or child.type in ("{", "}", "!", ":"):
                continue
            text = _text(child).strip()
            if text.startswith("!") and len(text) == 2:
                conversion = ord(text[1])
            elif text.startswith(":"):
                format_spec = self._format_spec(child, text)
        return _pos(node, ast.FormattedValue(value=self._expression(expr, _LOAD),
                                             conversion=conversion, format_spec=format_spec))

    def _format_spec(self, node, raw: str) -> ast.AST:
        """CPython models every format spec as a JoinedStr: nested fields (`{x:{w}}`) become real
        FormattedValues and the spec text around them becomes literals. tree-sitter reports only the
        fields as children, so each literal run is the gap between field spans inside the spec text.
        Reading the gaps in order is what keeps `:>{pad}` a Constant-then-FormattedValue, the way
        CPython builds it, instead of lumping all the spec text in front."""
        text = raw if isinstance(raw, str) else ""
        # The grammar's spec node spans the leading `:`; CPython's `format_spec` does not include it.
        lead = 1 if text.startswith(":") else 0
        body = text[lead:]
        base = self._byte_base(node)
        values: List[ast.AST] = []
        cursor = 0
        for child in self._named(node):
            if child.type not in ("format_expression", "interpolation"):
                continue
            start, end = self._spec_span(node, child, base, len(text))
            piece = body[cursor:max(0, start - lead)]
            if piece:
                values.append(_pos(node, ast.Constant(value=piece)))
            values.append(self._interpolation(child))
            cursor = max(cursor, end - lead)
        tail = body[cursor:]
        if tail:
            values.append(_pos(node, ast.Constant(value=tail)))
        if not values:
            values = [_pos(node, ast.Constant(value=body))]
        return _pos(node, ast.JoinedStr(values=values))

    @staticmethod
    def _byte_base(node):
        try:
            return node.start_byte
        except Exception:
            return None

    @staticmethod
    def _spec_span(node, child, base, size) -> Tuple[int, int]:
        if base is None:
            return 0, 0
        try:
            return max(0, min(child.start_byte - base, size)), max(0, min(child.end_byte - base, size))
        except Exception:
            return 0, 0

    def _first_named(self, node):
        named = self._named(node)
        return named[0] if named else None

    def _comprehension_clause(self, node) -> ast.comprehension:
        target = node.child_by_field_name("left")
        iterable = node.child_by_field_name("right")
        return ast.comprehension(
            target=self._expression(target, _STORE),
            iter=self._expression(iterable, _LOAD), ifs=[],
            is_async=1 if any(c.type == "async" for c in self._kids(node)) else 0)

    def _comprehension(self, node, ctx, kind) -> ast.AST:
        body = node.child_by_field_name("body")
        generators: List[ast.comprehension] = []
        for child in self._named(node):
            if child.type == "for_in_clause":
                generators.append(self._comprehension_clause(child))
            elif child.type == "if_clause" and generators:
                condition = child.child_by_field_name("condition") or self._param_name(child)
                generators[-1].ifs.append(self._expression(condition, _LOAD))
        if not generators:
            # A broken comprehension still needs a traversable generator slot.
            generators = [ast.comprehension(target=_pos(node, ast.Name(id="_", ctx=_STORE())),
                                            iter=_pos(node, ast.Constant(None)), ifs=[], is_async=0)]
        if kind is ast.DictComp:
            key = body.child_by_field_name("key") if body is not None else None
            value = body.child_by_field_name("value") if body is not None else None
            out = ast.DictComp(key=self._expression(key, _LOAD), value=self._expression(value, _LOAD),
                               generators=generators)
        else:
            out = kind(elt=self._expression(body, _LOAD), generators=generators)
        return _pos(node, out)

    def _list_comp(self, node, ctx):
        return self._comprehension(node, ctx, ast.ListComp)

    def _set_comp(self, node, ctx):
        return self._comprehension(node, ctx, ast.SetComp)

    def _dict_comp(self, node, ctx):
        return self._comprehension(node, ctx, ast.DictComp)

    def _gen_exp(self, node, ctx):
        return self._comprehension(node, ctx, ast.GeneratorExp)

    def _lambda(self, node, ctx):
        return _pos(node, ast.Lambda(args=self._parameters(node.child_by_field_name("parameters")),
                                     body=self._expression(node.child_by_field_name("body"), _LOAD)))

    def _named_expr(self, node, ctx):
        target = self._expression(node.child_by_field_name("name"), _STORE)
        if not isinstance(target, ast.Name):
            target = _pos(node, ast.Name(id="_", ctx=_STORE()))
        return _pos(node, ast.NamedExpr(target=target,
                                       value=self._expression(node.child_by_field_name("value"),
                                                              _LOAD)))

    def _yield(self, node, ctx):
        parts = self._named(node)
        value = self._expression(parts[0], _LOAD) if parts else None
        kind = ast.YieldFrom if any(c.type == "from" for c in self._kids(node)) else ast.Yield
        if kind is ast.YieldFrom and value is None:
            return self._placeholder(node)
        return _pos(node, kind(value=value))

    def _generic_type(self, node, ctx):
        """`list[T]`, `dict[str, int]`: a Subscript keeps the names reachable exactly as CPython does."""
        parts = self._named(node)
        if not parts:
            return self._placeholder(node)
        params: List[ast.AST] = []
        for child in parts[1:]:
            if child.type == "type_parameter":
                for param in self._named(child):
                    made = self._unwrap_type(param)
                    if made is not None:
                        params.append(made)
            else:
                params.append(self._expression(child, _LOAD))
        value = self._expression(parts[0], _LOAD)
        if not params:
            return _pos(node, value)
        slice_node = params[0] if len(params) == 1 else _pos(node, ast.Tuple(
            elts=params, ctx=_LOAD()))
        return _pos(node, ast.Subscript(value=value, slice=slice_node, ctx=ctx()))

    def _sequence(self, node, ctx, kind):
        elts = [self._expression(c, _LOAD) for c in self._named(node)]
        return _pos(node, kind(elts=elts, ctx=ctx()))

    def _list(self, node, ctx):
        return self._sequence(node, ctx, ast.List)

    def _tuple(self, node, ctx):
        return self._sequence(node, ctx, ast.Tuple)

    def _set(self, node, ctx):
        return _pos(node, ast.Set(elts=[self._expression(c, _LOAD) for c in self._named(node)]))

    def _tuple_of(self, node, ctx):
        return _pos(node, ast.Tuple(elts=[self._expression(c, ctx) for c in self._named(node)],
                                    ctx=ctx()))

    def _list_of(self, node, ctx):
        return _pos(node, ast.List(elts=[self._expression(c, ctx) for c in self._named(node)],
                                   ctx=ctx()))

    def _dict(self, node, ctx):
        keys: List[Optional[ast.AST]] = []
        values: List[ast.AST] = []
        for child in self._named(node):
            if child.type == "pair":
                key = child.child_by_field_name("key")
                value = child.child_by_field_name("value")
                keys.append(self._expression(key, _LOAD) if key is not None else None)
                values.append(self._expression(value, _LOAD) if value is not None
                              else _pos(child, ast.Constant(None)))
            else:
                keys.append(None)
                values.append(self._expression(child, _LOAD))
        return _pos(node, ast.Dict(keys=keys, values=values))

    def _parenthesized(self, node, ctx):
        inner = self._named(node)
        return self._expression(inner[0], ctx) if inner else self._placeholder(node)

    def _starred(self, node, ctx):
        # In `a, *b = c` the star and its name are Store targets; in `f(*a)` they are Load.
        return _pos(node, ast.Starred(value=self._expression(self._param_name(node), ctx),
                                      ctx=ctx()))

    def _await(self, node, ctx):
        inner = node.child_by_field_name("argument") or self._last_named(node)
        return _pos(node, ast.Await(value=self._expression(inner, _LOAD)))

    def _conditional(self, node, ctx):
        # `a if c else b` -> named children [a, c, b].
        parts = self._named(node)
        if len(parts) < 3:
            return self._generic_expression(node, ctx)
        return _pos(node, ast.IfExp(test=self._expression(parts[1], _LOAD),
                                    body=self._expression(parts[0], _LOAD),
                                    orelse=self._expression(parts[2], _LOAD)))

    _STMT = {
        "expression_statement": _expr_statement,
        "assignment": _assignment,
        "augmented_assignment": _assignment,
        "function_definition": _function,
        "class_definition": _class,
        "decorated_definition": _decorated,
        "return_statement": _return,
        "import_statement": _import,
        "import_from_statement": _import_from,
        "future_import_statement": _future_import,
        "if_statement": _if,
        "for_statement": _for,
        "while_statement": _while,
        "try_statement": _try,
        "with_statement": _with,
        "break_statement": _break,
        "continue_statement": _continue,
        "pass_statement": _pass_stmt,
        "raise_statement": _raise,
        "global_statement": _global,
        "nonlocal_statement": lambda self, node: self._global(node, True),
        "assert_statement": _assert,
        "delete_statement": _delete,
        "type_alias_statement": _type_alias,
        "match_statement": _match,
        "module": lambda self, node: self._stmt_module(node),
        "block": lambda self, node: self._statements(node),
    }

    _EXPR = {
        "identifier": _name,
        "as_pattern_target": _name,
        "dotted_name": _dotted,
        "attribute": _attribute,
        "subscript": _subscript,
        "call": _call,
        "string": _string,
        "concatenated_string": _string,
        "integer": _constant,
        "float": _constant,
        "true": _constant,
        "false": _constant,
        "none": _constant,
        "imaginary": _constant,
        "list": _list,
        "tuple": _tuple,
        "set": _set,
        "dictionary": _dict,
        "parenthesized_expression": _parenthesized,
        "binary_operator": _binary,
        "boolean_operator": _boolean,
        "comparison_operator": _comparison,
        "unary_operator": _unary,
        "not_operator": _unary,
        "await": _await,
        "conditional_expression": _conditional,
        "starred_expression": _starred,
        "list_splat_pattern": _starred,
        "list_splat": _starred,
        "lambda": _lambda,
        "named_expression": _named_expr,
        "yield": _yield,
        "generic_type": _generic_type,
        "list_comprehension": _list_comp,
        "set_comprehension": _set_comp,
        "dictionary_comprehension": _dict_comp,
        "generator_expression": _gen_exp,
        "expression_list": _tuple_of,
        "pattern_list": _tuple_of,
        "tuple_pattern": _tuple_of,
        "list_pattern": _list_of,
    }

    # PEP 634 patterns. An unmodelled pattern degrades to `MatchAs()` - a bare `_` capture, which
    # is always a valid pattern node, so the case block and its body stay traversable.
    _PATTERN = {
        "case_pattern": _pattern_unwrap,
        "group_pattern": _pattern_unwrap,
        "wildcard_pattern": _pattern_wildcard,
        "identifier": _pattern_capture,
        "dotted_name": _pattern_value,
        "attribute": _pattern_value,
        "string": _pattern_value,
        "concatenated_string": _pattern_value,
        "integer": _pattern_value,
        "float": _pattern_value,
        "true": _pattern_value,
        "false": _pattern_value,
        "none": _pattern_value,
        "list_pattern": _pattern_sequence,
        "tuple_pattern": _pattern_sequence,
        "dict_pattern": _pattern_mapping,
        "class_pattern": _pattern_class,
        "as_pattern": _pattern_as,
        "union_pattern": _pattern_or,
        "splat_pattern": _pattern_star,
        "list_splat_pattern": _pattern_star,
    }


_BINOP = {"+": ast.Add, "-": ast.Sub, "*": ast.Mult, "/": ast.Div, "//": ast.FloorDiv,
          "%": ast.Mod, "**": ast.Pow, "@": ast.MatMult, "<<": ast.LShift, ">>": ast.RShift,
          "|": ast.BitOr, "&": ast.BitAnd, "^": ast.BitXor}
_AUGOP = {k + "=": v for k, v in _BINOP.items()}
_CMPOP = {"==": ast.Eq, "!=": ast.NotEq, "<": ast.Lt, "<=": ast.LtE, ">": ast.Gt, ">=": ast.GtE,
          "in": ast.In, "not in": ast.NotIn, "is": ast.Is, "is not": ast.IsNot}
_BOOLOP = {"and": ast.And, "or": ast.Or}
_UNOP = {"-": ast.USub, "+": ast.UAdd, "~": ast.Invert, "not": ast.Not}
