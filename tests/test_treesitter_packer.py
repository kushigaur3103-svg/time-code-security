"""Phase 1 of the resilient parser: the standalone Tree-sitter CST -> `ast` translator.

`tcs/treesitter_packer.py` converts a tree-sitter concrete syntax tree into a real `ast.Module`
that `ast.walk` and `ast.NodeVisitor` can traverse. Three contracts are proven here:

1. **Isolation** -- the translator imports nothing from the engine, and the engine reaches it through
   one gated helper (`clean_parse`), never through the unconditional `parse_to_ast`.
2. **Parity** -- for valid Python the output matches `ast.parse` node-for-node, so a later phase
   cannot introduce false positives or misses by switching to it.
3. **Zero panic** -- for broken, binary, or cutting-edge syntax it still returns a traversable
   `ast.Module` and never raises, and the intact code around the damage is kept.

Every number asserted below was measured by running this file, not chosen to make a claim pass.
Fixtures are 1-12 lines each; the whole suite fits a laptop with ~400 MB free RAM.

Run it either way:
    python tests/test_treesitter_packer.py
    python -m pytest tests/test_treesitter_packer.py -q
"""
from __future__ import annotations

import ast
import collections
import gc
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tcs.treesitter_packer import parse_to_ast, tree_sitter_available  # noqa: E402

PY = f"{sys.version_info[0]}.{sys.version_info[1]}"

# ─── valid-Python parity fixtures ───
SNIPPETS = {
    "call_attr": "result = obj.method(arg).other\n",
    "assign_chain": "a = b = c = compute(1)\n",
    "aug_assign": "total += 1\ntotal //= 2\ntotal **= 3\n",
    "ann_assign": "COUNT: Final = 3\nname: str\n",
    "import": "import os\nimport sys.path as sp\nfrom a.b import c, d as e\n",
    "from_star": "from mod import *\nfrom .pkg.mod import x\n",
    "func": "def f(a, b=2, *args, c=3, **kw) -> int:\n    return a + b\n",
    "posonly": "def f(a, b=1, /, c=2, *args, d, **kw) -> int:\n    return a + b + c\n",
    "kwonly_only": "def f(*args, a=1, b, **kw):\n    return a + b\n",
    "bare_star": "def f(x, *, y):\n    return x\n",
    "async_func": "async def f(req: Request) -> Response:\n    return await handle(req)\n",
    "typed_func": "def g(x: int, y: Optional[str] = None) -> Dict[str, int]:\n    return {}\n",
    "decorated": "@app.route('/x')\n@auth.require()\ndef handler(request):\n    return render(request)\n",
    "class": "class C(Base, metaclass=Meta):\n    x = 1\n\n    def m(self):\n        return self.x\n",
    "if_elif": "if a:\n    f(1)\nelif b:\n    g(2)\nelse:\n    h(3)\n",
    "for_else": "for i in items:\n    if i:\n        break\nelse:\n    log('none')\n",
    "while": "while not done():\n    step()\n    continue\n",
    "try": "try:\n    run(cmd)\nexcept ValueError as e:\n    raise\nexcept (KeyError, IndexError):\n"
           "    pass\nelse:\n    ok()\nfinally:\n    cleanup()\n",
    "with": "with open(p) as fh, lock as l:\n    fh.read()\n",
    "async_with": "async def f():\n    async with session.get(u) as resp:\n        data = await resp.text()\n",
    "fstring": "msg = f\"user {user.name} ran {cmd('x')} at {ts:%H:%M}\"\n",
    "fstring_nested": "msg = f\"{d['k']} and {f'{inner}'}\"\n",
    "concat": "sql = \"SELECT\" \" x\"\ntwo = f\"a{x}\" \"b\"\n",
    "listcomp": "out = [x.strip() for x in rows if x]\n",
    "dictcomp": "out = {k: v.strip() for k, v in items}\n",
    "setcomp": "out = {x.id for x in rows}\n",
    "genexp": "total = sum(x for x in rows)\n",
    "nested_comp": "out = [[f(y) for y in r] for r in rows]\n",
    "lambda": "f = lambda a, b=2, *c, **d: a + b\nsorted(rows, key=lambda r: r.name)\n",
    "walrus": "if (n := len(rows)) > 3:\n    use(n)\n",
    "splat_call": "h(*args, **kw)\n",
    "star_assign": "a, *b = c\n(d, e), f = g()\n",
    "subscript_slice": "x = d['k'][1:2].m()\ny = seq[::2]\n",
    "bool_cmp": "if a and not b or c == d or e in f and g is not None:\n    pass\n",
    "ternary": "v = a() if cond else b()\n",
    "yield": "def g():\n    yield 1\n    x = yield\n",
    "yield_from": "def g():\n    return (yield from inner())\n",
    "assert_del": "assert len(x) > 0, 'empty'\ndel a[0], b.c\n",
    "raise_from": "raise ValueError('bad') from err\n",
    "global_nonlocal": "G = 1\n\n\ndef outer():\n    H = 1\n\n    def inner():\n"
                       "        nonlocal H\n        H = 2\n",
    "comments": "# leading\ndef f():  # trailing\n    # inner\n    return 1\n",
    "match": "match cmd:\n    case ['go', direction]:\n        move(direction)\n    case _:\n        pass\n",
    "try_star": "try:\n    a()\nexcept* ValueError as e:\n    log(e)\n",
    "decorators_chained": "@a.b(c)\n@d\nclass K:\n    pass\n",
    "dict_nest": "cfg = {'a': {'b': [1, 2]}, **extra}\n",
    "multiline_call": "log.info(\n    'text %s',\n    request.query['q'],\n    extra={'k': v},\n)\n",
    "spec_nested": 'v = f"{x:{w},>5}"\nv2 = f"{y!r:>{pad}}"\n',
    "spec_multi": 'v = f"{x:>{a}b{c}}"\nw = f"{y:>{a}}" + f"{z}"\n',
    "star_list_target": "[a, *b] = c\n",
    "match_rich": "match event:\n"
                  "    case {'type': t, **extra}:\n        log(t)\n"
                  "    case Point(x=1, y=2) if t:\n        pass\n"
                  "    case (1, 2) | (3,):\n        pass\n"
                  "    case Color.RED:\n        pass\n"
                  "    case str() as s:\n        use(s)\n"
                  "    case [a, *rest]:\n        pass\n"
                  "    case _:\n        drop()\n",
    "complex_call": "svc.call(a, b, key=val, *more, **rest)\n",
    "dict_in_fstring": "v = f\"{json.dumps({'a': b.attr})}\"\n",
    # Two forms CPython 3.11 rejects outright; kept here so the newer-syntax path is exercised too.
    "pep695_generic": "def g[T](x: T) -> T:\n    return x\n",
    "pep695_alias": "type Alias = list[int]\n",
    "pep701_fstring": "msg = f\"{d['key']}\"\n",
}

# On an older interpreter these cannot be *compared* to native parse; only our side is checked.
NATIVE_MIN_VERSION = {"pep695_generic": (3, 12), "pep695_alias": (3, 12)}

# ─── hostile inputs: none of these may raise ───
GARBAGE = {
    "empty": "",
    "blank": "\n\n\n",
    "comment_only": "# nothing here\n",
    "def_colon": "def (:\n",
    "unclosed_bracket": "x = [1, 2\ny = 3\n",
    "from_import": "from import\n",
    "if_no_colon": "if True\n    print(\n",
    "parens": "((((\n",
    "unterminated_str": "x = 'never ends\n",
    "hex_only": "0x\n",
    "nul_bytes": b"\x00\x01\xff\xfe binary junk \x00",
    "token_soup": "@@@ ??? >>> ### <<< === ~~~ ^^^ &&& ||| !!! $$$$ if if if else else "
                 "while for for def class return yield await lambda lambda",
    "deep_expr": "x = " + "1 + " * 2000 + "1\n",
    "truncated_class": "class A(Base, metaclass=\n",
    "dangling_indent": "def f():\n        over-indented\n    return 1\n",
    "star_in_target": "* = 3\n",
    "only_keywords": "def def def\nclass class\nreturn return\n",
    "fake_pep695": "def g[T](x: T) -> T:\n    return x\n\ntype X = int\n",
    "pep701": 'v = f"{d[\'k\']} and {f\'{inner}\'}"\n',
}

# Inputs whose recovered tree deliberately does *not* compile, with the reason. The source itself is
# uncompileable Python (a top-level `return`, an assignment target that cannot exist); the module
# keeps the shape so a scanner can still see the code, and nothing downstream compiles these files.
KNOWN_UNCOMPILABLE = {
    "dangling_indent": ("SyntaxError", "'return' outside function"),
    "only_keywords": ("SyntaxError", "'return' outside function"),
    "star_in_target": ("ValueError", "can't be assigned to"),
}

# Inputs that recover into chains hundreds of nodes deep: walked iteratively, see section 4.
DEEP_INPUTS = {"deep_expr", "star_in_target"}

# Intact code that must survive a neighbouring broken line, as measured.
SANDWICH = {
    "broken_first": ("def f(:\n    return 1\n\ndef safe():\n    log('kept')\n",
                     ["f", "safe"], [(5, "log")]),
    "broken_middle": ("def a():\n    x = 1\n\ndef broken(:\n    y = 2\n\ndef b():\n    run(cmd)\n",
                      ["a", "broken", "b"], [(8, "run")]),
    "broken_last": ("def ok():\n    audit(user)\n\ndef tail(:\n",
                    ["ok", "tail"], [(2, "audit")]),
    "broken_in_class": ("class C:\n    def m(self):\n        send(data)\n    bad(:\n        x = 1\n",
                        ["m"], [(3, "send")]),
}

BENCH_SRC = ("def handle(request):\n"
             "    user = request.query['user']\n"
             "    log.info('run %s', user.name, extra={'k': v})\n"
             "    return f\"done {user.id}\"\n")


# ─── helpers ───
def counter(tree):
    return collections.Counter(type(node).__name__ for node in ast.walk(tree))


def coords(tree, kind):
    out = []
    for node in ast.walk(tree):
        if isinstance(node, kind):
            out.append((node.lineno, node.col_offset,
                        getattr(node, "end_lineno", None), getattr(node, "end_col_offset", None)))
    return sorted(out)


def traversable(tree, label, recursive=True):
    """Every consumer-side operation an `ast` tree can be put through, with no exception allowed.

    `recursive=False` skips the `NodeVisitor` pass, which is only used for the two inputs that
    recover into chains hundreds of nodes deep -- there the stack limit is a property of the input,
    proven against CPython's own tree just below, not something the translator introduces.
    """
    nodes = list(ast.walk(tree))
    assert ast.dump(tree), label
    seen = []

    class Probe(ast.NodeVisitor):
        def generic_visit(self, node):
            seen.append(type(node).__name__)
            super().generic_visit(node)

    if recursive:
        Probe().visit(tree)
        assert len(seen) == len(nodes), (label, len(seen), len(nodes))
    for node in nodes:
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    ast.iter_fields(item)
        if isinstance(node, (ast.stmt, ast.expr)):
            assert isinstance(node.lineno, int) and node.lineno >= 1, (label, node)
            assert isinstance(node.col_offset, int) and node.col_offset >= 0, (label, node)
    return nodes


def names_of(tree, kinds):
    return [n.name for n in ast.walk(tree) if isinstance(n, kinds) and hasattr(n, "name")]


def call_sites(tree):
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            while isinstance(func, ast.Attribute):
                func = func.value
            out.append((node.lineno, getattr(func, "id", "?")))
    return sorted(out)


def expect_compile(tree, label):
    """Compile, or match the one recorded reason the source itself cannot compile."""
    try:
        compile(tree, "<test>", "exec")
    except Exception as exc:
        expected = KNOWN_UNCOMPILABLE.get(label)
        assert expected is not None, f"{label}: unexpected {type(exc).__name__}: {exc}"
        assert type(exc).__name__ == expected[0], (label, exc)
        assert expected[1] in str(exc), (label, exc)
        return False
    assert label not in KNOWN_UNCOMPILABLE, f"{label} was expected to fail and did not"
    return True


# ─── the suite ───
def test_treesitter_packer_phase_one():
    try:
        import pytest
    except ImportError:
        pytest = None
    if not tree_sitter_available():
        if pytest is not None:
            pytest.skip("tree-sitter wheels not installed; Phase 1 module is inert by design")
        print(f"SKIP: tree-sitter not installed on Python {PY}")
        return

    # ─── 1. Isolation: the translator is standalone, and the scanner touches one function ───
    imports = []
    for node in ast.walk(ast.parse((ROOT / "tcs" / "treesitter_packer.py").read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            imports += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "the packer uses a relative import"
            imports.append(node.module or "")
    # Only stdlib plus its own optional grammar wheels - never the engine it is meant to feed.
    allowed = {"__future__", "ast", "threading", "typing", "tree_sitter", "tree_sitter_python"}
    assert set(imports) <= allowed, sorted(set(imports) - allowed)
    # Phase 2 wired the shield in. The contract that keeps it reviewable: the *unconditional* parser
    # (`parse_to_ast`, which answers even for garbage) is still never called by the scanner, and the
    # only code that touches the packer at all is the one rescue helper.
    scanner_src = (ROOT / "ast_scanner.py").read_text(encoding="utf-8")
    assert "parse_to_ast" not in scanner_src, "the scanner must go through the gated clean_parse"
    users = sorted({node.name for node in ast.walk(ast.parse(scanner_src))
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and "_treesitter_packer" in ast.dump(node)})
    assert users == ["_treesitter_rescue"], users

    # ─── 2. Structural + coordinate parity against ast.parse on valid Python ───
    assert len(SNIPPETS) >= 20, len(SNIPPETS)
    checked = 0
    for name, code in SNIPPETS.items():
        ours = parse_to_ast(code, name)
        assert isinstance(ours, ast.Module), name
        traversable(ours, name)
        expect_compile(ours, name)
        if name in NATIVE_MIN_VERSION and sys.version_info[:2] < NATIVE_MIN_VERSION[name]:
            continue  # nothing to compare against on this interpreter; section 6 covers our side
        native = ast.parse(code)
        assert counter(native) == counter(ours), f"{name}: {counter(native) - counter(ours)} " \
                                                 f"missing / {counter(ours) - counter(native)} extra"
        for kind in (ast.Call, ast.Attribute, ast.Name):
            assert coords(native, kind) == coords(ours, kind), \
                f"{name}: {kind.__name__} coords native={coords(native, kind)} ours={coords(ours, kind)}"
        # Node counts and spans are not enough: the field values have to agree too (argument
        # buckets, operator types, conversions, slice kinds). This dump compares every field.
        assert ast.dump(native, include_attributes=False) == \
               ast.dump(ours, include_attributes=False), f"{name}: field-level tree differs"
        checked += 1
    assert checked >= len(SNIPPETS) - 2, checked

    # ─── 3. Coordinates are the real source span, not an approximation ───
    one = "result = obj.method(arg).other\n"
    ours = parse_to_ast(one, "coords.py")
    calls = [n for n in ast.walk(ours) if isinstance(n, ast.Call)]
    assert [(c.lineno, c.col_offset, c.end_lineno, c.end_col_offset) for c in calls] == [(1, 9, 1, 24)]
    attrs = sorted((a.lineno, a.col_offset, a.end_col_offset) for a in ast.walk(ours)
                   if isinstance(a, ast.Attribute))
    assert attrs == [(1, 9, 19), (1, 9, 30)], attrs
    assert attrs == sorted((a.lineno, a.col_offset, a.end_col_offset)
                           for a in ast.walk(ast.parse(one)) if isinstance(a, ast.Attribute))
    assert ours.body[0].lineno == 1 and ours.body[0].col_offset == 0
    assert ours.body[0].targets[0].col_offset == 0
    assert ours.body[0].value.attr == "other"
    assert isinstance(ours.body[0].value.value, ast.Call)
    assert ours.body[0].value.value.func.attr == "method"
    assert ours.body[0].value.value.func.value.id == "obj"
    # A call that starts inside an f-string keeps the interpolation's own column.
    f = parse_to_ast('msg = f"{user.name} {cmd(1)}"\n', "f.py")
    assert coords(f, ast.Call) == coords(ast.parse('msg = f"{user.name} {cmd(1)}"\n'), ast.Call)
    assert f.filename == "f.py", f.filename

    # ─── 4. Fault tolerance: garbage in, traversable Module out, never an exception ───
    for label, src in GARBAGE.items():
        tree = parse_to_ast(src, label)
        assert isinstance(tree, ast.Module), label
        assert tree.body, label
        traversable(tree, label, recursive=label not in DEEP_INPUTS)
        expect_compile(tree, label)
    # What the two extremes actually recover: the 2000-term sum keeps hundreds of its terms as real
    # BinOp nodes, and binary junk still yields a module.
    deep = parse_to_ast(GARBAGE["deep_expr"], "deep")
    nodes = traversable(deep, "deep", recursive=False)
    assert len(nodes) > 1000, len(nodes)
    assert sum(1 for n in nodes if isinstance(n, ast.BinOp)) > 400, "terms lost"
    # The recovered chain is deeper than CPython's recursive visitor can walk -- and so is the tree
    # `ast.parse` builds from the same line, which is the point: the limit belongs to the input.
    native_deep = ast.parse(GARBAGE["deep_expr"])

    class DepthProbe(ast.NodeVisitor):
        def generic_visit(self, node):
            super().generic_visit(node)

    for tree, who in ((native_deep, "ast.parse"), (deep, "parse_to_ast")):
        try:
            DepthProbe().visit(tree)
            raise AssertionError(f"{who} walked a {2000}-term chain without overflowing the stack")
        except RecursionError:
            pass
    assert len(parse_to_ast(b"", "b").body) == 1
    assert len(parse_to_ast("\x00\x01\xff junk", "nul").body) >= 1

    # ─── 5. Broken neighbours do not delete valid code ───
    for label, (src, funcs, calls) in SANDWICH.items():
        tree = parse_to_ast(src, label)
        traversable(tree, label)
        expect_compile(tree, label)
        assert names_of(tree, (ast.FunctionDef, ast.AsyncFunctionDef)) == funcs, label
        assert call_sites(tree) == sorted(calls), label

    # ─── 6. Syntax newer than this interpreter still yields usable code ───
    generic = "def g[T](x: T) -> T:\n    return x\n\n\ndef safe(cmd):\n    log(cmd)\n"
    tree = parse_to_ast(generic, "pep695.py")
    traversable(tree, "pep695")
    assert "safe" in names_of(tree, (ast.FunctionDef,)), tree
    assert (6, "log") in call_sites(tree), call_sites(tree)
    if sys.version_info[:2] < (3, 12):
        try:
            ast.parse(generic)
            raise AssertionError("3.11 accepted PEP 695 generics -- fixture premise is wrong")
        except SyntaxError:
            pass
    alias = parse_to_ast("type Config = int\n", "alias.py")
    assert "Config" in ast.dump(alias), ast.dump(alias)[:200]
    nested = parse_to_ast('v = f"{d[\'k\']} and {f\'{inner}\'}"\n', "pep701.py")
    traversable(nested, "pep701")
    expect_compile(nested, "pep701")
    assert any(isinstance(n, ast.JoinedStr) for n in ast.walk(nested)), "f-string lost"
    assert sorted(getattr(n, "id", "") for n in ast.walk(nested)
                  if isinstance(n, ast.Name)) == ["d", "inner", "v"], ast.dump(nested)[:200]
    assert sum(1 for n in ast.walk(nested) if isinstance(n, ast.JoinedStr)) == 2
    assert sum(1 for n in ast.walk(nested) if isinstance(n, ast.FormattedValue)) == 3

    # ─── 7. Memory stays scoped: 500 parses hold no tree-sitter state afterwards ───
    import psutil

    parse_to_ast(BENCH_SRC, "warm.py")          # load grammar + build dispatch before measuring
    gc.collect()
    rss0 = psutil.Process().memory_info().rss
    times = []
    for _ in range(500):
        start = time.perf_counter()
        tree = parse_to_ast(BENCH_SRC, "bench.py")
        times.append(time.perf_counter() - start)
        assert isinstance(tree, ast.Module)
    gc.collect()  # the CST is already gone with each call's frame; this only clears our own cycles
    grow = psutil.Process().memory_info().rss - rss0
    median = statistics.median(times) * 1000
    assert grow < 20 * 1024 * 1024, f"500 parses grew RSS by {grow / 1e6:.1f} MB"
    assert median < 5.0, f"median parse took {median:.2f} ms (limit 5 ms)"

    # ─── 8. Deterministic: same bytes in, same tree out, every time ───
    for label, src in list(SNIPPETS.items())[:6] + list(SANDWICH.items())[:2]:
        code = src[0] if isinstance(src, tuple) else src
        assert ast.dump(parse_to_ast(code, label)) == ast.dump(parse_to_ast(code, label)), label
    assert ast.dump(parse_to_ast(BENCH_SRC, "a.py")) == ast.dump(parse_to_ast(BENCH_SRC, "a.py"))

    # ─── 9. Never retains CST nodes on the module-level singletons ───
    import tcs.treesitter_packer as packer

    for attr in ("_LANG", "_PARSER"):
        held = getattr(packer, attr)
        assert held is None or not hasattr(held, "root_node"), f"{attr} holds a parsed tree"
    assert not [k for k in vars(packer) if k.endswith("_CACHE") or k.endswith("_NODES")], \
        "module-level node cache exists"

    print(f"treesitter packer: {len(SNIPPETS)} parity snippets, {len(GARBAGE)} hostile inputs, "
          f"500 parses grew {grow / 1e6:.1f} MB, median {median:.2f} ms -- all assertions passed "
          f"on Python {PY}")


if __name__ == "__main__":
    test_treesitter_packer_phase_one()
