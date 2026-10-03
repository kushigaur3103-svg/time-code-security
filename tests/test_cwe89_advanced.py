"""Phase 10.2 targeted tests: driver alias sinks and ORM query-builder sinks (CWE-89)."""

import pytest
from ast_scanner import TaintTracker


def _cwe89_finding_lines(source: str) -> set:
    """Lines with edge-backed CWE-89 findings (what the CLI/showdown report)."""
    tracker = TaintTracker(files={"test.py": source})
    _s, sinks, edges = tracker.analyze()
    by_id = {x.id: x for x in sinks}
    out = set()
    for edge in edges:
        sink = by_id.get(edge.target_id)
        if sink is None:
            continue
        cwe = (sink.metadata or {}).get("cwe") or (
            edge.proof_graph.cwe if edge.proof_graph else None)
        if cwe == "CWE-89":
            out.add(sink.lineno)
    return out


class TestDriverAliasPositives:
    def test_asyncpg_fetch_fstring(self):
        source = """
async def bad(conn, user_id):
    await conn.fetch(f"SELECT * FROM users WHERE id = {user_id}")
"""
        assert 3 in _cwe89_finding_lines(source)

    def test_pg8000_run_fstring(self):
        source = """
def bad(pg_conn, name):
    pg_conn.run(f"SELECT * FROM items WHERE name = '{name}'")
"""
        assert 3 in _cwe89_finding_lines(source)

    def test_alias_cursor_execute_resolved_variable(self):
        source = """
def handler(event):
    ip = event["queryStringParameters"]["ip"]
    sql = "UPDATE t SET x = '%s' WHERE id = 1" % ip
    mydbCursor.execute(sql)
"""
        assert 5 in _cwe89_finding_lines(source)

    def test_connection_execute_concat(self):
        source = """
def bad(conn, req):
    conn.run("SELECT name FROM users WHERE age=" + req.FormValue("age"))
"""
        assert 3 in _cwe89_finding_lines(source)

    def test_cursor_with_dynamic_query_arg(self):
        source = """
def bad(conn, user_input):
    cur = conn.cursor('SELECT * FROM {}'.format(user_input))
"""
        assert 3 in _cwe89_finding_lines(source)


class TestQueryBuilderPositives:
    def test_order_by_concat(self):
        source = """
def bad(query, user_order):
    query.order_by("col_" + user_order)
"""
        assert 3 in _cwe89_finding_lines(source)

    def test_distinct_format(self):
        source = """
def bad(query, param):
    one = query.distinct("foo={}".format(param))
"""
        assert 3 in _cwe89_finding_lines(source)

    def test_having_fstring(self):
        source = """
def bad(query, param):
    one = query.join(DeploymentPermission).having(f"oops{param}")
"""
        assert 3 in _cwe89_finding_lines(source)

    def test_django_raw_percent(self):
        source = """
def bad(request):
    user_name = request.POST.get("user_name")
    Person.objects.raw("SELECT age FROM person WHERE name = %s" % user_name)
"""
        assert 4 in _cwe89_finding_lines(source)

    def test_dynamic_text_wrapper(self):
        source = """
search = "foo" + param

def bad(query):
    one = query.distinct(text(search))
"""
        assert 5 in _cwe89_finding_lines(source)

    def test_bare_django_extra(self):
        source = """
def bad(Entry):
    Entry.objects.get().extra()
"""
        assert 3 in _cwe89_finding_lines(source)


def _phase102_finding_lines(source: str) -> set:
    """Lines where the Phase 10.2 driver/query-builder path emitted or repaired a CWE-89 sink."""
    tracker = TaintTracker(files={"test.py": source})
    _s, sinks, _e = tracker.analyze()
    return {s.lineno for s in sinks
            if (s.metadata or {}).get("cwe") == "CWE-89"
            and (s.symbol == "SQL_DRIVER_QUERYBUILDER"
                 or any(k.endswith("source_id") for k in (s.metadata or {})))}


class TestSafetyGuards:
    def test_parameterized_positional_silent(self):
        source = """
async def good(conn, user_id):
    await conn.fetch("SELECT * FROM users WHERE id = $1", user_id)
"""
        assert not _cwe89_finding_lines(source)

    def test_parameterized_keyword_silent(self):
        source = """
def good(pg_conn, user_id):
    pg_conn.run("SELECT * FROM items WHERE id = :id", id=user_id)
"""
        assert not _cwe89_finding_lines(source)

    def test_static_literal_silent(self):
        source = """
def good(query):
    query.order_by("name ASC")
"""
        assert not _cwe89_finding_lines(source)

    def test_bindparams_silent(self):
        source = """
def good(query, var):
    query.filter("oops{}".bindparams(var))
"""
        assert not _cwe89_finding_lines(source)

    def test_sql_identifier_format_silent(self):
        source = """
def good(cur, req):
    query = sql.SQL("SELECT {} FROM t").format(sql.Identifier(req.x))
    cur.execute(query)
"""
        # Legacy core param-taint path may emit its own POTENTIAL finding here;
        # the guard asserts the Phase 10.2 path stays silent (no synthesis/repair).
        assert not _phase102_finding_lines(source)

    def test_static_text_silent(self):
        source = """
def good(engine):
    engine.execute(text("INSERT INTO t (name) VALUES (:name)"), {"name": x})
"""
        assert not _cwe89_finding_lines(source)

    def test_comparison_args_silent(self):
        source = """
def good(cls, query):
    query.distinct(cls.id == DeploymentPermission.token_id)
"""
        assert not _cwe89_finding_lines(source)

    def test_non_string_call_arg_silent(self):
        source = """
def good(query):
    query.order_by(desc(Scan.started_at))
"""
        assert not _cwe89_finding_lines(source)

    def test_ok_annotation_silent(self):
        source = """
def bad(query, user_order):
    # ok:sql-injection
    query.order_by("col_" + user_order)
"""
        assert not _cwe89_finding_lines(source)

    def test_nosec_on_sink_line_silent(self):
        source = """
def bad(conn, req):
    conn.run("SELECT * FROM t WHERE x=" + req.q)  # nosec B608
"""
        assert not _cwe89_finding_lines(source)

    def test_assignment_line_suppression_silent(self):
        source = """
def handler(event):
    ip = event["queryStringParameters"]["ip"]
    sql = "UPDATE t SET x = '%s'" % ip  # ok: reviewed
    mydbCursor.execute(sql)
"""
        assert not _cwe89_finding_lines(source)
