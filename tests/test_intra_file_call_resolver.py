"""Unit tests for Phase 10.1: Intra-File Function Call Resolver (parameter-to-argument bridge)."""

import pytest
from ast_scanner import TaintTracker


def _bridge_findings(source: str) -> list:
    """Scan source and return only sinks created by the intra-file bridge."""
    tracker = TaintTracker(files={"test.py": source})
    tracker.analyze()
    return [s for s in tracker.sinks
            if s.metadata.get("cwe") == "CWE-89" and s.metadata.get("intra_file_bridge")]


def _all_cwe89_lines(source: str) -> set:
    tracker = TaintTracker(files={"test.py": source})
    tracker.analyze()
    return {s.lineno for s in tracker.sinks if s.metadata.get("cwe") == "CWE-89"}


HELP = '''
def run_query(sql):
    mydbCursor.execute(sql)
'''


class TestBridgePositives:
    """Cases where the bridged caller argument IS dynamic -> must flag."""

    def test_cwe89_helper_bridge(self):
        """Mission canonical case: source in view(), query passed into helper()."""
        source = """
def helper(q):
    cursor.execute(q)

def view(req):
    user = req.GET['u']
    query = f"SELECT * FROM t WHERE name = '{user}'"
    helper(query)
"""
        findings = _bridge_findings(source)
        assert not findings  # cursor.execute already caught structurally by Phase 6
        assert 3 in _all_cwe89_lines(source), "CWE-89 must be reported at the helper sink line"

    def test_alias_cursor_dynamic_arg(self):
        source = HELP + """

def handler(event):
    ip = event["queryStringParameters"]["ip"]
    q = "UPDATE t SET x = '%s'" % ip
    run_query(q)
"""
        findings = _bridge_findings(source)
        assert len(findings) == 1
        assert findings[0].lineno == 3

    def test_direct_expression_argument(self):
        source = HELP + """

def handler(req):
    run_query(req.body["sql"])
"""
        assert len(_bridge_findings(source)) == 1

    def test_two_hop_forwarding(self):
        """Bridge may trace at most two call edges: inner <- middle <- caller."""
        source = """
def inner(q):
    mydbCursor.execute(q)

def middle(m):
    inner(m)

def outer(req):
    s = f"DROP TABLE {req.name}"
    middle(s)
"""
        findings = _bridge_findings(source)
        assert len(findings) == 1
        assert findings[0].lineno == 3


class TestBridgeGuards:
    """Cases where a guard must keep the bridge completely silent."""

    def test_literal_argument_not_flagged(self):
        source = HELP + """

def handler():
    run_query("SELECT 1")
"""
        assert not _bridge_findings(source)

    def test_parameterized_query_preserved(self):
        """Sink with params argument (args[1]) is SAFE: never bridge-flagged."""
        source = """
def run_query(sql, params):
    mydbCursor.execute(sql, params)

def handler(req):
    q = f"SELECT {req.x}"
    run_query(q, (1,))
"""
        assert not _bridge_findings(source)

    def test_safe_builder_at_caller(self):
        source = HELP + """

def handler(req):
    q = sql.SQL("SELECT {}").format(sql.Identifier(req.x))
    run_query(q)
"""
        assert not _bridge_findings(source)

    def test_text_wrapper_at_caller(self):
        source = HELP + """

def handler(req):
    q = text("SELECT 1")
    run_query(q)
"""
        assert not _bridge_findings(source)

    def test_sink_line_suppression(self):
        source = """
def run_query(sql):
    mydbCursor.execute(sql)  # ok: validated upstream
"""
        assert not _bridge_findings(source)

    def test_caller_line_suppression(self):
        source = HELP + """

def handler(req):
    q = f"SELECT {req.x}"
    run_query(q)  # ok: reviewed
"""
        assert not _bridge_findings(source)

    def test_assignment_line_suppression(self):
        source = HELP + """

def handler(req):
    q = f"SELECT {req.x}"  # nosec B608
    run_query(q)
"""
        assert not _bridge_findings(source)

    def test_three_hop_chain_silent(self):
        """Exceeding the 2-hop tracing budget must stay silent, never guess."""
        source = """
def inner(q):
    mydbCursor.execute(q)

def middle(m):
    inner(m)

def deep(d):
    middle(d)

def outer(req):
    s = f"DROP {req.x}"
    deep(s)
"""
        assert not _bridge_findings(source)

    def test_helper_without_callers_silent(self):
        """A helper that is never invoked in the module has no bridge evidence."""
        assert not _bridge_findings(HELP)

    def test_unresolved_argument_silent(self):
        source = HELP + """

def handler(req):
    run_query(mystery_global)
"""
        assert not _bridge_findings(source)

    def test_shadowed_parameter_uses_local_assignment(self):
        source = """
def run_query(sql):
    sql = "SELECT 1"
    mydbCursor.execute(sql)

def handler(req):
    run_query(req.body["sql"])
"""
        assert not _bridge_findings(source)

    def test_recursive_helper_no_hang(self):
        """Cycle guard: visited_functions prevents infinite recursion on self-calls."""
        source = """
def ping(p):
    mydbCursor.execute(p)
    ping(p)
"""
        _bridge_findings(source)  # must terminate

    def test_starred_args_not_guessed(self):
        source = HELP + """

def handler(req, rest):
    run_query(*rest)
"""
        assert not _bridge_findings(source)

    def test_kwargs_splat_not_guessed(self):
        source = HELP + """

def handler(req, opts):
    run_query(**opts)
"""
        assert not _bridge_findings(source)

    def test_keyword_call_argument_bridged(self):
        source = HELP + """

def handler(req):
    s = f"DELETE {req.x}"
    run_query(sql=s)
"""
        assert len(_bridge_findings(source)) == 1
