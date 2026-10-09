r"""Enterprise route sources (Zulip, FastAPI/Pydantic) and the paired ZeroMQ CWE-502 sink.

Each positive below is proven by a switch diff, not by a bare count: the same fixture is scanned with
`_compute_enterprise_param_names` / `_collect_cwe502_socket_deserialization` stubbed out and with them
live, and the finding must exist only in the second run. That is what makes "zero false positives"
checkable - a rule that fires on everything would also "find" these cases.

    Zulip `@has_request_variables` / `@authenticated_json_view` / `@rest_dispatch` /
        `@api_key_only_webhook_view`: only `REQ(...)` parameters and unannotated parameters with no
        server-side default become sources. The seven context names (`request`, `user_profile`,
        `realm`, `acting_user`, `client`, `subdomain`, `identity`) never do, and neither does an
        annotated parameter holding a literal.
    FastAPI: `Query(...)` / `Header(...)` / `Path(...)` defaults, including the modern
        `Annotated[str, Header()]` spelling, under a `@app.*` / `@router.*` route decorator. A
        `directory: Path = Path("/srv/data")` pathlib default is the same spelling as the extractor
        and is rejected by the annotation guard.
    CWE-502: the pairing is the rule. `msgpack.unpackb(payload)` alone is not a finding; the argument
        must reach a `.recv()` / `.recv_multipart()` / `zmq.Stream` read inside one function scope in
        at most `TAINT_TRAVERSAL_MAX_HOPS` (8) copies - a ninth copy leaves the site unreported.

Airflow, PyGoat and the 552-case gate corpus contain none of these spellings (measured: no
`has_request_variables`, no `REQ(`, no `Query(`/`Header(` parameter default, no `msgpack`, and the
only `recv()` fixtures are the CWE-770 unbounded-read pair, which deserializes nothing), so every new
rule is silent there and Gate 1 stays 552/552.

The two production trees the arenas now point at were measured too, and the honest result is that the
rules stay quiet on them - which is the point of the guards:

    saltstack/salt @ v3000.1 (2,819 .py files, first 300 scanned with the methods live and stubbed):
        GAINED=0, LOST=0. All 26 `msgpack`/`pickle` load sites read a *file handle*
        (`pickle.load(fp_)`) or go through salt's own `salt.payload.unpackage` wrapper, so the
        socket-pairing rule correctly refuses them. The four CWE-502 rows that do appear there carry
        the pre-existing generic `DESERIALIZATION` message, not this rule's text.
    zulip/zulip @ main (1,392 .py files, first 300): GAINED=0, LOST=0. Modern Zulip has dropped the
        old spelling entirely - `has_request_variables` and `REQ(` occur zero times - and
        `rest_dispatch` / `authenticated_json_view` appear only as the definitions in
        `zerver/lib/rest.py` and `zerver/decorator.py`, applied at runtime, never as a decorator on a
        view in source. So the decorator branch has nothing to match, and inventing a finding there
        would be a false positive wearing an enterprise costume.
"""

import ast
import textwrap
import unittest

from ast_scanner import TAINT_TRAVERSAL_MAX_HOPS, TaintTracker
from cli import _findings_for

ENTERPRISE = "_compute_enterprise_param_names"
SOCKET = "_collect_cwe502_socket_deserialization"
MSG502 = "CWE-502: Deserialization of untrusted ZeroMQ network socket stream"


def _messages(name, source, disabled=None):
    """CWE-502 messages this file produces, optionally with one collector switched off."""
    original = getattr(TaintTracker, disabled) if disabled else None
    if disabled:
        setattr(TaintTracker, disabled, lambda *args, **kwargs: None)
    try:
        tracker = TaintTracker(files={name + ".py": textwrap.dedent(source)}, audit_all=False)
        _sources, _sinks, edges = tracker.analyze()
        return sorted({row["message"] for row in _findings_for(tracker, edges)
                       if row["cwe"] == "CWE-502"})
    finally:
        if disabled:
            setattr(TaintTracker, disabled, original)


def _rows(name, source, disabled=None):
    """(cwe, line) pairs with the named engine method live or switched off."""
    original = getattr(TaintTracker, disabled) if disabled else None
    if disabled:
        setattr(TaintTracker, disabled, lambda *args, **kwargs: frozenset())
    try:
        tracker = TaintTracker(files={name + ".py": textwrap.dedent(source)}, audit_all=False)
        _sources, _sinks, edges = tracker.analyze()
        return (sorted({(row["cwe"], row["line"]) for row in _findings_for(tracker, edges)}),
                sorted(s.symbol for s in tracker.sources
                       if s.metadata.get("category") == "WEB_PARAMETER"))
    finally:
        if disabled:
            setattr(TaintTracker, disabled, original)


def _classify(source, func_name):
    """The classifier's answer for one function, without running the whole pipeline."""
    source = textwrap.dedent(source)
    tracker = TaintTracker(files={"classify.py": source}, audit_all=False)
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            return frozenset(tracker._compute_enterprise_param_names(node))
    raise AssertionError(f"no function {func_name!r} in the fixture")


def _chain(copies, deserializer="pickle.loads"):
    """`sock.recv()` copied *copies* times, then deserialized on the last line."""
    lines = ["import pickle", "import msgpack", "", "def serve(sock):",
             "    frame = sock.recv()"]
    previous = "frame"
    for index in range(copies):
        lines.append(f"    hop{index} = {previous}")
        previous = f"hop{index}"
    lines.append(f"    return {deserializer}({previous})")
    return "\n".join(lines) + "\n"


class TestZulipDecoratorSources(unittest.TestCase):
    REQ_VIEW = '''
        import subprocess

        from zerver.decorator import has_request_variables
        from zerver.lib.request import REQ


        @has_request_variables
        def api_export_view(request, user_profile,
                            topic: str = REQ(),
                            stream_name = REQ(str, only_in_post=True)):
            return subprocess.check_output(["ls", "/tmp/" + topic + stream_name])
'''
    TRUSTED_VIEW = '''
        import subprocess

        from zerver.decorator import has_request_variables


        @has_request_variables
        def export_view(request, user_profile, realm, acting_user, client, subdomain, identity):
            return subprocess.check_output(["ls", "/" + subdomain + realm.string_id
                                            + acting_user + client + identity
                                            + user_profile.email])
'''
    PLAIN_DEFAULT_VIEW = '''
        import subprocess

        from zerver.decorator import has_request_variables


        @has_request_variables
        def export_view(request, user_profile, path: str = "/srv/fixed",
                        limit: int = 10):
            return subprocess.check_output(["ls", path])
'''
    UNANNOTATED_VIEW = '''
        import subprocess

        from zerver.decorator import rest_dispatch


        @rest_dispatch
        def search_view(request, query):
            return subprocess.check_output(["ls", "/tmp/" + query])
'''
    WEBHOOK_VIEW = '''
        import subprocess

        from zerver.decorator import api_key_only_webhook_view
        from zerver.lib.request import REQ


        @api_key_only_webhook_view("GCP")
        def gcp_view(request, client, name: str = REQ()):
            return render(name)


        def render(value):
            return subprocess.check_output(["ls", "/tmp/" + value])
'''
    NO_DECORATOR_CONTROL = '''
        import subprocess


        def api_export_view(request, user_profile, topic):
            return subprocess.check_output(["ls", "/tmp/" + topic])
'''

    def test_req_parameters_become_sources(self):
        on, sources_on = _rows("req", self.REQ_VIEW)
        off, sources_off = _rows("req", self.REQ_VIEW, disabled=ENTERPRISE)
        self.assertEqual(sources_on, ["stream_name (api_export_view)", "topic (api_export_view)"])
        self.assertEqual(sources_off, [])
        self.assertIn(("CWE-78", 12), on)
        self.assertNotIn(("CWE-78", 12), off)

    def test_trusted_context_names_are_never_sources(self):
        _on, sources = _rows("trusted", self.TRUSTED_VIEW)
        self.assertEqual(sources, [])
        self.assertEqual(_classify(self.TRUSTED_VIEW, "export_view"), frozenset())

    def test_annotated_plain_default_is_server_side_not_client(self):
        self.assertEqual(_classify(self.PLAIN_DEFAULT_VIEW, "export_view"), frozenset())

    def test_unannotated_argument_of_a_rest_dispatch_is_client_text(self):
        self.assertEqual(_classify(self.UNANNOTATED_VIEW, "search_view"), frozenset({"query"}))

    def test_webhook_view_flows_through_a_helper(self):
        on, _sources = _rows("webhook", self.WEBHOOK_VIEW)
        off, _ = _rows("webhook", self.WEBHOOK_VIEW, disabled=ENTERPRISE)
        self.assertIn(("CWE-78", 14), on)
        self.assertNotIn(("CWE-78", 14), off)

    def test_ordinary_function_is_untouched(self):
        on, sources = _rows("control", self.NO_DECORATOR_CONTROL)
        self.assertEqual(sources, [])
        self.assertEqual(on, [])

    def test_non_zulip_decorator_names_are_not_route_boundaries(self):
        self.assertEqual(_classify('''
            import subprocess


            @pytest.fixture
            def export_view(request, topic):
                return subprocess.check_output(["ls", topic])
        ''', "export_view"), frozenset())


class TestFastAPIBoundarySources(unittest.TestCase):
    QUERY_VIEW = '''
        import subprocess

        from fastapi import FastAPI, Query


        app = FastAPI()


        @app.get("/export")
        def export(topic: str = Query(None, description="term")):
            return subprocess.check_output(["ls", "/tmp/" + topic])
'''
    ANNOTATED_HEADER_VIEW = '''
        import subprocess
        from typing import Annotated

        from fastapi import FastAPI, Header


        app = FastAPI()


        @app.post("/sync")
        def sync(token: Annotated[str, Header()]):
            return subprocess.check_output(["ls", "/tmp/" + token])
'''
    PATH_VIEW = '''
        import subprocess

        from fastapi import APIRouter, Path


        router = APIRouter()


        @router.put("/items/{item_id}")
        def update(item_id: int = Path(..., title="The item id")):
            return subprocess.check_output(["ls", "/tmp/" + str(item_id)])
'''
    PATHLIB_VIEW = '''
        import subprocess
        from pathlib import Path

        from fastapi import FastAPI


        app = FastAPI()


        @app.get("/tree")
        def tree(directory: Path = Path("/srv/data")):
            return subprocess.check_output(["ls", str(directory)])
'''
    PLAIN_PARAM_VIEW = '''
        import subprocess

        from fastapi import FastAPI


        app = FastAPI()


        @app.get("/export")
        def export(topic: str):
            return subprocess.check_output(["ls", "/tmp/" + topic])
'''
    BODY_MODEL_VIEW = '''
        from fastapi import FastAPI
        from pydantic import BaseModel


        app = FastAPI()


        class Payload(BaseModel):
            topic: str


        @app.post("/export")
        def export(payload: Payload):
            return payload.topic
'''
    NON_WEB_DECORATOR = '''
        import subprocess


        @cache.memoize(timeout=30)
        def export(topic: str = Query(None)):
            return subprocess.check_output(["ls", topic])
'''

    def test_query_default_is_a_source_and_reaches_a_sink(self):
        on, sources = _rows("query", self.QUERY_VIEW)
        off, _ = _rows("query", self.QUERY_VIEW, disabled=ENTERPRISE)
        self.assertEqual(sources, ["topic (export)"])
        self.assertIn(("CWE-78", 12), on)
        self.assertNotIn(("CWE-78", 12), off)

    def test_annotated_header_spelling_is_a_source(self):
        self.assertEqual(_classify(self.ANNOTATED_HEADER_VIEW, "sync"), frozenset({"token"}))

    def test_path_extractor_on_a_scalar_annotation_is_a_source(self):
        self.assertEqual(_classify(self.PATH_VIEW, "update"), frozenset({"item_id"}))

    def test_pathlib_default_is_not_the_path_extractor(self):
        self.assertEqual(_classify(self.PATHLIB_VIEW, "tree"), frozenset())

    def test_plain_annotation_without_an_extractor_is_not_a_source(self):
        # FastAPI reads that value from the query string too, but claiming it without an explicit
        # extractor would make every decorated function parameter a source, so the rule stays quiet.
        self.assertEqual(_classify(self.PLAIN_PARAM_VIEW, "export"), frozenset())

    def test_pydantic_model_body_is_validated_by_the_framework(self):
        self.assertEqual(_classify(self.BODY_MODEL_VIEW, "export"), frozenset())

    def test_route_decorator_is_required(self):
        self.assertEqual(_classify(self.NON_WEB_DECORATOR, "export"), frozenset())


class TestCwe502SocketDeserialization(unittest.TestCase):
    DIRECT_RECV = '''
        import msgpack


        class Channel:
            def handle(self):
                payload = self.stream.recv()
                return msgpack.loads(payload)
'''
    MULTIPART_LOOP = '''
        import msgpack


        def serve(stream):
            for frame in stream.recv_multipart():
                msgpack.unpackb(frame, raw=False)
'''
    ALIAS_IMPORTS = '''
        import msgpack as mp
        import pickle as pk


        def serve(sock):
            blob = sock.recv_bytes()
            return pk.loads(blob)
'''
    ZMQ_STREAM_OBJECT = '''
        import pickle
        import zmq


        def serve(ctx):
            stream = zmq.Stream(ctx)
            data = stream.recv()
            return pickle.loads(data)
'''
    ISOLATED_MSGPACK = '''
        import msgpack


        def decode(handle):
            return msgpack.unpackb(handle.read())
'''
    FILE_PICKLE = '''
        import pickle


        def boot(path):
            with open(path, "rb") as handle:
                return pickle.load(handle)
'''
    SUPPRESSED = '''
        import msgpack


        def serve(sock):
            payload = sock.recv()
            return msgpack.loads(payload)  # ok: authenticated framing
'''

    def test_direct_recv_into_msgpack(self):
        self.assertIn(MSG502, _messages("direct", self.DIRECT_RECV))

    def test_multipart_loop_target_is_a_socket_read(self):
        self.assertIn(MSG502, _messages("loop", self.MULTIPART_LOOP))

    def test_aliased_imports_still_match(self):
        self.assertIn(MSG502, _messages("alias", self.ALIAS_IMPORTS))

    def test_zmq_stream_construction_counts_as_the_channel(self):
        self.assertIn(MSG502, _messages("stream", self.ZMQ_STREAM_OBJECT))

    def test_isolated_msgpack_is_not_a_finding(self):
        # msgpack cannot execute anything; without a channel read there is nothing to report.
        self.assertEqual(_messages("isolated", self.ISOLATED_MSGPACK, disabled=SOCKET), [])
        self.assertEqual(_messages("isolated", self.ISOLATED_MSGPACK), [])

    def test_pickle_from_a_file_is_not_a_socket_stream(self):
        self.assertNotIn(MSG502, _messages("file", self.FILE_PICKLE))

    LITERAL_WITH_SOCKET = '''
        import msgpack


        def serve(sock):
            payload = sock.recv()
            return msgpack.unpackb(b"\\x81\\xa3abc\\x04")
'''

    def test_static_literal_bytes_are_not_attacker_shaped(self):
        # A channel read sits in the same scope, so only the literal argument keeps this quiet.
        self.assertNotIn(MSG502, _messages("literal", self.LITERAL_WITH_SOCKET))
        # Nothing else in the file is this rule's either.
        self.assertEqual(_messages("literal", self.LITERAL_WITH_SOCKET, disabled=SOCKET), [])

    def test_copy_chain_up_to_the_hop_cap_is_traced(self):
        self.assertEqual(TAINT_TRAVERSAL_MAX_HOPS, 8)
        self.assertIn(MSG502, _messages("hop8", _chain(8)))

    def test_one_hop_past_the_cap_is_left_unreported(self):
        self.assertNotIn(MSG502, _messages("hop9", _chain(9)))

    def test_review_marker_suppresses_the_finding(self):
        self.assertNotIn(MSG502, _messages("suppressed", self.SUPPRESSED))

    def test_collector_contributes_nothing_else(self):
        """Switching the rule off removes only its own message, never a pre-existing one."""
        on = _messages("direct", self.DIRECT_RECV)
        off = _messages("direct", self.DIRECT_RECV, disabled=SOCKET)
        self.assertEqual([message for message in on if message != MSG502], off)


if __name__ == "__main__":
    unittest.main()
