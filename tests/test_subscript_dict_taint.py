"""Regression tests for Subscript / dict-method taint handling on command sinks.

Two opposite guarantees, both measured through the real engine:

1. Taint propagation (no false negatives): indexing or `.get()`-ing a tainted object must
   still reach the sink, whether the object is a serverless `event` parameter or a value
   read off the request.
2. Literal folding (no false positives): an inline container whose members are all literals
   is still a literal — `os.system({"cmd": "ls"}["cmd"])` has no hole for attacker input.

The boundary is deliberate: a dict bound to a *name* is never folded, because subscript
stores are recorded under `d[key]` rather than `d`, so `d[attacker_key] = evil` would be
invisible to a name-bound fold. Folding names would trade a false positive for a false
negative, which a security scanner must not do.
"""

from ast_scanner import TaintTracker


def _cwes(code):
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    by_id = {sink.id: sink for sink in sinks}
    return {by_id[edge.target_id].metadata.get("cwe")
            for edge in edges if edge.target_id in by_id}


def test_handler_event_subscript_flags_command_injection():
    assert "CWE-78" in _cwes("""
import os


def handler(event, context):
    os.system(event["cmd"])
""")


def test_handler_event_dict_get_flags_command_injection():
    assert "CWE-78" in _cwes("""
import os


def lambda_handler(event, context):
    os.system(event.get("cmd"))
""")


def test_request_backed_dict_subscript_flags_command_injection():
    assert "CWE-78" in _cwes("""
import os
import flask

app = flask.Flask(__name__)


@app.route("/run")
def run():
    data = flask.request.get_json()
    os.system(data["cmd"])
""")


def test_tainted_container_key_flags_command_injection():
    """The attacker chooses *which* slot to read: `d[user_key]` is still untrusted."""
    assert "CWE-78" in _cwes("""
import os
import flask

app = flask.Flask(__name__)


@app.route("/run")
def run():
    os.system({"cmd": "ls"}[flask.request.args["k"]])
""")


def test_tainted_value_inside_inline_dict_flags_command_injection():
    """The fold must stop at the first non-literal member, not fold the whole dict anyway."""
    assert "CWE-78" in _cwes("""
import os
import flask

app = flask.Flask(__name__)


@app.route("/run")
def run():
    os.system({"cmd": flask.request.args.get("c")}["cmd"])
""")


def test_mutated_name_bound_dict_still_flags_command_injection():
    """`d["cmd"] = request…` after a literal initialisation is the reason names stay unfolded."""
    assert "CWE-78" in _cwes("""
import os
import flask

app = flask.Flask(__name__)

d = {"cmd": "ls"}


@app.route("/run")
def run():
    d["cmd"] = flask.request.args.get("c")
    os.system(d["cmd"])
""")


def test_inline_literal_dict_subscript_is_clean():
    assert "CWE-78" not in _cwes("""
import os

os.system({"cmd": "ls"}["cmd"])
""")


def test_inline_literal_list_index_is_clean():
    assert "CWE-78" not in _cwes("""
import os

os.system(["ls", "pwd"][0])
""")


def test_inline_literal_dict_get_is_clean():
    assert "CWE-78" not in _cwes("""
import os

os.system({"cmd": "ls"}.get("cmd"))
""")


def test_pure_literal_command_stays_clean():
    assert "CWE-78" not in _cwes("""
import os

os.system("ls")
""")
