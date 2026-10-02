"""Unit tests for CWE-95 Dynamic Code Execution Sinks and Taint Tracking."""

import pytest
from ast_scanner import TaintTracker


def test_interactive_console_push_tainted():
    code = """
import code
import flask

app = flask.Flask(__name__)

@app.route("/execute/<payload>")
def run_code(payload):
    console = code.InteractiveConsole()
    console.push(payload)
    return "ok"
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    assert len(sinks) >= 1
    assert any(
        s.metadata.get("cwe") == "CWE-95" and s.metadata.get("operation") == "DYNAMIC_CODE_EXECUTION"
        for s in sinks
    )
    assert len(edges) >= 1
    assert any(e.kind == "CONFIRMED_DATA_FLOW" for e in edges)


def test_interactive_console_push_literal_safe():
    code = """
import code

def safe():
    console = code.InteractiveConsole()
    console.push("print(123)")
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    # Literal argument must not produce any data flow edge or finding
    assert len(edges) == 0


def test_subinterpreters_run_string_tainted():
    code = """
import _xxsubinterpreters
import flask

app = flask.Flask(__name__)

@app.route("/run/<cmd>")
def run_sub(cmd):
    sub_id = _xxsubinterpreters.create()
    _xxsubinterpreters.run_string(sub_id, cmd)
    return "done"
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    assert len(sinks) >= 1
    cwe95_sinks = [s for s in sinks if s.metadata.get("cwe") == "CWE-95"]
    assert len(cwe95_sinks) >= 1
    assert cwe95_sinks[0].metadata.get("target_arg") == 1
    assert len(edges) >= 1


def test_subinterpreters_run_string_literal_safe():
    code = """
import _xxsubinterpreters

def safe():
    sub_id = _xxsubinterpreters.create()
    _xxsubinterpreters.run_string(sub_id, "print('hello')")
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    assert len(edges) == 0


def test_testcapi_run_in_subinterp_tainted():
    code = """
import _testcapi
import flask

app = flask.Flask(__name__)

@app.route("/test/<payload>")
def run_test(payload):
    _testcapi.run_in_subinterp(payload)
    return "ok"
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    assert len(sinks) >= 1
    assert any(s.metadata.get("cwe") == "CWE-95" for s in sinks)
    assert len(edges) >= 1


def test_testcapi_run_in_subinterp_literal_safe():
    code = """
import _testcapi

def safe():
    _testcapi.run_in_subinterp("print('test')")
"""
    tracker = TaintTracker(files={"app.py": code})
    _, sinks, edges = tracker.analyze()
    assert len(edges) == 0


def test_run_in_executor_exec_tainted():
    code = """
import asyncio

async def handle(request):
    code_str = request.POST.get("code")
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, exec, code_str)
"""
    tracker = TaintTracker(files={"views.py": code})
    _, sinks, edges = tracker.analyze()
    cwe95_sinks = [s for s in sinks if s.metadata.get("cwe") == "CWE-95"]
    assert len(cwe95_sinks) >= 1
    assert cwe95_sinks[0].metadata.get("target_arg") == 2
    assert len(edges) >= 1


def test_run_in_executor_exec_literal_safe():
    code = """
import asyncio

async def handle_safe():
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, exec, "print('safe')")
"""
    tracker = TaintTracker(files={"views.py": code})
    _, sinks, edges = tracker.analyze()
    assert len(edges) == 0


def test_run_in_executor_non_code_func_safe():
    code = """
import asyncio

def my_worker(x):
    return x * 2

async def handle_worker(request):
    val = request.POST.get("val")
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, my_worker, val)
"""
    tracker = TaintTracker(files={"views.py": code})
    _, sinks, edges = tracker.analyze()
    cwe95_sinks = [s for s in sinks if s.metadata.get("cwe") == "CWE-95"]
    assert len(cwe95_sinks) == 0


def test_compile_command_tainted_and_safe():
    tainted_code = """
import code

def handle(user_input: str):
    code.compile_command(user_input)
"""
    tracker = TaintTracker(files={"mod.py": tainted_code})
    _, _, edges = tracker.analyze()
    assert len(edges) >= 1

    safe_code = """
import code

def safe():
    code.compile_command("x = 1")
"""
    tracker_safe = TaintTracker(files={"mod.py": safe_code})
    _, _, safe_edges = tracker_safe.analyze()
    assert len(safe_edges) == 0
