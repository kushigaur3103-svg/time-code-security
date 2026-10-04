"""Phase 12: CWE-78 / CWE-95 dethrone strike — dynamic command & code payloads.

Every detector is value-gated: pure literals, literal-only argv lists, shlex-sanitized
values and `# ok:` / `# nosec` suppressed lines must stay completely silent.
"""
from ast_scanner import TaintTracker


def _scan(source: str) -> list[dict]:
    tracker = TaintTracker(files={"test.py": source})
    _s, sinks, edges = tracker.analyze()
    by_id = {x.id: x for x in sinks}
    findings = []
    for edge in edges:
        sink = by_id.get(edge.target_id)
        if sink is None:
            continue
        cwe = (sink.metadata or {}).get("cwe")
        if cwe in ("CWE-78", "CWE-95"):
            findings.append({"line": sink.lineno, "operation": sink.operation, "cwe": cwe})
    return findings


def _cwes(source: str) -> list[str]:
    return [f["cwe"] for f in _scan(source)]


# ------------------------------------------------------------------ mission cases

def test_eval_fstring_with_user_operand_is_cwe95():
    source = '''
def calculate(user_op):
    eval(f"calculate_{user_op}()")
'''
    assert "CWE-95" in _cwes(source)


def test_os_system_concat_is_cwe78():
    source = '''
import os

def ping(host):
    os.system("ping " + host)
'''
    assert "CWE-78" in _cwes(source)


def test_eval_static_constant_is_silent():
    assert _cwes('eval("1 + 1")\n') == []


def test_subprocess_argv_list_without_shell_is_silent():
    source = '''
import subprocess

def list_dir(user_arg):
    subprocess.run(["ls", "-l", user_arg])
'''
    assert _cwes(source) == []


def test_shlex_quoted_fstring_is_silent():
    source = '''
import os
import shlex

def cat(filename):
    os.system(f"cat {shlex.quote(filename)}")
'''
    assert _cwes(source) == []


def test_ok_marker_on_previous_line_suppresses():
    source = '''
import os

def ping(host):
    # ok:code-injection
    os.system("ping " + host)
'''
    assert _cwes(source) == []


# ------------------------------------------------------- os.exec* / os.spawn* payload

def test_spawnl_dynamic_payload_is_cwe78():
    source = '''
import os
import sys

cmd = sys.argv[2]
os.spawnl(os.P_WAIT, "/bin/bash", "-c", cmd)
'''
    assert "CWE-78" in _cwes(source)


def test_spawnve_dynamic_argv_list_is_cwe78():
    source = '''
import os
import sys

cmd = sys.argv[2]
os.spawnve(os.P_WAIT, "/bin/bash", ["-c", cmd], os.environ)
'''
    assert "CWE-78" in _cwes(source)


def test_spawnve_literal_argv_with_environ_is_silent():
    """`os.P_WAIT` and `os.environ` are handles, not command text."""
    source = '''
import os

os.spawnve(os.P_WAIT, "/bin/ls", ["-a"], os.environ)
'''
    assert _cwes(source) == []


def test_execl_all_literal_arguments_is_silent():
    source = '''
import os

os.execl("/foo/bar", "/foo/bar")
os.execv("/foo/bar", ["/foo/bar", "-a", "-b"])
os.execl("static")
'''
    assert _cwes(source) == []


def test_execve_with_call_payload_is_cwe78():
    source = '''
import os
from somewhere import something

os.execve("/bin/bash", ["/bin/bash", "-c", something()], os.environ)
'''
    assert "CWE-78" in _cwes(source)


def test_nosec_on_assignment_line_suppresses_payload():
    source = '''
import os
import sys

# nosec hardcoded command source
cmd = sys.argv[2]
os.spawnl(os.P_WAIT, "/bin/bash", "-c", cmd)
'''
    assert _cwes(source) == []


# ------------------------------------------------------------------- asyncio sinks

def test_loop_subprocess_exec_dynamic_argv_is_cwe78():
    source = '''
import asyncio

def handler(event):
    loop = asyncio.new_event_loop()
    cmd = event["cmd"]
    loop.run_until_complete(loop.subprocess_exec(lambda: P(), ["bash", "-c", cmd]))
'''
    assert "CWE-78" in _cwes(source)


def test_loop_subprocess_exec_literal_argv_is_silent():
    source = '''
import asyncio

def ok_handler(event):
    loop = asyncio.new_event_loop()
    loop.run_until_complete(loop.subprocess_exec(lambda: P(), ["echo", "a"]))
'''
    assert _cwes(source) == []


def test_loop_subprocess_shell_parameter_is_cwe78():
    source = '''
import asyncio

def vuln(shell_command):
    loop = asyncio.new_event_loop()
    loop.run_until_complete(loop.subprocess_shell(lambda: P(), shell_command))
'''
    assert "CWE-78" in _cwes(source)


def test_loop_subprocess_shell_literal_assignment_is_silent():
    source = '''
import asyncio

def ok1():
    shell_command = 'echo "Hello world"'
    loop = asyncio.new_event_loop()
    loop.run_until_complete(loop.subprocess_shell(lambda: P(), shell_command))
'''
    assert _cwes(source) == []


def test_create_subprocess_exec_dynamic_is_cwe78():
    source = '''
import asyncio
import sys

def vuln2():
    program = "bash"
    loop = asyncio.new_event_loop()
    loop.run_until_complete(
        asyncio.subprocess.create_subprocess_exec(program, [program, "-c", sys.argv[1]])
    )
'''
    assert "CWE-78" in _cwes(source)


def test_create_subprocess_exec_literal_alias_is_silent():
    source = '''
import asyncio

def ok1():
    program = "echo"
    loop = asyncio.new_event_loop()
    loop.run_until_complete(asyncio.subprocess.create_subprocess_exec(program, [program, "123"]))
'''
    assert _cwes(source) == []


# --------------------------------------------------------------- sh / airflow / format

def test_sh_wrapper_concat_is_cwe78():
    source = '''
import os
import sh

long = os.environ.get("LONG", "")
sh.ls("-a" + long)
'''
    assert "CWE-78" in _cwes(source)


def test_sh_wrapper_literal_is_silent():
    source = '''
import sh

sh.ls("-al")
sh.semgrep("--config", "https://semgrep.dev/p/r2c-CI")
'''
    assert _cwes(source) == []


def test_sh_wrapper_starred_argv_is_silent():
    source = '''
import os
import sh

confurl = os.environ.get("SEMGREP_CONFIG_URL", "")
args = ["--config", confurl]
sh.semgrep(*args)
'''
    assert _cwes(source) == []


def test_bash_operator_dynamic_command_is_cwe78():
    source = '''
import requests
from airflow.operators.bash_operator import BashOperator

message = requests.get("https://fakeurl.asdf/message").text
BashOperator(task_id="print_date", bash_command="echo " + message)
'''
    assert "CWE-78" in _cwes(source)


def test_bash_operator_literal_command_is_silent():
    source = '''
from airflow.operators.bash_operator import BashOperator

BashOperator(task_id="safe", bash_command="echo hello world!")
'''
    assert _cwes(source) == []


def test_bash_operator_static_template_is_silent():
    source = '''
from airflow.operators.bash_operator import BashOperator

templated_command = """
{% for i in range(5) %}
    echo "{{ ds }}"
{% endfor %}
"""
BashOperator(task_id="safe_templated", bash_command=templated_command)
'''
    assert _cwes(source) == []


def test_eval_of_format_call_is_cwe95():
    """A `str.format(...)` result is constructed program text even with literal arguments."""
    source = '''
dynamic = "import requests; r = requests.get('{}')"
eval(dynamic.format("https://example.com"))
'''
    assert "CWE-95" in _cwes(source)


def test_eval_of_literal_alias_is_silent():
    source = '''
blah = "import requests; r = requests.get('https://example.com')"
eval(blah)
'''
    assert _cwes(source) == []


def test_paramiko_exec_command_dynamic_name_is_cwe78():
    source = '''
import paramiko

client = paramiko.client.SSHClient()
client.connect("somehost")
client.exec_command(user_input)
'''
    assert "CWE-78" in _cwes(source)


def test_paramiko_exec_command_literal_is_silent():
    source = '''
import paramiko

client = paramiko.client.SSHClient()
client.exec_command("ls -r /")
'''
    assert _cwes(source) == []


def test_paramiko_exec_command_ok_annotated_dynamic_is_silent():
    source = '''
import paramiko

client = paramiko.client.SSHClient()
# ok:paramiko-exec-command
client.exec_command(user_input)
'''
    assert _cwes(source) == []
