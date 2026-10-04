"""Level 2 clean-code guards: real open-source libraries must not pay for engine noise.

Three suppression contexts, each with a reportable control right next to it:

  CWE-916/759  a digest declared `usedforsecurity=False` (HTTP digest-auth) is not a password hash
  CWE-94       a pytest fixture importing the module it parametrises is not code injection
  CWE-918      an HTTP client's own transport layer is not a web request handler
"""

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ast_scanner import TaintTracker


def _sites(code: str, filename: str, cwe: str) -> list[int]:
    tracker = TaintTracker(files={filename: code})
    tracker.analyze()
    return sorted({sink.location.line_start for sink in tracker.sinks
                   if sink.metadata.get("cwe") == cwe})


DIGEST_MODULE = '''
import hashlib

NOT_FOR_SECURITY = False


class HTTPDigestAuth:
    def md5_utf8(self, x):
        return hashlib.md5(x, usedforsecurity=False).hexdigest()

    def sha1_utf8(self, x):
        return hashlib.sha1(x, usedforsecurity=False).hexdigest()

    def via_constant(self, x):
        return hashlib.md5(x, usedforsecurity=NOT_FOR_SECURITY).hexdigest()

    def report_plain(self, password):
        return hashlib.md5(password).hexdigest()

    def report_declared_secure(self, password):
        return hashlib.sha1(password, usedforsecurity=True).hexdigest()
'''


@pytest.mark.parametrize("cwe", ["CWE-916", "CWE-759"])
def test_usedforsecurity_false_is_not_a_password_hash(cwe):
    assert _sites(DIGEST_MODULE, "src/requests/auth.py", cwe) == [18, 21]


FASTAPI_TUTORIAL_FIXTURE = '''
import importlib
import pytest


@pytest.fixture(name="client")
def get_client(request: pytest.FixtureRequest):
    mod = importlib.import_module(f"docs_src.body.{request.param}")
    return mod.app


@pytest.fixture(name="main_mod")
def get_main_mod(mod_path: str):
    return importlib.import_module(f"docs_src.settings.{mod_path}.main")


@pytest.fixture(name="mod")
def get_mod(request):
    name = f"docs_src.x.{request.param}"
    return importlib.import_module(name)
'''

CORPUS_DYNAMIC_IMPORT = '''
import importlib


class Loader:
    def __init__(self, m):
        self.module = m

    def load(self):
        importlib.import_module(self.module)


name = input("m: ")
Loader(name).load()
'''


@pytest.mark.parametrize("filename", [
    "tests/test_tutorial/test_body/test_tutorial001.py",
    "tests/conftest.py",
    "app/modules_test.py",
])
def test_pytest_parametrised_module_import_is_not_code_injection(filename):
    assert _sites(FASTAPI_TUTORIAL_FIXTURE, filename, "CWE-94") == []


def test_dynamic_import_in_a_test_file_that_is_not_fixture_supplied_still_reports():
    code = CORPUS_DYNAMIC_IMPORT + '''
import pytest


@pytest.mark.parametrize("value", ["a"])
def test_ok(value):
    assert value
'''
    assert _sites(code, "tests/test_mods.py", "CWE-94")
    assert _sites(CORPUS_DYNAMIC_IMPORT, "benchmark/corpus/cwe_94_codei_load/test_v04_bad.py", "CWE-94")


def test_dynamic_import_outside_a_test_module_still_reports():
    assert _sites(FASTAPI_TUTORIAL_FIXTURE, "docs_src/registry.py", "CWE-94")


def test_a_pytest_module_reading_a_live_web_request_still_reports():
    code = '''
import importlib
import pytest
from flask import request


@pytest.fixture
def client(request):
    return importlib.import_module(request.args["module"])
'''
    assert _sites(code, "tests/test_mods.py", "CWE-94")


ADAPTER_TRANSPORT = '''
import requests


class HTTPAdapter:
    def send(self, request, stream=False):
        return requests.get(request.url).content
'''


@pytest.mark.parametrize("filename", [
    "src/requests/adapters.py",
    "src/requests/sessions.py",
    "src/urllib3/connectionpool.py",
    "src/urllib3/poolmanager.py",
])
def test_http_client_transport_layer_is_not_an_ssrf_surface(filename):
    assert _sites(ADAPTER_TRANSPORT, filename, "CWE-918") == []


def test_the_same_fetch_in_an_application_module_still_reports():
    assert _sites(ADAPTER_TRANSPORT, "myshop/sessions.py", "CWE-918")
    assert _sites(ADAPTER_TRANSPORT, "myshop/adapters.py", "CWE-918")


def test_handler_passing_user_input_to_a_client_library_still_reports_ssrf():
    code = '''
from flask import request
import requests


@app.route("/proxy")
def proxy():
    return requests.get(request.args["url"]).text
'''
    assert _sites(code, "myapp/views.py", "CWE-918")
