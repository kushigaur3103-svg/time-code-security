"""API-safe CWE-352 guard: stateless JSON routers must stay silent on missing CSRF.

A cookie-bound cross-site request cannot ride a FastAPI/Starlette/ninja route that
authenticates with a bearer token, so "this route lacks CSRF protection" is noise there.
Traditional session/cookie web views (Django `@csrf_exempt`, Flask form routes) keep
reporting — that is the population the guard must not touch.
"""

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ast_scanner import TaintTracker


FASTAPI_ROUTER = '''
from fastapi import FastAPI, APIRouter

router = APIRouter()
app = FastAPI()

@router.post("/items")
def create(payload: dict):
    return payload

@app.get("/status")
def status():
    return {"ok": True}
'''

FASTAPI_WITH_CSRF_EXEMPT = '''
from fastapi import FastAPI
from django.views.decorators.csrf import csrf_exempt

app = FastAPI()

@csrf_exempt
@app.post("/hook")
def hook(payload: dict):
    return payload
'''

STARLETTE_APP = '''
from starlette.applications import Starlette
from starlette.routing import Route

async def update(request):
    return {"ok": True}

app = Starlette(routes=[Route("/update", update, methods=["POST"])])
'''

NINJA_API = '''
from ninja import NinjaAPI

api = NinjaAPI()

@api.post("/webhook")
def webhook(request, payload: dict):
    return payload
'''

DJANGO_CSRF_EXEMPT = '''
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render

@csrf_exempt
def upload_view(request):
    if request.method == "POST":
        return render(request, "upload.html", {"name": request.POST["name"]})
    return render(request, "upload.html")
'''

FLASK_POST_ROUTE = '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    return request.form["username"]
'''

def _csrf_sites(code: str, filename: str = "svc.py") -> list[tuple[int, str]]:
    tracker = TaintTracker(files={filename: code})
    tracker.analyze()
    return sorted(
        {(sink.location.line_start, sink.metadata.get("operation") or "")
         for sink in tracker.sinks if sink.metadata.get("cwe") == "CWE-352"}
    )


@pytest.mark.parametrize("code", [FASTAPI_ROUTER, FASTAPI_WITH_CSRF_EXEMPT, STARLETTE_APP, NINJA_API],
                         ids=["fastapi-routes", "fastapi-plus-csrf-exempt", "starlette", "ninja"])
def test_json_api_routers_emit_no_csrf_finding(code: str):
    assert _csrf_sites(code) == []


@pytest.mark.parametrize("code", [DJANGO_CSRF_EXEMPT, FLASK_POST_ROUTE],
                         ids=["django-csrf-exempt", "flask-post-route"])
def test_traditional_web_views_still_report(code: str):
    assert _csrf_sites(code), "regression: a session/cookie web view went quiet"


def test_django_exempt_view_reports_on_or_above_the_decorator():
    sites = _csrf_sites(DJANGO_CSRF_EXEMPT)
    assert sites and all(line <= 6 for line, _ in sites)


def test_flask_post_route_reports_on_the_route_decorator():
    sites = _csrf_sites(FLASK_POST_ROUTE)
    assert sites and all(line <= 7 for line, _ in sites)


def test_guard_is_scoped_to_the_module_that_imports_the_framework():
    """A Django view in another module must not be silenced by a sibling FastAPI module."""
    tracker = TaintTracker(files={"api.py": FASTAPI_ROUTER, "legacy_views.py": DJANGO_CSRF_EXEMPT})
    tracker.analyze()
    django_sites = {sink.location.file for sink in tracker.sinks if sink.metadata.get("cwe") == "CWE-352"}
    assert any("legacy_views.py" in path for path in django_sites), sorted(django_sites)
    assert not any(path.endswith("api.py") for path in django_sites), sorted(django_sites)


def test_other_cwe_families_are_unaffected_inside_a_fastapi_module():
    """The guard is CSRF-only: a real sink in the same FastAPI file still reports."""
    code = FASTAPI_ROUTER + '''
import pickle

def replay(blob):
    return pickle.loads(blob)
'''
    tracker = TaintTracker(files={"svc.py": code})
    sources, sinks, edges = tracker.analyze()
    cwes = {sink.metadata.get("cwe") for sink in sinks}
    assert "CWE-502" in cwes
    assert "CWE-352" not in cwes
