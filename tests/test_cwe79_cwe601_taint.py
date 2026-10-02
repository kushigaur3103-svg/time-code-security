"""
Unit tests for CWE-79 (Cross-Site Scripting) and CWE-601 (Open Redirect).

Verifies:
1. CWE-601:
   - Safe redirect with is_safe_url and url_has_allowed_host_and_scheme.
   - Safe redirect with relative request paths (request.path, request.full_path, request.get_full_path()).
   - Unsafe redirect flagged as CWE-601 and NOT misclassified as CWE-79.
2. CWE-79:
   - render_template with unescaped extensions (.txt, .csv, .xml, .json, .sql) and context variables.
   - render_template with .html/.htm is safe (autoescaped by default in Jinja).
   - render_template without context variables is safe.
   - Direct template rendering (render_template_string, mako.template.Template, jinja2.Template.render).
   - Misused format_html with f-string or string formatting on first argument.
   - Safe format_html using positional arguments.
   - Raw dynamic HTML responses (HttpResponse, make_response) vs safe static/JSON responses.
"""

from ast_scanner import TaintTracker


def _get_findings_by_cwe(code: str, filename: str = "app.py") -> dict[str, list]:
    tracker = TaintTracker(files={filename: code})
    _, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    findings: dict[str, list] = {}
    for edge in edges:
        sink = by_id.get(edge.target_id)
        if not sink:
            continue
        cwe = (sink.metadata or {}).get("cwe")
        if not cwe and edge.proof_graph is not None:
            cwe = edge.proof_graph.cwe
        if cwe:
            findings.setdefault(cwe, []).append(sink)
    return findings


# ---------------------------------------------------------------------------
# CWE-601 (Open Redirect) Tests
# ---------------------------------------------------------------------------

def test_safe_redirect_is_safe_url():
    code = """
from django.http import HttpResponseRedirect
from django.utils.http import is_safe_url

def my_view(request):
    next_url = request.GET.get('next')
    if is_safe_url(next_url, allowed_hosts={'example.com'}):
        return HttpResponseRedirect(next_url)
    return HttpResponseRedirect('/')
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-601" not in findings
    assert "CWE-79" not in findings


def test_safe_redirect_url_has_allowed_host_and_scheme():
    code = """
from django.http import HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme

def my_view(request):
    next_url = request.GET.get('next')
    if url_has_allowed_host_and_scheme(next_url, allowed_hosts={'example.com'}):
        return HttpResponseRedirect(next_url)
    return HttpResponseRedirect('/')
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-601" not in findings
    assert "CWE-79" not in findings


def test_safe_redirect_request_relative_paths():
    code = """
from django.http import HttpResponseRedirect
from flask import redirect, request

def django_view(req):
    return HttpResponseRedirect(req.get_full_path())

def flask_view():
    return redirect(f"{request.path}/")

def flask_view_concat():
    return redirect(request.path + "?retry=1")
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-601" not in findings
    assert "CWE-79" not in findings


def test_unsafe_redirect_detected_as_cwe601_not_cwe79():
    code = """
from django.http import HttpResponseRedirect

def unsafe_view(request):
    target = request.GET.get('next')
    return HttpResponseRedirect(target)
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-601" in findings
    assert "CWE-79" not in findings


def test_unsafe_flask_redirect_detected():
    code = """
from flask import redirect, request

def unsafe_flask_view():
    url = request.args.get('target')
    return redirect(url)
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-601" in findings


# ---------------------------------------------------------------------------
# CWE-79 (Cross-Site Scripting) Tests
# ---------------------------------------------------------------------------

def test_render_template_unescaped_extension_positive():
    code = """
from flask import render_template, request

def txt_view():
    user_input = request.args.get('name')
    return render_template('memo.txt', name=user_input)

def csv_view():
    data = request.args.get('data')
    return render_template('export.csv', content=data)

def xml_view():
    payload = request.args.get('xml')
    return render_template('doc.xml', payload=payload)
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-79" in findings
    assert len(findings["CWE-79"]) >= 3


def test_render_template_html_autoescaped_safe():
    code = """
from flask import render_template, request

def safe_html_view():
    user_input = request.args.get('name')
    return render_template('index.html', name=user_input)

def safe_htm_view():
    user_input = request.args.get('name')
    return render_template('profile.htm', name=user_input)
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-79" not in findings


def test_render_template_no_context_safe():
    code = """
from flask import render_template

def static_view():
    return render_template('notice.txt')
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-79" not in findings


def test_render_template_string_positive():
    code = """
from flask import render_template_string, request

def dynamic_template_view():
    tpl = request.args.get('template')
    return render_template_string(tpl)
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-79" in findings


def test_mako_template_positive():
    code = """
from mako.template import Template
from flask import request

def mako_view():
    tpl_source = request.args.get('tpl')
    return Template(tpl_source).render()
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-79" in findings


def test_jinja2_template_render_positive():
    code = """
import jinja2
from flask import request

def jinja_view():
    raw_tpl = request.args.get('tpl')
    return jinja2.Template(raw_tpl).render()
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-79" in findings


def test_format_html_misuse_positive():
    code = """
from django.utils.html import format_html
from flask import request

def fstring_view():
    name = request.args.get('name')
    return format_html(f"<b>{name}</b>")

def percent_view():
    name = request.args.get('name')
    return format_html("<b>%s</b>" % name)

def format_view():
    name = request.args.get('name')
    return format_html("<b>{}</b>".format(name))
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-79" in findings
    assert len(findings["CWE-79"]) >= 3


def test_format_html_proper_usage_safe():
    code = """
from django.utils.html import format_html
from flask import request

def safe_format_html_view():
    name = request.args.get('name')
    return format_html("<b>{}</b>", name)

def safe_kwargs_format_html_view():
    name = request.args.get('name')
    return format_html("<b>{user}</b>", user=name)
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-79" not in findings


def test_raw_dynamic_response_positive():
    code = """
from django.http import HttpResponse
from flask import make_response, request

def django_raw(req):
    user = req.GET.get('user')
    return HttpResponse(f"Hello {user}")

def flask_raw():
    user = request.args.get('user')
    return make_response(f"Hello {user}")
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-79" in findings
    assert len(findings["CWE-79"]) >= 2


def test_raw_response_safe_cases():
    code = """
import json
from django.http import HttpResponse
from flask import make_response

def static_django(req):
    return HttpResponse("<h1>Static Hello</h1>")

def static_flask():
    return make_response("<h1>Static Hello</h1>")

def json_django(req):
    data = req.GET.get('data')
    return HttpResponse(json.dumps({"result": data}), content_type="application/json")
"""
    findings = _get_findings_by_cwe(code)
    assert "CWE-79" not in findings
