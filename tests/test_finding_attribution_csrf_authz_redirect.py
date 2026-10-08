"""Finding-attribution contracts for three structural rules, measured before they were written.

All numbers below come from running the shipped engine (`TaintTracker(..., audit_all=True)`) against
the snippets, plus a full scan of NetSPI/django.nV (50 `.py` + 51 `.html` files, `python cli.py scan`):

    django.nV total findings   56 -> 36
    CWE-352                    12 ->  8   (4 exempt views were charged twice: decorator line + def line)
    CWE-862                    22 -> 15   (7 extra hits: a view reading 3 rows reported 3 defects)
    CWE-601                    10 ->  1   (9 were `redirect('/taskManager/' + project_id + '/')`)

The surviving CWE-601 finding is views.py:387, `redirect(request.GET.get('redirect', ...))`, which is
the target's real open redirect. Everything else this file pins is a boundary rule: one finding per
view, charged to the view, and no host injection possible through a same-origin relative Location.
"""

from ast_scanner import TaintTracker

CSRF_CWE = "CWE-352"
AUTHZ_CWE = "CWE-862"
REDIRECT_CWE = "CWE-601"

BARE_EXEMPT = """from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def profile_by_id(request, user_id):
    if request.method == 'POST':
        form = ProfileForm(request.POST)
        form.save()
    return render(request, 'p.html')
"""

DOTTED_EXEMPT = """from flask_wtf import csrf

@csrf.exempt
def transfer(request):
    if request.method == 'POST':
        db.transfer(request.form['amount'])
    return render(request, 't.html')
"""

EXEMPT_READ_ONLY = """from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def read_only(request, user_id):
    user = User.objects.get(pk=user_id)
    return render(request, 'p.html')
"""

PLAIN_POST_ROUTE = """from flask import request, render_template

@app.route('/transfer', methods=['POST'])
def transfer():
    amount = request.form['amount']
    return render_template('t.html', amount=amount)
"""

THREE_FETCHES = """def note_edit(request, project_id, task_id, note_id):
    proj = Project.objects.get(pk=project_id)
    task = Task.objects.get(pk=task_id)
    note = Notes.objects.get(pk=note_id)
    return render(request, 'n.html')
"""

TWO_VIEWS = """def a_view(request, pk):
    obj = Thing.objects.get(pk=pk)
    other = Other.objects.get(pk=pk)
    return obj

def b_view(request, pk):
    third = Thing.objects.get(pk=pk)
    return third
"""

DECORATED_VIEW = """from django.contrib.auth.decorators import login_not_required

@some_decorator
def c_view(request, pk):
    obj = Thing.objects.get(pk=pk)
    other = Thing.objects.get(pk=pk)
    return obj
"""

GUARDED_VIEW = """from django.contrib.auth.decorators import login_required

@login_required
def safe_view(request, pk):
    obj = Thing.objects.get(pk=pk)
    other = Thing.objects.get(pk=pk)
    return obj
"""

MODULE_LEVEL_FETCH = """order_id = request.args.get("id")
order = Order.objects.get(pk=order_id)
"""

REDIRECT_HEAD = """from django.shortcuts import redirect

def go(request, project_id):
    return redirect(%s)
"""


def _findings(code, cwe):
    tracker = TaintTracker(files={"sample.py": code}, audit_all=True)
    _sources, sinks, edges = tracker.analyze()
    by_id = {sink.id: sink for sink in sinks}
    return sorted({(by_id[edge.target_id].location.line_start, by_id[edge.target_id].symbol)
                   for edge in edges
                   if edge.target_id in by_id
                   and by_id[edge.target_id].metadata.get("cwe") == cwe})


def _lines(code, cwe):
    return {line for line, _symbol in _findings(code, cwe)}


def _redirect(code):
    return _findings(REDIRECT_HEAD % code, REDIRECT_CWE)


class TestCsrfExemptViewIsChargedOnce:
    def test_bare_exempt_yields_exactly_one_finding(self):
        assert len(_findings(BARE_EXEMPT, CSRF_CWE)) == 1

    def test_bare_exempt_is_charged_to_the_decorator(self):
        # The canonical emitter is Cluster 3's CSRF_EXEMPT_VIEW, anchored on `@csrf_exempt` itself.
        assert _findings(BARE_EXEMPT, CSRF_CWE) == [(3, "CSRF_EXEMPT_VIEW")]

    def test_dotted_exempt_is_still_reported(self):
        # Cluster 3 matches a decorator whose last segment is `csrf_exempt`; `@csrf.exempt` ends in
        # `exempt`, so it is NOT covered there. Dropping it here would be a false negative
        # (benchmark/corpus/cwe_352_csrf/test_v04_bad.py is exactly this shape).
        assert _findings(DOTTED_EXEMPT, CSRF_CWE) == [(4, "CSRF_MISSING_PROTECTION")]

    def test_read_only_exempt_view_still_gets_one_finding(self):
        assert len(_findings(EXEMPT_READ_ONLY, CSRF_CWE)) == 1

    def test_plain_state_changing_route_is_untouched(self):
        # Control: the missing-protection rule without an exempt decorator keeps its old behaviour.
        assert _findings(PLAIN_POST_ROUTE, CSRF_CWE) == [(4, "CSRF_MISSING_PROTECTION")]


class TestMissingAuthorizationIsChargedToTheView:
    def test_three_object_fetches_produce_one_finding(self):
        assert len(_findings(THREE_FETCHES, AUTHZ_CWE)) == 1

    def test_the_single_finding_names_the_view_not_a_statement(self):
        assert _lines(THREE_FETCHES, AUTHZ_CWE) == {1}

    def test_two_unguarded_views_produce_two_findings(self):
        # The debounce is per function, not per file.
        assert _lines(TWO_VIEWS, AUTHZ_CWE) == {1, 6}

    def test_decorated_view_is_charged_to_the_decorator(self):
        assert _lines(DECORATED_VIEW, AUTHZ_CWE) == {3}

    def test_module_level_fetch_still_reports_at_its_own_line(self):
        # No enclosing FunctionDef: nothing to relocate to, the statement line is kept.
        assert _lines(MODULE_LEVEL_FETCH, AUTHZ_CWE) == {2}

    def test_guarded_view_still_reports_nothing(self):
        # Control: `@login_required` suppresses every fetch in the view, not just the extras.
        assert _findings(GUARDED_VIEW, AUTHZ_CWE) == []


class TestOpenRedirectRelativeDestinationCarveOut:
    def test_literal_anchor_plus_route_parameter_is_not_a_finding(self):
        assert _redirect("'/taskManager/' + project_id + '/'") == []

    def test_fstring_anchor_plus_route_parameter_is_not_a_finding(self):
        assert _redirect("f'/taskManager/{project_id}/'") == []

    def test_pure_constant_destination_is_not_a_finding(self):
        assert _redirect("'/home'") == []

    def test_protocol_relative_anchor_is_still_a_finding(self):
        # `//host/…` is resolved against another origin, so the same-origin proof does not hold.
        assert len(_redirect("'//host/' + project_id")) == 1

    def test_request_component_is_still_a_finding(self):
        assert len(_redirect("'/x/' + request.GET['next']")) == 1

    def test_input_component_is_still_a_finding(self):
        assert len(_redirect("'/x/' + input()")) == 1

    def test_destination_that_is_only_a_parameter_is_still_a_finding(self):
        # No literal anchor at all: nothing proves the destination stays on this origin.
        code = """from flask import redirect

def go(request, next_url):
    return redirect(next_url)
"""
        assert len(_findings(code, REDIRECT_CWE)) == 1
