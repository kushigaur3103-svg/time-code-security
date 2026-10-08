"""Regression contracts for the two blind-spot fixes measured on NetSPI/django.nV.

Measured evidence behind these tests (all numbers produced by running the code here):

* CWE-20 (Django raw request data after validation) was a complete engine blind spot: a scan
  of django.nV before the fix reported 36 findings across 10 distinct CWEs and zero CWE-20,
  while Semgrep's `django-using-request-post-after-is-valid` reported the reads at
  `taskManager/views.py` 178/718/724. After adding `_collect_django_post_validation_findings`
  the same scan reports 50 findings across 11 CWEs, with CWE-20 at
  [178, 179, 718, 719, 720, 721, 722, 723, 724, 725, 726, 727, 728, 730] - every one of them a
  raw `request.POST` / `request.FILES` read inside `if form.is_valid():`. Gate 1 stayed at
  552 cases / 0 FP / 0 FN / 4-4 GREEN, and no corpus fixture contains `is_valid` at all, which
  is why the new rule cannot move the benchmark.
* Template CSRF: `html_auditor.py` matched its token markers case-sensitively against character
  data only. Two protected shapes were therefore reported as vulnerable: `{% CSRF_TOKEN %}` and
  the pre-rendered `<input type="hidden" name="csrfmiddlewaretoken">`, whose value lives in an
  attribute and so never reaches `handle_data`. Both are pinned below, next to the shapes that
  must still be reported.

Note on the reported "blind spot" for `manage_groups.html:11` and `task_edit.html:18`: those
forms DO contain `{% csrf_token %}` (lines 12 and 19), so not flagging them is correct. The
Semgrep rule `django-no-csrf-token` (generic mode, `pattern-not-inside` exclusion, metadata
`confidence: MEDIUM`, `subcategory: audit`) misses its own exclusion there. These tests pin the
protected forms as *not reported*; changing that would manufacture false positives.
"""

from __future__ import annotations

import unittest

from ast_scanner import TaintTracker
from html_auditor import audit_template

CWE20 = "CWE-20"
CWE352 = "CWE-352"
MESSAGE = ("CWE-20: Direct use of raw request.POST after form.is_valid();"
           " use form.cleaned_data instead")


def _findings(code: str, cwe: str):
    """Sorted {(line, symbol)} for every taint edge pointing at a `cwe` sink."""
    tracker = TaintTracker(files={"sample.py": code}, audit_all=True)
    _sources, sinks, edges = tracker.analyze()
    by_id = {sink.id: sink for sink in sinks}
    return sorted({(by_id[edge.target_id].location.line_start,
                    by_id[edge.target_id].symbol)
                   for edge in edges
                   if edge.target_id in by_id
                   and by_id[edge.target_id].metadata.get("cwe") == cwe})


def _lines(code: str, cwe: str):
    return {line for line, _symbol in _findings(code, cwe)}


def _messages(code: str, cwe: str):
    tracker = TaintTracker(files={"sample.py": code}, audit_all=True)
    _sources, sinks, _edges = tracker.analyze()
    return {sink.metadata.get("message") for sink in sinks
            if sink.metadata.get("cwe") == cwe}


VIEW = (
    "from django.shortcuts import render\n"
    "from taskManager.forms import ProfileForm\n"
    "\n"
    "def edit_profile(request):\n"
    "    form = ProfileForm(request.POST)\n"
    "    if form.is_valid():\n"
)


class TestCwe20RawRequestAfterValidatedForm(unittest.TestCase):
    """`is_valid()` fills `form.cleaned_data`; the request multi-dict stays raw client input."""

    def test_get_call_inside_validated_body_is_reported_at_the_read(self):
        code = VIEW + "        username = request.POST.get('username')\n        return render(request, 'a.html')\n"
        self.assertEqual(_lines(code, CWE20), {7}, "anchor is the request.POST read, not the if")

    def test_subscript_inside_validated_body_is_reported(self):
        code = VIEW + "        name = request.POST['name']\n"
        self.assertEqual(_lines(code, CWE20), {7})

    def test_every_distinct_read_is_reported_once(self):
        code = (VIEW
                + "        a = request.POST.get('a')\n"
                  "        b = request.POST.get('b')\n"
                  "        c = request.FILES['file']\n")
        self.assertEqual(_lines(code, CWE20), {7, 8, 9})
        self.assertEqual(_findings(code, CWE20),
                         [(7, "IMPROPER_INPUT_VALIDATION"),
                          (8, "IMPROPER_INPUT_VALIDATION"),
                          (9, "IMPROPER_INPUT_VALIDATION")])

    def test_files_multidict_is_covered_too(self):
        code = VIEW + "        save(request.FILES['picture'])\n"
        self.assertEqual(_lines(code, CWE20), {7})

    def test_cleaned_data_is_the_safe_path_and_is_not_reported(self):
        code = (VIEW
                + "        username = form.cleaned_data['username']\n"
                  "        form.cleaned_data.get('email')\n")
        self.assertEqual(_lines(code, CWE20), set())

    def test_reads_without_any_validation_gate_are_out_of_scope(self):
        # A plain request handler with no form validation is a different rule's business;
        # reporting here would double-count every Django view in the world.
        code = ("from django.shortcuts import render\n"
                "\n"
                "def plain(request):\n"
                "    name = request.POST.get('name')\n"
                "    return render(request, 'a.html', {'n': name})\n")
        self.assertEqual(_lines(code, CWE20), set())

    def test_negated_guard_with_unconditional_exit_scopes_the_following_statements(self):
        code = (
            "from django.shortcuts import render\n"
            "\n"
            "def create(request):\n"
            "    form = ProjectForm(request.POST)\n"
            "    if not form.is_valid():\n"
            "        return render(request, 'form.html', {'form': form})\n"
            "    name = request.POST.get('name')\n"
            "    return save(name)\n")
        self.assertEqual(_lines(code, CWE20), {7})

    def test_negated_guard_without_an_exit_proves_nothing_and_is_skipped(self):
        # `if not form.is_valid(): log()` falls through, so the read below may well be on the
        # unvalidated path. The rule stays silent instead of guessing.
        code = (
            "from django.shortcuts import render\n"
            "\n"
            "def create(request):\n"
            "    form = ProjectForm(request.POST)\n"
            "    if not form.is_valid():\n"
            "        mark(request)\n"
            "    name = request.POST.get('name')\n")
        self.assertEqual(_lines(code, CWE20), set())

    def test_orelse_is_the_invalid_form_path_and_is_not_reported(self):
        # `else:` of `if form.is_valid():` is precisely the branch where validation FAILED,
        # so a raw read there is not a post-validation leak.
        code = VIEW + "        pass\n    else:\n        name = request.POST.get('x')\n"
        self.assertEqual(_lines(code, CWE20), set())

    def test_raiselike_guard_exit_also_proves_the_scope(self):
        code = (
            "def create(request):\n"
            "    form = ProjectForm(request.POST)\n"
            "    if not form.is_valid():\n"
            "        raise ValidationError('bad')\n"
            "    name = request.POST['name']\n")
        self.assertEqual(_lines(code, CWE20), {5})

    def test_class_based_view_self_request_is_reported(self):
        code = (
            "class ProfileView(View):\n"
            "    def post(self, request):\n"
            "        form = ProfileForm(request.POST)\n"
            "        if form.is_valid():\n"
            "            self.username = self.request.POST.get('username')\n")
        self.assertEqual(_lines(code, CWE20), {5})

    def test_nested_blocks_inside_the_validated_body_are_found(self):
        code = (VIEW
                + "        for field in ('a', 'b'):\n"
                  "            value = request.POST.get(field)\n")
        self.assertEqual(_lines(code, CWE20), {8})

    def test_message_is_the_contracted_sentence(self):
        code = VIEW + "        name = request.POST.get('name')\n"
        self.assertEqual(_messages(code, CWE20), {MESSAGE})

    def test_is_valid_with_arguments_is_not_the_django_form_call(self):
        code = (
            "def create(request):\n"
            "    checker = Checker()\n"
            "    if checker.is_valid(request.POST):\n"
            "        name = request.POST['name']\n")
        self.assertEqual(_lines(code, CWE20), set())


class TestTemplateCsrfTokenRecognition(unittest.TestCase):
    """A state-changing form is protected by a token wherever Django can render it."""

    def _lines(self, source: str):
        return sorted(finding["line"] for finding in audit_template("t.html", source)
                      if finding["cwe"] == CWE352)

    def test_unprotected_post_form_is_still_reported(self):
        self.assertEqual(self._lines('<form method="post"><input name="x"></form>'), [1])

    def test_template_token_is_case_insensitive(self):
        self.assertEqual(self._lines('<form method="post">\n{% CSRF_TOKEN %}\n</form>'), [])
        self.assertEqual(self._lines('<form method="post">\n{% csrf_token %}\n</form>'), [])

    def test_prerendered_hidden_input_counts_as_a_token(self):
        self.assertEqual(self._lines(
            '<form method="post">'
            '<input type="hidden" name="csrfmiddlewaretoken" value="{{ token }}">'
            '</form>'), [])

    def test_form_object_rendering_counts_as_a_token(self):
        self.assertEqual(self._lines('<form method="post">{{ form.csrf_token }}</form>'), [])

    def test_state_changing_method_spellings_are_all_matched(self):
        for source in ('<FORM METHOD=POST>\n</FORM>',
                       '<form\n   method="PUT"\n   action="/a">\n</form>',
                       '<form method = "Delete" >\n</form>',
                       "<form method='patch'>\n</form>"):
            self.assertEqual(self._lines(source), [1], source)

    def test_read_only_methods_are_out_of_scope(self):
        self.assertEqual(self._lines('<form method="get"><input name="q"></form>'), [])
        self.assertEqual(self._lines('<form><input name="q"></form>'), [])

    def test_one_token_never_exonerates_a_different_open_form(self):
        # Outer form stays unprotected; the token belongs to the inner form only.
        source = ('<form method="post">\n'
                  '<form method="post">\n{% csrf_token %}\n</form>\n'
                  '</form>')
        self.assertEqual(self._lines(source), [1])

    def test_django_nv_protected_forms_stay_unreported(self):
        # manage_groups.html:11 and task_edit.html:18 carry {% csrf_token %} on the next line,
        # so TimeCodeSecurity is right to stay quiet and the Semgrep hit is its own false
        # positive. Pinned so nobody "fixes" this by reporting protected forms.
        protected = '<form method="post" role="form">\n    {% csrf_token %}\n    <div class="form-group">\n        <input type="submit" value="Add">\n    </div>\n</form>'
        self.assertEqual(self._lines(protected), [])


if __name__ == "__main__":
    unittest.main()
