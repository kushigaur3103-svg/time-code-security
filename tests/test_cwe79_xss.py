"""Phase 10.3 targeted tests: CWE-79 reflected XSS recovery and auto-escape bypasses."""

from ast_scanner import TaintTracker

XSS_FAMILY = {"CWE-79", "CWE-80", "CWE-116"}


def _xss_finding_lines(source: str) -> set:
    """Lines with edge-backed CWE-79-family findings (what the CLI/showdown report)."""
    tracker = TaintTracker(files={"test.py": source})
    _s, sinks, edges = tracker.analyze()
    by_id = {x.id: x for x in sinks}
    out = set()
    for edge in edges:
        sink = by_id.get(edge.target_id)
        if sink is None:
            continue
        cwe = (sink.metadata or {}).get("cwe")
        if cwe in XSS_FAMILY:
            out.add(sink.lineno)
    return out


class TestMissionPositives:
    def test_httpresponse_fstring_flagged(self):
        source = """
@app.route("/x")
def view(request):
    user_input = request.args.get("q")
    return HttpResponse(f"<h1>Hello {user_input}</h1>")
"""
        assert 5 in _xss_finding_lines(source)

    def test_mark_safe_concat_flagged(self):
        source = """
def view(request):
    name = request.args.get("name")
    return mark_safe("<div>" + name + "</div>")
"""
        assert 4 in _xss_finding_lines(source)

    def test_variable_bridge_flagged(self):
        source = """
def view(request):
    u = request.args.get("u")
    msg = f"User: {u}"
    return HttpResponse(msg)
"""
        assert 5 in _xss_finding_lines(source)


class TestMissionGuards:
    def test_render_template_silent(self):
        source = """
def view(request):
    user_input = request.args.get("q")
    return render(request, "index.html", {"name": user_input})
"""
        assert not _xss_finding_lines(source)

    def test_static_literal_silent(self):
        source = """
def view(request):
    return HttpResponse("<h1>Static Title</h1>")
"""
        assert not _xss_finding_lines(source)

    def test_escaped_value_silent(self):
        source = """
def view(request):
    user_input = request.args.get("q")
    return HttpResponse(html.escape(user_input))
"""
        assert not _xss_finding_lines(source)

    def test_bleach_clean_silent(self):
        source = """
def view(request):
    user_input = request.GET.get("q")
    return HttpResponse(bleach.clean(user_input))
"""
        assert not _xss_finding_lines(source)

    def test_ok_annotation_silent(self):
        source = """
def view(request):
    user_input = request.args.get("q")
    # ok:direct-use-of-response-data
    return HttpResponse(f"<h1>Hello {user_input}</h1>")
"""
        assert not _xss_finding_lines(source)


class TestRecoveryPredicates:
    def test_dynamic_html_assignment_flagged(self):
        source = """
def handler(event):
    html_out = '<a href="http://ext/abc/%s">link</a>' % event['input']
"""
        assert 3 in _xss_finding_lines(source)

    def test_format_receiver_variable_flagged(self):
        source = """
def handler(event):
    link = '<a href="http://ext/abc/{}">link</a>'
    out = link.format(event['input'])
"""
        assert 4 in _xss_finding_lines(source)

    def test_reassigned_variable_chain_flagged(self):
        source = """
def get(request):
    text = request.GET['text']
    text = text.replace('"', '')
    link = '<a href="http://ext/abc/%s">Check</a>'
    context = self.get_context_data()
    context['html'] = link % text
"""
        assert 7 in _xss_finding_lines(source)

    def test_dynamic_html_argument_flagged(self):
        source = """
def lambda_handler(event, context):
    emit(f"<div>{event['input']}</div>")
"""
        assert 3 in _xss_finding_lines(source)

    def test_unescaped_template_extension_flagged(self):
        source = """
def unsafe(request):
    return render_template("unsafe.txt", name=request.args.get("name"))
"""
        assert 3 in _xss_finding_lines(source)

    def test_html_template_extension_silent(self):
        source = """
def safe(request):
    return render_template("safe.html", name=request.args.get("name"))
"""
        assert not _xss_finding_lines(source)

    def test_template_without_extension_flagged(self):
        source = """
def unsafe(request):
    return render_template("will-crash-without-extension", name=request.args.get("name"))
"""
        assert 3 in _xss_finding_lines(source)

    def test_template_no_context_silent(self):
        source = """
def ok():
    return render_template("hello.txt")
"""
        assert not _xss_finding_lines(source)

    def test_autoescape_dict_key_flagged(self):
        source = """
def xss(request):
    env = {'qs': request.GET.get('qs', 'hello'), 'autoescape': False}
"""
        assert 3 in _xss_finding_lines(source)

    def test_safestring_subclass_flagged(self):
        source = """
from django.utils.safestring import SafeString

class IWantToBypassEscaping(SafeString):
    pass
"""
        assert 4 in _xss_finding_lines(source)

    def test_plain_str_subclass_silent(self):
        source = """
class SomethingElse(str):
    pass
"""
        assert not _xss_finding_lines(source)

    def test_html_safe_decorator_flagged(self):
        source = """
from django.utils.html import html_safe

@html_safe
class HtmlClass:
    def __str__(self):
        return "<h1>I'm a html class!</h1>"
"""
        assert 4 in _xss_finding_lines(source)

    def test_filter_is_safe_true_flagged(self):
        source = """
@register.filter(is_safe=True)
def ordinal(value):
    return value
"""
        assert 2 in _xss_finding_lines(source)

    def test_filter_is_safe_false_silent(self):
        source = """
# ok:filter-with-is-safe
@register.filter(is_safe=False)
def intword(value):
    return value
"""
        assert not _xss_finding_lines(source)

    def test_markup_unescape_flagged(self):
        source = """
def search(request):
    q = request.args.get('q')
    return Markup.unescape(q)
"""
        assert 4 in _xss_finding_lines(source)

    def test_container_body_response_flagged(self):
        source = """
def switch(target):
    return make_response({'Error': "The knowledge base '" + target + "' does not exist"})
"""
        assert 3 in _xss_finding_lines(source)

    def test_static_container_body_silent(self):
        source = """
def ok():
    return make_response({"hello": "world"}, 200)
"""
        assert not _xss_finding_lines(source)

    def test_lambda_html_body_flagged(self):
        source = """
def lambda_handler(event, context):
    html = f"<div>{event['input']}</div>"
    result = {
        "statusCode": 200,
        "body": html,
        "headers": {
            "Content-Type": "text/html"
        }
    }
    return result
"""
        assert 6 in _xss_finding_lines(source)

    def test_json_body_response_silent(self):
        source = """
def handler(event):
    return make_response(jsonify({"data": event['x']}))
"""
        assert not _xss_finding_lines(source)
