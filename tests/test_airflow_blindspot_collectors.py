r"""Blind-spot collectors for the apache/airflow CWE families this engine used to miss.

Measured on apache/airflow @ `v1-10-test` (shallow clone in gitignored `scratch/target_airflow`),
HEAD engine vs this engine, whole target, same 1261 scanned / 1351 discovered files:

    findings total  803 -> 846    (43 gained, 0 lost; every gained row is a `.py` file — the new
                                   rules never touch YAML or JavaScript)
    CWE-209           0 ->  26    (11 in www/api/experimental/endpoints.py, 12 in the www_rbac
                                   twins, www/views.py:783, plus 2 context-call rows:
                                   secrets/local_filesystem.py:103 and docs/exts/exampleinclude.py:132)
    CWE-117          10 ->  13    (+ ldap_auth.py:305, www endpoints.py:96,
                                   www_rbac endpoints.py:94; the 6 `logging.error(e)` rows in
                                   www*/views.py were already reported by the taint path)
    CWE-601          70 ->  74    (kerberos_auth.py:160, ldap_auth.py:321,
                                   contrib/auth/backends/password_auth.py:178, default_login.py:90)
    CWE-89           46 ->  55    (operators/hive_stats_operator.py:167,175 plus 7 rows inside
                                   airflow's own tests/ dirs, which call hooks directly)
    CWE-319           1 ->   2    (utils/log/file_task_handler.py:163)
    CWE-79           77 ->  77    (the autoescape rule adds nothing here: `autoescape` appears ZERO
                                   times in this revision, so it is pinned synthetically below)
    CWE-532           0 ->   0    (Airflow logs no credential-named variable in these files; the
                                   shipped rule is pinned by the synthetic case below instead)

Anchor contract: CWE-209 lands on the response-construction / `return` line, CWE-117 on the logging
call line. `return str(e)` stays owned by the pre-existing structural except-handler rule, so
`_is_bad_error_return` is consulted first and one defect never becomes two findings. Every new
collector calls `_add_blindspot_sink(..., reuse_existing=True)`, so a site the taint path already
owns is adopted instead of re-reported.

Sites the brief asked for that have no viable finding, verified rather than assumed:
`hooks/presto_hook.py` passes `parameters` to `cursor.execute` / `super().run`, so it stays
unflagged (its real injection is the already-reported `metastore_browser` call site);
`utils/helpers.py` logs only process internals (`p`, `p.pid`, `sig`, `pgid`), never client text.
"""

import ast
import os
import textwrap
import unittest

import ast_scanner
from ast_scanner import TaintTracker
from cli import _findings_for

C209 = "_collect_cwe209_stack_trace_exposure"
C117 = "_collect_cwe117_log_injection"
C532 = "_collect_cwe532_logging_leaks"
C601 = "_collect_cwe601_open_redirect"
C319 = "_collect_cwe319_insecure_transport"
C79J = "_collect_cwe79_insecure_jinja_config"
C89 = "_collect_cwe89_hook_query_execution"
MSG209 = "CWE-209: Detailed exception or stack trace exposed in response"
MSG117 = "CWE-117: Unsanitized user input written to log file"
AIRFLOW = os.path.join("scratch", "target_airflow")

EXPOSED_JSONIFY = '''
    from flask import jsonify


    def view(request):
        try:
            load()
        except Exception as e:
            return jsonify(error=str(e))
'''
EXPOSED_RESPONSE_TRACEBACK = '''
    import traceback
    from flask import Response


    def view(request):
        try:
            load()
        except Exception:
            return Response(traceback.format_exc(), 500)
'''
EXPOSED_ERROR_HANDLER_PAGE = '''
    import traceback
    from flask import render_template


    @app.errorhandler(500)
    def show_traceback(self):
        return render_template('airflow/traceback.html', info=traceback.format_exc()), 500
'''
EXPOSED_RESPONSE_VARIABLE = '''
    from flask import jsonify


    def view(request):
        try:
            trigger()
        except AirflowException as err:
            response = jsonify(error="{}".format(err))
            response.status_code = 400
            return response
'''
EXPOSED_DICT_PAYLOAD = '''
    def view(request):
        try:
            load()
        except Exception as e:
            return {"error": str(e), "detail": e.args}
'''
LOG_ONLY_HANDLER = '''
    import logging


    logger = logging.getLogger(__name__)


    def view(request):
        try:
            load()
        except Exception as e:
            logger.error("handled %s", e)
            return "Server error"
'''
PRINT_TYPE_NAME = '''
    def handle(request):
        try:
            return load()
        except Exception as e:
            print(type(e).__name__)
            return "Error handled"
'''
GENERIC_MESSAGE = '''
    def handle(request):
        try:
            return load()
        except Exception as e:
            return "Contact support"
'''
BARE_RETURN = '''
    def handle():
        try:
            return load()
        except Exception as e:
            return str(e)
'''
ROUTE_KWARG_LOG = '''
    import logging


    log = logging.getLogger(__name__)


    @blueprint.route("/delete_dag/<dag_id>")
    def delete(dag_id):
        log.info("DAG deleted: %s", dag_id)
'''
REQUEST_THREE_HOP_LOG = '''
    import logging


    log = logging.getLogger(__name__)


    @api.route("/trigger")
    def trigger(request):
        data = request.get_json()
        execution_date = data['execution_date']
        error_message = 'Given execution date, {}, could not be identified'.format(execution_date)
        log.info(error_message)
'''
FORM_DIRECT_LOG = '''
    import logging


    def view(request):
        logging.warning("bad login for %s", request.form["username"])
'''
CURRENT_APP_LOGGER_LOG = '''
    import logging


    def view(request):
        current_app.logger.info("state %s", request.args.get('state'))
'''
STATIC_LOG = '''
    import logging


    def view(request):
        logging.info("Retrieving rendered templates.")
'''
LENGTH_CAST_LOG = '''
    import logging


    @blueprint.route("/x")
    def view(dag_id):
        logging.info("length %s", len(dag_id))
'''
NAMED_SANITIZER_LOG = '''
    import logging


    def view(request):
        logging.info(replace_crlf(request.form["username"]))
'''
INLINE_REPLACE_LOG = '''
    import logging


    @blueprint.route("/x")
    def view(dag_id):
        clean = dag_id.replace("\\n", "_")
        logging.info("DAG %s", clean)
'''
HELPER_PARAM_NOT_ENDPOINT = '''
    import logging


    log = logging.getLogger(__name__)


    @provide_session
    def delete_dag(dag_id, session=None):
        log.info("Deleting DAG: %s", dag_id)
'''
CREDENTIAL_LOGGED = '''
    import logging


    logger = logging.getLogger(__name__)


    def save(connection):
        password = connection.password
        logger.info("stored %s", password)
'''

# ── CWE-601: the `or url_for(...)` fallback that hid four Airflow login views ──────────────
OR_URLFOR_FALLBACK = '''
    from flask import redirect, request, url_for


    def login(request):
        return redirect(request.args.get("next") or url_for("index"))
'''
VALUES_OR_LITERAL = '''
    from flask import redirect, request


    def login(request):
        return redirect(request.values.get("next") or "/home")
'''
PLAIN_REQUEST_TARGET = '''
    from flask import redirect, request


    def login(request):
        return redirect(request.args.get("next"))
'''
VIA_VARIABLE_TARGET = '''
    from flask import redirect, request, url_for


    def callback(request):
        next_url = request.args.get('state') or url_for('admin.index')
        return redirect(next_url)
'''
URL_FOR_ONLY = '''
    from flask import redirect, url_for


    def login(request):
        return redirect(url_for('admin.index'))
'''
WRAPPED_REDIRECT_GUARD = '''
    from flask import redirect, request


    def login(request):
        return redirect(validate_redirect_url(request.args.get("next")))
'''

# ── CWE-319: a cleartext scheme whose host is only known at runtime ────────────────────────
CLEARTEXT_FORMAT_TEMPLATE = '''
    import os
    import requests


    def fetch(ti, conf, path):
        url = os.path.join(
            "http://{ti.hostname}:{port}/log", path
        ).format(ti=ti, port=conf.get('celery', 'PORT'))
        response = requests.get(url, timeout=None)
        return response
'''
CLEARTEXT_FSTRING_HOST = '''
    import requests


    def fetch(host):
        return requests.post(f"http://{host}/authenticate", json={"a": 1})
'''
CLEARTEXT_PERCENT_HOST = '''
    import requests


    def fetch(host, port):
        return requests.get("http://%s:%d/log" % (host, port))
'''
CLEARTEXT_STATIC_LITERAL = '''
    import requests


    def fetch():
        return requests.get("http://api.example.com/log")
'''
CLEARTEXT_LOOPBACK = '''
    import requests


    def fetch(port):
        return requests.get(f"http://localhost:{port}/log")
'''
CLEARTEXT_HTTPS_DYNAMIC = '''
    import requests


    def fetch(host):
        return requests.get(f"https://{host}/log")
'''

# ── CWE-89: a statement handed to a hook method rather than a cursor ───────────────────────
HOOK_FORMATTED_QUERY = '''
    from airflow.hooks.presto_hook import PrestoHook


    def query(table):
        hook = PrestoHook("presto_default")
        sql = "SELECT * FROM {} LIMIT 10".format(table)
        return hook.get_records(sql)
'''
HOOK_BOUND_QUERY = '''
    from airflow.hooks.presto_hook import PrestoHook


    def query(table):
        hook = PrestoHook("presto_default")
        return hook.run("SELECT %s FROM t", (table,))
'''
CURSOR_CONSTANT_QUERY = '''
    def bootstrap(cursor):
        return cursor.execute("SELECT 1")
'''
NON_SQL_RUN = '''
    def drive(worker, name):
        return worker.run("PING {0}".format(name))
'''
HOOK_COMPOSED_QUERY = '''
    from psycopg2 import sql


    def good(cursor, table_name):
        query = sql.SQL("SELECT {} FROM t").format(sql.Identifier(table_name))
        return cursor.execute(query)
'''

# ── CWE-79: Jinja2 told not to escape ─────────────────────────────────────────────────────
JINJA_AUTOESCAPE_FALSE = '''
    import jinja2


    def render(body):
        env = jinja2.Environment(autoescape=False)
        return env.from_string(body).render()
'''
JINJA_SELECTOR_DEFAULT_FALSE = '''
    from jinja2 import Environment, select_autoescape


    def build():
        return Environment(autoescape=select_autoescape(default=False))
'''
JINJA_AUTOESCAPE_TRUE = '''
    import jinja2


    def render(body):
        env = jinja2.Environment(autoescape=True)
        return env.from_string(body).render()
'''
JINJA_BARE_ENVIRONMENT = '''
    import jinja2


    def build():
        return jinja2.Environment()
'''

# A parameter named `request` that is not a web request at all (google-api-python-client).
DISCOVERY_REQUEST_LOG = '''
    import logging


    log = logging.getLogger(__name__)


    def _poll(request, response):
        log.info("Operation is done: %s", response)
'''

NEW_COLLECTORS = {
    "CWE-601": "_collect_cwe601_open_redirect",
    "CWE-319": "_collect_cwe319_insecure_transport",
    "CWE-79": "_collect_cwe79_insecure_jinja_config",
    "CWE-89": "_collect_cwe89_hook_query_execution",
    "CWE-117": "_collect_cwe117_log_injection",
}


def _rows(name, source, collector=None, enabled=True):
    original = getattr(TaintTracker, collector) if collector else None
    if collector and not enabled:
        setattr(TaintTracker, collector, lambda *args, **kwargs: None)
    try:
        tracker = TaintTracker(files={name + ".py": source}, audit_all=False)
        _sources, _sinks, edges = tracker.analyze()
        return _findings_for(tracker, edges)
    finally:
        if collector and not enabled:
            setattr(TaintTracker, collector, original)


def _cwe_rows(name, source, cwe, collector=None, enabled=True):
    return sorted(row["line"] for row in _rows(name, source, collector, enabled)
                  if row["cwe"] == cwe)


def _scan_file(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        source = handle.read()
    tracker = TaintTracker(files={path: source}, audit_all=False)
    _sources, _sinks, edges = tracker.analyze()
    return _findings_for(tracker, edges)


class TestCwe209StackTraceExposure(unittest.TestCase):
    def test_jsonify_keyword_exposes_str_of_exception(self):
        rows = [row for row in _rows("jsonify_str", textwrap.dedent(EXPOSED_JSONIFY))
                if row["cwe"] == "CWE-209"]
        self.assertEqual([row["line"] for row in rows], [9])
        self.assertEqual({row["message"] for row in rows}, {MSG209})

    def test_response_wrapping_traceback_format_exc(self):
        self.assertEqual(_cwe_rows("resp_tb", textwrap.dedent(EXPOSED_RESPONSE_TRACEBACK),
                                   "CWE-209"), [10])

    def test_error_handler_page_renders_traceback(self):
        self.assertEqual(_cwe_rows("tb_page", textwrap.dedent(EXPOSED_ERROR_HANDLER_PAGE),
                                   "CWE-209"), [8])

    def test_response_variable_anchors_to_return_line(self):
        # The Airflow idiom: `response = jsonify(...)` then `return response` two statements later.
        self.assertEqual(_cwe_rows("resp_var", textwrap.dedent(EXPOSED_RESPONSE_VARIABLE),
                                   "CWE-209"), [11])

    def test_dict_payload_from_handler(self):
        self.assertEqual(_cwe_rows("dict_pay", textwrap.dedent(EXPOSED_DICT_PAYLOAD),
                                   "CWE-209"), [6])

    def test_logging_an_exception_is_not_a_web_exposure(self):
        self.assertEqual(_cwe_rows("log_only", textwrap.dedent(LOG_ONLY_HANDLER), "CWE-209"), [])

    def test_print_and_generic_message_are_not_exposures(self):
        self.assertEqual(_cwe_rows("print_type", textwrap.dedent(PRINT_TYPE_NAME), "CWE-209"), [])
        self.assertEqual(_cwe_rows("generic", textwrap.dedent(GENERIC_MESSAGE), "CWE-209"), [])

    def test_bare_return_is_reported_exactly_once(self):
        rows = _cwe_rows("bare", textwrap.dedent(BARE_RETURN), "CWE-209", collector=C209)
        off = _cwe_rows("bare", textwrap.dedent(BARE_RETURN), "CWE-209", collector=C209,
                        enabled=False)
        self.assertEqual(rows, [5])
        self.assertEqual(rows, off)
        self.assertEqual(len(rows), 1)


class TestCwe117LogInjection(unittest.TestCase):
    def test_route_kwarg_reaches_log(self):
        self.assertEqual(_cwe_rows("route_kw", textwrap.dedent(ROUTE_KWARG_LOG), "CWE-117", C117), [10])

    def test_request_json_three_hops_to_log(self):
        self.assertEqual(_cwe_rows("three_hop", textwrap.dedent(REQUEST_THREE_HOP_LOG),
                                   "CWE-117", C117), [13])

    def test_direct_request_form_argument(self):
        self.assertEqual(_cwe_rows("form_direct", textwrap.dedent(FORM_DIRECT_LOG), "CWE-117", C117), [6])

    def test_current_app_logger_spelling_is_a_sink(self):
        self.assertEqual(_cwe_rows("ca_logger", textwrap.dedent(CURRENT_APP_LOGGER_LOG),
                                   "CWE-117", C117), [6])

    def test_static_literal_and_length_cast_are_inert(self):
        self.assertEqual(_cwe_rows("static", textwrap.dedent(STATIC_LOG), "CWE-117", C117), [])
        self.assertEqual(_cwe_rows("length", textwrap.dedent(LENGTH_CAST_LOG), "CWE-117", C117), [])

    def test_crlf_sanitizers_clear_the_value(self):
        self.assertEqual(_cwe_rows("named_san", textwrap.dedent(NAMED_SANITIZER_LOG), "CWE-117", C117), [])
        self.assertEqual(_cwe_rows("inline_rep", textwrap.dedent(INLINE_REPLACE_LOG), "CWE-117", C117), [])

    def test_parameter_of_a_non_endpoint_helper_is_not_evidence(self):
        # Airflow's `delete_dag(dag_id)` helper: the client value arrives from another module, and
        # this engine has no cross-module parameter model, so the site stays unreported by design.
        self.assertEqual(
            _cwe_rows("helper", textwrap.dedent(HELPER_PARAM_NOT_ENDPOINT), "CWE-117", C117), [])

    def test_message_names_the_log_sink_not_the_route(self):
        rows = [row for row in _rows("route_kw_msg", textwrap.dedent(ROUTE_KWARG_LOG))
                if row["cwe"] == "CWE-117"]
        self.assertEqual({row["message"] for row in rows}, {MSG117})


class TestCwe532SensitiveLogging(unittest.TestCase):
    def test_credential_named_variable_in_log_is_reported(self):
        rows = _cwe_rows("cred_log", textwrap.dedent(CREDENTIAL_LOGGED), "CWE-532", C532)
        self.assertEqual(rows, [10])
        # Measured: stubbing `_collect_cwe532_logging_leaks` changes nothing, so this site is
        # already covered by the shipped CWE-532 rule. The item needed no new code, only a pin.
        disabled = _cwe_rows("cred_log", textwrap.dedent(CREDENTIAL_LOGGED), "CWE-532", C532,
                             enabled=False)
        self.assertEqual(disabled, [10])

    def test_sensitive_value_name_regex_covers_the_documented_words(self):
        for name in ("password", "secret", "auth_token", "api_key", "private_key"):
            with self.subTest(name=name):
                self.assertTrue(ast_scanner.SENSITIVE_VALUE_NAME_RE.search(name))


@unittest.skipUnless(os.path.isdir(AIRFLOW), "clone apache/airflow into scratch/target_airflow")
class TestAirflowEvidence(unittest.TestCase):
    ENDPOINTS = os.path.join(AIRFLOW, "airflow", "www", "api", "experimental", "endpoints.py")
    WWW_VIEWS = os.path.join(AIRFLOW, "airflow", "www", "views.py")
    RBAC_VIEWS = os.path.join(AIRFLOW, "airflow", "www_rbac", "views.py")
    DELETE_DAG = os.path.join(AIRFLOW, "airflow", "api", "common",
                             "experimental", "delete_dag.py")

    def test_api_error_responses_expose_exception_text(self):
        rows = sorted(row["line"] for row in _scan_file(self.ENDPOINTS) if row["cwe"] == "CWE-209")
        self.assertEqual(rows, [93, 119, 141, 162, 175, 241, 282, 317, 332, 349, 365])

    def test_webserver_500_page_renders_the_traceback(self):
        for path in (self.WWW_VIEWS, self.RBAC_VIEWS):
            with self.subTest(path=path):
                rows = sorted(row["line"] for row in _scan_file(path) if row["cwe"] == "CWE-209")
                self.assertIn(783 if "www_rbac" not in path else 193, rows)

    def test_without_the_collector_airflow_has_zero_cwe209(self):
        """The whole 14-finding cluster is this collector's; HEAD reported none of it."""
        for path in (self.ENDPOINTS, self.WWW_VIEWS, self.RBAC_VIEWS):
            with self.subTest(path=path):
                with open(path, encoding="utf-8", errors="replace") as handle:
                    source = handle.read()
                self.assertEqual(_cwe_rows(path, source, "CWE-209", C209, enabled=False), [])

    def test_request_derived_text_reaches_the_log(self):
        rows = sorted(row["line"] for row in _scan_file(self.ENDPOINTS) if row["cwe"] == "CWE-117")
        self.assertIn(96, rows)

    def test_cross_module_helper_site_stays_unreported(self):
        rows = sorted(row["line"] for row in _scan_file(self.DELETE_DAG)
                      if row["cwe"] in ("CWE-117", "CWE-209"))
        self.assertEqual(rows, [])


def _multi_rows(name, source, cwe, disabled=()):
    """Rows for *cwe* with the listed collector methods stubbed out."""
    originals = {method: getattr(TaintTracker, method) for method in disabled}
    for method in disabled:
        setattr(TaintTracker, method, lambda *args, **kwargs: None)
    try:
        tracker = TaintTracker(files={name + ".py": source}, audit_all=False)
        _sources, _sinks, edges = tracker.analyze()
        return sorted(row["line"] for row in _findings_for(tracker, edges) if row["cwe"] == cwe)
    finally:
        for method, original in originals.items():
            setattr(TaintTracker, method, original)


MSG601 = "CWE-601: Potential open redirect using unvalidated user input parameter"
MSG319 = "CWE-319: Cleartext HTTP transmission directed to dynamic network host"
MSG79J = "CWE-79: Jinja2 environment configured with autoescape disabled"


class TestCwe601RedirectFallback(unittest.TestCase):
    """`user_input or url_for(...)` used to read as framework-generated, so nothing was reported."""

    def test_args_get_behind_url_for_fallback(self):
        self.assertEqual(_cwe_rows("or_urlfor", textwrap.dedent(OR_URLFOR_FALLBACK),
                                   "CWE-601", C601), [6])

    def test_values_get_behind_literal_fallback(self):
        self.assertEqual(_cwe_rows("or_literal", textwrap.dedent(VALUES_OR_LITERAL),
                                   "CWE-601", C601), [6])

    def test_message_names_the_unvalidated_parameter(self):
        rows = [row for row in _rows("msg601", textwrap.dedent(OR_URLFOR_FALLBACK))
                if row["cwe"] == "CWE-601"]
        self.assertEqual({row["message"] for row in rows}, {MSG601})

    def test_target_the_taint_path_already_owns_is_not_emitted_twice(self):
        on = _cwe_rows("plain", textwrap.dedent(PLAIN_REQUEST_TARGET), "CWE-601", C601)
        off = _multi_rows("plain", textwrap.dedent(PLAIN_REQUEST_TARGET), "CWE-601",
                          disabled=(NEW_COLLECTORS["CWE-601"],))
        self.assertEqual(on, [6])
        self.assertEqual(on, off)

    def test_variable_target_is_left_to_the_existing_rule(self):
        on = _cwe_rows("var", textwrap.dedent(VIA_VARIABLE_TARGET), "CWE-601", C601)
        off = _multi_rows("var", textwrap.dedent(VIA_VARIABLE_TARGET), "CWE-601",
                          disabled=(NEW_COLLECTORS["CWE-601"],))
        self.assertEqual(on, off)

    def test_framework_built_target_is_not_a_finding(self):
        self.assertEqual(_cwe_rows("urlfor", textwrap.dedent(URL_FOR_ONLY), "CWE-601", C601), [])

    def test_named_guard_wrapping_the_value_clears_it(self):
        self.assertEqual(_cwe_rows("guard", textwrap.dedent(WRAPPED_REDIRECT_GUARD),
                                   "CWE-601", C601), [])


class TestCwe319CleartextTransport(unittest.TestCase):
    def test_template_url_reaching_requests_get(self):
        self.assertEqual(_cwe_rows("tmpl", textwrap.dedent(CLEARTEXT_FORMAT_TEMPLATE),
                                   "CWE-319", C319), [10])

    def test_f_string_host(self):
        self.assertEqual(_cwe_rows("fs", textwrap.dedent(CLEARTEXT_FSTRING_HOST),
                                   "CWE-319", C319), [6])

    def test_percent_formatted_host(self):
        self.assertEqual(_cwe_rows("pct", textwrap.dedent(CLEARTEXT_PERCENT_HOST),
                                   "CWE-319", C319), [6])

    def test_static_literal_stays_with_the_rule_that_already_reports_it(self):
        on = _cwe_rows("lit", textwrap.dedent(CLEARTEXT_STATIC_LITERAL), "CWE-319", C319)
        off = _multi_rows("lit", textwrap.dedent(CLEARTEXT_STATIC_LITERAL), "CWE-319",
                          disabled=(NEW_COLLECTORS["CWE-319"],))
        self.assertEqual(on, [6])
        self.assertEqual(on, off)

    def test_loopback_host_and_https_are_not_cleartext_exposure(self):
        self.assertEqual(_cwe_rows("lb", textwrap.dedent(CLEARTEXT_LOOPBACK), "CWE-319", C319), [])
        self.assertEqual(_cwe_rows("https", textwrap.dedent(CLEARTEXT_HTTPS_DYNAMIC),
                                   "CWE-319", C319), [])

    def test_scope_guard_silences_the_rule_inside_tests(self):
        # Same vulnerable body, but the file is a test: fixtures legitimately speak plain HTTP.
        self.assertEqual(_multi_rows("test_dyn", textwrap.dedent(CLEARTEXT_FORMAT_TEMPLATE),
                                     "CWE-319"), [])

    def test_message_names_the_dynamic_host(self):
        rows = [row for row in _rows("msg319", textwrap.dedent(CLEARTEXT_FSTRING_HOST))
                if row["cwe"] == "CWE-319" and row["line"] == 6]
        self.assertEqual({row["message"] for row in rows}, {MSG319})


class TestCwe89HookQuery(unittest.TestCase):
    def test_formatted_statement_into_get_records(self):
        self.assertEqual(_cwe_rows("hook", textwrap.dedent(HOOK_FORMATTED_QUERY),
                                   "CWE-89", C89), [8])

    def test_bound_parameters_are_the_drivers_job(self):
        self.assertEqual(_cwe_rows("bound", textwrap.dedent(HOOK_BOUND_QUERY), "CWE-89", C89), [])

    def test_constant_statement_is_not_interpolated(self):
        self.assertEqual(_cwe_rows("const", textwrap.dedent(CURSOR_CONSTANT_QUERY),
                                   "CWE-89", C89), [])

    def test_run_on_a_non_database_receiver(self):
        self.assertEqual(_cwe_rows("worker", textwrap.dedent(NON_SQL_RUN), "CWE-89", C89), [])

    def test_psycopg2_object_composition_is_not_string_interpolation(self):
        # `sql.SQL("SELECT {} FROM t").format(sql.Identifier(x))` is quoted by the driver. A legacy
        # taint path may still surface its own candidate here, so the assertion is on this rule's
        # message rather than on the CWE being absent.
        rows = [row for row in _rows("composed", textwrap.dedent(HOOK_COMPOSED_QUERY))
                if row["cwe"] == "CWE-89"
                and "assembled by string interpolation" in row["message"]]
        self.assertEqual(rows, [])


class TestCwe79JinjaAutoescapeConfig(unittest.TestCase):
    def test_environment_with_autoescape_false(self):
        on = _cwe_rows("env", textwrap.dedent(JINJA_AUTOESCAPE_FALSE), "CWE-79", C79J)
        off = _multi_rows("env", textwrap.dedent(JINJA_AUTOESCAPE_FALSE), "CWE-79",
                          disabled=(NEW_COLLECTORS["CWE-79"],))
        self.assertIn(6, on)          # the Environment(...) construction line
        self.assertEqual(off, [7])    # line 7 is the pre-existing XSS sink, not this rule

    def test_selector_default_false_reaches_the_environment_line(self):
        self.assertEqual(_cwe_rows("sel", textwrap.dedent(JINJA_SELECTOR_DEFAULT_FALSE),
                                   "CWE-79", C79J), [6])

    def test_explicit_autoescape_true_is_not_evidence(self):
        on = _cwe_rows("true", textwrap.dedent(JINJA_AUTOESCAPE_TRUE), "CWE-79", C79J)
        off = _multi_rows("true", textwrap.dedent(JINJA_AUTOESCAPE_TRUE), "CWE-79",
                          disabled=(NEW_COLLECTORS["CWE-79"],))
        self.assertEqual(on, off)

    def test_bare_environment_is_jinjas_default_not_a_config_choice(self):
        self.assertEqual(_cwe_rows("bare", textwrap.dedent(JINJA_BARE_ENVIRONMENT),
                                   "CWE-79", C79J), [])

    def test_message_names_the_autoescape_config(self):
        rows = [row for row in _rows("msg79j", textwrap.dedent(JINJA_AUTOESCAPE_FALSE))
                if row["cwe"] == "CWE-79" and row["line"] == 6]
        self.assertEqual({row["message"] for row in rows}, {MSG79J})


class TestCwe117EndpointEvidence(unittest.TestCase):
    def test_request_shaped_parameter_without_a_request_read(self):
        # google-api-python-client hands `_poll(request, response, ...)` a discovery request object;
        # logging its response is not client input reaching a log line.
        self.assertEqual(_cwe_rows("discovery", textwrap.dedent(DISCOVERY_REQUEST_LOG),
                                   "CWE-117", C117), [])


@unittest.skipUnless(os.path.isdir(AIRFLOW), "clone apache/airflow into scratch/target_airflow")
class TestAirflowBlindSpotSites(unittest.TestCase):
    ROOT = os.path.join(AIRFLOW, "airflow")
    SITES = {
        ("utils", "log", "file_task_handler.py"): ("CWE-319", [163]),
        ("default_login.py",): ("CWE-601", [90]),
        ("contrib", "auth", "backends", "password_auth.py"): ("CWE-601", [178]),
        ("contrib", "auth", "backends", "kerberos_auth.py"): ("CWE-601", [160]),
        ("contrib", "auth", "backends", "ldap_auth.py"): ("CWE-601", [321]),
    }

    def test_each_measured_site_is_reported_at_its_own_line(self):
        for parts, (cwe, expected) in sorted(self.SITES.items()):
            path = os.path.join(self.ROOT, *parts)
            with self.subTest(site="/".join(parts)):
                with open(path, encoding="utf-8", errors="replace") as handle:
                    source = handle.read()
                rows = [row["line"] for row in _scan_file(path) if row["cwe"] == cwe]
                for line in expected:
                    self.assertIn(line, rows)

    def test_the_gcp_discovery_false_positive_is_gone(self):
        path = os.path.join(self.ROOT, "contrib", "hooks", "gcp_mlengine_hook.py")
        rows = [row["line"] for row in _scan_file(path) if row["cwe"] == "CWE-117"]
        self.assertNotIn(38, rows)

    def test_parameterised_presto_hook_is_not_flagged(self):
        # `cursor.execute(self._strip_sql(hql), parameters)` and `super().run(..., parameters)`:
        # the driver quotes the value, so there is no injection site here to report.
        path = os.path.join(self.ROOT, "hooks", "presto_hook.py")
        rows = [row["cwe"] for row in _scan_file(path)
                if row["cwe"] in ("CWE-89", "CWE-601", "CWE-319")]
        self.assertEqual(rows, [])

    def test_new_collectors_change_nothing_in_metastore_browser(self):
        path = os.path.join(self.ROOT, "contrib", "plugins", "metastore_browser", "main.py")
        with open(path, encoding="utf-8", errors="replace") as handle:
            source = handle.read()
        watched = ("CWE-89", "CWE-601", "CWE-319", "CWE-79", "CWE-117")
        on = sorted((row["cwe"], row["line"]) for row in _scan_file(path) if row["cwe"] in watched)
        off = []
        methods = tuple(NEW_COLLECTORS.values())
        originals = {method: getattr(TaintTracker, method) for method in methods}
        for method in methods:
            setattr(TaintTracker, method, lambda *args, **kwargs: None)
        try:
            tracker = TaintTracker(files={path: source}, audit_all=False)
            _sources, _sinks, edges = tracker.analyze()
            off = sorted((row["cwe"], row["line"]) for row in _findings_for(tracker, edges)
                         if row["cwe"] in watched)
        finally:
            for method, original in originals.items():
                setattr(TaintTracker, method, original)
        self.assertEqual(on, off)


if __name__ == "__main__":
    unittest.main()
