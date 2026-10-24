"""Reproduction fixtures for the two actionable Odoo 17 miss families.

Baseline probe against the frozen engine (HEAD f7d144f) shows both Odoo shapes
are missed, while every paired control is flagged. The repro tests carry
``xfail(strict=True)``: they stay XFAIL while the gap exists, and turn into a
hard failure (XPASS) the moment the engine starts detecting them, so a marker
can never silently outlive the gap it documents.

Case 1 - CWE-532: a credential-bearing container arrives as a function
parameter (triage rows 3, 6, 9). Container proof follows same-scope writes
only, see ``_c532_container_bearing_arg`` at ast_scanner.py:10204.

Case 2 - CWE-89: ``request.params.get('order')`` is interpolated into an ORM
search ``order=`` string (triage row 27). The CWE-89 family watches
``execute()``-style sinks, not ORM keyword arguments.
"""

import pytest

from ast_scanner import TaintTracker


def _scan(source: str) -> list:
    tracker = TaintTracker(files={"odoo_repro.py": source})
    _, sinks, _ = tracker.analyze()
    return [s.metadata for s in sinks]


def _findings(source: str, cwe: str) -> list:
    return [meta for meta in _scan(source) if meta.get("cwe") == cwe]


# -- Case 1: CWE-532, credential-bearing dict passed in as a parameter --------

CWE532_HEADERS_PARAM = """
import logging

_logger = logging.getLogger(__name__)


class GoogleService:
    def _do_request(self, uri, method, headers, params):
        _log_params = dict(params or {})
        if 'client_secret' in _log_params:
            _log_params['client_secret'] = _log_params['client_secret'][0:4] + 'x' * 12
        _logger.debug("Uri: %s - Type : %s - Headers: %s - Params : %s!",
                      uri, method, headers, _log_params)
"""

CWE532_PASSWORD_PARAM_CONTROL = """
import logging

_logger = logging.getLogger(__name__)


def log_login(password):
    _logger.debug("login with password=%s", password)
"""

CWE532_CONF_PARAM = """
import logging

_logger = logging.getLogger(__name__)


def update_conf(values):
    _logger.debug("Updating odoo.conf with values: %s", values)
"""

CWE532_CONF_SAME_SCOPE_CONTROL = """
import logging

_logger = logging.getLogger(__name__)


def update_conf():
    values = {'password': 'hunter2', 'host': 'localhost'}
    _logger.debug("Updating odoo.conf with values: %s", values)
"""


class TestCWE532HeaderAndConfDictLogging:
    def test_control_password_parameter_is_flagged(self):
        assert _findings(CWE532_PASSWORD_PARAM_CONTROL, "CWE-532"), (
            "control: a parameter literally named password must be flagged")

    def test_control_same_scope_credential_dict_is_flagged(self):
        assert _findings(CWE532_CONF_SAME_SCOPE_CONTROL, "CWE-532"), (
            "control: a dict built in the same scope with a password key "
            "must be flagged")

    @pytest.mark.xfail(
        strict=True,
        reason="baseline miss: headers is a function parameter; container "
               "proof only follows same-scope writes (ast_scanner.py:10204)",
    )
    def test_headers_parameter_logged(self):
        assert _findings(CWE532_HEADERS_PARAM, "CWE-532"), (
            "CWE-532: OAuth request headers dict logged with credentials")

    @pytest.mark.xfail(
        strict=True,
        reason="baseline miss: odoo.conf values dict arrives as a parameter, "
               "so no container write exists in scope (ast_scanner.py:10204)",
    )
    def test_conf_values_parameter_logged(self):
        assert _findings(CWE532_CONF_PARAM, "CWE-532"), (
            "CWE-532: odoo.conf values dict (DB password) logged")


# -- Case 2: CWE-89, request order interpolated into ORM order= --------------

CWE89_ORM_ORDER = """
from odoo import http
from odoo.http import request


class WebsiteSale(http.Controller):
    def _get_search_order(self):
        # id is added to be sure that order is a unique sort key
        order = request.params.get('order') or 'id desc'
        return 'is_published desc, %s, id desc' % order

    @http.route('/shop', type='http', auth='public', website=True)
    def shop(self, **post):
        order = self._get_search_order()
        return request.env['product.template'].search(
            [('sale_ok', '=', True)], order=order)
"""

CWE89_SQL_CONTROL = """
from odoo import http
from odoo.http import request


class OrderReport(http.Controller):
    @http.route('/report', type='http', auth='user')
    def report(self):
        order = request.params.get('order') or 'id desc'
        query = "SELECT * FROM product_template ORDER BY %s" % order
        self.env.cr.execute(query)
        return request.make_response('ok')
"""


class TestCWE89ORMOrderInjection:
    def test_control_same_taint_into_execute_is_flagged(self):
        assert _findings(CWE89_SQL_CONTROL, "CWE-89"), (
            "control: the same request order reaching cr.execute must be "
            "flagged")

    def test_request_param_interpolated_into_orm_order(self):
        assert _findings(CWE89_ORM_ORDER, "CWE-89"), (
            "CWE-89: request.params['order'] interpolated into ORM order=")
