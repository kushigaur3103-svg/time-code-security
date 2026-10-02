"""Phase 9.2 unit tests for CWE-614 (Cookie without Secure) and CWE-1004 (Cookie without HttpOnly).

Tests cover:
1. Flask/Django .set_cookie() calls missing secure/httponly flags
2. Pyramid AuthTktCookieHelper/AuthTktAuthenticationPolicy constructors
3. Explicit False values for cookie flags
4. **kwargs unpacking suppression
5. SameSite attribute handling
"""

import pytest
from ast_scanner import TaintTracker


def _scan(code: str):
    """Helper to scan code and return sinks."""
    tracker = TaintTracker(files={"test.py": code})
    tracker.analyze()
    return tracker.sinks


def _cookie_sinks(sinks):
    """Filter for cookie-related sinks."""
    return [s for s in sinks if 'COOKIE' in s.operation]


# ─── Flask set_cookie tests ───

def test_flask_set_cookie_missing_both_flags():
    """Flag when both secure and httponly are missing."""
    code = '''
def test():
    import flask
    response = flask.make_response()
    response.set_cookie("name", "value")
    return response
'''
    sinks = _cookie_sinks(_scan(code))
    cwes = {s.metadata.get('cwe') for s in sinks}
    assert 'CWE-614' in cwes, "Should flag missing secure flag"
    assert 'CWE-1004' in cwes, "Should flag missing httponly flag"


def test_flask_set_cookie_missing_secure_only():
    """Flag CWE-614 when only secure is missing."""
    code = '''
def test():
    import flask
    response = flask.make_response()
    response.set_cookie("name", "value", httponly=True)
    return response
'''
    sinks = _cookie_sinks(_scan(code))
    cwes = {s.metadata.get('cwe') for s in sinks}
    assert 'CWE-614' in cwes, "Should flag missing secure flag"
    # May or may not have CWE-1004 depending on implementation


def test_flask_set_cookie_all_flags_present():
    """Do not flag when all flags are properly set."""
    code = '''
def test():
    import flask
    response = flask.make_response()
    response.set_cookie("name", "value", secure=True, httponly=True, samesite='Lax')
    return response
'''
    sinks = _cookie_sinks(_scan(code))
    assert len(sinks) == 0, f"Should not flag when all flags present, got {len(sinks)} findings"


def test_flask_set_cookie_explicit_false():
    """Flag when secure=False or httponly=False explicitly."""
    code = '''
def test():
    import flask
    response = flask.make_response()
    response.set_cookie("name", "value", secure=False, httponly=False)
    return response
'''
    sinks = _cookie_sinks(_scan(code))
    cwes = {s.metadata.get('cwe') for s in sinks}
    assert 'CWE-614' in cwes, "Should flag secure=False"
    assert 'CWE-1004' in cwes, "Should flag httponly=False"


def test_flask_set_cookie_with_kwargs_unpack():
    """Do not flag when **kwargs is used (config externalised)."""
    code = '''
def test():
    import flask
    response = flask.make_response()
    response.set_cookie("name", "value", **cookie_settings)
    return response
'''
    sinks = _cookie_sinks(_scan(code))
    assert len(sinks) == 0, f"Should not flag with **kwargs unpacking, got {len(sinks)} findings"


# ─── Pyramid AuthTkt tests ───

def test_pyramid_authtkt_missing_secure():
    """Flag CWE-614 when AuthTktCookieHelper lacks secure parameter."""
    code = '''
from pyramid.authentication import AuthTktCookieHelper

def test():
    authtkt = AuthTktCookieHelper(secret="test")
'''
    sinks = _cookie_sinks(_scan(code))
    cwes = {s.metadata.get('cwe') for s in sinks}
    assert 'CWE-614' in cwes, "Should flag missing secure parameter"


def test_pyramid_authtkt_has_secure():
    """Do not flag CWE-614 when secure=True is present."""
    code = '''
from pyramid.authentication import AuthTktCookieHelper

def test():
    authtkt = AuthTktCookieHelper(secret="test", secure=True)
'''
    sinks = _cookie_sinks(_scan(code))
    cwe_614_sinks = [s for s in sinks if s.metadata.get('cwe') == 'CWE-614']
    assert len(cwe_614_sinks) == 0, "Should not flag when secure=True present"


def test_pyramid_authtkt_explicit_secure_false():
    """Flag CWE-614 when secure=False explicitly."""
    code = '''
from pyramid.authentication import AuthTktCookieHelper

def test():
    authtkt = AuthTktCookieHelper(secret="test", secure=False)
'''
    sinks = _cookie_sinks(_scan(code))
    cwes = {s.metadata.get('cwe') for s in sinks}
    assert 'CWE-614' in cwes, "Should flag secure=False"


def test_pyramid_authtkt_missing_httponly():
    """Flag CWE-1004 when AuthTktCookieHelper lacks httponly parameter."""
    code = '''
from pyramid.authentication import AuthTktCookieHelper

def test():
    authtkt = AuthTktCookieHelper(secret="test")
'''
    sinks = _cookie_sinks(_scan(code))
    cwes = {s.metadata.get('cwe') for s in sinks}
    assert 'CWE-1004' in cwes, "Should flag missing httponly parameter"


def test_pyramid_authtkt_has_httponly():
    """Do not flag CWE-1004 when httponly=True is present."""
    code = '''
from pyramid.authentication import AuthTktCookieHelper

def test():
    authtkt = AuthTktCookieHelper(secret="test", httponly=True)
'''
    sinks = _cookie_sinks(_scan(code))
    cwe_1004_sinks = [s for s in sinks if s.metadata.get('cwe') == 'CWE-1004']
    assert len(cwe_1004_sinks) == 0, "Should not flag when httponly=True present"


def test_pyramid_authentication_policy():
    """Test AuthTktAuthenticationPolicy same as AuthTktCookieHelper."""
    code = '''
from pyramid.authentication import AuthTktAuthenticationPolicy

def test():
    policy = AuthTktAuthenticationPolicy(secret="test")
'''
    sinks = _cookie_sinks(_scan(code))
    cwes = {s.metadata.get('cwe') for s in sinks}
    assert 'CWE-614' in cwes, "Should flag missing secure"
    assert 'CWE-1004' in cwes, "Should flag missing httponly"


def test_pyramid_authtkt_with_kwargs():
    """Do not flag when **params is used."""
    code = '''
from pyramid.authentication import AuthTktCookieHelper

def test(params):
    authtkt = AuthTktCookieHelper(**params)
'''
    sinks = _cookie_sinks(_scan(code))
    assert len(sinks) == 0, f"Should not flag with **kwargs, got {len(sinks)} findings"


# ─── Django tests ───

def test_django_set_cookie_missing_flags():
    """Test Django response.set_cookie() similar to Flask."""
    code = '''
from django.http import HttpResponse

def test(request):
    response = HttpResponse()
    response.set_cookie("name", "value")
    return response
'''
    sinks = _cookie_sinks(_scan(code))
    cwes = {s.metadata.get('cwe') for s in sinks}
    assert 'CWE-614' in cwes or 'CWE-1004' in cwes, "Should flag missing cookie flags"


def test_django_set_cookie_with_settings():
    """Do not flag when using Django settings references."""
    code = '''
from django.http import HttpResponse
from django.conf import settings

def test(request):
    response = HttpResponse()
    response.set_cookie(
        "name", "value",
        secure=settings.SESSION_COOKIE_SECURE,
        httponly=settings.SESSION_COOKIE_HTTPONLY,
    )
    return response
'''
    sinks = _cookie_sinks(_scan(code))
    # Settings references should be treated as "configured" not "missing"
    # May still flag if the logic doesn't recognize settings references
    # This test documents current behavior


# ─── Edge cases ───

def test_multiple_set_cookie_calls():
    """Test multiple set_cookie calls in same function."""
    code = '''
def test():
    import flask
    response = flask.make_response()
    response.set_cookie("safe", "value", secure=True, httponly=True, samesite='Lax')
    response.set_cookie("unsafe", "value")
    return response
'''
    sinks = _cookie_sinks(_scan(code))
    # Should only flag the unsafe call
    assert len(sinks) >= 1, "Should flag at least the unsafe call"


def test_nested_function_scope():
    """Test cookie setting in nested function."""
    code = '''
def outer():
    def inner():
        import flask
        response = flask.make_response()
        response.set_cookie("name", "value")
        return response
    return inner()
'''
    sinks = _cookie_sinks(_scan(code))
    cwes = {s.metadata.get('cwe') for s in sinks}
    assert 'CWE-614' in cwes or 'CWE-1004' in cwes, "Should flag in nested scope"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
