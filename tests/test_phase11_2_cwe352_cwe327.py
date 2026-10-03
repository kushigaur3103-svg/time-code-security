"""Phase 11.2: CWE-352 Pyramid CSRF & CWE-327 JWT/Hashids detection tests."""
from ast_scanner import TaintTracker


def _scan(source):
    """Helper to scan source and return findings."""
    tracker = TaintTracker(files={"test.py": source})
    _s, sinks, edges = tracker.analyze()
    by_id = {x.id: x for x in sinks}
    findings = []
    for edge in edges:
        sink = by_id.get(edge.target_id)
        if sink is None:
            continue
        cwe = (sink.metadata or {}).get("cwe")
        if cwe in ("CWE-352", "CWE-327"):
            findings.append({
                "line": sink.lineno,
                "operation": sink.operation,
                "cwe": cwe,
            })
    return findings


def test_pyramid_view_config_require_csrf_false():
    """Positive: @view_config with require_csrf=False should be flagged."""
    source = '''
from pyramid.view import view_config

@view_config(
    route_name='home',
    require_csrf=False,
    renderer='my_app:templates/mytemplate.jinja2'
)
def my_view(request):
    return {'project': 'my_proj'}
'''
    findings = _scan(source)
    csrf_findings = [f for f in findings if f["cwe"] == "CWE-352"]
    assert len(csrf_findings) >= 1, f"Expected at least 1 CWE-352 finding, got {len(csrf_findings)}: {findings}"


def test_pyramid_view_config_check_origin_false():
    """Positive: @view_config with check_origin=False should be flagged."""
    source = '''
from pyramid.view import view_config

@view_config(
    route_name='home',
    check_origin=False,
    renderer='my_app:templates/mytemplate.jinja2'
)
def my_view(request):
    return {'project': 'my_proj'}
'''
    findings = _scan(source)
    csrf_findings = [f for f in findings if f["cwe"] == "CWE-352"]
    assert len(csrf_findings) >= 1, f"Expected at least 1 CWE-352 finding, got {len(csrf_findings)}: {findings}"


def test_pyramid_set_default_csrf_options_check_origin_false():
    """Positive: config.set_default_csrf_options(check_origin=False) should be flagged."""
    source = '''
from pyramid.csrf import CookieCSRFStoragePolicy

def includeme(config):
    config.set_csrf_storage_policy(CookieCSRFStoragePolicy())
    config.set_default_csrf_options(check_origin=False)
'''
    findings = _scan(source)
    csrf_findings = [f for f in findings if f["cwe"] == "CWE-352"]
    assert len(csrf_findings) >= 1, f"Expected at least 1 CWE-352 finding, got {len(csrf_findings)}: {findings}"


def test_pyramid_safe_patterns_not_flagged():
    """Negative: Safe Pyramid patterns should not be flagged."""
    source = '''
from pyramid.view import view_config
from pyramid.csrf import CookieCSRFStoragePolicy

@view_config(
    route_name='home',
    require_csrf=True,
    renderer='my_app:templates/mytemplate.jinja2'
)
def my_good_view(request):
    return {'project': 'my_proj'}

@view_config(
    route_name='home2',
    check_origin=True,
    renderer='my_app:templates/mytemplate.jinja2'
)
def my_good_view2(request):
    return {'project': 'my_proj'}

def includeme_good(config):
    config.set_csrf_storage_policy(CookieCSRFStoragePolicy())
    config.set_default_csrf_options(check_origin=True)
'''
    findings = _scan(source)
    csrf_findings = [f for f in findings if f["cwe"] == "CWE-352"]
    assert len(csrf_findings) == 0, f"Expected 0 CWE-352 findings for safe patterns, got {len(csrf_findings)}: {csrf_findings}"


def test_jwt_encode_none_algorithm():
    """Positive: jwt.encode with algorithm='none' should be flagged."""
    source = '''
import jwt

def bad():
    encoded = jwt.encode({'some': 'payload'}, None, algorithm='none')
    return encoded
'''
    findings = _scan(source)
    crypto_findings = [f for f in findings if f["cwe"] == "CWE-327"]
    assert len(crypto_findings) >= 1, f"Expected at least 1 CWE-327 finding, got {len(crypto_findings)}: {findings}"


def test_jwt_decode_none_algorithms():
    """Positive: jwt.decode with algorithms=['none'] should be flagged."""
    source = '''
import jwt

def bad(encoded):
    jwt.decode(encoded, None, algorithms=['none'])
'''
    findings = _scan(source)
    crypto_findings = [f for f in findings if f["cwe"] == "CWE-327"]
    assert len(crypto_findings) >= 1, f"Expected at least 1 CWE-327 finding, got {len(crypto_findings)}: {findings}"


def test_hashids_with_flask_secret_key():
    """Positive: Hashids(salt=app.config['SECRET_KEY']) should be flagged."""
    source = '''
from hashids import Hashids
from flask import Flask

app = Flask(__name__)
hash_id = Hashids(salt=app.config['SECRET_KEY'], min_length=34)
'''
    findings = _scan(source)
    crypto_findings = [f for f in findings if f["cwe"] == "CWE-327"]
    assert len(crypto_findings) >= 1, f"Expected at least 1 CWE-327 finding, got {len(crypto_findings)}: {findings}"


def test_hashids_with_current_app_secret():
    """Positive: Hashids(salt=current_app.config['SECRET_KEY']) should be flagged."""
    source = '''
from hashids import Hashids
from flask import current_app

hashids = Hashids(min_length=5, salt=current_app.config['SECRET_KEY'])
'''
    findings = _scan(source)
    crypto_findings = [f for f in findings if f["cwe"] == "CWE-327"]
    assert len(crypto_findings) >= 1, f"Expected at least 1 CWE-327 finding, got {len(crypto_findings)}: {findings}"


def test_jwt_safe_hs256_not_flagged():
    """Negative: jwt.encode with HS256 should not be flagged as weak crypto."""
    source = '''
import jwt

def ok(secret_key):
    encoded = jwt.encode({'some': 'payload'}, secret_key, algorithm='HS256')
    return encoded
'''
    findings = _scan(source)
    # Should only have HARDCODED_JWT_SECRET (CWE-522), not JWT_NONE_ALGORITHM (CWE-327)
    crypto_findings = [f for f in findings if f["cwe"] == "CWE-327"]
    assert len(crypto_findings) == 0, f"Expected 0 CWE-327 findings for HS256, got {len(crypto_findings)}: {crypto_findings}"


def test_suppression_marker_pyramid():
    """Negative: # ok: suppression marker should silence Pyramid CSRF finding."""
    source = '''
from pyramid.view import view_config

# ok:pyramid-csrf-check-disabled
@view_config(
    route_name='home',
    require_csrf=False,
    renderer='my_app:templates/mytemplate.jinja2'
)
def my_view(request):
    return {'project': 'my_proj'}
'''
    findings = _scan(source)
    csrf_findings = [f for f in findings if f["cwe"] == "CWE-352"]
    assert len(csrf_findings) == 0, f"Expected 0 CWE-352 findings with # ok: marker, got {len(csrf_findings)}: {csrf_findings}"


def test_hashids_positional_secret_key_salt():
    """Positive: Hashids(settings.SECRET_KEY, ...) passes salt positionally."""
    source = '''
from django.conf import settings
from hashids import Hashids

def uid(id, length, alphabet):
    return Hashids(settings.SECRET_KEY, min_length=length, alphabet=alphabet).encrypt(id)
'''
    findings = _scan(source)
    crypto_findings = [f for f in findings if f["cwe"] == "CWE-327"]
    assert len(crypto_findings) >= 1, f"Expected at least 1 CWE-327 finding, got {len(crypto_findings)}: {findings}"


def test_hashids_derived_digest_salt_not_flagged():
    """Negative: a salt derived from a digest is not the framework signing key."""
    source = '''
import hashlib
from hashids import Hashids

def build():
    md5 = hashlib.md5()
    md5.update("seed")
    return Hashids(salt=md5.hexdigest(), min_length=16)
'''
    findings = _scan(source)
    crypto_findings = [f for f in findings if f["cwe"] == "CWE-327"]
    assert len(crypto_findings) == 0, f"Expected 0 CWE-327 findings for digest salt, got {len(crypto_findings)}: {crypto_findings}"


def test_hashids_literal_salt_not_flagged():
    """Negative: a literal test-dummy salt stays silent."""
    source = '''
from hashids import Hashids

hashids = Hashids(salt="my-cool-suite.ru", min_length=16)
'''
    findings = _scan(source)
    crypto_findings = [f for f in findings if f["cwe"] == "CWE-327"]
    assert len(crypto_findings) == 0, f"Expected 0 CWE-327 findings for literal salt, got {len(crypto_findings)}: {crypto_findings}"


def test_jwt_decode_safe_options_not_flagged():
    """Negative: verify_signature=True, a non-none opts dict, and bare decode stay silent.

    These are the exact shapes that regressed to +8 FP when jwt.decode was a blanket sink.
    """
    source = '''
import jwt

def tests(encoded, key):
    opts = {"verify_signature": True}
    jwt.decode(encoded, key, options={"verify_signature": True})
    jwt.decode(encoded, key, options=opts)
    jwt.decode(encoded, key, verify=True)
    jwt.decode(encoded, key)
'''
    findings = _scan(source)
    crypto_findings = [f for f in findings if f["cwe"] in ("CWE-327", "CWE-352")]
    assert len(crypto_findings) == 0, f"Expected 0 findings for safe jwt.decode, got {len(crypto_findings)}: {crypto_findings}"


def test_pyramid_view_config_without_csrf_kwargs_not_flagged():
    """Negative: a view_config that omits the CSRF keywords uses the secure default."""
    source = '''
from pyramid.view import view_config

@view_config(route_name='home', renderer='my_app:templates/mytemplate.jinja2')
def my_view(request):
    return {'project': 'my_proj'}
'''
    findings = _scan(source)
    csrf_findings = [f for f in findings if f["cwe"] == "CWE-352"]
    assert len(csrf_findings) == 0, f"Expected 0 CWE-352 findings, got {len(csrf_findings)}: {csrf_findings}"
