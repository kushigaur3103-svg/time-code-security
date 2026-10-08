"""Regression tests for the two new Cluster 3 structural rules: the mutable default argument
audit (CWE-1188) and credential-bearing token payloads (CWE-522).

Both rules were measured before they were written, and this file locks what the measurement
showed. The predicate prototypes live in `scratch/_h1_predicates.py`; running the shipped
engine against `external/semgrep_rules_python` and `benchmark/corpus` (1181 files, HEAD vs
working tree, `scratch/_h1_attrib.py`) produced 45 added findings, all 45 on `# ruleid:`
lines, 0 on negatives, 0 removed, and 0 changed (file, line) positions:

  * 42 x CWE-1188 MUTABLE_DEFAULT_ARGUMENT — 21 positive lines in each of
    python/lang/correctness/common-mistakes/default-mutable-{list,dict}.py.
  *  3 x CWE-522 HARDCODED_CREDENTIAL_IN_PAYLOAD — every `# ruleid:` line of
    python/jwt/security/jwt-exposed-credentials.py (4, 8, 17) and none of its `# ok:` line 23.

The mutable default family is a correctness rule upstream (the semgrep rule carries no CWE),
so CWE-1188 "Insecure Default Initialization of Resource" is the catalog's closest registered
entry; the corpus itself decides which shapes are not defects, and the negatives below are
the shapes it labels `# OK`.
"""

import ast_scanner
from ast_scanner import TaintTracker

CORPUS = "external/semgrep_rules_python"
MUTABLE_CWE = "CWE-1188"
PAYLOAD_CWE = "CWE-522"


def _findings(code, cwe, symbol=None):
    tracker = TaintTracker(files={"sample.py": code}, audit_all=True)
    _sources, sinks, edges = tracker.analyze()
    by_id = {sink.id: sink for sink in sinks}
    return {(by_id[edge.target_id].location.line_start, by_id[edge.target_id].symbol)
            for edge in edges
            if edge.target_id in by_id
            and by_id[edge.target_id].metadata.get("cwe") == cwe
            and (symbol is None or by_id[edge.target_id].symbol == symbol)}


def _lines(code, cwe, symbol=None):
    return {line for line, _symbol in _findings(code, cwe, symbol)}


def _corpus(relative_path):
    with open(f"{CORPUS}/{relative_path}", encoding="utf-8") as handle:
        return handle.read()


# The 21 `# ruleid:` mutation lines in each of the two common-mistakes files. Both files use
# the identical line numbers because their positive sections are parallel (list/extend/insert
# versus subscript-store/update/setdefault).
MUTABLE_CORPUS_HITS = frozenset({6, 12, 18, 23, 29, 34, 48, 54, 60, 66, 71, 77, 82, 96,
                                 102, 108, 114, 119, 125, 130, 144})


class TestMutableDefaultContainerIsFlagged:
    def test_list_default_append(self):
        code = "def f(acc=[]):\n    acc.append(1)\n"
        assert _lines(code, MUTABLE_CWE) == {2}

    def test_dict_default_subscript_store(self):
        code = "def f(acc={}):\n    acc['k'] = 1\n"
        assert _lines(code, MUTABLE_CWE) == {2}

    def test_set_default_add(self):
        code = "def f(acc=set()):\n    acc.add(1)\n"
        assert _lines(code, MUTABLE_CWE) == {2}

    def test_call_form_default_is_still_shared(self):
        # `acc=list()` builds one list at definition time, exactly like `acc=[]`.
        code = "def f(acc=list()):\n    acc.append(1)\n"
        assert _lines(code, MUTABLE_CWE) == {2}

    def test_in_place_augmented_assignment(self):
        code = "def f(acc=[]):\n    acc += [1]\n"
        assert _lines(code, MUTABLE_CWE) == {2}

    def test_alias_through_plain_assignment_is_the_same_object(self):
        code = "def f(acc=[]):\n    tmp = acc\n    tmp.append(1)\n"
        assert _lines(code, MUTABLE_CWE) == {3}

    def test_keyword_only_parameter(self):
        code = "def f(*, acc=[]):\n    acc.append(1)\n"
        assert _lines(code, MUTABLE_CWE) == {2}

    def test_defaults_align_with_the_right_parameters(self):
        # Two positional parameters without defaults plus a keyword-only default: a naive
        # zip of (all parameters) x (all defaults) would pair `a` with `[]` and miss this.
        code = "def f(a, b, /, c, *, acc=[]):\n    acc.append(1)\n"
        assert _lines(code, MUTABLE_CWE) == {2}

    def test_method_in_class_is_in_scope(self):
        code = "class C:\n    def m(self, acc=[]):\n        acc.append(1)\n"
        assert _lines(code, MUTABLE_CWE) == {3}


class TestMutableDefaultNegativesStayClean:
    def test_none_sentinel_is_the_documented_fix(self):
        code = ("def f(acc=None):\n"
                "    if acc is None:\n"
                "        acc = []\n"
                "    acc.append(1)\n")
        assert _lines(code, MUTABLE_CWE) == set()

    def test_slice_rebind_builds_a_fresh_list(self):
        code = "def f(acc=[]):\n    acc = acc[:]\n    acc.append(1)\n"
        assert _lines(code, MUTABLE_CWE) == set()

    def test_or_empty_literal_rebind_is_fresh(self):
        code = "def f(acc={}):\n    acc = acc or {}\n    acc['k'] = 1\n"
        assert _lines(code, MUTABLE_CWE) == set()

    def test_read_only_use_never_mutates(self):
        code = "def f(acc=[]):\n    return len(acc)\n"
        assert _lines(code, MUTABLE_CWE) == set()

    def test_immutable_default_cannot_be_shared_mutably(self):
        code = "def f(n=1):\n    n += 1\n"
        assert _lines(code, MUTABLE_CWE) == set()

    def test_fresh_local_container_is_not_the_default(self):
        code = "def f(x=1):\n    y = []\n    y.append(2)\n"
        assert _lines(code, MUTABLE_CWE) == set()

    def test_nosec_comment_suppresses_the_finding(self):
        code = "def f(acc=[]):\n    acc.append(1)  # nosec\n"
        assert _lines(code, MUTABLE_CWE) == set()

    def test_nested_definition_is_out_of_scope(self):
        # The corpus writes this shape as `# OK` (append_wrapper / not_append_func6) and the
        # upstream rule excludes a def nested in another def, so the exclusion is the contract.
        code = ("def outer():\n"
                "    def inner(acc=[]):\n"
                "        acc.append(1)\n"
                "    return inner\n")
        assert _lines(code, MUTABLE_CWE) == set()


class TestTokenPayloadCredentials:
    def test_inline_password_dict_in_encode(self):
        code = ("import jwt\n\n"
                "def bad(k):\n"
                "    return jwt.encode({'password': 'x', 'sub': 'a'}, k, algorithm='HS256')\n")
        assert _lines(code, PAYLOAD_CWE) == {4}

    def test_module_level_payload_that_reaches_the_token(self):
        code = ("import jwt\n\n"
                "payload = {'foo': 'bar', 'password': 123}\n\n"
                "def bad(secret):\n"
                "    return jwt.encode(payload, secret, algorithm='HS256')\n")
        assert _lines(code, PAYLOAD_CWE) == {3}

    def test_local_payload_that_reaches_the_token(self):
        code = ("import jwt\n\n"
                "def bad(secret, value):\n"
                "    pp = {'one': 'two', 'password': value}\n"
                "    return jwt.encode(pp, secret, algorithm='HS256')\n")
        assert _lines(code, PAYLOAD_CWE) == {4}

    def test_sign_is_also_a_token_call(self):
        code = "import jwt\n\njwt.sign({'password': pw}, k)\n"
        assert _lines(code, PAYLOAD_CWE) == {3}

    def test_from_import_of_the_encoder_still_counts(self):
        code = "from jwt import encode\n\nencode({'password': pw}, k)\n"
        assert _lines(code, PAYLOAD_CWE) == {3}

    def test_key_match_ignores_case(self):
        code = "import jwt\n\njwt.encode({'PASSWORD': pw}, k)\n"
        assert _lines(code, PAYLOAD_CWE) == {3}

    def test_standard_claims_only_stay_clean(self):
        code = ("import jwt\n\n"
                "jwt.encode({'sub': 'a', 'exp': 1, 'iat': 2, 'user_id': 3,\n"
                "            'email': 'e', 'role': 'r'}, k)\n")
        assert _lines(code, PAYLOAD_CWE) == set()

    def test_http_request_body_is_not_a_token_payload(self):
        # Same key, different CWE's business: this is what keeps the two gate good cases in
        # benchmark/corpus/cwe_319_cleartext_transmit silent.
        code = ("import requests\n\n"
                "requests.post('https://x/', json={'user': 'a', 'password': pw})\n")
        assert _lines(code, PAYLOAD_CWE) == set()

    def test_password_dict_that_never_reaches_a_token_is_clean(self):
        code = ("import jwt\n\n"
                "payload = {'password': pw}\n"
                "jwt.decode(token, k)\n")
        assert _lines(code, PAYLOAD_CWE) == set()

    def test_existing_hardcoded_jwt_secret_contract_is_untouched(self):
        # HEAD already reports a literal signing key; the new rule must not absorb or replace it.
        code = ("import jwt\n\n"
                "jwt.encode({'sub': 'a'}, 'super-secret-key', algorithm='HS256')\n")
        assert _findings(code, PAYLOAD_CWE) == {(3, "HARDCODED_JWT_SECRET")}


class TestDocumentedDeviationsFromTheBrief:
    def test_receiver_need_not_be_named_jwt(self):
        # The anchor is the call's last segment (encode / Encrypt / sign) plus a token library
        # import somewhere in the module, so any alias of the library is matched.
        code = ("import jwt as token_lib\n\n"
                "token_lib.encode({'password': pw}, k)\n")
        assert _lines(code, PAYLOAD_CWE) == {3}

    def test_module_without_a_token_library_is_not_scoped(self):
        # A broad "any sensitive dict" reading fires on 2 gate good cases, so the dictionary
        # has to be reachable from a token call in a module that imports a token library.
        code = "x.encode({'password': pw}, k)\n"
        assert _lines(code, PAYLOAD_CWE) == set()

    def test_credential_nested_one_level_down_is_not_matched(self):
        # Known gap, measured: only the keys of the dictionary that is itself the argument are
        # inspected, so {'user': {'password': ...}} stays silent rather than guessing at depth.
        code = "import jwt\n\njwt.encode({'user': {'password': pw}}, k)\n"
        assert _lines(code, PAYLOAD_CWE) == set()

    def test_mutable_default_finding_survives_audit_all_off(self):
        # The synthetic source id path is unconditional, so the rule does not depend on the
        # wide-audit flag.
        code = "def f(acc=[]):\n    acc.append(1)\n"
        tracker = TaintTracker(files={"sample.py": code})
        _sources, sinks, edges = tracker.analyze()
        by_id = {sink.id: sink for sink in sinks}
        assert {(by_id[e.target_id].location.line_start,
                 by_id[e.target_id].metadata.get("cwe"))
                for e in edges if e.target_id in by_id} == {(2, MUTABLE_CWE)}


class TestCorpusLocks:
    def test_default_mutable_list_file(self):
        code = _corpus("python/lang/correctness/common-mistakes/default-mutable-list.py")
        hits = _lines(code, MUTABLE_CWE)
        assert hits == MUTABLE_CORPUS_HITS
        # Everything below the "should not fire" banner is a `# OK` negative.
        assert max(hits) == 144

    def test_default_mutable_dict_file(self):
        code = _corpus("python/lang/correctness/common-mistakes/default-mutable-dict.py")
        hits = _lines(code, MUTABLE_CWE)
        assert hits == MUTABLE_CORPUS_HITS

    def test_exposed_credentials_file(self):
        code = _corpus("python/jwt/security/jwt-exposed-credentials.py")
        assert _lines(code, PAYLOAD_CWE, "HARDCODED_CREDENTIAL_IN_PAYLOAD") == {4, 8, 17}
        # Line 23 is the `# ok:` payload: standard claim keys only.
        assert 23 not in _lines(code, PAYLOAD_CWE)


class TestEngineWiring:
    def test_both_operations_are_registered_source_ids(self):
        # An unregistered operation would still report (the lookup has a fallback), but the
        # registry is the documented contract, so a new rule has to be added to it.
        registry = ast_scanner.CLUSTER3_STRUCTURAL_SOURCE_IDS
        assert registry["MUTABLE_DEFAULT_ARGUMENT"] == "MUTABLE_DEFAULT_ARGUMENT"
        assert registry["HARDCODED_CREDENTIAL_IN_PAYLOAD"] == \
            "HARDCODED_CREDENTIAL_IN_PAYLOAD"
