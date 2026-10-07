"""Regression tests for the H2 static-config rules: unverified JWT decode and empty cipher key.

Both checks are pure line-local AST patterns inside the Cluster 3 structural collector, so
they need no taint source and must stay silent on the corpus' own negative controls.

The measured corpus exposure was two `# ruleid:` sites and zero `# ok:` sites for the JWT
option, one and zero for the empty key. The deliberate limits are encoded here as tests:
a name-bound boolean (`{"verify_signature": a_false_boolean}`) is undecidable at the line,
and unauthenticated CBC without a nearby HMAC fires on lines the corpus labels `# ok:`,
so neither is reported.
"""

from ast_scanner import TaintTracker


def _hits(code):
    tracker = TaintTracker(files={"sample.py": code})
    _sources, sinks, edges = tracker.analyze()
    by_id = {sink.id: sink for sink in sinks}
    found = set()
    for edge in edges:
        sink = by_id.get(edge.target_id)
        if sink is None:
            continue
        found.add((sink.location.line_start, sink.metadata.get("cwe"), sink.symbol))
    return found


class TestUnverifiedJwtDecode:
    def test_inline_options_dict_flagged(self):
        code = (
            "import jwt\n"
            "def read(encoded, key):\n"
            "    return jwt.decode(encoded, key, options={\"verify_signature\": False})\n"
        )
        assert (3, "CWE-287", "UNVERIFIED_JWT_DECODE") in _hits(code)

    def test_assigned_options_dict_flagged_at_its_own_line(self):
        code = (
            "import jwt\n"
            "def read(encoded, key):\n"
            "    opts = {\"verify_signature\": False}\n"
            "    return jwt.decode(encoded, key, options=opts)\n"
        )
        hits = _hits(code)
        assert (3, "CWE-287", "UNVERIFIED_JWT_DECODE") in hits
        assert not any(line == 4 for line, _cwe, _op in hits)

    def test_signature_verification_enabled_is_clean(self):
        code = (
            "import jwt\n"
            "def read(encoded, key):\n"
            "    return jwt.decode(encoded, key, options={\"verify_signature\": True})\n"
        )
        assert not [hit for hit in _hits(code) if hit[1] == "CWE-287"]

    def test_no_options_argument_is_clean(self):
        code = (
            "import jwt\n"
            "def read(encoded, key):\n"
            "    return jwt.decode(encoded, key)\n"
        )
        assert not [hit for hit in _hits(code) if hit[1] == "CWE-287"]

    def test_name_bound_boolean_is_left_undecided(self):
        """`a_false_boolean` may be True or False; guessing would mint false positives."""
        code = (
            "import jwt\n"
            "def read(encoded, key):\n"
            "    a_false_boolean = False\n"
            "    opts2 = {\"verify_signature\": a_false_boolean}\n"
            "    return jwt.decode(encoded, key, options=opts2)\n"
        )
        assert not [hit for hit in _hits(code) if hit[1] == "CWE-287"]

    def test_unrelated_options_dict_is_clean(self):
        code = (
            "import jwt\n"
            "def read(encoded, key):\n"
            "    opts = {\"require_exp\": False}\n"
            "    return jwt.decode(encoded, key, options=opts)\n"
        )
        assert not [hit for hit in _hits(code) if hit[1] == "CWE-287"]


class TestEmptyCipherKey:
    def test_pycryptodome_empty_key_flagged(self):
        code = (
            "from Crypto.Ciphers import AES\n"
            "def seal(iv):\n"
            "    return AES.new(\"\", AES.MODE_CFB, iv)\n"
        )
        assert (3, "CWE-327", "EMPTY_CIPHER_KEY") in _hits(code)

    def test_cryptography_empty_key_flagged(self):
        code = (
            "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
            "def seal(iv):\n"
            "    return Cipher(algorithms.AES(\"\"), modes.CBC(iv))\n"
        )
        assert (3, "CWE-327", "EMPTY_CIPHER_KEY") in _hits(code)

    def test_real_key_is_clean(self):
        code = (
            "from Crypto.Ciphers import AES\n"
            "def seal(key, nonce):\n"
            "    return AES.new(key, AES.MODE_EAX, nonce=nonce)\n"
        )
        assert not [hit for hit in _hits(code) if hit[2] == "EMPTY_CIPHER_KEY"]

    def test_non_empty_string_literal_is_clean(self):
        code = (
            "from Crypto.Ciphers import AES\n"
            "def seal(iv):\n"
            "    return AES.new(\"a-real-key\", AES.MODE_CFB, iv)\n"
        )
        assert not [hit for hit in _hits(code) if hit[2] == "EMPTY_CIPHER_KEY"]

    def test_unrelated_empty_first_argument_is_clean(self):
        code = (
            "class Registry:\n"
            "    @staticmethod\n"
            "    def new(name):\n"
            "        return name\n\n"
            "def build():\n"
            "    return Registry.new(\"\")\n"
        )
        assert not [hit for hit in _hits(code) if hit[2] == "EMPTY_CIPHER_KEY"]
