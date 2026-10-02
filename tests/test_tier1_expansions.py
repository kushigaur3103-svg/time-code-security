"""Phase 6.3 Tier-1 sink expansions, zero-FP policy.

Covers the five vetted expansions:
  1. hashlib.new(md5/sha1/sha224)           -> CWE-327 (usedforsecurity=False guard)
  2. weak ssl.PROTOCOL_* constants          -> CWE-326
  3. RSA/DSA key generation < 2048 bits     -> CWE-326
  4. legacy Crypto(Dome).Cipher algorithms  -> CWE-327
  5. stdlib XML parse entry points          -> CWE-611 (alias-aware; defusedxml calls stay silent)

Each test asserts vulnerable shapes FIRE and the audited-safe shapes stay SILENT.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ast_scanner import TaintTracker  # noqa: E402
from cli import consolidate_findings, get_rule  # noqa: E402


def _cwes_at(code: str, line: int) -> set[str]:
    """Run the production-parity API pipeline on a snippet and return the CWE ids
    reported for the given (1-based) line."""
    tracker = TaintTracker(files={"snippet.py": code})
    _sources, sinks, edges = tracker.analyze()
    by_id = {s.id: s for s in sinks}
    raw = []
    seen = set()
    for edge in edges:
        sink = by_id.get(edge.target_id)
        if sink is None:
            continue
        cwe = (sink.metadata or {}).get("cwe")
        if not cwe and edge.proof_graph is not None:
            cwe = edge.proof_graph.cwe
        cwe = cwe or "UNKNOWN_CWE"
        rule = get_rule(cwe)
        label = "CONFIRMED" if edge.kind == "CONFIRMED_DATA_FLOW" else "POTENTIAL"
        severity = rule.get_severity(label).upper() if rule else "HIGH"
        finding = {"file": "snippet.py", "line": sink.location.line_start, "cwe": cwe,
                   "severity": severity, "category": "Security", "message": cwe}
        identity = (finding["file"], finding["line"], finding["cwe"])
        if identity not in seen:
            seen.add(identity)
            raw.append(finding)
    return {f["cwe"] for f in consolidate_findings(raw) if f["line"] == line}


def _fires(code: str, line: int, cwe: str) -> None:
    assert cwe in _cwes_at(code, line), f"expected {cwe} at line {line}, got {_cwes_at(code, line)}"


def _silent(code: str, line: int, cwe: str) -> None:
    assert cwe not in _cwes_at(code, line), f"unexpected {cwe} at line {line}"


# ─── 1. hashlib.new(weak algo) ───────────────────────────────────────────────

class TestHashlibNew:
    def test_md5_positional(self):
        _fires("import hashlib\nhashlib.new('md5')\n", 2, "CWE-327")

    def test_sha1_positional(self):
        _fires("import hashlib\nhashlib.new('sha1')\n", 2, "CWE-327")

    def test_sha224_positional(self):
        _fires("import hashlib\nhashlib.new('sha224')\n", 2, "CWE-327")

    def test_name_kwarg_case_insensitive(self):
        _fires("import hashlib\nhashlib.new(string='test', name='MD5')\n", 2, "CWE-327")

    def test_usedforsecurity_true_still_fires(self):
        _fires("import hashlib\nhashlib.new('md5', usedforsecurity=True)\n", 2, "CWE-327")

    def test_usedforsecurity_false_guard(self):
        _silent("import hashlib\nhashlib.new('md5', usedforsecurity=False)\n", 2, "CWE-327")

    def test_strong_algos_silent(self):
        _silent("import hashlib\nhashlib.new('sha256')\n", 2, "CWE-327")
        _silent("import hashlib\nhashlib.new('SHA512')\n", 2, "CWE-327")
        _silent("import hashlib\nhashlib.new('sha3_224')\n", 2, "CWE-327")


# ─── 2. Weak ssl.PROTOCOL_* constants ────────────────────────────────────────

class TestWeakSslProtocol:
    def test_kwarg_in_call(self):
        _fires("import ssl\nssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv2)\n",
               2, "CWE-326")

    def test_sslv3(self):
        _fires("import ssl\nssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv3)\n",
               2, "CWE-326")

    def test_tlsv1_positional(self):
        _fires("import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n", 2, "CWE-326")

    def test_tlsv1_1_other_call(self):
        _fires("import ssl\nsome_other_method(ssl_version=ssl.PROTOCOL_TLSv1_1)\n",
               2, "CWE-326")

    def test_default_argument(self):
        _fires("import ssl\ndef open_ssl_socket(version=ssl.PROTOCOL_SSLv2):\n    pass\n",
               2, "CWE-326")

    def test_from_import_bare_name(self):
        _fires("from ssl import PROTOCOL_SSLv2\nfoo(ssl_version=PROTOCOL_SSLv2)\n",
               2, "CWE-326")

    def test_strong_versions_silent(self):
        _silent("import ssl\nssl.wrap_socket(ssl_version=ssl.PROTOCOL_TLSv1_2)\n",
                2, "CWE-326")
        _silent("import ssl\nssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv23)\n",
                2, "CWE-326")
        _silent("import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS)\n", 2, "CWE-326")


# ─── 3. RSA/DSA key generation below 2048 bits ───────────────────────────────

class TestInsufficientKeySize:
    def test_pycrypto_rsa_bits(self):
        _fires("from Crypto.PublicKey import RSA as r\nr.generate(bits=1024)\n",
               2, "CWE-326")

    def test_cryptodome_rsa_bits(self):
        _fires("from Cryptodome.PublicKey import RSA as r\nr.generate(bits=1024)\n",
               2, "CWE-326")

    def test_pycrypto_dsa_bits(self):
        _fires("from Crypto.PublicKey import DSA as d\nd.generate(bits=1024)\n",
               2, "CWE-326")

    def test_cryptodome_dsa_positional(self):
        _fires("from Cryptodome.PublicKey import DSA as d\nd.generate(512)\n",
               2, "CWE-326")

    def test_cryptography_rsa_key_size(self):
        _fires("from cryptography.hazmat.primitives.asymmetric import rsa\n"
               "rsa.generate_private_key(public_exponent=65537, key_size=1024)\n",
               2, "CWE-326")

    def test_cryptography_dsa_key_size(self):
        _fires("from cryptography.hazmat.primitives.asymmetric import dsa\n"
               "dsa.generate_private_key(key_size=1024)\n", 2, "CWE-326")

    def test_safe_sizes_silent(self):
        _silent("from Crypto.PublicKey import RSA as r\nr.generate(bits=2048)\n",
                2, "CWE-326")
        _silent("from Crypto.PublicKey import RSA as r\nr.generate(bits=3072)\n",
                2, "CWE-326")
        _silent("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                "rsa.generate_private_key(public_exponent=65537, key_size=3072)\n",
                2, "CWE-326")

    def test_dynamic_size_silent(self):
        _silent("import os\nfrom Crypto.PublicKey import RSA as r\n"
                "r.generate(bits=int(os.environ['K']))\n", 3, "CWE-326")


# ─── 4. Legacy broken ciphers ────────────────────────────────────────────────

class TestLegacyCiphers:
    def test_blowfish_bare(self):
        _fires("from Crypto.Cipher import Blowfish\n"
               "cipher = Blowfish.new(key, Blowfish.MODE_CBC)\n", 2, "CWE-327")

    def test_des_aliased(self):
        _fires("from Crypto.Cipher import DES as pycrypto_des\n"
               "cipher = pycrypto_des.new(key, pycrypto_des.MODE_CTR)\n", 2, "CWE-327")

    def test_arc2_aliased_cryptodome(self):
        _fires("from Cryptodome.Cipher import ARC2 as x\n"
               "cipher = x.new(key, x.MODE_CFB, iv)\n", 2, "CWE-327")

    def test_arc4(self):
        _fires("from Crypto.Cipher import ARC4\ncipher = ARC4.new(tempkey)\n",
               2, "CWE-327")

    def test_idea(self):
        _fires("from Crypto.Cipher import IDEA\n"
               "cipher = IDEA.new(key, IDEA.MODE_CBC)\n", 2, "CWE-327")

    def test_xor(self):
        _fires("from Crypto.Cipher import XOR\ncipher = XOR.new(key)\n", 2, "CWE-327")

    def test_dotted_import_form(self):
        _fires("import Crypto.Cipher.Blowfish as bf\ncipher = bf.new(key)\n",
               2, "CWE-327")

    def test_aes_silent(self):
        _silent("from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_GCM)\n",
                2, "CWE-327")


# ─── 5. Stdlib XML parse entry points ────────────────────────────────────────

class TestStdlibXmlSinks:
    def test_elementtree_parse_aliased(self):
        _fires("import xml.etree.ElementTree as ET\nET.parse(user_path)\n",
               2, "CWE-611")

    def test_elementtree_fromstring_full_dotted(self):
        _fires("import xml.etree.ElementTree\nxml.etree.ElementTree.fromstring(data)\n",
               2, "CWE-611")

    def test_elementtree_from_import(self):
        _fires("from xml.etree import ElementTree\nElementTree.parse(user_path)\n",
               2, "CWE-611")

    def test_minidom_parse(self):
        _fires("from xml.dom.minidom import parse\nparse(user_path)\n", 2, "CWE-611")

    def test_minidom_parse_string(self):
        _fires("import xml.dom.minidom\nxml.dom.minidom.parseString(data)\n",
               2, "CWE-611")

    def test_sax_parse(self):
        _fires("import xml.sax\nxml.sax.parse(user_path, handler)\n", 2, "CWE-611")

    def test_sax_parse_string(self):
        _fires("from xml.sax import parseString\nparseString(data, handler)\n",
               2, "CWE-611")

    def test_defusedxml_alias_never_flagged(self):
        _silent("import defusedxml.ElementTree as ET\nET.parse(user_path)\n", 2, "CWE-611")

    def test_stdlib_use_flagged_despite_defusedxml_import(self):
        # Bandit corpus ground truth (xml_* examples): a defusedxml import elsewhere in the
        # module does not excuse the stdlib alias — resolution is per-call, not per-module.
        _fires("import xml.etree.ElementTree as badET\n"
               "import defusedxml.ElementTree as goodET\nbadET.parse(user_path)\n",
               3, "CWE-611")

    def test_good_alias_line_silent_next_to_bad(self):
        _silent("from xml.dom.minidom import parseString as bad\n"
                "from defusedxml.minidom import parseString as good\n"
                "a = bad(xmlString)\nb = good(xmlString)\n", 4, "CWE-611")

    def test_literal_parse_safe_shape(self):
        _silent("import xml.etree.ElementTree as ET\nET.parse('f.xml')\n", 2, "CWE-611")
