"""CWE-611 truth table: which XML shapes the engine answers, and what a safe exemption may cover.

Why this gate exists
--------------------
CWE-611 is the largest single finding count in the tracked real-world artifact: 491 findings on
odoo/odoo@17.0 (7,191 python files, engine rev f7d144f2, GitHub run 39999081384), out of 2,128 total.
This probe is the contract the exemption was written against, and the thing that fails loudly if any
part of it is widened, narrowed or half-undone by a later refactor.

Three record paths answer for one XML parse call
------------------------------------------------
  * the sink registry - `TCS_SINKS` entries at ast_scanner.py:748-754, message `CWE-611: <sink>`;
  * the aliased-import emitter - ast_scanner.py:14891-14923, reached whenever the callee segment is in
    `CLUSTER2_XML_METHODS` (ast_scanner.py:1659) and the import form starts with `xml.` or `lxml.`
    (`CLUSTER2_XML_UNSAFE_ROOTS`, ast_scanner.py:1661);
  * the structural phase-7 layer - ast_scanner.py:21734-21775, which is the only place that knows how
    to *take a finding away*: `_is_defused` (:21411), `_parser_is_safe` (:21414), the removal (:21773).

The defect this closed was that the last of those three could not reach the second. Phase 7 judged an
author-written document inert and removed the registry record; the emitter then added its own back,
because all it asked was "is the leaf called `parse` and the argument a Constant". Both now call one
question, `_xml_parse_is_inert` (ast_scanner.py:2731), the same shape CWE-117 uses to keep its two
paths honest (`_cwe117_message_is_sealed`, ast_scanner.py:5334).

Measured evidence behind the numbers. Tier 2 and tier 3 below re-measure everything this gate claims
from the tracked tree alone; the odoo figures were measured against odoo/odoo@17.0 in the git-ignored
`scratch/` tree (`_c611_truth.py`, `_c611_classify.py`, plus the eight fetched files), so they are the
reason the exemption is bounded to 10.8% rather than a check CI can re-run.
--------------------------------------------------------------------------------------------
  odoo message split          : 361 lxml.etree.fromstring, 53 ALIASED_UNSAFE_XML_PARSE,
                                51 lxml.html.fromstring, 13 lxml.etree.parse, 5 minidom.parseString,
                                3 lxml.objectify.fromstring, 2+2 etree.*, 1 dateutil.parser.parse
  odoo path split             : 366 of 491 under a `tests/` directory, 125 in shipped code, 120 files
  8-file sample reproduced    : 214 of 214 CWE-611 findings, identical lines, peak 59.2 MB / 17.2 s
  argument census of those 212: 37 provably author-written (all 37 ride ALIASED_UNSAFE_XML_PARSE),
                                0 author-written rows on the registry message,
                                44 parse the app's own renderer output (`_render`), 26 parameters,
                                45 unresolvable names, 14 attributes, 11 `f.read()` on a variable path
  bound on any literal fix     : the exemption can only move ALIASED rows = 53 of 491 = 10.8%.
                                The other 438 findings sit on dynamic values and are not proven safe.

The two lines the exemption must not cross
------------------------------------------
1. "the argument is a constant" is not "the argument is inert". A constant XML document can carry its
   own payload:

       etree.fromstring('<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>')  -> REPORTED
       minidom.parseString('<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>') -> REPORTED

   `_xml_parse_is_inert` asks `_xml_declares_entity` (ast_scanner.py:2689) before either of its two
   yes-branches, so an entity declaration vetoes the exemption whatever the parser looks like --
   including `XMLParser(resolve_entities=False)`. The two `*_external_entity` rows below are that
   tripwire.
2. "folds to a literal" is not "was written here". `_xml_written_document_text`
   (ast_scanner.py:2642) reads the argument structurally -- a Constant, a placeholder-free f-string,
   a concatenation, a codec hop over those -- and never follows the assignment chain. Measured reason:
   `benchmark/corpus/cwe_776_xml_bomb/test_v03_bad.py` is `def process_file(path): ET.parse(path)`
   with `process_file("config.xml")` on line 7, and the chain fold answers `"config.xml"` for the
   parameter. The file it names is unbounded XML, the line is a blessed true positive, and one call
   site in the same module is not proof of what the parameter holds at runtime. A name -- parameter,
   module constant, or import -- is None here and stays reported, which is what keeps all 16 blessed
   CWE-611 keys on the `*_param`, `module_constant_import` and `parse_variable_file` shapes.

Root qualification and repo-internal reads (the two narrowings this gate also pins)
-------------------------------------------------------------------------------
1. A leaf is not a library. `rule_engine.CWE611_SINKS` matches the bare leaves `parse` and
   `fromstring`, so `dateutil.parser.parse` reached the report on a date string. The engine now asks
   `_xml_sink_recognised` (ast_scanner.py), which refuses a *resolved* leaf under a non-XML root and
   keeps every unresolved or bare name reported. `lxml.html`, `lxml.objectify`, `xml.dom.minidom`
   and the stdlib `fromstring` rows below are the proof the leaf itself still answers.
2. A file inside the repo is not an attacker's document. `_xml_input_is_internal_repo_file` accepts
   only `<handle>.read()` where the handle is the *unique* binding of `open`/`file_open(<literal>)`,
   the realpath stays strictly inside the scanned tree, and the file's bytes declare no
   `<!DOCTYPE`/`<!ENTITY`. Tier 5 writes those fixtures into `tempfile.mkdtemp()`: the entity file,
   the `../` escape, the missing path and the rebound handle must all stay reported.

What is already right, and must stay right
------------------------------------------
`defusedxml` is silent in both spellings -- including the `*_external_entity` case, because that
removal at ast_scanner.py:21411 is entity-blind and stays so: defusedxml refuses DTDs by
construction, so the declaration never resolves. Widening the entity veto to cover it would cost
findings on safe code and buys no detection. `XMLParser(resolve_entities=True)` reports.

Seal semantics - `XML_LITERAL_SEAL`
-----------------------------------
  'shipped' (today) : the false-positive rows MUST be silent, and MUST_REPORT_ROWS must stay loud on
            both spellings - narrow AND still catching the bad input.
  'abstained'       : the false-positive rows MUST still be loud. If one goes quiet while the seal
            says abstained, an exemption was shipped without updating this contract, and the
            path-agreement claim can no longer be trusted.
Either way a mismatch is exit 1.
"""
from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile

GATES_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(GATES_DIR, '..', '..'))
sys.path.insert(0, ROOT)
sys.path.insert(0, GATES_DIR)

import ast_scanner  # noqa: E402
import cli  # noqa: E402
from gate_common import META, load_keys, scan_rows  # noqa: E402

XML_LITERAL_SEAL = 'shipped'
SEAL_TARGETS = ('abstained', 'shipped')

# The blessed CWE-611 population, counted from the frozen baselines themselves.
CWE611_LOCKED = {'parity': 16, 'big8': 0}

# --------------------------------------------------------------------------- shapes
# (label, source, expect_when_abstained, expect_when_shipped)
# 'loud' = a CWE-611 finding is required, 'quiet' = none is allowed.
SHAPES = [
    # ---- author-written documents: no attacker byte can enter, so these are the FP candidates ----
    ('alias_literal_doc', 'from lxml import etree\n\n\ndef render():\n    return etree.fromstring("""<root><a/></root>""")\n',
     'loud', 'quiet'),
    ('dotted_literal_doc', 'import lxml.etree\n\n\ndef render():\n    return lxml.etree.fromstring("""<root><a/></root>""")\n',
     'loud', 'quiet'),
    ('stdlib_alias_literal_doc', 'import xml.etree.ElementTree as ET\n\n\ndef render():\n    return ET.fromstring("<root><a/></root>")\n',
     'loud', 'quiet'),
    ('minidom_literal_doc', 'from xml.dom import minidom\n\n\ndef render():\n    return minidom.parseString("<root><a/></root>")\n',
     'loud', 'quiet'),
    ('minidom_dotted_literal', 'import xml.dom.minidom\n\n\ndef render():\n    return xml.dom.minidom.parseString("<root/>")\n',
     'loud', 'quiet'),
    ('literal_through_codec', 'from lxml import etree\n\n\ndef render():\n    return etree.fromstring(b"<root/>".decode().encode())\n',
     'loud', 'quiet'),
    ('iterparse_literal_name', 'from lxml import etree\n\n\ndef load():\n    return etree.iterparse("sample.xml")\n',
     'loud', 'quiet'),
    # ---- provably inert parser configuration: the second FP family ----
    ('safe_parser_kw', 'from lxml import etree\n\n\ndef parse_xml(payload):\n    return etree.fromstring(payload, parser=etree.XMLParser(resolve_entities=False))\n',
     'loud', 'quiet'),
    ('safe_parser_positional', 'from lxml import etree\n\n\ndef parse_xml(payload):\n    return etree.fromstring(payload, etree.XMLParser(resolve_entities=False))\n',
     'loud', 'quiet'),
    ('safe_parser_no_dtd', 'from lxml import etree\n\n\ndef parse_xml(payload):\n    return etree.fromstring(payload, parser=etree.XMLParser(with_dtd=False, with_external_dtd=False, resolve_entities=False))\n',
     'loud', 'quiet'),
    ('safe_parse_file_kw', 'from lxml import etree\n\n\ndef load(path):\n    return etree.parse(path, parser=etree.XMLParser(resolve_entities=False))\n',
     'loud', 'quiet'),
    # ---- already silent, and required to stay silent at both seals ----
    ('defused_param', 'import defusedxml.ElementTree as DET\n\n\ndef parse_xml(payload):\n    return DET.fromstring(payload)\n',
     'quiet', 'quiet'),
    ('defused_alias_param', 'from defusedxml import ElementTree as DET\n\n\ndef render(payload):\n    return DET.fromstring(payload)\n',
     'quiet', 'quiet'),
    ('parse_literal_file', 'from lxml import etree\n\n\ndef render():\n    return etree.parse("sample.xml")\n',
     'quiet', 'quiet'),
    # ---- the bad input: loud at both seals, this is the proof the exemption stays narrow ----
    ('alias_param', 'from lxml import etree\n\n\ndef parse_xml(payload):\n    return etree.fromstring(payload)\n',
     'loud', 'loud'),
    ('dotted_param', 'import lxml.etree\n\n\ndef parse_xml(payload):\n    return lxml.etree.fromstring(payload)\n',
     'loud', 'loud'),
    ('request_fed', 'from lxml import etree\nfrom flask import request\n\n\ndef upload():\n    xml_data = request.get_data()\n    return etree.fromstring(xml_data)\n',
     'loud', 'loud'),
    ('percent_of_var', 'from lxml import etree\n\n\ndef wrap(xpath):\n    return etree.fromstring("<data>%s</data>" % xpath)\n',
     'loud', 'loud'),
    ('fstring_of_var', 'from lxml import etree\n\n\ndef wrap(xpath):\n    return etree.fromstring(f"<data>{xpath}</data>")\n',
     'loud', 'loud'),
    ('subscript_of_local_dict', 'from lxml import etree\n\n\ndef parse_xml(xml_data):\n    payloads = {"xml": xml_data.encode()}\n    return etree.fromstring(payloads["xml"])\n',
     'loud', 'loud'),
    ('attribute_of_self', 'from lxml import etree\n\n\nclass C:\n    def __init__(self, xml_data):\n        self.payload = xml_data.encode()\n\n    def parse(self):\n        return etree.fromstring(self.payload)\n',
     'loud', 'loud'),
    # A document literal is only inert when nothing in it resolves. `<!ENTITY ... SYSTEM>` is the
    # attacker byte written into the document itself, so these two rows are the edge every future
    # literal exemption has to survive: an exemption keyed on "the argument is a constant" and not
    # on "the constant declares no external entity" deletes them. Measured loud at HEAD `ca2142d`
    # (ast_scanner.py:14786 and :751), so they hold today and must hold at both seals.
    ('literal_declares_external_entity',
     'from lxml import etree\n\n\ndef render():\n'
     '    return etree.fromstring("""<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
     '<r>&xxe;</r>""")\n',
     'loud', 'loud'),
    ('minidom_literal_declares_external_entity',
     'from xml.dom import minidom\n\n\ndef render():\n'
     '    return minidom.parseString("""<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>'
     '<r>&x;</r>""")\n',
     'loud', 'loud'),
    ('unsafe_parser_true', 'from lxml import etree\n\n\ndef parse_xml(payload):\n    return etree.fromstring(payload, parser=etree.XMLParser(resolve_entities=True))\n',
     'loud', 'loud'),
    ('file_read_variable_path', 'from lxml import etree\n\n\ndef load(path):\n    with open(path) as handle:\n        return etree.fromstring(handle.read())\n',
     'loud', 'loud'),
    ('parse_variable_file', 'import xml.etree.ElementTree as ET\n\n\ndef process_file(path):\n    return ET.parse(path)\n',
     'loud', 'loud'),
    ('sax_dynamic', 'import xml.sax\nfrom xml.sax import ContentHandler\n\n\ndef render(data):\n    return xml.sax.parseString(data, ContentHandler())\n',
     'loud', 'loud'),
    ('module_constant_import', 'from lxml import etree\nfrom app import SAMPLE_DOC\n\n\ndef render():\n    return etree.fromstring(SAMPLE_DOC)\n',
     'loud', 'loud'),
    # ---- root-qualified recognition: the XML leaf only counts under an XML root ----
    # `dateutil.parser.parse` is a date parser that reached the report only because its leaf is
    # called `parse`; the odoo baseline carried exactly these two spellings. Narrowing the *leaf*
    # may not widen into deleting the leaf: every XML-root spelling below stays reported, and an
    # unresolved bare `parse` cannot be proven to be a date parser, so it stays reported too.
    ('dateutil_alias_parse', 'from dateutil.parser import parse\n\n\ndef when(event):\n    return parse(event.updated)\n',
     'loud', 'quiet'),
    # The dotted spelling never matched: the registry only ever matched the bare leaf. Both
    # spellings must land on the same answer, which is what TIER 4's date-parser pair asserts.
    ('dateutil_dotted_parse', 'import dateutil.parser\n\n\ndef when(event):\n    return dateutil.parser.parse(event.updated)\n',
     'quiet', 'quiet'),
    ('html_alias_fromstring_param', 'from lxml import html\n\n\ndef parse_xml(payload):\n    return html.fromstring(payload)\n',
     'loud', 'loud'),
    ('html_dotted_fromstring_param', 'import lxml.html\n\n\ndef parse_xml(payload):\n    return lxml.html.fromstring(payload)\n',
     'loud', 'loud'),
    ('objectify_fromstring_param', 'from lxml import objectify\n\n\ndef parse_xml(payload):\n    return objectify.fromstring(payload)\n',
     'loud', 'loud'),
    ('stdlib_fromstring_direct_param', 'from xml.etree.ElementTree import fromstring\n\n\ndef parse_xml(payload):\n    return fromstring(payload)\n',
     'loud', 'loud'),
    ('minidom_parsestring_param', 'from xml.dom import minidom\n\n\ndef parse_xml(payload):\n    return minidom.parseString(payload)\n',
     'loud', 'loud'),
    ('unresolved_bare_parse', 'def when(event):\n    return parse(event.updated)\n',
     'loud', 'loud'),
]

FP_ROWS = [row for row in SHAPES if row[2] == 'loud' and row[3] == 'quiet']
MUST_REPORT_ROWS = [row for row in SHAPES if row[3] == 'loud']
ALREADY_QUIET_ROWS = [row for row in SHAPES if row[2] == 'quiet']


def scan_path_a(source):
    """Path A: one in-memory module through the real record path, as both baselines are built."""
    with contextlib.redirect_stderr(io.StringIO()):
        tracker = ast_scanner.TaintTracker(files={'m.py': source})
        _, _, edges = tracker.analyze()
        rows = cli._findings_for(tracker, edges)
    return sorted({(row['line'], row['message']) for row in rows if row['cwe'] == 'CWE-611'})


def check_floors():
    """TIER 1: the blessed CWE-611 population, in the baseline and in the engine's own output."""
    failures = []
    for kind in ('parity', 'big8'):
        rows = load_keys(os.path.join(GATES_DIR, META[kind]['keys_file']), kind)
        keys = {row for row in rows if row[2] == 'CWE-611'}
        print(f'  {kind:7s} total={len(rows)} (want {META[kind]["expected_keys"]})  '
              f'CWE-611={len(keys)} (want {CWE611_LOCKED[kind]})')
        if len(rows) != META[kind]['expected_keys']:
            failures.append((kind, 'baseline total', META[kind]['expected_keys'], len(rows)))
        if len(keys) != CWE611_LOCKED[kind]:
            failures.append((kind, 'CWE-611', CWE611_LOCKED[kind], len(keys),
                             'the blessed CWE-611 population moved'))
    return failures


def check_corpus():
    """TIER 2: the frozen keys re-produced by a real tree scan, as an exact key set.

    In-memory single-module scanning is not how the baselines were made - it loses every row that
    depends on package context (a `decode_xml` import, a sibling module), so it under-reports. The
    only honest comparison is the same whole-tree scan `aa_parity` uses, filtered to CWE-611.
    """
    failures = []
    tree = os.path.join(ROOT, META['parity']['scan_root'])
    live = {row for row in scan_rows('parity', tree) if row[2] == 'CWE-611'}
    frozen = {row for row in load_keys(os.path.join(GATES_DIR, META['parity']['keys_file']), 'parity')
              if row[2] == 'CWE-611'}
    missing = sorted(frozen - live)
    extra = sorted(live - frozen)
    print(f'  scan_root={META["parity"]["scan_root"]}  frozen={len(frozen)}  live={len(live)}  '
          f'MISSING={len(missing)} NEW={len(extra)}')
    for row in sorted(frozen):
        tag = 'held' if row in live else 'MISSING'
        print(f'  {tag:8s} {str(row[0])[str(row[0]).find("corpus"):][:52]}:{row[1]} {row[4]}')
    for row in extra:
        print(f'  NEW      {row[0]}:{row[1]} {row[4]}')
    if missing:
        failures.append((len(missing), 'frozen CWE-611 keys no longer reported'))
    if extra:
        failures.append((len(extra), 'CWE-611 keys appeared that the baseline never held'))
    return failures


def check_shapes():
    """TIER 3: the truth table, asserted against the seal the file is standing under."""
    failures = []
    for label, source, when_abstained, when_shipped in SHAPES:
        expected = when_abstained if XML_LITERAL_SEAL == 'abstained' else when_shipped
        found = scan_path_a(source)
        loud = bool(found)
        status = 'loud' if loud else 'quiet'
        note = '; '.join(f'L{n}:{m.replace("CWE-611: ", "")}' for n, m in found)[:52]
        marker = 'ok' if status == expected else 'MISMATCH'
        print(f'  {label:24s} want={expected:5s} got={status:5s} {marker:8s} {note}')
        if status != expected:
            failures.append((label, 'seal', expected, status,
                             'the answer moved without the seal, or the seal moved without the answer'))
    return failures


def check_path_agreement():
    """TIER 4: the same document must not get two answers from two record paths.

    The aliased spelling and the fully dotted spelling are the same call after import resolution, so
    any difference between them means one path is consulting the input shape and the other is not.
    """
    failures = []
    pairs = [
        ('literal document, alias vs dotted',
         'from lxml import etree\n\n\ndef render():\n    return etree.fromstring("""<root/>""")\n',
         'import lxml.etree\n\n\ndef render():\n    return lxml.etree.fromstring("""<root/>""")\n'),
        ('parameter, alias vs dotted',
         'from lxml import etree\n\n\ndef parse_xml(payload):\n    return etree.fromstring(payload)\n',
         'import lxml.etree\n\n\ndef parse_xml(payload):\n    return lxml.etree.fromstring(payload)\n'),
    ]
    pairs.append(
        ('date parser, alias vs dotted',
         'from dateutil.parser import parse\n\n\ndef when(event):\n    return parse(event.updated)\n',
         'import dateutil.parser\n\n\ndef when(event):\n    return dateutil.parser.parse(event.updated)\n'))
    for label, left, right in pairs:
        a = {message for _line, message in scan_path_a(left)}
        b = {message for _line, message in scan_path_a(right)}
        agree = a == b
        print(f'  {label:34s} alias={sorted(a)} dotted={sorted(b)} {"agree" if agree else "DISAGREE"}')
        if not agree:
            failures.append((label, 'the two record paths disagree about the same call', sorted(a), sorted(b)))
    return failures


REPO_FILE_DOC = '<root><item id="1"/></root>\n'
REPO_FILE_ENTITY = '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>\n'

# (relative path, source, expected answer under the shipped seal)
REPO_FILE_CASES = [
    # The eleven odoo rows this answers are `lxml.etree.fromstring(f.read().encode())` on a
    # `with file_open(<literal>)` handle. Nothing here is a parameter, an attribute or a renderer:
    # the bytes come from a file that is inside the scanned tree and declares no entity.
    ('pkg/repo_read.py', 'from lxml import etree\n\n\ndef load():\n'
     '    with open("doc.xml") as handle:\n        return etree.fromstring(handle.read())\n', 'quiet'),
    ('pkg/repo_dotted.py', 'import lxml.etree\n\n\ndef load():\n'
     '    with open("doc.xml") as handle:\n        return lxml.etree.fromstring(handle.read())\n', 'quiet'),
    ('pkg/repo_direct.py', 'from lxml import etree\n\n\ndef load():\n'
     '    return etree.fromstring(open("doc.xml").read())\n', 'quiet'),
    ('pkg/repo_file_open.py', 'from lxml import etree\nfrom odoo.tools import file_open\n\n\ndef load():\n'
     '    with file_open("addons/pkg/doc2.xml") as handle:\n'
     '        return etree.fromstring(handle.read())\n', 'quiet'),
    # The tripwires. Each is one step further out than the exemption is allowed to reach.
    ('pkg/repo_entity.py', 'from lxml import etree\n\n\ndef load():\n'
     '    with open("evil.xml") as handle:\n        return etree.fromstring(handle.read())\n', 'loud'),
    ('pkg/repo_dotted_entity.py', 'import lxml.etree\n\n\ndef load():\n'
     '    with open("evil.xml") as handle:\n        return lxml.etree.fromstring(handle.read())\n', 'loud'),
    ('pkg/repo_escape.py', 'from lxml import etree\n\n\ndef load():\n'
     '    with open("../outside.xml") as handle:\n        return etree.fromstring(handle.read())\n', 'loud'),
    ('pkg/repo_missing.py', 'from lxml import etree\n\n\ndef load():\n'
     '    with open("nope.xml") as handle:\n        return etree.fromstring(handle.read())\n', 'loud'),
    ('pkg/repo_rebound.py', 'from lxml import etree\n\n\ndef load():\n'
     '    handle = open("doc.xml")\n    handle = open("doc.xml")\n'
     '    return etree.fromstring(handle.read())\n', 'loud'),
]


def _write_fixtures():
    # The temp root is created here and never crosses a function boundary as an argument:
    # a `root` parameter is a taint source, so `open(join(root, ...), "w")` is the exact
    # CWE-22 shape and the gate would report itself. Deletion is owned by the
    # TemporaryDirectory handle for the same reason: `shutil.rmtree` is an unconditional
    # CWE-22 sink in this engine, so calling it in harness code adds a NEW parity key.
    holder = tempfile.TemporaryDirectory(prefix='cwe611_repo_', ignore_cleanup_errors=True)
    base = holder.name
    for rel, text in (('scan/doc.xml', REPO_FILE_DOC),
                      ('scan/evil.xml', REPO_FILE_ENTITY),
                      ('scan/addons/pkg/doc2.xml', REPO_FILE_DOC),
                      ('outside.xml', REPO_FILE_DOC)):
        path = os.path.join(base, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(text)
    for rel, source, _expect in REPO_FILE_CASES:
        path = os.path.join(base, 'scan', rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(source)
    return holder


def check_repo_files():
    """TIER 5: a read of an entity-free file inside the scanned tree is inert, and every way out is not.

    The fixture tree is a `tempfile.TemporaryDirectory`, never a directory under `benchmark/`: the
    parity gate scans that whole tree, so a fixture written there would report itself as a NEW key
    and the gate would be measuring its own test data instead of the engine.
    """
    failures = []
    holder = _write_fixtures()
    base = holder.name
    try:
        scan_root = os.path.join(base, 'scan')
        live = [(os.path.normpath(str(row[0])).replace('\\', '/'), row[1])
                for row in scan_rows('parity', scan_root) if row[2] == 'CWE-611']
        for rel, _source, expect in REPO_FILE_CASES:
            hits = [line for path, line in live if path.endswith(rel)]
            got = 'loud' if hits else 'quiet'
            marker = 'ok' if got == expect else 'MISMATCH'
            print(f'  {rel:28s} want={expect:5s} got={got:5s} {marker} lines={hits}')
            if got != expect:
                failures.append((rel, 'repo-file read', expect, got))
    finally:
        holder.cleanup()
    return failures


def main() -> int:
    if XML_LITERAL_SEAL not in SEAL_TARGETS:
        print(f'BAD SEAL: {XML_LITERAL_SEAL!r} is not one of {SEAL_TARGETS}')
        return 1
    print('TIER 1 - blessed CWE-611 floors in both frozen baselines:')
    failures = check_floors()
    print('TIER 2 - the corpus behind those keys, scanned live:')
    failures += check_corpus()
    print(f'TIER 3 - truth table under seal={XML_LITERAL_SEAL!r}:')
    failures += check_shapes()
    print('TIER 4 - the two record paths, same call:')
    failures += check_path_agreement()
    print('TIER 5 - repo-internal file reads, scanned in a temp tree:')
    failures += check_repo_files()
    print(f'\nseal={XML_LITERAL_SEAL} shapes={len(SHAPES)} fp_rows={len(FP_ROWS)} '
          f'must_report={len(MUST_REPORT_ROWS)} already_quiet={len(ALREADY_QUIET_ROWS)} '
          f'repo_rows={len(REPO_FILE_CASES)} '
          f'locked_cwe611={sum(CWE611_LOCKED.values())} failures={len(failures)}')
    for item in failures[:12]:
        print(f'  !! {item}')
    if failures:
        print('VERDICT: FAIL - the CWE-611 XML layer no longer matches its measured evidence. Restore '
              'the answer or update the seal with a re-measured truth table; never re-bless a baseline.')
        return 1
    print('VERDICT: PASS - 16 blessed parity CWE-611 keys held, corpus exact-set, '
          f'{len(MUST_REPORT_ROWS)} untrusted-input shapes reported and '
          f'{len(ALREADY_QUIET_ROWS)} safe-parser shapes silent, both record paths agreeing.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
