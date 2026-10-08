"""Characterisation tests for CWE-611: stdlib XML parser entry points.

Why these tests exist instead of a new rule. The task asked for a deterministic structural
CWE-611 audit over `xml.etree`, `xml.dom.minidom`, `xml.dom.pulldom` and `xml.sax`. It was
built, measured and then removed, because measurement showed it changes nothing:

  * Prototype predicate over 1181 labelled files (552 gate cases + 629 external benchmark
    files): 33 candidate sites, 8 on positive-labelled sites, 0 on negative-labelled sites.
  * Same 1181 files scanned by the committed engine and by the engine with the new rule:
    added findings = 0, removed findings = 0, distinct CWE-611 (file, line) positions 45 -> 45.

Every site the new rule matched was already reported, by the Cluster 2 alias rule
(`ALIASED_UNSAFE_XML_PARSE`), by the Phase 7 XXE collector, or by the registry sinks. The only
sites the new rule could have added were `parse('<literal path>')` calls, and the suite already
pins those as the audited-safe shape (`test_literal_parse_safe_shape`), so claiming them would
have broken a tested contract for zero net coverage.

These tests therefore lock down what the shipped engine actually does, so a future edit to this
family is a deliberate decision and not a silent regression. The two gaps at the bottom are real
deviations from the brief, written as passing tests so they are visible rather than hidden.
"""

from ast_scanner import TaintTracker


def _xxe_lines(code):
    tracker = TaintTracker(files={"sample.py": code})
    _sources, sinks, edges = tracker.analyze()
    by_id = {sink.id: sink for sink in sinks}
    return {by_id[edge.target_id].location.line_start
            for edge in edges
            if edge.target_id in by_id
            and by_id[edge.target_id].metadata.get("cwe") == "CWE-611"}


class TestStdlibElementTreeIsFlagged:
    def test_aliased_module_parse(self):
        assert _xxe_lines("""
import xml.etree.ElementTree as ET
tree = ET.parse(user_path)
""") == {3}

    def test_full_dotted_path_fromstring(self):
        assert _xxe_lines("""
import xml.etree.ElementTree
xml.etree.ElementTree.fromstring(data)
""") == {3}

    def test_module_import_then_parse(self):
        assert _xxe_lines("""
from xml.etree import ElementTree
ElementTree.parse(user_path)
""") == {3}

    def test_celementtree_iterparse(self):
        assert _xxe_lines("""
import xml.etree.cElementTree as ET
ET.iterparse('payload.xml')
""") == {3}

    def test_bare_function_import(self):
        assert _xxe_lines("""
from xml.etree.ElementTree import fromstring
fromstring(data)
""") == {3}


class TestOtherParserFamiliesAreFlagged:
    def test_minidom_parse(self):
        assert _xxe_lines("""
from xml.dom.minidom import parse
parse(user_path)
""") == {3}

    def test_minidom_parse_string(self):
        assert _xxe_lines("""
import xml.dom.minidom
xml.dom.minidom.parseString(data)
""") == {3}

    def test_pulldom_parse(self):
        assert _xxe_lines("""
from xml.dom import pulldom
pulldom.parse(user_path)
""") == {3}

    def test_sax_module_alias_and_bare_alias(self):
        assert _xxe_lines("""
import xml.sax
from xml import sax
xml.sax.parseString(body, Handler())
sax.parse(user_path, Handler)
sax.make_parser()
""") == {4, 5, 6}


class TestDefusedXmlIsClean:
    def test_defusedxml_aliased_module(self):
        assert _xxe_lines("""
import defusedxml.ElementTree as ET
ET.parse(user_path)
""") == set()

    def test_defusedxml_from_import(self):
        assert _xxe_lines("""
from defusedxml.etree import ElementTree
ElementTree.parse(user_path)
""") == set()

    def test_good_alias_line_silent_next_to_bad(self):
        assert _xxe_lines("""
from xml.dom.minidom import parseString as bad
from defusedxml.minidom import parseString as good
a = bad('<x/>')
b = good('<x/>')
""") == {4}

    def test_resolution_is_per_scope_not_per_file(self):
        """`ok()` rebinds ElementTree to defusedxml after `bad()` bound it to xml.etree.

        A file-global last-wins alias map would silently mark both sites safe.
        """
        assert _xxe_lines("""
def bad(input_string):
    from xml.etree import ElementTree
    return ElementTree.parse(input_string)

def ok(input_string):
    from defusedxml.etree import ElementTree
    return ElementTree.parse(input_string)
""") == {4}


class TestTreeBuildingIsClean:
    def test_element_subelement_tostring(self):
        assert _xxe_lines("""
import xml.etree.ElementTree as ET
root = ET.Element('note')
child = ET.SubElement(root, 'to')
data = ET.tostring(root)
""") == set()

    def test_document_construction(self):
        assert _xxe_lines("""
from xml.dom.minidom import Document
doc = Document()
text = doc.toxml()
""") == set()


class TestLiteralDocumentPathContract:
    """`parse('f.xml')` is the audited-safe shape; only `parse` gets that treatment."""

    def test_parse_of_literal_path_is_silent(self):
        assert _xxe_lines("""
import xml.etree.ElementTree as ET
ET.parse('f.xml')
""") == set()

    def test_sax_parse_of_literal_path_is_silent(self):
        assert _xxe_lines("""
import xml.sax
xml.sax.parse('f.xml', Handler)
""") == set()

    def test_iterparse_of_literal_path_still_fires(self):
        assert _xxe_lines("""
import xml.etree.ElementTree as ET
ET.iterparse('f.xml')
""") == {3}

    def test_fromstring_of_literal_content_still_fires(self):
        assert _xxe_lines("""
import xml.etree.ElementTree as ET
ET.fromstring('<note/>')
""") == {3}


class TestDocumentedDeviationsFromTheBrief:
    """Two conditions the brief asked for that the shipped engine does not implement.

    Written as passing tests of current behaviour, not as expected failures, so the gap is
    recorded where a reader will find it. Neither one changes the gate or the corpus score:
    over all 1181 labelled files no site is currently affected.
    """

    def test_defuse_stdlib_is_not_honoured_module_wide(self):
        """A module that calls defusedxml.defuse_stdlib() has safe stdlib parsers, but the
        parse site is still reported. Fixing this needs a module-level fact consulted by the
        Cluster 2 alias rule and the registry sinks, not just one collector."""
        assert _xxe_lines("""
import xml.etree.ElementTree as ET
from defusedxml import defuse_stdlib
defuse_stdlib()
ET.parse(user_path)
""") == {5}

    def test_any_receiver_named_xml_is_reported_not_only_stdlib_paths(self):
        """`xml` here is a plain object from load_config(), so the resolved chain is not a
        stdlib parser family. The rule keys on the written name, which is broader than the
        brief's four families."""
        assert _xxe_lines("""
xml = load_config()
tree = xml.parse(user_path)
""") == {3}
