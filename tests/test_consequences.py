import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from etl.consequences import (
    CAPEC_IMPACTS,
    CWE_IMPACTS,
    LIKELIHOODS,
    SCOPES,
    consequence_records,
    flatten_text,
    out_of_vocabulary,
    unique_attrs,
    unique_texts,
)

SHAPES = Path(__file__).resolve().parents[1] / "spec" / "shapes"
NS = "{urn:test}"


def _shape_in_lists(shape_file: str, node_shape: str) -> dict:
    """{property local name: sh:in values} of one node shape in the pinned spec."""
    from rdflib import Graph, Namespace, URIRef
    from rdflib.collection import Collection

    if not (SHAPES / shape_file).exists():
        pytest.skip("spec/ not materialized (run python sync_spec.py)")
    SH = Namespace("http://www.w3.org/ns/shacl#")
    g = Graph().parse(str(SHAPES / shape_file), format="turtle")
    out = {}
    for shape in g.subjects(SH.targetClass, None):
        if not str(shape).endswith(node_shape):
            continue
        for prop in g.objects(shape, SH.property):
            values = g.value(prop, SH["in"])
            if values is not None:
                path = str(g.value(prop, SH.path)).split("#")[-1]
                out[path] = tuple(str(v) for v in Collection(g, values))
    assert out, f"{node_shape} not found in {shape_file}"
    return out


def test_cwe_vocabularies_match_pinned_shapes():
    lists = _shape_in_lists("cwe.shacl.ttl", "ConsequenceShape")
    assert set(lists["scope"]) == set(SCOPES)
    assert set(lists["technical_impact"]) == set(CWE_IMPACTS)
    assert len(CWE_IMPACTS) == 25
    assert set(lists["consequence_likelihood"]) == set(LIKELIHOODS)


def test_capec_vocabularies_match_pinned_shapes():
    lists = _shape_in_lists("capec.shacl.ttl", "ConsequenceShape")
    assert set(lists["scope"]) == set(SCOPES)
    assert set(lists["technicalImpact"]) == set(CAPEC_IMPACTS)
    assert len(CAPEC_IMPACTS) == 10
    assert set(lists["consequenceLikelihood"]) == set(LIKELIHOODS)


def test_impact_vocabularies_are_never_merged():
    # Same wording only where MITRE uses the same string; the fine CWE terms
    # are not CAPEC terms and vice versa.
    assert "Read Application Data" in CWE_IMPACTS and "Read Application Data" not in CAPEC_IMPACTS
    assert "Read Data" in CAPEC_IMPACTS and "Read Data" not in CWE_IMPACTS
    assert set(CWE_IMPACTS) & set(CAPEC_IMPACTS) == {
        "Bypass Protection Mechanism", "Hide Activities", "Alter Execution Logic", "Other",
    }


def test_flatten_text_collapses_structured_text():
    elem = ET.fromstring(
        '<Note xmlns:xhtml="http://www.w3.org/1999/xhtml">\n\t\t'
        "<xhtml:p>First  para <xhtml:b>bold</xhtml:b>.</xhtml:p>\n"
        "<xhtml:ul><xhtml:li>one</xhtml:li>\n<xhtml:li>two</xhtml:li></xhtml:ul>\n</Note>"
    )
    assert flatten_text(elem) == "First para bold. one two"
    assert flatten_text(ET.fromstring("<Note>  \n\t </Note>")) is None
    assert flatten_text(None) is None


def test_unique_values_keep_first_seen_order():
    root = ET.fromstring("<r><p> B </p><p>A</p><p>B</p><p></p><q Type='X'/><q Type='Y'/><q Type='X'/></r>")
    assert unique_texts(root.findall("p")) == ["B", "A"]
    assert unique_attrs(root.findall("q"), "Type") == ["X", "Y"]


def _consequences(xml: str):
    root = ET.fromstring(f'<Common_Consequences xmlns="urn:test">{xml}</Common_Consequences>')
    return root.findall(f"{NS}Consequence")


def test_multi_valued_records_stay_grouped_and_ordered():
    rows = consequence_records("CWE-79", _consequences(
        "<Consequence><Scope>Confidentiality</Scope><Scope>Integrity</Scope>"
        "<Impact>Read Application Data</Impact><Impact>Execute Unauthorized Code or Commands</Impact>"
        "<Note>first</Note></Consequence>"
        "<Consequence><Scope>Availability</Scope><Scope>Availability</Scope>"
        "<Impact>DoS: Crash, Exit, or Restart</Impact><Likelihood>High</Likelihood></Consequence>"
    ), NS)
    assert rows == [
        {"parentId": "CWE-79", "consequenceId": "CWE-79-C1",
         "scopes": ["Confidentiality", "Integrity"],
         "impacts": ["Read Application Data", "Execute Unauthorized Code or Commands"],
         "likelihood": None, "note": "first"},
        {"parentId": "CWE-79", "consequenceId": "CWE-79-C2",
         "scopes": ["Availability"],                     # deduplicated inside the record
         "impacts": ["DoS: Crash, Exit, or Restart"],
         "likelihood": "High", "note": None},
    ]


def test_record_without_impact_has_no_impacts_property():
    rows = consequence_records("CAPEC-1", _consequences(
        "<Consequence><Scope>Other</Scope></Consequence>"
    ), NS)
    assert rows[0]["impacts"] is None           # absent, never []
    assert rows[0]["consequenceId"] == "CAPEC-1-C1"


def test_out_of_vocabulary_is_per_standard():
    rows = consequence_records("CAPEC-2", _consequences(
        "<Consequence><Scope>Integrity</Scope><Impact>Read Application Data</Impact>"
        "<Likelihood>Often</Likelihood></Consequence>"
    ), NS)
    assert out_of_vocabulary(rows, CWE_IMPACTS) == ["CAPEC-2-C1 likelihood 'Often'"]
    assert out_of_vocabulary(rows, CAPEC_IMPACTS) == [
        "CAPEC-2-C1 impact 'Read Application Data'",
        "CAPEC-2-C1 likelihood 'Often'",
    ]
