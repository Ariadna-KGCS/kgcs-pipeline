"""Focused tests for CWE ETL record extraction (enrichment increment 1).

Covers the field table and transformation rules in
spec/mappings/cwe-enrichment-to-owl-v1.0.md:
  - StructuredText flattening (rule 1)
  - array dedup, document order, no empty arrays (rules 2-5)
  - deprecated entries loaded with status flag (rule 6)
  - idempotent refresh via SET += with explicit nulls (rule 7)
"""

import json
from pathlib import Path
from uuid import uuid4

from etl.load_cwe import (
    _CYPHER_WEAKNESS,
    _iter_caused_by_records,
    _iter_weakness_nodes,
)

_XML_HEADER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" '
    'xmlns:xhtml="http://www.w3.org/1999/xhtml" '
    'Name="CWE" Version="4.20" Date="2025-12-11">\n'
)

_FULL_WEAKNESS = """\
<Weaknesses>
<Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')" Abstraction="Base" Structure="Simple" Status="Stable">
  <Description>The product does not neutralize user-controllable input before it is placed in output.</Description>
  <Extended_Description>
    <xhtml:p>Cross-site scripting (XSS) occurs when:</xhtml:p>
    <xhtml:ol>
      <xhtml:li>Untrusted data enters.</xhtml:li>
      <xhtml:li>It is sent unescaped.</xhtml:li>
    </xhtml:ol>
  </Extended_Description>
  <Alternate_Terms>
    <Alternate_Term><Term>XSS</Term><Description><xhtml:p>Common abbreviation.</xhtml:p></Description></Alternate_Term>
    <Alternate_Term><Term>CSS</Term></Alternate_Term>
  </Alternate_Terms>
  <Modes_Of_Introduction>
    <Introduction><Phase>Implementation</Phase><Note><xhtml:p>Realization note.</xhtml:p></Note></Introduction>
    <Introduction><Phase>Architecture and Design</Phase></Introduction>
    <Introduction><Phase>Implementation</Phase></Introduction>
  </Modes_Of_Introduction>
  <Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
  <Weakness_Ordinalities>
    <Weakness_Ordinality><Ordinality>Primary</Ordinality><Description>independent</Description></Weakness_Ordinality>
    <Weakness_Ordinality><Ordinality>Resultant</Ordinality></Weakness_Ordinality>
  </Weakness_Ordinalities>
  <Functional_Areas>
    <Functional_Area>Session Management</Functional_Area>
  </Functional_Areas>
  <Affected_Resources>
    <Affected_Resource>Memory</Affected_Resource>
    <Affected_Resource>Memory</Affected_Resource>
  </Affected_Resources>
  <Mapping_Notes>
    <Usage>Allowed</Usage>
    <Rationale><xhtml:p>Base-level weakness.</xhtml:p></Rationale>
    <Comments><xhtml:p>Carefully consider variants.</xhtml:p></Comments>
    <Reasons><Reason Type="Frequent Misuse"/><Reason Type="Abstraction"/></Reasons>
  </Mapping_Notes>
</Weakness>
</Weaknesses>
"""

_MINIMAL_WEAKNESS = """\
<Weaknesses>
<Weakness ID="1004" Name="Sensitive Cookie Without 'HttpOnly' Flag" Abstraction="Variant" Structure="Simple" Status="Incomplete">
  <Description>Cookie lacks HttpOnly.</Description>
  <Mapping_Notes>
    <Usage>Allowed</Usage>
    <Rationale><xhtml:p>r</xhtml:p></Rationale>
    <Comments><xhtml:p>c</xhtml:p></Comments>
    <Reasons><Reason Type="Acceptable-Use"/></Reasons>
  </Mapping_Notes>
</Weakness>
</Weaknesses>
"""

_DEPRECATED_WEAKNESS = """\
<Weaknesses>
<Weakness ID="373" Name="DEPRECATED: State Synchronization Error" Abstraction="Base" Structure="Simple" Status="Deprecated">
  <Description>This entry has been deprecated.</Description>
  <Mapping_Notes>
    <Usage>Prohibited</Usage>
    <Rationale><xhtml:p>r</xhtml:p></Rationale>
    <Comments><xhtml:p>c</xhtml:p></Comments>
    <Reasons><Reason Type="Deprecated"/></Reasons>
  </Mapping_Notes>
</Weakness>
</Weaknesses>
"""


def _write_catalog(body: str, name: str) -> Path:
    path = Path("tests") / f"{name}-{uuid4().hex}.xml"
    path.write_text(_XML_HEADER + body + "</Weakness_Catalog>", encoding="utf-8")
    return path


def test_full_weakness_extracts_all_enrichment_properties():
    path = _write_catalog(_FULL_WEAKNESS, "sample_cwe_full")
    try:
        rows = list(_iter_weakness_nodes(path))
        assert len(rows) == 1
        row = rows[0]
        assert row["cweId"] == "CWE-79"
        p = row["props"]

        # identity
        assert p["name"].startswith("Improper Neutralization")
        assert p["abstraction"] == "Base"
        # required enrichment
        assert p["description"] == (
            "The product does not neutralize user-controllable input "
            "before it is placed in output."
        )
        assert p["structure"] == "Simple"
        assert p["status"] == "Stable"
        assert p["mappingUsage"] == "Allowed"
        # StructuredText flattening: XHTML markup gone, whitespace collapsed
        assert p["extendedDescription"] == (
            "Cross-site scripting (XSS) occurs when: "
            "Untrusted data enters. It is sent unescaped."
        )
        # arrays: dedup, document order, terms/enums only (notes dropped)
        assert p["mappingReasons"] == ["Frequent Misuse", "Abstraction"]
        assert p["alternateTerms"] == ["XSS", "CSS"]
        assert p["modesOfIntroduction"] == ["Implementation", "Architecture and Design"]
        assert p["ordinalities"] == ["Primary", "Resultant"]
        assert p["functionalAreas"] == ["Session Management"]
        assert p["affectedResources"] == ["Memory"]
        assert p["likelihoodOfExploit"] == "High"
    finally:
        path.unlink(missing_ok=True)


def test_minimal_weakness_uses_explicit_nulls_for_absent_optionals():
    path = _write_catalog(_MINIMAL_WEAKNESS, "sample_cwe_minimal")
    try:
        rows = list(_iter_weakness_nodes(path))
        assert len(rows) == 1
        p = rows[0]["props"]

        assert rows[0]["cweId"] == "CWE-1004"
        assert p["description"] == "Cookie lacks HttpOnly."
        assert p["mappingUsage"] == "Allowed"
        assert p["mappingReasons"] == ["Acceptable-Use"]

        # Absent optionals must be explicit None (never "" or []) so the
        # `SET w += row.props` refresh removes stale values (rule 7),
        # and empty arrays are never stored (rule 2).
        for key in ("extendedDescription", "likelihoodOfExploit",
                    "alternateTerms", "functionalAreas", "affectedResources",
                    "modesOfIntroduction", "ordinalities"):
            assert p[key] is None, key
    finally:
        path.unlink(missing_ok=True)


def test_deprecated_weakness_loads_with_status_and_prohibited_usage():
    path = _write_catalog(_DEPRECATED_WEAKNESS, "sample_cwe_deprecated")
    try:
        rows = list(_iter_weakness_nodes(path))
        # Rule 6: deprecated entries ARE loaded, flagged for the query layer.
        assert len(rows) == 1
        p = rows[0]["props"]
        assert p["status"] == "Deprecated"
        assert p["mappingUsage"] == "Prohibited"
        assert p["mappingReasons"] == ["Deprecated"]
    finally:
        path.unlink(missing_ok=True)


def test_weakness_without_id_is_skipped():
    body = """\
<Weaknesses>
<Weakness Name="No ID" Abstraction="Base" Structure="Simple" Status="Draft">
  <Description>d</Description>
</Weakness>
</Weaknesses>
"""
    path = _write_catalog(body, "sample_cwe_noid")
    try:
        assert list(_iter_weakness_nodes(path)) == []
    finally:
        path.unlink(missing_ok=True)


def test_extraction_is_deterministic_across_passes():
    """Two parses of the same catalog yield identical records (idempotent input)."""
    path = _write_catalog(_FULL_WEAKNESS, "sample_cwe_repeat")
    try:
        assert list(_iter_weakness_nodes(path)) == list(_iter_weakness_nodes(path))
    finally:
        path.unlink(missing_ok=True)


def test_weakness_cypher_refreshes_on_match():
    """Guard the idempotent-refresh contract: properties must be written
    with `SET w +=` (create AND refresh), not ON CREATE SET only."""
    assert "SET w += row.props" in _CYPHER_WEAKNESS
    assert "ON CREATE" not in _CYPHER_WEAKNESS


def test_caused_by_records_skip_nvd_placeholders():
    sample = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "weaknesses": [
                        {"description": [
                            {"value": "CWE-79"},
                            {"value": "NVD-CWE-noinfo"},
                        ]}
                    ],
                }
            }
        ]
    }
    path = Path("tests") / f"sample_cwe_cve-{uuid4().hex}.json"
    path.write_text(json.dumps(sample), encoding="utf-8")
    try:
        pairs = list(_iter_caused_by_records(path))
        assert ("CVE-2024-0001", "CWE-79") in pairs
        assert ("CVE-2024-0001", None) in pairs   # placeholder counted, not loaded
    finally:
        path.unlink(missing_ok=True)
