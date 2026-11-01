from pathlib import Path

import pytest

from validation.shacl_export_check import shapes_graph, to_rdf, validate

SHAPES = Path(__file__).resolve().parents[1] / "spec" / "shapes"

WEAKNESS = {
    "cweId": "CWE-79", "name": "XSS", "abstraction": "Base",
    "description": "The product does not neutralize user input.",
    "mappingUsage": "Allowed", "mappingReasons": ["Acceptable-Use"],
    "structure": "Simple", "status": "Stable",
    "modesOfIntroduction": ["Implementation", "Architecture and Design"],
}
ATTACK_PATTERN = {
    "capecId": "CAPEC-63", "name": "XSS", "status": "Draft", "abstraction": "Standard",
    "attackLikelihood": "High", "typicalSeverity": "Very High",
}
CWE_C1 = {"consequenceId": "CWE-79-C1", "scopes": ["Confidentiality", "Integrity"],
          "impacts": ["Read Application Data"], "likelihood": None, "note": "n"}
CAPEC_C1 = {"consequenceId": "CAPEC-63-C1", "scopes": ["Confidentiality"],
            "impacts": None, "likelihood": "High", "note": None}


@pytest.fixture(scope="module")
def shapes():
    if not SHAPES.exists():
        pytest.skip("spec/ not materialized (run python scripts/sync_spec.py)")
    return shapes_graph(SHAPES)


def _check(shapes, weakness=WEAKNESS, cwe_c=CWE_C1, capec_c=CAPEC_C1):
    data = to_rdf(
        [weakness], [ATTACK_PATTERN],
        [("Weakness", "CWE-79", cwe_c), ("AttackPattern", "CAPEC-63", capec_c)],
        [("CWE-79", "CAPEC-63")],
    )
    return validate(data, shapes)


def test_loader_rows_conform(shapes):
    conforms, messages = _check(shapes)
    assert conforms, messages


def test_weakness_without_description_fails(shapes):
    # spec negative case weakness-missing-description
    conforms, messages = _check(shapes, weakness={**WEAKNESS, "description": None})
    assert not conforms
    assert any("non-empty description" in m for m in messages)


def test_cwe_impact_on_capec_consequence_fails(shapes):
    # spec negative case consequence-foreign-vocab: vocabularies never merged
    conforms, messages = _check(shapes, capec_c={**CAPEC_C1, "impacts": ["Read Application Data"]})
    assert not conforms
    assert any("CAPEC TechnicalImpactEnumeration" in m for m in messages)


def test_cwe_consequence_needs_an_impact(shapes):
    conforms, _ = _check(shapes, cwe_c={**CWE_C1, "impacts": None})
    assert not conforms
