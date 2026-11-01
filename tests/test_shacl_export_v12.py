"""SHACL export of the spec 1.2 rows against the pinned decision / ATLAS shapes."""

import copy
from pathlib import Path

import pytest

from validation.shacl_export_v12 import shapes_graph, to_rdf, validate

SHAPES = Path(__file__).resolve().parents[1] / "spec" / "shapes"

KEV = {"cveId": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
       "vulnerabilityName": "Log4Shell", "dateAdded": "2021-12-10", "shortDescription": "s",
       "requiredAction": "a", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known",
       "forensicTriage": "No", "notes": "n", "cwes": ["CWE-20", "CWE-917"],
       "catalogVersion": "2026.09.25", "dateReleased": "2026-09-25T18:58:16.5029Z"}
EPSS = {"epssId": "CVE-2021-44228::EPSS::2026-09-27", "cveId": "CVE-2021-44228",
        "score": 0.94358, "percentile": 0.1, "scoreDate": "2026-09-27",
        "scoreTimestamp": "2026-09-27T12:00:21Z", "modelVersion": "v2026.06.15"}
SSVC = {"ssvcId": "CVE-2021-44228::SSVC::2024-09-12T17:22:46+00:00", "cveId": "CVE-2021-44228",
        "version": "2.0.3", "timestamp": "2024-09-12T17:22:46+00:00", "exploitation": "active",
        "automatable": "yes", "technicalImpact": "total", "role": "CISA Coordinator",
        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0", "sourceRole": "adp"}


def _atlas(aid, **extra):
    return {"atlasId": aid, "name": "n", "description": "d", "createdDate": "2021-05-13",
            "modifiedDate": "2026-09-15", **extra}


TECH = {"maturity": "Realized", "platforms": ["Generative AI"]}
NODES = {
    "AtlasTactic": [_atlas("AML.TA0002", matrixPosition=1)],
    "AtlasTechnique": [_atlas("AML.T0073", **TECH)],
    "AtlasSubTechnique": [_atlas("AML.T0073.000", **TECH)],
    "AtlasMitigation": [_atlas("AML.M0000", categories=["Policy"], lifecyclePhases=["Deployment"])],
}
EDGES = [("ACHIEVES", "AML.T0073", "AML.TA0002"), ("ACHIEVES", "AML.T0073.000", "AML.TA0002"),
         ("SPECIALIZES", "AML.T0073.000", "AML.T0073"), ("MITIGATES", "AML.M0000", "AML.T0073")]
ADAPTED = [{"src": "AML.T0073", "tgt": "T1684.001", "tgtLabel": "SubTechnique",
            "attackReferenceId": "T1656",
            "attackReferenceUrl": "https://attack.mitre.org/techniques/T1656/"}]


@pytest.fixture(scope="module")
def shapes():
    if not SHAPES.exists():
        pytest.skip("spec/ not materialized (run python scripts/sync_spec.py)")
    return shapes_graph(SHAPES)


def _check(shapes, kev=KEV, epss=EPSS, ssvc=SSVC, nodes=NODES, edges=EDGES, adapted=ADAPTED):
    data = to_rdf({"KevEntry": [kev], "EpssScore": [epss], "SsvcDecision": [ssvc]},
                  nodes, edges, adapted)
    return validate(data, shapes)


def test_loader_rows_conform(shapes):
    conforms, messages = _check(shapes)
    assert conforms, messages
    # the remapped T1656 -> T1684.001 bridge is legitimate and only a Warning
    assert [m for m in messages if m.startswith("Warning")]


@pytest.mark.parametrize("field, value", [
    ("exploitation", "high"), ("sourceRole", "cna"), ("version", "2.0.2")])
def test_ssvc_vocabulary_violations(shapes, field, value):
    conforms, _ = _check(shapes, ssvc={**SSVC, field: value})
    assert not conforms


def test_epss_out_of_range_and_kev_bad_cwe_fail(shapes):
    assert not _check(shapes, epss={**EPSS, "score": 1.5})[0]
    assert not _check(shapes, kev={**KEV, "cwes": ["CWE-X"]})[0]


def test_adapted_from_without_provenance_url_fails(shapes):
    assert not _check(shapes, adapted=[{**ADAPTED[0], "attackReferenceUrl": "https://x/"}])[0]


def test_subtechnique_without_specializes_fails(shapes):
    edges = [e for e in EDGES if e[0] != "SPECIALIZES"]
    assert not _check(shapes, edges=edges)[0]


def test_mitigation_vocabulary(shapes):
    nodes = copy.deepcopy(NODES)
    nodes["AtlasMitigation"][0]["categories"] = ["Organisational"]
    assert not _check(shapes, nodes=nodes)[0]
