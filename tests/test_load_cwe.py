import json
import re
from pathlib import Path

import pytest

from etl.load_cwe import (
    _DECLARED_ADP_SOURCES,
    CWELoader,
    _aggregate_caused_by,
    _source_role,
    _weakness_entries,
)

NVD = "nvd@nist.gov"
CNA = "secalert@redhat.com"
ADP = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
LOADED = {"CWE-20", "CWE-79", "CWE-89", "CWE-787"}


def _weakness(source: str, wtype: str, *cwes: str) -> dict:
    return {
        "source": source,
        "type": wtype,
        "description": [{"lang": "en", "value": c} for c in cwes],
    }


def _cve(cve_id: str, *weaknesses: dict, last_modified: str = "2025-01-01T00:00:00.000") -> dict:
    return {"cve": {"id": cve_id, "lastModified": last_modified, "weaknesses": list(weaknesses)}}


def _aggregate(cve_id: str, *weaknesses: dict):
    return _aggregate_caused_by(
        cve_id, _weakness_entries(_cve(cve_id, *weaknesses)["cve"]), LOADED
    )


def test_source_role_vocabulary():
    assert _source_role(NVD) == "nvd"
    assert _source_role(ADP) == "adp"
    assert _source_role(CNA) == "cna"
    assert _source_role("2b2c1f5e-0000-4000-8000-000000000000") == "cna"


def test_nvd_and_cna_disagree_gives_two_edges_one_source_each():
    records, placeholders, unmapped = _aggregate(
        "CVE-2024-0001",
        _weakness(NVD, "Primary", "CWE-89"),
        _weakness(CNA, "Secondary", "CWE-20"),
    )
    assert records == [
        {"cveId": "CVE-2024-0001", "cweId": "CWE-89",
         "sources": [NVD], "sourceRoles": ["nvd"], "types": ["Primary"]},
        {"cveId": "CVE-2024-0001", "cweId": "CWE-20",
         "sources": [CNA], "sourceRoles": ["cna"], "types": ["Secondary"]},
    ]
    assert (placeholders, unmapped) == (0, [])


def test_nvd_and_cna_agree_gives_one_edge_two_sources():
    records, _, _ = _aggregate(
        "CVE-2024-0002",
        _weakness(NVD, "Primary", "CWE-79"),
        _weakness(CNA, "Secondary", "CWE-79"),
    )
    assert records == [
        {"cveId": "CVE-2024-0002", "cweId": "CWE-79",
         "sources": [NVD, CNA], "sourceRoles": ["nvd", "cna"],
         "types": ["Primary", "Secondary"]},
    ]


def test_nvd_placeholders_and_unmapped_ids_are_skipped_and_counted():
    records, placeholders, unmapped = _aggregate(
        "CVE-2024-0003",
        _weakness(NVD, "Primary", "NVD-CWE-noinfo", "NVD-CWE-Other"),
        _weakness(CNA, "Primary", "CWE-16", "CWE-787"),
    )
    assert [r["cweId"] for r in records] == ["CWE-787"]
    assert records[0]["sources"] == [CNA]
    assert placeholders == 2
    assert unmapped == ["CWE-16"]


def test_placeholder_only_cve_yields_no_edge():
    records, placeholders, _ = _aggregate(
        "CVE-2024-0004", _weakness(NVD, "Primary", "NVD-CWE-Other")
    )
    assert records == []
    assert placeholders == 1


def test_adp_role_duplicates_and_mixed_types():
    records, _, _ = _aggregate(
        "CVE-2024-0005",
        _weakness(CNA, "Primary", "CWE-787"),
        _weakness(CNA, "Primary", "CWE-787"),     # exact duplicate: collapses
        _weakness(CNA, "Secondary", "CWE-787"),   # same source, other type: kept
        _weakness(ADP, "Secondary", "CWE-787"),
    )
    assert len(records) == 1
    rec = records[0]
    assert rec["sources"] == [CNA, CNA, ADP]
    assert rec["sourceRoles"] == ["cna", "cna", "adp"]
    assert rec["types"] == ["Primary", "Secondary", "Secondary"]
    assert len(rec["sources"]) == len(rec["sourceRoles"]) == len(rec["types"])


def test_declared_adp_list_matches_pinned_spec():
    mapping = Path(__file__).resolve().parents[1] / "spec" / "mappings" / "cve-to-owl-v1.0.md"
    if not mapping.exists():
        pytest.skip("spec/ not materialized (run python scripts/sync_spec.py)")
    text = mapping.read_text(encoding="utf-8")
    declared = set(re.findall(r"^\| `([^`]+)` \| [^|]+\| `adp` \|", text, flags=re.M))
    assert declared, "ADP table not found in the pinned cve-to-owl mapping"
    assert set(_DECLARED_ADP_SOURCES) == declared


# ---------------------------------------------------------------------------
# run(): Cypher shape and the newest-record rule
# ---------------------------------------------------------------------------

OLD = "2025-06-01T10:00:00.000"
NEW = "2026-09-05T08:30:00.000"


def _write_raw(raw: Path, yearly: list, modified: list) -> None:
    cwe = raw / "CWE"
    cwe.mkdir(parents=True)
    weaknesses = "".join(
        f'<Weakness ID="{c.split("-")[1]}" Name="{c}" Abstraction="Base"/>' for c in sorted(LOADED)
    )
    (cwe / "cwec_v4.20.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7"><Weaknesses>{weaknesses}'
        "</Weaknesses></Weakness_Catalog>",
        encoding="utf-8",
    )
    cve = raw / "CVE"
    cve.mkdir()
    (cve / "nvdcve-2.0-2025.json").write_text(
        json.dumps({"vulnerabilities": yearly}), encoding="utf-8")
    (cve / "nvdcve-2.0-modified.json").write_text(
        json.dumps({"vulnerabilities": modified}), encoding="utf-8")


def _run(tmp_path: Path, fake_writer, yearly: list, modified: list):
    raw = tmp_path / "raw"
    _write_raw(raw, yearly, modified)
    result = CWELoader(str(raw), fake_writer, batch_size=100).run()
    assert result["success"], result["errors"]
    # the last SET per edge wins, as in Neo4j
    edges = {}
    for row in fake_writer.rows("[r:CAUSED_BY]"):
        edges[(row["cveId"], row["cweId"])] = row
    return result, edges


def test_cwe_loader_cypher_merges_edge_then_replaces_lists(tmp_path: Path, fake_writer):
    _run(tmp_path, fake_writer, [_cve("CVE-2025-0009", _weakness(NVD, "Primary", "CWE-79"))], [])
    cypher = next(c for c, _ in fake_writer.calls if "[r:CAUSED_BY]" in c)
    assert "MERGE (v)-[r:CAUSED_BY]->(w)" in cypher
    assert "SET r.sources     = row.sources" in cypher      # replaced, never appended
    assert "+" not in cypher


def test_newer_modified_record_adding_a_cwe_supplies_the_lists(tmp_path: Path, fake_writer):
    # The 34 CVEs of 2026-09-06: the modified record is newer and adds one CWE.
    result, edges = _run(
        tmp_path, fake_writer,
        yearly=[
            _cve("CVE-2025-0001", _weakness(CNA, "Primary", "CWE-79"), last_modified=OLD),
            _cve("CVE-2025-0002",
                 _weakness(NVD, "Primary", "CWE-89"),
                 _weakness(CNA, "Secondary", "CWE-89"), last_modified=OLD),
        ],
        modified=[
            _cve("CVE-2025-0001",
                 _weakness(CNA, "Primary", "CWE-79"),
                 _weakness(ADP, "Secondary", "CWE-79", "CWE-20"), last_modified=NEW),
        ],
    )
    assert set(edges) == {
        ("CVE-2025-0001", "CWE-79"),
        ("CVE-2025-0001", "CWE-20"),      # added by the newer record
        ("CVE-2025-0002", "CWE-89"),
    }
    assert len(fake_writer.rows("[r:CAUSED_BY]")) == 3   # the older CWE-79 record is not written
    assert edges[("CVE-2025-0001", "CWE-79")]["sources"] == [CNA, ADP]
    assert edges[("CVE-2025-0001", "CWE-79")]["sourceRoles"] == ["cna", "adp"]
    assert edges[("CVE-2025-0001", "CWE-20")]["sourceRoles"] == ["adp"]
    assert edges[("CVE-2025-0002", "CWE-89")]["sourceRoles"] == ["nvd", "cna"]
    assert result["stats"]["superseded_by_newer"] == 1
    assert result["stats"]["pairs_only_in_older"] == 0
    assert result["stats"]["caused_by_records"] == 3


def test_newer_yearly_record_supplies_the_lists_and_union_is_kept(tmp_path: Path, fake_writer):
    # General rule: lastModified decides, not the file. Here the yearly record
    # is newer, and the older modified record names a CWE the newer one dropped.
    result, edges = _run(
        tmp_path, fake_writer,
        yearly=[
            _cve("CVE-2025-0003", _weakness(NVD, "Primary", "CWE-787"), last_modified=NEW),
        ],
        modified=[
            _cve("CVE-2025-0003",
                 _weakness(CNA, "Secondary", "CWE-787", "CWE-20"), last_modified=OLD),
        ],
    )
    assert set(edges) == {("CVE-2025-0003", "CWE-787"), ("CVE-2025-0003", "CWE-20")}
    assert edges[("CVE-2025-0003", "CWE-787")]["sources"] == [NVD]     # newest wins
    assert edges[("CVE-2025-0003", "CWE-20")]["sources"] == [CNA]      # only in older: kept
    assert result["stats"]["superseded_by_newer"] == 1
    assert result["stats"]["pairs_only_in_older"] == 1


def test_equally_new_records_keep_the_modified_lists(tmp_path: Path, fake_writer):
    result, edges = _run(
        tmp_path, fake_writer,
        yearly=[_cve("CVE-2025-0004", _weakness(NVD, "Primary", "CWE-79"), last_modified=NEW)],
        modified=[_cve("CVE-2025-0004", _weakness(NVD, "Primary", "CWE-79"), last_modified=NEW)],
    )
    assert len(fake_writer.rows("[r:CAUSED_BY]")) == 1
    assert result["stats"]["pairs_only_in_older"] == 0


# ---------------------------------------------------------------------------
# spec 1.1.0: Weakness enrichment + Consequence sub-nodes
# ---------------------------------------------------------------------------

from etl.load_cwe import _CYPHER_WEAKNESS, _iter_weakness_records, detect_cwe_namespace  # noqa: E402

_CWE79 = """
<Weakness ID="79" Name="XSS" Abstraction="Base" Structure="Simple" Status="Stable">
  <Description>The product does not neutralize
\t\t\t\t\tuser input.</Description>
  <Extended_Description>
    <xhtml:p>Cross-site scripting.</xhtml:p>
    <xhtml:ul><xhtml:li>Type 1</xhtml:li><xhtml:li>Type 2</xhtml:li></xhtml:ul>
  </Extended_Description>
  <Modes_Of_Introduction>
    <Introduction><Phase>Implementation</Phase><Note>n1</Note></Introduction>
    <Introduction><Phase>Architecture and Design</Phase></Introduction>
    <Introduction><Phase>Implementation</Phase><Note>n2</Note></Introduction>
  </Modes_Of_Introduction>
  <Weakness_Ordinalities>
    <Weakness_Ordinality><Ordinality>Resultant</Ordinality><Description>d</Description></Weakness_Ordinality>
  </Weakness_Ordinalities>
  <Alternate_Terms>
    <Alternate_Term><Term>XSS</Term><Description>d</Description></Alternate_Term>
    <Alternate_Term><Term>CSS</Term></Alternate_Term>
  </Alternate_Terms>
  <Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
  <Functional_Areas><Functional_Area>Networking</Functional_Area></Functional_Areas>
  <Affected_Resources><Affected_Resource>Memory</Affected_Resource></Affected_Resources>
  <Common_Consequences>
    <Consequence>
      <Scope>Confidentiality</Scope><Scope>Integrity</Scope>
      <Impact>Read Application Data</Impact><Impact>Execute Unauthorized Code or Commands</Impact>
      <Note><xhtml:p>Cookie   theft.</xhtml:p></Note>
    </Consequence>
    <Consequence>
      <Scope>Availability</Scope><Impact>DoS: Crash, Exit, or Restart</Impact>
      <Likelihood>Low</Likelihood>
    </Consequence>
  </Common_Consequences>
  <Mapping_Notes>
    <Usage>Allowed</Usage>
    <Reasons><Reason Type="Acceptable-Use"/><Reason Type="Abstraction"/><Reason Type="Acceptable-Use"/></Reasons>
  </Mapping_Notes>
</Weakness>"""

_CWE79_SECOND_RECORD = """
    <Consequence>
      <Scope>Availability</Scope><Impact>DoS: Crash, Exit, or Restart</Impact>
      <Likelihood>Low</Likelihood>
    </Consequence>"""

_CWE20 = """
<Weakness ID="20" Name="Input Validation" Abstraction="Class" Structure="Simple" Status="Deprecated">
  <Description>Deprecated entry.</Description>
  <Mapping_Notes><Usage>Prohibited</Usage><Reasons><Reason Type="Deprecated"/></Reasons></Mapping_Notes>
</Weakness>"""


def _cwe_catalog(raw: Path, *weaknesses: str, schema: int = 7, version: str = "4.20") -> Path:
    cwe = raw / "CWE"
    cwe.mkdir(parents=True, exist_ok=True)
    path = cwe / f"cwec_v{version}.xml"
    path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<Weakness_Catalog Name="CWE" Version="{version}" Date="2026-04-30" '
        f'xmlns="http://cwe.mitre.org/cwe-{schema}" xmlns:xhtml="http://www.w3.org/1999/xhtml">'
        f'<Weaknesses>{"".join(weaknesses)}</Weaknesses>'
        '<Categories><Category ID="16" Name="Configuration" Status="Obsolete"/></Categories>'
        "</Weakness_Catalog>",
        encoding="utf-8",
    )
    return path


def test_weakness_enrichment_properties(tmp_path: Path):
    records = list(_iter_weakness_records(_cwe_catalog(tmp_path, _CWE79, _CWE20)))
    assert [n["cweId"] for n, _ in records] == ["CWE-79", "CWE-20"]   # Category not loaded
    node, _ = records[0]
    assert node == {
        "cweId": "CWE-79",
        "name": "XSS",
        "abstraction": "Base",
        "description": "The product does not neutralize user input.",
        "extendedDescription": "Cross-site scripting. Type 1 Type 2",
        "mappingUsage": "Allowed",
        "mappingReasons": ["Acceptable-Use", "Abstraction"],
        "structure": "Simple",
        "status": "Stable",
        "alternateTerms": ["XSS", "CSS"],
        "likelihoodOfExploit": "High",
        "functionalAreas": ["Networking"],
        "affectedResources": ["Memory"],
        "modesOfIntroduction": ["Implementation", "Architecture and Design"],
        "ordinalities": ["Resultant"],
    }


def test_absent_optional_fields_are_null_never_empty_lists(tmp_path: Path):
    node, consequences = list(_iter_weakness_records(_cwe_catalog(tmp_path, _CWE20)))[0]
    assert node["status"] == "Deprecated"          # deprecated entries are loaded
    assert node["mappingUsage"] == "Prohibited"
    for field in ("extendedDescription", "alternateTerms", "likelihoodOfExploit",
                  "functionalAreas", "affectedResources", "modesOfIntroduction",
                  "ordinalities"):
        assert node[field] is None, field
    assert consequences == []


def test_weakness_consequences_keep_record_grouping(tmp_path: Path):
    _, consequences = list(_iter_weakness_records(_cwe_catalog(tmp_path, _CWE79)))[0]
    assert consequences == [
        {"parentId": "CWE-79", "consequenceId": "CWE-79-C1",
         "scopes": ["Confidentiality", "Integrity"],
         "impacts": ["Read Application Data", "Execute Unauthorized Code or Commands"],
         "likelihood": None, "note": "Cookie theft."},
        {"parentId": "CWE-79", "consequenceId": "CWE-79-C2",
         "scopes": ["Availability"], "impacts": ["DoS: Crash, Exit, or Restart"],
         "likelihood": "Low", "note": None},
    ]


def test_weakness_cypher_sets_on_create_and_on_match():
    assert "ON CREATE SET" not in _CYPHER_WEAKNESS
    assert "SET w.name" in _CYPHER_WEAKNESS
    for prop in ("description", "extendedDescription", "mappingUsage", "mappingReasons",
                 "structure", "status", "alternateTerms", "likelihoodOfExploit",
                 "functionalAreas", "affectedResources", "modesOfIntroduction",
                 "ordinalities"):
        assert f"w.{prop}" in _CYPHER_WEAKNESS and f"row.{prop}" in _CYPHER_WEAKNESS


def test_cwe_consequences_written_after_all_weaknesses(tmp_path: Path, fake_writer):
    raw = tmp_path / "raw"
    _cwe_catalog(raw, _CWE79, _CWE20)
    result = CWELoader(str(raw), fake_writer, batch_size=1).run()
    assert result["success"], result["errors"]
    order = [c for c, _ in fake_writer.calls]
    last_weakness = max(i for i, c in enumerate(order) if "MERGE (w:Weakness" in c)
    first_consequence = min(i for i, c in enumerate(order) if "MERGE (c:Consequence" in c)
    assert last_weakness < first_consequence
    assert fake_writer.rows("DETACH DELETE c") == [
        {"parentId": "CWE-79", "count": 2}, {"parentId": "CWE-20", "count": 0},
    ]
    assert result["stats"]["consequence_records"] == 2
    assert result["stats"]["consequence_out_of_vocabulary"] == 0


def test_cwe_load_is_idempotent_and_prunes_removed_records(tmp_path: Path, graph_sim):
    raw = tmp_path / "raw"
    _cwe_catalog(raw, _CWE79, _CWE20)
    first = CWELoader(str(raw), graph_sim, batch_size=100).run()
    snapshot = ({k: dict(v) for k, v in graph_sim.nodes.items()}, set(graph_sim.edges))
    second = CWELoader(str(raw), graph_sim, batch_size=100).run()

    assert first["stats"]["nodes_created"] == 2
    assert first["stats"]["consequence_nodes_created"] == 2
    assert first["stats"]["has_consequence_created"] == 2
    assert second["stats"]["nodes_created"] == 0
    assert second["stats"]["consequence_nodes_created"] == 0
    assert second["stats"]["has_consequence_created"] == 0
    assert (graph_sim.nodes, graph_sim.edges) == snapshot

    # Newer catalog: MITRE dropped the second record and the exploit likelihood.
    assert _CWE79_SECOND_RECORD in _CWE79
    newer = _CWE79.replace(_CWE79_SECOND_RECORD, "").replace(
        "<Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>", ""
    )
    _cwe_catalog(raw, newer, _CWE20)
    third = CWELoader(str(raw), graph_sim, batch_size=100).run()
    assert third["stats"]["consequence_nodes_pruned"] == 1
    assert set(graph_sim.consequences()) == {"CWE-79-C1"}
    assert graph_sim.edges == {("CWE-79", "CWE-79-C1")}
    assert "likelihoodOfExploit" not in graph_sim.nodes[("Weakness", "CWE-79")]


# --- CWE 5.0 moved the catalog to the cwe-8 namespace (2026-10) ----------------

def test_namespace_is_read_from_the_catalog_root(tmp_path: Path):
    v7 = _cwe_catalog(tmp_path / "a", _CWE79)
    v8 = _cwe_catalog(tmp_path / "b", _CWE79, schema=8, version="5.0")
    assert detect_cwe_namespace(v7) == "http://cwe.mitre.org/cwe-7"
    assert detect_cwe_namespace(v8) == "http://cwe.mitre.org/cwe-8"
    # Same catalog content, either schema: identical node rows.
    assert [n for n, _ in _iter_weakness_records(v7)] == [n for n, _ in _iter_weakness_records(v8)]


def test_unknown_catalog_root_fails_hard(tmp_path: Path):
    path = tmp_path / "cwec_v9.9.xml"
    path.write_text('<Catalog xmlns="http://example.org/not-cwe"><Weakness ID="1"/></Catalog>', encoding="utf-8")
    with pytest.raises(ValueError, match="Weakness_Catalog"):
        detect_cwe_namespace(path)


def test_zero_weaknesses_is_a_failed_load(tmp_path: Path, graph_sim):
    raw = tmp_path / "raw"
    _cwe_catalog(raw)                      # valid catalog, no Weakness elements
    (raw / "CVE").mkdir()
    result = CWELoader(str(raw), graph_sim, batch_size=100).run()
    assert result["success"] is False
    assert any("No Weakness elements" in e for e in result["errors"])
    assert graph_sim.nodes == {}
