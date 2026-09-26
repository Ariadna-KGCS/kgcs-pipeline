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
        pytest.skip("spec/ not materialized (run python sync_spec.py)")
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
