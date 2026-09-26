import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from etl import build_metadata as bm

SHAPES = Path(__file__).resolve().parents[1] / "spec" / "shapes"
SEP_6 = datetime(2026, 9, 6, 13, 40, tzinfo=timezone.utc).timestamp()


def _touch(path: Path, text: str, mtime: float = SEP_6) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    os.utime(path, (mtime, mtime))
    return path


def _nvd(ts: str, fmt: str = "NVD_CVE") -> str:
    return (
        '{\n  "resultsPerPage" : 1,\n  "format" : "%s",\n  "version" : "2.0",\n'
        '  "timestamp" : "%s",\n  "vulnerabilities" : [ ]\n}' % (fmt, ts)
    )


def _bundle(objects) -> str:
    return json.dumps({"type": "bundle", "id": "bundle--x", "objects": objects})


def _raw_tree(raw: Path, collections=(None, None, None)) -> Path:
    _touch(raw / "CWE" / "cwec_v4.19.1.xml", '<Weakness_Catalog Name="CWE" Version="4.19.1"/>')
    _touch(raw / "CWE" / "cwec_v4.20.xml",
           '<Weakness_Catalog Name="CWE" Version="4.20" Date="2026-04-30"><Weaknesses/></Weakness_Catalog>')
    _touch(raw / "CAPEC" / "capec_latest.xml",
           '<Attack_Pattern_Catalog Name="CAPEC" Version="3.9" Date="2023-01-24"/>')
    _touch(raw / "D3FEND" / "d3fend.json", json.dumps({"@graph": [
        {"@id": "d3f:Foo", "@type": "owl:Class"},
        {"@id": "http://d3fend.mitre.org/ontologies/d3fend.owl",
         "@type": "owl:Ontology", "owl:versionInfo": "1.3.0"},
    ]}))
    for name, coll, modified in zip(
        ("enterprise-attack.json", "mobile-attack.json", "ics-attack.json"),
        collections,
        ("2026-08-04T20:48:45.192Z", "2026-07-31T20:48:58.758Z", "2026-08-04T20:48:45.205Z"),
    ):
        objects = [
            {"type": "x-mitre-matrix", "x_mitre_version": "2.0", "modified": "2020-01-01T00:00:00.000Z"},
            {"type": "attack-pattern", "modified": modified},
        ]
        if coll:
            objects.append({"type": "x-mitre-collection", "x_mitre_version": coll,
                            "modified": "2019-01-01T00:00:00.000Z"})
        _touch(raw / "ATTCK-STIX" / name, _bundle(objects))
    _touch(raw / "CVE" / "nvdcve-2.0-2024.json", _nvd("2026-09-06T03:01:12.8807303"))
    _touch(raw / "CVE" / "nvdcve-2.0-modified.json", _nvd("2026-09-06T08:00:03.9682631"))
    _touch(raw / "CPE" / "nvdcpe-2.0-chunks" / "nvdcpe-2.0-chunk-00001.json",
           _nvd("2026-09-05T23:50:01.1480597", "NVD_CPE"))
    _touch(raw / "CPE-MATCH" / "nvdcpematch-2.0-chunks" / "nvdcpematch-2.0-chunk-00001.json",
           _nvd("2026-09-05T23:40:00.5922862", "NVD_CPEMatchString"))
    _touch(raw / "car" / "analytics" / "CAR-2013-01-002.yaml", "id: CAR-2013-01-002\n")
    _touch(raw / "SHIELD" / "techniques.json", "[]")
    _touch(raw / "ENGAGE" / "activities.json", "[]")
    return raw


def test_source_snapshots_read_the_exact_release_from_raw_files(tmp_path: Path):
    snapshots, missing = bm.source_snapshots(_raw_tree(tmp_path / "raw"))
    assert missing == []
    assert snapshots == [
        "CPE=2026-09-05T23:40:00Z..2026-09-05T23:50:01Z",   # range covers CPE-MATCH
        "CVE=2026-09-06T03:01:12Z..2026-09-06T08:00:03Z",   # files disagree: range
        "CVSS=2026-09-06T03:01:12Z..2026-09-06T08:00:03Z",
        "CWE=4.20",                                  # newest catalog, numeric order
        "CAPEC=3.9",
        "ATTCK=download:2026-09-06;modified-max:2026-08-04",
        "D3FEND=1.3.0",
        "CAR=download:2026-09-06",
        "SHIELD=download:2026-09-06",
        "ENGAGE=download:2026-09-06",
    ]


def test_nvd_timestamps_single_value_when_files_agree(tmp_path: Path):
    a = _touch(tmp_path / "a.json", _nvd("2026-09-06T03:00:41.4343668"))
    b = _touch(tmp_path / "b.json", _nvd("2026-09-06T03:00:41.9"))      # same second
    c = _touch(tmp_path / "c.json", _nvd("2026-08-28T03:04:40.2405914"))
    assert bm.nvd_feed_timestamp([a, b]) == "2026-09-06T03:00:41Z"
    assert bm.nvd_feed_timestamp([a, b, c]) == "2026-08-28T03:04:40Z..2026-09-06T03:00:41Z"
    assert bm.nvd_feed_timestamp([]) is None


def test_attck_uses_collection_release_only_when_all_three_agree(tmp_path: Path):
    raw = _raw_tree(tmp_path / "same", collections=("18.1", "18.1", "18.1"))
    assert "ATTCK=18.1" in bm.source_snapshots(raw)[0]

    raw = _raw_tree(tmp_path / "mixed", collections=("18.1", "18.0", "18.1"))
    assert "ATTCK=download:2026-09-06;modified-max:2026-08-04" in bm.source_snapshots(raw)[0]

    raw = _raw_tree(tmp_path / "partial", collections=("18.1", None, "18.1"))
    assert "ATTCK=download:2026-09-06;modified-max:2026-08-04" in bm.source_snapshots(raw)[0]


def test_missing_sources_are_reported_not_invented(tmp_path: Path):
    raw = tmp_path / "raw"
    _touch(raw / "CAPEC" / "capec_latest.xml", '<Attack_Pattern_Catalog Version="3.9"/>')
    snapshots, missing = bm.source_snapshots(raw)
    assert snapshots == ["CAPEC=3.9"]
    assert "CWE" in missing and "ATTCK" in missing and len(missing) == 9


class _OneWriter:
    def __init__(self):
        self.calls = []

    def execute_one(self, cypher, params=None):
        self.calls.append((cypher, params))
        return {"success": True, "counters": {}, "errors": []}


def test_run_build_metadata_merges_a_single_node(tmp_path: Path):
    writer = _OneWriter()
    result = bm.run_build_metadata(writer, _raw_tree(tmp_path / "raw"))
    assert result["success"]
    (cypher, params), = writer.calls
    assert cypher.startswith("MERGE (b:BuildMetadata)\nSET")      # label-only MERGE: singleton
    assert "datetime($buildTimestamp)" in cypher
    assert params["specVersion"] == bm.spec_version()
    assert len(params["pipelineCommit"]) == 40
    assert params["buildTimestamp"].endswith("Z")
    assert len(params["sourceSnapshots"]) == 10


def test_build_record_conforms_to_pinned_build_shape(tmp_path: Path):
    if not (SHAPES / "build.shacl.ttl").exists():
        pytest.skip("spec/ not materialized (run python sync_spec.py)")
    from validation.shacl_export_check import shapes_graph, to_rdf, validate

    record, _, _ = bm.build_record(_raw_tree(tmp_path / "raw"))
    conforms, messages = validate(to_rdf([], [], [], build=record), shapes_graph(SHAPES))
    assert conforms, messages

    record["sourceSnapshots"].append("CWE=4.19.1")            # two values for one SOURCE
    conforms, messages = validate(to_rdf([], [], [], build=record), shapes_graph(SHAPES))
    assert not conforms
    assert any("at most one value per SOURCE" in m for m in messages)
