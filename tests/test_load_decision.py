"""Decision extension loaders (spec 1.2.0, ADR-0003): KEV, EPSS, SSVC."""

import gzip
import json
from pathlib import Path
from typing import Dict, List

import pytest

from etl.load_epss import EPSSLoader, epss_files, epss_snapshot, iter_epss_rows, parse_comment
from etl.load_kev import KEVLoader, kev_records
from etl.load_ssvc import SSVCLoader, ssvc_records

ADP = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
CISA_CNA = "9119a7d8-5eab-497f-8521-727c672e3725"


class DecisionWriter:
    """Fake writer: a fixed Vulnerability set, MERGE-by-key node store."""

    def __init__(self, vulns) -> None:
        self.vulns = set(vulns)
        self.calls: List[tuple] = []
        self.nodes: Dict[str, Dict] = {}

    def read_rows(self, cypher: str, params=None):
        assert "MATCH (v:Vulnerability {cveId: id})" in cypher
        return [{"id": i} for i in params["ids"] if i in self.vulns]

    def read_one(self, cypher: str, params=None):
        return sum(1 for k in self.nodes if "::EPSS::" in k)

    def execute_batch(self, cypher: str, rows: List[Dict], batch_size: int = 1000):
        self.calls.append((cypher, list(rows)))
        created = 0
        for row in rows:
            key = row.get("epssId") or row.get("ssvcId") or row["cveId"]
            if key not in self.nodes:
                created += 1
                self.nodes[key] = dict(row)
            elif "ON CREATE SET" not in cypher:        # KEV refresh: SET k = row.props
                self.nodes[key] = dict(row)
        return {"success": True, "nodes_created": created, "rels_created": created, "errors": []}

    def cyphers(self) -> List[str]:
        return [c for c, _ in self.calls]


def _entry(cve: str, **extra) -> Dict:
    base = {"cveID": cve, "vendorProject": "V", "product": "P", "vulnerabilityName": "N",
            "dateAdded": "2026-09-25", "shortDescription": "S", "requiredAction": "A",
            "dueDate": "2026-10-16", "knownRansomwareCampaignUse": "Unknown",
            "forensicTriage": "No", "notes": "https://x ; https://y", "cwes": ["CWE-841"]}
    base.update(extra)
    return base


def _catalog(entries, count=None) -> Dict:
    return {"title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": "2026.09.25", "dateReleased": "2026-09-25T18:58:16.5029Z",
            "count": len(entries) if count is None else count, "vulnerabilities": entries}


# ---------------------------------------------------------------- KEV

def test_kev_records_verbatim_with_file_provenance():
    records, counts = kev_records(_catalog([_entry("CVE-2021-44228"), _entry("CVE-2021-44228")],
                                           count=2))
    assert counts == {"entries": 2, "duplicates": 1}
    (r,) = records
    assert r["cveId"] == "CVE-2021-44228" and r["dateAdded"] == "2026-09-25"
    assert r["cwes"] == ["CWE-841"]                 # string list, never an edge
    assert r["catalogVersion"] == "2026.09.25"
    assert r["dateReleased"] == "2026-09-25T18:58:16.5029Z"


def test_kev_optional_fields_absent_are_not_invented():
    raw = _entry("CVE-2020-0001", cwes=[])
    for f in ("knownRansomwareCampaignUse", "forensicTriage", "notes"):
        raw.pop(f)
    (r,), _ = kev_records(_catalog([raw]))
    assert not {"knownRansomwareCampaignUse", "forensicTriage", "notes", "cwes"} & set(r)


def test_kev_count_mismatch_and_missing_required_fail():
    with pytest.raises(ValueError, match="count"):
        kev_records(_catalog([_entry("CVE-2020-0001")], count=5))
    bad = _entry("CVE-2020-0001")
    del bad["dueDate"]
    with pytest.raises(ValueError, match="dueDate"):
        kev_records(_catalog([bad]))


def test_kev_loader_drops_unknown_cves_and_refreshes(tmp_path: Path):
    kev_dir = tmp_path / "KEV"
    kev_dir.mkdir()
    path = kev_dir / "known_exploited_vulnerabilities.json"
    path.write_text(json.dumps(_catalog([_entry("CVE-2021-44228"), _entry("CVE-2026-99999")])))
    writer = DecisionWriter({"CVE-2021-44228"})
    result = KEVLoader(str(tmp_path), writer).run()
    assert result["success"]
    assert result["stats"]["loaded"] == 1 and result["stats"]["dropped_no_vulnerability"] == 1
    (cypher,) = writer.cyphers()
    assert cypher.index("MATCH (v:Vulnerability") < cypher.index("MERGE (k:KevEntry")
    assert "SET k = row.props" in cypher and "HAS_KEV_ENTRY" in cypher
    assert "CAUSED_BY" not in cypher and "Weakness" not in cypher

    # CISA edits in place: the refresh overwrites and a dropped field disappears
    path.write_text(json.dumps(_catalog([_entry("CVE-2021-44228", dueDate="2026-12-01",
                                                knownRansomwareCampaignUse="Known")])))
    KEVLoader(str(tmp_path), writer).run()
    node = writer.nodes["CVE-2021-44228"]["props"]
    assert node["dueDate"] == "2026-12-01" and node["knownRansomwareCampaignUse"] == "Known"


# ---------------------------------------------------------------- EPSS

def _epss(path: Path, day="2026-09-27", model="v2026.06.15", rows=None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = rows if rows is not None else [("CVE-1999-0001", "0.03351", "0.88245"),
                                         ("CVE-1999-0002", "0.1", "0.98035"),
                                         ("CVE-2099-0001", "0.00001", "0.0")]
    with gzip.open(path, "wt", encoding="utf-8", newline="") as fh:
        fh.write(f"#model_version:{model},score_date:{day}T12:00:21Z\n")
        fh.write("cve,epss,percentile\n")
        for r in rows:
            fh.write(",".join(r) + "\n")
    return path


def test_epss_comment_line_parsed_and_required():
    assert parse_comment("#model_version:v2026.06.15,score_date:2026-09-27T12:00:21Z\n") == {
        "model_version": "v2026.06.15", "score_date": "2026-09-27T12:00:21Z"}
    with pytest.raises(ValueError):
        parse_comment("cve,epss,percentile")        # EPSS v1 files: no header line
    with pytest.raises(ValueError):
        parse_comment("#model_version:v2022.01.01")


def test_epss_rows_key_and_verbatim_values(tmp_path: Path):
    path = _epss(tmp_path / "EPSS" / "epss_scores-2026-09-27.csv.gz")
    rows = [rec for _, rec in iter_epss_rows(path)]
    assert rows[0] == {
        "epssId": "CVE-1999-0001::EPSS::2026-09-27", "cveId": "CVE-1999-0001",
        "score": 0.03351, "percentile": 0.88245, "scoreDate": "2026-09-27",
        "scoreTimestamp": "2026-09-27T12:00:21Z", "modelVersion": "v2026.06.15"}
    assert rows[1]["score"] == 0.1                  # no rounding, no rescaling


def test_epss_out_of_range_fails(tmp_path: Path):
    path = _epss(tmp_path / "e.csv.gz", rows=[("CVE-1999-0001", "1.2", "0.5")])
    with pytest.raises(ValueError, match="out of"):
        list(iter_epss_rows(path))


def test_epss_files_prefer_dated_and_snapshot(tmp_path: Path):
    d = tmp_path / "EPSS"
    _epss(d / "epss_scores-current.csv.gz")
    assert [p.name for p in epss_files(d)] == ["epss_scores-current.csv.gz"]
    _epss(d / "epss_scores-2026-09-27.csv.gz")
    assert [p.name for p in epss_files(d)] == ["epss_scores-2026-09-27.csv.gz"]
    assert epss_snapshot(tmp_path) == "2026-09-27;model:v2026.06.15"


def test_epss_loader_append_only_and_drops(tmp_path: Path):
    _epss(tmp_path / "EPSS" / "epss_scores-2026-09-27.csv.gz")
    writer = DecisionWriter({"CVE-1999-0001", "CVE-1999-0002"})
    result = EPSSLoader(str(tmp_path), writer, batch_size=2).run()
    assert result["success"], result["errors"]
    s = result["stats"]
    assert (s["rows"], s["loaded"], s["dropped_no_vulnerability"]) == (3, 2, 1)
    assert all("ON CREATE SET" in c and " SET e" not in c.replace("ON CREATE SET", "")
               for c in writer.cyphers())
    first = dict(writer.nodes)
    # same file again: a no-op, and the node count never decreases
    again = EPSSLoader(str(tmp_path), writer, batch_size=2).run()
    assert again["stats"]["nodes_created"] == 0 and writer.nodes == first
    assert again["stats"]["epss_nodes_after"] >= again["stats"]["epss_nodes_before"]
    # a new score date adds nodes next to the old ones
    _epss(tmp_path / "EPSS" / "epss_scores-2026-09-28.csv.gz", day="2026-09-28")
    EPSSLoader(str(tmp_path), writer).run()
    assert "CVE-1999-0001::EPSS::2026-09-27" in writer.nodes
    assert "CVE-1999-0001::EPSS::2026-09-28" in writer.nodes


# ---------------------------------------------------------------- SSVC

def _ssvc(source, cve="CVE-2022-34821", ts="2025-04-18T15:23:16.425380Z", role="CISA Coordinator",
          options=({"exploitation": "none"}, {"automatable": "no"}, {"technicalImpact": "total"})):
    data = {"options": list(options), "role": role, "version": "2.0.3"}
    if ts is not None:
        data.update({"timestamp": ts, "id": cve})
    return {"source": source, "ssvcData": data}


def _cve(entries, cve="CVE-2022-34821"):
    return {"id": cve, "metrics": {"ssvcV203": entries}}


def test_ssvc_adp_only_and_read_by_key():
    reordered = ({"technicalImpact": "partial"}, {"exploitation": "active"}, {"automatable": "yes"})
    records, dropped = ssvc_records(_cve([
        _ssvc(ADP, options=reordered),
        _ssvc(CISA_CNA, ts="2025-01-01T00:00:00Z"),        # CISA acting as CNA
        _ssvc("cve@takeonme.org", ts=None, role="CNA"),     # CNA role: no timestamp, no id
    ]))
    (r,) = records
    assert r == {
        "ssvcId": "CVE-2022-34821::SSVC::2025-04-18T15:23:16.425380Z",
        "cveId": "CVE-2022-34821", "version": "2.0.3",
        "timestamp": "2025-04-18T15:23:16.425380Z", "exploitation": "active",
        "automatable": "yes", "technicalImpact": "partial", "role": "CISA Coordinator",
        "source": ADP, "sourceRole": "adp"}
    assert dropped == {f"source:{CISA_CNA}": 1, "source:cve@takeonme.org": 1}


def test_ssvc_timestamp_verbatim_and_malformed_dropped():
    records, dropped = ssvc_records(_cve([
        _ssvc(ADP, ts="2024-09-12T17:22:46+00:00"),
        _ssvc(ADP, ts="2024-09-13T00:00:00Z", options=({"exploitation": "poc"},)),
        _ssvc(ADP, ts=None),
    ]))
    assert [r["timestamp"] for r in records] == ["2024-09-12T17:22:46+00:00"]
    assert dropped == {"malformed_options": 1, "no_timestamp": 1}


def test_ssvc_id_mismatch_is_dropped():
    records, dropped = ssvc_records(_cve([_ssvc(ADP, cve="CVE-1999-0001")]))
    assert records == [] and dropped == {"id_mismatch": 1}


def test_ssvc_loader_collapses_duplicates_across_files(tmp_path: Path):
    cve_dir = tmp_path / "CVE"
    cve_dir.mkdir()
    dup = _ssvc(ADP)
    newer = _ssvc(ADP, ts="2026-01-02T00:00:00.000000Z")
    for name, entries in (("nvdcve-2.0-modified.json", [dup, newer]),
                          ("nvdcve-2.0-2022.json", [dup, dup])):
        (cve_dir / name).write_text(json.dumps(
            {"vulnerabilities": [{"cve": _cve(entries)},
                                 {"cve": _cve([_ssvc(ADP, cve="CVE-2099-0001")], "CVE-2099-0001")}]}))
    writer = DecisionWriter({"CVE-2022-34821"})
    result = SSVCLoader(str(tmp_path), writer).run()
    assert result["success"], result["errors"]
    s = result["stats"]
    assert s["adp_entries"] == 6 and s["distinct_decisions"] == 3
    assert s["duplicates_collapsed"] == 3
    assert s["loaded"] == 2 and s["dropped_no_vulnerability"] == 1
    assert sorted(k for k in writer.nodes) == [
        "CVE-2022-34821::SSVC::2025-04-18T15:23:16.425380Z",
        "CVE-2022-34821::SSVC::2026-01-02T00:00:00.000000Z"]
    assert all("ON CREATE SET" in c and "HAS_SSVC" in c for c in writer.cyphers())
