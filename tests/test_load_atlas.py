"""ATLAS module loader (spec 1.2.1, ADR-0004)."""

import copy
from pathlib import Path
from typing import Dict, List

import pytest
import yaml

from etl.attck_revocations import build_revocation_remap
from etl.load_atlas import (
    ATLASLoader, atlas_snapshot, resolve_adapted_from, select_atlas_yaml, transform_atlas,
)
from etl.load_attck import _find_attck_dir, _ordered_stix_files


def _obj(oid: str, kind: str, **extra) -> Dict:
    o = {"id": oid, "uuid": f"u-{oid}", "object-type": kind, "name": f"n {oid}",
         "description": f"d {oid}", "references": [], "created-date": "2021-05-13",
         "modified-date": "2026-09-15"}
    o.update(extra)
    return o


def _tech(oid: str, ref=None) -> Dict:
    extra = {"maturity": "Realized", "platforms": ["Generative AI", "Agentic AI"]}
    if ref:
        extra["attack-reference"] = {"id": ref, "url": f"https://attack.mitre.org/techniques/{ref.replace('.', '/')}/"}
    return _obj(oid, "technique", **extra)


def _rel(src, rtype, tgt, **extra) -> Dict:
    return {"source": src, "target": tgt, "relationship-type": rtype, **extra}


def atlas_doc() -> Dict:
    """Two tactics, two techniques, three sub-techniques, one mitigation, one case study."""
    rels: Dict[str, Dict[str, List]] = {}

    def add(src, rtype, tgt, **extra):
        rels.setdefault(src, {}).setdefault(rtype, []).append(_rel(src, rtype, tgt, **extra))

    add("ATLAS-matrix", "sequences", "AML.TA0002", position=1)
    add("ATLAS-matrix", "sequences", "AML.TA0003", position=2)
    for t, tac in (("AML.T0000", "AML.TA0002"), ("AML.T0001", "AML.TA0003"),
                   ("AML.T0000.000", "AML.TA0002"), ("AML.T0000.001", "AML.TA0002"),
                   ("AML.T0001.000", "AML.TA0003"), ("AML.T0001.000", "AML.TA0002")):
        add(t, "achieves", tac)
    for s, p in (("AML.T0000.000", "AML.T0000"), ("AML.T0000.001", "AML.T0000"),
                 ("AML.T0001.000", "AML.T0001")):
        add(s, "specializes", p)
    add("AML.M0000", "mitigates", "AML.T0000", description="x")
    add("AML.M0000", "mitigates", "AML.T0001.000", description="y")
    add("AML.CS0000", "employs", "AML.T0000", description="z", tactic="AML.TA0002",
        **{"step-id": "S00", "leads-to": []})
    return {
        "format-version": "6.0.0",
        "collection": {"id": "ATLAS-collection", "version": "2026.09"},
        "matrix": {"id": "ATLAS-matrix"},
        "tactics": {
            "AML.TA0002": _obj("AML.TA0002", "tactic", **{"attack-reference": {"id": "TA0043", "url": "u"}}),
            "AML.TA0003": _obj("AML.TA0003", "tactic"),
        },
        "techniques": {
            "AML.T0000": _tech("AML.T0000", "T1059"),               # live
            "AML.T0001": _tech("AML.T0001", "T1574.002"),           # revoked -> T1574.001
            "AML.T0000.000": _tech("AML.T0000.000", "T1300"),       # deprecated
            "AML.T0000.001": _tech("AML.T0000.001", "T9999"),       # unresolved
            "AML.T0001.000": _tech("AML.T0001.000", "T1574.001"),   # live sub
        },
        "mitigations": {
            "AML.M0000": _obj("AML.M0000", "mitigation", categories=["Policy"],
                              **{"lifecycle-phases": ["Deployment"],
                                 "attack-reference": {"id": "M1017", "url": "u"}}),
        },
        "case-studies": {"AML.CS0000": _obj("AML.CS0000", "case-study")},
        "relationships": rels,
    }


def test_transform_counts_and_classification():
    d = transform_atlas(atlas_doc())
    c = d["counts"]
    assert (c["tactics"], c["techniques"], c["subtechniques"], c["mitigations"]) == (2, 2, 3, 1)
    assert (c["achieves"], c["specializes"], c["mitigates"]) == (6, 3, 2)
    assert c["attack_reference_rows"] == 5
    assert c["excluded_tactic_attack_reference"] == 1 and c["excluded_mitigation_attack_reference"] == 1
    assert c["excluded_case_studies"] == 1 and c["excluded_employs"] == 1
    tactic = next(t for t in d["nodes"]["AtlasTactic"] if t["atlasId"] == "AML.TA0003")
    assert tactic["matrixPosition"] == 2 and tactic["createdDate"] == "2021-05-13"
    sub = next(t for t in d["nodes"]["AtlasSubTechnique"] if t["atlasId"] == "AML.T0001.000")
    assert sub["platforms"] == ["Generative AI", "Agentic AI"] and sub["maturity"] == "Realized"
    mit = d["nodes"]["AtlasMitigation"][0]
    assert mit["categories"] == ["Policy"] and mit["lifecyclePhases"] == ["Deployment"]
    assert {e["srcLabel"] for e in d["achieves"]} == {"AtlasTechnique", "AtlasSubTechnique"}
    # uuid, references and case studies are not mapped
    assert not any("uuid" in n or "references" in n for ns in d["nodes"].values() for n in ns)


def test_yaml_dates_normalised_to_strings():
    doc = atlas_doc()
    import datetime
    doc["tactics"]["AML.TA0003"]["created-date"] = datetime.date(2021, 5, 13)
    t = next(t for t in transform_atlas(doc)["nodes"]["AtlasTactic"] if t["atlasId"] == "AML.TA0003")
    assert t["createdDate"] == "2021-05-13"


@pytest.mark.parametrize("mutate, match", [
    (lambda d: d["relationships"]["AML.T0000.001"].pop("specializes"), "disagrees"),
    (lambda d: d["relationships"].setdefault("AML.T0001", {}).setdefault("specializes", []).append(
        _rel("AML.T0001", "specializes", "AML.T0000")), "disagrees"),
    (lambda d: d.__setitem__("format-version", "5.1.0"), "format"),
    (lambda d: d["relationships"]["AML.M0000"]["mitigates"].append(
        _rel("AML.M0000", "mitigates", "AML.TA0002")), "unexpected endpoint"),
])
def test_structural_surprises_fail_the_load(mutate, match):
    doc = copy.deepcopy(atlas_doc())
    mutate(doc)
    with pytest.raises(ValueError, match=match):
        transform_atlas(doc)


def test_adapted_from_uses_the_attck_revocation_remap(attck_raw: Path):
    d = transform_atlas(atlas_doc())
    remap = build_revocation_remap(_ordered_stix_files(_find_attck_dir(attck_raw)))
    edges, counts = resolve_adapted_from(d["attack_refs"], remap)
    assert (counts["rows"], counts["remapped"], counts["dropped_deprecated"], counts["unresolved"]) == (5, 1, 1, 1)
    assert counts["unresolved_ids"] == ["AML.T0000.001->T9999"]
    by_src = {e["src"]: e for e in edges}
    remapped = by_src["AML.T0001"]
    assert (remapped["tgt"], remapped["tgtLabel"], remapped["attackReferenceId"]) == (
        "T1574.001", "SubTechnique", "T1574.002")    # cited id kept verbatim on the edge
    assert by_src["AML.T0000"]["tgtLabel"] == "Technique"


def test_select_atlas_yaml_never_reads_latest(tmp_path: Path):
    d = tmp_path / "ATLAS"
    d.mkdir()
    for name in ("ATLAS-latest.yaml", "ATLAS-2026.04.yaml", "ATLAS-2026.09.yaml", "ATLAS-2022.03.2.yaml"):
        (d / name).write_text(yaml.safe_dump({"collection": {"version": name[6:-5]}}))
    assert select_atlas_yaml(d).name == "ATLAS-2026.09.yaml"
    assert atlas_snapshot(tmp_path) == "2026.09"
    (d / "ATLAS-2026.09.yaml").unlink()
    (d / "ATLAS-2026.04.yaml").unlink()
    (d / "ATLAS-2022.03.2.yaml").unlink()
    assert select_atlas_yaml(d) is None


class AtlasWriter:
    def __init__(self, attack_ids) -> None:
        self.attack_ids = set(attack_ids)
        self.calls: List[tuple] = []

    def read_rows(self, cypher: str, params=None):
        if "UNWIND $ids" in cypher:
            return [{"id": i} for i in params["ids"] if i in self.attack_ids]
        return []                                   # no ATLAS node in the graph yet

    def execute_batch(self, cypher: str, rows: List[Dict], batch_size: int = 1000):
        self.calls.append((cypher, list(rows)))
        return {"success": True, "nodes_created": 0, "rels_created": len(rows), "errors": []}


def test_loader_writes_only_atlas_types_and_bridges(attck_raw: Path):
    atlas_dir = attck_raw / "ATLAS"
    atlas_dir.mkdir()
    (atlas_dir / "ATLAS-2026.09.yaml").write_text(yaml.safe_dump(atlas_doc()), encoding="utf-8")
    writer = AtlasWriter({"T1059", "T1574.001"})
    result = ATLASLoader(str(attck_raw), writer).run()
    assert result["success"], result["errors"]
    s = result["stats"]
    assert (s["adapted_from_rows"], s["adapted_from_written"], s["adapted_from_remapped"],
            s["adapted_from_dropped_deprecated"], s["adapted_from_unresolved"]) == (5, 3, 1, 1, 1)
    cyphers = "\n".join(c for c, _ in writer.calls)
    assert "PART_OF" not in cyphers and "SUBTECHNIQUE_OF" not in cyphers
    for t in ("ACHIEVES", "SPECIALIZES", "MITIGATES", "ADAPTED_FROM"):
        assert f":{t}]" in cyphers
    # every MATCH is label-qualified (never an unlabelled ATLAS id match)
    assert "MATCH (a {" not in cyphers and "MATCH (t {" not in cyphers
    adapted = [r for c, rows in writer.calls if "ADAPTED_FROM" in c for r in rows]
    assert {r["tgt"] for r in adapted} == {"T1059", "T1574.001"}
    # node order: tactics, techniques, sub-techniques, mitigations, then edges
    merges = [c.split("MERGE (n:")[1].split(" ")[0] for c, _ in writer.calls if "MERGE (n:" in c]
    assert merges == ["AtlasTactic", "AtlasTechnique", "AtlasSubTechnique", "AtlasMitigation"]


def test_loader_reports_bridge_target_missing_from_graph(attck_raw: Path):
    atlas_dir = attck_raw / "ATLAS"
    atlas_dir.mkdir()
    (atlas_dir / "ATLAS-2026.09.yaml").write_text(yaml.safe_dump(atlas_doc()), encoding="utf-8")
    result = ATLASLoader(str(attck_raw), AtlasWriter({"T1059"})).run()
    s = result["stats"]
    assert s["adapted_from_written"] == 1          # only T1059 exists in this graph
    assert s["adapted_from_unresolved"] == 3       # T9999 + two edges to the absent T1574.001
    assert "AML.T0001.000->T1574.001 (not in graph)" in s["adapted_from_unresolved_ids"]
    assert "AML.T0001->T1574.001 (not in graph)" in s["adapted_from_unresolved_ids"]


def test_loader_fails_without_attck_bundles(tmp_path: Path):
    (tmp_path / "ATLAS").mkdir()
    (tmp_path / "ATLAS" / "ATLAS-2026.09.yaml").write_text(yaml.safe_dump(atlas_doc()))
    result = ATLASLoader(str(tmp_path), AtlasWriter(set())).run()
    assert not result["success"] and "revoked-by remap" in result["errors"][0]
