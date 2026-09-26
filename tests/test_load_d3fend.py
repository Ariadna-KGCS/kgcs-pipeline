import json
from pathlib import Path

from etl.attck_revocations import apply_remap, build_revocation_remap
from etl.load_attck import _ordered_stix_files
from etl.load_d3fend import D3FENDLoader

_D3F = "https://d3fend.mitre.org/ontologies/d3fend.owl#"


def _binding(fragment: str, label: str, attack_id: str) -> dict:
    return {
        "def_tech": {"type": "uri", "value": _D3F + fragment},
        "def_tech_label": {"type": "literal", "value": label},
        "off_tech_id": {"type": "literal", "value": attack_id},
    }


def _write_d3fend(raw: Path, bindings) -> None:
    d = raw / "D3FEND"
    d.mkdir(parents=True)
    (d / "d3fend-full-mappings.json").write_text(
        json.dumps({"head": {}, "results": {"bindings": list(bindings)}}), encoding="utf-8"
    )
    (d / "d3fend.json").write_text(
        json.dumps({"@graph": [
            {"@id": "d3f:ProcessAnalysis", "d3f:d3fend-id": "D3-PA"},
            {"@id": "d3f:FileAnalysis", "d3f:d3fend-id": "D3-FA"},
        ]}),
        encoding="utf-8",
    )


def test_apply_remap_on_mitigated_by_pairs(attck_raw: Path):
    remap = build_revocation_remap(_ordered_stix_files(attck_raw / "ATTCK-STIX"))
    pairs, counts = apply_remap(
        [
            ("T1562.001", "D3-PA"),   # revoked -> T1685
            ("T1685", "D3-PA"),       # already live: collapses with the row above
            ("T1574.002", "D3-FA"),   # revoked -> SubTechnique T1574.001, no roll-up
            ("T1300", "D3-FA"),       # deprecated: dropped
            ("T9999", "D3-FA"),       # in no bundle: unresolved
            ("T1059", "D3-FA"),
            ("T1059", "D3-FA"),       # duplicate input row counted once
        ],
        remap,
        target_index=0,
    )
    assert pairs == [("T1685", "D3-PA"), ("T1574.001", "D3-FA"), ("T1059", "D3-FA")]
    assert counts == {"rows": 6, "remapped": 2, "dropped_deprecated": 1, "unresolved": 1}


def test_d3fend_loader_writes_remapped_mitigated_by(attck_raw: Path, fake_writer):
    _write_d3fend(attck_raw, [
        _binding("ProcessAnalysis", "Process Analysis", "T1562.001"),
        _binding("FileAnalysis", "File Analysis", "T1574.002"),
        _binding("FileAnalysis", "File Analysis", "T1300"),
        _binding("FileAnalysis", "File Analysis", "T1059"),
    ])

    result = D3FENDLoader(str(attck_raw), fake_writer, batch_size=100).run()
    assert result["success"], result["errors"]

    rows = fake_writer.rows("[:MITIGATED_BY]")
    assert {(r["attackId"], r["d3fendId"]) for r in rows} == {
        ("T1685", "D3-PA"),
        ("T1574.001", "D3-FA"),
        ("T1059", "D3-FA"),
    }
    assert not {r["attackId"] for r in rows} & {"T1562.001", "T1574.002", "T1300"}
    stats = result["stats"]
    assert stats["mitigated_by"] == 3
    assert stats["mitigated_by_remapped"] == 2
    assert stats["mitigated_by_dropped_deprecated"] == 1
    assert stats["mitigated_by_unresolved"] == 0


def test_d3fend_loader_fails_without_attck_bundles(tmp_path: Path, fake_writer):
    raw = tmp_path / "raw"
    _write_d3fend(raw, [_binding("FileAnalysis", "File Analysis", "T1059")])
    result = D3FENDLoader(str(raw), fake_writer, batch_size=100).run()
    assert not result["success"]
    assert not fake_writer.rows("[:MITIGATED_BY]")
