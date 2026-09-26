from pathlib import Path

from etl.attck_revocations import build_revocation_remap
from etl.load_attck import (
    ATTCKLoader,
    _capec_taxonomy_pairs,
    _load_stix_bundle,
    _normalize_attack_id,
    _normalize_attack_id_to_technique,
    _ordered_stix_files,
    _part_of_pairs,
    _resolve_implements,
)

_CAPEC_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">
  <Attack_Patterns>
{patterns}
  </Attack_Patterns>
</Attack_Pattern_Catalog>
"""


def _capec_pattern(capec_num: int, *entry_ids: str) -> str:
    maps = "".join(
        f'<Taxonomy_Mapping Taxonomy_Name="ATTACK"><Entry_ID>{e}</Entry_ID></Taxonomy_Mapping>'
        for e in entry_ids
    )
    return (
        f'    <Attack_Pattern ID="{capec_num}" Name="P{capec_num}" Status="Stable">'
        f"<Taxonomy_Mappings>{maps}</Taxonomy_Mappings></Attack_Pattern>"
    )


def test_normalize_attack_id_to_technique_strips_subtechnique_suffix():
    assert _normalize_attack_id_to_technique("1574.010") == "T1574"
    assert _normalize_attack_id_to_technique("T1059.001") == "T1059"
    assert _normalize_attack_id_to_technique("1110") == "T1110"
    assert _normalize_attack_id_to_technique("") is None


def test_normalize_attack_id_keeps_subtechnique():
    assert _normalize_attack_id("1574.010") == "T1574.010"
    assert _normalize_attack_id(" T1190 ") == "T1190"
    assert _normalize_attack_id("") is None


def test_capec_taxonomy_pairs_extracts_cited_ids_without_rollup(tmp_path: Path):
    xml_path = tmp_path / "capec.xml"
    xml_path.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">
  <Attack_Patterns>
    <Attack_Pattern ID="1" Name="One" Status="Stable">
      <Taxonomy_Mappings>
        <Taxonomy_Mapping Taxonomy_Name="ATTACK">
          <Entry_ID>1574.010</Entry_ID>
        </Taxonomy_Mapping>
        <Taxonomy_Mapping Taxonomy_Name="ATTACK">
          <Entry_ID>1110</Entry_ID>
        </Taxonomy_Mapping>
        <Taxonomy_Mapping Taxonomy_Name="WASC">
          <Entry_ID>3</Entry_ID>
        </Taxonomy_Mapping>
      </Taxonomy_Mappings>
    </Attack_Pattern>
    <Attack_Pattern ID="2" Name="Two" Status="Stable">
      <Taxonomy_Mappings>
        <Taxonomy_Mapping Taxonomy_Name="ATTACK">
          <Entry_ID>T1190</Entry_ID>
        </Taxonomy_Mapping>
      </Taxonomy_Mappings>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
""",
        encoding="utf-8",
    )

    # Roll-up happens after the revoked-by remap, in _resolve_implements.
    assert _capec_taxonomy_pairs(xml_path) == {
        ("CAPEC-1", "T1574.010"),
        ("CAPEC-1", "T1110"),
        ("CAPEC-2", "T1190"),
    }


# ---------------------------------------------------------------------------
# PART_OF: same-bundle tactic resolution
# ---------------------------------------------------------------------------

def _all_part_of(raw: Path):
    pairs, unresolved = set(), 0
    for path in _ordered_stix_files(raw / "ATTCK-STIX"):
        p, u = _part_of_pairs(_load_stix_bundle(path))
        pairs |= p
        unresolved += u
    return pairs, unresolved


def test_part_of_t1059_links_only_to_enterprise_execution(attck_raw: Path):
    pairs, unresolved = _all_part_of(attck_raw)

    # `execution` exists in all three matrices (TA0002, TA0041, TA0104);
    # the v1.0 phaseName match linked T1059 to all three.
    assert {ta for t, ta in pairs if t == "T1059"} == {"TA0002"}
    assert {ta for t, ta in pairs if t == "T1623"} == {"TA0041"}
    assert {ta for t, ta in pairs if t == "T0807"} == {"TA0104"}
    assert {ta for t, ta in pairs if t == "T1574"} == {"TA0003", "TA0005"}
    assert unresolved == 0


def test_part_of_counts_phase_with_foreign_kill_chain_as_unresolved(tmp_path: Path):
    from conftest import stix_tactic, stix_technique, write_bundle

    d = tmp_path / "ATTCK-STIX"
    path = write_bundle(d, "enterprise-attack.json", [
        stix_tactic("x-mitre-tactic--e", "TA0002", "execution"),
        # a mobile kill chain entry inside the enterprise bundle
        stix_technique("attack-pattern--x", "T9999", ["execution"], kill_chain="mitre-mobile-attack"),
    ])
    pairs, unresolved = _part_of_pairs(_load_stix_bundle(path))
    assert pairs == set()
    assert unresolved == 1


# ---------------------------------------------------------------------------
# revoked-by remap
# ---------------------------------------------------------------------------

def _remap(raw: Path):
    return build_revocation_remap(_ordered_stix_files(raw / "ATTCK-STIX"))


def test_remap_follows_revoked_by(attck_raw: Path):
    remap = _remap(attck_raw)
    assert remap.resolve("T1562.001") == ("remapped", "T1685")
    assert remap.resolve("T1574.002") == ("remapped", "T1574.001")
    assert remap.resolve("T1100") == ("remapped", "T1059")      # two-step chain
    assert remap.resolve("T1059") == ("live", "T1059")
    assert remap.resolve("T1300") == ("deprecated", None)
    assert remap.resolve("T1301") == ("deprecated", None)       # chain ends deprecated
    assert remap.resolve("T1400") == ("unresolved", None)       # no successor
    assert remap.resolve("T9999") == ("unresolved", None)       # in no bundle
    assert "T1400" in remap.revoked_without_successor


def test_resolve_implements_remaps_before_rollup(attck_raw: Path):
    remap = _remap(attck_raw)
    live_techniques = {"T1059", "T1685", "T1574", "T1623", "T0807"}
    refs = {
        ("CAPEC-13", "T1562.001"),   # -> T1685, not the revoked T1562
        ("CAPEC-1", "T1574.002"),    # -> T1574.001 -> roll-up T1574
        ("CAPEC-2", "T1574.001"),    # live sub-technique -> T1574 (collapses)
        ("CAPEC-3", "T1300"),        # deprecated: dropped
        ("CAPEC-4", "T9999"),        # unknown: unresolved
        ("CAPEC-5", "T1059"),
    }
    pairs, counts = _resolve_implements(refs, remap, live_techniques)

    assert pairs == {
        ("CAPEC-13", "T1685"),
        ("CAPEC-1", "T1574"),
        ("CAPEC-2", "T1574"),
        ("CAPEC-5", "T1059"),
    }
    assert counts == {"rows": 6, "remapped": 2, "dropped_deprecated": 1, "unresolved": 1}


def test_attck_loader_writes_part_of_by_tactic_id_and_remapped_implements(
    attck_raw: Path, fake_writer
):
    (attck_raw / "CAPEC").mkdir()
    (attck_raw / "CAPEC" / "capec_latest.xml").write_text(
        _CAPEC_XML.format(patterns="\n".join([
            _capec_pattern(571, "1562.001"),
            _capec_pattern(574, "1574.002"),
            _capec_pattern(600, "1300"),
        ])),
        encoding="utf-8",
    )

    result = ATTCKLoader(str(attck_raw), fake_writer, batch_size=100).run()
    assert result["success"], result["errors"]

    part_of = fake_writer.rows("[:PART_OF]")
    assert {"techniqueId": "T1059", "tacticId": "TA0002"} in part_of
    assert not [r for r in part_of if r["techniqueId"] == "T1059" and r["tacticId"] != "TA0002"]
    assert all(set(r) == {"techniqueId", "tacticId"} for r in part_of)
    assert "Tactic {attackId: row.tacticId}" in next(
        c for c, _ in fake_writer.calls if "[:PART_OF]" in c
    )

    implements = {(r["capecId"], r["techniqueId"]) for r in fake_writer.rows("[:IMPLEMENTS]")}
    assert implements == {
        ("CAPEC-571", "T1685"),   # CAPEC XML, remapped
        ("CAPEC-574", "T1574"),   # CAPEC XML, remapped then rolled up
        ("CAPEC-13", "T1685"),    # STIX capec ref on the revoked T1562
    }
    stats = result["stats"]
    assert stats["implements"] == 3
    assert stats["implements_remapped"] == 3
    assert stats["implements_dropped_deprecated"] == 2   # CAPEC-600 XML + CAPEC-99 STIX
    assert stats["implements_unresolved"] == 0
