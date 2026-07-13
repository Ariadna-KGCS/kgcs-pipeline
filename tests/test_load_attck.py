from pathlib import Path

from etl.load_attck import (
    _capec_taxonomy_pairs,
    _normalize_attack_id_to_technique,
)


def test_normalize_attack_id_to_technique_strips_subtechnique_suffix():
    assert _normalize_attack_id_to_technique("1574.010") == "T1574"
    assert _normalize_attack_id_to_technique("T1059.001") == "T1059"
    assert _normalize_attack_id_to_technique("1110") == "T1110"
    assert _normalize_attack_id_to_technique("") is None


def test_capec_taxonomy_pairs_extracts_attack_mappings():
    xml_path = Path(__file__).with_name("_capec_test_fixture.xml")
    try:
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

        assert _capec_taxonomy_pairs(xml_path) == {
            ("CAPEC-1", "T1574"),
            ("CAPEC-1", "T1110"),
            ("CAPEC-2", "T1190"),
        }
    finally:
        if xml_path.exists():
            xml_path.unlink()
