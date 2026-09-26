from pathlib import Path

from etl.load_capec import _iter_capec_records


def test_iter_capec_records_extracts_child_of_relationships():
    xml_path = Path(__file__).with_name("_capec_childof_fixture.xml")
    try:
        xml_path.write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">
  <Attack_Patterns>
    <Attack_Pattern ID="85" Name="AJAX Footprinting" Status="Stable">
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="79" />
      </Related_Weaknesses>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="580" />
        <Related_Attack_Pattern Nature="CanPrecede" CAPEC_ID="63" />
      </Related_Attack_Patterns>
      <Taxonomy_Mappings>
        <Taxonomy_Mapping Taxonomy_Name="ATTACK">
          <Entry_ID>1082</Entry_ID>
        </Taxonomy_Mapping>
      </Taxonomy_Mappings>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
""",
            encoding="utf-8",
        )

        records = list(_iter_capec_records(xml_path))
        assert len(records) == 1
        # ATT&CK Taxonomy_Mappings are not yielded: IMPLEMENTS is written by
        # load_attck.py (revoked-by remap + roll-up), never by load_capec.py.
        ap, weakness_edges, child_of_edges = records[0]

        assert ap["capecId"] == "CAPEC-85"
        assert weakness_edges == [{"cweId": "CWE-79", "capecId": "CAPEC-85"}]
        assert child_of_edges == [{"childCapecId": "CAPEC-85", "parentCapecId": "CAPEC-580"}]
    finally:
        if xml_path.exists():
            xml_path.unlink()
