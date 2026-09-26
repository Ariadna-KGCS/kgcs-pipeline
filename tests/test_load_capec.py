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
        ap, weakness_edges, child_of_edges, consequences = records[0]

        assert ap["capecId"] == "CAPEC-85"
        assert weakness_edges == [{"cweId": "CWE-79", "capecId": "CAPEC-85"}]
        assert child_of_edges == [{"childCapecId": "CAPEC-85", "parentCapecId": "CAPEC-580"}]
        assert consequences == []
    finally:
        if xml_path.exists():
            xml_path.unlink()

class _MatchingWriter:
    """Applies MERGE/MATCH semantics for AttackPattern nodes and CHILD_OF edges."""

    def __init__(self) -> None:
        self.patterns = set()
        self.child_of = set()

    def execute_batch(self, cypher, params_list, batch_size=1000):
        if "MERGE (ap:AttackPattern" in cypher:
            self.patterns.update(r["capecId"] for r in params_list)
        elif "[:CHILD_OF]" in cypher:
            for r in params_list:
                if r["childCapecId"] in self.patterns and r["parentCapecId"] in self.patterns:
                    self.child_of.add((r["childCapecId"], r["parentCapecId"]))
        return {"success": True, "nodes_created": 0, "rels_created": 0, "errors": []}


def test_child_of_complete_after_one_run_and_unchanged_by_a_second(tmp_path):
    from etl.load_capec import CAPECLoader

    capec_dir = tmp_path / "raw" / "CAPEC"
    capec_dir.mkdir(parents=True)
    # Children come before their parent in the XML, and batch_size=1 forces a
    # flush after every pattern: a CHILD_OF written with its child's batch
    # would find no parent node yet.
    (capec_dir / "capec_latest.xml").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">
  <Attack_Patterns>
    <Attack_Pattern ID="2" Name="Child A" Status="Stable">
      <Related_Weaknesses><Related_Weakness CWE_ID="79" /></Related_Weaknesses>
      <Related_Attack_Patterns><Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="1" /></Related_Attack_Patterns>
    </Attack_Pattern>
    <Attack_Pattern ID="3" Name="Child B" Status="Stable">
      <Related_Attack_Patterns><Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="1" /></Related_Attack_Patterns>
    </Attack_Pattern>
    <Attack_Pattern ID="1" Name="Parent" Status="Stable">
      <Related_Attack_Patterns><Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="999" /></Related_Attack_Patterns>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
""",
        encoding="utf-8",
    )
    writer = _MatchingWriter()
    loader = CAPECLoader(str(tmp_path / "raw"), writer, batch_size=1)

    assert loader.run()["success"]
    after_one = set(writer.child_of)
    assert loader.run()["success"]
    after_two = set(writer.child_of)

    # CAPEC-999 is not an AttackPattern: that ChildOf never lands.
    assert after_one == {("CAPEC-2", "CAPEC-1"), ("CAPEC-3", "CAPEC-1")}
    assert after_two == after_one


def test_capec_run_reports_each_edge_type_separately(tmp_path, caplog):
    from etl.load_capec import CAPECLoader

    class CountingWriter:
        def execute_batch(self, cypher, params_list, batch_size=1000):
            nodes = len(params_list) if "MERGE (ap:AttackPattern" in cypher else 0
            rels = 0 if nodes else len(params_list)
            return {"success": True, "nodes_created": nodes, "rels_created": rels, "errors": []}

    capec_dir = tmp_path / "raw" / "CAPEC"
    capec_dir.mkdir(parents=True)
    (capec_dir / "capec_latest.xml").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">
  <Attack_Patterns>
    <Attack_Pattern ID="2" Name="Child" Status="Stable">
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="79" /><Related_Weakness CWE_ID="89" />
      </Related_Weaknesses>
      <Related_Attack_Patterns><Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="1" /></Related_Attack_Patterns>
    </Attack_Pattern>
    <Attack_Pattern ID="1" Name="Parent" Status="Deprecated" />
  </Attack_Patterns>
</Attack_Pattern_Catalog>
""",
        encoding="utf-8",
    )
    with caplog.at_level("INFO"):
        result = CAPECLoader(str(tmp_path / "raw"), CountingWriter(), batch_size=100).run()

    stats = result["stats"]
    assert stats["nodes_created"] == 2
    assert stats["demonstrated_by_created"] == 2
    assert stats["child_of_created"] == 1
    assert stats["rels_created"] == 3
    assert (
        "2 AttackPattern nodes, 2 DEMONSTRATED_BY edges, 1 CHILD_OF edges created "
        "(1 deprecated nodes included)"
    ) in caplog.text


# ---------------------------------------------------------------------------
# spec 1.1.0: AttackPattern properties + Consequence sub-nodes
# ---------------------------------------------------------------------------

_AP_66 = """
    <Attack_Pattern ID="66" Name="SQL Injection" Abstraction="Standard" Status="Draft">
      <Description>SQLi.</Description>
      <Likelihood_Of_Attack>High</Likelihood_Of_Attack>
      <Typical_Severity>Very High</Typical_Severity>
      <Consequences>
        <Consequence>
          <Scope>Confidentiality</Scope><Scope>Integrity</Scope><Scope>Availability</Scope>
          <Impact>Execute Unauthorized Commands</Impact>
          <Note>Run arbitrary <xhtml:b>SQL</xhtml:b>.</Note>
        </Consequence>
        <Consequence>
          <Scope>Confidentiality</Scope>
          <Impact>Read Data</Impact>
        </Consequence>
        <Consequence>
          <Scope>Access Control</Scope>
          <Likelihood>High</Likelihood>
        </Consequence>
      </Consequences>
    </Attack_Pattern>"""

_AP_7 = """
    <Attack_Pattern ID="7" Name="Blind SQL Injection" Abstraction="Detailed" Status="Deprecated"/>"""


def _capec_catalog(raw, *patterns):
    capec_dir = raw / "CAPEC"
    capec_dir.mkdir(parents=True, exist_ok=True)
    path = capec_dir / "capec_latest.xml"
    path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" '
        'xmlns:xhtml="http://www.w3.org/1999/xhtml" Name="CAPEC" Version="3.9" Date="2023-01-24">'
        f'<Attack_Patterns>{"".join(patterns)}</Attack_Patterns></Attack_Pattern_Catalog>',
        encoding="utf-8",
    )
    return path


def test_attack_pattern_declared_properties(tmp_path):
    records = list(_iter_capec_records(_capec_catalog(tmp_path, _AP_66, _AP_7)))
    assert [r[0] for r in records] == [
        {"capecId": "CAPEC-66", "name": "SQL Injection", "status": "Draft",
         "abstraction": "Standard", "attackLikelihood": "High",
         "typicalSeverity": "Very High"},           # verbatim XSD value
        {"capecId": "CAPEC-7", "name": "Blind SQL Injection", "status": "Deprecated",
         "abstraction": "Detailed", "attackLikelihood": None, "typicalSeverity": None},
    ]


def test_capec_consequences_grouped_with_optional_impact(tmp_path):
    _, _, _, consequences = list(_iter_capec_records(_capec_catalog(tmp_path, _AP_66)))[0]
    assert consequences == [
        {"parentId": "CAPEC-66", "consequenceId": "CAPEC-66-C1",
         "scopes": ["Confidentiality", "Integrity", "Availability"],
         "impacts": ["Execute Unauthorized Commands"],
         "likelihood": None, "note": "Run arbitrary SQL."},
        {"parentId": "CAPEC-66", "consequenceId": "CAPEC-66-C2",
         "scopes": ["Confidentiality"], "impacts": ["Read Data"],
         "likelihood": None, "note": None},
        {"parentId": "CAPEC-66", "consequenceId": "CAPEC-66-C3",
         "scopes": ["Access Control"], "impacts": None,   # CAPEC Impact is minOccurs=0
         "likelihood": "High", "note": None},
    ]


def test_capec_load_is_idempotent_and_prunes(tmp_path, graph_sim):
    from etl.load_capec import CAPECLoader

    raw = tmp_path / "raw"
    _capec_catalog(raw, _AP_66, _AP_7)
    first = CAPECLoader(str(raw), graph_sim, batch_size=1).run()
    snapshot = ({k: dict(v) for k, v in graph_sim.nodes.items()}, set(graph_sim.edges))
    second = CAPECLoader(str(raw), graph_sim, batch_size=1).run()

    assert first["success"] and second["success"]
    assert first["stats"]["consequence_nodes_created"] == 3
    assert first["stats"]["has_consequence_created"] == 3
    assert first["stats"]["consequence_out_of_vocabulary"] == 0
    assert second["stats"]["nodes_created"] == 0
    assert second["stats"]["consequence_nodes_created"] == 0
    assert second["stats"]["has_consequence_created"] == 0
    assert (graph_sim.nodes, graph_sim.edges) == snapshot
    assert "impacts" not in graph_sim.consequences()["CAPEC-66-C3"]

    # MITRE drops the third record and the severity in a later release.
    newer = _AP_66.replace(
        "<Consequence>\n          <Scope>Access Control</Scope>\n"
        "          <Likelihood>High</Likelihood>\n        </Consequence>", ""
    ).replace("<Typical_Severity>Very High</Typical_Severity>", "")
    assert newer.count("<Consequence>") == 2
    _capec_catalog(raw, newer, _AP_7)
    third = CAPECLoader(str(raw), graph_sim, batch_size=1).run()
    assert third["stats"]["consequence_nodes_pruned"] == 1
    assert set(graph_sim.consequences()) == {"CAPEC-66-C1", "CAPEC-66-C2"}
    assert "typicalSeverity" not in graph_sim.nodes[("AttackPattern", "CAPEC-66")]


def test_cwe_impact_in_capec_record_is_reported(tmp_path, caplog, fake_writer):
    from etl.load_capec import CAPECLoader

    raw = tmp_path / "raw"
    _capec_catalog(raw, _AP_66.replace("<Impact>Read Data</Impact>",
                                       "<Impact>Read Application Data</Impact>"))
    with caplog.at_level("WARNING"):
        result = CAPECLoader(str(raw), fake_writer, batch_size=100).run()
    assert result["stats"]["consequence_out_of_vocabulary"] == 1
    assert "CAPEC-66-C2 impact 'Read Application Data'" in caplog.text
