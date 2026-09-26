import json
from pathlib import Path
from typing import Dict, List

import pytest


class FakeWriter:
    """Records execute_batch calls instead of talking to Neo4j."""

    def __init__(self) -> None:
        self.calls: List[tuple] = []

    def execute_batch(self, cypher: str, params_list: List[Dict], batch_size: int = 1000):
        self.calls.append((cypher, list(params_list)))
        return {"success": True, "nodes_created": 0, "rels_created": 0, "errors": []}

    def rows(self, marker: str) -> List[Dict]:
        """All rows sent with a Cypher statement containing `marker`."""
        return [row for cypher, rows in self.calls if marker in cypher for row in rows]


@pytest.fixture
def fake_writer() -> FakeWriter:
    return FakeWriter()


class GraphSim:
    """In-memory MERGE / SET / prune semantics of the Weakness, AttackPattern
    and Consequence statements (SET x = null removes x, as in Neo4j).
    Any other statement is recorded and ignored."""

    _PARENTS = {"Weakness": "cweId", "AttackPattern": "capecId"}

    def __init__(self) -> None:
        self.nodes: Dict[tuple, Dict] = {}     # (label, key) -> properties
        self.edges: set = set()                # (parent key, consequenceId)
        self.other: List[str] = []

    @staticmethod
    def _set(props: Dict, row: Dict, skip=("parentId",)) -> None:
        for field, value in row.items():
            if field in skip:
                continue
            if value is None:
                props.pop(field, None)
            else:
                props[field] = value

    def execute_batch(self, cypher: str, params_list: List[Dict], batch_size: int = 1000):
        created = rels = deleted = 0
        parent = "Weakness" if ":Weakness" in cypher else "AttackPattern"
        key = self._PARENTS[parent]
        if f"MERGE (w:{parent}" in cypher or f"MERGE (ap:{parent}" in cypher:
            for row in params_list:
                node = (parent, row[key])
                if node not in self.nodes:
                    self.nodes[node] = {}
                    created += 1
                self._set(self.nodes[node], row)
        elif "MERGE (c:Consequence" in cypher:
            for row in params_list:
                if (parent, row["parentId"]) not in self.nodes:
                    continue                    # MATCH on the parent found nothing
                node = ("Consequence", row["consequenceId"])
                if node not in self.nodes:
                    self.nodes[node] = {}
                    created += 1
                self._set(self.nodes[node], row)
                edge = (row["parentId"], row["consequenceId"])
                if edge not in self.edges:
                    self.edges.add(edge)
                    rels += 1
        elif "DETACH DELETE c" in cypher:
            for row in params_list:
                for edge in sorted(self.edges):
                    pid, cid = edge
                    if pid == row["parentId"] and cid.startswith(pid + "-C") \
                            and int(cid.split("-C")[-1]) > row["count"]:
                        self.edges.discard(edge)
                        del self.nodes[("Consequence", cid)]
                        deleted += 1
        else:
            self.other.append(cypher)
        return {"success": True, "nodes_created": created, "rels_created": rels,
                "nodes_deleted": deleted, "errors": []}

    def consequences(self) -> Dict[str, Dict]:
        return {k: v for (label, k), v in self.nodes.items() if label == "Consequence"}


@pytest.fixture
def graph_sim() -> GraphSim:
    return GraphSim()


# ---------------------------------------------------------------------------
# Minimal STIX builders
# ---------------------------------------------------------------------------

def stix_tactic(stix_id: str, attack_id: str, shortname: str, name: str = "") -> Dict:
    return {
        "type": "x-mitre-tactic",
        "id": stix_id,
        "name": name or shortname,
        "x_mitre_shortname": shortname,
        "external_references": [{"source_name": "mitre-attack", "external_id": attack_id}],
    }


def stix_technique(
    stix_id: str,
    attack_id: str,
    phases=(),
    kill_chain: str = "mitre-attack",
    sub: bool = False,
    revoked: bool = False,
    deprecated: bool = False,
    capec=(),
) -> Dict:
    refs = [{"source_name": "mitre-attack", "external_id": attack_id}]
    refs += [{"source_name": "capec", "external_id": c} for c in capec]
    return {
        "type": "attack-pattern",
        "id": stix_id,
        "name": attack_id,
        "x_mitre_is_subtechnique": sub,
        "revoked": revoked,
        "x_mitre_deprecated": deprecated,
        "kill_chain_phases": [
            {"kill_chain_name": kill_chain, "phase_name": p} for p in phases
        ],
        "external_references": refs,
    }


def stix_rel(rel_type: str, src: str, tgt: str) -> Dict:
    return {
        "type": "relationship",
        "id": f"relationship--{src}-{tgt}",
        "relationship_type": rel_type,
        "source_ref": src,
        "target_ref": tgt,
    }


def write_bundle(directory: Path, name: str, objects: List[Dict]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(
        json.dumps({"type": "bundle", "id": f"bundle--{name}", "objects": objects}),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def attck_raw(tmp_path: Path) -> Path:
    """data/raw-like tree with three small ATT&CK bundles.

    - T1059 (enterprise, execution): only TA0002 is the right tactic, although
      mobile TA0041 and ics TA0104 share the phase name `execution`.
    - T1562.001 revoked-by T1685 (enterprise); T1562 itself revoked-by T1685.
    - T1574.002 revoked-by T1574.001 (sub-technique successor).
    - T1100 revoked-by T1200 revoked-by T1059 (two-step chain).
    - T1300 deprecated; T1301 revoked-by the deprecated T1300.
    - T1400 revoked with no successor.
    - Revoked T1562 carries STIX capec ref CAPEC-13; deprecated T1300 CAPEC-99.
    """
    raw = tmp_path / "raw"
    d = raw / "ATTCK-STIX"
    ap = "attack-pattern--"
    enterprise = [
        stix_tactic("x-mitre-tactic--e-exec", "TA0002", "execution"),
        stix_tactic("x-mitre-tactic--e-def", "TA0005", "defense-evasion"),
        stix_tactic("x-mitre-tactic--e-pers", "TA0003", "persistence"),
        stix_technique(ap + "t1059", "T1059", ["execution"]),
        stix_technique(ap + "t1685", "T1685", ["defense-evasion"]),
        stix_technique(ap + "t1574", "T1574", ["persistence", "defense-evasion"]),
        stix_technique(ap + "t1574-001", "T1574.001", ["persistence"], sub=True),
        stix_technique(ap + "t1562", "T1562", ["defense-evasion"], revoked=True, capec=["CAPEC-13"]),
        stix_technique(ap + "t1562-001", "T1562.001", ["defense-evasion"], sub=True, revoked=True),
        stix_technique(ap + "t1574-002", "T1574.002", ["persistence"], sub=True, revoked=True),
        stix_technique(ap + "t1100", "T1100", ["execution"], revoked=True),
        stix_technique(ap + "t1200", "T1200", ["execution"], revoked=True),
        stix_technique(ap + "t1300", "T1300", ["execution"], deprecated=True, capec=["CAPEC-99"]),
        stix_technique(ap + "t1301", "T1301", ["execution"], revoked=True),
        stix_technique(ap + "t1400", "T1400", ["execution"], revoked=True),
        stix_rel("subtechnique-of", ap + "t1574-001", ap + "t1574"),
        stix_rel("revoked-by", ap + "t1562", ap + "t1685"),
        stix_rel("revoked-by", ap + "t1562-001", ap + "t1685"),
        stix_rel("revoked-by", ap + "t1574-002", ap + "t1574-001"),
        stix_rel("revoked-by", ap + "t1100", ap + "t1200"),
        stix_rel("revoked-by", ap + "t1200", ap + "t1059"),
        stix_rel("revoked-by", ap + "t1301", ap + "t1300"),
    ]
    mobile = [
        stix_tactic("x-mitre-tactic--m-exec", "TA0041", "execution"),
        stix_technique(ap + "t1623", "T1623", ["execution"], kill_chain="mitre-mobile-attack"),
    ]
    ics = [
        stix_tactic("x-mitre-tactic--i-exec", "TA0104", "execution"),
        stix_technique(ap + "t0807", "T0807", ["execution"], kill_chain="mitre-ics-attack"),
    ]
    write_bundle(d, "enterprise-attack.json", enterprise)
    write_bundle(d, "mobile-attack.json", mobile)
    write_bundle(d, "ics-attack.json", ics)
    return raw
