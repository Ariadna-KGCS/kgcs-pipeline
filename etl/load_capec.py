"""
ETL loader for CAPEC (Common Attack Pattern Enumeration and Classification).

Step 5 of the KGCS load order. Must run after load_cwe (DEMONSTRATED_BY
requires Weakness nodes).

Node types created:
  - AttackPattern  (capecId unique key, e.g. "CAPEC-66")

Relationships created:
  - (Weakness)-[:DEMONSTRATED_BY]->(AttackPattern)
  - (AttackPattern)-[:CHILD_OF]->(AttackPattern)

Data source (already downloaded):
  - data/raw/CAPEC/capec_latest.xml

Deprecation policy:
  Deprecated AttackPattern nodes ARE loaded — real CVE records may still
  reference deprecated CAPEC IDs.  A `status` property records the value
  from the XML Status attribute so callers can filter in Cypher if needed.

SHACL invariant enforced here:
  SH-CORE-05: IMPLEMENTS source must be AttackPattern (loader creates the
  nodes on which load_attck.py will later hang IMPLEMENTS edges).

Write order: every AttackPattern node is written (streamed in batches)
before any DEMONSTRATED_BY / CHILD_OF edge. A CHILD_OF parent often comes
later in the XML than its child; writing edges with the child's batch lost
14 CHILD_OF edges on CAPEC 3.9 (519 instead of 533) and let a second run add
them. The edge lists are small (~1.7k rows) and are deduplicated before the
write.

IMPLEMENTS is written only by load_attck.py (spec 1.1.0 coverage matrix):
it needs the ATT&CK bundles for the revoked-by remap and the sub-technique
roll-up, and Technique nodes do not exist yet at this step.
"""

import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Generator, List, Tuple

from .base import AbstractETL

logger = logging.getLogger(__name__)

_CAPEC_NS = "http://capec.mitre.org/capec-3"

# ---------------------------------------------------------------------------
# Cypher statements
# ---------------------------------------------------------------------------

_CYPHER_ATTACK_PATTERN = """\
UNWIND $batch AS row
MERGE (ap:AttackPattern {capecId: row.capecId})
ON CREATE SET
    ap.name   = row.name,
    ap.status = row.status
ON MATCH SET
    ap.name   = row.name,
    ap.status = row.status
"""

_CYPHER_DEMONSTRATED_BY = """\
UNWIND $batch AS row
MATCH (w:Weakness {cweId: row.cweId})
MATCH (ap:AttackPattern {capecId: row.capecId})
MERGE (w)-[:DEMONSTRATED_BY]->(ap)
"""

_CYPHER_CHILD_OF = """\
UNWIND $batch AS row
MATCH (child:AttackPattern {capecId: row.childCapecId})
MATCH (parent:AttackPattern {capecId: row.parentCapecId})
MERGE (child)-[:CHILD_OF]->(parent)
"""


# ---------------------------------------------------------------------------
# XML extraction
# ---------------------------------------------------------------------------

def _iter_capec_records(
    xml_path: Path,
) -> Generator[Tuple[Dict, List[Dict], List[Dict]], None, None]:
    """Yield per-Attack_Pattern records for nodes plus CAPEC/CWE relationships.

    cwe_edge_dicts:        {cweId, capecId} for DEMONSTRATED_BY.
    child_of_dicts:        {childCapecId, parentCapecId} for CAPEC ChildOf hierarchy.
    """
    ap_tag  = f"{{{_CAPEC_NS}}}Attack_Pattern"
    rw_tag  = f"{{{_CAPEC_NS}}}Related_Weakness"
    rws_tag = f"{{{_CAPEC_NS}}}Related_Weaknesses"

    try:
        context = ET.iterparse(str(xml_path), events=("start", "end"))
        current_ap: Dict = {}
        in_ap = False

        for event, elem in context:
            if event == "start" and elem.tag == ap_tag:
                ap_id = elem.get("ID", "")
                if not ap_id:
                    continue
                current_ap = {
                    "capecId": f"CAPEC-{ap_id}",
                    "name":    elem.get("Name", ""),
                    "status":  elem.get("Status", ""),
                }
                in_ap = True

            elif event == "end" and elem.tag == ap_tag and in_ap:
                # Collect Related_Weaknesses
                edges: List[Dict] = []
                for rws in elem.iter(rws_tag):
                    for rw in rws.iter(rw_tag):
                        cwe_id_raw = rw.get("CWE_ID", "")
                        if cwe_id_raw:
                            edges.append({
                                "cweId":   f"CWE-{cwe_id_raw}",
                                "capecId": current_ap["capecId"],
                            })

                child_of: List[Dict] = []
                related_parent_tag = f"{{{_CAPEC_NS}}}Related_Attack_Pattern"
                related_patterns_tag = f"{{{_CAPEC_NS}}}Related_Attack_Patterns"
                for related_patterns in elem.iter(related_patterns_tag):
                    for related_pattern in related_patterns.iter(related_parent_tag):
                        if related_pattern.get("Nature") != "ChildOf":
                            continue
                        parent_capec = related_pattern.get("CAPEC_ID", "").strip()
                        if parent_capec:
                            child_of.append({
                                "childCapecId": current_ap["capecId"],
                                "parentCapecId": f"CAPEC-{parent_capec}",
                            })

                yield current_ap, edges, child_of
                elem.clear()
                in_ap = False
                current_ap = {}

    except Exception as exc:
        logger.error(f"[CAPEC] Failed parsing {xml_path}: {exc}")


class CAPECLoader(AbstractETL):
    """ETL loader for CAPEC AttackPattern nodes, DEMONSTRATED_BY and CHILD_OF edges."""

    @property
    def standard_name(self) -> str:
        return "CAPEC"

    def extract(self) -> Any:
        return None

    def transform(self, raw_data: Any) -> List[Dict]:
        return []

    def load_nodes(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    def load_relationships(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    def run(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "success": False,
            "errors":  [],
            "stats":   {
                "nodes_created": 0,
                "rels_created":  0,
                "demonstrated_by_created": 0,
                "child_of_created":        0,
                "deprecated":    0,
            },
        }

        try:
            self.log_success("Starting CAPEC ETL")

            xml_path = self.raw_data_dir / "CAPEC" / "capec_latest.xml"
            if not xml_path.exists():
                self.log_error(f"CAPEC XML not found: {xml_path}")
                result["errors"].append(f"Missing: {xml_path}")
                return result

            nodes_created = 0
            deprecated    = 0
            errors: List[str] = []

            ap_batch: List[Dict] = []
            # Edges wait until every AttackPattern node exists (see module
            # docstring); dict keys deduplicate and keep XML order.
            demonstrated_by: Dict[Tuple[str, str], None] = {}
            child_of_pairs: Dict[Tuple[str, str], None] = {}

            def _flush_nodes():
                nonlocal nodes_created
                if ap_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_ATTACK_PATTERN, ap_batch, self.batch_size
                    )
                    nodes_created += r.get("nodes_created", 0)
                    errors.extend(r.get("errors", []))
                    ap_batch.clear()

            for ap, edges, child_of in _iter_capec_records(xml_path):
                if ap.get("status") == "Deprecated":
                    deprecated += 1
                ap_batch.append(ap)
                for e in edges:
                    demonstrated_by[(e["cweId"], e["capecId"])] = None
                for c in child_of:
                    child_of_pairs[(c["childCapecId"], c["parentCapecId"])] = None
                if len(ap_batch) >= self.batch_size:
                    _flush_nodes()
            _flush_nodes()

            created: Dict[str, int] = {}
            for name, cypher, rows in (
                ("DEMONSTRATED_BY", _CYPHER_DEMONSTRATED_BY,
                 [{"cweId": w, "capecId": c} for w, c in demonstrated_by]),
                ("CHILD_OF", _CYPHER_CHILD_OF,
                 [{"childCapecId": ch, "parentCapecId": pa} for ch, pa in child_of_pairs]),
            ):
                created[name] = 0
                if rows:
                    r = self.writer.execute_batch(cypher, rows, self.batch_size)
                    created[name] = r.get("rels_created", 0)
                    errors.extend(r.get("errors", []))
            rels_created = sum(created.values())

            result["stats"]["nodes_created"] = nodes_created
            result["stats"]["rels_created"]  = rels_created
            result["stats"]["demonstrated_by_created"] = created["DEMONSTRATED_BY"]
            result["stats"]["child_of_created"]        = created["CHILD_OF"]
            result["stats"]["deprecated"]    = deprecated
            result["errors"]  = errors
            result["success"] = len(errors) == 0

            if result["success"]:
                self.log_success(
                    f"Complete: {nodes_created} AttackPattern nodes, "
                    f"{created['DEMONSTRATED_BY']} DEMONSTRATED_BY edges, "
                    f"{created['CHILD_OF']} CHILD_OF edges created "
                    f"({deprecated} deprecated nodes included)"
                )
            else:
                self.log_error(f"Completed with {len(errors)} errors")

        except Exception as exc:
            self.log_error(f"Unhandled exception: {exc}")
            result["errors"].append(str(exc))

        return result
