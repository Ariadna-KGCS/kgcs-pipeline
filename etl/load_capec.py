"""
ETL loader for CAPEC (Common Attack Pattern Enumeration and Classification).

Step 5 of the KGCS load order. Must run after load_cwe (DEMONSTRATED_BY
requires Weakness nodes).

Node types created:
  - AttackPattern  (capecId unique key, e.g. "CAPEC-66")
  - Consequence    (consequenceId unique key, e.g. "CAPEC-66-C1"; ADR-0001)

Relationships created:
  - (Weakness)-[:DEMONSTRATED_BY]->(AttackPattern)
  - (AttackPattern)-[:CHILD_OF]->(AttackPattern)
  - (AttackPattern)-[:HAS_CONSEQUENCE]->(Consequence)

Data source (already downloaded):
  - data/raw/CAPEC/capec_latest.xml

Deprecation policy:
  Deprecated AttackPattern nodes ARE loaded — real CVE records may still
  reference deprecated CAPEC IDs.  A `status` property records the value
  from the XML Status attribute so callers can filter in Cypher if needed.

AttackPattern properties (frozen capec-ontology-v1.0.owl terms):
  name, status, abstraction (@Abstraction), attackLikelihood
  (Likelihood_Of_Attack), typicalSeverity (Typical_Severity). Values are
  the verbatim XSD enum strings ("Very High", not the OWL comment's
  "veryHigh"); an absent element is sent as null, which removes the
  property on refresh.

Consequence sub-nodes (ADR-0001, consequences-to-owl-v1.0.md):
  one node per Consequences/Consequence record, key <capecId>-C<ordinal>;
  scopes / impacts grouped per record, impacts optional (CAPEC XSD
  minOccurs=0). CAPEC's own 10-value impact vocabulary, never merged with
  CWE's. Stale ordinals beyond a pattern's current record count are pruned.

SHACL invariant enforced here:
  SH-CORE-05: IMPLEMENTS source must be AttackPattern (loader creates the
  nodes on which load_attck.py will later hang IMPLEMENTS edges).

Write order: every AttackPattern node is written (streamed in batches)
before any DEMONSTRATED_BY / CHILD_OF / HAS_CONSEQUENCE edge. A CHILD_OF parent often comes
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
from .consequences import CAPEC_IMPACTS, consequence_records, out_of_vocabulary

logger = logging.getLogger(__name__)

_CAPEC_NS = "http://capec.mitre.org/capec-3"

# ---------------------------------------------------------------------------
# Cypher statements
# ---------------------------------------------------------------------------

_CYPHER_ATTACK_PATTERN = """\
UNWIND $batch AS row
MERGE (ap:AttackPattern {capecId: row.capecId})
SET ap.name             = row.name,
    ap.status           = row.status,
    ap.abstraction      = row.abstraction,
    ap.attackLikelihood = row.attackLikelihood,
    ap.typicalSeverity  = row.typicalSeverity
"""

_CYPHER_CONSEQUENCE = """\
UNWIND $batch AS row
MATCH (ap:AttackPattern {capecId: row.parentId})
MERGE (c:Consequence {consequenceId: row.consequenceId})
SET c.scopes     = row.scopes,
    c.impacts    = row.impacts,
    c.likelihood = row.likelihood,
    c.note       = row.note
MERGE (ap)-[:HAS_CONSEQUENCE]->(c)
"""

# Rows: {parentId, count} for every AttackPattern (count 0 prunes all).
_CYPHER_PRUNE_CONSEQUENCES = """\
UNWIND $batch AS row
MATCH (:AttackPattern {capecId: row.parentId})-[:HAS_CONSEQUENCE]->(c:Consequence)
WHERE c.consequenceId STARTS WITH row.parentId + '-C'
  AND toInteger(split(c.consequenceId, '-C')[-1]) > row.count
DETACH DELETE c
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
) -> Generator[Tuple[Dict, List[Dict], List[Dict], List[Dict]], None, None]:
    """Yield per-Attack_Pattern records for nodes plus CAPEC/CWE relationships.

    cwe_edge_dicts:        {cweId, capecId} for DEMONSTRATED_BY.
    child_of_dicts:        {childCapecId, parentCapecId} for CAPEC ChildOf hierarchy.
    consequence_dicts:     Consequence sub-node rows (ADR-0001), document order.
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
                    "capecId":     f"CAPEC-{ap_id}",
                    "name":        elem.get("Name", ""),
                    "status":      elem.get("Status", ""),
                    "abstraction": elem.get("Abstraction") or None,
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

                ns = f"{{{_CAPEC_NS}}}"
                current_ap["attackLikelihood"] = (
                    (elem.findtext(f"{ns}Likelihood_Of_Attack") or "").strip() or None
                )
                current_ap["typicalSeverity"] = (
                    (elem.findtext(f"{ns}Typical_Severity") or "").strip() or None
                )
                consequences = consequence_records(
                    current_ap["capecId"],
                    elem.findall(f"{ns}Consequences/{ns}Consequence"),
                    ns,
                )

                yield current_ap, edges, child_of, consequences
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
                "has_consequence_created": 0,
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
            consequence_rows: List[Dict] = []
            prune_rows: List[Dict] = []

            def _flush_nodes():
                nonlocal nodes_created
                if ap_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_ATTACK_PATTERN, ap_batch, self.batch_size
                    )
                    nodes_created += r.get("nodes_created", 0)
                    errors.extend(r.get("errors", []))
                    ap_batch.clear()

            for ap, edges, child_of, consequences in _iter_capec_records(xml_path):
                if ap.get("status") == "Deprecated":
                    deprecated += 1
                ap_batch.append(ap)
                for e in edges:
                    demonstrated_by[(e["cweId"], e["capecId"])] = None
                for c in child_of:
                    child_of_pairs[(c["childCapecId"], c["parentCapecId"])] = None
                consequence_rows.extend(consequences)
                prune_rows.append({"parentId": ap["capecId"], "count": len(consequences)})
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

            # Consequence sub-nodes, then prune ordinals MITRE removed.
            bad = out_of_vocabulary(consequence_rows, CAPEC_IMPACTS)
            if bad:
                self.log_warning(
                    f"{len(bad)} consequence values outside the CAPEC vocabularies "
                    f"(loaded verbatim, SHACL flags them): {'; '.join(bad[:10])}"
                )
            r = self.writer.execute_batch(
                _CYPHER_CONSEQUENCE, consequence_rows, self.batch_size
            )
            created["HAS_CONSEQUENCE"] = r.get("rels_created", 0)
            consequence_nodes_created = r.get("nodes_created", 0)
            errors.extend(r.get("errors", []))
            r = self.writer.execute_batch(
                _CYPHER_PRUNE_CONSEQUENCES, prune_rows, self.batch_size
            )
            consequence_nodes_pruned = r.get("nodes_deleted", 0)
            errors.extend(r.get("errors", []))

            rels_created = sum(created.values())

            result["stats"]["nodes_created"] = nodes_created
            result["stats"]["rels_created"]  = rels_created
            result["stats"]["demonstrated_by_created"] = created["DEMONSTRATED_BY"]
            result["stats"]["child_of_created"]        = created["CHILD_OF"]
            result["stats"]["has_consequence_created"] = created["HAS_CONSEQUENCE"]
            result["stats"]["consequence_records"]           = len(consequence_rows)
            result["stats"]["consequence_nodes_created"]     = consequence_nodes_created
            result["stats"]["consequence_nodes_pruned"]      = consequence_nodes_pruned
            result["stats"]["consequence_out_of_vocabulary"] = len(bad)
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
                self.log_success(
                    f"Consequence: {len(consequence_rows)} records written "
                    f"({consequence_nodes_created} nodes, "
                    f"{created['HAS_CONSEQUENCE']} HAS_CONSEQUENCE created, "
                    f"{consequence_nodes_pruned} stale nodes pruned)"
                )
            else:
                self.log_error(f"Completed with {len(errors)} errors")

        except Exception as exc:
            self.log_error(f"Unhandled exception: {exc}")
            result["errors"].append(str(exc))

        return result
