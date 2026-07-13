"""
ETL loader for MITRE D3FEND defensive technique data.

Step 7 of the KGCS load order. Must run after load_attck (MITIGATED_BY
requires Technique/SubTechnique nodes).

Node types created:
  - DefensiveTechnique  (d3fendId unique key, e.g. "D3-TB")

Relationships created:
  - (Technique)-[:MITIGATED_BY]->(DefensiveTechnique)
  - (SubTechnique)-[:MITIGATED_BY]->(DefensiveTechnique)

Data sources (already downloaded):
  - data/raw/D3FEND/d3fend-full-mappings.json  (SPARQL result set)
  - data/raw/D3FEND/d3fend.json                (ontology export; used for ID lookup)

ID extraction:
  The SPARQL result provides URI values like
  "https://d3fend.mitre.org/ontologies/d3fend.owl#TokenBinding".
  The fragment ("TokenBinding") is extracted and looked up in a table
  built from d3fend.json (which contains d3fend-id property mappings).
  If no canonical ID is found, the fragment is used directly with a
  warning log.

MITIGATED_BY target:
  The off_tech_id field contains ATT&CK IDs (T####, T####.###).
  Both Technique and SubTechnique nodes are matched without label
  discrimination using MERGE on attackId.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .base import AbstractETL

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cypher statements
# ---------------------------------------------------------------------------

_CYPHER_DEFENSIVE_TECH = """\
UNWIND $batch AS row
MERGE (d:DefensiveTechnique {d3fendId: row.d3fendId})
ON CREATE SET
    d.name     = row.name,
    d.fragment = row.fragment
ON MATCH SET
    d.name = row.name
"""

_CYPHER_MITIGATED_BY = """\
UNWIND $batch AS row
OPTIONAL MATCH (tt:Technique {attackId: row.attackId})
OPTIONAL MATCH (ts:SubTechnique {attackId: row.attackId})
WITH row, coalesce(tt, ts) AS t
WHERE t IS NOT NULL
MATCH (d:DefensiveTechnique {d3fendId: row.d3fendId})
MERGE (t)-[:MITIGATED_BY]->(d)
"""


# ---------------------------------------------------------------------------
# D3FEND canonical ID lookup
# ---------------------------------------------------------------------------

def _build_d3fend_id_lookup(d3fend_json_path: Path) -> Dict[str, str]:
    """Build {uri_fragment: d3fendId} from d3fend.json.

    d3fend.json may be a JSON-LD export or a plain JSON ontology dump.
    We look for objects that have a 'd3fend-id' (or 'd3f:d3fend-id')
    property and a '@id' that contains a '#Fragment' or '/Fragment'.

    Returns an empty dict if the file cannot be parsed or has an
    unexpected schema (caller will fallback to using the fragment as-is).
    """
    lookup: Dict[str, str] = {}
    if not d3fend_json_path.exists():
        logger.warning(
            f"[D3FEND] d3fend.json not found at {d3fend_json_path} — "
            "falling back to URI fragment as d3fendId"
        )
        return lookup

    try:
        with open(d3fend_json_path, encoding="utf-8") as fh:
            data = json.load(fh)

        # Handle JSON-LD @graph array or flat list of objects
        objects = []
        if isinstance(data, dict):
            objects = data.get("@graph", [])
            if not objects:
                # Try top-level list of objects
                objects = [data]
        elif isinstance(data, list):
            objects = data

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            oid = obj.get("@id", "")
            # Extract fragment from IRI.
            # Handles full IRIs ("...d3fend.owl#TokenBinding"), path IRIs,
            # and compact JSON-LD prefixed ids ("d3f:TokenBinding") — the
            # format used by d3fend.json exports since 2026.
            fragment = ""
            if "#" in oid:
                fragment = oid.split("#")[-1]
            elif "/" in oid:
                fragment = oid.split("/")[-1]
            elif ":" in oid:
                fragment = oid.split(":")[-1]
            if not fragment:
                continue

            # Look for d3fend-id under various key formats
            d3fend_id = (
                obj.get("d3fend-id")
                or obj.get("d3f:d3fend-id")
                or (obj.get("d3f:d3fend-id", {}) or {}).get("@value")
                or None
            )
            if d3fend_id and isinstance(d3fend_id, str):
                lookup[fragment] = d3fend_id
            elif isinstance(d3fend_id, dict):
                val = d3fend_id.get("@value")
                if val:
                    lookup[fragment] = val

    except Exception as exc:
        logger.warning(f"[D3FEND] Could not parse d3fend.json: {exc}")

    return lookup


# ---------------------------------------------------------------------------
# Mappings extraction
# ---------------------------------------------------------------------------

def _extract_mappings(
    mappings_path: Path,
    id_lookup: Dict[str, str],
) -> Tuple[Dict[str, Dict], List[Dict], int]:
    """Parse d3fend-full-mappings.json SPARQL result.

    Returns:
      (defensive_tech_dict, mitigated_by_list, fallback_count)

      defensive_tech_dict: {d3fendId: {d3fendId, name, fragment}}
      mitigated_by_list:   [{attackId, d3fendId}]  (deduplicated)
      fallback_count:      how many entries used fragment fallback for ID
    """
    defensive_techs: Dict[str, Dict] = {}
    seen_pairs: Set[Tuple[str, str]] = set()
    mitigated_by: List[Dict] = []
    fallbacks = 0

    try:
        with open(mappings_path, encoding="utf-8") as fh:
            data = json.load(fh)

        bindings = data.get("results", {}).get("bindings", [])
        for binding in bindings:
            uri = binding.get("def_tech", {}).get("value", "")
            label = binding.get("def_tech_label", {}).get("value", "")
            attack_id = binding.get("off_tech_id", {}).get("value", "")

            if not uri or not attack_id:
                continue

            # Extract URI fragment
            fragment = ""
            if "#" in uri:
                fragment = uri.split("#")[-1]
            elif "/" in uri:
                fragment = uri.split("/")[-1]
            if not fragment:
                continue

            # Resolve d3fendId
            d3fend_id = id_lookup.get(fragment)
            if not d3fend_id:
                d3fend_id = fragment
                fallbacks += 1

            # Accumulate DefensiveTechnique node
            if d3fend_id not in defensive_techs:
                defensive_techs[d3fend_id] = {
                    "d3fendId": d3fend_id,
                    "name":     label,
                    "fragment": fragment,
                }

            # Deduplicate relationship pairs
            pair = (attack_id, d3fend_id)
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                mitigated_by.append({
                    "attackId":  attack_id,
                    "d3fendId":  d3fend_id,
                })

    except Exception as exc:
        logger.error(f"[D3FEND] Failed reading {mappings_path}: {exc}")

    return defensive_techs, mitigated_by, fallbacks


class D3FENDLoader(AbstractETL):
    """ETL loader for D3FEND DefensiveTechnique nodes and MITIGATED_BY edges."""

    @property
    def standard_name(self) -> str:
        return "D3FEND"

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
                "nodes_created":  0,
                "rels_created":   0,
                "id_fallbacks":   0,
            },
        }

        try:
            self.log_success("Starting D3FEND ETL")

            d3fend_dir  = self.raw_data_dir / "D3FEND"
            mappings_p  = d3fend_dir / "d3fend-full-mappings.json"
            ontology_p  = d3fend_dir / "d3fend.json"

            if not mappings_p.exists():
                self.log_error(f"d3fend-full-mappings.json not found: {mappings_p}")
                result["errors"].append(f"Missing: {mappings_p}")
                return result

            # Build canonical ID lookup from ontology
            id_lookup = _build_d3fend_id_lookup(ontology_p)
            self.log_success(
                f"ID lookup built: {len(id_lookup)} fragment→id mappings"
            )

            # Parse SPARQL mappings
            def_techs, mitigated_by, fallbacks = _extract_mappings(
                mappings_p, id_lookup
            )
            if fallbacks:
                self.log_warning(
                    f"{fallbacks} D3FEND entries used URI fragment as fallback ID"
                )

            errors: List[str] = []
            nodes_created = 0
            rels_created  = 0

            # Write DefensiveTechnique nodes
            node_recs = list(def_techs.values())
            if node_recs:
                r = self.writer.execute_batch(
                    _CYPHER_DEFENSIVE_TECH, node_recs, self.batch_size
                )
                nodes_created += r.get("nodes_created", 0)
                errors.extend(r.get("errors", []))
            self.log_success(f"DefensiveTechnique: {len(node_recs)} nodes written")

            # Write MITIGATED_BY relationships
            if mitigated_by:
                r = self.writer.execute_batch(
                    _CYPHER_MITIGATED_BY, mitigated_by, self.batch_size
                )
                rels_created += r.get("rels_created", 0)
                errors.extend(r.get("errors", []))
            self.log_success(
                f"MITIGATED_BY: {len(mitigated_by)} relationships written"
            )

            result["stats"]["nodes_created"] = nodes_created
            result["stats"]["rels_created"]  = rels_created
            result["stats"]["id_fallbacks"]  = fallbacks
            result["errors"]  = errors
            result["success"] = len(errors) == 0

            if result["success"]:
                self.log_success(f"Complete: {result['stats']}")
            else:
                self.log_error(f"Completed with {len(errors)} errors")

        except Exception as exc:
            self.log_error(f"Unhandled exception: {exc}")
            result["errors"].append(str(exc))

        return result
