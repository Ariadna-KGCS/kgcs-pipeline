"""
ETL loader for MITRE ENGAGE engagement concept data.

Step 10 of the KGCS load order. Must run after load_attck (DISRUPTS
requires Technique nodes).

Node types created:
  - EngagementConcept  (activityId OR approachId OR goalId, from three source files)

Relationships created:
  - (EngagementConcept {activityId: "EAC####"})-[:DISRUPTS]->(Technique)

Data sources (already downloaded):
  - data/raw/ENGAGE/activities.json    (EAC/SAC concepts)
  - data/raw/ENGAGE/approaches.json   (EAP/SAP concepts)
  - data/raw/ENGAGE/goals.json        (EGO/SGO concepts)
  - data/raw/ENGAGE/attack_mapping.json

DISRUPTS restriction:
  Only activity nodes with an EAC-prefixed ID create DISRUPTS edges.
  SAC (strategic activities), EAP/SAP (approaches), and EGO/SGO (goals)
  are loaded as EngagementConcept nodes but do NOT create DISRUPTS edges.

Schema probe:
  attack_mapping.json top-level keys are verified to match T#### pattern
  before processing begins. Unexpected schema → abort with diagnostic.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .base import AbstractETL

logger = logging.getLogger(__name__)

_TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

# ---------------------------------------------------------------------------
# Cypher statements
# ---------------------------------------------------------------------------

_CYPHER_ACTIVITY = """\
UNWIND $batch AS row
MERGE (ec:EngagementConcept {activityId: row.activityId})
ON CREATE SET
    ec.name        = row.name,
    ec.description = row.description
ON MATCH SET
    ec.name = row.name
"""

_CYPHER_APPROACH = """\
UNWIND $batch AS row
MERGE (ec:EngagementConcept {approachId: row.approachId})
ON CREATE SET
    ec.name        = row.name,
    ec.description = row.description
ON MATCH SET
    ec.name = row.name
"""

_CYPHER_GOAL = """\
UNWIND $batch AS row
MERGE (ec:EngagementConcept {goalId: row.goalId})
ON CREATE SET
    ec.name        = row.name,
    ec.description = row.description
ON MATCH SET
    ec.name = row.name
"""

_CYPHER_DISRUPTS = """\
UNWIND $batch AS row
MATCH (ec:EngagementConcept {activityId: row.activityId})
OPTIONAL MATCH (tt:Technique {attackId: row.attackId})
OPTIONAL MATCH (ts:SubTechnique {attackId: row.attackId})
WITH row, ec, coalesce(tt, ts) AS t
WHERE t IS NOT NULL
MERGE (ec)-[:DISRUPTS]->(t)
"""


# ---------------------------------------------------------------------------
# Generic concept loader
# ---------------------------------------------------------------------------

def _load_concepts(
    path: Path,
    id_field: str,
    id_prefix: Optional[str] = None,
) -> List[Dict]:
    """Load EngagementConcept records from a JSON source file.

    Args:
        path:      JSON file path.
        id_field:  Neo4j property name to use (activityId, approachId, goalId).
        id_prefix: If given, only include entries whose id starts with this.

    The file is expected to be a list of objects with at least 'id' and 'name'.
    Alternative: an object with a top-level list value (probed automatically).
    """
    out: List[Dict] = []
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)

        # Normalise to a list
        items: list = []
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            # Try top-level list key (e.g. {"activities": [...]})
            for v in raw.values():
                if isinstance(v, list):
                    items = v
                    break
            if not items:
                items = [raw]

        for item in items:
            if not isinstance(item, dict):
                continue
            concept_id = item.get("id", "")
            if not concept_id:
                continue
            if id_prefix and not concept_id.startswith(id_prefix):
                continue
            out.append({
                id_field:      concept_id,
                "name":        item.get("name", ""),
                "description": (item.get("description", "") or "")[:500],
            })
    except Exception as exc:
        logger.error(f"[ENGAGE] Failed loading {path}: {exc}")
    return out


def _probe_and_load_attack_mapping(path: Path) -> Tuple[bool, Dict[str, List[str]]]:
    """Load attack_mapping.json with schema probe.

    Actual format: a list of {attack_id, eac_id, ...} entries.
    Returns (schema_ok, {attackId: [activityId, ...]}).
    """
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)

        if not isinstance(raw, list) or not raw:
            logger.error("[ENGAGE] attack_mapping.json is not a non-empty list")
            return False, {}

        # Schema probe: first item must have 'attack_id' key matching T#### pattern
        first_item = raw[0]
        if not isinstance(first_item, dict) or "attack_id" not in first_item:
            logger.error("[ENGAGE] attack_mapping.json first item missing 'attack_id'")
            return False, {}

        first_attack_id = first_item.get("attack_id", "")
        if not _TECHNIQUE_ID_PATTERN.match(first_attack_id):
            logger.error(
                f"[ENGAGE] Unexpected attack_mapping.json schema — "
                f"first attack_id '{first_attack_id}' does not match T#### pattern"
            )
            return False, {}

        # Build {attackId: [eac_id, ...]} from flat list
        out: Dict[str, List[str]] = {}
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            attack_id = entry.get("attack_id", "")
            eac_id = entry.get("eac_id", "")
            if attack_id and eac_id:
                out.setdefault(attack_id, [])
                if eac_id not in out[attack_id]:
                    out[attack_id].append(eac_id)

        return True, out

    except Exception as exc:
        logger.error(f"[ENGAGE] Failed loading attack_mapping.json: {exc}")
        return False, {}


class ENGAGELoader(AbstractETL):
    """ETL loader for MITRE ENGAGE EngagementConcept nodes and DISRUPTS edges."""

    @property
    def standard_name(self) -> str:
        return "ENGAGE"

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
                "activities":    0,
                "approaches":    0,
                "goals":         0,
            },
        }

        try:
            self.log_success("Starting ENGAGE ETL")

            engage_dir   = self.raw_data_dir / "ENGAGE"
            activities_p = engage_dir / "activities.json"
            approaches_p = engage_dir / "approaches.json"
            goals_p      = engage_dir / "goals.json"
            mapping_p    = engage_dir / "attack_mapping.json"

            for p in (activities_p, approaches_p, goals_p, mapping_p):
                if not p.exists():
                    self.log_error(f"Missing: {p}")
                    result["errors"].append(f"Missing: {p}")
                    return result

            # Probe + load attack mapping first
            schema_ok, attack_mapping = _probe_and_load_attack_mapping(mapping_p)
            if not schema_ok:
                result["errors"].append(
                    "ENGAGE attack_mapping.json schema unexpected — aborting"
                )
                return result

            # Load all three concept types
            activities = _load_concepts(activities_p, "activityId")
            approaches = _load_concepts(approaches_p, "approachId")
            goals      = _load_concepts(goals_p,      "goalId")

            errors: List[str] = []
            nodes_created = 0
            rels_created  = 0

            # Write Activities
            if activities:
                r = self.writer.execute_batch(
                    _CYPHER_ACTIVITY, activities, self.batch_size
                )
                nodes_created += r.get("nodes_created", 0)
                errors.extend(r.get("errors", []))
            result["stats"]["activities"] = len(activities)

            # Write Approaches
            if approaches:
                r = self.writer.execute_batch(
                    _CYPHER_APPROACH, approaches, self.batch_size
                )
                nodes_created += r.get("nodes_created", 0)
                errors.extend(r.get("errors", []))
            result["stats"]["approaches"] = len(approaches)

            # Write Goals
            if goals:
                r = self.writer.execute_batch(
                    _CYPHER_GOAL, goals, self.batch_size
                )
                nodes_created += r.get("nodes_created", 0)
                errors.extend(r.get("errors", []))
            result["stats"]["goals"] = len(goals)

            self.log_success(
                f"EngagementConcept nodes: {len(activities)} activities, "
                f"{len(approaches)} approaches, {len(goals)} goals"
            )

            # Build DISRUPTS edges — only EAC-prefixed activities
            # Build lookup: activityId → True for EAC activities
            eac_ids: Set[str] = {
                a["activityId"]
                for a in activities
                if a["activityId"].startswith("EAC")
            }

            seen_pairs: Set[Tuple[str, str]] = set()
            disrupts_recs: List[Dict] = []
            for attack_id, activity_ids in attack_mapping.items():
                for act_id in activity_ids:
                    if act_id not in eac_ids:
                        continue  # SAC/SAP/SGO — no DISRUPTS edge
                    pair = (act_id, attack_id)
                    if pair not in seen_pairs:
                        seen_pairs.add(pair)
                        disrupts_recs.append({
                            "activityId": act_id,
                            "attackId":   attack_id,
                        })

            if disrupts_recs:
                r = self.writer.execute_batch(
                    _CYPHER_DISRUPTS, disrupts_recs, self.batch_size
                )
                rels_created += r.get("rels_created", 0)
                errors.extend(r.get("errors", []))

            self.log_success(
                f"DISRUPTS: {len(disrupts_recs)} relationships written "
                f"({len(eac_ids)} EAC activities → ATT&CK techniques)"
            )

            result["stats"]["nodes_created"] = nodes_created
            result["stats"]["rels_created"]  = rels_created
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
