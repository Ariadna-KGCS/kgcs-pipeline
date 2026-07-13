"""
ETL loader for MITRE SHIELD deception technique data.

Step 9 of the KGCS load order. Must run after load_attck (COUNTERED_BY
requires Technique/SubTechnique nodes).

Node types created:
  - DeceptionTechnique  (techniqueId unique key, e.g. "DTE0001")

Relationships created:
  - (Technique)-[:COUNTERED_BY]->(DeceptionTechnique)
  - (SubTechnique)-[:COUNTERED_BY]->(DeceptionTechnique)

Data sources (already downloaded):
  - data/raw/SHIELD/techniques.json      (DTE node definitions)
  - data/raw/SHIELD/attack_mapping.json  (SHIELD → ATT&CK mappings)

Schema probe:
  attack_mapping.json first key is checked to confirm it matches a
  T#### pattern before full processing begins. If the schema is
  unexpected, the loader aborts with a diagnostic error.

Expected attack_mapping.json structure (probe checks first key):
  {
    "T1001": [{"shield_techniques": [{"id": "DTE0015"}, ...]}],
    ...
  }
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from .base import AbstractETL

logger = logging.getLogger(__name__)

_TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

# ---------------------------------------------------------------------------
# Cypher statements
# ---------------------------------------------------------------------------

_CYPHER_DECEPTION_TECH = """\
UNWIND $batch AS row
MERGE (dt:DeceptionTechnique {techniqueId: row.techniqueId})
ON CREATE SET
    dt.name        = row.name,
    dt.description = row.description
ON MATCH SET
    dt.name = row.name
"""

_CYPHER_COUNTERED_BY = """\
UNWIND $batch AS row
OPTIONAL MATCH (tt:Technique {attackId: row.attackId})
OPTIONAL MATCH (ts:SubTechnique {attackId: row.attackId})
WITH row, coalesce(tt, ts) AS t
WHERE t IS NOT NULL
MATCH (dt:DeceptionTechnique {techniqueId: row.techniqueId})
MERGE (t)-[:COUNTERED_BY]->(dt)
"""


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _load_techniques(path: Path) -> Dict[str, Dict]:
    """Load DTE technique definitions; return {techniqueId: record}."""
    out: Dict[str, Dict] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        # techniques.json may be a list or dict keyed by ID
        items = raw if isinstance(raw, list) else raw.values()
        for item in items:
            if not isinstance(item, dict):
                continue
            tid = item.get("id", "")
            if not tid:
                continue
            out[tid] = {
                "techniqueId":  tid,
                "name":         item.get("name", ""),
                "description":  (item.get("description", "") or "")[:500],
            }
    except Exception as exc:
        logger.error(f"[SHIELD] Failed reading {path}: {exc}")
    return out


def _probe_and_load_mapping(
    path: Path,
) -> Tuple[bool, Dict[str, List[str]]]:
    """Load attack_mapping.json with schema probe.

    Actual format: a list of {attack_id, technique: {id: "DTE####", ...}} entries.
    Returns (schema_ok, {attackId: [techniqueId, ...]}).
    """
    try:
        with open(path, encoding="utf-8") as fh:
            mapping_raw = json.load(fh)

        if not isinstance(mapping_raw, list) or not mapping_raw:
            logger.error("[SHIELD] attack_mapping.json is not a non-empty list")
            return False, {}

        # Schema probe: first item must have 'attack_id' key matching T#### pattern
        first_item = mapping_raw[0]
        if not isinstance(first_item, dict) or "attack_id" not in first_item:
            logger.error("[SHIELD] attack_mapping.json first item missing 'attack_id'")
            return False, {}

        first_attack_id = first_item.get("attack_id", "")
        if not _TECHNIQUE_ID_PATTERN.match(first_attack_id):
            logger.error(
                f"[SHIELD] Unexpected attack_mapping.json schema — "
                f"first attack_id '{first_attack_id}' does not match T#### pattern"
            )
            return False, {}

        # Build {attackId: [dte_ids]} from flat list
        out: Dict[str, List[str]] = {}
        for item in mapping_raw:
            if not isinstance(item, dict):
                continue
            attack_id = item.get("attack_id", "")
            if not attack_id:
                continue
            technique = item.get("technique", {})
            dte_id = technique.get("id", "") if isinstance(technique, dict) else ""
            if dte_id:
                out.setdefault(attack_id, [])
                if dte_id not in out[attack_id]:
                    out[attack_id].append(dte_id)

        return True, out

    except Exception as exc:
        logger.error(f"[SHIELD] Failed loading attack_mapping.json: {exc}")
        return False, {}


class SHIELDLoader(AbstractETL):
    """ETL loader for SHIELD DeceptionTechnique nodes and COUNTERED_BY edges."""

    @property
    def standard_name(self) -> str:
        return "SHIELD"

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
            },
        }

        try:
            self.log_success("Starting SHIELD ETL")

            shield_dir   = self.raw_data_dir / "SHIELD"
            tech_path    = shield_dir / "techniques.json"
            mapping_path = shield_dir / "attack_mapping.json"

            for p in (tech_path, mapping_path):
                if not p.exists():
                    self.log_error(f"Missing: {p}")
                    result["errors"].append(f"Missing: {p}")
                    return result

            # Load DTE node definitions
            dte_nodes = _load_techniques(tech_path)
            if not dte_nodes:
                self.log_warning("No DTE node definitions found")

            # Schema probe + load mapping
            schema_ok, mapping = _probe_and_load_mapping(mapping_path)
            if not schema_ok:
                result["errors"].append(
                    "SHIELD attack_mapping.json schema is unexpected — aborting"
                )
                return result

            errors: List[str] = []
            nodes_created = 0
            rels_created  = 0

            # Write DeceptionTechnique nodes
            if dte_nodes:
                r = self.writer.execute_batch(
                    _CYPHER_DECEPTION_TECH,
                    list(dte_nodes.values()),
                    self.batch_size,
                )
                nodes_created += r.get("nodes_created", 0)
                errors.extend(r.get("errors", []))
            self.log_success(f"DeceptionTechnique: {len(dte_nodes)} nodes written")

            # Build and write COUNTERED_BY relationships
            seen: Set[Tuple[str, str]] = set()
            rel_recs: List[Dict] = []
            for attack_id, dte_ids in mapping.items():
                for dte_id in dte_ids:
                    pair = (attack_id, dte_id)
                    if pair not in seen:
                        seen.add(pair)
                        rel_recs.append({
                            "attackId":   attack_id,
                            "techniqueId": dte_id,
                        })

            if rel_recs:
                r = self.writer.execute_batch(
                    _CYPHER_COUNTERED_BY, rel_recs, self.batch_size
                )
                rels_created += r.get("rels_created", 0)
                errors.extend(r.get("errors", []))
            self.log_success(
                f"COUNTERED_BY: {len(rel_recs)} relationships written"
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
