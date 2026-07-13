"""
ETL loader for MITRE CAR (Cyber Analytics Repository) data.

Step 8 of the KGCS load order. Must run after load_attck (DETECTED_BY
requires Technique/SubTechnique nodes).

Node types created:
  - DetectionAnalytic  (analyticId unique key, e.g. "CAR-2019-11-003")

Relationships created:
  - (Technique)-[:DETECTED_BY]->(DetectionAnalytic)
  - (SubTechnique)-[:DETECTED_BY]->(DetectionAnalytic)

Data sources (already downloaded):
  - data/raw/car/analytics/*.yaml

Coverage property:
  The DETECTED_BY relationship carries a `coverageLevel` property
  sourced from coverage[].coverage in the YAML (e.g. "Moderate").
  Technique and SubTechnique nodes are matched without label
  discrimination using attackId alone.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List

import yaml

from .base import AbstractETL

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cypher statements
# ---------------------------------------------------------------------------

_CYPHER_ANALYTIC = """\
UNWIND $batch AS row
MERGE (da:DetectionAnalytic {analyticId: row.analyticId})
ON CREATE SET
    da.title       = row.title,
    da.description = row.description,
    da.platform    = row.platform
ON MATCH SET
    da.title = row.title
"""

_CYPHER_DETECTED_BY = """\
UNWIND $batch AS row
OPTIONAL MATCH (tt:Technique {attackId: row.attackId})
OPTIONAL MATCH (ts:SubTechnique {attackId: row.attackId})
WITH row, coalesce(tt, ts) AS t
WHERE t IS NOT NULL
MATCH (da:DetectionAnalytic {analyticId: row.analyticId})
MERGE (t)-[r:DETECTED_BY]->(da)
SET r.coverageLevel = row.coverageLevel
"""


# ---------------------------------------------------------------------------
# YAML extraction
# ---------------------------------------------------------------------------

def _load_analytic(path: Path):
    """Load a single CAR analytic YAML file.

    Returns (analytic_dict, [detected_by_records]) or (None, []) on error.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            return None, []

        analytic_id = data.get("id", "")
        if not analytic_id:
            return None, []

        analytic = {
            "analyticId":  analytic_id,
            "title":       data.get("title", ""),
            "description": (data.get("description", "") or "")[:500],
            "platform":    ", ".join(data.get("platforms", [])),
        }

        rels: List[Dict] = []
        for cov in data.get("coverage", []):
            technique_id = cov.get("technique", "")
            coverage_level = cov.get("coverage", "")

            # Link the parent technique
            if technique_id:
                rels.append({
                    "attackId":     technique_id,
                    "analyticId":   analytic_id,
                    "coverageLevel": coverage_level,
                })

            # Link any listed sub-techniques
            for sub_id in cov.get("subtechniques", []):
                if sub_id:
                    rels.append({
                        "attackId":     sub_id,
                        "analyticId":   analytic_id,
                        "coverageLevel": coverage_level,
                    })

        return analytic, rels

    except Exception as exc:
        logger.error(f"[CAR] Failed reading {path}: {exc}")
        return None, []


class CARLoader(AbstractETL):
    """ETL loader for CAR DetectionAnalytic nodes and DETECTED_BY edges."""

    @property
    def standard_name(self) -> str:
        return "CAR"

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
                "files_loaded":  0,
            },
        }

        try:
            self.log_success("Starting CAR ETL")

            # CAR uses lowercase directory name
            car_dir = self.raw_data_dir / "car" / "analytics"
            if not car_dir.exists():
                # Fallback to uppercase
                car_dir = self.raw_data_dir / "CAR" / "analytics"
            if not car_dir.exists():
                self.log_error(f"CAR analytics directory not found under {self.raw_data_dir}")
                result["errors"].append("CAR analytics directory missing")
                return result

            yaml_files = sorted(car_dir.glob("*.yaml"))
            if not yaml_files:
                self.log_warning(f"No YAML files found in {car_dir}")
                result["success"] = True
                return result

            analytic_batch: List[Dict] = []
            rel_batch:      List[Dict] = []
            errors: List[str] = []
            nodes_created = 0
            rels_created  = 0

            def _flush():
                nonlocal nodes_created, rels_created
                if analytic_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_ANALYTIC, analytic_batch, self.batch_size
                    )
                    nodes_created += r.get("nodes_created", 0)
                    errors.extend(r.get("errors", []))
                    analytic_batch.clear()
                if rel_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_DETECTED_BY, rel_batch, self.batch_size
                    )
                    rels_created += r.get("rels_created", 0)
                    errors.extend(r.get("errors", []))
                    rel_batch.clear()

            for path in yaml_files:
                analytic, rels = _load_analytic(path)
                if analytic:
                    analytic_batch.append(analytic)
                    rel_batch.extend(rels)
                    result["stats"]["files_loaded"] += 1
                if (len(analytic_batch) >= self.batch_size
                        or len(rel_batch) >= self.batch_size):
                    _flush()
            _flush()

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
