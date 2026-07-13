"""
ETL loader for CVSS (Common Vulnerability Scoring System) data.

Step 3 of the KGCS load order. Must run after load_cve (HAS_SCORE
targets Vulnerability nodes created there).

Node types created:
  - Score  (scoreId unique key: "{cveId}_{version}")

Relationships created:
  - (Vulnerability)-[:HAS_SCORE]->(Score)

Data sources (re-read from CVE directory):
  - data/raw/CVE/nvdcve-2.0-modified.json
  - data/raw/CVE/nvdcve-2.0-YYYY.json (2002–2025)

CVSS version handling:
  Each CVE may have metrics for multiple CVSS versions (2.0, 3.0, 3.1, 4.0).
  Each version produces a SEPARATE Score node — versions are NEVER merged.
  scoreId = "{cveId}_{version}" binds each node to exactly one version.

  When NVD provides multiple entries for the same version (e.g., two
  cvssMetricV31 objects), the "Primary" source entry is preferred;
  if no Primary exists the first entry is used.  This ensures the
  post-load check "no duplicate CVSS versions per CVE" passes.

SHACL enforced: Score.version in {2.0, 3.0, 3.1, 4.0}
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Generator, List

from .base import AbstractETL

logger = logging.getLogger(__name__)

# Metric key → CVSS version string (canonical, never normalised)
_METRIC_KEYS = {
    "cvssMetricV2":  "2.0",
    "cvssMetricV30": "3.0",
    "cvssMetricV31": "3.1",
    "cvssMetricV40": "4.0",
}

# ---------------------------------------------------------------------------
# Cypher statements
# ---------------------------------------------------------------------------

_CYPHER_SCORE = """\
UNWIND $batch AS row
MERGE (s:Score {scoreId: row.scoreId})
ON CREATE SET
    s.version      = row.version,
    s.baseScore    = row.baseScore,
    s.baseSeverity = row.baseSeverity,
    s.vectorString = row.vectorString,
    s.cveId        = row.cveId
"""

_CYPHER_HAS_SCORE = """\
UNWIND $batch AS row
MATCH (v:Vulnerability {cveId: row.cveId})
MATCH (s:Score {scoreId: row.scoreId})
MERGE (v)-[:HAS_SCORE]->(s)
"""


# ---------------------------------------------------------------------------
# File ordering (same as CVELoader)
# ---------------------------------------------------------------------------

def _ordered_cve_files(cve_dir: Path) -> List[Path]:
    modified = cve_dir / "nvdcve-2.0-modified.json"
    annual = sorted(cve_dir.glob("nvdcve-2.0-[0-9]*.json"), key=lambda p: p.name)
    files = []
    if modified.exists():
        files.append(modified)
    files.extend(annual)
    return files


# ---------------------------------------------------------------------------
# Record generator
# ---------------------------------------------------------------------------

def _iter_score_records(path: Path) -> Generator[Dict, None, None]:
    """Yield one Score dict per (CVE, version) from a CVE JSON file.

    Deduplication within a single CVE: for each metric key, prefer the
    entry with type=="Primary"; fall back to the first entry.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            metrics = cve.get("metrics", {})
            seen_versions: set = set()

            for metric_key, version_str in _METRIC_KEYS.items():
                entries = metrics.get(metric_key, [])
                if not entries:
                    continue

                # Prefer Primary; fall back to first
                entry = next(
                    (e for e in entries if e.get("type") == "Primary"),
                    entries[0],
                )
                cvss_data = entry.get("cvssData", {})
                version = cvss_data.get("version", version_str)

                # Guard against cross-contamination (shouldn't happen, but safe)
                if version in seen_versions:
                    continue
                seen_versions.add(version)

                score_id = f"{cve_id}_{version}"
                base_score = cvss_data.get("baseScore")
                if base_score is None:
                    continue

                yield {
                    "scoreId":      score_id,
                    "cveId":        cve_id,
                    "version":      version,
                    "baseScore":    float(base_score),
                    "baseSeverity": cvss_data.get("baseSeverity", ""),
                    "vectorString": cvss_data.get("vectorString", ""),
                }

    except Exception as exc:
        logger.error(f"[CVSS] Failed reading {path}: {exc}")


class CVSSLoader(AbstractETL):
    """ETL loader for CVSS Score nodes.

    Streams the same CVE JSON files used by CVELoader.
    Overrides run() for streaming.
    """

    @property
    def standard_name(self) -> str:
        return "CVSS"

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
                "nodes_created":   0,
                "rels_created":    0,
                "files_processed": 0,
            },
        }

        try:
            self.log_success("Starting CVSS ETL (streaming mode)")

            cve_dir = self.raw_data_dir / "CVE"
            files = _ordered_cve_files(cve_dir)
            if not files:
                self.log_warning(f"No CVE JSON files found in {cve_dir}")
                result["success"] = True
                return result

            total_nodes = 0
            total_rels  = 0
            errors: List[str] = []

            score_batch:  List[Dict] = []
            has_score_batch: List[Dict] = []

            def _flush():
                nonlocal total_nodes, total_rels
                if score_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_SCORE, score_batch, self.batch_size
                    )
                    total_nodes += r.get("nodes_created", 0)
                    errors.extend(r.get("errors", []))
                    score_batch.clear()
                if has_score_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_HAS_SCORE, has_score_batch, self.batch_size
                    )
                    total_rels += r.get("rels_created", 0)
                    errors.extend(r.get("errors", []))
                    has_score_batch.clear()

            for path in files:
                logger.debug(f"[CVSS] Processing {path.name}")
                for rec in _iter_score_records(path):
                    score_batch.append(rec)
                    has_score_batch.append({
                        "cveId":   rec["cveId"],
                        "scoreId": rec["scoreId"],
                    })
                    if (len(score_batch) >= self.batch_size
                            or len(has_score_batch) >= self.batch_size):
                        _flush()
                _flush()
                result["stats"]["files_processed"] += 1

            result["stats"]["nodes_created"] = total_nodes
            result["stats"]["rels_created"]  = total_rels
            result["errors"] = errors
            result["success"] = len(errors) == 0

            if result["success"]:
                self.log_success(f"Complete: {result['stats']}")
            else:
                self.log_error(f"Completed with {len(errors)} errors")

        except Exception as exc:
            self.log_error(f"Unhandled exception: {exc}")
            result["errors"].append(str(exc))

        return result
