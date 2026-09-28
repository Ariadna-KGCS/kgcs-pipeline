"""
ETL loader for CISA SSVC v2.0.3 decisions republished by NVD in
`metrics.ssvcV203[]` (spec 1.2.0, ADR-0003, mappings/ssvc-to-owl-v1.0.md).

Decision step, right after load_cvss: HAS_SSVC targets Vulnerability nodes.

Node types created:
  - SsvcDecision  (ssvcId unique key: "<cveId>::SSVC::<timestamp>")

Relationships created:
  - (Vulnerability)-[:HAS_SSVC]->(SsvcDecision)

Data sources (re-read, as load_cvss.py / load_cwe.py do):
  - data/raw/CVE/nvdcve-2.0-modified.json, then nvdcve-2.0-YYYY.json

Rules (ssvc-to-owl-v1.0.md, "Transformation Rules"):
  1. Only entries whose `source` is a declared ADP (the list load_cwe.py
     keeps equal to cve-to-owl-v1.0.md); sourceRole = "adp". Every other
     entry (CISA acting as CNA, CNA-role entries without timestamp) is
     dropped and counted per source.
  2. Key <cveId>::SSVC::<timestamp>, timestamp verbatim; exact duplicates
     collapse (deduplicated in Python across all files).
  3. Never overwritten: MERGE with ON CREATE SET only.
  4. The only edge is HAS_SSVC from the Vulnerability whose cveId equals
     ssvcData.id; an entry whose id differs from the owning CVE is dropped
     and counted. Entries whose CVE has no Vulnerability node are dropped.
  options[] is read by key, never by position; an entry lacking one of the
  three decision points is counted as malformed and dropped.
"""

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

from .base import AbstractETL
from .decision_common import existing_cve_ids
from .load_cvss import _ordered_cve_files
from .load_cwe import _DECLARED_ADP_SOURCES

logger = logging.getLogger(__name__)

_DECISION_POINTS = ("exploitation", "automatable", "technicalImpact")

_CYPHER_SSVC = """\
UNWIND $batch AS row
MATCH (v:Vulnerability {cveId: row.cveId})
MERGE (s:SsvcDecision {ssvcId: row.ssvcId})
ON CREATE SET
    s.cveId           = row.cveId,
    s.version         = row.version,
    s.timestamp       = row.timestamp,
    s.exploitation    = row.exploitation,
    s.automatable     = row.automatable,
    s.technicalImpact = row.technicalImpact,
    s.role            = row.role,
    s.source          = row.source,
    s.sourceRole      = row.sourceRole
MERGE (v)-[:HAS_SSVC]->(s)
"""


def ssvc_records(cve: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Counter]:
    """One NVD `cve` object -> (SsvcDecision dicts, drop counter). Pure.

    Drop counter keys: "source:<source>" for non-ADP entries,
    "no_timestamp", "id_mismatch", "malformed_options".
    Duplicates inside the record are NOT removed here (the caller dedups
    across files on ssvcId).
    """
    cve_id = cve.get("id", "")
    out: List[Dict[str, Any]] = []
    dropped: Counter = Counter()
    for entry in cve.get("metrics", {}).get("ssvcV203", []) or []:
        source = entry.get("source", "")
        data = entry.get("ssvcData") or {}
        if source not in _DECLARED_ADP_SOURCES:
            dropped[f"source:{source}"] += 1
            continue
        timestamp = data.get("timestamp")
        if not timestamp:
            dropped["no_timestamp"] += 1
            continue
        if data.get("id") != cve_id:
            dropped["id_mismatch"] += 1
            continue
        points: Dict[str, str] = {}
        for option in data.get("options") or []:
            points.update(option)
        if any(not points.get(p) for p in _DECISION_POINTS):
            dropped["malformed_options"] += 1
            continue
        out.append({
            "ssvcId":          f"{cve_id}::SSVC::{timestamp}",
            "cveId":           cve_id,
            "version":         data.get("version"),
            "timestamp":       timestamp,
            "exploitation":    points["exploitation"],
            "automatable":     points["automatable"],
            "technicalImpact": points["technicalImpact"],
            "role":            data.get("role"),
            "source":          source,
            "sourceRole":      "adp",
        })
    return out, dropped


def iter_ssvc_file(path: Path) -> Iterator[Tuple[List[Dict[str, Any]], Counter]]:
    """Per-CVE (records, drops) for one NVD file (one file in memory)."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        if cve.get("id") and cve.get("metrics", {}).get("ssvcV203"):
            yield ssvc_records(cve)


class SSVCLoader(AbstractETL):
    """SsvcDecision leaves from NVD `metrics.ssvcV203[]` (streaming by file)."""

    @property
    def standard_name(self) -> str:
        return "SSVC"

    def extract(self) -> Any:
        return None

    def transform(self, raw_data: Any) -> List[Dict]:
        return []

    def load_nodes(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    def load_relationships(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    def run(self) -> Dict[str, Any]:
        files = _ordered_cve_files(self.raw_data_dir / "CVE")
        if not files:
            return self._error_result(f"No CVE JSON files in {self.raw_data_dir / 'CVE'}")
        stats: Dict[str, Any] = {
            "nodes_created": 0, "rels_created": 0, "files_processed": 0,
            "adp_entries": 0, "duplicates_collapsed": 0, "loaded": 0,
            "dropped_no_vulnerability": 0,
        }
        drops: Counter = Counter()
        errors: List[str] = []
        seen: set = set()

        def flush(batch: List[Dict]) -> None:
            present = existing_cve_ids(self.writer, [r["cveId"] for r in batch])
            rows = [r for r in batch if r["cveId"] in present]
            stats["dropped_no_vulnerability"] += len(batch) - len(rows)
            stats["loaded"] += len(rows)
            r = self.writer.execute_batch(_CYPHER_SSVC, rows, self.batch_size)
            stats["nodes_created"] += r.get("nodes_created", 0)
            stats["rels_created"] += r.get("rels_created", 0)
            errors.extend(r.get("errors", []))

        try:
            for path in files:
                batch: List[Dict] = []
                for records, dropped in iter_ssvc_file(path):
                    drops.update(dropped)
                    for rec in records:
                        stats["adp_entries"] += 1
                        if rec["ssvcId"] in seen:
                            stats["duplicates_collapsed"] += 1
                            continue
                        seen.add(rec["ssvcId"])
                        batch.append(rec)
                        if len(batch) >= self.batch_size:
                            flush(batch)
                            batch = []
                if batch:
                    flush(batch)
                stats["files_processed"] += 1
                logger.debug(f"[SSVC] {path.name} done")
        except (OSError, ValueError) as exc:
            errors.append(f"SSVC read failed: {exc}")

        stats["distinct_decisions"] = len(seen)
        stats["dropped"] = dict(sorted(drops.items()))
        for key, n in sorted(drops.items()):
            self.log_warning(f"dropped {n} entries: {key}")
        result = {"success": not errors, "errors": errors, "stats": stats}
        if result["success"]:
            self.log_success(f"Complete: {stats}")
        else:
            self.log_error(f"Completed with {len(errors)} errors: {errors[:3]}")
        return result
