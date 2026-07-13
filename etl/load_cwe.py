"""
ETL loader for CWE (Common Weakness Enumeration) data.

Step 4 of the KGCS load order. Must run after load_cve (CAUSED_BY
targets Vulnerability nodes created there).

Node types created:
  - Weakness  (cweId unique key, e.g. "CWE-79")

Relationships created:
  - (Vulnerability)-[:CAUSED_BY]->(Weakness)

Data sources (already downloaded):
  - data/raw/CWE/cwec_v*.xml        (Weakness node definitions; newest version wins)
  - data/raw/CVE/nvdcve-2.0-*.json  (re-read for weaknesses[] array)

XML streaming:
  iterparse() is used so the full 30 MB XML is never held in memory
  as a DOM tree.  Only Weakness element start events are captured.

CAUSED_BY coverage note:
  Many CVE records use NVD placeholder IDs ("NVD-CWE-Other",
  "NVD-CWE-noinfo") that do not map to real CWE nodes. These are
  skipped and counted in the stats dict.  The SHACL shape allows
  minCount 0 on CAUSED_BY, so this is expected and not an error.
"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Generator, List, Tuple

from .base import AbstractETL

logger = logging.getLogger(__name__)

_CWE_NS = "http://cwe.mitre.org/cwe-7"
_NVD_SKIP_PREFIXES = ("NVD-CWE-",)

# ---------------------------------------------------------------------------
# Cypher statements
# ---------------------------------------------------------------------------

_CYPHER_WEAKNESS = """\
UNWIND $batch AS row
MERGE (w:Weakness {cweId: row.cweId})
ON CREATE SET
    w.name        = row.name,
    w.abstraction = row.abstraction
"""

_CYPHER_CAUSED_BY = """\
UNWIND $batch AS row
MATCH (v:Vulnerability {cveId: row.cveId})
MATCH (w:Weakness {cweId: row.cweId})
MERGE (v)-[:CAUSED_BY]->(w)
"""


# ---------------------------------------------------------------------------
# XML extraction helpers
# ---------------------------------------------------------------------------

def _iter_weakness_nodes(xml_path: Path) -> Generator[Dict, None, None]:
    """Stream Weakness elements from the CWE XML using iterparse."""
    ns_weakness = f"{{{_CWE_NS}}}Weakness"
    try:
        context = ET.iterparse(str(xml_path), events=("start",))
        for event, elem in context:
            if elem.tag == ns_weakness:
                cwe_id_raw = elem.get("ID", "")
                if not cwe_id_raw:
                    continue
                yield {
                    "cweId":       f"CWE-{cwe_id_raw}",
                    "name":        elem.get("Name", ""),
                    "abstraction": elem.get("Abstraction", ""),
                }
                elem.clear()   # release memory
    except Exception as exc:
        logger.error(f"[CWE] Failed parsing {xml_path}: {exc}")


# ---------------------------------------------------------------------------
# CVE re-read for CAUSED_BY relationships
# ---------------------------------------------------------------------------

def _ordered_cve_files(cve_dir: Path) -> List[Path]:
    modified = cve_dir / "nvdcve-2.0-modified.json"
    annual = sorted(cve_dir.glob("nvdcve-2.0-[0-9]*.json"), key=lambda p: p.name)
    files = []
    if modified.exists():
        files.append(modified)
    files.extend(annual)
    return files


def _iter_caused_by_records(
    path: Path,
) -> Generator[tuple, None, None]:
    """Yield (cve_id, cwe_id) pairs from CVE weaknesses[].

    Also yields None for each skipped NVD placeholder so the caller can
    count them.  Signature: yields (cve_id, cwe_id) or (cve_id, None).
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            for weakness_block in cve.get("weaknesses", []):
                for desc in weakness_block.get("description", []):
                    raw_id = desc.get("value", "")
                    if not raw_id:
                        continue
                    if any(raw_id.startswith(p) for p in _NVD_SKIP_PREFIXES):
                        yield cve_id, None   # placeholder — skip
                    else:
                        yield cve_id, raw_id
    except Exception as exc:
        logger.error(f"[CWE] Failed reading {path}: {exc}")


class CWELoader(AbstractETL):
    """ETL loader for CWE Weakness nodes and CAUSED_BY relationships."""

    @property
    def standard_name(self) -> str:
        return "CWE"

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
                "nodes_created":        0,
                "rels_created":         0,
                "skipped_nvd_ids":      0,
                "skipped_unmapped_cwe": 0,
                "files_processed":      0,
            },
        }

        try:
            self.log_success("Starting CWE ETL")

            # --- Step 1: Weakness nodes from XML ---
            # The downloader keeps the upstream versioned filename
            # (cwec_v4.19.1.xml, cwec_v4.20.xml, ...), so glob and pick the
            # highest version numerically — lexicographic sort would rank
            # v4.9 above v4.10.
            cwe_dir = self.raw_data_dir / "CWE"

            def _cwe_version_key(p: Path) -> Tuple[int, ...]:
                m = re.search(r"cwec_v([\d.]+)\.xml$", p.name)
                if not m:
                    return (0,)
                return tuple(int(x) for x in m.group(1).split(".") if x.isdigit())

            candidates = sorted(cwe_dir.glob("cwec_v*.xml"), key=_cwe_version_key)
            if not candidates:
                self.log_error(f"CWE XML not found: no cwec_v*.xml in {cwe_dir}")
                result["errors"].append(f"Missing: cwec_v*.xml in {cwe_dir}")
                return result
            xml_path = candidates[-1]
            self.log_success(f"CWE XML selected: {xml_path.name}")

            nodes_created = 0
            errors: List[str] = []
            batch: List[Dict] = []
            loaded_cwe_ids: set = set()

            for rec in _iter_weakness_nodes(xml_path):
                loaded_cwe_ids.add(rec["cweId"])
                batch.append(rec)
                if len(batch) >= self.batch_size:
                    r = self.writer.execute_batch(
                        _CYPHER_WEAKNESS, batch, self.batch_size
                    )
                    nodes_created += r.get("nodes_created", 0)
                    errors.extend(r.get("errors", []))
                    batch = []
            if batch:
                r = self.writer.execute_batch(
                    _CYPHER_WEAKNESS, batch, self.batch_size
                )
                nodes_created += r.get("nodes_created", 0)
                errors.extend(r.get("errors", []))
                batch = []

            result["stats"]["nodes_created"] = nodes_created
            self.log_success(f"Weakness nodes: {nodes_created} created")

            # --- Step 2: CAUSED_BY relationships from CVE JSON ---
            cve_dir = self.raw_data_dir / "CVE"
            cve_files = _ordered_cve_files(cve_dir)
            if not cve_files:
                self.log_warning("No CVE files found — skipping CAUSED_BY load")
                result["success"] = len(errors) == 0
                result["errors"] = errors
                return result

            rels_created = 0
            skipped = 0
            skipped_unmapped = 0
            unmapped_ids: set = set()
            rel_batch: List[Dict] = []

            n_files = len(cve_files)
            for file_idx, path in enumerate(cve_files, 1):
                logger.info(
                    f"[CWE] Reading weaknesses from {path.name} "
                    f"({file_idx}/{n_files}, {file_idx * 100 // n_files}%)"
                )
                for cve_id, cwe_id in _iter_caused_by_records(path):
                    if cwe_id is None:
                        skipped += 1
                        continue
                    if cwe_id not in loaded_cwe_ids:
                        # Real CWE id, but not a Weakness in this XML release
                        # (typically a Category or View NVD still maps to on
                        # legacy CVEs, e.g. CWE-16, CWE-19, CWE-254). The
                        # MATCH would drop it silently; count it instead.
                        skipped_unmapped += 1
                        unmapped_ids.add(cwe_id)
                        continue
                    rel_batch.append({"cveId": cve_id, "cweId": cwe_id})
                    if len(rel_batch) >= self.batch_size:
                        r = self.writer.execute_batch(
                            _CYPHER_CAUSED_BY, rel_batch, self.batch_size
                        )
                        rels_created += r.get("rels_created", 0)
                        errors.extend(r.get("errors", []))
                        rel_batch = []
                if rel_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_CAUSED_BY, rel_batch, self.batch_size
                    )
                    rels_created += r.get("rels_created", 0)
                    errors.extend(r.get("errors", []))
                    rel_batch = []
                result["stats"]["files_processed"] += 1

            result["stats"]["rels_created"]         = rels_created
            result["stats"]["skipped_nvd_ids"]      = skipped
            result["stats"]["skipped_unmapped_cwe"] = skipped_unmapped
            result["errors"]  = errors
            result["success"] = len(errors) == 0

            self.log_success(
                f"CAUSED_BY: {rels_created} created, "
                f"{skipped} NVD placeholders skipped, "
                f"{skipped_unmapped} unmapped CWE refs skipped"
            )
            if skipped_unmapped:
                self.log_warning(
                    f"{skipped_unmapped} CAUSED_BY pairs reference "
                    f"{len(unmapped_ids)} CWE ids absent from {xml_path.name} "
                    f"(Categories/Views): "
                    f"{', '.join(sorted(unmapped_ids, key=lambda x: int(x.split('-')[1]))[:10])}"
                    f"{' ...' if len(unmapped_ids) > 10 else ''}"
                )
            if result["success"]:
                self.log_success(f"Complete: {result['stats']}")
            else:
                self.log_error(f"Completed with {len(errors)} errors")

        except Exception as exc:
            self.log_error(f"Unhandled exception: {exc}")
            result["errors"].append(str(exc))

        return result
