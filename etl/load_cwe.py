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

CAUSED_BY provenance (spec 1.1.0, ADR-0002, cve-to-owl-v1.0.md v1.1):
  Exactly one edge per (CVE, CWE) pair, carrying three index-aligned
  string lists, one entry per weaknesses[] entry that names that CWE, in
  document order, exact (source, type) duplicates collapsed:
    sources      raw weaknesses[].source
    sourceRoles  nvd (nvd@nist.gov) | adp (declared ADP list) | cna
    types        Primary | Secondary
  The lists are aggregated per CVE in Python, then the edge is MERGEd on
  its endpoints and the lists are SET (replaced, never appended), so
  re-runs stay idempotent.

  A CVE can have more than one record (nvdcve-2.0-modified.json and its
  per-year file). The record with the greatest cve.lastModified supplies
  the lists of every pair it names (see _NewestRecordRule). The edge set
  stays the union of all records, as in v1.0; pairs named only by an older
  record keep their edge with that record's lists and are counted
  ("pairs_only_in_older", 0 on the 2026-09-06 data).
"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional, Set, Tuple

from .base import AbstractETL

logger = logging.getLogger(__name__)

_CWE_NS = "http://cwe.mitre.org/cwe-7"
_NVD_SKIP_PREFIXES = ("NVD-CWE-",)

# sourceRoles vocabulary (ADR-0002). The declared ADP list lives in the spec
# (mappings/cve-to-owl-v1.0.md, "Declared ADP identifiers"); keep this set
# equal to it (tests/test_load_cwe.py checks it against the pinned spec).
_NVD_SOURCE = "nvd@nist.gov"
_DECLARED_ADP_SOURCES = frozenset({
    "134c704f-9b21-4f2e-91b3-4a467353bcc0",   # CISA ADP
})

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
MERGE (v)-[r:CAUSED_BY]->(w)
SET r.sources     = row.sources,
    r.sourceRoles = row.sourceRoles,
    r.types       = row.types
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


def _source_role(source: str) -> str:
    """Map a raw weaknesses[].source to its ADR-0002 role."""
    if source == _NVD_SOURCE:
        return "nvd"
    if source in _DECLARED_ADP_SOURCES:
        return "adp"
    return "cna"


def _weakness_entries(cve: Dict) -> List[Tuple[str, str, str]]:
    """Return (cwe value, source, type) per weaknesses[] description, document order."""
    entries: List[Tuple[str, str, str]] = []
    for weakness_block in cve.get("weaknesses", []):
        source = weakness_block.get("source", "")
        wtype = weakness_block.get("type", "")
        for desc in weakness_block.get("description", []):
            raw_id = desc.get("value", "")
            if raw_id:
                entries.append((raw_id, source, wtype))
    return entries


def _iter_cve_weaknesses(
    path: Path,
) -> Generator[Tuple[str, str, List[Tuple[str, str, str]]], None, None]:
    """Yield (cve_id, lastModified, weakness entries) per CVE record of one NVD JSON file."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if cve_id:
                yield cve_id, cve.get("lastModified", ""), _weakness_entries(cve)
    except Exception as exc:
        logger.error(f"[CWE] Failed reading {path}: {exc}")


class _NewestRecordRule:
    """Decide which CAUSED_BY records of a CVE record to write.

    The modified feed is read first and its records are remembered (a few
    thousand CVEs). When a later file carries another record of the same
    CVE, the record with the greater lastModified supplies the lists:

      - later record newer: all its pairs are written (the SET replaces the
        lists written from the older record);
      - later record older or equally new: only its pairs that the
        remembered record does not name are written.

    Either way the edge set is the union of both records. Counters:
      superseded          pairs named by both records (the older record's
                          lists are not kept);
      pairs_only_in_older pairs named only by the older record (edge kept
                          with the older record's lists).
    """

    def __init__(self) -> None:
        self._remembered: Dict[str, Tuple[str, Set[str]]] = {}
        self.superseded = 0
        self.pairs_only_in_older = 0

    def remember(self, cve_id: str, last_modified: str, records: List[Dict]) -> List[Dict]:
        """Register a modified-feed record; all its records are written."""
        self._remembered[cve_id] = (last_modified, {r["cweId"] for r in records})
        return records

    def admit(self, cve_id: str, last_modified: str, records: List[Dict]) -> List[Dict]:
        """Filter a later file's records for a CVE against the remembered record."""
        prev = self._remembered.get(cve_id)
        if prev is None:
            return records
        prev_modified, prev_cwes = prev
        cwes = {r["cweId"] for r in records}
        self.superseded += len(cwes & prev_cwes)
        if last_modified > prev_modified:
            self.pairs_only_in_older += len(prev_cwes - cwes)
            return records
        self.pairs_only_in_older += len(cwes - prev_cwes)
        return [r for r in records if r["cweId"] not in prev_cwes]


def _aggregate_caused_by(
    cve_id: str,
    entries: Iterable[Tuple[str, str, str]],
    loaded_cwe_ids: Set[str],
) -> Tuple[List[Dict], int, List[str]]:
    """Aggregate one CVE's weakness entries into CAUSED_BY edge records.

    Returns (records, placeholder entries skipped, unmapped CWE ids skipped
    — one per entry). Records are one per kept CWE, first-seen order, with
    index-aligned sources / sourceRoles / types lists; exact (source, type)
    duplicates collapse, so a source that gives the same CWE as Primary and
    Secondary keeps two entries.
    """
    by_cwe: Dict[str, List[Tuple[str, str]]] = {}
    placeholders = 0
    unmapped: List[str] = []
    for cwe_id, source, wtype in entries:
        if any(cwe_id.startswith(p) for p in _NVD_SKIP_PREFIXES):
            placeholders += 1
            continue
        if cwe_id not in loaded_cwe_ids:
            # Real CWE id, but not a Weakness in this XML release
            # (typically a Category or View NVD still maps to on legacy
            # CVEs, e.g. CWE-16, CWE-19, CWE-254).
            unmapped.append(cwe_id)
            continue
        assignments = by_cwe.setdefault(cwe_id, [])
        if (source, wtype) not in assignments:
            assignments.append((source, wtype))

    records = [
        {
            "cveId":       cve_id,
            "cweId":       cwe_id,
            "sources":     [src for src, _ in assignments],
            "sourceRoles": [_source_role(src) for src, _ in assignments],
            "types":       [wtype for _, wtype in assignments],
        }
        for cwe_id, assignments in by_cwe.items()
    ]
    return records, placeholders, unmapped



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
            edges_written = 0
            skipped = 0
            skipped_unmapped = 0
            unmapped_ids: set = set()
            rel_batch: List[Dict] = []
            # Which record of a CVE supplies the provenance lists
            newest = _NewestRecordRule()

            n_files = len(cve_files)
            for file_idx, path in enumerate(cve_files, 1):
                logger.info(
                    f"[CWE] Reading weaknesses from {path.name} "
                    f"({file_idx}/{n_files}, {file_idx * 100 // n_files}%)"
                )
                is_modified = path.name == "nvdcve-2.0-modified.json"
                for cve_id, last_modified, entries in _iter_cve_weaknesses(path):
                    records, placeholders, unmapped = _aggregate_caused_by(
                        cve_id, entries, loaded_cwe_ids
                    )
                    skipped += placeholders
                    skipped_unmapped += len(unmapped)
                    unmapped_ids.update(unmapped)
                    if is_modified:
                        records = newest.remember(cve_id, last_modified, records)
                    else:
                        records = newest.admit(cve_id, last_modified, records)
                    rel_batch.extend(records)
                    edges_written += len(records)
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
            result["stats"]["caused_by_records"]    = edges_written
            result["stats"]["superseded_by_newer"]  = newest.superseded
            result["stats"]["pairs_only_in_older"]  = newest.pairs_only_in_older
            result["errors"]  = errors
            result["success"] = len(errors) == 0

            self.log_success(
                f"CAUSED_BY: {rels_created} created, "
                f"{edges_written} edge records written with provenance lists "
                f"({newest.superseded} pairs named by two records of a CVE, "
                f"lists from the newest lastModified), "
                f"{skipped} NVD placeholders skipped, "
                f"{skipped_unmapped} unmapped CWE refs skipped"
            )
            if newest.pairs_only_in_older:
                self.log_warning(
                    f"{newest.pairs_only_in_older} (CVE, CWE) pairs appear only in "
                    "an older record than the newest one for their CVE (edge kept, "
                    "lists from the older record)"
                )
            else:
                self.log_success("0 (CVE, CWE) pairs appear only in an older record")
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
