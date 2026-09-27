"""
ETL loader for the CISA Known Exploited Vulnerabilities catalog (spec 1.2.0,
ADR-0003, mappings/kev-to-owl-v1.0.md).

Decision step, right after load_cvss: HAS_KEV_ENTRY targets Vulnerability
nodes created by load_cve.

Node types created:
  - KevEntry  (cveId unique key; exactly one entry per CVE)

Relationships created:
  - (Vulnerability)-[:HAS_KEV_ENTRY]->(KevEntry)

Data source:
  - data/raw/KEV/known_exploited_vulnerabilities.json (CISA JSON feed)

Rules (kev-to-owl-v1.0.md, "Transformation Rules"):
  1. Full refresh: MERGE on cveId, then SET every field of the current
     catalog, including the file's catalogVersion and dateReleased.
     Entries whose CVE has no Vulnerability node are dropped and counted.
  2. The only edge is HAS_KEV_ENTRY from the Vulnerability with the same cveId.
  3. cwes[] stays a string list on the entry; never CAUSED_BY, never an edge.
  4. Dates stay YYYY-MM-DD strings in the graph.
  5. The file's `count` must equal the number of entries (loader check).
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .base import AbstractETL
from .decision_common import existing_cve_ids

logger = logging.getLogger(__name__)

KEV_FILE = "known_exploited_vulnerabilities.json"

# source field -> graph property (verbatim names, kev-to-owl-v1.0.md)
_REQUIRED = {
    "cveID":             "cveId",
    "vendorProject":     "vendorProject",
    "product":           "product",
    "vulnerabilityName": "vulnerabilityName",
    "dateAdded":         "dateAdded",
    "shortDescription":  "shortDescription",
    "requiredAction":    "requiredAction",
    "dueDate":           "dueDate",
}
_OPTIONAL = {
    "knownRansomwareCampaignUse": "knownRansomwareCampaignUse",
    "forensicTriage":             "forensicTriage",
    "notes":                      "notes",
    "cwes":                       "cwes",
}

# SET k = row.props replaces every property: the catalog is the full truth
# for an entry (CISA edits in place), so a field CISA drops disappears too.
_CYPHER_KEV = """\
UNWIND $batch AS row
MATCH (v:Vulnerability {cveId: row.cveId})
MERGE (k:KevEntry {cveId: row.cveId})
SET k = row.props
MERGE (v)-[:HAS_KEV_ENTRY]->(k)
"""


def read_catalog(path: Path) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def kev_records(catalog: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Catalog -> (node property dicts, counts). Pure; no Neo4j.

    Deduplicates on cveID (first entry wins; CISA's catalog has one entry
    per CVE, a duplicate is counted). Raises ValueError when a required
    field is missing or `count` disagrees with the entries.
    """
    entries = catalog.get("vulnerabilities") or []
    stated = catalog.get("count")
    if stated is not None and stated != len(entries):
        raise ValueError(f"KEV count {stated} != {len(entries)} entries")
    catalog_version = catalog.get("catalogVersion")
    if not catalog_version:
        raise ValueError("KEV catalog has no catalogVersion")
    date_released = catalog.get("dateReleased")

    records: List[Dict[str, Any]] = []
    seen = set()
    duplicates = 0
    for entry in entries:
        missing = [f for f in _REQUIRED if not entry.get(f)]
        if missing:
            raise ValueError(f"KEV entry {entry.get('cveID')!r} lacks {missing}")
        if entry["cveID"] in seen:
            duplicates += 1
            continue
        seen.add(entry["cveID"])
        props: Dict[str, Any] = {prop: entry[f] for f, prop in _REQUIRED.items()}
        for f, prop in _OPTIONAL.items():
            value = entry.get(f)
            if value is None:
                continue
            if f == "cwes":
                value = [str(c) for c in value]
                if not value:
                    continue
            props[prop] = value
        props["catalogVersion"] = catalog_version
        if date_released:
            props["dateReleased"] = date_released
        records.append(props)
    return records, {"entries": len(entries), "duplicates": duplicates}


def kev_snapshot(raw_data_dir: Path) -> str | None:
    """BuildMetadata value KEV=<catalogVersion> (build.shacl.ttl v1.2)."""
    path = Path(raw_data_dir) / "KEV" / KEV_FILE
    if not path.exists():
        return None
    return read_catalog(path).get("catalogVersion") or None


class KEVLoader(AbstractETL):
    """KevEntry leaves from the CISA KEV JSON feed."""

    @property
    def standard_name(self) -> str:
        return "KEV"

    def extract(self) -> Any:
        return None

    def transform(self, raw_data: Any) -> List[Dict]:
        return []

    def load_nodes(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    def load_relationships(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    def run(self) -> Dict[str, Any]:
        path = self.standard_dir / KEV_FILE
        if not path.exists():
            return self._error_result(f"KEV catalog not found: {path}")
        try:
            catalog = read_catalog(path)
            records, counts = kev_records(catalog)
        except (OSError, ValueError) as exc:
            return self._error_result(f"KEV catalog unreadable: {exc}")

        self.log_success(
            f"catalogVersion {catalog.get('catalogVersion')}, {counts['entries']} entries, "
            f"{counts['duplicates']} duplicate cveIDs"
        )
        present = existing_cve_ids(self.writer, [r["cveId"] for r in records])
        rows = [{"cveId": r["cveId"], "props": r} for r in records if r["cveId"] in present]
        dropped = sorted(r["cveId"] for r in records if r["cveId"] not in present)
        if dropped:
            self.log_warning(
                f"{len(dropped)} entries dropped (no Vulnerability node): "
                f"{', '.join(dropped[:20])}{' …' if len(dropped) > 20 else ''}"
            )
        r = self.writer.execute_batch(_CYPHER_KEV, rows, self.batch_size)
        stats = {
            "nodes_created":   r.get("nodes_created", 0),
            "rels_created":    r.get("rels_created", 0),
            "catalog_version": catalog.get("catalogVersion"),
            "entries":         counts["entries"],
            "loaded":          len(rows),
            "dropped_no_vulnerability": len(dropped),
        }
        result = {"success": r["success"], "errors": r.get("errors", []), "stats": stats}
        if result["success"]:
            self.log_success(f"Complete: {stats}")
        else:
            self.log_error(f"Completed with {len(result['errors'])} errors")
        return result
