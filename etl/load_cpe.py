"""
ETL loader for CPE (Common Platform Enumeration) data.

Step 1 of the KGCS load order.

Node types created:
  - Platform           (cpeUri unique key; cpeNameId also unique)
  - PlatformConfiguration (matchCriteriaId unique key)

Relationship created:
  - (PlatformConfiguration)-[:MATCHES_PLATFORM]->(Platform)

Data sources (already downloaded):
  - data/raw/CPE/nvdcpe-2.0-chunks/*.json          ~15 files
  - data/raw/CPE-MATCH/nvdcpematch-2.0-chunks/*.json ~56 files

Streaming design:
  Both source directories are multi-GB in total. This loader overrides
  run() to process one chunk file at a time, never accumulating across
  files (open → iterate → MERGE batch → close → GC).

CPE URI normalisation:
  All cpeUri values are lowercased at ingest time.  The MATCHES_PLATFORM
  join likewise lowercases cpeName from the matches[] array so the lookup
  is case-insensitive by construction.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Generator, List

from .base import AbstractETL

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cypher statements
# ---------------------------------------------------------------------------

_CYPHER_PLATFORM = """\
UNWIND $batch AS row
MERGE (p:Platform {cpeUri: row.cpeUri})
ON CREATE SET
    p.cpeNameId    = row.cpeNameId,
    p.part         = row.part,
    p.vendor       = row.vendor,
    p.product      = row.product,
    p.version      = row.version,
    p.lastModified = row.lastModified,
    p.deprecated   = row.deprecated
ON MATCH SET
    p.lastModified = row.lastModified,
    p.deprecated   = row.deprecated
"""

# Design decision — PlatformConfiguration.cpeUri is intentionally absent.
#
# PlatformConfiguration represents an NVD CPE match criterion, not a concrete
# platform entry.  Its canonical identifiers are:
#   - matchCriteriaId  (unique UUID from the cpematch source, graph merge key)
#   - criteria         (the CPE URI wildcard pattern, e.g.
#                       cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*)
#
# A single criterion typically expands to many concrete Platform nodes via
# MATCHES_PLATFORM edges.  Storing a derived cpeUri on PlatformConfiguration
# would be both redundant with `criteria` and semantically misleading (it would
# imply a 1:1 relationship that does not exist).  The authoritative
# Platform.cpeUri lives on Platform nodes only.  Use MATCHES_PLATFORM to
# traverse from a criterion to its concrete CPE set.
_CYPHER_PLATFORM_CONFIG = """\
UNWIND $batch AS row
MERGE (pc:PlatformConfiguration {matchCriteriaId: row.matchCriteriaId})
ON CREATE SET
    pc.criteria               = row.criteria,
    pc.configStatus           = row.configStatus,
    pc.created                = row.created,
    pc.lastModified           = row.lastModified,
    pc.cpeLastModified        = row.cpeLastModified,
    pc.versionStartExcluding  = row.versionStartExcluding,
    pc.versionStartIncluding  = row.versionStartIncluding,
    pc.versionEndExcluding    = row.versionEndExcluding,
    pc.versionEndIncluding    = row.versionEndIncluding
ON MATCH SET
    pc.criteria               = row.criteria,
    pc.configStatus           = row.configStatus,
    pc.created                = row.created,
    pc.lastModified           = row.lastModified,
    pc.cpeLastModified        = row.cpeLastModified,
    pc.versionStartExcluding  = row.versionStartExcluding,
    pc.versionStartIncluding  = row.versionStartIncluding,
    pc.versionEndExcluding    = row.versionEndExcluding,
    pc.versionEndIncluding    = row.versionEndIncluding
"""

_CYPHER_MATCHES_PLATFORM = """\
UNWIND $batch AS row
MATCH (pc:PlatformConfiguration {matchCriteriaId: row.matchCriteriaId})
MATCH (p:Platform {cpeUri: row.cpeUri})
MERGE (pc)-[:MATCHES_PLATFORM]->(p)
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_cpe_uri(cpe_name: str) -> Dict[str, str]:
    """Split a CPE 2.3 URI into component fields.

    Format: cpe:2.3:part:vendor:product:version:update:edition:...
    Indices after split on ':':
        0  → "cpe"
        1  → "2.3"
        2  → part   (a / o / h)
        3  → vendor
        4  → product
        5  → version
        6+ → ignored for graph storage
    Returns dict with keys: part, vendor, product, version.
    Any component that is "*" or "-" is kept as-is.
    """
    parts = cpe_name.split(":")
    return {
        "part":    parts[2] if len(parts) > 2 else "*",
        "vendor":  parts[3] if len(parts) > 3 else "*",
        "product": parts[4] if len(parts) > 4 else "*",
        "version": parts[5] if len(parts) > 5 else "*",
    }


def _iter_cpe_records(path: Path) -> Generator[Dict, None, None]:
    """Yield one platform dict per CPE product entry in a chunk file."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        for item in data.get("products", []):
            cpe = item.get("cpe", {})
            cpe_name = cpe.get("cpeName", "")
            if not cpe_name:
                continue
            cpe_uri = cpe_name.lower()
            components = _parse_cpe_uri(cpe_uri)
            yield {
                "cpeUri":      cpe_uri,
                "cpeNameId":   cpe.get("cpeNameId", ""),
                "lastModified": cpe.get("lastModified", ""),
                "deprecated":  cpe.get("deprecated", False),
                **components,
            }
    except Exception as exc:
        logger.error(f"[CPE] Failed reading {path}: {exc}")


def _iter_cpematch_node_records(path: Path) -> Generator[Dict, None, None]:
    """Yield one PlatformConfiguration dict per matchString entry."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        for item in data.get("matchStrings", []):
            ms = item.get("matchString", {})
            match_id = ms.get("matchCriteriaId", "")
            if not match_id:
                continue
            yield {
                "matchCriteriaId":       match_id,
                "criteria":              ms.get("criteria", ""),
                "configStatus":          ms.get("status", ""),
                "created":               ms.get("created", ""),
                "lastModified":          ms.get("lastModified", ""),
                "cpeLastModified":       ms.get("cpeLastModified", ""),
                "versionStartExcluding": ms.get("versionStartExcluding", ""),
                "versionStartIncluding": ms.get("versionStartIncluding", ""),
                "versionEndExcluding":   ms.get("versionEndExcluding", ""),
                "versionEndIncluding":   ms.get("versionEndIncluding", ""),
            }
    except Exception as exc:
        logger.error(f"[CPE] Failed reading {path}: {exc}")


def _iter_cpematch_rel_records(path: Path) -> Generator[Dict, None, None]:
    """Yield one relationship dict per (matchCriteriaId, cpeName) pair."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        for item in data.get("matchStrings", []):
            ms = item.get("matchString", {})
            match_id = ms.get("matchCriteriaId", "")
            if not match_id:
                continue
            for match in ms.get("matches", []):
                cpe_name = match.get("cpeName", "")
                if cpe_name:
                    yield {
                        "matchCriteriaId": match_id,
                        "cpeUri":          cpe_name.lower(),
                    }
    except Exception as exc:
        logger.error(f"[CPE] Failed reading {path}: {exc}")


class CPELoader(AbstractETL):
    """ETL loader for CPE Platform and PlatformConfiguration data.

    Overrides run() to stream chunk files one at a time.
    The base-class extract()/transform()/load_* abstract methods are
    implemented as no-ops since run() drives the entire pipeline directly.
    """

    @property
    def standard_name(self) -> str:
        return "CPE"

    # ------------------------------------------------------------------
    # Abstract method stubs (not used — run() overrides the lifecycle)
    # ------------------------------------------------------------------

    def extract(self) -> Any:
        return None

    def transform(self, raw_data: Any) -> List[Dict]:
        return []

    def load_nodes(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    def load_relationships(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    # ------------------------------------------------------------------
    # Streaming run() override
    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        """Stream all CPE chunk files, load nodes and relationships."""
        result: Dict[str, Any] = {
            "success": False,
            "errors":  [],
            "stats":   {"nodes_created": 0, "rels_created": 0,
                        "platform_files": 0, "match_files": 0},
        }

        try:
            self.log_success("Starting CPE ETL (streaming mode)")

            # Step 1 — Platform nodes
            cpe_dir = self.raw_data_dir / "CPE" / "nvdcpe-2.0-chunks"
            cpe_files = sorted(cpe_dir.glob("*.json"))
            if not cpe_files:
                self.log_warning(f"No CPE chunk files found in {cpe_dir}")
            else:
                n, e = self._stream_nodes(
                    files=cpe_files,
                    record_generator=_iter_cpe_records,
                    cypher=_CYPHER_PLATFORM,
                    label="Platform",
                )
                result["stats"]["nodes_created"] += n
                result["errors"].extend(e)
                result["stats"]["platform_files"] = len(cpe_files)
                self.log_success(
                    f"Platform nodes done: {len(cpe_files)} files, "
                    f"{n} nodes created"
                )

            # Step 2 — PlatformConfiguration nodes
            match_dir = self.raw_data_dir / "CPE-MATCH" / "nvdcpematch-2.0-chunks"
            match_files = sorted(match_dir.glob("*.json"))
            if not match_files:
                self.log_warning(f"No CPE-MATCH chunk files found in {match_dir}")
            else:
                n, e = self._stream_nodes(
                    files=match_files,
                    record_generator=_iter_cpematch_node_records,
                    cypher=_CYPHER_PLATFORM_CONFIG,
                    label="PlatformConfiguration",
                )
                result["stats"]["nodes_created"] += n
                result["errors"].extend(e)
                result["stats"]["match_files"] = len(match_files)
                self.log_success(
                    f"PlatformConfiguration nodes done: {len(match_files)} files, "
                    f"{n} nodes created"
                )

            # Step 3 — MATCHES_PLATFORM relationships
            if match_files:
                r, e = self._stream_nodes(
                    files=match_files,
                    record_generator=_iter_cpematch_rel_records,
                    cypher=_CYPHER_MATCHES_PLATFORM,
                    label="MATCHES_PLATFORM",
                    count_key="rels_created",
                )
                result["stats"]["rels_created"] += r
                result["errors"].extend(e)
                self.log_success(
                    f"MATCHES_PLATFORM relationships done: {r} created"
                )

            result["success"] = len(result["errors"]) == 0
            if result["success"]:
                self.log_success(f"Complete: {result['stats']}")
            else:
                self.log_error(
                    f"Completed with {len(result['errors'])} errors"
                )

        except Exception as exc:
            self.log_error(f"Unhandled exception: {exc}")
            result["errors"].append(str(exc))

        return result

    # ------------------------------------------------------------------
    # Internal streaming helper
    # ------------------------------------------------------------------

    def _stream_nodes(
        self,
        files: List[Path],
        record_generator,
        cypher: str,
        label: str,
        count_key: str = "nodes_created",
    ):
        """Process files one at a time, flushing each batch to Neo4j.

        Returns (total_count, errors_list).
        """
        total = 0
        errors: List[str] = []
        batch: List[Dict] = []

        n_files = len(files)
        for file_idx, path in enumerate(files, 1):
            logger.info(
                f"[CPE] {label}: {path.name} "
                f"({file_idx}/{n_files}, {file_idx * 100 // n_files}%)"
            )
            for record in record_generator(path):
                batch.append(record)
                if len(batch) >= self.batch_size:
                    r = self.writer.execute_batch(cypher, batch, self.batch_size)
                    total += r.get(count_key, 0)
                    errors.extend(r.get("errors", []))
                    batch = []
            # flush remainder for this file
            if batch:
                r = self.writer.execute_batch(cypher, batch, self.batch_size)
                total += r.get(count_key, 0)
                errors.extend(r.get("errors", []))
                batch = []

        return total, errors
