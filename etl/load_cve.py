"""
ETL loader for CVE (Common Vulnerabilities and Exposures) data.

Step 2 of the KGCS load order. Must run after load_cpe (AFFECTS targets
PlatformConfiguration nodes created there).

Node types created:
  - Vulnerability  (cveId unique key)
  - Reference      (referenceUrl unique key)
  - VulnerabilityConfiguration      (vcId unique key)
  - VulnerabilityConfigurationNode  (vcnId unique key)

Relationships created:
  - (Vulnerability)-[:HAS_CONFIGURATION]->(VulnerabilityConfiguration)
  - (VulnerabilityConfiguration)-[:HAS_NODE]->(VulnerabilityConfigurationNode)
  - (VulnerabilityConfigurationNode)-[:MATCHES_CRITERIA]->(PlatformConfiguration)
  - (Vulnerability)-[:AFFECTS]->(PlatformConfiguration)  # compatibility projection
  - (Vulnerability)-[:REFERENCES]->(Reference)

Data sources (already downloaded):
  - data/raw/CVE/nvdcve-2.0-modified.json    (processed first)
  - data/raw/CVE/nvdcve-2.0-YYYY.json        (2002–2025, processed in order)

Load order detail:
  The modified file is processed first so that recently updated entries
  are present; the annual files are then processed in chronological order.
  All MERGE statements are idempotent — re-processing a CVE from both
  files is safe.

AFFECTS cardinality:
  Only matchCriteriaId entries where negate is NOT True are linked.
  AND/OR operators within a configuration node are flattened — all
  cpeMatch entries are iterated regardless of operator.

SHACL invariant enforced here:
  SH-CORE-01: AFFECTS must point to PlatformConfiguration, never Platform.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Generator, List, Tuple

from .base import AbstractETL
from .cve_applicability import flatten_vulnerable_configurations

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cypher statements
# ---------------------------------------------------------------------------

_CYPHER_VULNERABILITY = """\
UNWIND $batch AS row
MERGE (v:Vulnerability {cveId: row.cveId})
ON CREATE SET
    v.source       = row.source,
    v.published    = row.published,
    v.lastModified = row.lastModified
ON MATCH SET
    v.lastModified = row.lastModified
"""

_CYPHER_REFERENCE = """\
UNWIND $batch AS row
MERGE (r:Reference {referenceUrl: row.referenceUrl})
ON CREATE SET
    r.source = row.source
"""

_CYPHER_REFERENCES_REL = """\
UNWIND $batch AS row
MATCH (v:Vulnerability {cveId: row.cveId})
MATCH (r:Reference {referenceUrl: row.referenceUrl})
MERGE (v)-[:REFERENCES]->(r)
"""

_CYPHER_AFFECTS_REL = """\
UNWIND $batch AS row
MATCH (v:Vulnerability {cveId: row.cveId})
MATCH (pc:PlatformConfiguration {matchCriteriaId: row.matchCriteriaId})
MERGE (v)-[:AFFECTS]->(pc)
"""

_CYPHER_VULN_CONFIG = """\
UNWIND $batch AS row
MERGE (vc:VulnerabilityConfiguration {vcId: row.vcId})
ON CREATE SET
    vc.cveId = row.cveId,
    vc.configIndex = row.configIndex,
    vc.operator = row.operator,
    vc.negate = row.negate
ON MATCH SET
    vc.operator = row.operator,
    vc.negate = row.negate
"""

_CYPHER_VULN_CONFIG_NODE = """\
UNWIND $batch AS row
MERGE (vcn:VulnerabilityConfigurationNode {vcnId: row.vcnId})
ON CREATE SET
    vcn.vcId = row.vcId,
    vcn.cveId = row.cveId,
    vcn.configIndex = row.configIndex,
    vcn.nodeIndex = row.nodeIndex,
    vcn.operator = row.operator,
    vcn.negate = row.negate
ON MATCH SET
    vcn.operator = row.operator,
    vcn.negate = row.negate
"""

_CYPHER_HAS_CONFIGURATION = """\
UNWIND $batch AS row
MATCH (v:Vulnerability {cveId: row.cveId})
MATCH (vc:VulnerabilityConfiguration {vcId: row.vcId})
MERGE (v)-[:HAS_CONFIGURATION]->(vc)
"""

_CYPHER_HAS_NODE = """\
UNWIND $batch AS row
MATCH (vc:VulnerabilityConfiguration {vcId: row.vcId})
MATCH (vcn:VulnerabilityConfigurationNode {vcnId: row.vcnId})
MERGE (vc)-[:HAS_NODE]->(vcn)
"""

_CYPHER_MATCHES_CRITERIA = """\
UNWIND $batch AS row
MATCH (vcn:VulnerabilityConfigurationNode {vcnId: row.vcnId})
MATCH (pc:PlatformConfiguration {matchCriteriaId: row.matchCriteriaId})
MERGE (vcn)-[r:MATCHES_CRITERIA]->(pc)
ON CREATE SET
    r.vulnerable = row.vulnerable,
    r.matchIndex = row.matchIndex
ON MATCH SET
    r.vulnerable = row.vulnerable,
    r.matchIndex = row.matchIndex
"""


# ---------------------------------------------------------------------------
# File ordering helper
# ---------------------------------------------------------------------------

def _ordered_cve_files(cve_dir: Path) -> List[Path]:
    """Return CVE JSON files with modified file first, then annual ascending."""
    modified = cve_dir / "nvdcve-2.0-modified.json"
    annual = sorted(
        [p for p in cve_dir.glob("nvdcve-2.0-[0-9]*.json")],
        key=lambda p: p.name,
    )
    files = []
    if modified.exists():
        files.append(modified)
    files.extend(annual)
    return files


# ---------------------------------------------------------------------------
# Record generators
# ---------------------------------------------------------------------------


def _build_affects_projection(cve_id: str, configurations: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Build the current compatibility AFFECTS projection from flattened applicability rows.

    This projection intentionally remains a simplification:
    - emit only vulnerable leaves
    - exclude config/node branches marked with negate
    - deduplicate by (cveId, matchCriteriaId)

    Exact applicability reconstruction is handled by the explicit applicability
    layer planned for Priority 3; AFFECTS remains a convenience projection.
    """
    rows = flatten_vulnerable_configurations(configurations, cve_id)
    affects: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for row in rows:
        if row.get("configNegate") or row.get("nodeNegate"):
            continue
        if not row.get("vulnerable"):
            continue
        match_id = row.get("matchCriteriaId")
        if not match_id:
            continue
        key = (cve_id, match_id)
        if key in seen:
            continue
        seen.add(key)
        affects.append({"cveId": cve_id, "matchCriteriaId": match_id})

    return affects


def _build_applicability_records(
    cve_id: str,
    configurations: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, str]], List[Dict[str, str]], List[Dict[str, Any]]]:
    """Build explicit applicability-layer records from flattened CVE configurations."""
    rows = flatten_vulnerable_configurations(configurations, cve_id)

    config_records: List[Dict[str, Any]] = []
    node_records: List[Dict[str, Any]] = []
    has_configuration: List[Dict[str, str]] = []
    has_node: List[Dict[str, str]] = []
    matches_criteria: List[Dict[str, Any]] = []

    seen_configs: set[str] = set()
    seen_nodes: set[str] = set()
    seen_has_config: set[tuple[str, str]] = set()
    seen_has_node: set[tuple[str, str]] = set()
    seen_matches: set[tuple[str, str]] = set()

    for row in rows:
        vc_id = f"{cve_id}::CFG::{row['configIndex']}"
        vcn_id = f"{vc_id}::NODE::{row['nodeIndex']}"

        if vc_id not in seen_configs:
            seen_configs.add(vc_id)
            config_records.append(
                {
                    "vcId": vc_id,
                    "cveId": cve_id,
                    "configIndex": row["configIndex"],
                    "operator": row["configOperator"],
                    "negate": row["configNegate"],
                }
            )

        if vcn_id not in seen_nodes:
            seen_nodes.add(vcn_id)
            node_records.append(
                {
                    "vcnId": vcn_id,
                    "vcId": vc_id,
                    "cveId": cve_id,
                    "configIndex": row["configIndex"],
                    "nodeIndex": row["nodeIndex"],
                    "operator": row["nodeOperator"],
                    "negate": row["nodeNegate"],
                }
            )

        has_config_key = (cve_id, vc_id)
        if has_config_key not in seen_has_config:
            seen_has_config.add(has_config_key)
            has_configuration.append({"cveId": cve_id, "vcId": vc_id})

        has_node_key = (vc_id, vcn_id)
        if has_node_key not in seen_has_node:
            seen_has_node.add(has_node_key)
            has_node.append({"vcId": vc_id, "vcnId": vcn_id})

        match_id = row.get("matchCriteriaId")
        if not match_id:
            continue

        matches_key = (vcn_id, match_id)
        if matches_key in seen_matches:
            continue
        seen_matches.add(matches_key)
        matches_criteria.append(
            {
                "vcnId": vcn_id,
                "matchCriteriaId": match_id,
                "vulnerable": row["vulnerable"],
                "matchIndex": row["matchIndex"],
            }
        )

    return config_records, node_records, has_configuration, has_node, matches_criteria

def _iter_vuln_records(path: Path) -> Generator[Tuple[Dict, List, List, Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, str]], List[Dict[str, str]], List[Dict[str, Any]]]], None, None]:
    """Yield ETL-ready records per CVE entry.

    references_list: list of {referenceUrl, source}
    affects_list:    list of {cveId, matchCriteriaId}
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            vuln = {
                "cveId":        cve_id,
                "source":       cve.get("sourceIdentifier", ""),
                "published":    cve.get("published", ""),
                "lastModified": cve.get("lastModified", ""),
            }

            # References
            refs = []
            for ref in cve.get("references", []):
                url = ref.get("url", "")
                if url:
                    refs.append({
                        "referenceUrl": url,
                        "source":       ref.get("source", ""),
                    })

            configurations = cve.get("configurations", [])
            applicability = _build_applicability_records(cve_id, configurations)
            affects = _build_affects_projection(cve_id, configurations)

            yield vuln, refs, affects, applicability

    except Exception as exc:
        logger.error(f"[CVE] Failed reading {path}: {exc}")


class CVELoader(AbstractETL):
    """ETL loader for Vulnerability and Reference nodes with relationships.

    Overrides run() for streaming due to multi-GB source data.
    """

    @property
    def standard_name(self) -> str:
        return "CVE"

    # Abstract stubs — run() drives the pipeline
    def extract(self) -> Any:
        return None

    def transform(self, raw_data: Any) -> List[Dict]:
        return []

    def load_nodes(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    def load_relationships(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    # ------------------------------------------------------------------
    # Streaming run()
    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "success": False,
            "errors":  [],
            "stats":   {
                "nodes_created": 0,
                "rels_created":  0,
                "files_processed": 0,
            },
        }

        try:
            self.log_success("Starting CVE ETL (streaming mode)")

            cve_dir = self.raw_data_dir / "CVE"
            files = _ordered_cve_files(cve_dir)
            if not files:
                self.log_warning(f"No CVE JSON files found in {cve_dir}")
                result["success"] = True
                return result

            vuln_batch: List[Dict] = []
            ref_batch:  List[Dict] = []
            ref_rel_batch:    List[Dict] = []
            vuln_config_batch: List[Dict] = []
            vuln_config_node_batch: List[Dict] = []
            has_configuration_batch: List[Dict] = []
            has_node_batch: List[Dict] = []
            matches_criteria_batch: List[Dict] = []
            affects_batch:    List[Dict] = []

            # Track seen references to avoid duplicates within the run
            seen_refs: set = set()

            total_nodes = 0
            total_rels  = 0
            errors: List[str] = []

            def _flush_all():
                nonlocal total_nodes, total_rels
                if vuln_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_VULNERABILITY, vuln_batch, self.batch_size
                    )
                    total_nodes += r.get("nodes_created", 0)
                    errors.extend(r.get("errors", []))
                    vuln_batch.clear()
                if ref_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_REFERENCE, ref_batch, self.batch_size
                    )
                    total_nodes += r.get("nodes_created", 0)
                    errors.extend(r.get("errors", []))
                    ref_batch.clear()
                if ref_rel_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_REFERENCES_REL, ref_rel_batch, self.batch_size
                    )
                    total_rels += r.get("rels_created", 0)
                    errors.extend(r.get("errors", []))
                    ref_rel_batch.clear()
                if vuln_config_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_VULN_CONFIG, vuln_config_batch, self.batch_size
                    )
                    total_nodes += r.get("nodes_created", 0)
                    errors.extend(r.get("errors", []))
                    vuln_config_batch.clear()
                if vuln_config_node_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_VULN_CONFIG_NODE, vuln_config_node_batch, self.batch_size
                    )
                    total_nodes += r.get("nodes_created", 0)
                    errors.extend(r.get("errors", []))
                    vuln_config_node_batch.clear()
                if has_configuration_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_HAS_CONFIGURATION, has_configuration_batch, self.batch_size
                    )
                    total_rels += r.get("rels_created", 0)
                    errors.extend(r.get("errors", []))
                    has_configuration_batch.clear()
                if has_node_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_HAS_NODE, has_node_batch, self.batch_size
                    )
                    total_rels += r.get("rels_created", 0)
                    errors.extend(r.get("errors", []))
                    has_node_batch.clear()
                if matches_criteria_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_MATCHES_CRITERIA, matches_criteria_batch, self.batch_size
                    )
                    total_rels += r.get("rels_created", 0)
                    errors.extend(r.get("errors", []))
                    matches_criteria_batch.clear()
                if affects_batch:
                    r = self.writer.execute_batch(
                        _CYPHER_AFFECTS_REL, affects_batch, self.batch_size
                    )
                    total_rels += r.get("rels_created", 0)
                    errors.extend(r.get("errors", []))
                    affects_batch.clear()

            n_files = len(files)
            for file_idx, path in enumerate(files, 1):
                logger.info(
                    f"[CVE] Processing {path.name} "
                    f"({file_idx}/{n_files}, {file_idx * 100 // n_files}%)"
                )
                for vuln, refs, affects, applicability in _iter_vuln_records(path):
                    vuln_batch.append(vuln)

                    for ref in refs:
                        url = ref["referenceUrl"]
                        if url not in seen_refs:
                            seen_refs.add(url)
                            ref_batch.append(ref)
                        ref_rel_batch.append({
                            "cveId":        vuln["cveId"],
                            "referenceUrl": url,
                        })

                    config_records, node_records, has_configs, has_nodes, matches_criteria = applicability
                    vuln_config_batch.extend(config_records)
                    vuln_config_node_batch.extend(node_records)
                    has_configuration_batch.extend(has_configs)
                    has_node_batch.extend(has_nodes)
                    matches_criteria_batch.extend(matches_criteria)
                    affects_batch.extend(affects)

                    # Flush when any batch reaches threshold
                    if (len(vuln_batch) >= self.batch_size
                            or len(ref_batch) >= self.batch_size
                            or len(ref_rel_batch) >= self.batch_size
                            or len(vuln_config_batch) >= self.batch_size
                            or len(vuln_config_node_batch) >= self.batch_size
                            or len(has_configuration_batch) >= self.batch_size
                            or len(has_node_batch) >= self.batch_size
                            or len(matches_criteria_batch) >= self.batch_size
                            or len(affects_batch) >= self.batch_size):
                        _flush_all()

                # Flush at end of each file to free memory
                _flush_all()
                result["stats"]["files_processed"] += 1

            result["stats"]["nodes_created"] = total_nodes
            result["stats"]["rels_created"]  = total_rels
            result["errors"] = errors
            result["success"] = len(errors) == 0

            if result["success"]:
                self.log_success(f"Complete: {result['stats']}")
            else:
                self.log_error(
                    f"Completed with {len(errors)} errors"
                )

        except Exception as exc:
            self.log_error(f"Unhandled exception: {exc}")
            result["errors"].append(str(exc))

        return result
