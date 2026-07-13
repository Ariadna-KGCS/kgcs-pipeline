"""
KGCS SHACL validation and post-load check runner.

Usage:
    python validation/validate_all_standards.py [options]

Options:
    --standard NAME     Validate only a specific standard (cpe, cve, attck, ...)
    --post-load         Run Cypher post-load integrity checks against Neo4j
    --shapes-dir PATH   SHACL shape files directory (default: spec/shapes/)
    --owl-dir PATH      OWL ontology files directory (default: spec/ontology/)
    --log-level LEVEL   Logging level (default: INFO)

Exit codes:
    0  All checks passed.
    1  One or more violations found.

Requires:
    pip install pyshacl   (for SHACL validation)
    Neo4j credentials in env for --post-load
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("validate_all_standards")

# ---------------------------------------------------------------------------
# Shape → OWL mapping
# ---------------------------------------------------------------------------
# Each shape file is paired with the core OWL and its standard-specific OWL.
# The core.shacl.ttl is always included to enforce causal chain invariants.

_STANDARD_SHAPE_MAP: Dict[str, str] = {
    "cpe":    "spec/shapes/cpe.shacl.ttl",
    "cve":    "spec/shapes/cve.shacl.ttl",
    "cvss":   "spec/shapes/cvss.shacl.ttl",
    "cwe":    "spec/shapes/cwe.shacl.ttl",
    "capec":  "spec/shapes/capec.shacl.ttl",
    "attck":  "spec/shapes/attck.shacl.ttl",
    "d3fend": "spec/shapes/d3fend.shacl.ttl",
    "car":    "spec/shapes/car.shacl.ttl",
    "shield": "spec/shapes/shield.shacl.ttl",
    "engage": "spec/shapes/engage.shacl.ttl",
}
_CORE_SHAPE = "spec/shapes/core.shacl.ttl"
_STANDARD_NAMES = list(_STANDARD_SHAPE_MAP.keys())

# ---------------------------------------------------------------------------
# Post-load Cypher checks
# ---------------------------------------------------------------------------
# Each tuple: (label, cypher, description)
# A check PASSES if COUNT returns 0.

_POST_LOAD_CHECKS: List[Tuple[str, str, str]] = [
    (
        "subtech_cardinality",
        "MATCH (st:SubTechnique) WHERE size([(st)-[:SUBTECHNIQUE_OF]->() | 1]) <> 1 "
        "RETURN count(st) AS n",
        "Every SubTechnique has exactly 1 SUBTECHNIQUE_OF parent",
    ),
    (
        "no_direct_platform_affects",
        "MATCH (v:Vulnerability)-[:AFFECTS]->(p:Platform) RETURN count(p) AS n",
        "No Vulnerability→AFFECTS→Platform edges (only PlatformConfiguration allowed)",
    ),
    (
        "technique_in_tactic",
        "MATCH (t:Technique) WHERE NOT (t)-[:PART_OF]->(:Tactic) RETURN count(t) AS n",
        "Every Technique belongs to at least one Tactic",
    ),
    (
        "no_duplicate_cvss_per_cve",
        "MATCH (v:Vulnerability)-[:HAS_SCORE]->(s:Score) "
        "WITH v, s.version AS ver, count(*) AS c WHERE c > 1 RETURN count(c) AS n",
        "No duplicate CVSS versions per CVE",
    ),
    (
        "affects_backed_by_applicability",
        "MATCH (v:Vulnerability)-[:AFFECTS]->(pc:PlatformConfiguration) "
        "WHERE NOT EXISTS { "
        "  MATCH (v)-[:HAS_CONFIGURATION]->(vc:VulnerabilityConfiguration)-[:HAS_NODE]->(vcn:VulnerabilityConfigurationNode)-[mc:MATCHES_CRITERIA]->(pc) "
        "  WHERE mc.vulnerable = true AND coalesce(vc.negate, false) = false AND coalesce(vcn.negate, false) = false "
        "} "
        "RETURN count(*) AS n",
        "Every AFFECTS edge is backed by a non-negated vulnerable applicability leaf",
    ),
    (
        "expanded_criteria_have_platform_targets",
        "MATCH (:VulnerabilityConfigurationNode)-[:MATCHES_CRITERIA]->(pc:PlatformConfiguration)-[:MATCHES_PLATFORM]->(p:Platform) "
        "WHERE p.cpeUri IS NULL OR p.cpeNameId IS NULL "
        "RETURN count(DISTINCT pc) AS n",
        "Every applicability criterion that expands via MATCHES_PLATFORM resolves to canonical Platform identifiers",
    ),
    (
        "configuration_nodes_have_parent",
        "MATCH (vcn:VulnerabilityConfigurationNode) "
        "WHERE size([(:VulnerabilityConfiguration)-[:HAS_NODE]->(vcn) | 1]) <> 1 "
        "RETURN count(vcn) AS n",
        "Every VulnerabilityConfigurationNode has exactly one HAS_NODE parent",
    ),
]


# ---------------------------------------------------------------------------
# SHACL validation
# ---------------------------------------------------------------------------

def _validate_shacl(
    shape_path: Path,
    owl_dir: Path,
    standard: str,
) -> Tuple[bool, List[str]]:
    """Run pySHACL for one standard's shape file against OWL files.

    Returns (conforms, [violation_messages]).
    """
    try:
        import pyshacl
        from rdflib import Graph
    except ImportError:
        return False, ["pyshacl/rdflib not installed — run: pip install pyshacl"]

    if not shape_path.exists():
        return False, [f"Shape file not found: {shape_path}"]

    # Build combined data graph from all OWL files in owl_dir
    data_graph = Graph()
    owl_files = list(owl_dir.rglob("*.owl")) + list(owl_dir.rglob("*.ttl"))
    if not owl_files:
        return False, [f"No OWL/TTL ontology files found in {owl_dir}"]

    for owl_file in owl_files:
        try:
            # KGCS ontology modules are Turtle-authored despite the .owl suffix.
            # Parse explicitly to avoid rdflib treating them as RDF/XML.
            rdf_format = "turtle" if owl_file.suffix.lower() in {".owl", ".ttl"} else None
            data_graph.parse(str(owl_file), format=rdf_format)
        except Exception as exc:
            logger.warning(f"Could not parse {owl_file}: {exc}")

    if len(data_graph) == 0:
        return False, [f"No triples loaded from {owl_dir}"]

    try:
        conforms, results_graph, results_text = pyshacl.validate(
            data_graph=data_graph,
            shacl_graph=str(shape_path),
            inference="rdfs",
            abort_on_first=False,
            allow_warnings=True,
            meta_shacl=False,
        )
        if conforms:
            return True, []
        else:
            # Extract violation messages from results text
            violations = [
                line.strip()
                for line in results_text.splitlines()
                if line.strip() and not line.startswith("Validation")
            ]
            return False, violations[:20]  # cap at 20 to avoid log flood

    except Exception as exc:
        return False, [f"pyshacl raised exception: {exc}"]


# ---------------------------------------------------------------------------
# Post-load Cypher checks
# ---------------------------------------------------------------------------

def _run_post_load_checks() -> Tuple[bool, List[str]]:
    """Run all Cypher post-load integrity checks.

    Returns (all_passed, [failure_messages]).
    """
    _scripts_dir = Path(__file__).resolve().parent.parent
    if str(_scripts_dir) not in sys.path:
        sys.path.insert(0, str(_scripts_dir))

    try:
        from etl import Neo4jWriter
    except ImportError:
        return False, ["Cannot import Neo4jWriter — run from project root"]

    failures: List[str] = []
    try:
        with Neo4jWriter() as writer:
            total = len(_POST_LOAD_CHECKS)
            for idx, (check_name, cypher, description) in enumerate(
                _POST_LOAD_CHECKS, 1
            ):
                logger.info(f"[{idx}/{total}] {check_name}: running ...")
                count = writer.read_one(cypher)
                if count is None:
                    logger.warning(f"[{check_name}] Query returned None — skipping")
                    continue
                if count != 0:
                    msg = (
                        f"FAIL [{check_name}]: {description} — "
                        f"found {count} violation(s)"
                    )
                    logger.error(msg)
                    failures.append(msg)
                else:
                    logger.info(f"PASS [{check_name}]: {description}")
    except Exception as exc:
        failures.append(f"Neo4j connection error: {exc}")

    return len(failures) == 0, failures


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="KGCS SHACL + post-load validation runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--standard",
        choices=_STANDARD_NAMES,
        help="Validate only one standard (default: all)",
    )
    parser.add_argument(
        "--post-load", action="store_true",
        help="Also run Cypher post-load integrity checks against Neo4j",
    )
    parser.add_argument(
        "--shapes-dir", default="spec/shapes",
        help="Directory containing SHACL .ttl files (default: spec/shapes/)",
    )
    parser.add_argument(
        "--owl-dir", default="spec/ontology",
        help="Directory containing OWL ontology files (default: spec/ontology/)",
    )
    parser.add_argument(
        "--skip-shacl", action="store_true",
        help="Skip SHACL OWL validation (useful when running --post-load only)",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser


def configure_logging(level: str) -> None:
    # Force UTF-8 output: Windows consoles default to cp1252, which mangles
    # log glyphs (✓, →, —) both on screen and through tee.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="backslashreplace")
            except Exception:
                pass
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.log_level)

    project_root = Path(__file__).resolve().parent.parent
    shapes_dir = (project_root / args.shapes_dir).resolve()
    owl_dir    = (project_root / args.owl_dir).resolve()

    all_violations: List[str] = []
    overall_pass = True

    # --- SHACL validation ---
    if not args.skip_shacl:
        core_shape = shapes_dir / "core.shacl.ttl"
        standards_to_check = (
            [args.standard] if args.standard else _STANDARD_NAMES
        )
        for standard in standards_to_check:
            shape_file = shapes_dir / f"{standard}.shacl.ttl"
            logger.info(f"Validating {standard} against {shape_file.name} ...")

            conforms, violations = _validate_shacl(shape_file, owl_dir, standard)
            if conforms:
                logger.info(f"  PASS: {standard}")
            else:
                logger.error(f"  FAIL: {standard} — {len(violations)} violation(s)")
                for v in violations:
                    logger.error(f"    {v}")
                all_violations.extend(violations)
                overall_pass = False

        # Always validate core invariants
        if core_shape.exists():
            logger.info("Validating core causal chain invariants ...")
            conforms, violations = _validate_shacl(
                core_shape, owl_dir, "core"
            )
            if conforms:
                logger.info("  PASS: core invariants")
            else:
                logger.error(f"  FAIL: core — {len(violations)} violation(s)")
                for v in violations:
                    logger.error(f"    {v}")
                all_violations.extend(violations)
                overall_pass = False

    # --- Post-load Cypher checks ---
    if args.post_load:
        logger.info("Running post-load Cypher integrity checks ...")
        passed, failures = _run_post_load_checks()
        if not passed:
            all_violations.extend(failures)
            overall_pass = False

    # --- Summary ---
    if overall_pass:
        logger.info("All validation checks PASSED.")
        return 0
    else:
        logger.error(
            f"Validation FAILED — {len(all_violations)} total violation(s)."
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
