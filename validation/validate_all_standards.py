"""
KGCS SHACL validation and post-load check runner.

Usage:
    python validation/validate_all_standards.py [options]

Options:
    --standard NAME     Validate only a specific standard (cpe, cve, attck, ...)
    --post-load         Run Cypher post-load integrity checks against Neo4j
    --partial-load      With --post-load: the graph is a partial load (--step);
                        0 BuildMetadata nodes is a warning instead of a failure
    --shapes-dir PATH   SHACL shape files directory (default: spec/shapes/)
    --owl-dir PATH      OWL ontology files directory (default: spec/ontology/)
    --log-level LEVEL   Logging level (default: INFO)

Exit codes:
    0  All checks passed.
    1  One or more violations found.

BuildMetadata rule (spec 1.1.0, build.shacl.ttl): a full load writes exactly
one BuildMetadata node (run_all_etl.py step build_metadata).
    0 nodes   FAIL; known causes: a graph loaded by a pipeline older than
              spec 1.1, or a partial load (--step). With --partial-load it
              is a WARNING and the report says why.
    1 node    PASS
    >1 nodes  FAIL always, with or without --partial-load.
Q7 and any pre-release validation run WITHOUT --partial-load; the flag
exists only for development and partial loads.

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

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from etl.consequences import CAPEC_IMPACTS, CWE_IMPACTS, LIKELIHOODS, SCOPES  # noqa: E402

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
# Each tuple: (label, cypher, description[, params])
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
        "part_of_domain_coherence",
        "MATCH (t)-[:PART_OF]->(ta:Tactic) "
        "WHERE any(d IN ta.domains WHERE NOT d IN t.domains) "
        "RETURN count(*) AS n",
        "Every PART_OF Tactic domain is one of the Technique's domains "
        "(spec 1.1.0 attack:PartOfDomainCoherenceShape)",
    ),
    (
        "caused_by_provenance_aligned",
        "MATCH (:Vulnerability)-[r:CAUSED_BY]->(:Weakness) "
        "WHERE r.sources IS NOT NULL AND NOT ("
        "  size(r.sources) > 0 AND size(r.sources) = size(r.sourceRoles) "
        "  AND size(r.sources) = size(r.types)) "
        "RETURN count(r) AS n",
        "CAUSED_BY provenance lists are non-empty and index-aligned "
        "(spec 1.1.0 ADR-0002; edges without provenance are only a Warning)",
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
    # Causal-chain shortcut guards (Seeds: archaeology/GraphDatabase_2023
    # Obs 002 + review residual uncertainty). The chain is
    # CPE -> CVE/CVSS -> CWE -> CAPEC -> ATT&CK -> countermeasures; any edge
    # that skips a hop is forbidden regardless of type.
    (
        "no_cve_to_attck_shortcut",
        "MATCH (v:Vulnerability)-[r]->(x) "
        "WHERE x:Technique OR x:SubTechnique OR x:Tactic OR x:AttackPattern "
        "RETURN count(r) AS n",
        "No shortcut edges CVE→CAPEC/ATT&CK (chain must pass through CWE)",
    ),
    (
        "no_platform_shortcut",
        "MATCH (p:Platform)-[r]->(x) "
        "WHERE x:Vulnerability OR x:Weakness "
        "RETURN count(r) AS n",
        "No Platform→Vulnerability/Weakness shortcuts (must go via PlatformConfiguration and AFFECTS direction)",
    ),
    (
        "no_cwe_to_attck_shortcut",
        "MATCH (w:Weakness)-[r]->(x) "
        "WHERE x:Technique OR x:SubTechnique OR x:Tactic "
        "RETURN count(r) AS n",
        "No shortcut edges CWE→ATT&CK (chain must pass through CAPEC)",
    ),
    # --- spec 1.1.0: CWE enrichment (cwe.shacl.ttl v1.1 minCount 1 fields) ---
    (
        "weakness_required_enrichment",
        "MATCH (w:Weakness) "
        "WHERE coalesce(w.description, '') = '' OR w.mappingUsage IS NULL "
        "   OR w.structure IS NULL OR w.status IS NULL "
        "RETURN count(w) AS n",
        "Every Weakness has description, mappingUsage, structure and status "
        "(spec 1.1.0 cwe-enrichment; negative case weakness-missing-description)",
    ),
    # --- spec 1.1.0: Consequence sub-nodes (consequences-to-owl-v1.0.md) ---
    (
        "consequence_one_parent",
        "MATCH (c:Consequence) "
        "WHERE size([(p)-[:HAS_CONSEQUENCE]->(c) WHERE p:Weakness OR p:AttackPattern | 1]) <> 1 "
        "RETURN count(c) AS n",
        "Every Consequence has exactly one HAS_CONSEQUENCE parent (Weakness or AttackPattern)",
    ),
    (
        "consequence_is_leaf",
        "MATCH (c:Consequence)-[r]-() "
        "WHERE NOT (type(r) = 'HAS_CONSEQUENCE' AND endNode(r) = c) "
        "RETURN count(DISTINCT r) AS n",
        "Consequence nodes are leaf annotations: no edge other than the incoming HAS_CONSEQUENCE",
    ),
    (
        "consequence_key_matches_parent",
        "MATCH (p)-[:HAS_CONSEQUENCE]->(c:Consequence) "
        "WHERE NOT c.consequenceId STARTS WITH coalesce(p.cweId, p.capecId) + '-C' "
        "RETURN count(c) AS n",
        "consequenceId is <parentId>-C<ordinal> of its own parent",
    ),
    (
        "consequence_ordinals_contiguous",
        "MATCH (p)-[:HAS_CONSEQUENCE]->(c:Consequence) "
        "WITH p, count(c) AS n, max(toInteger(split(c.consequenceId, '-C')[-1])) AS top "
        "WHERE top <> n "
        "RETURN count(p) AS n",
        "Consequence ordinals are C1..Cn per parent (no gaps after pruning)",
    ),
    (
        "consequence_scopes_present",
        "MATCH (c:Consequence) WHERE c.scopes IS NULL OR size(c.scopes) = 0 "
        "RETURN count(c) AS n",
        "Every Consequence has at least one scope",
    ),
    (
        "cwe_consequence_impacts_present",
        "MATCH (:Weakness)-[:HAS_CONSEQUENCE]->(c:Consequence) "
        "WHERE c.impacts IS NULL OR size(c.impacts) = 0 "
        "RETURN count(c) AS n",
        "Every CWE Consequence has at least one impact (CWE XSD; CAPEC impacts are optional)",
    ),
    (
        "cwe_consequence_vocabulary",
        "MATCH (:Weakness)-[:HAS_CONSEQUENCE]->(c:Consequence) "
        "WHERE any(s IN coalesce(c.scopes, []) WHERE NOT s IN $scopes) "
        "   OR any(i IN coalesce(c.impacts, []) WHERE NOT i IN $impacts) "
        "   OR (c.likelihood IS NOT NULL AND NOT c.likelihood IN $likelihoods) "
        "RETURN count(c) AS n",
        "CWE Consequence scopes / impacts / likelihood within the CWE vocabularies",
        {"scopes": list(SCOPES), "impacts": list(CWE_IMPACTS), "likelihoods": list(LIKELIHOODS)},
    ),
    (
        "capec_consequence_vocabulary",
        "MATCH (:AttackPattern)-[:HAS_CONSEQUENCE]->(c:Consequence) "
        "WHERE any(s IN coalesce(c.scopes, []) WHERE NOT s IN $scopes) "
        "   OR any(i IN coalesce(c.impacts, []) WHERE NOT i IN $impacts) "
        "   OR (c.likelihood IS NOT NULL AND NOT c.likelihood IN $likelihoods) "
        "RETURN count(c) AS n",
        "CAPEC Consequence scopes / impacts / likelihood within the CAPEC vocabularies",
        {"scopes": list(SCOPES), "impacts": list(CAPEC_IMPACTS), "likelihoods": list(LIKELIHOODS)},
    ),
]

_BUILD_METADATA_COUNT = "MATCH (b:BuildMetadata) RETURN count(b) AS n"


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

def _check_constraints_present(writer) -> Tuple[bool, List[str]]:
    """Verify every expected uniqueness constraint physically exists in the DB.

    Seeds: archaeology/GraphDatabase_2023 Obs 003 + review residual
    uncertainty ("no direct evidence for indexes, uniqueness constraints,
    or load-order enforcement in production"). This check IS that evidence:
    it compares SHOW CONSTRAINTS output against the single source of truth
    in etl.init_constraints.UNIQUE_CONSTRAINTS.

    Returns (passed, [failure_messages]).
    """
    from etl.init_constraints import UNIQUE_CONSTRAINTS

    pairs = writer.read_one(
        "SHOW CONSTRAINTS YIELD type, labelsOrTypes, properties "
        "WHERE type CONTAINS 'UNIQUENESS' "
        "RETURN collect([labelsOrTypes[0], properties[0]]) AS pairs"
    )
    if pairs is None:
        return False, [
            "FAIL [constraints_present]: SHOW CONSTRAINTS returned no result"
        ]

    present = {(label, prop) for label, prop in pairs}
    missing = [
        (label, prop)
        for label, prop in UNIQUE_CONSTRAINTS
        if (label, prop) not in present
    ]
    if missing:
        return False, [
            f"FAIL [constraints_present]: missing uniqueness constraint "
            f"{label}.{prop}"
            for label, prop in missing
        ]
    logger.info(
        f"PASS [constraints_present]: all {len(UNIQUE_CONSTRAINTS)} expected "
        f"uniqueness constraints exist in the database"
    )
    return True, []


def _check_build_metadata(writer, partial_load: bool) -> Tuple[bool, List[str], List[str]]:
    """build_metadata_singleton (rule in the module docstring).

    Returns (passed, [failure_messages], [warning_messages]).
    """
    name = "build_metadata_singleton"
    count = writer.read_one(_BUILD_METADATA_COUNT)
    if count is None:
        return False, [f"FAIL [{name}]: BuildMetadata count query returned no result"], []
    if count == 1:
        return True, [], []
    if count > 1:
        return False, [
            f"FAIL [{name}]: {count} BuildMetadata nodes; a graph has exactly one "
            f"(this fails with or without --partial-load)"
        ], []
    if partial_load:
        return True, [], [
            f"WARN [{name}]: no BuildMetadata node; accepted because --partial-load "
            f"was given (a --step load does not run the build_metadata step). "
            f"Q7 and pre-release validation must run without --partial-load."
        ]
    return False, [
        f"FAIL [{name}]: no BuildMetadata node. Known causes: the graph was loaded "
        f"by a pipeline older than spec 1.1, or it is a partial load (--step; "
        f"validate those with --partial-load)"
    ], []


def _run_post_load_checks(partial_load: bool = False) -> Tuple[bool, List[str]]:
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
            # Schema evidence first: graph-shape checks below assume the
            # uniqueness constraints that make MERGE deduplication reliable.
            ok, msgs = _check_constraints_present(writer)
            if not ok:
                for msg in msgs:
                    logger.error(msg)
                failures.extend(msgs)
            total = len(_POST_LOAD_CHECKS)
            for idx, (check_name, cypher, description, *params) in enumerate(
                _POST_LOAD_CHECKS, 1
            ):
                logger.info(f"[{idx}/{total}] {check_name}: running ...")
                count = writer.read_one(cypher, params[0] if params else None)
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
            ok, msgs, warnings = _check_build_metadata(writer, partial_load)
            for msg in warnings:
                logger.warning(msg)
            for msg in msgs:
                logger.error(msg)
            failures.extend(msgs)
            if ok and not warnings:
                logger.info("PASS [build_metadata_singleton]: exactly one BuildMetadata node")
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
        "--partial-load", action="store_true",
        help="Partial load (--step): 0 BuildMetadata nodes is a warning, not a "
             "failure. Never for Q7 / pre-release validation.",
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
        passed, failures = _run_post_load_checks(partial_load=args.partial_load)
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
