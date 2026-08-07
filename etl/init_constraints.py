"""
Neo4j database constraint and index initialisation for KGCS.

Run once before any ETL load (or on every run with --skip-constraints=False,
since all statements use IF NOT EXISTS and are therefore idempotent).

Constraints enforce uniqueness on the canonical identifier property of each
node label. Without these, MERGE statements would silently create duplicate
nodes on property-level mismatches.

Neo4j 5.x syntax is required:
    CREATE CONSTRAINT IF NOT EXISTS FOR (n:Label) REQUIRE n.prop IS UNIQUE;
"""

import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constraint definitions
# Each (label, property) pair corresponds to the canonical unique key
# defined in docs/04-graph/agent-consumable-schema.md.
# ---------------------------------------------------------------------------

UNIQUE_CONSTRAINTS: List[tuple] = [
    # CPE
    ("Platform",              "cpeUri"),
    ("Platform",              "cpeNameId"),
    ("PlatformConfiguration", "matchCriteriaId"),
    # CVE / CVSS
    ("Vulnerability",         "cveId"),
    ("VulnerabilityConfiguration", "vcId"),
    ("VulnerabilityConfigurationNode", "vcnId"),
    ("Score",                 "scoreId"),
    ("Reference",             "referenceUrl"),
    # CWE
    ("Weakness",              "cweId"),
    # CAPEC
    ("AttackPattern",         "capecId"),
    # ATT&CK
    ("Technique",             "attackId"),
    ("SubTechnique",          "attackId"),
    ("Tactic",                "attackId"),
    # D3FEND
    ("DefensiveTechnique",    "d3fendId"),
    # CAR
    ("DetectionAnalytic",     "analyticId"),
    # SHIELD
    ("DeceptionTechnique",    "techniqueId"),
    # ENGAGE — one label, three key namespaces (activities, approaches, goals).
    # Neo4j uniqueness constraints exempt null values, so per-property
    # constraints on the same label do not collide across the three subtypes.
    ("EngagementConcept",     "activityId"),
    ("EngagementConcept",     "approachId"),
    ("EngagementConcept",     "goalId"),
]

# ---------------------------------------------------------------------------
# Composite label+property name for constraint naming
# Neo4j auto-names constraints; IF NOT EXISTS prevents re-creation errors.
# ---------------------------------------------------------------------------

CONSTRAINT_CYPHER_TEMPLATE = (
    "CREATE CONSTRAINT IF NOT EXISTS "
    "FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"
)

# Additional lookup indexes (non-unique; aid relationship resolution)
LOOKUP_INDEXES: List[tuple] = [
    # Tactic phaseName is used for PART_OF join during ATT&CK load
    ("Tactic", "phaseName"),
    # Vulnerability source for provenance queries
    ("Vulnerability", "published"),
    # Score version for CVSS filtering queries
    ("Score", "version"),
]

INDEX_CYPHER_TEMPLATE = (
    "CREATE INDEX IF NOT EXISTS FOR (n:{label}) ON (n.{prop})"
)


def run_constraints(writer) -> Dict[str, Any]:
    """Apply all unique constraints and lookup indexes.

    Args:
        writer: Neo4jWriter instance.

    Returns:
        {"success": bool, "applied": int, "errors": List[str]}
    """
    errors: List[str] = []
    applied = 0

    logger.info("Applying Neo4j unique constraints...")
    for label, prop in UNIQUE_CONSTRAINTS:
        cypher = CONSTRAINT_CYPHER_TEMPLATE.format(label=label, prop=prop)
        result = writer.execute_one(cypher)
        if result["success"]:
            applied += 1
            logger.info(f"  ✓ UNIQUE constraint: {label}.{prop}")
        else:
            errors.extend(result["errors"])
            logger.error(f"  ✗ UNIQUE constraint FAILED: {label}.{prop} — {result['errors']}")

    logger.info("Applying Neo4j lookup indexes...")
    for label, prop in LOOKUP_INDEXES:
        cypher = INDEX_CYPHER_TEMPLATE.format(label=label, prop=prop)
        result = writer.execute_one(cypher)
        if result["success"]:
            applied += 1
            logger.info(f"  ✓ INDEX: {label}.{prop}")
        else:
            errors.extend(result["errors"])
            logger.error(f"  ✗ INDEX FAILED: {label}.{prop} — {result['errors']}")

    success = len(errors) == 0
    total = len(UNIQUE_CONSTRAINTS) + len(LOOKUP_INDEXES)
    logger.info(
        f"Constraints complete: {applied}/{total} applied, {len(errors)} errors."
    )
    return {"success": success, "applied": applied, "errors": errors}
