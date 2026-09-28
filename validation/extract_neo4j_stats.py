"""
KGCS Neo4j graph statistics extractor.

Usage:
    python validation/extract_neo4j_stats.py [options]

Options:
    --pretty            Print a formatted table (uses rich library)
    --json              Output raw JSON to stdout
    --check-minimums    Exit 1 if any node label is below minimum threshold
    --log-level LEVEL   Logging verbosity (default: WARNING)

Required environment variables:
    NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

Exit codes:
    0  Stats retrieved (and minimums passed if --check-minimums)
    1  Connection error or minimum check failure
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger("extract_neo4j_stats")

# ---------------------------------------------------------------------------
# Make scripts/ importable
# ---------------------------------------------------------------------------
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

# Load .env if present (no-op when python-dotenv is not installed)
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(override=False)
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Expected minimum node counts (from approved plan)
# ---------------------------------------------------------------------------

EXPECTED_MINIMUMS: Dict[str, int] = {
    "Vulnerability":         250_000,
    "Platform":               50_000,
    "AttackPattern":             500,
    "Technique":                 350,  # current ATT&CK v16 active (non-revoked/deprecated)
    "SubTechnique":              400,
    "Tactic":                     14,
    "Weakness":                  900,
    # spec 1.2.0 decision extension (ADR-0003). Floors well under the offline
    # expectation on the 2026-09 raw data (docs/spec-v1.2-deltas.md: KEV 1,711,
    # EPSS 368,628 for one score date, SSVC 182,047).
    "KevEntry":                1_500,
    "EpssScore":             300_000,
    "SsvcDecision":          150_000,
    # spec 1.2.1 ATLAS module (ADR-0004); release 2026.09: 16 / 120 / 88 / 40
    "AtlasTactic":                14,
    "AtlasTechnique":            100,
    "AtlasSubTechnique":          70,
    "AtlasMitigation":            30,
}

# ---------------------------------------------------------------------------
# Node labels to count
# ---------------------------------------------------------------------------

NODE_LABELS = [
    "Platform",
    "PlatformConfiguration",
    "Vulnerability",
    "Reference",
    "Score",
    "Weakness",
    "AttackPattern",
    "Technique",
    "SubTechnique",
    "Tactic",
    "DefensiveTechnique",
    "DetectionAnalytic",
    "DeceptionTechnique",
    "EngagementConcept",
    "Consequence",
    "BuildMetadata",
    # spec 1.2 (decision extension, ATLAS module)
    "KevEntry",
    "EpssScore",
    "SsvcDecision",
    "AtlasTactic",
    "AtlasTechnique",
    "AtlasSubTechnique",
    "AtlasMitigation",
]

# ---------------------------------------------------------------------------
# Relationship types to count
# ---------------------------------------------------------------------------

REL_TYPES = [
    "MATCHES_PLATFORM",
    "AFFECTS",
    "REFERENCES",
    "HAS_SCORE",
    "CAUSED_BY",
    "DEMONSTRATED_BY",
    "IMPLEMENTS",
    "PART_OF",
    "SUBTECHNIQUE_OF",
    "MITIGATED_BY",
    "DETECTED_BY",
    "COUNTERED_BY",
    "DISRUPTS",
    "HAS_CONSEQUENCE",
    # spec 1.2 (decision extension, ATLAS module); ATLAS never writes PART_OF /
    # SUBTECHNIQUE_OF, so the two counts above stay ATT&CK-only (v1.2.1)
    "HAS_KEV_ENTRY",
    "HAS_EPSS",
    "HAS_SSVC",
    "ACHIEVES",
    "SPECIALIZES",
    "MITIGATES",
    "ADAPTED_FROM",
]

# ---------------------------------------------------------------------------
# Freshness queries (label → cypher for max date field)
# ---------------------------------------------------------------------------

FRESHNESS_QUERIES: Dict[str, str] = {
    "Vulnerability":   "MATCH (n:Vulnerability) RETURN max(n.lastModified) AS v",
    "Platform":        "MATCH (n:Platform) RETURN max(n.lastModified) AS v",
    "Weakness":        "MATCH (n:Weakness) RETURN n.cweId AS v LIMIT 1",
}


# ---------------------------------------------------------------------------
# Stats collection
# ---------------------------------------------------------------------------

def collect_stats(writer) -> Dict[str, Any]:
    """Query Neo4j for node counts, rel counts, and freshness dates."""
    stats: Dict[str, Any] = {
        "nodes": {},
        "relationships": {},
        "freshness": {},
        "errors": [],
    }

    # Node counts
    for label in NODE_LABELS:
        cypher = f"MATCH (n:{label}) RETURN count(n) AS c"
        result = writer.read_one(cypher)
        stats["nodes"][label] = result if result is not None else -1

    # Relationship counts
    for rel_type in REL_TYPES:
        cypher = f"MATCH ()-[r:{rel_type}]->() RETURN count(r) AS c"
        result = writer.read_one(cypher)
        stats["relationships"][rel_type] = result if result is not None else -1

    # Freshness dates
    for label, cypher in FRESHNESS_QUERIES.items():
        result = writer.read_one(cypher)
        stats["freshness"][label] = result

    return stats


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _print_json(stats: Dict[str, Any]) -> None:
    print(json.dumps(stats, indent=2, default=str))


def _print_pretty(stats: Dict[str, Any], minimums: Dict[str, int]) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box

        console = Console()

        # Node table
        node_table = Table(
            title="Node Counts",
            box=box.SIMPLE_HEAVY,
            show_header=True,
        )
        node_table.add_column("Label", style="cyan", min_width=24)
        node_table.add_column("Count", justify="right", style="white")
        node_table.add_column("Min", justify="right", style="dim")
        node_table.add_column("Status", justify="center")

        for label, count in stats["nodes"].items():
            minimum = minimums.get(label, 0)
            min_str = str(minimum) if minimum else "-"
            if minimum and count < minimum:
                status = "[red]BELOW[/red]"
            elif minimum:
                status = "[green]OK[/green]"
            else:
                status = "-"
            count_str = f"{count:,}" if count >= 0 else "[red]ERR[/red]"
            node_table.add_row(label, count_str, min_str, status)

        console.print(node_table)

        # Relationship table
        rel_table = Table(
            title="Relationship Counts",
            box=box.SIMPLE_HEAVY,
            show_header=True,
        )
        rel_table.add_column("Type", style="cyan", min_width=24)
        rel_table.add_column("Count", justify="right", style="white")

        for rel_type, count in stats["relationships"].items():
            count_str = f"{count:,}" if count >= 0 else "[red]ERR[/red]"
            rel_table.add_row(rel_type, count_str)

        console.print(rel_table)

        # Freshness
        if stats.get("freshness"):
            console.print("\n[bold]Freshness[/bold]")
            for label, date in stats["freshness"].items():
                console.print(f"  {label}: {date}")

    except ImportError:
        # Fallback to plain text
        _print_plain(stats, minimums)


def _print_plain(stats: Dict[str, Any], minimums: Dict[str, int]) -> None:
    print("\n--- Node Counts ---")
    for label, count in stats["nodes"].items():
        minimum = minimums.get(label)
        flag = ""
        if minimum and count < minimum:
            flag = f"  [BELOW minimum {minimum}]"
        elif minimum:
            flag = "  [OK]"
        print(f"  {label:<28} {count:>10,}{flag}")

    print("\n--- Relationship Counts ---")
    for rel_type, count in stats["relationships"].items():
        print(f"  {rel_type:<28} {count:>10,}")

    if stats.get("freshness"):
        print("\n--- Freshness ---")
        for label, date in stats["freshness"].items():
            print(f"  {label}: {date}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract KGCS graph statistics from Neo4j"
    )
    parser.add_argument(
        "--pretty", action="store_true",
        help="Print a formatted table (requires rich)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output raw JSON to stdout",
    )
    parser.add_argument(
        "--check-minimums", action="store_true",
        help="Exit 1 if any label count is below the expected minimum",
    )
    parser.add_argument(
        "--log-level", default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.log_level)

    for var in ("NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD"):
        if not os.environ.get(var):
            logger.error(f"Required environment variable not set: {var}")
            return 1

    try:
        from etl import Neo4jWriter
    except ImportError:
        print("Cannot import Neo4jWriter — run from project root", file=sys.stderr)
        return 1

    try:
        with Neo4jWriter() as writer:
            stats = collect_stats(writer)
    except Exception as exc:
        print(f"Neo4j connection failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        _print_json(stats)
    elif args.pretty:
        _print_pretty(stats, EXPECTED_MINIMUMS)
    else:
        _print_plain(stats, EXPECTED_MINIMUMS)

    if args.check_minimums:
        failures = []
        for label, minimum in EXPECTED_MINIMUMS.items():
            count = stats["nodes"].get(label, 0)
            if count < minimum:
                failures.append(
                    f"{label}: {count:,} < {minimum:,} (minimum)"
                )
        if failures:
            print("\nMinimum check FAILED:", file=sys.stderr)
            for f in failures:
                print(f"  {f}", file=sys.stderr)
            return 1
        else:
            print("\nMinimum check PASSED.", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
