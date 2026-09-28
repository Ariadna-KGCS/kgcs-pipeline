"""
KGCS pipeline orchestrator — runs all ETL steps in strict load order.

Usage:
    python scripts/run_all_etl.py [options]

Options:
    --raw-data-dir PATH     Base directory for raw data (default: data/raw)
    --batch-size INT        Neo4j transaction batch size (default: 1000)
    --step NAME             Run only one named step (see STEPS below)
    --dry-run               Show what would run without touching Neo4j
    --skip-constraints      Skip init_constraints step (use if already applied)
    --log-level LEVEL       Logging level: DEBUG/INFO/WARNING/ERROR (default: INFO)

Exit codes:
    0  All steps completed successfully.
    1  One or more steps failed.

Required environment variables:
    NEO4J_URI       e.g. bolt://localhost:7687
    NEO4J_USER      e.g. neo4j
    NEO4J_PASSWORD  database password
"""

import argparse
import logging
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Make scripts/ importable when run directly
# ---------------------------------------------------------------------------
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from etl import Neo4jWriter
from etl.init_constraints import run_constraints
from etl.build_metadata import run_build_metadata
from etl.load_cpe    import CPELoader
from etl.load_cve    import CVELoader
from etl.load_cvss   import CVSSLoader
from etl.load_cwe    import CWELoader
from etl.load_capec  import CAPECLoader
from etl.load_attck  import ATTCKLoader
from etl.load_d3fend import D3FENDLoader
from etl.load_car    import CARLoader
from etl.load_shield import SHIELDLoader
from etl.load_engage import ENGAGELoader
from etl.load_kev    import KEVLoader
from etl.load_epss   import EPSSLoader
from etl.load_ssvc   import SSVCLoader
from etl.load_atlas  import ATLASLoader

logger = logging.getLogger("run_all_etl")


# ---------------------------------------------------------------------------
# Step registry
# ---------------------------------------------------------------------------

# (step_name, callable(writer, raw_data_dir, batch_size) → result_dict or None)
# constraints step uses a different signature (just writer)

def _run_constraints(writer, raw_data_dir: Path, batch_size: int):
    return run_constraints(writer)


def _run_build_metadata(writer, raw_data_dir: Path, batch_size: int):
    return run_build_metadata(writer, raw_data_dir)


def _make_loader(cls):
    def _runner(writer, raw_data_dir: Path, batch_size: int):
        loader = cls(
            raw_data_dir=str(raw_data_dir),
            writer=writer,
            batch_size=batch_size,
        )
        return loader.run()
    return _runner


STEPS = [
    ("constraints",  _run_constraints),
    ("cpe",          _make_loader(CPELoader)),
    ("cve",          _make_loader(CVELoader)),
    ("cvss",         _make_loader(CVSSLoader)),
    # Decision extension (spec 1.2.0, ADR-0003): leaves on Vulnerability,
    # outside the chain; they only need the Vulnerability nodes.
    ("kev",          _make_loader(KEVLoader)),
    ("epss",         _make_loader(EPSSLoader)),
    ("ssvc",         _make_loader(SSVCLoader)),
    ("cwe",          _make_loader(CWELoader)),
    ("capec",        _make_loader(CAPECLoader)),
    ("attck",        _make_loader(ATTCKLoader)),
    # ATLAS module (spec 1.2.1, ADR-0004): parallel matrix; ADAPTED_FROM
    # needs the ATT&CK nodes.
    ("atlas",        _make_loader(ATLASLoader)),
    ("d3fend",       _make_loader(D3FENDLoader)),
    ("car",          _make_loader(CARLoader)),
    ("shield",       _make_loader(SHIELDLoader)),
    ("engage",       _make_loader(ENGAGELoader)),
    # Postscript (spec 1.1.0): records spec, commit and source releases.
    ("build_metadata", _run_build_metadata),
]

STEP_NAMES = [name for name, _ in STEPS]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="KGCS full ETL pipeline orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available steps: {', '.join(STEP_NAMES)}",
    )
    parser.add_argument(
        "--raw-data-dir", default="data/raw",
        help="Base directory for raw source data (default: data/raw)",
    )
    parser.add_argument(
        "--batch-size", type=int, default=1000,
        help="Rows per Neo4j transaction batch (default: 1000)",
    )
    parser.add_argument(
        "--step",
        choices=STEP_NAMES,
        help="Run only a single named step instead of the full pipeline",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show step order without connecting to Neo4j",
    )
    parser.add_argument(
        "--skip-constraints", action="store_true",
        help="Skip the constraints step (already applied to database)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
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

    raw_data_dir = Path(args.raw_data_dir).resolve()
    batch_size   = args.batch_size

    # Determine which steps to run
    if args.step:
        selected = [(name, fn) for name, fn in STEPS if name == args.step]
    else:
        selected = list(STEPS)
        if args.skip_constraints:
            selected = [(n, f) for n, f in selected if n != "constraints"]

    if args.dry_run:
        logger.info("DRY RUN — would execute the following steps:")
        for name, _ in selected:
            logger.info(f"  {name}")
        logger.info(f"  raw_data_dir={raw_data_dir}  batch_size={batch_size}")
        return 0

    # Validate environment
    for var in ("NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD"):
        if not os.environ.get(var):
            logger.error(f"Required environment variable not set: {var}")
            return 1

    # Run pipeline
    overall_success = True

    with Neo4jWriter() as writer:
        total_steps = len(selected)
        for step_idx, (name, fn) in enumerate(selected, 1):
            logger.info(f"{'='*60}")
            logger.info(f"STEP {step_idx}/{total_steps}: {name}")
            logger.info(f"{'='*60}")
            try:
                result = fn(writer, raw_data_dir, batch_size)
            except Exception as exc:
                logger.error(f"[{name}] Unhandled exception: {exc}")
                overall_success = False
                break

            if result is None:
                logger.warning(f"[{name}] Step returned None — treating as success")
                continue

            success = result.get("success", False)
            errors  = result.get("errors", [])
            stats   = result.get("stats", {})

            if success:
                logger.info(f"[{name}] SUCCESS — stats: {stats}")
            else:
                logger.error(f"[{name}] FAILED — errors: {errors}")
                overall_success = False
                break   # Hard stop on first failure (ETL is causally ordered)

    if overall_success:
        logger.info("Pipeline complete — all steps succeeded.")
        return 0
    else:
        logger.error("Pipeline FAILED — see errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
