#!/usr/bin/env python3
"""
Download the official schema definitions for KGCS upstream standards.

Fetches the XSD / JSON Schema files published by MITRE and NIST so the
raw-data contracts can be diffed when an upstream version bumps (e.g.
CWE 4.19.1 -> 4.20). Complements download.py, which fetches the data
but not the schemas.

Sources come from ingest_config.APIEndpoints — single source of truth
for URLs; add new schema endpoints there, then register them in
SCHEMA_SOURCES below.

Usage:
    python download_schemas.py                 # download all
    python download_schemas.py --standard cwe  # one standard
    python download_schemas.py --list          # show sources, no download

Output layout (mirrors data/raw/ naming):
    data/schemas/CWE/cwe_schema_latest.xsd
    data/schemas/CAPEC/ap_schema_latest.xsd
    data/schemas/CVE/cve_api_json_2.0.schema
    data/schemas/CPE/cpe_api_json_2.0.schema
    data/schemas/CPE-MATCH/cpematch_api_json_2.0.schema
    data/schemas/CVSS/cvss-v{2.0,3.0,3.1,4.0}.json
    data/schemas/ATTCK-STIX/stix2.0.zip   (OASIS STIX 2.0 JSON Schemas)
    data/schemas/KEV/known_exploited_vulnerabilities_schema.json
    data/schemas/SSVC/ssvc-v2.0.3.json

No machine schema exists for: d3fend (the OWL ontology is the schema),
car (YAML format defined in prose), shield, engage (plain JSON exports),
epss (CSV), atlas (format 6.0.0 has none).
See NO_SCHEMA below; --list prints the reasons.
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, List, Tuple

from ingest_config import APIEndpoints
from utils.http_client import HTTPClient

logger = logging.getLogger("download_schemas")

# standard -> list of (endpoint attribute on APIEndpoints, target subdir)
SCHEMA_SOURCES: Dict[str, List[Tuple[str, str]]] = {
    "cwe":      [("cwe_xsd", "CWE")],
    "capec":    [("capec_xsd", "CAPEC")],
    "cve":      [("cve_schema", "CVE")],
    "cpe":      [("cpe_schema", "CPE")],
    "cpematch": [("cpematch_schema", "CPE-MATCH")],
    "cvss": [
        ("cvss_v2_schema",  "CVSS"),
        ("cvss_v30_schema", "CVSS"),
        ("cvss_v31_schema", "CVSS"),
        ("cvss_v40_schema", "CVSS"),
    ],
    # OASIS STIX 2.0 JSON Schemas (branch zip: schemas cross-reference each
    # other with relative paths, so single files are not self-contained).
    "attck": [("stix_schemas_zip", "ATTCK-STIX")],
    # spec 1.2.0 decision extension / spec 1.2.1 ATLAS module
    "kev":   [("kev_schema", "KEV")],
    "ssvc":  [("ssvc_v203_schema", "SSVC")],
}

# Standards with no downloadable machine schema — documented so their absence
# from SCHEMA_SOURCES is a decision, not an omission.
NO_SCHEMA: Dict[str, str] = {
    "d3fend": "the OWL ontology IS the schema (already fetched by download.py "
              "as data/raw/D3FEND/d3fend.owl / d3fend.ttl)",
    "car":    "analytics are YAML with a prose-defined format "
              "(CONTRIBUTING.md in mitre-attack/car); no JSON/XSD published",
    "shield": "static JSON dumps from the retired SHIELD site; "
              "no schema published",
    "engage": "JSON exports from engage.mitre.org; no schema published",
    "epss":   "gzip CSV (#model_version/score_date comment line, then cve,epss,"
              "percentile); format documented at first.org/epss/data, no schema",
    "atlas":  "no schema for format 6.0.0 (dist/v6/ATLAS-<release>.yaml); "
              "atlas-data dist/schemas/atlas_output_schema.json describes the "
              "legacy `matrices` layout and does not apply",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Download upstream standard schema files (XSD / JSON Schema)",
    )
    parser.add_argument(
        "--standard",
        choices=sorted(SCHEMA_SOURCES) + ["all"],
        default="all",
        help="Standard to fetch schemas for (default: all)",
    )
    parser.add_argument(
        "--output-dir", default="data/schemas",
        help="Base output directory (default: data/schemas)",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List schema sources without downloading",
    )
    parser.add_argument(
        "--timeout", type=int, default=60,
        help="HTTP timeout in seconds (default: 60)",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    endpoints = APIEndpoints()
    standards = sorted(SCHEMA_SOURCES) if args.standard == "all" else [args.standard]

    if args.list:
        for std in standards:
            for attr, subdir in SCHEMA_SOURCES[std]:
                print(f"{std:10s} {subdir:10s} {getattr(endpoints, attr)}")
        for std, reason in sorted(NO_SCHEMA.items()):
            print(f"{std:10s} {'-':10s} (no machine schema: {reason})")
        return 0

    out_base = Path(args.output_dir)
    failures = 0
    with HTTPClient(timeout=args.timeout) as client:
        for std in standards:
            for attr, subdir in SCHEMA_SOURCES[std]:
                url = getattr(endpoints, attr)
                target_dir = out_base / subdir
                target_dir.mkdir(parents=True, exist_ok=True)
                target = target_dir / url.rstrip("/").rsplit("/", 1)[-1]
                logger.info(f"[{std}] {url} -> {target}")
                if client.download_file(url, str(target)):
                    logger.info(f"[{std}] OK ({target.stat().st_size} bytes)")
                else:
                    logger.error(f"[{std}] FAILED: {url}")
                    failures += 1

    if failures:
        logger.error(f"{failures} schema download(s) failed.")
        return 1
    logger.info("All schema downloads complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
