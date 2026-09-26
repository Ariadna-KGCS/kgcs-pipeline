"""
Post-load check of the 2026-09 graph-quality fixes against offline expectations.

Compares live edge counts with the v1.1 counts computed offline by
validation/expected_graph_deltas.py (same data/raw), and checks that no
IMPLEMENTS / MITIGATED_BY endpoint carries an ATT&CK id that is revoked or
deprecated in the loaded STIX bundles.

Read-only. The target database comes from NEO4J_DATABASE; set it in the SAME
command, and check the "Neo4jWriter connected ... (database=...)" log line:

    $env:NEO4J_DATABASE='kgcs-q-smoke'; python validation/check_graph_quality.py `
        --expected expected.json --edges PART_OF,IMPLEMENTS,MITIGATED_BY

Exit 0 when every selected check passes, 1 otherwise.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from etl import Neo4jWriter  # noqa: E402
from etl.attck_revocations import build_revocation_remap  # noqa: E402
from etl.load_attck import _find_attck_dir, _ordered_stix_files  # noqa: E402

_EDGE_COUNT = "MATCH ()-[r:{t}]->() RETURN count(r)"
_BRIDGE_ENDPOINTS = {
    "IMPLEMENTS": "MATCH (:AttackPattern)-[:IMPLEMENTS]->(t) RETURN collect(DISTINCT t.attackId)",
    "MITIGATED_BY": "MATCH (t)-[:MITIGATED_BY]->(:DefensiveTechnique) RETURN collect(DISTINCT t.attackId)",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--expected", required=True,
                        help="JSON written by expected_graph_deltas.py --json")
    parser.add_argument("--edges", default="PART_OF,IMPLEMENTS,MITIGATED_BY",
                        help="comma-separated edge types to compare (default: the Q5 bridges)")
    parser.add_argument("--raw-data-dir", default="data/raw")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s: %(message)s")

    expected = json.loads(Path(args.expected).read_text(encoding="utf-8"))["v1.1"]
    attck_dir = _find_attck_dir(Path(args.raw_data_dir))
    remap = build_revocation_remap(_ordered_stix_files(attck_dir))
    dead = set(remap.successors) | remap.deprecated | remap.revoked_without_successor

    ok = True
    with Neo4jWriter() as writer:
        for edge_type in [e.strip() for e in args.edges.split(",") if e.strip()]:
            live = writer.read_one(_EDGE_COUNT.format(t=edge_type))
            want = expected.get(edge_type)
            passed = live == want
            ok &= passed
            print(f"{'PASS' if passed else 'FAIL'}  {edge_type}: graph={live} expected={want}")
        for edge_type, cypher in _BRIDGE_ENDPOINTS.items():
            ids = set(writer.read_one(cypher) or [])
            bad = sorted(ids & dead)
            ok &= not bad
            print(f"{'PASS' if not bad else 'FAIL'}  {edge_type} endpoints on revoked/deprecated "
                  f"ATT&CK ids: {len(bad)}{' ' + str(bad[:10]) if bad else ''} "
                  f"({len(ids)} distinct endpoints checked)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
