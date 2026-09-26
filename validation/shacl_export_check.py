"""
SHACL check of exported Weakness / AttackPattern / Consequence / BuildMetadata nodes.

Exports the nodes the spec 1.1.0 loaders write to RDF, using the OWL
property names (naming layers: shapes/README.md), and validates them with
pySHACL against the pinned shapes in spec/shapes/ (cwe, capec, core, build).

Consequence nodes are typed by topology (ADR-0001): cwe:Consequence under a
Weakness, capec:Consequence under an AttackPattern. Like the spec harness,
the check runs with inference="none"; no alignment closure is needed because
the export asserts the core classes directly.

Sources:
    --from-neo4j (default)  read-only queries on NEO4J_DATABASE; set it in
                            the SAME command and check the log line
                            "Neo4jWriter connected ... (database=...)".
    --from-raw PATH         the loaders' own transforms over data/raw, no Neo4j

Usage (from the repo root):
    $env:NEO4J_DATABASE='kgcs-q-smoke'; python validation/shacl_export_check.py
    python validation/shacl_export_check.py --from-raw data/raw --limit 50

Exit 0 when the export conforms, 1 otherwise.
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from rdflib import RDF, XSD, Graph, Literal, Namespace, URIRef  # noqa: E402

logger = logging.getLogger("shacl_export_check")

KGCS = Namespace("http://www.motherhacker.me/kgcs/ontology/core#")
CWE = Namespace("http://www.motherhacker.me/kgcs/ontology/cwe#")
CAPEC = Namespace("http://www.motherhacker.me/kgcs/ontology/capec#")
BUILD = Namespace("http://www.motherhacker.me/kgcs/ontology/build#")
EX = "urn:kgcs:export:"

SHAPE_FILES = ("cwe.shacl.ttl", "capec.shacl.ttl", "core.shacl.ttl", "build.shacl.ttl")

# graph property -> OWL property (cwe-enrichment-to-owl-v1.0.md, consequences-to-owl-v1.0.md)
WEAKNESS_PROPS = {
    "cweId": CWE.cweId,
    "abstraction": CWE.abstraction,
    "description": CWE.description,
    "extendedDescription": CWE.extended_description,
    "mappingUsage": CWE.mapping_usage,
    "mappingReasons": CWE.mapping_reasons,
    "structure": CWE.structure,
    "status": CWE.status,
    "alternateTerms": CWE.alternate_terms,
    "likelihoodOfExploit": CWE.likelihood_of_exploit,
    "functionalAreas": CWE.functional_areas,
    "affectedResources": CWE.affected_resources,
    "modesOfIntroduction": CWE.modes_of_introduction,
    "ordinalities": CWE.ordinalities,
}
ATTACK_PATTERN_PROPS = {
    "capecId": CAPEC.capecId,
    "name": CAPEC.name,
    "abstraction": CAPEC.abstraction,
    "status": CAPEC.status,
    "attackLikelihood": CAPEC.attackLikelihood,
    "typicalSeverity": CAPEC.typicalSeverity,
}
CONSEQUENCE_PROPS = {
    "Weakness": (CWE.Consequence, CWE.has_consequence, {
        "consequenceId": CWE.consequence_id,
        "scopes": CWE.scope,
        "impacts": CWE.technical_impact,
        "likelihood": CWE.consequence_likelihood,
        "note": CWE.consequence_note,
    }),
    "AttackPattern": (CAPEC.Consequence, CAPEC.hasConsequence, {
        "consequenceId": CAPEC.consequence_id,
        "scopes": CAPEC.scope,
        "impacts": CAPEC.technicalImpact,
        "likelihood": CAPEC.consequenceLikelihood,
        "note": CAPEC.consequence_note,
    }),
}
BUILD_PROPS = {
    "specVersion": BUILD.spec_version,
    "pipelineCommit": BUILD.pipeline_commit,
    "sourceSnapshots": BUILD.source_snapshot,
}


def _add_props(g: Graph, node: URIRef, row: Dict, mapping: Dict) -> None:
    for key, prop in mapping.items():
        value = row.get(key)
        if value is None:
            continue
        for v in value if isinstance(value, list) else [value]:
            g.add((node, prop, Literal(v)))   # plain = xsd:string; sh:in compares terms


def to_rdf(
    weaknesses: Iterable[Dict],
    attack_patterns: Iterable[Dict],
    consequences: Iterable[Tuple[str, str, Dict]],
    demonstrated_by: Iterable[Tuple[str, str]] = (),
    build: Optional[Dict] = None,
) -> Graph:
    """RDF export. consequences: (parent label, parent id, consequence row)."""
    g = Graph()
    g.bind("kgcs", KGCS)
    g.bind("cwe", CWE)
    g.bind("capec", CAPEC)
    g.bind("build", BUILD)
    for w in weaknesses:
        node = URIRef(f"{EX}{w['cweId']}")
        g.add((node, RDF.type, KGCS.Weakness))
        _add_props(g, node, w, WEAKNESS_PROPS)
    for ap in attack_patterns:
        node = URIRef(f"{EX}{ap['capecId']}")
        g.add((node, RDF.type, KGCS.AttackPattern))
        _add_props(g, node, ap, ATTACK_PATTERN_PROPS)
    for parent_label, parent_id, c in consequences:
        cls, edge, mapping = CONSEQUENCE_PROPS[parent_label]
        node = URIRef(f"{EX}{c['consequenceId']}")
        g.add((node, RDF.type, cls))
        g.add((URIRef(f"{EX}{parent_id}"), edge, node))
        _add_props(g, node, c, mapping)
    for cwe_id, capec_id in demonstrated_by:
        g.add((URIRef(f"{EX}{cwe_id}"), KGCS.exploited_by, URIRef(f"{EX}{capec_id}")))
    if build:
        node = URIRef(f"{EX}build")
        g.add((node, RDF.type, BUILD.BuildMetadata))
        _add_props(g, node, build, BUILD_PROPS)
        g.add((node, BUILD.build_timestamp,
               Literal(build["buildTimestamp"], datatype=XSD.dateTime)))
    return g


def shapes_graph(shapes_dir: Path) -> Graph:
    g = Graph()
    for name in SHAPE_FILES:
        g.parse(str(shapes_dir / name), format="turtle")
    return g


def validate(data: Graph, shapes: Graph) -> Tuple[bool, List[str]]:
    import pyshacl

    conforms, results, _ = pyshacl.validate(
        data_graph=data, shacl_graph=shapes, inference="none",
        abort_on_first=False, allow_warnings=True, meta_shacl=False,
    )
    SH = Namespace("http://www.w3.org/ns/shacl#")
    messages = sorted(
        f"{results.value(r, SH.focusNode)}: {results.value(r, SH.resultMessage)}"
        for r in results.subjects(RDF.type, SH.ValidationResult)
    )
    return conforms, messages


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def from_raw(raw: Path, limit: Optional[int]):
    """Same rows the loaders send to Neo4j, built from data/raw."""
    from etl.build_metadata import build_record
    from etl.load_capec import _iter_capec_records
    from etl.load_cwe import _iter_weakness_records, select_cwe_xml

    weaknesses, aps, cons, demo = [], [], [], []
    for node, consequences in _iter_weakness_records(select_cwe_xml(raw / "CWE")):
        if limit is None or len(weaknesses) < limit:
            weaknesses.append(node)
            cons += [("Weakness", node["cweId"], c) for c in consequences]
    for ap, edges, _, consequences in _iter_capec_records(raw / "CAPEC" / "capec_latest.xml"):
        if limit is None or len(aps) < limit:
            aps.append(ap)
            cons += [("AttackPattern", ap["capecId"], c) for c in consequences]
            demo += [(e["cweId"], e["capecId"]) for e in edges]
    kept = {w["cweId"] for w in weaknesses}
    demo = [d for d in dict.fromkeys(demo) if d[0] in kept]   # the loader deduplicates too
    build, _, _ = build_record(raw)
    return weaknesses, aps, cons, demo, build


_Q_WEAKNESS = "MATCH (w:Weakness) RETURN properties(w) AS p ORDER BY w.cweId LIMIT $limit"
_Q_ATTACK_PATTERN = (
    "MATCH (ap:AttackPattern) RETURN properties(ap) AS p ORDER BY ap.capecId LIMIT $limit"
)
_Q_CONSEQUENCE = (
    "MATCH (p)-[:HAS_CONSEQUENCE]->(c:Consequence) WHERE coalesce(p.cweId, p.capecId) IN $ids "
    "RETURN CASE WHEN p:Weakness THEN 'Weakness' ELSE 'AttackPattern' END AS label, "
    "coalesce(p.cweId, p.capecId) AS parent, properties(c) AS c"
)
_Q_DEMONSTRATED_BY = (
    "MATCH (w:Weakness)-[:DEMONSTRATED_BY]->(ap:AttackPattern) "
    "WHERE w.cweId IN $cwe AND ap.capecId IN $capec RETURN w.cweId AS w, ap.capecId AS ap"
)
_Q_BUILD = (
    "MATCH (b:BuildMetadata) RETURN b.specVersion AS specVersion, "
    "toString(b.buildTimestamp) AS buildTimestamp, b.pipelineCommit AS pipelineCommit, "
    "b.sourceSnapshots AS sourceSnapshots"
)


def from_neo4j(limit: Optional[int]):
    from etl import Neo4jWriter

    n = limit if limit is not None else 1_000_000
    with Neo4jWriter() as writer:
        weaknesses = [r["p"] for r in writer.read_rows(_Q_WEAKNESS, {"limit": n})]
        aps = [r["p"] for r in writer.read_rows(_Q_ATTACK_PATTERN, {"limit": n})]
        cwe_ids = [w["cweId"] for w in weaknesses]
        capec_ids = [a["capecId"] for a in aps]
        cons = [
            (r["label"], r["parent"], r["c"])
            for r in writer.read_rows(_Q_CONSEQUENCE, {"ids": cwe_ids + capec_ids})
        ]
        demo = [
            (r["w"], r["ap"])
            for r in writer.read_rows(_Q_DEMONSTRATED_BY, {"cwe": cwe_ids, "capec": capec_ids})
        ]
        builds = writer.read_rows(_Q_BUILD)
    if len(builds) > 1:
        logger.error(f"{len(builds)} BuildMetadata nodes (expected at most one)")
    return weaknesses, aps, cons, demo, builds[0] if builds else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--from-raw", metavar="PATH", help="build rows from data/raw (no Neo4j)")
    parser.add_argument("--limit", type=int, help="first N Weakness / AttackPattern by id")
    parser.add_argument("--shapes-dir", default=str(_REPO / "spec" / "shapes"))
    parser.add_argument("--ttl-out", help="also write the export as Turtle")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(name)s: %(message)s")

    rows = from_raw(Path(args.from_raw), args.limit) if args.from_raw else from_neo4j(args.limit)
    weaknesses, aps, cons, demo, build = rows
    data = to_rdf(weaknesses, aps, cons, demo, build)
    if args.ttl_out:
        data.serialize(args.ttl_out, format="turtle")
    by_label: Dict[str, int] = {}
    for label, _, _ in cons:
        by_label[label] = by_label.get(label, 0) + 1
    logger.info(
        f"export: {len(weaknesses)} Weakness, {len(aps)} AttackPattern, "
        f"{by_label.get('Weakness', 0)} CWE Consequence, "
        f"{by_label.get('AttackPattern', 0)} CAPEC Consequence, "
        f"{len(demo)} DEMONSTRATED_BY, BuildMetadata {'yes' if build else 'no'}; "
        f"{len(data)} triples"
    )
    conforms, messages = validate(data, shapes_graph(Path(args.shapes_dir)))
    if conforms:
        logger.info(f"CONFORMS against {', '.join(SHAPE_FILES)} (pinned spec/shapes)")
        return 0
    logger.error(f"{len(messages)} SHACL results:")
    for m in messages[:50]:
        logger.error(f"  {m}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
