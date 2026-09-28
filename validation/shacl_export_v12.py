"""
SHACL check of exported spec 1.2 nodes: decision leaves and the ATLAS module.

Exports KevEntry / EpssScore / SsvcDecision (with the owning Vulnerability
and its has_* edge) and the ATLAS nodes and edges (with the ATT&CK targets of
ADAPTED_FROM and one atlas:AdaptedFromStatement per edge) to RDF, using the
OWL property names of decision-extension-v1.0.owl and atlas-ontology-v1.1.owl,
and validates them with pySHACL against the pinned spec/shapes/decision.shacl.ttl
and atlas.shacl.ttl (inference "none", like shacl_export_check.py).

Only the two v1.2 shape files are loaded: the exported Vulnerability and
ATT&CK nodes carry just the identifiers the v1.2 shapes read (cve:cveId,
attack:attackId), so the v1.0 cve / attck shapes are out of scope here.

Sources:
    --from-neo4j (default)  read-only queries on NEO4J_DATABASE; set it in
                            the SAME command and check the log line
                            "Neo4jWriter connected ... (database=...)".
    --from-raw PATH         the loaders' own transforms over data/raw (no
                            Neo4j; every leaf is attached to a Vulnerability
                            with its cveId, ADAPTED_FROM after the remap)

Usage (from the repo root):
    $env:NEO4J_DATABASE='kgcs-q-smoke'; python validation/shacl_export_v12.py --limit 500
    python validation/shacl_export_v12.py --from-raw data/raw --limit 500

--limit N samples the first N nodes by key per decision label (the ATLAS
module is small and always exported whole). Exit 0 when the export conforms.
"""

import argparse
import logging
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from rdflib import RDF, XSD, BNode, Graph, Literal, Namespace, URIRef  # noqa: E402

logger = logging.getLogger("shacl_export_v12")

KGCS = Namespace("http://www.motherhacker.me/kgcs/ontology/core#")
CVE = Namespace("http://www.motherhacker.me/kgcs/ontology/cve#")
KEV = Namespace("http://www.motherhacker.me/kgcs/ontology/kev#")
EPSS = Namespace("http://www.motherhacker.me/kgcs/ontology/epss#")
SSVC = Namespace("http://www.motherhacker.me/kgcs/ontology/ssvc#")
ATTACK = Namespace("http://www.motherhacker.me/kgcs/ontology/attack#")
ATLAS = Namespace("http://www.motherhacker.me/kgcs/ontology/atlas#")
EX = "urn:kgcs:export:"

SHAPE_FILES = ("decision.shacl.ttl", "atlas.shacl.ttl")

_S, _D, _DT, _DEC, _INT = "string", "date", "dateTime", "decimal", "integer"
_TYPES = {_D: XSD.date, _DT: XSD.dateTime, _INT: XSD.integer}

# graph property -> (OWL property, lexical type)
KEV_PROPS = {
    "cveId": (KEV.cve_id, _S), "vendorProject": (KEV.vendor_project, _S),
    "product": (KEV.product, _S), "vulnerabilityName": (KEV.vulnerability_name, _S),
    "dateAdded": (KEV.date_added, _D), "shortDescription": (KEV.short_description, _S),
    "requiredAction": (KEV.required_action, _S), "dueDate": (KEV.due_date, _D),
    "knownRansomwareCampaignUse": (KEV.known_ransomware_campaign_use, _S),
    "forensicTriage": (KEV.forensic_triage, _S), "notes": (KEV.notes, _S),
    "cwes": (KEV.cwes, _S), "catalogVersion": (KEV.catalog_version, _S),
    "dateReleased": (KEV.date_released, _DT),
}
EPSS_PROPS = {
    "epssId": (EPSS.epss_id, _S), "cveId": (EPSS.cve_id, _S),
    "score": (EPSS.score, _DEC), "percentile": (EPSS.percentile, _DEC),
    "scoreDate": (EPSS.score_date, _D), "scoreTimestamp": (EPSS.score_timestamp, _DT),
    "modelVersion": (EPSS.model_version, _S),
}
SSVC_PROPS = {
    "ssvcId": (SSVC.ssvc_id, _S), "cveId": (SSVC.cve_id, _S), "version": (SSVC.version, _S),
    "timestamp": (SSVC.timestamp, _DT), "exploitation": (SSVC.exploitation, _S),
    "automatable": (SSVC.automatable, _S), "technicalImpact": (SSVC.technical_impact, _S),
    "role": (SSVC.role, _S), "source": (SSVC.source, _S), "sourceRole": (SSVC.source_role, _S),
}
ATLAS_PROPS = {
    "atlasId": (ATLAS.atlasId, _S), "name": (ATLAS.name, _S),
    "description": (ATLAS.description, _S), "createdDate": (ATLAS.createdDate, _D),
    "modifiedDate": (ATLAS.modifiedDate, _D), "matrixPosition": (ATLAS.matrixPosition, _INT),
    "maturity": (ATLAS.maturity, _S), "platforms": (ATLAS.platforms, _S),
    "categories": (ATLAS.categories, _S), "lifecyclePhases": (ATLAS.lifecyclePhases, _S),
}
DECISION = {   # label -> (class, has_* property, key, property map)
    "KevEntry": (KEV.KevEntry, KEV.has_kev_entry, "cveId", KEV_PROPS),
    "EpssScore": (EPSS.EpssScore, EPSS.has_epss, "epssId", EPSS_PROPS),
    "SsvcDecision": (SSVC.SsvcDecision, SSVC.has_ssvc, "ssvcId", SSVC_PROPS),
}
ATLAS_CLASSES = {
    "AtlasTactic": ATLAS.AtlasTactic, "AtlasTechnique": ATLAS.AtlasTechnique,
    "AtlasSubTechnique": ATLAS.AtlasSubTechnique, "AtlasMitigation": ATLAS.AtlasMitigation,
}
ATLAS_EDGES = {"ACHIEVES": ATLAS.achieves, "SPECIALIZES": ATLAS.specializes,
               "MITIGATES": ATLAS.mitigates}


def _literal(value: Any, kind: str) -> Literal:
    if kind == _DEC:   # verbatim decimal lexical form of the stored number
        return Literal(Decimal(repr(value)) if isinstance(value, float) else Decimal(str(value)),
                       datatype=XSD.decimal)
    if kind in _TYPES:
        return Literal(str(value), datatype=_TYPES[kind])
    return Literal(value)   # plain = xsd:string; sh:in compares terms


def _add_props(g: Graph, node: URIRef, row: Dict, mapping: Dict) -> None:
    for key, (prop, kind) in mapping.items():
        value = row.get(key)
        if value is None:
            continue
        for v in value if isinstance(value, list) else [value]:
            g.add((node, prop, _literal(v, kind)))


def _uri(kind: str, key: str) -> URIRef:
    return URIRef(f"{EX}{kind}/{key.replace(' ', '_')}")


def to_rdf(
    decisions: Dict[str, List[Dict]],
    atlas_nodes: Dict[str, List[Dict]],
    atlas_edges: Iterable[Tuple[str, str, str]],
    adapted_from: Iterable[Dict],
) -> Graph:
    """decisions: label -> leaf rows (with cveId); atlas_edges: (type, src, tgt);
    adapted_from: {src, tgt, tgtLabel, attackReferenceId, attackReferenceUrl, sourceField?}."""
    g = Graph()
    for prefix, ns in (("kgcs", KGCS), ("cve", CVE), ("kev", KEV), ("epss", EPSS),
                       ("ssvc", SSVC), ("attack", ATTACK), ("atlas", ATLAS)):
        g.bind(prefix, ns)
    for label, rows in decisions.items():
        cls, edge, key, mapping = DECISION[label]
        for row in rows:
            vuln = _uri("cve", row["cveId"])
            g.add((vuln, RDF.type, KGCS.Vulnerability))
            g.add((vuln, CVE.cveId, Literal(row["cveId"])))
            node = _uri(label, row[key])
            g.add((node, RDF.type, cls))
            g.add((vuln, edge, node))
            _add_props(g, node, row, mapping)
    for label, rows in atlas_nodes.items():
        for row in rows:
            node = _uri("atlas", row["atlasId"])
            g.add((node, RDF.type, ATLAS_CLASSES[label]))
            _add_props(g, node, row, ATLAS_PROPS)
    for rtype, src, tgt in atlas_edges:
        g.add((_uri("atlas", src), ATLAS_EDGES[rtype], _uri("atlas", tgt)))
    for e in adapted_from:
        src, tgt = _uri("atlas", e["src"]), _uri("attack", e["tgt"])
        g.add((tgt, RDF.type, ATTACK.SubTechnique if e["tgtLabel"] == "SubTechnique" else ATTACK.Technique))
        g.add((tgt, ATTACK.attackId, Literal(e["tgt"])))
        g.add((src, ATLAS.adapted_from, tgt))
        st = BNode()
        g.add((st, RDF.type, ATLAS.AdaptedFromStatement))
        g.add((st, RDF.subject, src))
        g.add((st, RDF.predicate, ATLAS.adapted_from))
        g.add((st, RDF.object, tgt))
        g.add((st, ATLAS.sourceField, Literal(e.get("sourceField", "attack-reference"))))
        g.add((st, ATLAS.attackReferenceId, Literal(e["attackReferenceId"])))
        g.add((st, ATLAS.attackReferenceUrl, Literal(e["attackReferenceUrl"])))
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
        f"{results.value(r, SH.resultSeverity).split('#')[-1]} "
        f"{results.value(r, SH.focusNode)}: {results.value(r, SH.resultMessage)}"
        for r in results.subjects(RDF.type, SH.ValidationResult)
    )
    return conforms, messages


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def from_raw(raw: Path, limit: Optional[int]):
    """Rows the loaders would write, from data/raw (sampled by first N)."""
    import itertools

    from etl.attck_revocations import build_revocation_remap
    from etl.load_atlas import read_atlas, resolve_adapted_from, select_atlas_yaml, transform_atlas
    from etl.load_attck import _find_attck_dir, _ordered_stix_files
    from etl.load_epss import epss_files, iter_epss_rows
    from etl.load_kev import KEV_FILE, kev_records, read_catalog
    from etl.load_ssvc import iter_ssvc_file

    n = limit if limit is not None else 10 ** 9
    kev, _ = kev_records(read_catalog(raw / "KEV" / KEV_FILE))
    epss_path = epss_files(raw / "EPSS")[-1]
    epss = [rec for _, rec in itertools.islice(iter_epss_rows(epss_path), n)]
    ssvc: List[Dict] = []
    seen = set()
    for records, _ in iter_ssvc_file(raw / "CVE" / "nvdcve-2.0-2024.json"):
        for r in records:
            if r["ssvcId"] not in seen and len(ssvc) < n:
                seen.add(r["ssvcId"])
                ssvc.append(r)
    data = transform_atlas(read_atlas(select_atlas_yaml(raw / "ATLAS")))
    remap = build_revocation_remap(_ordered_stix_files(_find_attck_dir(raw)))
    adapted, _ = resolve_adapted_from(data["attack_refs"], remap)
    edges = ([("ACHIEVES", e["src"], e["tgt"]) for e in data["achieves"]]
             + [("SPECIALIZES", e["src"], e["tgt"]) for e in data["specializes"]]
             + [("MITIGATES", e["src"], e["tgt"]) for e in data["mitigates"]])
    return ({"KevEntry": kev[:n], "EpssScore": epss, "SsvcDecision": ssvc},
            data["nodes"], edges, adapted)


_Q_LEAF = (
    "MATCH (v:Vulnerability)-[:{edge}]->(d:{label}) "
    "RETURN properties(d) AS p ORDER BY d.{key} LIMIT $limit"
)
_Q_ATLAS_NODES = "MATCH (n:{label}) RETURN properties(n) AS p"
_Q_ATLAS_EDGES = (
    "MATCH (a)-[r:ACHIEVES|SPECIALIZES|MITIGATES]->(b) "
    "WHERE a.atlasId IS NOT NULL AND b.atlasId IS NOT NULL "
    "RETURN type(r) AS t, a.atlasId AS s, b.atlasId AS o"
)
_Q_ADAPTED = (
    "MATCH (a)-[r:ADAPTED_FROM]->(t) "
    "RETURN a.atlasId AS src, t.attackId AS tgt, "
    "CASE WHEN t:SubTechnique THEN 'SubTechnique' ELSE 'Technique' END AS tgtLabel, "
    "r.sourceField AS sourceField, r.attackReferenceId AS attackReferenceId, "
    "r.attackReferenceUrl AS attackReferenceUrl"
)
_EDGE_OF = {"KevEntry": "HAS_KEV_ENTRY", "EpssScore": "HAS_EPSS", "SsvcDecision": "HAS_SSVC"}


def from_neo4j(limit: Optional[int]):
    from etl import Neo4jWriter

    n = limit if limit is not None else 10 ** 9
    with Neo4jWriter() as writer:
        decisions = {
            label: [r["p"] for r in writer.read_rows(
                _Q_LEAF.format(edge=_EDGE_OF[label], label=label, key=key), {"limit": n})]
            for label, (_, _, key, _) in DECISION.items()
        }
        nodes = {label: [r["p"] for r in writer.read_rows(_Q_ATLAS_NODES.format(label=label))]
                 for label in ATLAS_CLASSES}
        edges = [(r["t"], r["s"], r["o"]) for r in writer.read_rows(_Q_ATLAS_EDGES)]
        adapted = writer.read_rows(_Q_ADAPTED)
    return decisions, nodes, edges, adapted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--from-raw", metavar="PATH", help="build rows from data/raw (no Neo4j)")
    parser.add_argument("--limit", type=int, default=500,
                        help="first N nodes per decision label (default 500; ATLAS always whole)")
    parser.add_argument("--shapes-dir", default=str(_REPO / "spec" / "shapes"))
    parser.add_argument("--ttl-out", help="also write the export as Turtle")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(name)s: %(message)s")

    rows = from_raw(Path(args.from_raw), args.limit) if args.from_raw else from_neo4j(args.limit)
    decisions, nodes, edges, adapted = rows
    data = to_rdf(decisions, nodes, edges, adapted)
    if args.ttl_out:
        data.serialize(args.ttl_out, format="turtle")
    logger.info(
        "export: " + ", ".join(f"{len(v)} {k}" for k, v in decisions.items()) + "; "
        + ", ".join(f"{len(v)} {k}" for k, v in nodes.items())
        + f"; {len(edges)} ATLAS-internal edges, {len(adapted)} ADAPTED_FROM; {len(data)} triples"
    )
    conforms, messages = validate(data, shapes_graph(Path(args.shapes_dir)))
    warnings = [m for m in messages if m.startswith("Warning")]
    if conforms:
        logger.info(f"CONFORMS against {', '.join(SHAPE_FILES)} (pinned spec/shapes); "
                    f"{len(warnings)} warnings")
        for m in warnings[:20]:
            logger.info(f"  {m}")
        return 0
    logger.error(f"{len(messages)} SHACL results:")
    for m in messages[:50]:
        logger.error(f"  {m}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
