"""
Offline expected edge counts for the 2026-09 graph-quality fixes (session Q5).

Computes, from data/raw only (no Neo4j), the edge counts the loaders write
for the edge types touched by the fixes, in two modes:

  v1.0  the pre-fix loader rules (kgcs-pipeline pinned to spec 1.0.0):
        PART_OF by Tactic.phaseName, no revoked-by remap, CAUSED_BY without
        provenance. Must reproduce the kgcs-demo counts of 2026-09-26.
  v1.1  the fixed loaders (spec 1.1.0), using their own transform
        functions: PART_OF by same-bundle tactic attackId, the shared
        revoked-by remap on IMPLEMENTS and MITIGATED_BY, and CAUSED_BY
        provenance lists.

Every count applies the loaders' MATCH semantics: an edge is counted only
when both endpoint nodes are created by the load (Vulnerability nodes: every
CVE id in the NVD files, as load_cve.py MERGEs them all).

Usage (from the repo root):
    python validation/expected_graph_deltas.py                  # both modes, markdown to stdout
    python validation/expected_graph_deltas.py --skip-cve       # skip the ~3 GB NVD scan
    python validation/expected_graph_deltas.py --json out.json
    python validation/expected_graph_deltas.py --check-v10      # exit 1 if v1.0 != kgcs-demo
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Set, Tuple

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from etl.attck_revocations import (  # noqa: E402
    DEPRECATED,
    REMAPPED,
    UNRESOLVED,
    RevocationRemapBuilder,
    apply_remap,
)
from etl.load_attck import (  # noqa: E402
    _capec_ids,
    _capec_taxonomy_pairs,
    _external_id,
    _find_attck_dir,
    _load_stix_bundle,
    _normalize_attack_id_to_technique,
    _ordered_stix_files,
    _part_of_pairs,
    _resolve_implements,
)
from etl.load_capec import _iter_capec_records  # noqa: E402
from etl.load_cwe import (  # noqa: E402
    _NewestRecordRule,
    _aggregate_caused_by,
    _iter_cve_weaknesses,
    _iter_weakness_nodes,
    _ordered_cve_files,
)
from etl.load_d3fend import _build_d3fend_id_lookup, _extract_mappings  # noqa: E402

# kgcs-demo edge counts, 2026-09-26 (kgcs-research working notes: ATT&CK §"Què
# hi ha carregat avui", CAPEC idem, D3FEND idem, CWE idem; identical to
# experiments/2026-09-26-snapshot/).
KGCS_DEMO_2026_09_26 = {
    "PART_OF": 1054,
    "SUBTECHNIQUE_OF": 540,
    "IMPLEMENTS": 235,
    "MITIGATED_BY": 3010,
    "CAUSED_BY": 331107,
    "DEMONSTRATED_BY": 1212,
    "CHILD_OF": 519,
}


# ---------------------------------------------------------------------------
# Source readers (shared by both modes)
# ---------------------------------------------------------------------------

def read_attck(raw: Path) -> Dict:
    """Mirror ATTCKLoader.run's accumulation over the three bundles."""
    attck_dir = _find_attck_dir(raw)
    if attck_dir is None:
        raise SystemExit(f"ATT&CK bundles not found under {raw}")
    builder = RevocationRemapBuilder()
    tactics: Dict[str, Dict] = {}            # attackId -> {phaseName, domain}
    techniques: Dict[str, Dict] = {}         # attackId -> {domain, phases_v10, capec}
    subtechniques: Set[str] = set()
    stix_to_attack: Dict[str, str] = {}
    sub_of: Set[Tuple[str, str]] = set()
    part_of_v11: Set[Tuple[str, str]] = set()
    part_of_unresolved = 0
    dead_capec_refs: Set[Tuple[str, str]] = set()
    kill_chain_phase_entries = 0

    for path in _ordered_stix_files(attck_dir):
        bundle = _load_stix_bundle(path, builder)
        domain = bundle["domain"]
        dead_capec_refs.update(bundle["dead_capec_refs"])
        pairs, unresolved = _part_of_pairs(bundle)
        part_of_v11 |= pairs
        part_of_unresolved += unresolved

        for stix_id, obj in bundle["tactics"].items():
            aid = _external_id(obj, "mitre-attack")
            if not aid:
                continue
            stix_to_attack[stix_id] = aid
            tactics.setdefault(aid, {
                "phaseName": obj.get("x_mitre_shortname", ""), "domain": domain,
            })
        for stix_id, obj in bundle["techniques"].items():
            aid = _external_id(obj, "mitre-attack")
            if not aid:
                continue
            stix_to_attack[stix_id] = aid
            kill_chain_phase_entries += len(obj.get("kill_chain_phases", []))
            phases = []
            for kcp in obj.get("kill_chain_phases", []):
                if kcp.get("kill_chain_name", "").startswith("mitre-"):
                    phase = kcp.get("phase_name", "")
                    if phase and phase not in phases:
                        phases.append(phase)
            techniques.setdefault(aid, {
                "domain": domain, "phases_v10": phases, "capec": _capec_ids(obj),
            })
        for stix_id, obj in bundle["subtechniques"].items():
            aid = _external_id(obj, "mitre-attack")
            if aid:
                stix_to_attack[stix_id] = aid
                subtechniques.add(aid)
        for rel in bundle["sub_of_rels"]:
            s = stix_to_attack.get(rel["source_ref"])
            t = stix_to_attack.get(rel["target_ref"])
            if s and t:
                sub_of.add((s, t))

    return {
        "tactics": tactics,
        "techniques": techniques,
        "subtechniques": subtechniques,
        "sub_of": sub_of,
        "part_of_v11": part_of_v11,
        "part_of_unresolved": part_of_unresolved,
        "kill_chain_phase_entries": kill_chain_phase_entries,
        "dead_capec_refs": dead_capec_refs,
        "remap": builder.build(),
    }


def read_capec(raw: Path, weakness_ids: Set[str], batch_size: int) -> Dict:
    """CAPEC nodes and edges, replaying CAPECLoader.run's flush order.

    CAPECLoader flushes nodes and edges together whenever any buffer reaches
    batch_size. A CHILD_OF whose parent appears later in the XML than the
    flush finds no parent node and is lost (pre-existing behaviour, unchanged
    by Q5); "CHILD_OF_complete" is the count without that loss.
    """
    xml_path = raw / "CAPEC" / "capec_latest.xml"
    patterns: Set[str] = set()
    demonstrated: Set[Tuple[str, str]] = set()
    child_all: Set[Tuple[str, str]] = set()
    child_loaded: Set[Tuple[str, str]] = set()
    buf_ap: List[str] = []
    buf_rel = 0
    buf_child: List[Tuple[str, str]] = []

    def flush() -> None:
        nonlocal buf_rel
        patterns.update(buf_ap)
        buf_ap.clear()
        buf_rel = 0
        child_loaded.update(c for c in buf_child if c[0] in patterns and c[1] in patterns)
        buf_child.clear()

    for ap, edges, children in _iter_capec_records(xml_path):
        pairs = [(c["childCapecId"], c["parentCapecId"]) for c in children]
        demonstrated.update((e["cweId"], e["capecId"]) for e in edges)
        child_all.update(pairs)
        buf_ap.append(ap["capecId"])
        buf_rel += len(edges)
        buf_child.extend(pairs)
        if len(buf_ap) >= batch_size or buf_rel >= batch_size or len(buf_child) >= batch_size:
            flush()
    flush()
    return {
        "patterns": patterns,
        "taxonomy_refs": _capec_taxonomy_pairs(xml_path),
        "DEMONSTRATED_BY": {p for p in demonstrated if p[0] in weakness_ids and p[1] in patterns},
        "CHILD_OF": child_loaded,
        "CHILD_OF_complete": {p for p in child_all if p[0] in patterns and p[1] in patterns},
    }


def read_d3fend(raw: Path) -> Tuple[Set[str], List[Tuple[str, str]]]:
    d = raw / "D3FEND"
    id_lookup = _build_d3fend_id_lookup(d / "d3fend.json")
    def_techs, mitigated_by, _ = _extract_mappings(d / "d3fend-full-mappings.json", id_lookup)
    return set(def_techs), [(r["attackId"], r["d3fendId"]) for r in mitigated_by]


def read_weakness_ids(raw: Path) -> Set[str]:
    candidates = sorted((raw / "CWE").glob("cwec_v*.xml"))
    if not candidates:
        raise SystemExit(f"no cwec_v*.xml under {raw / 'CWE'}")
    # same numeric-version pick as CWELoader
    import re

    def key(p: Path):
        m = re.search(r"cwec_v([\d.]+)\.xml$", p.name)
        return tuple(int(x) for x in m.group(1).split(".") if x.isdigit()) if m else (0,)

    xml_path = sorted(candidates, key=key)[-1]
    return {rec["cweId"] for rec in _iter_weakness_nodes(xml_path)}


# ---------------------------------------------------------------------------
# CAUSED_BY (one NVD pass computes both modes)
# ---------------------------------------------------------------------------

def caused_by(raw: Path, weakness_ids: Set[str]) -> Dict:
    pairs_v10: Set[Tuple[str, str]] = set()
    newest = _NewestRecordRule()
    edges_v11: Dict[Tuple[str, str], Dict] = {}   # last SET wins, as in Neo4j
    role_entries: Counter = Counter()
    edge_role_sets: Counter = Counter()
    multi_source_edges = 0
    unequal = 0
    type_entries: Counter = Counter()

    for path in _ordered_cve_files(raw / "CVE"):
        print(f"  CAUSED_BY: reading {path.name}", file=sys.stderr)
        is_modified = path.name == "nvdcve-2.0-modified.json"
        for cve_id, last_modified, entries in _iter_cve_weaknesses(path):
            records, _, _ = _aggregate_caused_by(cve_id, entries, weakness_ids)
            pairs_v10.update((r["cveId"], r["cweId"]) for r in records)
            if is_modified:
                records = newest.remember(cve_id, last_modified, records)
            else:
                records = newest.admit(cve_id, last_modified, records)
            for rec in records:
                edges_v11[(rec["cveId"], rec["cweId"])] = rec

    for rec in edges_v11.values():
        if not (len(rec["sources"]) == len(rec["sourceRoles"]) == len(rec["types"]) > 0):
            unequal += 1
        role_entries.update(rec["sourceRoles"])
        type_entries.update(rec["types"])
        edge_role_sets["+".join(sorted(set(rec["sourceRoles"])))] += 1
        if len(set(rec["sources"])) > 1:
            multi_source_edges += 1

    return {
        "v1.0": len(pairs_v10),
        "v1.1": len(edges_v11),
        "superseded_by_newer": newest.superseded,
        "pairs_only_in_older": newest.pairs_only_in_older,
        "unequal_list_edges": unequal,
        "role_entries": dict(role_entries),
        "type_entries": dict(type_entries),
        "edges_by_role_set": dict(sorted(edge_role_sets.items())),
        "multi_source_edges": multi_source_edges,
    }


# ---------------------------------------------------------------------------
# Mode computations
# ---------------------------------------------------------------------------

def compute(raw: Path, skip_cve: bool, batch_size: int = 1000) -> Dict:
    weakness_ids = read_weakness_ids(raw)
    capec = read_capec(raw, weakness_ids, batch_size)
    attck = read_attck(raw)
    def_techs, d3f_pairs = read_d3fend(raw)

    tactics = attck["tactics"]
    techniques = attck["techniques"]
    live_techniques = set(techniques)
    live_attack_nodes = live_techniques | attck["subtechniques"]
    remap = attck["remap"]
    patterns = capec["patterns"]

    # ---------------- v1.0 ----------------
    tactics_by_phase: Dict[str, List[str]] = {}
    for aid, t in tactics.items():
        tactics_by_phase.setdefault(t["phaseName"], []).append(aid)
    part_of_v10 = {
        (tid, ta)
        for tid, t in techniques.items()
        for phase in t["phases_v10"]
        for ta in tactics_by_phase.get(phase, [])
    }
    cross = Counter(
        f"{techniques[t]['domain']}->{tactics[ta]['domain']}"
        for t, ta in part_of_v10
        if techniques[t]["domain"] != tactics[ta]["domain"]
    )
    impl_v10_refs = {(c, tid) for tid, t in techniques.items() for c in t["capec"]}
    impl_v10_refs |= {
        (c, _normalize_attack_id_to_technique(a)) for c, a in capec["taxonomy_refs"]
    }
    implements_v10 = {
        (c, t) for c, t in impl_v10_refs if c in patterns and t in live_techniques
    }
    mitigated_v10 = {
        (a, d) for a, d in d3f_pairs if a in live_attack_nodes and d in def_techs
    }

    # ---------------- v1.1 ----------------
    part_of_v11 = {
        (t, ta) for t, ta in attck["part_of_v11"] if t in live_techniques and ta in tactics
    }
    impl_refs = set(capec["taxonomy_refs"]) | impl_v10_refs_stix(techniques) | attck["dead_capec_refs"]
    impl_pairs, impl_counts = _resolve_implements(impl_refs, remap, live_techniques)
    implements_v11 = {(c, t) for c, t in impl_pairs if c in patterns}
    mit_pairs, mit_counts = apply_remap(d3f_pairs, remap, target_index=0)
    mitigated_v11 = {(a, d) for a, d in mit_pairs if a in live_attack_nodes and d in def_techs}

    techniques_without_part_of = sorted(live_techniques - {t for t, _ in part_of_v11})
    cross_v11 = sum(
        1 for t, ta in part_of_v11 if techniques[t]["domain"] != tactics[ta]["domain"]
    )

    def remap_detail(refs, index):
        detail = {"remapped": {}, "deprecated": set(), "unresolved": set()}
        for ref in refs:
            cited = ref[index]
            status, target = remap.resolve(cited)
            if status == REMAPPED:
                detail["remapped"][cited] = target
            elif status == DEPRECATED:
                detail["deprecated"].add(cited)
            elif status == UNRESOLVED:
                detail["unresolved"].add(cited)
        return {
            "remapped": dict(sorted(detail["remapped"].items())),
            "deprecated": sorted(detail["deprecated"]),
            "unresolved": sorted(detail["unresolved"]),
        }

    out = {
        "raw_data_dir": str(raw),
        "nodes": {
            "Tactic": len(tactics),
            "Technique": len(live_techniques),
            "SubTechnique": len(attck["subtechniques"]),
            "AttackPattern": len(patterns),
            "Weakness": len(weakness_ids),
            "DefensiveTechnique": len(def_techs),
        },
        "remap_table": {
            "revoked_with_successor": len(remap.successors),
            "deprecated": len(remap.deprecated),
            "revoked_without_successor": len(remap.revoked_without_successor),
        },
        "v1.0": {
            "PART_OF": len(part_of_v10),
            "SUBTECHNIQUE_OF": len(attck["sub_of"]),
            "IMPLEMENTS": len(implements_v10),
            "MITIGATED_BY": len(mitigated_v10),
            "DEMONSTRATED_BY": len(capec["DEMONSTRATED_BY"]),
            "CHILD_OF": len(capec["CHILD_OF"]),
        },
        "v1.1": {
            "PART_OF": len(part_of_v11),
            "SUBTECHNIQUE_OF": len(attck["sub_of"]),
            "IMPLEMENTS": len(implements_v11),
            "MITIGATED_BY": len(mitigated_v11),
            "DEMONSTRATED_BY": len(capec["DEMONSTRATED_BY"]),
            "CHILD_OF": len(capec["CHILD_OF"]),
        },
        "details": {
            "CHILD_OF": {
                "as_loaded": len(capec["CHILD_OF"]),
                "complete": len(capec["CHILD_OF_complete"]),
                "lost_to_flush_order": sorted(capec["CHILD_OF_complete"] - capec["CHILD_OF"]),
            },
            "PART_OF": {
                "v1.0_cross_domain": sum(cross.values()),
                "v1.0_cross_domain_by_pair": dict(sorted(cross.items())),
                "v1.1_cross_domain": cross_v11,
                "v1.1_unresolved_kill_chain_phases": attck["part_of_unresolved"],
                "kill_chain_phase_entries": attck["kill_chain_phase_entries"],
                "v1.1_techniques_without_part_of": techniques_without_part_of,
                "v1.1_minus_v1.0": len(part_of_v11 - part_of_v10),
            },
            "IMPLEMENTS": {
                "refs": impl_counts,
                "taxonomy_rows": len(capec["taxonomy_refs"]),
                "stix_refs_on_live_techniques": len(impl_v10_refs_stix(techniques)),
                "stix_refs_on_revoked_or_deprecated": len(attck["dead_capec_refs"]),
                "added": sorted(implements_v11 - implements_v10),
                "removed": sorted(implements_v10 - implements_v11),
                "remap_detail": remap_detail(impl_refs, 1),
            },
            "MITIGATED_BY": {
                "refs": mit_counts,
                "v1.0_pairs_dropped_by_match": len(set(d3f_pairs)) - len(mitigated_v10),
                "added": len(mitigated_v11 - mitigated_v10),
                "removed": len(mitigated_v10 - mitigated_v11),
                "remap_detail": remap_detail(d3f_pairs, 0),
            },
        },
    }
    if not skip_cve:
        cb = caused_by(raw, weakness_ids)
        out["v1.0"]["CAUSED_BY"] = cb.pop("v1.0")
        out["v1.1"]["CAUSED_BY"] = cb.pop("v1.1")
        out["details"]["CAUSED_BY"] = cb
    return out


def impl_v10_refs_stix(techniques: Dict[str, Dict]) -> Set[Tuple[str, str]]:
    """STIX capec refs on live (non-sub) techniques."""
    return {(c, tid) for tid, t in techniques.items() for c in t["capec"]}


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def to_markdown(r: Dict) -> str:
    edge_types = ["PART_OF", "SUBTECHNIQUE_OF", "IMPLEMENTS", "MITIGATED_BY",
                  "CAUSED_BY", "DEMONSTRATED_BY", "CHILD_OF"]
    lines = [
        "| Edge type | kgcs-demo 2026-09-26 | v1.0 offline | v1.0 = kgcs-demo | v1.1 offline | Delta |",
        "| --- | ---: | ---: | :---: | ---: | ---: |",
    ]
    for et in edge_types:
        if et not in r["v1.0"]:
            continue
        demo, v10, v11 = KGCS_DEMO_2026_09_26[et], r["v1.0"][et], r["v1.1"][et]
        lines.append(
            f"| `{et}` | {demo:,} | {v10:,} | {'yes' if demo == v10 else '**NO**'} "
            f"| {v11:,} | {v11 - v10:+,} |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--raw-data-dir", default="data/raw")
    parser.add_argument("--batch-size", type=int, default=1000,
                        help="run_all_etl.py --batch-size used by the load (default 1000)")
    parser.add_argument("--skip-cve", action="store_true",
                        help="skip the NVD scan (CAUSED_BY)")
    parser.add_argument("--json", metavar="PATH", help="also write the full result as JSON")
    parser.add_argument("--check-v10", action="store_true",
                        help="exit 1 unless every v1.0 count equals kgcs-demo 2026-09-26")
    args = parser.parse_args()

    result = compute(Path(args.raw_data_dir), args.skip_cve, args.batch_size)
    print(to_markdown(result))
    print()
    print("```json")
    print(json.dumps({k: result[k] for k in ("nodes", "remap_table", "details")},
                     indent=2, default=list))
    print("```")
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2, default=list), encoding="utf-8")

    if args.check_v10:
        bad = {k: (v, KGCS_DEMO_2026_09_26[k]) for k, v in result["v1.0"].items()
               if v != KGCS_DEMO_2026_09_26[k]}
        if bad:
            print(f"v1.0 mismatch vs kgcs-demo (offline, demo): {bad}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
