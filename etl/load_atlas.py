"""
ETL loader for MITRE ATLAS (spec 1.2.1, ADR-0004, mappings/atlas-to-owl-v1.0.md,
ontology/standards/atlas-ontology-v1.1.owl).

Parallel matrix beside ATT&CK, outside the causal chain. Runs right after
load_attck: ADAPTED_FROM needs the ATT&CK Technique / SubTechnique nodes.

Node types created (key atlasId, unique per label):
  - AtlasTactic        AML.TA####           (+ matrixPosition from `sequences`)
  - AtlasTechnique     AML.T####            (no `specializes` edge)
  - AtlasSubTechnique  AML.T####.###        (exactly one `specializes` edge)
  - AtlasMitigation    AML.M####

Relationships created (ATLAS-only types; never PART_OF / SUBTECHNIQUE_OF):
  - (AtlasTechnique|AtlasSubTechnique)-[:ACHIEVES]->(AtlasTactic)
  - (AtlasSubTechnique)-[:SPECIALIZES]->(AtlasTechnique)
  - (AtlasMitigation)-[:MITIGATES]->(AtlasTechnique|AtlasSubTechnique)
  - (AtlasTechnique|AtlasSubTechnique)-[:ADAPTED_FROM
        {sourceField, attackReferenceId, attackReferenceUrl}]->(Technique|SubTechnique)

Data source:
  - data/raw/ATLAS/ATLAS-<release>.yaml (format 6.0.0), the versioned file of
    mitre-atlas/atlas-data dist/v6/. Never ATLAS-latest.yaml (a moving
    symlink); with several releases present the newest is loaded.

Rules (atlas-to-owl-v1.0.md, "Transformation rules"):
  1. BuildMetadata ATLAS=<collection.version>.
  2. Techniques are classified by `specializes`, not by id shape; if the two
     disagree the load fails.
  3. Order: tactics, techniques, sub-techniques, mitigations, then edges.
  4. Edges are MERGEd between ATLAS-labelled nodes only.
  5. ADAPTED_FROM only from technique / sub-technique `attack-reference`,
     through the shared ATT&CK revoked-by remap (attck_revocations.py):
     remapped followed, deprecated and unresolved dropped and counted. The
     three edge properties are verbatim.
  6. Not loaded: tactic / mitigation attack-reference, case studies,
     `employs`, references, uuid, mitigates[].description.
  7. Refresh: MERGE on atlasId and SET all properties; atlasIds present in
     the graph but absent from the release are reported, not deleted.
"""

import logging
import re
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .attck_revocations import DEPRECATED, REMAPPED, UNRESOLVED, build_revocation_remap
from .base import AbstractETL
from .load_attck import _find_attck_dir, _ordered_stix_files

logger = logging.getLogger(__name__)

_RELEASE_FILE = re.compile(r"^ATLAS-(\d{4}\.\d{2}(?:\.\d+)?)\.yaml$")
_TECHNIQUE_ID = re.compile(r"^AML\.T\d{4}$")
_SUBTECHNIQUE_ID = re.compile(r"^AML\.T\d{4}\.\d{3}$")
_ATTACK_SUB_ID = re.compile(r"^T\d{4}\.\d{3}$")

TACTIC, TECHNIQUE, SUBTECHNIQUE, MITIGATION = (
    "AtlasTactic", "AtlasTechnique", "AtlasSubTechnique", "AtlasMitigation",
)
LABELS = (TACTIC, TECHNIQUE, SUBTECHNIQUE, MITIGATION)

# Labels are loader constants, never input: interpolating them into Cypher is
# not string-building from data (Hard Rule 2 is about values).
_CYPHER_NODE = """\
UNWIND $batch AS row
MERGE (n:{label} {{atlasId: row.atlasId}})
SET n = row
"""

_CYPHER_ACHIEVES = """\
UNWIND $batch AS row
MATCH (a:{label} {{atlasId: row.src}})
MATCH (t:AtlasTactic {{atlasId: row.tgt}})
MERGE (a)-[:ACHIEVES]->(t)
"""

_CYPHER_SPECIALIZES = """\
UNWIND $batch AS row
MATCH (s:AtlasSubTechnique {atlasId: row.src})
MATCH (t:AtlasTechnique {atlasId: row.tgt})
MERGE (s)-[:SPECIALIZES]->(t)
"""

_CYPHER_MITIGATES = """\
UNWIND $batch AS row
MATCH (m:AtlasMitigation {{atlasId: row.src}})
MATCH (t:{label} {{atlasId: row.tgt}})
MERGE (m)-[:MITIGATES]->(t)
"""

_CYPHER_ADAPTED_FROM = """\
UNWIND $batch AS row
MATCH (a:{src_label} {{atlasId: row.src}})
MATCH (t:{tgt_label} {{attackId: row.tgt}})
MERGE (a)-[r:ADAPTED_FROM]->(t)
SET r.sourceField        = 'attack-reference',
    r.attackReferenceId  = row.attackReferenceId,
    r.attackReferenceUrl = row.attackReferenceUrl
"""

_CYPHER_EXISTING_ATTACK = """\
UNWIND $ids AS id
OPTIONAL MATCH (t:Technique {attackId: id})
OPTIONAL MATCH (s:SubTechnique {attackId: id})
WITH id, t, s WHERE t IS NOT NULL OR s IS NOT NULL
RETURN id
"""

_CYPHER_IDS = "MATCH (n:{label}) RETURN n.atlasId AS id"


# ---------------------------------------------------------------------------
# Source file
# ---------------------------------------------------------------------------

def select_atlas_yaml(atlas_dir: Path) -> Optional[Path]:
    """Newest versioned ATLAS-<release>.yaml; ATLAS-latest.yaml is never read."""
    if not atlas_dir.is_dir():
        return None
    found = []
    for p in atlas_dir.iterdir():
        m = _RELEASE_FILE.match(p.name)
        if m:
            found.append((tuple(int(x) for x in m.group(1).split(".")), p))
    return max(found)[1] if found else None


def read_atlas(path: Path) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def atlas_snapshot(raw_data_dir: Path) -> Optional[str]:
    """BuildMetadata value ATLAS=<collection.version> (ADR-0004 D6)."""
    path = select_atlas_yaml(Path(raw_data_dir) / "ATLAS")
    if path is None:
        return None
    version = (read_atlas(path).get("collection") or {}).get("version")
    return str(version) if version else None


# ---------------------------------------------------------------------------
# Transform (pure)
# ---------------------------------------------------------------------------

def _day(value: Any) -> str:
    """YAML dates may come back as date objects; the graph keeps YYYY-MM-DD."""
    return value.isoformat() if isinstance(value, date) else str(value)


def _common(obj: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "atlasId":      obj["id"],
        "name":         obj["name"],
        "description":  obj["description"],
        "createdDate":  _day(obj["created-date"]),
        "modifiedDate": _day(obj["modified-date"]),
    }


def _relationships(doc: Dict[str, Any]) -> Dict[str, List[Tuple[str, str, Dict]]]:
    """relationship-type -> [(source, target, relationship dict)], deduplicated."""
    out: Dict[str, List[Tuple[str, str, Dict]]] = {}
    seen = set()
    for src, by_type in (doc.get("relationships") or {}).items():
        for rtype, rels in (by_type or {}).items():
            for rel in rels or []:
                key = (rel["source"], rtype, rel["target"])
                if key in seen:
                    continue
                seen.add(key)
                out.setdefault(rtype, []).append((rel["source"], rel["target"], rel))
    return out


def transform_atlas(doc: Dict[str, Any]) -> Dict[str, Any]:
    """ATLAS format 6.0.0 document -> nodes per label, edges and counts.

    Raises ValueError on a structural surprise the mapping depends on
    (unknown format, id-shape vs `specializes` disagreement, dangling edge).
    """
    fmt = str(doc.get("format-version", ""))
    if not fmt.startswith("6."):
        raise ValueError(f"ATLAS format-version {fmt!r}; this loader maps format 6.x")
    tactics = doc.get("tactics") or {}
    techniques = doc.get("techniques") or {}
    mitigations = doc.get("mitigations") or {}
    for coll in (tactics, techniques, mitigations):
        for key, obj in coll.items():
            if obj.get("id") != key:
                raise ValueError(f"ATLAS key {key} != id {obj.get('id')}")
    rels = _relationships(doc)

    # Rule 2: classify by `specializes`, check against the id shape.
    parent_of: Dict[str, str] = {}
    for src, tgt, _ in rels.get("specializes", []):
        if src in parent_of:
            raise ValueError(f"{src} specializes more than one technique")
        parent_of[src] = tgt
    for tid in techniques:
        by_edge = tid in parent_of
        by_shape = bool(_SUBTECHNIQUE_ID.match(tid))
        if by_edge != by_shape or not (by_shape or _TECHNIQUE_ID.match(tid)):
            raise ValueError(f"{tid}: specializes={by_edge} disagrees with its id shape")
    for sub, parent in parent_of.items():
        if parent not in techniques or parent in parent_of or not sub.startswith(parent + "."):
            raise ValueError(f"{sub} specializes {parent}: not its top-level parent")

    positions = {
        tgt: int(rel["position"])
        for src, tgt, rel in rels.get("sequences", [])
        if tgt in tactics
    }
    nodes: Dict[str, List[Dict[str, Any]]] = {label: [] for label in LABELS}
    for tid, obj in tactics.items():
        if tid not in positions:
            raise ValueError(f"tactic {tid} has no matrix `sequences` position")
        nodes[TACTIC].append({**_common(obj), "matrixPosition": positions[tid]})
    label_of: Dict[str, str] = {tid: TACTIC for tid in tactics}
    for tid, obj in techniques.items():
        label = SUBTECHNIQUE if tid in parent_of else TECHNIQUE
        label_of[tid] = label
        nodes[label].append({
            **_common(obj),
            "maturity":  obj["maturity"],
            "platforms": [str(p) for p in obj["platforms"]],
        })
    for mid, obj in mitigations.items():
        label_of[mid] = MITIGATION
        nodes[MITIGATION].append({
            **_common(obj),
            "categories":      [str(c) for c in obj["categories"]],
            "lifecyclePhases": [str(c) for c in obj["lifecycle-phases"]],
        })

    def check(rtype: str, src: str, tgt: str, src_labels, tgt_labels) -> None:
        if label_of.get(src) not in src_labels or label_of.get(tgt) not in tgt_labels:
            raise ValueError(f"{rtype} {src} -> {tgt}: unexpected endpoint labels")

    achieves, specializes, mitigates = [], [], []
    for src, tgt, _ in rels.get("achieves", []):
        check("achieves", src, tgt, (TECHNIQUE, SUBTECHNIQUE), (TACTIC,))
        achieves.append({"src": src, "tgt": tgt, "srcLabel": label_of[src]})
    for src, tgt, _ in rels.get("specializes", []):
        check("specializes", src, tgt, (SUBTECHNIQUE,), (TECHNIQUE,))
        specializes.append({"src": src, "tgt": tgt})
    for src, tgt, _ in rels.get("mitigates", []):
        check("mitigates", src, tgt, (MITIGATION,), (TECHNIQUE, SUBTECHNIQUE))
        mitigates.append({"src": src, "tgt": tgt, "tgtLabel": label_of[tgt]})

    attack_refs = []
    for tid, obj in techniques.items():
        ref = obj.get("attack-reference")
        if ref:
            attack_refs.append({
                "src": tid, "srcLabel": label_of[tid],
                "attackReferenceId": str(ref["id"]),
                "attackReferenceUrl": str(ref["url"]),
            })

    counts = {
        "tactics": len(nodes[TACTIC]), "techniques": len(nodes[TECHNIQUE]),
        "subtechniques": len(nodes[SUBTECHNIQUE]), "mitigations": len(nodes[MITIGATION]),
        "achieves": len(achieves), "specializes": len(specializes),
        "mitigates": len(mitigates), "attack_reference_rows": len(attack_refs),
        "excluded_tactic_attack_reference": sum(1 for o in tactics.values() if o.get("attack-reference")),
        "excluded_mitigation_attack_reference": sum(1 for o in mitigations.values() if o.get("attack-reference")),
        "excluded_case_studies": len(doc.get("case-studies") or {}),
        "excluded_employs": sum(   # rows, as the source profile counts them (665 in 2026.09)
            len(by_type.get("employs") or []) for by_type in (doc.get("relationships") or {}).values()),
    }
    return {
        "release": str((doc.get("collection") or {}).get("version") or ""),
        "nodes": nodes, "achieves": achieves, "specializes": specializes,
        "mitigates": mitigates, "attack_refs": attack_refs, "counts": counts,
    }


def resolve_adapted_from(attack_refs: List[Dict[str, Any]], remap) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Apply the shared ATT&CK revoked-by remap to attack-reference rows.

    Returns (edge rows with target attackId and label, counts). One edge per
    ATLAS object (the field is single-valued).
    """
    counts: Dict[str, Any] = {"rows": len(attack_refs), "remapped": 0,
                              "dropped_deprecated": 0, "unresolved": 0,
                              "unresolved_ids": []}
    edges = []
    for ref in attack_refs:
        status, target = remap.resolve(ref["attackReferenceId"])
        if status == DEPRECATED:
            counts["dropped_deprecated"] += 1
            continue
        if status == UNRESOLVED:
            counts["unresolved"] += 1
            counts["unresolved_ids"].append(f"{ref['src']}->{ref['attackReferenceId']}")
            continue
        if status == REMAPPED:
            counts["remapped"] += 1
        edges.append({
            **ref, "tgt": target,
            "tgtLabel": "SubTechnique" if _ATTACK_SUB_ID.match(target) else "Technique",
        })
    return edges, counts


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

class ATLASLoader(AbstractETL):
    """MITRE ATLAS module loader (after ATT&CK)."""

    @property
    def standard_name(self) -> str:
        return "ATLAS"

    def extract(self) -> Any:
        return None

    def transform(self, raw_data: Any) -> List[Dict]:
        return []

    def load_nodes(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    def load_relationships(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    def _exec(self, cypher: str, rows: List[Dict], stats: Dict, errors: List[str]) -> int:
        r = self.writer.execute_batch(cypher, rows, self.batch_size)
        stats["nodes_created"] += r.get("nodes_created", 0)
        stats["rels_created"] += r.get("rels_created", 0)
        errors.extend(r.get("errors", []))
        return r.get("rels_created", 0)

    def run(self) -> Dict[str, Any]:
        path = select_atlas_yaml(self.standard_dir)
        if path is None:
            return self._error_result(f"No ATLAS-<release>.yaml in {self.standard_dir}")
        attck_dir = _find_attck_dir(self.raw_data_dir)
        if attck_dir is None:
            return self._error_result(
                "ATT&CK bundles not found: cannot apply the revoked-by remap to ADAPTED_FROM"
            )
        try:
            data = transform_atlas(read_atlas(path))
            remap = build_revocation_remap(_ordered_stix_files(attck_dir))
        except (OSError, ValueError, KeyError, yaml.YAMLError) as exc:
            return self._error_result(f"ATLAS transform failed ({path.name}): {exc}")
        adapted, remap_counts = resolve_adapted_from(data["attack_refs"], remap)

        stats: Dict[str, Any] = {"nodes_created": 0, "rels_created": 0,
                                 "release": data["release"], "file": path.name,
                                 **data["counts"]}
        errors: List[str] = []
        self.log_success(f"{path.name}: release {data['release']}, {data['counts']}")

        # Rule 7: report ids the graph has and the release lost.
        for label in LABELS:
            current = {n["atlasId"] for n in data["nodes"][label]}
            stale = sorted(r["id"] for r in self.writer.read_rows(_CYPHER_IDS.format(label=label))
                           if r["id"] not in current)
            if stale:
                self.log_warning(f"{len(stale)} {label} in the graph but not in {data['release']}: {stale[:10]}")
            stats[f"stale_{label}"] = len(stale)

        for label in LABELS:   # tactics, techniques, sub-techniques, mitigations
            self._exec(_CYPHER_NODE.format(label=label), data["nodes"][label], stats, errors)
        for label in (TECHNIQUE, SUBTECHNIQUE):
            self._exec(_CYPHER_ACHIEVES.format(label=label),
                       [e for e in data["achieves"] if e["srcLabel"] == label], stats, errors)
        self._exec(_CYPHER_SPECIALIZES, data["specializes"], stats, errors)
        for label in (TECHNIQUE, SUBTECHNIQUE):
            self._exec(_CYPHER_MITIGATES.format(label=label),
                       [e for e in data["mitigates"] if e["tgtLabel"] == label], stats, errors)

        # ADAPTED_FROM: only to ATT&CK nodes that exist (loader MATCH semantics).
        present = {r["id"] for r in self.writer.read_rows(
            _CYPHER_EXISTING_ATTACK, {"ids": sorted({e["tgt"] for e in adapted})})}
        missing = [e for e in adapted if e["tgt"] not in present]
        adapted = [e for e in adapted if e["tgt"] in present]
        for src_label in (TECHNIQUE, SUBTECHNIQUE):
            for tgt_label in ("Technique", "SubTechnique"):
                rows = [e for e in adapted if e["srcLabel"] == src_label and e["tgtLabel"] == tgt_label]
                self._exec(_CYPHER_ADAPTED_FROM.format(src_label=src_label, tgt_label=tgt_label),
                           rows, stats, errors)
        stats.update({
            "adapted_from_rows": remap_counts["rows"],
            "adapted_from_written": len(adapted),
            "adapted_from_remapped": remap_counts["remapped"],
            "adapted_from_dropped_deprecated": remap_counts["dropped_deprecated"],
            "adapted_from_unresolved": remap_counts["unresolved"] + len(missing),
            "adapted_from_unresolved_ids": remap_counts["unresolved_ids"]
                + [f"{e['src']}->{e['tgt']} (not in graph)" for e in missing],
        })
        self.log_success(
            f"ADAPTED_FROM: {remap_counts['rows']} attack-reference rows, "
            f"{len(adapted)} written, {remap_counts['remapped']} remapped, "
            f"{remap_counts['dropped_deprecated']} dropped as deprecated, "
            f"{stats['adapted_from_unresolved']} unresolved {stats['adapted_from_unresolved_ids']}"
        )
        result = {"success": not errors, "errors": errors, "stats": stats}
        if result["success"]:
            self.log_success(f"Complete: {stats}")
        else:
            self.log_error(f"Completed with {len(errors)} errors: {errors[:3]}")
        return result
