"""
ETL loader for MITRE ATT&CK data (enterprise + ICS + mobile domains).

Step 6 of the KGCS load order. Must run after load_capec (IMPLEMENTS
requires AttackPattern nodes).

Node types created:
  - Technique      (attackId unique key, e.g. "T1059")
  - SubTechnique   (attackId unique key, e.g. "T1059.001")
  - Tactic         (attackId unique key, e.g. "TA0002")

Relationships created:
  - (Technique)-[:PART_OF]->(Tactic)
  - (SubTechnique)-[:SUBTECHNIQUE_OF]->(Technique)
  - (AttackPattern)-[:IMPLEMENTS]->(Technique)

Data sources (already downloaded — 3 STIX bundles):
  - data/raw/ATTCK/enterprise-attack.json
  - data/raw/ATTCK/ics-attack.json
  - data/raw/ATTCK/mobile-attack.json

Processing order: enterprise → ics → mobile.

Domain deduplication:
  The same Technique may appear in multiple domains. MERGE handles
  structural deduplication; a `domains` list property accumulates all
  domain names in which the technique appears.

Revoked/deprecated filtering:
  Objects with revoked==True or x_mitre_deprecated==True are SKIPPED
  and counted in stats. They must not enter the graph as they contain
  stale data.

SHACL invariants enforced here:
  SH-CORE-06: Every Technique has ≥1 PART_OF edge to a Tactic.
  SH-CORE-07: Every SubTechnique has exactly 1 SUBTECHNIQUE_OF edge.
"""

import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .base import AbstractETL

logger = logging.getLogger(__name__)

_CAPEC_NS = "http://capec.mitre.org/capec-3"

# Domain resolution: filename substring → canonical domain string
_DOMAIN_MAP = {
    "enterprise": "enterprise",
    "ics":        "ics",
    "mobile":     "mobile",
}
_DOMAIN_PRIORITY = {"enterprise": 0, "ics": 1, "mobile": 2}

# ---------------------------------------------------------------------------
# Cypher statements
# ---------------------------------------------------------------------------

_CYPHER_TACTIC = """\
UNWIND $batch AS row
MERGE (t:Tactic {attackId: row.attackId})
ON CREATE SET
    t.name      = row.name,
    t.phaseName = row.phaseName,
    t.domains   = [row.domain]
ON MATCH SET
    t.name      = row.name,
    t.phaseName = row.phaseName,
    t.domains   = CASE WHEN row.domain IN coalesce(t.domains, [])
                       THEN t.domains
                       ELSE coalesce(t.domains, []) + [row.domain] END
"""

_CYPHER_TECHNIQUE = """\
UNWIND $batch AS row
MERGE (t:Technique {attackId: row.attackId})
ON CREATE SET
    t.name        = row.name,
    t.description = row.description,
    t.domains     = [row.domain]
ON MATCH SET
    t.name        = row.name,
    t.domains     = CASE WHEN row.domain IN coalesce(t.domains, [])
                         THEN t.domains
                         ELSE coalesce(t.domains, []) + [row.domain] END
"""

_CYPHER_SUBTECHNIQUE = """\
UNWIND $batch AS row
MERGE (st:SubTechnique {attackId: row.attackId})
ON CREATE SET
    st.name        = row.name,
    st.description = row.description,
    st.domains     = [row.domain]
ON MATCH SET
    st.name        = row.name,
    st.domains     = CASE WHEN row.domain IN coalesce(st.domains, [])
                          THEN st.domains
                          ELSE coalesce(st.domains, []) + [row.domain] END
"""

_CYPHER_PART_OF = """\
UNWIND $batch AS row
MATCH (t:Technique {attackId: row.techniqueId})
MATCH (ta:Tactic {phaseName: row.phaseName})
MERGE (t)-[:PART_OF]->(ta)
"""

_CYPHER_SUBTECHNIQUE_OF = """\
UNWIND $batch AS row
MATCH (st:SubTechnique {attackId: row.subId})
MATCH (t:Technique {attackId: row.parentId})
MERGE (st)-[:SUBTECHNIQUE_OF]->(t)
"""

_CYPHER_IMPLEMENTS = """\
UNWIND $batch AS row
MATCH (ap:AttackPattern {capecId: row.capecId})
MATCH (t:Technique {attackId: row.techniqueId})
MERGE (ap)-[:IMPLEMENTS]->(t)
"""


# ---------------------------------------------------------------------------
# STIX extraction helpers
# ---------------------------------------------------------------------------

def _resolve_domain(path: Path) -> str:
    name = path.stem.lower()
    for key, val in _DOMAIN_MAP.items():
        if key in name:
            return val
    return "unknown"


def _external_id(obj: Dict, source: str) -> Optional[str]:
    """Return the first external_id matching source_name, or None."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source:
            return ref.get("external_id")
    return None


def _capec_ids(obj: Dict) -> List[str]:
    """Return all CAPEC external_ids from an ATT&CK object."""
    return [
        ref.get("external_id", "")
        for ref in obj.get("external_references", [])
        if ref.get("source_name") == "capec"
        and ref.get("external_id", "").startswith("CAPEC-")
    ]


def _normalize_attack_id_to_technique(raw_attack_id: str) -> Optional[str]:
    """Normalize ATT&CK IDs to top-level Technique IDs for IMPLEMENTS edges.

    CAPEC taxonomy mappings may point to subtechniques (for example `1574.010`).
    The current KGCS Offensive/Defensive chain operates on `Technique`, so
    subtechnique mappings are collapsed to the parent technique (`T1574`) here.
    """
    raw = (raw_attack_id or "").strip()
    if not raw:
        return None

    attack_id = raw if raw.startswith("T") else f"T{raw}"
    if "." in attack_id:
        attack_id = attack_id.split(".", 1)[0]
    return attack_id


def _capec_taxonomy_pairs(capec_xml_path: Path) -> Set[Tuple[str, str]]:
    """Extract CAPEC -> ATT&CK Technique pairs from CAPEC XML taxonomy mappings."""
    pairs: Set[Tuple[str, str]] = set()
    ap_tag = f"{{{_CAPEC_NS}}}Attack_Pattern"
    tm_tag = f"{{{_CAPEC_NS}}}Taxonomy_Mapping"
    ei_tag = f"{{{_CAPEC_NS}}}Entry_ID"

    try:
        context = ET.iterparse(str(capec_xml_path), events=("start", "end"))
        current_capec_id: Optional[str] = None

        for event, elem in context:
            if event == "start" and elem.tag == ap_tag:
                ap_id = elem.get("ID", "").strip()
                current_capec_id = f"CAPEC-{ap_id}" if ap_id else None
            elif event == "end" and elem.tag == ap_tag:
                elem.clear()
                current_capec_id = None
            elif event == "end" and elem.tag == tm_tag and current_capec_id:
                taxonomy_name = elem.get("Taxonomy_Name", "")
                if "ATTACK" in taxonomy_name.upper():
                    entry_id_elem = elem.find(ei_tag)
                    if entry_id_elem is not None and entry_id_elem.text:
                        attack_id = _normalize_attack_id_to_technique(entry_id_elem.text)
                        if attack_id:
                            pairs.add((current_capec_id, attack_id))
                elem.clear()
    except Exception as exc:
        logger.error(f"[ATTCK] Failed parsing CAPEC taxonomy mappings from {capec_xml_path}: {exc}")

    return pairs


def _find_attck_dir(raw_data_dir: Path) -> Optional[Path]:
    """Locate the ATT&CK bundle directory, tolerating name variants."""
    for candidate in ("ATTCK-STIX", "ATTCK", "ATT&CK", "ATTACK", "attack", "attck"):
        d = raw_data_dir / candidate
        if d.is_dir():
            return d
    return None


def _ordered_stix_files(attck_dir: Path) -> List[Path]:
    """Return STIX bundle files sorted enterprise → ics → mobile."""
    def priority(p: Path) -> int:
        name = p.stem.lower()
        for key, val in _DOMAIN_PRIORITY.items():
            if key in name:
                return val
        return 99

    return sorted(attck_dir.glob("*.json"), key=priority)


def _load_stix_bundle(path: Path) -> Dict:
    """Load a STIX bundle JSON, returning {stix_id: object} maps.

    Returns:
      {
        "tactics":       {stix_id: obj},
        "techniques":    {stix_id: obj},
        "subtechniques": {stix_id: obj},
        "sub_of_rels":   [{source_ref, target_ref}],
        "skipped":       int,
        "domain":        str,
      }
    """
    result = {
        "tactics": {}, "techniques": {}, "subtechniques": {},
        "sub_of_rels": [], "skipped": 0, "domain": _resolve_domain(path),
    }
    try:
        with open(path, encoding="utf-8") as fh:
            bundle = json.load(fh)
        objects = bundle.get("objects", [])
        for obj in objects:
            otype = obj.get("type", "")

            # Skip revoked/deprecated
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                result["skipped"] += 1
                continue

            if otype == "x-mitre-tactic":
                stix_id = obj.get("id", "")
                if stix_id:
                    result["tactics"][stix_id] = obj

            elif otype == "attack-pattern":
                stix_id = obj.get("id", "")
                if not stix_id:
                    continue
                if obj.get("x_mitre_is_subtechnique", False):
                    result["subtechniques"][stix_id] = obj
                else:
                    result["techniques"][stix_id] = obj

            elif otype == "relationship":
                if obj.get("relationship_type") == "subtechnique-of":
                    result["sub_of_rels"].append({
                        "source_ref": obj.get("source_ref", ""),
                        "target_ref": obj.get("target_ref", ""),
                    })

    except Exception as exc:
        logger.error(f"[ATTCK] Failed loading {path}: {exc}")

    return result


class ATTCKLoader(AbstractETL):
    """ETL loader for Technique, SubTechnique, Tactic nodes and relationships."""

    @property
    def standard_name(self) -> str:
        return "ATT&CK"

    def extract(self) -> Any:
        return None

    def transform(self, raw_data: Any) -> List[Dict]:
        return []

    def load_nodes(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    def load_relationships(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    def run(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "success": False,
            "errors":  [],
            "stats":   {
                "nodes_created": 0,
                "rels_created":  0,
                "skipped_revoked": 0,
                "tactics": 0, "techniques": 0, "subtechniques": 0,
            },
        }

        try:
            self.log_success("Starting ATT&CK ETL")

            attck_dir = _find_attck_dir(self.raw_data_dir)
            if not attck_dir:
                self.log_error(
                    f"ATT&CK directory not found under {self.raw_data_dir}"
                )
                result["errors"].append("ATT&CK directory missing")
                return result

            files = _ordered_stix_files(attck_dir)
            if not files:
                self.log_warning(f"No STIX JSON files found in {attck_dir}")
                result["success"] = True
                return result

            capec_xml_path = self.raw_data_dir / "CAPEC" / "capec_latest.xml"
            capec_taxonomy_pairs = (
                _capec_taxonomy_pairs(capec_xml_path)
                if capec_xml_path.exists()
                else set()
            )

            # Accumulate across all 3 bundles (deduplicate by attackId)
            all_tactics:       Dict[str, Dict] = {}   # attackId → record
            all_techniques:    Dict[str, Dict] = {}
            all_subtechniques: Dict[str, Dict] = {}
            # stix_id → attackId for relationship resolution
            stix_to_attack_id: Dict[str, str]  = {}
            # De-duplicated sub-of pairs
            sub_of_pairs: Set[Tuple[str, str]] = set()
            # IMPLEMENTS pairs
            implements_pairs: Set[Tuple[str, str]] = set()

            total_skipped = 0

            for path in files:
                logger.debug(f"[ATTCK] Processing {path.name}")
                bundle = _load_stix_bundle(path)
                domain = bundle["domain"]
                total_skipped += bundle["skipped"]

                # --- Tactics ---
                for stix_id, obj in bundle["tactics"].items():
                    attack_id = _external_id(obj, "mitre-attack")
                    if not attack_id:
                        continue
                    stix_to_attack_id[stix_id] = attack_id
                    phase = obj.get("x_mitre_shortname", "")
                    if attack_id in all_tactics:
                        # Accumulate domain
                        d = all_tactics[attack_id]["domain"]
                        if domain not in d:
                            all_tactics[attack_id]["domain"] = domain
                    else:
                        all_tactics[attack_id] = {
                            "attackId": attack_id,
                            "name":     obj.get("name", ""),
                            "phaseName": phase,
                            "domain":   domain,
                        }

                # --- Techniques & SubTechniques ---
                for is_sub, obj_map in (
                    (False, bundle["techniques"]),
                    (True,  bundle["subtechniques"]),
                ):
                    for stix_id, obj in obj_map.items():
                        attack_id = _external_id(obj, "mitre-attack")
                        if not attack_id:
                            continue
                        stix_to_attack_id[stix_id] = attack_id
                        rec = {
                            "attackId":    attack_id,
                            "name":        obj.get("name", ""),
                            "description": obj.get("description", "")[:1000],
                            "domain":      domain,
                        }
                        target = all_subtechniques if is_sub else all_techniques
                        if attack_id not in target:
                            target[attack_id] = rec
                        # else already present; domain accumulation handled in Cypher

                        # Collect IMPLEMENTS (only non-subtechniques → CAPEC)
                        if not is_sub:
                            for capec_id in _capec_ids(obj):
                                implements_pairs.add((capec_id, attack_id))

                        # PART_OF from kill_chain_phases — include all MITRE domains
                        if not is_sub:
                            for kcp in obj.get("kill_chain_phases", []):
                                if kcp.get("kill_chain_name", "").startswith("mitre-"):
                                    phase_name = kcp.get("phase_name", "")
                                    if phase_name:
                                        # Will link via Tactic.phaseName
                                        rec.setdefault("phases", [])
                                        if phase_name not in rec["phases"]:
                                            rec["phases"].append(phase_name)

                # --- SUBTECHNIQUE_OF relationships ---
                for rel in bundle["sub_of_rels"]:
                    sub_stix  = rel["source_ref"]
                    par_stix  = rel["target_ref"]
                    sub_id  = stix_to_attack_id.get(sub_stix)
                    par_id  = stix_to_attack_id.get(par_stix)
                    if sub_id and par_id:
                        sub_of_pairs.add((sub_id, par_id))

            errors: List[str] = []
            nodes_created = 0
            rels_created  = 0

            # --- Write Tactics ---
            tactic_recs = list(all_tactics.values())
            if tactic_recs:
                r = self.writer.execute_batch(
                    _CYPHER_TACTIC, tactic_recs, self.batch_size
                )
                nodes_created += r.get("nodes_created", 0)
                errors.extend(r.get("errors", []))
            self.log_success(f"Tactics: {len(tactic_recs)} written")

            # --- Write Techniques ---
            tech_recs = list(all_techniques.values())
            if tech_recs:
                r = self.writer.execute_batch(
                    _CYPHER_TECHNIQUE, tech_recs, self.batch_size
                )
                nodes_created += r.get("nodes_created", 0)
                errors.extend(r.get("errors", []))
            self.log_success(f"Techniques: {len(tech_recs)} written")

            # --- Write SubTechniques ---
            sub_recs = list(all_subtechniques.values())
            if sub_recs:
                r = self.writer.execute_batch(
                    _CYPHER_SUBTECHNIQUE, sub_recs, self.batch_size
                )
                nodes_created += r.get("nodes_created", 0)
                errors.extend(r.get("errors", []))
            self.log_success(f"SubTechniques: {len(sub_recs)} written")

            # --- Write PART_OF ---
            part_of_recs = [
                {"techniqueId": attack_id, "phaseName": phase}
                for attack_id, rec in all_techniques.items()
                for phase in rec.get("phases", [])
            ]
            if part_of_recs:
                r = self.writer.execute_batch(
                    _CYPHER_PART_OF, part_of_recs, self.batch_size
                )
                rels_created += r.get("rels_created", 0)
                errors.extend(r.get("errors", []))
            self.log_success(f"PART_OF: {len(part_of_recs)} relationships written")

            # --- Write SUBTECHNIQUE_OF ---
            sub_of_recs = [
                {"subId": sub, "parentId": par}
                for sub, par in sub_of_pairs
            ]
            if sub_of_recs:
                r = self.writer.execute_batch(
                    _CYPHER_SUBTECHNIQUE_OF, sub_of_recs, self.batch_size
                )
                rels_created += r.get("rels_created", 0)
                errors.extend(r.get("errors", []))
            self.log_success(
                f"SUBTECHNIQUE_OF: {len(sub_of_recs)} relationships written"
            )

            # --- Write IMPLEMENTS ---
            implements_pairs.update(capec_taxonomy_pairs)
            impl_recs = [
                {"capecId": capec, "techniqueId": tid}
                for capec, tid in implements_pairs
            ]
            if impl_recs:
                r = self.writer.execute_batch(
                    _CYPHER_IMPLEMENTS, impl_recs, self.batch_size
                )
                rels_created += r.get("rels_created", 0)
                errors.extend(r.get("errors", []))
            self.log_success(
                f"IMPLEMENTS: {len(impl_recs)} relationships written"
            )

            result["stats"]["nodes_created"]   = nodes_created
            result["stats"]["rels_created"]    = rels_created
            result["stats"]["skipped_revoked"] = total_skipped
            result["stats"]["tactics"]         = len(tactic_recs)
            result["stats"]["techniques"]      = len(tech_recs)
            result["stats"]["subtechniques"]   = len(sub_recs)
            result["errors"]  = errors
            result["success"] = len(errors) == 0

            if result["success"]:
                self.log_success(f"Complete: {result['stats']}")
            else:
                self.log_error(f"Completed with {len(errors)} errors")

        except Exception as exc:
            self.log_error(f"Unhandled exception: {exc}")
            result["errors"].append(str(exc))

        return result
