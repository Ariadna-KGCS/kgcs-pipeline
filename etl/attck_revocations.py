"""
Shared ATT&CK revoked-by remap for every bridge that points into ATT&CK.

Spec rule (kgcs-spec 1.1.0, `mappings/attck-to-owl-v1.0.md`, "v1.1 — Revoked
and deprecated ATT&CK targets"):

  - Revoked targets are remapped. The remap table is built from the loaded
    bundles' `relationship` objects with `relationship_type = revoked-by`
    (source = revoked object, target = successor), followed transitively to
    a live object.
  - Deprecated targets are dropped and counted: the target itself, or the
    end of its revoked-by chain, is `x_mitre_deprecated = true`.
  - IDs present in no bundle (or revoked with no successor) are unresolved
    and counted.

Bridges using it: CAPEC `IMPLEMENTS` (load_attck.py, remap BEFORE the
sub-technique -> parent roll-up) and D3FEND `MITIGATED_BY` (load_d3fend.py).

Only `attack-pattern` objects (techniques and sub-techniques) take part:
bridges never target tactics.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

LIVE = "live"
REMAPPED = "remapped"
DEPRECATED = "deprecated"
UNRESOLVED = "unresolved"


def _mitre_attack_id(obj: Dict) -> Optional[str]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


class RevocationRemap:
    """Resolved attackId -> (status, live attackId) table."""

    def __init__(
        self,
        live: Set[str],
        successors: Dict[str, str],
        deprecated: Set[str],
        revoked_without_successor: Set[str],
    ) -> None:
        self.live = live
        self.successors = successors
        self.deprecated = deprecated
        self.revoked_without_successor = revoked_without_successor

    def resolve(self, attack_id: str) -> Tuple[str, Optional[str]]:
        """Return (status, target attackId or None).

        status is one of LIVE, REMAPPED, DEPRECATED, UNRESOLVED.
        """
        if attack_id in self.live:
            return LIVE, attack_id
        if attack_id in self.successors:
            return REMAPPED, self.successors[attack_id]
        if attack_id in self.deprecated:
            return DEPRECATED, None
        return UNRESOLVED, None


class RevocationRemapBuilder:
    """Accumulates attack-pattern objects and revoked-by edges across bundles."""

    def __init__(self) -> None:
        # stix_id -> (attackId or None, revoked, deprecated)
        self._objects: Dict[str, Tuple[Optional[str], bool, bool]] = {}
        # revoked stix_id -> successor stix_id
        self._revoked_by: Dict[str, str] = {}

    def add_object(self, obj: Dict) -> None:
        otype = obj.get("type", "")
        if otype == "attack-pattern":
            stix_id = obj.get("id", "")
            if stix_id:
                self._objects[stix_id] = (
                    _mitre_attack_id(obj),
                    bool(obj.get("revoked", False)),
                    bool(obj.get("x_mitre_deprecated", False)),
                )
        elif otype == "relationship" and obj.get("relationship_type") == "revoked-by":
            src = obj.get("source_ref", "")
            tgt = obj.get("target_ref", "")
            if src.startswith("attack-pattern--") and tgt:
                self._revoked_by[src] = tgt

    def add_bundle(self, objects: Iterable[Dict]) -> None:
        for obj in objects:
            self.add_object(obj)

    def _chain_end(self, stix_id: str) -> Optional[str]:
        """Follow revoked-by from stix_id to the first non-revoked object."""
        seen: Set[str] = set()
        cur = stix_id
        while True:
            entry = self._objects.get(cur)
            if entry is None:
                return None          # successor not present in any bundle
            if not entry[1]:
                return cur           # not revoked: end of chain
            if cur in seen:
                return None          # cycle
            seen.add(cur)
            nxt = self._revoked_by.get(cur)
            if nxt is None:
                return None          # revoked with no successor
            cur = nxt

    def build(self) -> RevocationRemap:
        live: Set[str] = set()
        for attack_id, revoked, deprecated in self._objects.values():
            if attack_id and not revoked and not deprecated:
                live.add(attack_id)

        candidates: Dict[str, Set[str]] = {}   # attackId -> successor attackIds
        deprecated_ids: Set[str] = set()
        no_successor: Set[str] = set()

        for stix_id, (attack_id, revoked, deprecated) in self._objects.items():
            if not attack_id or attack_id in live:
                continue
            if not revoked:
                if deprecated:
                    deprecated_ids.add(attack_id)
                continue
            end = self._chain_end(stix_id)
            if end is None:
                no_successor.add(attack_id)
                continue
            end_id, _, end_deprecated = self._objects[end]
            if end_deprecated or not end_id:
                deprecated_ids.add(attack_id)
            else:
                candidates.setdefault(attack_id, set()).add(end_id)

        successors: Dict[str, str] = {}
        for attack_id, targets in candidates.items():
            if len(targets) > 1:
                logger.warning(
                    f"[ATTCK-REMAP] {attack_id} revoked towards several successors "
                    f"{sorted(targets)}; using {min(targets)}"
                )
            successors[attack_id] = min(targets)

        # An id with a live successor is remapped, even if another copy of it
        # is deprecated or has no successor.
        deprecated_ids -= set(successors)
        no_successor -= set(successors) | deprecated_ids

        return RevocationRemap(live, successors, deprecated_ids, no_successor)


def build_revocation_remap(stix_paths: Iterable[Path]) -> RevocationRemap:
    """Build the remap from STIX bundle files (one bundle in memory at a time)."""
    builder = RevocationRemapBuilder()
    for path in stix_paths:
        with open(path, encoding="utf-8") as fh:
            builder.add_bundle(json.load(fh).get("objects", []))
    return builder.build()


def apply_remap(
    pairs: Iterable[Tuple[str, str]],
    remap: RevocationRemap,
    target_index: int,
) -> Tuple[List[Tuple[str, str]], Dict[str, int]]:
    """Remap the ATT&CK side of each (a, b) pair; position given by target_index.

    Returns (resolved pairs in input order, deduplicated; counts). Counts are
    per distinct input pair: rows, remapped, dropped_deprecated, unresolved.
    """
    counts = {"rows": 0, "remapped": 0, "dropped_deprecated": 0, "unresolved": 0}
    out: List[Tuple[str, str]] = []
    seen_in: Set[Tuple[str, str]] = set()
    seen_out: Set[Tuple[str, str]] = set()
    for pair in pairs:
        if pair in seen_in:
            continue
        seen_in.add(pair)
        counts["rows"] += 1
        status, target = remap.resolve(pair[target_index])
        if status == DEPRECATED:
            counts["dropped_deprecated"] += 1
            continue
        if status == UNRESOLVED:
            counts["unresolved"] += 1
            continue
        if status == REMAPPED:
            counts["remapped"] += 1
        new = (target, pair[1]) if target_index == 0 else (pair[0], target)
        if new not in seen_out:
            seen_out.add(new)
            out.append(new)
    return out, counts
