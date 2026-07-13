"""Helpers for preserving CVE applicability semantics during ETL.

This module is the starting point for Priority 3 applicability work.
It ports the useful flattening idea from the legacy R implementation
while aligning the output with current NVD schema terms:

- configurations[].operator / negate
- nodes[].operator / negate
- cpeMatch[].matchCriteriaId / criteria
- versionStartExcluding / versionStartIncluding
- versionEndExcluding / versionEndIncluding

The goal here is not to evaluate applicability yet. The goal is to
normalize CVE configuration trees into explicit rows that preserve enough
information for later logic reconstruction.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Dict, Iterable, List


def _as_list(value: Any) -> List[Dict[str, Any]]:
    """Normalize raw configuration payloads to a list of dicts."""
    if value is None or value == "":
        return []
    if isinstance(value, str):
        parsed = json.loads(value)
    else:
        parsed = value
    if parsed is None:
        return []
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    if isinstance(parsed, dict):
        return [parsed]
    return []


def _normalize_match(
    match: Dict[str, Any],
    *,
    cve_id: str,
    config_index: int,
    node_index: int,
    match_index: int,
    config_operator: str,
    config_negate: bool,
    node_operator: str,
    node_negate: bool,
    legacy_group: str | None = None,
) -> Dict[str, Any]:
    """Build one flattened applicability row."""
    return {
        "cveId": cve_id,
        "configIndex": config_index,
        "nodeIndex": node_index,
        "matchIndex": match_index,
        "configOperator": config_operator,
        "configNegate": config_negate,
        "nodeOperator": node_operator,
        "nodeNegate": node_negate,
        "groupId": f"vulnconf:{cve_id}:cfg{config_index}:node{node_index}",
        "legacyGroupId": legacy_group,
        "vulnerable": bool(match.get("vulnerable", False)),
        "criteria": match.get("criteria"),
        "matchCriteriaId": match.get("matchCriteriaId"),
        "cpe23Uri": match.get("cpe23Uri"),
        "versionStartExcluding": match.get("versionStartExcluding"),
        "versionStartIncluding": match.get("versionStartIncluding"),
        "versionEndExcluding": match.get("versionEndExcluding"),
        "versionEndIncluding": match.get("versionEndIncluding"),
        "cpeNames": match.get("cpe_name") or match.get("matches"),
    }


def _flatten_current_configurations(
    configurations: Iterable[Dict[str, Any]],
    cve_id: str,
) -> List[Dict[str, Any]]:
    """Flatten the current NVD-style configurations[].nodes[].cpeMatch[] shape."""
    rows: List[Dict[str, Any]] = []
    for config_index, config in enumerate(configurations, start=1):
        config_operator = str(config.get("operator", "OR"))
        config_negate = bool(config.get("negate", False))
        nodes = config.get("nodes") or []
        for node_index, node in enumerate(nodes, start=1):
            node_operator = str(node.get("operator", "OR"))
            node_negate = bool(node.get("negate", False))
            matches = node.get("cpeMatch") or []
            for match_index, match in enumerate(matches, start=1):
                rows.append(
                    _normalize_match(
                        match,
                        cve_id=cve_id,
                        config_index=config_index,
                        node_index=node_index,
                        match_index=match_index,
                        config_operator=config_operator,
                        config_negate=config_negate,
                        node_operator=node_operator,
                        node_negate=node_negate,
                    )
                )
    return rows


def _flatten_legacy_configurations(
    configurations: Iterable[Dict[str, Any]],
    cve_id: str,
) -> List[Dict[str, Any]]:
    """Flatten the older legacy shape used by the R helper."""
    rows: List[Dict[str, Any]] = []
    for config_index, config in enumerate(configurations, start=1):
        config_operator = str(config.get("operator", "OR"))
        config_negate = bool(config.get("negate", False))

        if config_operator == "AND" and config.get("children"):
            children = config.get("children") or []
            for node_index, child in enumerate(children, start=1):
                node_operator = str(child.get("operator", "OR"))
                node_negate = bool(child.get("negate", False))
                matches = child.get("cpe_match") or child.get("cpeMatch") or []
                for match_index, match in enumerate(matches, start=1):
                    rows.append(
                        _normalize_match(
                            match,
                            cve_id=cve_id,
                            config_index=config_index,
                            node_index=node_index,
                            match_index=match_index,
                            config_operator=config_operator,
                            config_negate=config_negate,
                            node_operator=node_operator,
                            node_negate=node_negate,
                            legacy_group=f"vulnconf:{cve_id}:{node_index}:OR{match_index}:AND{config_index}",
                        )
                    )
            continue

        matches = config.get("cpe_match") or config.get("cpeMatch") or []
        for match_index, match in enumerate(matches, start=1):
            rows.append(
                _normalize_match(
                    match,
                    cve_id=cve_id,
                    config_index=config_index,
                    node_index=1,
                    match_index=match_index,
                    config_operator=config_operator,
                    config_negate=config_negate,
                    node_operator=config_operator,
                    node_negate=config_negate,
                    legacy_group=f"vulnconf:{cve_id}:{config_index}:OR{match_index}",
                )
            )
    return rows


def flatten_vulnerable_configurations(vulnconf: Any, cve_id: str) -> List[Dict[str, Any]]:
    """Flatten a CVE vulnerable configuration payload into explicit applicability rows.

    Supports both:
    - current NVD schema: configurations[].nodes[].cpeMatch[]
    - older legacy shape: [{operator, children, cpe_match}]
    """
    configurations = _as_list(vulnconf)
    if not configurations:
        return []

    first = configurations[0]
    if "nodes" in first:
        return _flatten_current_configurations(configurations, cve_id)
    return _flatten_legacy_configurations(configurations, cve_id)


def evaluate_cve_applicability(
    vulnconf: Any,
    cve_id: str,
    inventory_cpes: Iterable[str],
    match_criteria_to_cpes: Dict[str, Iterable[str]],
) -> Dict[str, Any]:
    """Evaluate CVE applicability against a concrete CPE inventory.

    This is the first exact semantic evaluator for Priority 3.
    It uses:
    - the preserved CVE boolean structure (`AND` / `OR` / `negate`)
    - concrete CPE expansion for each `matchCriteriaId`
    - an inventory set of observed/platform CPEs

    The result answers:
    - does the inventory satisfy any CVE applicability configuration?
    - which concrete inventory CPEs are the vulnerable ones?
    """
    rows = flatten_vulnerable_configurations(vulnconf, cve_id)
    inventory = set(inventory_cpes)
    config_groups: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        config_groups[row["configIndex"]].append(row)

    config_results: List[Dict[str, Any]] = []
    vulnerable_inventory_cpes: set[str] = set()

    for config_index in sorted(config_groups):
        config_rows = config_groups[config_index]
        config_operator = str(config_rows[0].get("configOperator", "OR"))
        config_negate = bool(config_rows[0].get("configNegate", False))
        node_groups: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        for row in config_rows:
            node_groups[row["nodeIndex"]].append(row)

        node_results: List[Dict[str, Any]] = []
        for node_index in sorted(node_groups):
            node_rows = node_groups[node_index]
            node_operator = str(node_rows[0].get("nodeOperator", "OR"))
            node_negate = bool(node_rows[0].get("nodeNegate", False))

            leaf_satisfied: List[bool] = []
            node_vulnerable_hits: set[str] = set()
            leaf_results: List[Dict[str, Any]] = []
            for row in node_rows:
                expanded = set(match_criteria_to_cpes.get(row.get("matchCriteriaId"), []))
                inventory_hits = sorted(inventory & expanded)
                satisfied = bool(inventory_hits)
                leaf_satisfied.append(satisfied)
                if row.get("vulnerable") and not node_negate:
                    node_vulnerable_hits.update(inventory_hits)
                leaf_results.append(
                    {
                        "matchCriteriaId": row.get("matchCriteriaId"),
                        "vulnerable": row.get("vulnerable"),
                        "expandedCpes": sorted(expanded),
                        "inventoryHits": inventory_hits,
                        "satisfied": satisfied,
                    }
                )

            base_node_satisfied = all(leaf_satisfied) if node_operator == "AND" else any(leaf_satisfied)
            node_satisfied = (not base_node_satisfied) if node_negate else base_node_satisfied
            if not node_satisfied:
                node_vulnerable_hits.clear()

            node_results.append(
                {
                    "nodeIndex": node_index,
                    "operator": node_operator,
                    "negate": node_negate,
                    "satisfied": node_satisfied,
                    "vulnerableInventoryCpes": sorted(node_vulnerable_hits),
                    "matches": leaf_results,
                }
            )

        node_satisfied_values = [node["satisfied"] for node in node_results]
        base_config_satisfied = (
            all(node_satisfied_values) if config_operator == "AND" else any(node_satisfied_values)
        )
        config_satisfied = (not base_config_satisfied) if config_negate else base_config_satisfied
        config_vulnerable_hits = (
            sorted({cpe for node in node_results for cpe in node["vulnerableInventoryCpes"]})
            if config_satisfied
            else []
        )
        vulnerable_inventory_cpes.update(config_vulnerable_hits)

        config_results.append(
            {
                "configIndex": config_index,
                "operator": config_operator,
                "negate": config_negate,
                "satisfied": config_satisfied,
                "vulnerableInventoryCpes": config_vulnerable_hits,
                "nodes": node_results,
            }
        )

    return {
        "cveId": cve_id,
        "satisfied": any(config["satisfied"] for config in config_results),
        "vulnerableInventoryCpes": sorted(vulnerable_inventory_cpes),
        "configurations": config_results,
    }
