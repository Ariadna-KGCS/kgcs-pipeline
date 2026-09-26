"""
Shared transforms for the CWE / CAPEC XML enrichment (spec 1.1.0).

Consequence sub-nodes (ADR-0001, mappings/consequences-to-owl-v1.0.md):
  one XML Consequence record = one (:Consequence) node, key
  "<parentId>-C<ordinal>" (ordinal = document order, from 1), hanging from
  its parent Weakness / AttackPattern by HAS_CONSEQUENCE. The record's own
  Scope / Impact values stay grouped as arrays on that node and are never
  combined across records.

Vocabularies are per standard and never merged: the Scope wording is the
same 9 values in both XSDs, but CWE's Impact enum has 25 values and
CAPEC's has 10. tests/test_consequences.py checks these tuples against the
sh:in lists of the pinned spec/shapes.

StructuredText flattening (cwe-enrichment-to-owl-v1.0.md, rule 1):
  itertext(), collapse whitespace runs to one space, strip; list and
  paragraph boundaries become spaces; an empty result means the property
  is omitted.
"""

import xml.etree.ElementTree as ET
from typing import Dict, Iterable, List, Optional, Sequence

SCOPES = (
    "Confidentiality", "Integrity", "Availability", "Access Control",
    "Accountability", "Authentication", "Authorization", "Non-Repudiation",
    "Other",
)

CWE_IMPACTS = (
    "Modify Memory", "Read Memory", "Modify Files or Directories",
    "Read Files or Directories", "Modify Application Data",
    "Read Application Data", "DoS: Crash, Exit, or Restart",
    "DoS: Amplification", "DoS: Instability",
    "DoS: Resource Consumption (CPU)", "DoS: Resource Consumption (Memory)",
    "DoS: Resource Consumption (Other)",
    "Execute Unauthorized Code or Commands",
    "Gain Privileges or Assume Identity", "Bypass Protection Mechanism",
    "Hide Activities", "Alter Execution Logic", "Quality Degradation",
    "Unexpected State", "Varies by Context", "Increase Analytical Complexity",
    "Reduce Maintainability", "Reduce Performance", "Reduce Reliability",
    "Other",
)

CAPEC_IMPACTS = (
    "Modify Data", "Read Data", "Unreliable Execution", "Resource Consumption",
    "Execute Unauthorized Commands", "Gain Privileges",
    "Bypass Protection Mechanism", "Hide Activities", "Alter Execution Logic",
    "Other",
)

LIKELIHOODS = ("High", "Medium", "Low", "Unknown")


# XHTML block elements: their boundaries become a space even when the XML
# has no whitespace between them (<li>a</li><li>b</li> -> "a b"); inline
# markup (<b>, <i>, <code>, ...) joins without one.
_BLOCK_TAGS = frozenset({
    "p", "div", "br", "ul", "ol", "li", "table", "tr", "td", "th",
    "pre", "blockquote", "dl", "dt", "dd",
})


def _text_parts(elem: ET.Element, parts: List[str]) -> None:
    if elem.text:
        parts.append(elem.text)
    for child in elem:
        block = child.tag.rsplit("}", 1)[-1] in _BLOCK_TAGS
        if block:
            parts.append(" ")
        _text_parts(child, parts)
        if block:
            parts.append(" ")
        if child.tail:
            parts.append(child.tail)


def flatten_text(elem: Optional[ET.Element]) -> Optional[str]:
    """Flatten an element subtree to one line of text; None when empty.

    Same text nodes as itertext(); whitespace runs collapse to one space.
    """
    if elem is None:
        return None
    parts: List[str] = []
    _text_parts(elem, parts)
    text = " ".join("".join(parts).split())
    return text or None


def unique_texts(elems: Iterable[ET.Element]) -> List[str]:
    """Stripped, non-empty element texts, deduplicated in document order."""
    seen: Dict[str, None] = {}
    for e in elems:
        value = (e.text or "").strip()
        if value:
            seen.setdefault(value, None)
    return list(seen)


def unique_attrs(elems: Iterable[ET.Element], attr: str) -> List[str]:
    """Stripped, non-empty attribute values, deduplicated in document order."""
    seen: Dict[str, None] = {}
    for e in elems:
        value = (e.get(attr) or "").strip()
        if value:
            seen.setdefault(value, None)
    return list(seen)


def consequence_records(
    parent_id: str, consequences: Sequence[ET.Element], ns: str
) -> List[Dict]:
    """One Neo4j row per Consequence element of one parent, in document order.

    Absent optional fields are None (the node property is then removed by
    SET, so a refresh drops values MITRE deleted). Empty arrays are None,
    never [].
    """
    rows: List[Dict] = []
    for ordinal, c in enumerate(consequences, 1):
        rows.append({
            "parentId":      parent_id,
            "consequenceId": f"{parent_id}-C{ordinal}",
            "scopes":        unique_texts(c.findall(f"{ns}Scope")) or None,
            "impacts":       unique_texts(c.findall(f"{ns}Impact")) or None,
            "likelihood":    (c.findtext(f"{ns}Likelihood") or "").strip() or None,
            "note":          flatten_text(c.find(f"{ns}Note")),
        })
    return rows


def out_of_vocabulary(rows: Iterable[Dict], impacts: Sequence[str]) -> List[str]:
    """Human-readable list of values outside the owning standard's enums."""
    bad: List[str] = []
    for r in rows:
        for s in r["scopes"] or []:
            if s not in SCOPES:
                bad.append(f"{r['consequenceId']} scope {s!r}")
        for i in r["impacts"] or []:
            if i not in impacts:
                bad.append(f"{r['consequenceId']} impact {i!r}")
        if r["likelihood"] is not None and r["likelihood"] not in LIKELIHOODS:
            bad.append(f"{r['consequenceId']} likelihood {r['likelihood']!r}")
    return bad
