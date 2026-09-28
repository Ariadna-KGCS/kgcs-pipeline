"""
Shared pieces of the decision-extension loaders (spec 1.2, ADR-0003).

KEV, EPSS and SSVC nodes are leaves adhered to an existing Vulnerability.
A row whose CVE has no Vulnerability node is dropped and counted, never
created: the loaders ask the graph which of a batch's cveIds exist before
writing, so no orphan leaf is ever MERGEd.
"""

from typing import Iterable, List, Set

_CYPHER_EXISTING_CVES = """\
UNWIND $ids AS id
MATCH (v:Vulnerability {cveId: id})
RETURN id
"""


def existing_cve_ids(writer, ids: Iterable[str], batch_size: int = 5000) -> Set[str]:
    """Subset of ids that have a (:Vulnerability {cveId}) node (read-only)."""
    ids = list(dict.fromkeys(ids))
    found: Set[str] = set()
    for start in range(0, len(ids), batch_size):
        chunk: List[str] = ids[start:start + batch_size]
        found.update(r["id"] for r in writer.read_rows(_CYPHER_EXISTING_CVES, {"ids": chunk}))
    return found


def label_count(writer, label: str) -> int:
    """count(n:label); label comes from the loader's own constant, never input."""
    return writer.read_one(f"MATCH (n:{label}) RETURN count(n)") or 0
