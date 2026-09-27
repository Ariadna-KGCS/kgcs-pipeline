"""
Offline expected counts for the spec 1.2 loaders (session Q18): the decision
extension (KEV, EPSS, SSVC; ADR-0003) and the ATLAS module (ADR-0004).

Computes, from data/raw only (no Neo4j), the nodes and edges that
load_kev / load_epss / load_ssvc / load_atlas write, using their own
transform functions and the loaders' MATCH semantics:

  - a decision leaf is written only when its CVE is a Vulnerability node,
    i.e. a CVE id present in the NVD files (load_cve.py MERGEs them all);
  - ADAPTED_FROM is written only to an ATT&CK id that the loaded bundles
    hold live, after the shared revoked-by remap (attck_revocations.py);
    live ids are exactly the Technique / SubTechnique nodes load_attck.py
    writes.

The chain is untouched: the v1.2 loaders add labels and edge types only, so
every chain count (PART_OF, SUBTECHNIQUE_OF, CAUSED_BY, …) has delta 0.

Usage (from the repo root):
    python validation/expected_v12_deltas.py                       # markdown to stdout
    python validation/expected_v12_deltas.py --json out.json
    python validation/expected_v12_deltas.py --skip-cve            # no NVD scan (KEV/EPSS/SSVC not computed)
    $env:NEO4J_DATABASE='kgcs-q-smoke'; python validation/expected_v12_deltas.py --compare-neo4j
        # read the observed counts from NEO4J_DATABASE (read-only) and exit 1 on any difference
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Optional, Set

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from etl.attck_revocations import build_revocation_remap  # noqa: E402
from etl.load_atlas import (  # noqa: E402
    read_atlas, resolve_adapted_from, select_atlas_yaml, transform_atlas,
)
from etl.load_attck import _find_attck_dir, _ordered_stix_files  # noqa: E402
from etl.load_cvss import _ordered_cve_files  # noqa: E402
from etl.load_epss import epss_files, iter_epss_rows, read_header  # noqa: E402
from etl.load_kev import KEV_FILE, kev_records, read_catalog  # noqa: E402
from etl.load_ssvc import ssvc_records  # noqa: E402


def scan_cve(raw: Path) -> Dict:
    """CVE id set and SSVC records, one NVD file in memory at a time."""
    cve_ids: Set[str] = set()
    ssvc_ids: Dict[str, str] = {}      # ssvcId -> cveId
    per_file: Dict[str, Dict[str, int]] = {}
    drops: Counter = Counter()
    adp_entries = 0
    for path in _ordered_cve_files(raw / "CVE"):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        entries = adp = 0
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            cve_ids.add(cid)
            raw_entries = cve.get("metrics", {}).get("ssvcV203") or []
            if not raw_entries:
                continue
            entries += len(raw_entries)
            records, dropped = ssvc_records(cve)
            drops.update(dropped)
            adp += len(records)
            for r in records:
                ssvc_ids.setdefault(r["ssvcId"], r["cveId"])
        adp_entries += adp
        per_file[path.name] = {"ssvcV203_entries": entries, "adp_loadable_entries": adp}
        del data
    return {"cve_ids": cve_ids, "ssvc_ids": ssvc_ids, "per_file": per_file,
            "drops": drops, "adp_entries": adp_entries}


def compute(raw: Path, skip_cve: bool) -> Dict:
    out: Dict = {"raw_data_dir": str(raw)}
    cve_ids: Optional[Set[str]] = None
    if not skip_cve:
        scan = scan_cve(raw)
        cve_ids = scan["cve_ids"]
        ssvc = scan["ssvc_ids"]
        written = sum(1 for c in ssvc.values() if c in cve_ids)
        out["Vulnerability"] = len(cve_ids)
        out["SSVC"] = {
            "ssvcV203_entries_per_file": scan["per_file"],
            "adp_loadable_entries": scan["adp_entries"],
            "distinct_decisions": len(ssvc),
            "duplicates_collapsed": scan["adp_entries"] - len(ssvc),
            "distinct_cves": len(set(ssvc.values())),
            "dropped": dict(sorted(scan["drops"].items())),
            "SsvcDecision": written, "HAS_SSVC": written,
            "dropped_no_vulnerability": len(ssvc) - written,
        }

    catalog = read_catalog(raw / "KEV" / KEV_FILE)
    kev, kev_counts = kev_records(catalog)
    kev_out: Dict = {"catalogVersion": catalog.get("catalogVersion"),
                     "entries": kev_counts["entries"], "duplicates": kev_counts["duplicates"]}
    if cve_ids is not None:
        missing = sorted(r["cveId"] for r in kev if r["cveId"] not in cve_ids)
        kev_out.update({"KevEntry": len(kev) - len(missing), "HAS_KEV_ENTRY": len(kev) - len(missing),
                        "dropped_no_vulnerability": len(missing), "dropped_ids": missing})
    out["KEV"] = kev_out

    files = epss_files(raw / "EPSS")
    epss_out: Dict = {"files": [p.name for p in files],
                      "headers": [read_header(p) for p in files]}
    if cve_ids is not None:
        rows = matched = 0
        seen_days = set()
        for p in files:
            day = read_header(p)["score_day"]
            if day in seen_days:
                continue
            seen_days.add(day)
            for _, rec in iter_epss_rows(p):
                rows += 1
                matched += rec["cveId"] in cve_ids
        epss_out.update({"rows": rows, "EpssScore": matched, "HAS_EPSS": matched,
                         "dropped_no_vulnerability": rows - matched})
    out["EPSS"] = epss_out

    path = select_atlas_yaml(raw / "ATLAS")
    data = transform_atlas(read_atlas(path))
    remap = build_revocation_remap(_ordered_stix_files(_find_attck_dir(raw)))
    adapted, rc = resolve_adapted_from(data["attack_refs"], remap)
    written = [e for e in adapted if e["tgt"] in remap.live]
    out["ATLAS"] = {
        "file": path.name, "release": data["release"], **data["counts"],
        "ADAPTED_FROM_rows": rc["rows"], "ADAPTED_FROM": len(written),
        "ADAPTED_FROM_remapped": rc["remapped"],
        "ADAPTED_FROM_remapped_detail": [
            f"{e['src']}: {e['attackReferenceId']} -> {e['tgt']}"
            for e in adapted if e["tgt"] != e["attackReferenceId"]],
        "ADAPTED_FROM_dropped_deprecated": rc["dropped_deprecated"],
        "ADAPTED_FROM_unresolved": rc["unresolved"] + len(adapted) - len(written),
        "ADAPTED_FROM_unresolved_ids": rc["unresolved_ids"],
        "ADAPTED_FROM_distinct_targets": len({e["tgt"] for e in written}),
        "ADAPTED_FROM_to_SubTechnique": sum(e["tgtLabel"] == "SubTechnique" for e in written),
    }
    return out


def expected_counts(r: Dict) -> Dict[str, int]:
    """Flat label / type -> expected count, for --compare-neo4j."""
    a = r["ATLAS"]
    exp = {
        "AtlasTactic": a["tactics"], "AtlasTechnique": a["techniques"],
        "AtlasSubTechnique": a["subtechniques"], "AtlasMitigation": a["mitigations"],
        "ACHIEVES": a["achieves"], "SPECIALIZES": a["specializes"],
        "MITIGATES": a["mitigates"], "ADAPTED_FROM": a["ADAPTED_FROM"],
    }
    if "KevEntry" in r["KEV"]:
        exp.update({k: r["KEV"][k] for k in ("KevEntry", "HAS_KEV_ENTRY")})
        exp.update({k: r["EPSS"][k] for k in ("EpssScore", "HAS_EPSS")})
        exp.update({k: r["SSVC"][k] for k in ("SsvcDecision", "HAS_SSVC")})
    return exp


_NODE_LABELS = ("KevEntry", "EpssScore", "SsvcDecision", "AtlasTactic", "AtlasTechnique",
                "AtlasSubTechnique", "AtlasMitigation")


def observed_counts(names) -> Dict[str, int]:
    from etl import Neo4jWriter

    got: Dict[str, int] = {}
    with Neo4jWriter() as writer:
        for name in names:
            q = (f"MATCH (n:{name}) RETURN count(n)" if name in _NODE_LABELS
                 else f"MATCH ()-[r:{name}]->() RETURN count(r)")
            got[name] = writer.read_one(q)
    return got


def to_markdown(r: Dict) -> str:
    lines = ["| Item | Expected |", "| --- | --- |"]
    for k, v in expected_counts(r).items():
        lines.append(f"| {k} | {v:,} |")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--raw-data-dir", default="data/raw")
    parser.add_argument("--skip-cve", action="store_true", help="skip the ~3 GB NVD scan")
    parser.add_argument("--json", metavar="PATH", help="also write the full result as JSON")
    parser.add_argument("--compare-neo4j", action="store_true",
                        help="compare with the counts on NEO4J_DATABASE (read-only)")
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")

    r = compute(Path(args.raw_data_dir), args.skip_cve)
    if args.json:
        Path(args.json).write_text(json.dumps(r, indent=1, sort_keys=True) + "\n",
                                   encoding="utf-8", newline="\n")
    print(to_markdown(r))
    if not args.compare_neo4j:
        return 0
    exp = expected_counts(r)
    got = observed_counts(exp)
    bad = {k: (exp[k], got[k]) for k in exp if exp[k] != got[k]}
    print("\n| Item | Expected | Observed |\n| --- | --- | --- |")
    for k in exp:
        print(f"| {k} | {exp[k]:,} | {got[k]:,}{'  **DIFF**' if k in bad else ''} |")
    print(f"\n{'EQUAL' if not bad else f'{len(bad)} DIFFERENCES'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
