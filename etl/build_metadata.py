"""
BuildMetadata postscript (spec 1.1.0, build-metadata-v1.0.owl, build.shacl.ttl v1.1).

Final step of the KGCS load: writes the single (:BuildMetadata) node that
records which spec, which pipeline commit and which exact source releases
the graph was built from. Not part of the causal chain; no edges.

    specVersion      SPEC_VERSION of this repo (the pinned kgcs-spec release)
    buildTimestamp   completion instant of the load (UTC, Neo4j datetime)
    pipelineCommit   git rev-parse HEAD of kgcs-pipeline
    sourceSnapshots  one "<SOURCE>=<snapshot>" per standard, read from the
                     same raw files the loaders read

Snapshot values (mapping-coverage-matrix-v1.1.md, "Build metadata"): the
release the source states wherever it states one, else the download instant.

    CWE      catalog Version attribute                     CWE=4.20
    CAPEC    catalog Version attribute                     CAPEC=3.9
    D3FEND   ontology owl:versionInfo (d3fend.json)        D3FEND=1.3.0
    ATTCK    x-mitre-collection x_mitre_version when all three bundles carry
             the same one; else download:<file date>;modified-max:<max
             `modified` date across the three bundles>. Never the
             x-mitre-matrix x_mitre_version.
    CVE      NVD feed `timestamp` of the CVE files (NVD states it, UTC)
    CVSS     same files as CVE, same value
    CPE      NVD feed `timestamp` of the CPE and CPE-MATCH chunks together
    CAR, SHIELD, ENGAGE   no release stated in the files: download:<file date>

Common rule: the release when the source states one (CWE, CAPEC, D3FEND,
ATT&CK collection); dates or ranges only when it has none.

NVD rule: one value when every file states the same timestamp, else the
range <min>..<max>, both UTC ISO-8601 to the second with Z, e.g.
    CVE=2026-08-28T03:03:23Z..2026-09-06T08:00:03Z
The yearly CVE feeds lag the modified feed by up to nine days on the
2026-09-06 download, so the max alone would overstate freshness. The CPE
range also covers CPE-MATCH. build.shacl.ttl only requires <SOURCE>=.+.

"file date" is the UTC date of the newest file mtime. The downloader
records nothing else; the evidence for these dates is the data/raw listing
(path, size, mtime, sha256) recorded with each validated load.

The node is MERGEd on its label alone, so a re-run updates the one node in
place; exactly-one-per-graph is a post-load check
(validation/validate_all_standards.py, build_metadata_singleton).
"""

import json
import logging
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from .load_attck import _find_attck_dir, _ordered_stix_files
from .load_cwe import select_cwe_xml

logger = logging.getLogger(__name__)

_REPO = Path(__file__).resolve().parents[1]

# build.shacl.ttl sh:pattern order of the ten KGCS standards
SOURCES = ("CPE", "CVE", "CVSS", "CWE", "CAPEC", "ATTCK", "D3FEND", "CAR", "SHIELD", "ENGAGE")

_CYPHER_BUILD_METADATA = """\
MERGE (b:BuildMetadata)
SET b.specVersion     = $specVersion,
    b.buildTimestamp  = datetime($buildTimestamp),
    b.pipelineCommit  = $pipelineCommit,
    b.sourceSnapshots = $sourceSnapshots
"""

_NVD_TIMESTAMP = re.compile(rb'"timestamp"\s*:\s*"([^"]+)"')
_OWL_NS = "http://www.w3.org/2002/07/owl#"


# ---------------------------------------------------------------------------
# Per-source readers: each returns the snapshot value or None (source absent)
# ---------------------------------------------------------------------------

def _file_date(paths: Iterable[Path]) -> Optional[str]:
    mtimes = [p.stat().st_mtime for p in paths]
    if not mtimes:
        return None
    return datetime.fromtimestamp(max(mtimes), tz=timezone.utc).strftime("%Y-%m-%d")


def xml_catalog_version(xml_path: Optional[Path]) -> Optional[str]:
    """Version attribute of the root element (CWE / CAPEC catalogs)."""
    if xml_path is None or not xml_path.exists():
        return None
    for _, elem in ET.iterparse(str(xml_path), events=("start",)):
        return elem.get("Version") or None   # root element only
    return None


def nvd_feed_timestamp(paths: Iterable[Path]) -> Optional[str]:
    """NVD feed `timestamp` (UTC, stated in each file header) as ...Z, or the
    <min>..<max> range when the files disagree.

    Only the first 4 KB of each file is read: NVD writes the header fields
    before the record array.
    """
    stamps: List[str] = []
    for p in paths:
        with open(p, "rb") as fh:
            m = _NVD_TIMESTAMP.search(fh.read(4096))
        if m:
            stamps.append(m.group(1).decode("ascii"))
    if not stamps:
        return None
    # to the second; ISO-8601 strings of one format sort chronologically
    seconds = sorted({st.split(".")[0] + "Z" for st in stamps})
    return seconds[0] if len(seconds) == 1 else f"{seconds[0]}..{seconds[-1]}"


def d3fend_version(d3fend_json: Path) -> Optional[str]:
    """owl:versionInfo of the owl:Ontology node in d3fend.json (JSON-LD)."""
    if not d3fend_json.exists():
        return None
    with open(d3fend_json, encoding="utf-8") as fh:
        data = json.load(fh)
    nodes = data.get("@graph", []) if isinstance(data, dict) else data
    for node in nodes:
        types = node.get("@type", [])
        types = types if isinstance(types, list) else [types]
        if "owl:Ontology" in types or f"{_OWL_NS}Ontology" in types:
            version = node.get("owl:versionInfo") or node.get(f"{_OWL_NS}versionInfo")
            if isinstance(version, dict):
                version = version.get("@value")
            if isinstance(version, list):
                version = version[0] if version else None
            return str(version) if version else None
    return None


def attck_snapshot(bundle_paths: List[Path]) -> Optional[str]:
    """Single ATTCK value for the three bundles (see module docstring)."""
    if not bundle_paths:
        return None
    collection_versions: List[Optional[str]] = []
    modified_max = ""
    for path in bundle_paths:   # one bundle in memory at a time
        with open(path, encoding="utf-8") as fh:
            objects = json.load(fh).get("objects", [])
        versions = {
            o.get("x_mitre_version") for o in objects
            if o.get("type") == "x-mitre-collection" and o.get("x_mitre_version")
        }
        collection_versions.append(versions.pop() if len(versions) == 1 else None)
        modified_max = max([modified_max] + [o.get("modified", "") for o in objects])
        del objects
    if len(bundle_paths) == 3 and None not in collection_versions \
            and len(set(collection_versions)) == 1:
        return collection_versions[0]
    return f"download:{_file_date(bundle_paths)};modified-max:{modified_max[:10]}"


def _json_files(directory: Path, pattern: str) -> List[Path]:
    return sorted(directory.glob(pattern)) if directory.is_dir() else []


def _car_dir(raw: Path) -> Path:
    # load_car.py accepts both spellings
    return raw / "car" if (raw / "car").is_dir() else raw / "CAR"


def source_snapshots(raw: Path) -> Tuple[List[str], List[str]]:
    """Return (["<SOURCE>=<snapshot>", ...] in SOURCES order, [missing SOURCE])."""
    cve_files = _json_files(raw / "CVE", "nvdcve-2.0-*.json")
    readers: Dict[str, Callable[[], Optional[str]]] = {
        "CPE": lambda: nvd_feed_timestamp(
            _json_files(raw / "CPE" / "nvdcpe-2.0-chunks", "*.json")
            + _json_files(raw / "CPE-MATCH" / "nvdcpematch-2.0-chunks", "*.json")
        ),
        "CVE": lambda: nvd_feed_timestamp(cve_files),
        "CVSS": lambda: nvd_feed_timestamp(cve_files),
        "CWE": lambda: xml_catalog_version(select_cwe_xml(raw / "CWE")),
        "CAPEC": lambda: xml_catalog_version(raw / "CAPEC" / "capec_latest.xml"),
        "ATTCK": lambda: attck_snapshot(
            _ordered_stix_files(_find_attck_dir(raw)) if _find_attck_dir(raw) else []
        ),
        "D3FEND": lambda: d3fend_version(raw / "D3FEND" / "d3fend.json"),
        "CAR": lambda: _download_date(_car_dir(raw).rglob("*.yaml")),
        "SHIELD": lambda: _download_date((raw / "SHIELD").glob("*.json")),
        "ENGAGE": lambda: _download_date((raw / "ENGAGE").glob("*.json")),
    }
    snapshots: List[str] = []
    missing: List[str] = []
    for source in SOURCES:
        value = readers[source]()
        if value:
            snapshots.append(f"{source}={value}")
        else:
            missing.append(source)
    return snapshots, missing


def _download_date(paths: Iterable[Path]) -> Optional[str]:
    date = _file_date(list(paths))
    return f"download:{date}" if date else None


# ---------------------------------------------------------------------------
# Build facts
# ---------------------------------------------------------------------------

def spec_version(repo: Path = _REPO) -> str:
    return (repo / "SPEC_VERSION").read_text(encoding="utf-8").strip()


def pipeline_commit(repo: Path = _REPO) -> Tuple[str, bool]:
    """(HEAD hash, working tree dirty?)."""
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()
    dirty = bool(subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=repo, capture_output=True, text=True, check=True,
    ).stdout.strip())
    return head, dirty


def build_record(raw: Path, now: Optional[datetime] = None) -> Tuple[Dict, List[str], bool]:
    """(Cypher parameters, missing sources, dirty tree) — no Neo4j access."""
    snapshots, missing = source_snapshots(raw)
    commit, dirty = pipeline_commit()
    now = now or datetime.now(timezone.utc)
    params = {
        "specVersion":     spec_version(),
        "buildTimestamp":  now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pipelineCommit":  commit,
        "sourceSnapshots": snapshots,
    }
    return params, missing, dirty


def run_build_metadata(writer, raw_data_dir: Path) -> Dict:
    """Pipeline step: write the BuildMetadata node. Returns {success, errors, stats}."""
    try:
        params, missing, dirty = build_record(Path(raw_data_dir))
    except Exception as exc:
        logger.error(f"[BuildMetadata] could not compute the record: {exc}")
        return {"success": False, "errors": [str(exc)], "stats": {}}
    if missing:
        logger.warning(f"[BuildMetadata] no raw data, no snapshot for: {', '.join(missing)}")
    if dirty:
        logger.warning(
            f"[BuildMetadata] working tree has uncommitted changes; "
            f"pipelineCommit {params['pipelineCommit'][:12]} does not describe them"
        )
    for snapshot in params["sourceSnapshots"]:
        logger.info(f"[BuildMetadata] {snapshot}")
    result = writer.execute_one(_CYPHER_BUILD_METADATA, params)
    stats = {
        "specVersion":    params["specVersion"],
        "pipelineCommit": params["pipelineCommit"],
        "snapshots":      len(params["sourceSnapshots"]),
        "missing":        missing,
    }
    return {"success": result["success"], "errors": result["errors"], "stats": stats}


if __name__ == "__main__":
    # Offline preview: python -m etl.build_metadata [raw_data_dir]
    import sys

    record, missing_sources, dirty_tree = build_record(
        Path(sys.argv[1] if len(sys.argv) > 1 else "data/raw")
    )
    print(json.dumps(
        {"record": record, "missing": missing_sources, "dirty": dirty_tree}, indent=2
    ))
