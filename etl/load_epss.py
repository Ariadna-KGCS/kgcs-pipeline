"""
ETL loader for FIRST EPSS daily scores (spec 1.2.0, ADR-0003,
mappings/epss-to-owl-v1.0.md).

Decision step, right after load_cvss: HAS_EPSS targets Vulnerability nodes.

Node types created:
  - EpssScore  (epssId unique key: "<cve>::EPSS::<scoreDate>")

Relationships created:
  - (Vulnerability)-[:HAS_EPSS]->(EpssScore)

Data source:
  - data/raw/EPSS/epss_scores-<YYYY-MM-DD>.csv.gz (gzip CSV, ~380k rows).
    Line 1: "#model_version:<v>,score_date:<ISO timestamp>"; line 2: the
    header "cve,epss,percentile". Every dated file in the directory is
    loaded (history depth = the files present; ADR-0003 Open question 3).
    The undated epss_scores-current.csv.gz is read only when no dated file
    exists; a file whose score_date was already read in this run is skipped.

Rules (epss-to-owl-v1.0.md, "Transformation Rules"):
  1. Append-only: MERGE on epssId, ON CREATE SET only; an existing node is
     never modified, so reloading a file is a no-op and count(EpssScore)
     never decreases (checked before/after).
  2. One node per (CVE, score date).
  3. modelVersion travels with every node; KGCS derives nothing from score.
  4. Rows whose CVE has no Vulnerability node are dropped and counted.

Streaming: rows are read and written one batch at a time (Hard Rule 4).
"""

import csv
import gzip
import logging
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .base import AbstractETL
from .decision_common import existing_cve_ids, label_count

logger = logging.getLogger(__name__)

_DATED = re.compile(r"^epss_scores-(\d{4}-\d{2}-\d{2})\.csv\.gz$")
CURRENT_FILE = "epss_scores-current.csv.gz"
_HEADER = ["cve", "epss", "percentile"]

_CYPHER_EPSS = """\
UNWIND $batch AS row
MATCH (v:Vulnerability {cveId: row.cveId})
MERGE (e:EpssScore {epssId: row.epssId})
ON CREATE SET
    e.cveId          = row.cveId,
    e.score          = row.score,
    e.percentile     = row.percentile,
    e.scoreDate      = row.scoreDate,
    e.scoreTimestamp = row.scoreTimestamp,
    e.modelVersion   = row.modelVersion
MERGE (v)-[:HAS_EPSS]->(e)
"""


def parse_comment(line: str) -> Dict[str, str]:
    """'#model_version:v2026.06.15,score_date:2026-09-27T12:00:21Z' -> dict.

    Raises ValueError when either key is missing (pre-2022 EPSS v1 files have
    no comment line and are not loadable by this mapping).
    """
    if not line.startswith("#"):
        raise ValueError(f"EPSS file has no '#model_version…' line: {line[:60]!r}")
    fields: Dict[str, str] = {}
    for part in line[1:].strip().split(","):
        key, sep, value = part.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    for key in ("model_version", "score_date"):
        if not fields.get(key):
            raise ValueError(f"EPSS comment line lacks {key}: {line[:80]!r}")
    return fields


def epss_files(epss_dir: Path) -> List[Path]:
    """Dated files in date order; the 'current' file only if none is dated."""
    if not epss_dir.is_dir():
        return []
    dated = sorted(p for p in epss_dir.iterdir() if _DATED.match(p.name))
    if dated:
        return dated
    current = epss_dir / CURRENT_FILE
    return [current] if current.exists() else []


def read_header(path: Path) -> Dict[str, str]:
    """{model_version, score_date (verbatim timestamp), score_day (YYYY-MM-DD)}."""
    with gzip.open(path, "rt", encoding="utf-8", newline="") as fh:
        meta = parse_comment(fh.readline())
    meta["score_day"] = meta["score_date"][:10]
    return meta


def iter_epss_rows(path: Path) -> Iterator[Tuple[Dict[str, str], Dict[str, Any]]]:
    """Yield (header meta, node dict) per CSV row, streaming the gzip file.

    Values: score and percentile as floats parsed from the published
    decimal string (no rounding, no rescaling); rows outside [0, 1] raise.
    """
    with gzip.open(path, "rt", encoding="utf-8", newline="") as fh:
        meta = parse_comment(fh.readline())
        day = meta["score_date"][:10]
        reader = csv.reader(fh)
        header = next(reader, None)
        if header != _HEADER:
            raise ValueError(f"{path.name}: unexpected EPSS header {header}")
        for row in reader:
            if not row:
                continue
            cve, epss, percentile = row
            score, pct = float(epss), float(percentile)
            if not (0.0 <= score <= 1.0 and 0.0 <= pct <= 1.0):
                raise ValueError(f"{path.name}: {cve} out of [0, 1]: {epss}, {percentile}")
            yield meta, {
                "epssId":         f"{cve}::EPSS::{day}",
                "cveId":          cve,
                "score":          score,
                "percentile":     pct,
                "scoreDate":      day,
                "scoreTimestamp": meta["score_date"],
                "modelVersion":   meta["model_version"],
            }


def epss_snapshot(raw_data_dir: Path) -> Optional[str]:
    """BuildMetadata value EPSS=<scoreDate>;model:<modelVersion>.

    One file: that pair. Several (history back-fill): <first>..<last> dates
    and the distinct model versions in date order, joined by '+'.
    """
    files = epss_files(Path(raw_data_dir) / "EPSS")
    if not files:
        return None
    metas = [read_header(p) for p in files]
    days = sorted({m["score_day"] for m in metas})
    models = list(dict.fromkeys(m["model_version"] for m in sorted(metas, key=lambda m: m["score_day"])))
    day = days[0] if len(days) == 1 else f"{days[0]}..{days[-1]}"
    return f"{day};model:{'+'.join(models)}"


class EPSSLoader(AbstractETL):
    """EpssScore leaves from FIRST EPSS daily CSV files (streaming)."""

    @property
    def standard_name(self) -> str:
        return "EPSS"

    def extract(self) -> Any:
        return None

    def transform(self, raw_data: Any) -> List[Dict]:
        return []

    def load_nodes(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    def load_relationships(self, records: List[Dict]) -> Dict[str, Any]:
        return self._empty_result()

    def _write(self, batch: List[Dict], stats: Dict[str, Any], errors: List[str]) -> None:
        present = existing_cve_ids(self.writer, [r["cveId"] for r in batch])
        rows = [r for r in batch if r["cveId"] in present]
        stats["dropped_no_vulnerability"] += len(batch) - len(rows)
        stats["loaded"] += len(rows)
        r = self.writer.execute_batch(_CYPHER_EPSS, rows, self.batch_size)
        stats["nodes_created"] += r.get("nodes_created", 0)
        stats["rels_created"] += r.get("rels_created", 0)
        errors.extend(r.get("errors", []))

    def run(self) -> Dict[str, Any]:
        files = epss_files(self.standard_dir)
        if not files:
            return self._error_result(f"No EPSS file in {self.standard_dir}")
        stats: Dict[str, Any] = {
            "nodes_created": 0, "rels_created": 0, "rows": 0, "loaded": 0,
            "dropped_no_vulnerability": 0, "files": [], "skipped_files": [],
        }
        errors: List[str] = []
        try:
            before = label_count(self.writer, "EpssScore")
            seen_days = set()
            for path in files:
                meta = read_header(path)
                if meta["score_day"] in seen_days:
                    self.log_warning(f"{path.name}: score date {meta['score_day']} already read; skipped")
                    stats["skipped_files"].append(path.name)
                    continue
                seen_days.add(meta["score_day"])
                self.log_success(
                    f"{path.name}: score_date {meta['score_date']}, model {meta['model_version']}"
                )
                batch: List[Dict] = []
                file_rows = 0
                for _, rec in iter_epss_rows(path):
                    batch.append(rec)
                    file_rows += 1
                    if len(batch) >= self.batch_size:
                        self._write(batch, stats, errors)
                        batch = []
                if batch:
                    self._write(batch, stats, errors)
                stats["rows"] += file_rows
                stats["files"].append(f"{path.name}:{meta['score_day']}:{meta['model_version']}:{file_rows}")
            after = label_count(self.writer, "EpssScore")
            stats["epss_nodes_before"], stats["epss_nodes_after"] = before, after
            if after < before:
                errors.append(f"count(EpssScore) decreased: {before} -> {after}")
        except (OSError, ValueError) as exc:
            errors.append(f"EPSS read failed: {exc}")

        if stats["dropped_no_vulnerability"]:
            self.log_warning(f"{stats['dropped_no_vulnerability']} rows dropped (no Vulnerability node)")
        result = {"success": not errors, "errors": errors, "stats": stats}
        if result["success"]:
            self.log_success(f"Complete: {stats}")
        else:
            self.log_error(f"Completed with {len(errors)} errors: {errors[:3]}")
        return result
