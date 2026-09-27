"""
FIRST EPSS daily scores downloader (spec 1.2.0, ADR-0003).

Fetches epss_scores-current.csv.gz (or a dated file with --date) and saves it
under data/raw/EPSS/ as epss_scores-<score date>.csv.gz, the score date read
from the file's own "#model_version:…,score_date:…" line (the file date is
the score date). The loader reads every dated file in the directory, so the
files kept there are the EPSS history depth (ADR-0003 Open question 3).

Usage (from the repo root):
    python -m downloaders.first_epss [--output-dir data/raw] [--date YYYY-MM-DD]
"""

import gzip
import logging
import re
from pathlib import Path
from typing import Optional

from .base import AbstractDownloader
from utils.http_client import HTTPClient

from ingest_config import APIEndpoints

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _score_day(path: Path) -> str:
    """Date part of score_date from the file's comment line (ValueError if absent)."""
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        line = fh.readline().strip()
        header = fh.readline().strip()
    fields = dict(p.split(":", 1) for p in line.lstrip("#").split(",") if ":" in p)
    if not line.startswith("#") or "score_date" not in fields or "model_version" not in fields:
        raise ValueError(f"no model_version/score_date line: {line[:80]!r}")
    if header != "cve,epss,percentile":
        raise ValueError(f"unexpected header {header!r}")
    return fields["score_date"][:10]


class FirstEpssDownloader(AbstractDownloader):
    """Downloader for one FIRST EPSS daily CSV."""

    def __init__(self, output_dir: str, timeout: int = 300, retries: int = 5,
                 date: Optional[str] = None):
        super().__init__(output_dir, timeout, retries)
        if date is not None and not _DATE.match(date):
            raise ValueError(f"--date must be YYYY-MM-DD, got {date!r}")
        self.date = date
        self.http_client = HTTPClient(timeout, retries)
        self.saved: Optional[Path] = None

    @property
    def standard_name(self) -> str:
        return "EPSS"

    @property
    def download_url(self) -> str:
        if self.date:
            return f"{APIEndpoints.epss_base}epss_scores-{self.date}.csv.gz"
        return APIEndpoints.epss_current

    def download(self) -> bool:
        tmp = self.get_standard_dir() / "epss_scores-download.tmp.gz"
        if not self.http_client.download_file(self.download_url, str(tmp)):
            self.log_error(f"EPSS download failed: {self.download_url}")
            return False
        try:
            day = _score_day(tmp)
        except (OSError, ValueError) as exc:
            self.log_error(f"EPSS file rejected: {exc}")
            tmp.unlink(missing_ok=True)
            return False
        if self.date and day != self.date:
            self.log_error(f"asked for {self.date}, file states score_date {day}")
            tmp.unlink(missing_ok=True)
            return False
        self.saved = self.get_standard_dir() / f"epss_scores-{day}.csv.gz"
        tmp.replace(self.saved)
        self.log_success(f"score date {day} -> {self.saved}")
        return True

    def validate(self) -> bool:
        files = sorted(self.get_standard_dir().glob("epss_scores-????-??-??.csv.gz"))
        for path in files:
            try:
                if _score_day(path) != path.name[len("epss_scores-"):-len(".csv.gz")]:
                    self.log_error(f"{path.name}: name and score_date disagree")
                    return False
            except (OSError, ValueError) as exc:
                self.log_error(f"{path.name}: {exc}")
                return False
        if not files:
            self.log_warning("no dated EPSS file")
        return bool(files)

    def save(self) -> bool:
        return self.validate()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Download one FIRST EPSS daily CSV")
    parser.add_argument("--output-dir", default="data/raw")
    parser.add_argument("--date", help="dated file YYYY-MM-DD (default: current)")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    raise SystemExit(0 if FirstEpssDownloader(args.output_dir, date=args.date).download() else 1)
