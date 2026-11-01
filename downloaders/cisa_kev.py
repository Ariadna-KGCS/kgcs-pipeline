"""
CISA Known Exploited Vulnerabilities downloader (spec 1.2.0, ADR-0003).

Fetches the JSON feed (not the CSV twin) to data/raw/KEV/.
Schema: data/schemas/KEV/ (python scripts/download_schemas.py --standard kev).

Usage (from the repo root):
    python -m downloaders.cisa_kev [--output-dir data/raw]
"""

import json
import logging
from pathlib import Path

from .base import AbstractDownloader
from utils.http_client import HTTPClient

from downloaders.ingest_config import APIEndpoints

KEV_FILE = "known_exploited_vulnerabilities.json"


class CisaKevDownloader(AbstractDownloader):
    """Downloader for the CISA KEV catalog (JSON feed)."""

    @property
    def standard_name(self) -> str:
        return "KEV"

    @property
    def download_url(self) -> str:
        return APIEndpoints.kev_json

    def __init__(self, output_dir: str, timeout: int = 300, retries: int = 5):
        super().__init__(output_dir, timeout, retries)
        self.http_client = HTTPClient(timeout, retries)

    @property
    def target(self) -> Path:
        return self.get_standard_dir() / KEV_FILE

    def download(self) -> bool:
        ok = self.http_client.download_file(self.download_url, str(self.target))
        if not ok:
            self.log_error(f"KEV download failed: {self.download_url}")
        return ok and self.validate()

    def validate(self) -> bool:
        """Parseable, required top-level fields present, count = entries."""
        try:
            with open(self.target, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            self.log_error(f"KEV file unreadable: {exc}")
            return False
        missing = [k for k in ("catalogVersion", "dateReleased", "count", "vulnerabilities")
                   if k not in data]
        if missing:
            self.log_error(f"KEV file lacks {missing}")
            return False
        if data["count"] != len(data["vulnerabilities"]):
            self.log_error(f"KEV count {data['count']} != {len(data['vulnerabilities'])} entries")
            return False
        self.log_success(
            f"catalogVersion {data['catalogVersion']}, {data['count']} entries -> {self.target}"
        )
        return True

    def save(self) -> bool:
        return self.validate()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Download the CISA KEV JSON feed")
    parser.add_argument("--output-dir", default="data/raw")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    raise SystemExit(0 if CisaKevDownloader(args.output_dir).download() else 1)
