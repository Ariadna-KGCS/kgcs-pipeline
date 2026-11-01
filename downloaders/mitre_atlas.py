"""
MITRE ATLAS downloader (spec 1.2.1, ADR-0004).

Fetches the versioned YAML dist/v6/ATLAS-<release>.yaml (format 6.0.0) from
mitre-atlas/atlas-data to data/raw/ATLAS/, never dist/ATLAS-latest.yaml (a
moving symlink), so BuildMetadata names what was loaded. The release is
pinned in downloaders.ingest_config.APIEndpoints.atlas_release; --release overrides it.
The STIX bundle is a release asset, not a dist/ file, and is not used.

Usage (from the repo root):
    python -m downloaders.mitre_atlas [--output-dir data/raw] [--release 2026.09]
"""

import logging
from pathlib import Path
from typing import Optional

import yaml

from .base import AbstractDownloader
from utils.http_client import HTTPClient

from downloaders.ingest_config import APIEndpoints


class MitreAtlasDownloader(AbstractDownloader):
    """Downloader for one pinned ATLAS release (YAML, format 6.0.0)."""

    def __init__(self, output_dir: str, timeout: int = 300, retries: int = 5,
                 release: Optional[str] = None):
        super().__init__(output_dir, timeout, retries)
        self.release = release or APIEndpoints.atlas_release
        self.http_client = HTTPClient(timeout, retries)

    @property
    def standard_name(self) -> str:
        return "ATLAS"

    @property
    def download_url(self) -> str:
        return f"{APIEndpoints.atlas_dist_base}v6/ATLAS-{self.release}.yaml"

    @property
    def target(self) -> Path:
        return self.get_standard_dir() / f"ATLAS-{self.release}.yaml"

    def download(self) -> bool:
        if not self.http_client.download_file(self.download_url, str(self.target)):
            self.log_error(f"ATLAS download failed: {self.download_url}")
            return False
        return self.validate()

    def validate(self) -> bool:
        """Format 6.x and collection.version equal to the pinned release."""
        try:
            with open(self.target, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError) as exc:
            self.log_error(f"ATLAS file unreadable: {exc}")
            return False
        fmt = str(doc.get("format-version", ""))
        version = str((doc.get("collection") or {}).get("version", ""))
        if not fmt.startswith("6.") or version != self.release:
            self.log_error(f"format {fmt!r}, collection.version {version!r}; expected 6.x / {self.release}")
            return False
        self.log_success(
            f"release {version} (format {fmt}): {len(doc.get('tactics') or {})} tactics, "
            f"{len(doc.get('techniques') or {})} techniques, "
            f"{len(doc.get('mitigations') or {})} mitigations -> {self.target}"
        )
        return True

    def save(self) -> bool:
        return self.validate()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Download a pinned MITRE ATLAS release (YAML)")
    parser.add_argument("--output-dir", default="data/raw")
    parser.add_argument("--release", help="ATLAS release, e.g. 2026.09 (default: ingest_config pin)")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    raise SystemExit(0 if MitreAtlasDownloader(args.output_dir, release=args.release).download() else 1)
