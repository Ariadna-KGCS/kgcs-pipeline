"""
MITRE D3FEND framework downloader.

Downloads D3FEND (Defensive Techniques) reference materials.

Note: D3FEND OWL ontology is not publicly available in a Git repository.
The framework can be accessed via the MITRE d3defend.mitre.org website or
integrated from published research papers.

This downloader is a placeholder for future availability.

Data source: https://d3fend.mitre.org/
"""

import logging
from pathlib import Path

from .base import AbstractDownloader


class MitreD3fendDownloader(AbstractDownloader):
    """Downloader for MITRE D3FEND Framework."""

    @property
    def standard_name(self) -> str:
        return "D3FEND"

    @property
    def download_url(self) -> str:
        return "https://d3fend.mitre.org/"

    def __init__(self, output_dir: str, timeout: int = 300, retries: int = 5):
        """Initialize D3FEND downloader."""
        super().__init__(output_dir, timeout, retries)

    def download(self) -> bool:
        """
        D3FEND OWL is not publicly available for automated download.

        To use D3FEND data:
        1. Visit https://d3fend.mitre.org/
        2. Download the OWL/JSON ontology manually
        3. Place it in data/raw/D3FEND/

        Alternative: Use the D3FEND API at https://d3fend.mitre.org/api/
        """
        self.logger.info("D3FEND download: OWL file not available in public repository")
        self.log_warning("D3FEND OWL ontology requires manual download from https://d3fend.mitre.org/")
        self.logger.info("To integrate D3FEND:")
        self.logger.info("  1. Visit https://d3fend.mitre.org/")
        self.logger.info("  2. Download OWL or JSON format")
        self.logger.info("  3. Place in data/raw/D3FEND/")
        return False  # Mark as not downloaded (data not available)

    def validate(self) -> bool:
        """Check if D3FEND data exists."""
        d3fend_dir = self.output_dir / self.standard_name

        if d3fend_dir.exists():
            files = list(d3fend_dir.glob("*"))
            if files:
                self.log_success(f"D3FEND data found ({len(files)} files)")
                return True

        self.log_warning("D3FEND data not found - manual download required")
        return False

    def save(self) -> bool:
        """D3FEND data must be downloaded manually."""
        return self.validate()
