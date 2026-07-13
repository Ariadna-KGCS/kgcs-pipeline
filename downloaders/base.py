"""
Abstract base class for all standard-specific downloaders.

Provides a common interface for downloading, extracting, validating, and saving
cybersecurity standard data (CVE, CWE, CPE, CVSS, CAPEC, ATT&CK, D3FEND, CAR, ENGAGE, SHIELD).
"""

import json
import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Dict, Any


class AbstractDownloader(ABC):
    """
    Abstract base class for downloading and processing security standard data.

    Subclasses must implement:
    - download(): Fetch data from the source
    - validate(): Verify downloaded data integrity
    """

    def __init__(self, output_dir: str, timeout: int = 300, retries: int = 5):
        """
        Initialize downloader.

        Args:
            output_dir: Base directory for saving raw data (e.g., 'data/raw')
            timeout: HTTP request timeout in seconds
            retries: Number of retry attempts for failed downloads
        """
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.retries = retries
        self.logger = logging.getLogger(self.__class__.__name__)

        # Create output directory if needed
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @property
    @abstractmethod
    def standard_name(self) -> str:
        """Return the name of the security standard (e.g., 'CVE', 'ATT&CK')."""
        pass

    @property
    @abstractmethod
    def download_url(self) -> str:
        """Return the primary download URL or source for this standard."""
        pass

    @abstractmethod
    def download(self) -> bool:
        """
        Download data from source.

        Returns:
            True if download successful, False otherwise
        """
        pass

    @abstractmethod
    def validate(self) -> bool:
        """
        Validate downloaded data integrity.

        Checks:
        - File existence
        - Format validation (JSON, XML, OWL)
        - Basic sanity checks (file size, record counts)

        Returns:
            True if validation passes, False otherwise
        """
        pass

    @abstractmethod
    def save(self) -> bool:
        """
        Save downloaded data to output directory.

        Returns:
            True if save successful, False otherwise
        """
        pass

    def get_standard_dir(self) -> Path:
        """Get the directory for this standard's data (e.g., data/raw/CVE/)."""
        standard_dir = self.output_dir / self.standard_name
        standard_dir.mkdir(parents=True, exist_ok=True)
        return standard_dir

    def get_metadata_dir(self) -> Path:
        """Get the metadata directory for validation reports."""
        metadata_dir = self.output_dir / '.metadata'
        metadata_dir.mkdir(parents=True, exist_ok=True)
        return metadata_dir

    def log_success(self, message: str):
        """Log successful operation."""
        self.logger.info(f"[{self.standard_name}] ✓ {message}")

    def log_warning(self, message: str):
        """Log warning message."""
        self.logger.warning(f"[{self.standard_name}] ⚠ {message}")

    def log_error(self, message: str):
        """Log error message."""
        self.logger.error(f"[{self.standard_name}] ✗ {message}")

    def save_validation_report(self, report: Dict[str, Any]):
        """
        Save validation report to JSON file.

        Args:
            report: Dictionary containing validation results
        """
        report_path = self.get_metadata_dir() / f"{self.standard_name.lower()}-validation.json"
        try:
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            self.log_success(f"Validation report saved to {report_path}")
        except Exception as e:
            self.log_error(f"Failed to save validation report: {e}")
