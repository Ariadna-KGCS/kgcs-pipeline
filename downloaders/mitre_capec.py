"""
MITRE CAPEC framework downloader.

Downloads Common Attack Pattern Enumeration and Classification (CAPEC) STIX 2.1 data.

Data source: https://github.com/mitre/cti (capec/2.1/)
"""

import logging
from pathlib import Path
import zipfile
import io

from .base import AbstractDownloader
from .validators import validate_json_file
from utils.http_client import HTTPClient


class MitreCapecDownloader(AbstractDownloader):
    """Downloader for MITRE CAPEC Framework (STIX 2.1)."""

    # GitHub repository URL for CTI (includes CAPEC)
    GITHUB_REPO = "https://github.com/mitre/cti/archive/refs/heads/master.zip"

    @property
    def standard_name(self) -> str:
        return "CAPEC"

    @property
    def download_url(self) -> str:
        return self.GITHUB_REPO

    def __init__(self, output_dir: str, timeout: int = 300, retries: int = 5):
        """Initialize CAPEC downloader."""
        super().__init__(output_dir, timeout, retries)
        self.http_client = HTTPClient(timeout, retries)

    def download(self) -> bool:
        """Download CAPEC STIX 2.1 data."""
        try:
            self.logger.info("Starting CAPEC download...")
            capec_dir = self.output_dir / self.standard_name
            capec_dir.mkdir(parents=True, exist_ok=True)

            # Download ZIP from GitHub
            self.logger.info("Downloading CAPEC from GitHub...")
            response = self.http_client.get(self.GITHUB_REPO, stream=True)

            if not response:
                self.log_error("Failed to download CAPEC from GitHub")
                return False

            # Extract ZIP in memory
            try:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content))
            except zipfile.BadZipFile:
                self.log_error("Downloaded file is not a valid ZIP")
                return False

            # Extract CAPEC STIX files from capec/2.1/ directory
            extracted_count = 0
            repo_prefix = None

            for zip_info in zip_file.filelist:
                # Identify repo root
                if repo_prefix is None and '/' in zip_info.filename:
                    repo_prefix = zip_info.filename.split('/')[0]

                # Look for CAPEC STIX files
                if 'cti-master/capec/2.1/' in zip_info.filename and zip_info.filename.endswith('.json'):
                    # Extract relative path
                    path_parts = Path(zip_info.filename).parts

                    # Find the capec/2.1 position
                    for i, part in enumerate(path_parts):
                        if part == '2.1':
                            remaining_path = Path(*path_parts[i+1:])
                            break

                    # Create target directory
                    target_file = capec_dir / remaining_path
                    target_file.parent.mkdir(parents=True, exist_ok=True)

                    # Extract file
                    with zip_file.open(zip_info) as source, open(target_file, 'wb') as target:
                        target.write(source.read())
                    extracted_count += 1

            if extracted_count == 0:
                self.log_error("No CAPEC STIX files found in ZIP")
                return False

            self.log_success(f"Extracted {extracted_count} CAPEC STIX files")
            return True

        except Exception as e:
            self.log_error(f"CAPEC download error: {e}")
            return False

    def validate(self) -> bool:
        """Validate downloaded CAPEC data."""
        try:
            capec_dir = self.output_dir / self.standard_name

            if not capec_dir.exists():
                self.log_error("CAPEC directory not found")
                return False

            json_files = list(capec_dir.glob("*.json"))
            if json_files:
                # Validate at least one file
                result = validate_json_file(str(json_files[0]), min_records=1)
                if result['valid']:
                    self.log_success(f"Validated CAPEC: {len(json_files)} STIX files")
                    return True
                else:
                    self.log_warning(f"Validation failed for CAPEC: {result['errors']}")
                    return False
            else:
                self.log_error("No CAPEC JSON files found")
                return False

        except Exception as e:
            self.log_error(f"CAPEC validation error: {e}")
            return False

    def save(self) -> bool:
        """CAPEC data is saved during download process."""
        return self.validate()
