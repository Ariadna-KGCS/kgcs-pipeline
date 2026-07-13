"""
MITRE ATT&CK Framework downloader.

Downloads MITRE ATT&CK framework in STIX 2.0 format.
Includes Enterprise, ICS, and Mobile matrices.

Data source: https://github.com/mitre/cti
"""

import json
import logging
from pathlib import Path
import zipfile
import io
from typing import Optional

from .base import AbstractDownloader
from .validators import validate_json_file
from utils.http_client import HTTPClient


class MitreAttckDownloader(AbstractDownloader):
    """Downloader for MITRE ATT&CK Framework (STIX 2.0)."""

    # GitHub raw content URLs for ATT&CK STIX bundles
    GITHUB_REPO = "https://github.com/mitre/cti/archive/refs/heads/master.zip"

    @property
    def standard_name(self) -> str:
        return "ATTCK-STIX"

    @property
    def download_url(self) -> str:
        return self.GITHUB_REPO

    def __init__(self, output_dir: str, timeout: int = 300, retries: int = 5):
        """Initialize ATT&CK downloader."""
        super().__init__(output_dir, timeout, retries)
        self.http_client = HTTPClient(timeout, retries)

    def download(self) -> bool:
        """Download ATT&CK STIX data."""
        try:
            self.logger.info("Starting ATT&CK download...")
            attck_dir = self.output_dir / self.standard_name
            attck_dir.mkdir(parents=True, exist_ok=True)

            # Download ZIP from GitHub
            self.logger.info("Downloading ATT&CK from GitHub...")
            response = self.http_client.get(self.GITHUB_REPO, stream=True)

            if not response:
                self.log_error("Failed to download ATT&CK from GitHub")
                return False

            # Extract ZIP in memory
            try:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content))
            except zipfile.BadZipFile:
                self.log_error("Downloaded file is not a valid ZIP")
                return False

            # Extract STIX bundles
            # Structure: cti-master/enterprise-attack/, cti-master/ics-attack/, cti-master/mobile-attack/
            extracted_count = 0

            for zip_info in zip_file.filelist:
                # Look for STIX JSON files in attack directories
                if any(attack_type in zip_info.filename for attack_type in ['enterprise-attack', 'ics-attack', 'mobile-attack']):
                    if zip_info.filename.endswith('.json'):
                        # Extract relative path
                        path_parts = Path(zip_info.filename).parts

                        # Find the attack type
                        attack_type = None
                        for i, part in enumerate(path_parts):
                            if 'attack' in part:
                                attack_type = part
                                remaining_path = Path(*path_parts[i+1:])
                                break

                        if attack_type:
                            # Create target directory
                            target_dir = attck_dir / attack_type
                            target_dir.mkdir(parents=True, exist_ok=True)

                            # Extract file
                            target_file = target_dir / remaining_path.name
                            with zip_file.open(zip_info) as source, open(target_file, 'wb') as target:
                                target.write(source.read())
                            extracted_count += 1

            if extracted_count == 0:
                self.log_error("No STIX files found in ZIP")
                return False

            self.log_success(f"Extracted {extracted_count} STIX files")
            return True

        except Exception as e:
            self.log_error(f"ATT&CK download error: {e}")
            return False

    def validate(self) -> bool:
        """Validate downloaded ATT&CK data."""
        try:
            attck_dir = self.output_dir / self.standard_name

            if not attck_dir.exists():
                self.log_error("ATT&CK directory not found")
                return False

            # Check for subdirectories
            attack_types = ['enterprise-attack', 'ics-attack', 'mobile-attack']
            found_any = False

            for attack_type in attack_types:
                attack_dir = attck_dir / attack_type
                if attack_dir.exists():
                    json_files = list(attack_dir.glob("*.json"))
                    if json_files:
                        # Validate at least one file
                        result = validate_json_file(str(json_files[0]), min_records=1)
                        if result['valid']:
                            self.log_success(f"Validated {attack_type}: {len(json_files)} files")
                            found_any = True
                        else:
                            self.log_warning(f"Validation failed for {attack_type}")
                    else:
                        self.log_warning(f"No JSON files in {attack_type}")

            return found_any

        except Exception as e:
            self.log_error(f"ATT&CK validation error: {e}")
            return False

    def save(self) -> bool:
        """ATT&CK data is saved during download process."""
        return self.validate()
