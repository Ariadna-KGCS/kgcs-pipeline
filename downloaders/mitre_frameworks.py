"""
MITRE Framework downloader for CAR, ENGAGE, and SHIELD.

Downloads:
- CAR (Cyber Analytics Repository): analytics and data models
- ENGAGE: active engagement strategies
- SHIELD: active defense framework

Data sources:
- CAR: https://github.com/mitre-attack/car (master branch)
- ENGAGE: https://github.com/mitre/engage (main branch)
- SHIELD: Data already provided in data/raw/SHIELD/ - no download needed
"""

import json
import logging
from pathlib import Path
import zipfile
import io

from .base import AbstractDownloader
from .validators import validate_json_file
from utils.http_client import HTTPClient


class MitreFrameworksDownloader(AbstractDownloader):
    """Downloader for MITRE frameworks (CAR, ENGAGE, SHIELD)."""

    # GitHub repository URLs with CORRECT branches
    FRAMEWORKS = {
        'CAR': 'https://github.com/mitre-attack/car/archive/refs/heads/master.zip',
        'ENGAGE': 'https://github.com/mitre/engage/archive/refs/heads/main.zip',
        'SHIELD': 'https://github.com/mitre/shield/archive/refs/heads/main.zip',  # May not exist yet
    }

    @property
    def standard_name(self) -> str:
        return "MITRE-FRAMEWORKS"

    @property
    def download_url(self) -> str:
        return self.FRAMEWORKS['CAR']  # Primary

    def __init__(self, output_dir: str, timeout: int = 300, retries: int = 5):
        """Initialize MITRE frameworks downloader."""
        super().__init__(output_dir, timeout, retries)
        self.http_client = HTTPClient(timeout, retries)

    def download(self) -> bool:
        """Download CAR, ENGAGE, and SHIELD frameworks."""
        success = True

        # Download CAR
        if not self._download_framework('CAR', self.FRAMEWORKS['CAR']):
            self.log_warning("CAR download failed")
            success = False

        # Download ENGAGE
        if not self._download_framework('ENGAGE', self.FRAMEWORKS['ENGAGE']):
            self.log_warning("ENGAGE download failed")
            success = False

        # SHIELD - try download but don't fail if it doesn't exist
        # (data may already be present in data/raw/SHIELD/)
        shield_dir = self.output_dir / 'SHIELD'
        if shield_dir.exists() and list(shield_dir.glob("*.json")):
            self.log_success("SHIELD data already present in data/raw/SHIELD/")
        else:
            if not self._download_framework('SHIELD', self.FRAMEWORKS['SHIELD']):
                self.log_warning("SHIELD download failed or not available")

        if success:
            self.log_success("MITRE frameworks download complete")
        return success

    def _download_framework(self, framework: str, url: str) -> bool:
        """Download a single MITRE framework from GitHub."""
        try:
            self.logger.info(f"Downloading {framework}...")
            framework_dir = self.output_dir / framework
            framework_dir.mkdir(parents=True, exist_ok=True)

            # Download ZIP
            response = self.http_client.get(url, stream=True)
            if not response:
                self.log_error(f"Failed to download {framework} from GitHub")
                return False

            # Extract ZIP
            try:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content))
            except zipfile.BadZipFile:
                self.log_error(f"{framework} ZIP is corrupted")
                return False

            # Extract JSON files
            extracted_count = 0
            repo_prefix = None  # Find repo root dir

            for zip_info in zip_file.filelist:
                # Identify repo root (first directory in ZIP)
                if repo_prefix is None and '/' in zip_info.filename:
                    repo_prefix = zip_info.filename.split('/')[0]

                # Extract JSON files from data/ or analytics/ subdirectories
                data_suffixes = ['data/', 'analytics/', 'sensors/']
                is_data_file = any(suffix in zip_info.filename for suffix in data_suffixes)

                if is_data_file and zip_info.filename.endswith('.json'):
                    # Get relative path (remove repo root)
                    if repo_prefix:
                        relative_path = zip_info.filename.replace(f'{repo_prefix}/', '', 1)
                    else:
                        relative_path = zip_info.filename

                    target_file = framework_dir / relative_path

                    # Create subdirs
                    target_file.parent.mkdir(parents=True, exist_ok=True)

                    # Extract file
                    with zip_file.open(zip_info) as source, open(target_file, 'wb') as target:
                        target.write(source.read())
                    extracted_count += 1

            if extracted_count == 0:
                # For ENGAGE and SHIELD, all files might be at root level
                # Try to extract all JSON files
                for zip_info in zip_file.filelist:
                    if zip_info.filename.endswith('.json') and not zip_info.is_dir():
                        if repo_prefix:
                            relative_path = zip_info.filename.replace(f'{repo_prefix}/', '', 1)
                        else:
                            relative_path = zip_info.filename

                        target_file = framework_dir / relative_path
                        target_file.parent.mkdir(parents=True, exist_ok=True)

                        with zip_file.open(zip_info) as source, open(target_file, 'wb') as target:
                            target.write(source.read())
                        extracted_count += 1

            if extracted_count == 0:
                self.log_warning(f"No data files found in {framework} ZIP")
                # Continue anyway - some frameworks might have data in version control

            self.log_success(f"{framework} downloaded ({extracted_count} files)")
            return True

        except Exception as e:
            self.log_error(f"{framework} download error: {e}")
            return False

    def validate(self) -> bool:
        """Validate downloaded MITRE frameworks."""
        all_valid = True

        for framework in ['CAR', 'ENGAGE', 'SHIELD']:
            framework_dir = self.output_dir / framework

            if not framework_dir.exists():
                self.log_warning(f"{framework} directory not found")
                all_valid = False
                continue

            # Check for JSON files
            json_files = list(framework_dir.glob("**/*.json"))

            if json_files:
                # Validate first JSON file
                result = validate_json_file(str(json_files[0]), min_records=1)
                if result['valid']:
                    self.log_success(f"{framework} validation passed ({len(json_files)} JSON files)")
                else:
                    self.log_warning(f"{framework} validation failed: {result['errors']}")
                    all_valid = False
            else:
                self.log_warning(f"No JSON files found in {framework}")
                all_valid = False

        return all_valid

    def save(self) -> bool:
        """MITRE frameworks data is saved during download."""
        return self.validate()
