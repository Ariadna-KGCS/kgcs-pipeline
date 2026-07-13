"""
NIST NVD standards downloader.

Handles CVE and CWE data from National Vulnerability Database.
- CVE: Uses NVD REST API v2.0 (public endpoint, no auth required)
- CWE: Downloads from MITRE CTI GitHub (STIX 2.1 format)
- CPE: Requires registration/API key - download manually from nvd.nist.gov
- CVSS: Embedded in CVE records

Data sources:
- CVE: https://services.nvd.nist.gov/rest/json/cves/2.0/
- CWE: https://github.com/mitre/cti (cwe/2.1/ STIX format)
- CPE: https://nvd.nist.gov/products/cpe (requires authentication)
"""

import json
import logging
import zipfile
import io
from pathlib import Path
from typing import Optional

from .base import AbstractDownloader
from .validators import validate_json_file
from utils.http_client import HTTPClient


class NISTNVDDownloader(AbstractDownloader):
    """Downloader for NIST NVD standards (CVE, CWE)."""

    # NVD REST API v2.0 (public, no authentication required)
    CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/"

    # CWE from MITRE CTI GitHub (STIX 2.1 JSON)
    CWE_GITHUB_REPO = "https://github.com/mitre/cti/archive/refs/heads/master.zip"

    @property
    def standard_name(self) -> str:
        """Standards handled by this downloader."""
        return "NIST-NVD"

    @property
    def download_url(self) -> str:
        """Primary download source."""
        return self.CVE_API_URL

    def __init__(self, output_dir: str, timeout: int = 300, retries: int = 5):
        """Initialize NIST NVD downloader."""
        super().__init__(output_dir, timeout, retries)
        self.http_client = HTTPClient(timeout, retries)

    def download(self) -> bool:
        """Download CVE and CWE data."""
        cve_success = False
        cwe_success = False

        # Download CVE via REST API (PRIMARY)
        if self._download_cve_rest_api():
            cve_success = True
        else:
            self.log_error("CVE download failed")

        # Download CWE from GitHub (OPTIONAL - may have network issues)
        if self._download_cwe():
            cwe_success = True
        else:
            self.log_warning("CWE download failed - may retry from GitHub later")

        # Note: CPE and CVSS
        self.log_warning("CPE download skipped - requires registration at https://nvd.nist.gov/products/cpe")
        self.log_warning("CVSS severity scores are embedded in CVE records")

        # Success if at least CVE downloaded
        if cve_success:
            self.log_success("NVD standards download complete (CVE) + optional (CWE)")

        return cve_success  # Return success if CVE succeeded

    def _download_cve_rest_api(self) -> bool:
        """Download CVE data from NVD REST API v2.0."""
        try:
            self.logger.info("Starting CVE download from NVD REST API v2.0...")
            cve_dir = self.output_dir / "CVE"
            cve_dir.mkdir(parents=True, exist_ok=True)

            # Download recent CVE data (startIndex=0 gets latest)
            cve_file = cve_dir / "nvdcve-2.0-recent.json"

            # NVD API returns up to 2000 results per request
            url = f"{self.CVE_API_URL}?startIndex=0&resultsPerPage=2000"

            self.logger.info(f"Fetching CVE data from: {self.CVE_API_URL}")
            response = self.http_client.get(url)

            if not response:
                self.log_error("Failed to fetch CVE data from REST API")
                return False

            # Save the JSON response
            try:
                cve_data = response.json()
                with open(cve_file, 'w', encoding='utf-8') as f:
                    json.dump(cve_data, f, indent=2)

                # Count records
                record_count = len(cve_data.get('vulnerabilities', []))
                total_results = cve_data.get('totalResults', 0)

                self.log_success(f"Downloaded CVE data ({record_count} recent records, {total_results} total available)")
                return True

            except json.JSONDecodeError as e:
                self.log_error(f"Failed to parse CVE JSON: {e}")
                return False

        except Exception as e:
            self.log_error(f"CVE download error: {e}")
            return False

    def _download_cwe(self) -> bool:
        """Download CWE data from MITRE CTI GitHub (STIX 2.1)."""
        try:
            self.logger.info("Starting CWE download from MITRE CTI GitHub...")
            cwe_dir = self.output_dir / "CWE"
            cwe_dir.mkdir(parents=True, exist_ok=True)

            # Download ZIP from GitHub
            response = self.http_client.get(self.CWE_GITHUB_REPO, stream=True)

            if not response:
                self.log_error("Failed to download CWE from GitHub")
                return False

            # Extract ZIP in memory
            try:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content))
            except zipfile.BadZipFile:
                self.log_error("CWE ZIP is corrupted")
                return False

            # Extract CWE STIX files from cwe/2.1/ directory
            extracted_count = 0

            for zip_info in zip_file.filelist:
                # Look for CWE STIX files in cwe/2.1/
                if 'cti-master/cwe/2.1/' in zip_info.filename and zip_info.filename.endswith('.json'):
                    # Extract relative path
                    path_parts = Path(zip_info.filename).parts

                    # Find the cwe/2.1 position
                    for i, part in enumerate(path_parts):
                        if part == '2.1':
                            remaining_path = Path(*path_parts[i+1:])
                            break

                    # Create target directory
                    target_file = cwe_dir / remaining_path
                    target_file.parent.mkdir(parents=True, exist_ok=True)

                    # Extract file
                    with zip_file.open(zip_info) as source, open(target_file, 'wb') as target:
                        target.write(source.read())
                    extracted_count += 1

            if extracted_count == 0:
                self.log_error("No CWE STIX files found in CTI GitHub")
                return False

            self.log_success(f"Downloaded CWE data ({extracted_count} STIX files)")
            return True

        except Exception as e:
            self.log_error(f"CWE download error: {e}")
            return False

    def validate(self) -> bool:
        """Validate downloaded NVD data."""
        cve_valid = False
        cwe_valid = False

        # Check CVE
        cve_dir = self.output_dir / "CVE"
        if cve_dir.exists():
            cve_files = list(cve_dir.glob("*.json"))
            if cve_files:
                for cve_file in cve_files:
                    result = validate_json_file(str(cve_file), min_records=1)
                    if not result['valid']:
                        self.log_warning(f"CVE validation failed: {cve_file.name}")
                    else:
                        cve_valid = True
                        self.log_success(f"CVE validated: {cve_file.name}")
            else:
                self.log_warning("No CVE JSON files found")
        else:
            self.log_warning("CVE directory not found")

        # Check CWE (optional)
        cwe_dir = self.output_dir / "CWE"
        if cwe_dir.exists():
            json_files = list(cwe_dir.glob("**/*.json"))
            if json_files:
                result = validate_json_file(str(json_files[0]), min_records=1)
                if result['valid']:
                    cwe_valid = True
                    self.log_success(f"CWE validated ({len(json_files)} STIX files)")
                else:
                    self.log_warning(f"CWE validation failed: {result['errors']}")
            else:
                self.log_warning("No CWE JSON files found")
        else:
            self.log_warning("CWE directory not found (optional)")

        # Return success if CVE is valid (CWE is optional)
        return cve_valid

    def save(self) -> bool:
        """NVD data is saved during download process."""
        return self.validate()
