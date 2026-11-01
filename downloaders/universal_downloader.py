"""
Universal downloader for all cybersecurity standards.

Replaces individual downloaders with a single flexible implementation.
Based on patterns from https://github.com/motherhack3r/KGCS/src/ingest/downloader.py
"""

import json
import logging
import hashlib
import zipfile
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Tuple

from .base import AbstractDownloader
from .validators import validate_json_file, validate_xml_file
from utils.http_client import HTTPClient


class UniversalDownloader(AbstractDownloader):
    """Universal downloader supporting all 10 cybersecurity standards."""

    # Import centralized endpoints
    try:
        from downloaders.ingest_config import APIEndpoints, USER_AGENT
    except ImportError:
        # Fallback definitions
        APIEndpoints = type('APIEndpoints', (), {})()
        USER_AGENT = "KGCS-Downloader/2.0"

    @property
    def standard_name(self) -> str:
        return "UNIVERSAL"

    @property
    def download_url(self) -> str:
        return "https://nvd.nist.gov/"

    def __init__(self, output_dir: str, timeout: int = 300, retries: int = 5):
        """Initialize universal downloader."""
        super().__init__(output_dir, timeout, retries)
        self.http_client = HTTPClient(timeout, retries)
        self.manifest = {}

    def download(self) -> bool:
        """Download all supported standards."""
        results = {
            'cve': self._download_cve(),
            'cwe': self._download_cwe(),
            'cpe': self._download_cpe(),
            'cpematch': self._download_cpematch(),
            'capec': self._download_capec(),
            'attck': self._download_attck(),
            'car': self._download_car(),
            'engage': self._download_engage(),
            'd3fend': self._download_d3fend(),
            'shield': self._download_shield(),
            # spec 1.2: decision extension (ADR-0003) and ATLAS (ADR-0004)
            'kev': self._download_new('kev'),
            'epss': self._download_new('epss'),
            'atlas': self._download_new('atlas'),
        }

        successful = sum(1 for v in results.values() if v)
        total = len(results)

        self.log_success(f"Downloaded {successful}/{total} standards")
        return successful >= 7  # Success if at least 7 standards downloaded

    # ==================== CVE ====================
    def _download_cve(self) -> bool:
        """Download CVE data from NVD (2002-2026 + modified)."""
        try:
            self.logger.info("Downloading CVE data...")
            cve_dir = self.output_dir / "CVE"
            cve_dir.mkdir(parents=True, exist_ok=True)

            # Build URL list for all years 2002-2026 plus modified
            urls = ["https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip"]

            # Add all yearly CVE files (2002-2026)
            for year in range(2002, 2027):
                url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.zip"
                urls.append(url)

            downloaded = 0
            failed = 0

            for url in urls:
                filename = url.split('/')[-1]
                file_path = cve_dir / filename

                if self.http_client.download_file(url, str(file_path)):
                    # Extract JSON from ZIP
                    try:
                        with zipfile.ZipFile(file_path, 'r') as zf:
                            zf.extractall(cve_dir)
                        file_path.unlink()  # Remove ZIP after extraction
                        downloaded += 1
                    except Exception as e:
                        self.log_warning(f"Failed to extract {filename}: {e}")
                        failed += 1
                else:
                    failed += 1

            if downloaded > 0:
                self.log_success(f"CVE: Downloaded {downloaded} files ({failed} failed)")
                return True
            return False

        except Exception as e:
            self.log_error(f"CVE download failed: {e}")
            return False

    # ==================== CWE ====================
    def _download_cwe(self) -> bool:
        """Download CWE data from MITRE."""
        try:
            self.logger.info("Downloading CWE data...")
            cwe_dir = self.output_dir / "CWE"
            cwe_dir.mkdir(parents=True, exist_ok=True)

            zip_file = cwe_dir / "cwec_latest.xml.zip"
            url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

            if self.http_client.download_file(url, str(zip_file)):
                try:
                    with zipfile.ZipFile(zip_file, 'r') as zf:
                        zf.extractall(cwe_dir)
                    zip_file.unlink()
                    self.log_success("CWE: Downloaded and extracted")
                    return True
                except Exception as e:
                    self.log_warning(f"CWE extraction failed: {e}")
                    return False

            return False

        except Exception as e:
            self.log_error(f"CWE download failed: {e}")
            return False

    # ==================== CPE ====================
    def _download_cpe(self) -> bool:
        """Download CPE from NVD."""
        try:
            self.logger.info("Downloading CPE data...")
            cpe_dir = self.output_dir / "CPE"
            cpe_dir.mkdir(parents=True, exist_ok=True)

            zip_file = cpe_dir / "nvdcpe-2.0.zip"
            url = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip"

            if self.http_client.download_file(url, str(zip_file)):
                try:
                    with zipfile.ZipFile(zip_file, 'r') as zf:
                        zf.extractall(cpe_dir)
                    zip_file.unlink()
                    # The NVD zip ships the chunked layout directly
                    # (nvdcpe-2.0-chunks/*.json — verified 2026-08-07).
                    # Fallback: if NVD ever reverts to a single big JSON,
                    # chunk it into the layout load_cpe.py streams.
                    chunks_dir = cpe_dir / "nvdcpe-2.0-chunks"
                    if not any(chunks_dir.glob("*.json")):
                        from .chunker import chunk_nvd_file
                        jsons = sorted(cpe_dir.glob("*.json"),
                                       key=lambda p: p.stat().st_size)
                        if not jsons:
                            raise FileNotFoundError(
                                f"No chunks and no JSON extracted in {cpe_dir}")
                        chunk_nvd_file(jsons[-1], chunks_dir,
                                       "products", "nvdcpe-2.0")
                    n = len(list(chunks_dir.glob("*.json")))
                    self.log_success(f"CPE: Downloaded and extracted ({n} chunk files)")
                    return True
                except Exception as e:
                    self.log_warning(f"CPE extraction failed: {e}")
                    return False

            return False

        except Exception as e:
            self.log_error(f"CPE download failed: {e}")
            return False

    # ==================== CPE Match ====================
    def _download_cpematch(self) -> bool:
        """Download CPE Match from NVD."""
        try:
            self.logger.info("Downloading CPE Match data...")
            cpematch_dir = self.output_dir / "CPE-MATCH"
            cpematch_dir.mkdir(parents=True, exist_ok=True)

            zip_file = cpematch_dir / "nvdcpematch-2.0.zip"
            url = "https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.zip"

            if self.http_client.download_file(url, str(zip_file)):
                try:
                    with zipfile.ZipFile(zip_file, 'r') as zf:
                        zf.extractall(cpematch_dir)
                    zip_file.unlink()
                    # The NVD zip ships the chunked layout directly
                    # (nvdcpematch-2.0-chunks/*.json — verified 2026-08-07).
                    # Fallback: chunk a single big JSON if NVD reverts.
                    chunks_dir = cpematch_dir / "nvdcpematch-2.0-chunks"
                    if not any(chunks_dir.glob("*.json")):
                        from .chunker import chunk_nvd_file
                        jsons = sorted(cpematch_dir.glob("*.json"),
                                       key=lambda p: p.stat().st_size)
                        if not jsons:
                            raise FileNotFoundError(
                                f"No chunks and no JSON extracted in {cpematch_dir}")
                        chunk_nvd_file(jsons[-1], chunks_dir,
                                       "matchStrings", "nvdcpematch-2.0")
                    n = len(list(chunks_dir.glob("*.json")))
                    self.log_success(f"CPE Match: Downloaded and extracted ({n} chunk files)")
                    return True
                except Exception as e:
                    self.log_warning(f"CPE Match extraction failed: {e}")
                    return False

            return False

        except Exception as e:
            self.log_error(f"CPE Match download failed: {e}")
            return False

    # ==================== CAPEC ====================
    def _download_capec(self) -> bool:
        """Download CAPEC from MITRE."""
        try:
            self.logger.info("Downloading CAPEC data...")
            capec_dir = self.output_dir / "CAPEC"
            capec_dir.mkdir(parents=True, exist_ok=True)

            # Primary: XML
            xml_file = capec_dir / "capec_latest.xml"
            if self.http_client.download_file("https://capec.mitre.org/data/xml/capec_latest.xml", str(xml_file)):
                self.log_success("CAPEC: Downloaded XML")
                return True

            # Fallback: STIX JSON from GitHub
            stix_file = capec_dir / "stix-capec.json"
            if self.http_client.download_file(
                "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/capec/2.1/stix-capec.json",
                str(stix_file)
            ):
                self.log_success("CAPEC: Downloaded STIX JSON (fallback)")
                return True

            return False

        except Exception as e:
            self.log_error(f"CAPEC download failed: {e}")
            return False

    # ==================== ATT&CK ====================
    def _download_attck(self) -> bool:
        """Download ATT&CK from MITRE."""
        try:
            self.logger.info("Downloading ATT&CK data...")
            attck_dir = self.output_dir / "ATTCK-STIX"
            attck_dir.mkdir(parents=True, exist_ok=True)

            urls = {
                "enterprise-attack.json": "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/enterprise-attack/enterprise-attack.json",
                "ics-attack.json": "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/ics-attack/ics-attack.json",
                "mobile-attack.json": "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/mobile-attack/mobile-attack.json",
            }

            downloaded = 0
            for filename, url in urls.items():
                if self.http_client.download_file(url, str(attck_dir / filename)):
                    downloaded += 1

            if downloaded > 0:
                self.log_success(f"ATT&CK: Downloaded {downloaded} files")
                return True
            return False

        except Exception as e:
            self.log_error(f"ATT&CK download failed: {e}")
            return False

    # ==================== CAR ====================
    def _download_car(self) -> bool:
        """Download CAR from MITRE (analytics, data_model, sensors - YAML files)."""
        try:
            self.logger.info("Downloading CAR data...")
            car_dir = self.output_dir / "car"  # lowercase to match output
            car_dir.mkdir(parents=True, exist_ok=True)

            # Download YAML files from three CAR directories
            base_url = "https://raw.githubusercontent.com/mitre-attack/car/refs/heads/master"
            dirs = ["analytics", "data_model", "sensors"]

            downloaded = 0
            failed = 0

            for dir_name in dirs:
                # Query GitHub API to list files
                api_url = f"https://api.github.com/repos/mitre-attack/car/contents/{dir_name}"
                response = self.http_client.get(api_url)

                if response:
                    try:
                        files = response.json()
                        target_dir = car_dir / dir_name
                        target_dir.mkdir(parents=True, exist_ok=True)

                        for file_info in files:
                            # Filter for YAML/YML files only (not JSON)
                            if file_info.get('type') == 'file' and file_info['name'].endswith(('.yaml', '.yml')):
                                file_url = f"{base_url}/{dir_name}/{file_info['name']}"
                                if self.http_client.download_file(file_url, str(target_dir / file_info['name'])):
                                    downloaded += 1
                                else:
                                    failed += 1
                    except Exception as e:
                        self.log_warning(f"CAR {dir_name} parsing failed: {e}")
                else:
                    self.log_warning(f"Failed to query GitHub API for CAR {dir_name}")
                    failed += 1

            if downloaded > 0:
                self.log_success(f"CAR: Downloaded {downloaded} files ({failed} failed)")
                return True
            return False

        except Exception as e:
            self.log_error(f"CAR download failed: {e}")
            return False

    # ==================== ENGAGE ====================
    def _download_engage(self) -> bool:
        """Download ENGAGE from MITRE."""
        try:
            self.logger.info("Downloading ENGAGE data...")
            engage_dir = self.output_dir / "ENGAGE"
            engage_dir.mkdir(parents=True, exist_ok=True)

            # Get file list from GitHub API
            api_url = "https://api.github.com/repos/mitre/engage/contents/Data/json"
            response = self.http_client.get(api_url)

            if response:
                try:
                    files = response.json()
                    base_url = "https://raw.githubusercontent.com/mitre/engage/refs/heads/main/Data/json"

                    downloaded = 0
                    for file_info in files:
                        if file_info.get('type') == 'file' and file_info['name'].endswith('.json'):
                            file_url = f"{base_url}/{file_info['name']}"
                            if self.http_client.download_file(file_url, str(engage_dir / file_info['name'])):
                                downloaded += 1

                    if downloaded > 0:
                        self.log_success(f"ENGAGE: Downloaded {downloaded} files")
                        return True
                except Exception as e:
                    self.log_warning(f"ENGAGE parsing failed: {e}")

            return False

        except Exception as e:
            self.log_error(f"ENGAGE download failed: {e}")
            return False

    # ==================== SHIELD ====================
    def _download_shield(self) -> bool:
        """Download SHIELD from MITRECND."""
        try:
            self.logger.info("Downloading SHIELD data...")
            shield_dir = self.output_dir / "SHIELD"
            shield_dir.mkdir(parents=True, exist_ok=True)

            urls = {
                "attack_groups.json": "https://raw.githubusercontent.com/MITRECND/mitrecnd.github.io/refs/heads/master/_data/attack_groups.json",
                "tactics.json": "https://raw.githubusercontent.com/MITRECND/mitrecnd.github.io/refs/heads/master/_data/tactics.json",
                "techniques.json": "https://raw.githubusercontent.com/MITRECND/mitrecnd.github.io/refs/heads/master/_data/techniques.json",
                "procedures.json": "https://raw.githubusercontent.com/MITRECND/mitrecnd.github.io/refs/heads/master/_data/procedures.json",
                "use_cases.json": "https://raw.githubusercontent.com/MITRECND/mitrecnd.github.io/refs/heads/master/_data/use_cases.json",
                "opportunities.json": "https://raw.githubusercontent.com/MITRECND/mitrecnd.github.io/refs/heads/master/_data/opportunities.json",
                "tactic_details.json": "https://raw.githubusercontent.com/MITRECND/mitrecnd.github.io/refs/heads/master/_data/tactic_details.json",
                "technique_details.json": "https://raw.githubusercontent.com/MITRECND/mitrecnd.github.io/refs/heads/master/_data/technique_details.json",
                "attack_mapping.json": "https://raw.githubusercontent.com/MITRECND/mitrecnd.github.io/refs/heads/master/_data/attack_mapping.json",
            }

            downloaded = 0
            for filename, url in urls.items():
                if self.http_client.download_file(url, str(shield_dir / filename)):
                    downloaded += 1

            if downloaded > 0:
                self.log_success(f"SHIELD: Downloaded {downloaded} files")
                return True
            return False

        except Exception as e:
            self.log_error(f"SHIELD download failed: {e}")
            return False

    # ==================== D3FEND ====================
    def _download_d3fend(self) -> bool:
        """Download D3FEND ontology files."""
        try:
            self.logger.info("Downloading D3FEND data...")
            d3fend_dir = self.output_dir / "D3FEND"
            d3fend_dir.mkdir(parents=True, exist_ok=True)

            base_url = "https://d3fend.mitre.org/ontologies/d3fend/1.3.0"
            files = [
                "d3fend.json",
                "d3fend.owl",
                "d3fend.ttl",
                "d3fend-full-mappings.json",
            ]

            downloaded = 0
            for filename in files:
                url = f"{base_url}/{filename}"
                if self.http_client.download_file(url, str(d3fend_dir / filename)):
                    downloaded += 1

            if downloaded > 0:
                self.log_success(f"D3FEND: Downloaded {downloaded} files")
                return True
            return False

        except Exception as e:
            self.log_error(f"D3FEND download failed: {e}")
            return False

    # ==================== spec 1.2 sources ====================
    def _download_new(self, key: str) -> bool:
        """KEV / EPSS / ATLAS through their own downloader classes."""
        from .cisa_kev import CisaKevDownloader
        from .first_epss import FirstEpssDownloader
        from .mitre_atlas import MitreAtlasDownloader

        cls = {'kev': CisaKevDownloader, 'epss': FirstEpssDownloader,
               'atlas': MitreAtlasDownloader}[key]
        try:
            return cls(str(self.output_dir), self.timeout, self.retries).download()
        except Exception as e:
            self.log_error(f"{key.upper()} download failed: {e}")
            return False

    # ==================== VALIDATION ====================
    def validate(self) -> bool:
        """Validate all downloaded data."""
        standards_to_check = ['CVE', 'CWE', 'CPE', 'CAPEC', 'ATTCK-STIX', 'CAR', 'ENGAGE', 'SHIELD', 'D3FEND',
                              'KEV', 'EPSS', 'ATLAS']
        valid_count = 0

        for standard in standards_to_check:
            std_dir = self.output_dir / standard
            if std_dir.exists():
                files = list(std_dir.glob("**/*"))
                if files:
                    valid_count += 1
                    self.log_success(f"{standard}: {len(files)} files")

        self.log_success(f"Validation: {valid_count}/{len(standards_to_check)} standards have data")
        return valid_count >= 7

    def save(self) -> bool:
        """Data is saved during download."""
        return self.validate()
