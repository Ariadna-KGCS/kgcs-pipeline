"""
Centralized configuration for cybersecurity standards downloads.

This module separates URL endpoints and operational configuration from
download logic, enabling easy updates without code modifications.

Based on analysis of https://github.com/motherhack3r/KGCS
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime


@dataclass
class APIEndpoints:
    """Centralized cybersecurity standard download URLs.

    Organized by source family (MITRE, NIST) with support for:
    - Multiple data formats (JSON, XML, XSD, TTL, OWL, ZIP)
    - Dynamic URL generation for year-range downloads
    - Dual endpoint modes (API, raw GitHub) for flexibility
    """

    # ==================== MITRE ATT&CK ====================
    # Multiple threat intelligence domains
    attack_enterprise: str = "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/enterprise-attack/enterprise-attack.json"
    attack_ics: str = "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/ics-attack/ics-attack.json"
    attack_mobile: str = "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/mobile-attack/mobile-attack.json"
    attack_preattack: str = "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/pre-attack/pre-attack.json"

    @property
    def attack_domains(self) -> List[str]:
        """Get all ATT&CK domain URLs."""
        return [self.attack_enterprise, self.attack_ics, self.attack_mobile, self.attack_preattack]

    # ==================== MITRE CAPEC ====================
    # Attack Pattern Database and STIX variants
    capec_xml: str = "https://capec.mitre.org/data/xml/capec_latest.xml"
    capec_xsd: str = "https://capec.mitre.org/data/xsd/ap_schema_latest.xsd"
    capec_stix: str = "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/capec/2.1/stix-capec.json"

    # ==================== MITRE CWE ====================
    # Common Weakness Enumeration
    cwe_zip: str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    cwe_xsd: str = "https://cwe.mitre.org/data/xsd/cwe_schema_latest.xsd"

    # ==================== MITRE CAR ====================
    # Cyber Analytics Repository - three main directories
    car_analytics_base: str = "https://raw.githubusercontent.com/mitre-attack/car/refs/heads/master/analytics/"
    car_datamodel_base: str = "https://raw.githubusercontent.com/mitre-attack/car/refs/heads/master/data_model/"
    car_sensors_base: str = "https://raw.githubusercontent.com/mitre-attack/car/refs/heads/master/sensors/"

    # GitHub API endpoints for dynamic file discovery
    car_analytics_api: str = "https://api.github.com/repos/mitre-attack/car/contents/analytics"
    car_datamodel_api: str = "https://api.github.com/repos/mitre-attack/car/contents/data_model"
    car_sensors_api: str = "https://api.github.com/repos/mitre-attack/car/contents/sensors"

    @property
    def car_directories(self) -> List[Tuple[str, str, str]]:
        """Get CAR directory config: (name, base_url, api_url)."""
        return [
            ("analytics", self.car_analytics_base, self.car_analytics_api),
            ("data_model", self.car_datamodel_base, self.car_datamodel_api),
            ("sensors", self.car_sensors_base, self.car_sensors_api),
        ]

    # ==================== MITRE ENGAGE ====================
    # Defensive Actions Against Threat Actors
    engage_base: str = "https://raw.githubusercontent.com/mitre/engage/refs/heads/main/Data/json/"
    engage_api: str = "https://api.github.com/repos/mitre/engage/contents/Data/json"

    # ==================== MITRE SHIELD ====================
    # Active Defense
    # NOTE: SHIELD data is hosted at MITRECND organization, not mitre/shield
    shield_base: str = "https://raw.githubusercontent.com/MITRECND/mitrecnd.github.io/refs/heads/master/_data/"

    @property
    def shield_files(self) -> List[str]:
        """Get all SHIELD JSON file URLs."""
        files = [
            "attack_groups", "tactics", "techniques", "procedures",
            "use_cases", "opportunities", "tactic_details", "technique_details", "attack_mapping"
        ]
        return [f"{self.shield_base}{name}.json" for name in files]

    # ==================== MITRE D3FEND ====================
    # Defensive Functions and Techniques Enumeration
    d3fend_base: str = "https://d3fend.mitre.org/ontologies/d3fend/1.3.0/"

    @property
    def d3fend_files(self) -> List[Tuple[str, str]]:
        """Get D3FEND file downloads: (filename, url)."""
        return [
            ("d3fend.json", f"{self.d3fend_base}d3fend.json"),
            ("d3fend.owl", f"{self.d3fend_base}d3fend.owl"),
            ("d3fend.ttl", f"{self.d3fend_base}d3fend.ttl"),
            ("d3fend-full-mappings.json", f"{self.d3fend_base}d3fend-full-mappings.json"),
        ]

    # ==================== Decision extension (spec 1.2.0, ADR-0003) ====================
    # CISA KEV: JSON feed (the CSV twin is not used) and its JSON Schema
    kev_json: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_schema: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json"
    # FIRST EPSS daily CSV (gzip). The stable URL redirects to the current day;
    # dated files are epss_scores-<YYYY-MM-DD>.csv.gz under the same base.
    epss_base: str = "https://epss.empiricalsecurity.com/"
    epss_current: str = f"{epss_base}epss_scores-current.csv.gz"
    # SSVC v2.0.3 as embedded by NVD in metrics.ssvcV203 (referenced from cve_schema)
    ssvc_v203_schema: str = "https://csrc.nist.gov/schema/nvd/api/2.0/ssvc-v2.0.3.json"

    # ==================== MITRE ATLAS (spec 1.2.1, ADR-0004) ====================
    # Versioned YAML (format 6.0.0), never dist/ATLAS-latest.yaml (a moving
    # symlink). Bumping atlas_release is an explicit, reviewed change.
    atlas_release: str = "2026.09"
    atlas_dist_base: str = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/"

    @property
    def atlas_yaml(self) -> str:
        return f"{self.atlas_dist_base}v6/ATLAS-{self.atlas_release}.yaml"

    # ==================== NIST NVD ====================
    # National Vulnerability Database
    cve_base: str = "https://nvd.nist.gov/feeds/json/cve/2.0/"
    cve_modified: str = f"{cve_base}nvdcve-2.0-modified.json.zip"
    cpe_zip: str = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip"
    cpe_schema: str = "https://csrc.nist.gov/schema/nvd/api/2.0/cpe_api_json_2.0.schema"
    cpematch_zip: str = "https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.zip"
    cpematch_schema: str = "https://csrc.nist.gov/schema/nvd/api/2.0/cpematch_api_json_2.0.schema"
    cve_schema: str = "https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema"

    # CVSS JSON Schemas (FIRST-authored, hosted by NVD; referenced from cve_schema).
    # Versions are kept separate — never merge versioned scores.
    cvss_v2_schema: str = "https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v2.0.json"
    cvss_v30_schema: str = "https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.0.json"
    cvss_v31_schema: str = "https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.1.json"
    cvss_v40_schema: str = "https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v4.0.json"

    # ==================== STIX (ATT&CK container format) ====================
    # ATT&CK raw data is STIX; the OASIS JSON Schemas are the machine schema.
    # Schemas cross-reference each other with relative paths, so the whole
    # branch archive is fetched rather than individual files.
    # Branch pinned to the spec_version of the downloaded bundles (2.0).
    stix_schemas_zip: str = (
        "https://github.com/oasis-open/cti-stix2-json-schemas/archive/refs/heads/stix2.0.zip"
    )

    def get_cve_urls(self, start_year: int = 2002, end_year: Optional[int] = None) -> List[str]:
        """Generate CVE download URLs for specified year range.

        Args:
            start_year: Starting year (default 2002 for complete CVE history)
            end_year: Ending year (default current year)

        Returns:
            List of CVE ZIP file URLs for download, with modified data first
        """
        if end_year is None:
            end_year = datetime.now().year

        # Always download modified data first for incremental updates
        urls = [self.cve_modified]

        # Add yearly CVE archives
        for year in range(start_year, end_year + 1):
            urls.append(f"{self.cve_base}nvdcve-2.0-{year}.json.zip")

        return urls


@dataclass
class ETLConfig:
    """Pipeline operations configuration.

    Controls behavior for data extraction, transformation, and loading:
    - Network parameters (timeouts, retries)
    - Processing parameters (batch sizes, parallelization)
    - Output and logging configuration
    """

    # Network Configuration
    timeout_connect: int = 30          # Connection timeout (seconds)
    timeout_read: int = 300            # Read timeout (seconds)
    max_retries: int = 5               # Exponential backoff retries
    backoff_factor: float = 0.5        # Backoff multiplier (delays: 0.5s, 1s, 2s, 4s, 8s)

    # Processing Configuration
    batch_size: int = 1000             # Records per batch
    max_workers: int = 4               # Parallel download workers
    chunk_size: int = 8192             # File streaming chunk size (bytes)

    # Output Configuration
    output_dir: str = "data/raw"       # Base output directory
    extract_zips: bool = True          # Auto-extract downloaded ZIP files
    preserve_zips: bool = False        # Keep ZIP files after extraction
    overwrite_existing: bool = False   # Overwrite existing files

    # Logging Configuration
    log_level: str = "INFO"            # Logging verbosity
    log_format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    # User Agent for HTTP requests
    user_agent: str = field(
        default="KGCS-Downloader/2.0 (Cybersecurity Knowledge Graph)",
        init=False
    )

    def __post_init__(self):
        """Validate configuration after initialization."""
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        if self.backoff_factor <= 0:
            raise ValueError("backoff_factor must be positive")
        if self.batch_size < 1:
            raise ValueError("batch_size must be at least 1")
        if self.max_workers < 1:
            raise ValueError("max_workers must be at least 1")


# Default endpoint configuration
DEFAULT_ENDPOINTS = APIEndpoints()

# Default pipeline configuration
DEFAULT_ETL_CONFIG = ETLConfig()


# Backward compatibility exports (for existing code)
USER_AGENT = DEFAULT_ETL_CONFIG.user_agent
TIMEOUT_CONNECT = DEFAULT_ETL_CONFIG.timeout_connect
TIMEOUT_READ = DEFAULT_ETL_CONFIG.timeout_read
MAX_RETRIES = DEFAULT_ETL_CONFIG.max_retries
BACKOFF_FACTOR = DEFAULT_ETL_CONFIG.backoff_factor
