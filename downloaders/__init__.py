"""
Pluggable downloader modules for security standards.

Each downloader implements the AbstractDownloader interface:
- download(): Fetch data from source
- validate(): Verify data integrity
- save(): Write to output directory

Available downloader classes:
- NISTNVDDownloader: CVE, CWE, CPE, CVSS
- MitreAttckDownloader: ATT&CK STIX 2.0
- MitreCapecDownloader: CAPEC
- MitreD3fendDownloader: D3FEND
- MitreFrameworksDownloader: CAR, ENGAGE, SHIELD
- CisaKevDownloader, FirstEpssDownloader: KEV, EPSS (spec 1.2.0, ADR-0003)
- MitreAtlasDownloader: ATLAS (spec 1.2.1, ADR-0004)
"""

from .base import AbstractDownloader
from .nist_nvd import NISTNVDDownloader
from .mitre_attck import MitreAttckDownloader
from .mitre_capec import MitreCapecDownloader
from .mitre_d3fend import MitreD3fendDownloader
from .mitre_frameworks import MitreFrameworksDownloader
from .cisa_kev import CisaKevDownloader
from .first_epss import FirstEpssDownloader
from .mitre_atlas import MitreAtlasDownloader
from .validators import (
    validate_json_file,
    validate_xml_file,
    validate_owl_file,
    validate_directory_structure,
    validate_file_size,
)

__all__ = [
    'AbstractDownloader',
    'NISTNVDDownloader',
    'MitreAttckDownloader',
    'MitreCapecDownloader',
    'MitreD3fendDownloader',
    'MitreFrameworksDownloader',
    'CisaKevDownloader',
    'FirstEpssDownloader',
    'MitreAtlasDownloader',
    'validate_json_file',
    'validate_xml_file',
    'validate_owl_file',
    'validate_directory_structure',
    'validate_file_size',
]
