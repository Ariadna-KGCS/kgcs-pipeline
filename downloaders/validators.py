"""
Validation utilities for security standard data.

Provides format validation, record count verification, and sanity checks
for JSON, XML, and OWL files.
"""

import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from xml.etree import ElementTree as ET


logger = logging.getLogger(__name__)


def validate_json_file(file_path: str, min_records: int = 0) -> Dict[str, Any]:
    """
    Validate JSON file format and structure.

    Args:
        file_path: Path to JSON file
        min_records: Minimum expected records (for arrays)

    Returns:
        Dictionary with validation result and metadata
    """
    result = {
        'valid': False,
        'format': 'JSON',
        'file_size': 0,
        'record_count': 0,
        'errors': []
    }

    try:
        path = Path(file_path)
        if not path.exists():
            result['errors'].append(f"File not found: {file_path}")
            return result

        result['file_size'] = path.stat().st_size

        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Count records
        if isinstance(data, list):
            result['record_count'] = len(data)
            if result['record_count'] < min_records:
                result['errors'].append(f"Expected at least {min_records} records, got {result['record_count']}")
        elif isinstance(data, dict):
            # Check for common record containers
            for key in ['objects', 'records', 'data', 'entries', 'items']:
                if key in data and isinstance(data[key], list):
                    result['record_count'] = len(data[key])
                    break
            else:
                result['record_count'] = 1

        result['valid'] = len(result['errors']) == 0
        return result

    except json.JSONDecodeError as e:
        result['errors'].append(f"JSON decode error: {e}")
        return result
    except Exception as e:
        result['errors'].append(f"Validation error: {e}")
        return result


def validate_xml_file(file_path: str) -> Dict[str, Any]:
    """
    Validate XML file format and structure.

    Args:
        file_path: Path to XML file

    Returns:
        Dictionary with validation result and metadata
    """
    result = {
        'valid': False,
        'format': 'XML',
        'file_size': 0,
        'element_count': 0,
        'root_tag': None,
        'errors': []
    }

    try:
        path = Path(file_path)
        if not path.exists():
            result['errors'].append(f"File not found: {file_path}")
            return result

        result['file_size'] = path.stat().st_size

        tree = ET.parse(file_path)
        root = tree.getroot()

        result['root_tag'] = root.tag
        result['element_count'] = len(root)

        result['valid'] = len(result['errors']) == 0
        return result

    except ET.ParseError as e:
        result['errors'].append(f"XML parse error: {e}")
        return result
    except Exception as e:
        result['errors'].append(f"Validation error: {e}")
        return result


def validate_owl_file(file_path: str) -> Dict[str, Any]:
    """
    Validate OWL file format (basic XML check + content verification).

    Args:
        file_path: Path to OWL file

    Returns:
        Dictionary with validation result and metadata
    """
    result = {
        'valid': False,
        'format': 'OWL',
        'file_size': 0,
        'class_count': 0,
        'errors': []
    }

    try:
        path = Path(file_path)
        if not path.exists():
            result['errors'].append(f"File not found: {file_path}")
            return result

        result['file_size'] = path.stat().st_size

        # Parse XML
        tree = ET.parse(file_path)
        root = tree.getroot()

        # Get namespace
        namespaces = {'owl': 'http://www.w3.org/2002/07/owl#'}

        # Count owl:Class elements
        classes = root.findall('.//owl:Class', namespaces)
        result['class_count'] = len(classes)

        result['valid'] = len(result['errors']) == 0
        return result

    except ET.ParseError as e:
        result['errors'].append(f"XML parse error: {e}")
        return result
    except Exception as e:
        result['errors'].append(f"Validation error: {e}")
        return result


def validate_directory_structure(base_dir: str, required_files: list) -> Dict[str, Any]:
    """
    Validate that a directory contains expected files.

    Args:
        base_dir: Base directory path
        required_files: List of required file names or patterns

    Returns:
        Dictionary with validation result
    """
    result = {
        'valid': True,
        'missing_files': [],
        'found_files': []
    }

    base_path = Path(base_dir)

    if not base_path.exists():
        result['valid'] = False
        result['missing_files'].extend(required_files)
        return result

    for file_pattern in required_files:
        # Check for exact match first
        if (base_path / file_pattern).exists():
            result['found_files'].append(file_pattern)
        else:
            # Try glob pattern
            matches = list(base_path.glob(file_pattern))
            if matches:
                result['found_files'].extend([m.name for m in matches])
            else:
                result['missing_files'].append(file_pattern)
                result['valid'] = False

    return result


def validate_file_size(file_path: str, min_size: int = 100, max_size: Optional[int] = None) -> Dict[str, Any]:
    """
    Validate file size sanity checks.

    Args:
        file_path: Path to file
        min_size: Minimum expected size in bytes
        max_size: Maximum expected size in bytes (optional)

    Returns:
        Dictionary with validation result
    """
    result = {
        'valid': False,
        'file_size': 0,
        'errors': []
    }

    try:
        path = Path(file_path)
        if not path.exists():
            result['errors'].append(f"File not found: {file_path}")
            return result

        size = path.stat().st_size
        result['file_size'] = size

        if size < min_size:
            result['errors'].append(f"File too small: {size} bytes (minimum: {min_size})")

        if max_size and size > max_size:
            result['errors'].append(f"File too large: {size} bytes (maximum: {max_size})")

        result['valid'] = len(result['errors']) == 0
        return result

    except Exception as e:
        result['errors'].append(f"Validation error: {e}")
        return result
