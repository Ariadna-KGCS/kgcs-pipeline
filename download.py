#!/usr/bin/env python3
"""
KGCS Cybersecurity Data Downloader

Downloads raw data for 10 cybersecurity standards from NIST and MITRE:
- CVE, CWE, CPE, CVSS (from NIST NVD)
- CAPEC, ATT&CK, D3FEND (from MITRE)
- CAR, ENGAGE, SHIELD (from MITRE frameworks)

Usage:
    python download.py --standard all --validate
    python download.py --standard cve --output-report
    python download.py --standard attck --config config.yaml
"""

import argparse
import json
import logging
import sys
import yaml
from pathlib import Path
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import the improved universal downloader
from downloaders.universal_downloader import UniversalDownloader


# Configure logging
def setup_logging(verbose: bool = False) -> logging.Logger:
    """Set up logging with timestamp and level indicators."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)


# Load configuration
def load_config(config_file: str = None) -> dict:
    """Load configuration from YAML file or return defaults."""
    defaults = {
        'timeout': 300,
        'retries': 5,
        'output_dir': 'data/raw',
        'enabled_standards': ['all'],
        'validate': True,
        'report': False,
    }

    if config_file and Path(config_file).exists():
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
                if config:
                    defaults.update(config)
        except Exception as e:
            logging.error(f"Failed to load config file: {e}")

    return defaults


# Supported standards
SUPPORTED_STANDARDS = {
    'cve', 'cwe', 'cpe', 'cpematch', 'cvss', 'capec', 'attck', 'd3fend', 'car', 'engage', 'shield'
}


def get_standards_to_download(standard_arg: str) -> list:
    """Parse command-line standard argument."""
    if standard_arg.lower() == 'all':
        return list(SUPPORTED_STANDARDS)
    else:
        standards = [s.strip().lower() for s in standard_arg.split(',')]
        return [s for s in standards if s in SUPPORTED_STANDARDS]


def download_all_standards(output_dir: str, config: dict) -> dict:
    """Download all standards using UniversalDownloader."""
    logger = logging.getLogger(__name__)

    result = {
        'success': False,
        'timestamp': datetime.now().isoformat(),
        'details': {}
    }

    try:
        downloader = UniversalDownloader(
            output_dir=output_dir,
            timeout=config.get('timeout', 300),
            retries=config.get('retries', 5)
        )

        # Download all standards
        if not downloader.download():
            logger.warning("Some standards failed to download")
            result['details']['download_error'] = "One or more standards could not be downloaded"
        else:
            logger.info("All standards downloaded successfully")

        # Validate if enabled
        if config.get('validate', True):
            validation_result = downloader.validate()
            result['details']['validation'] = validation_result
            if not validation_result:
                logger.warning("Validation failed for some standards")
        else:
            logger.info("Skipping validation")

        result['success'] = True

    except Exception as e:
        result['details']['error'] = str(e)
        logger.error(f"Download error: {e}")

    return result


def generate_report(result: dict, output_file: str = None) -> str:
    """Generate summary report."""
    report_lines = [
        "\n" + "="*80,
        "KGCS Download Report",
        "="*80,
        f"Timestamp: {result.get('timestamp', datetime.now().isoformat())}",
    ]

    status = "[PASS]" if result.get('success') else "[FAIL]"
    report_lines.extend([
        f"Status: {status}",
        "",
    ])

    if result.get('details'):
        report_lines.append("Details:")
        report_lines.append("-" * 80)
        for key, value in result['details'].items():
            if isinstance(value, dict):
                report_lines.append(f"{key}:")
                for k, v in value.items():
                    report_lines.append(f"  {k}: {v}")
            else:
                report_lines.append(f"{key}: {value}")

    report_lines.append("="*80 + "\n")

    report_text = "\n".join(report_lines)

    # Print to console with safe encoding
    try:
        print(report_text)
    except UnicodeEncodeError:
        # Fallback for Windows console
        print(report_text.encode('utf-8', errors='replace').decode('utf-8'))

    # Write to file if requested
    if output_file:
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Write text report
            with open(str(output_path.with_suffix('.txt')), 'w', encoding='utf-8') as f:
                f.write(report_text)

            # Write JSON report
            with open(str(output_path.with_suffix('.json')), 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2)

            print(f"Report saved to {output_path.with_suffix('.*')}")
        except Exception as e:
            print(f"Warning: Failed to save report file: {e}")

    return report_text


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Download cybersecurity standard raw data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download all standards
  python download.py --standard all --validate

  # Download specific standards
  python download.py --standard cve,attck --validate

  # Download with configuration file
  python download.py --standard all --config download_config.yaml

  # Download and generate report
  python download.py --standard all --output-report data/raw/.metadata/download-report
        """
    )

    parser.add_argument(
        '--standard',
        default='all',
        help='Standard(s) to download: all, or comma-separated list (cve,cwe,cpe,cpematch,cvss,capec,attck,d3fend,car,engage,shield)'
    )

    parser.add_argument(
        '--output-dir',
        default='data/raw',
        help='Output directory for downloaded data (default: data/raw)'
    )

    parser.add_argument(
        '--config',
        help='YAML configuration file'
    )

    parser.add_argument(
        '--validate',
        action='store_true',
        default=True,
        help='Validate downloaded data (default: enabled)'
    )

    parser.add_argument(
        '--no-validate',
        action='store_false',
        dest='validate',
        help='Skip validation'
    )

    parser.add_argument(
        '--output-report',
        help='Generate summary report (filename prefix for .txt and .json)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(verbose=args.verbose)

    # Load configuration
    config = load_config(args.config)
    config['validate'] = args.validate

    # Determine output directory
    output_dir = args.output_dir or config.get('output_dir', 'data/raw')
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Get standards to download (for info purposes)
    standards = get_standards_to_download(args.standard)

    if not standards:
        print(f"No valid standards specified. Available: {', '.join(SUPPORTED_STANDARDS)}")
        return 1

    logger.info(f"Starting download for {len(standards)} standard(s): {', '.join(standards)}")

    # Download all standards using UniversalDownloader
    result = download_all_standards(output_dir, config)

    # Generate report
    if args.output_report:
        generate_report(result, args.output_report)
    else:
        generate_report(result)

    # Return exit code
    if result.get('success'):
        logger.info("Downloads completed successfully")
        return 0
    else:
        logger.error("Downloads failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
