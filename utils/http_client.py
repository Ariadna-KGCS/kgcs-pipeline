"""
Reusable HTTP client with retry logic and rate limiting awareness.

Implements exponential backoff for resilient downloads across all standards.
"""

import logging
import time
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class HTTPClient:
    """HTTP client with exponential backoff retry logic."""

    def __init__(self, timeout: int = 300, max_retries: int = 5, backoff_factor: float = 0.5):
        """
        Initialize HTTP client with retry strategy.

        Args:
            timeout: Request timeout in seconds (default: 300s = 5 minutes)
            max_retries: Maximum number of retry attempts (default: 5)
            backoff_factor: Exponential backoff multiplier (default: 0.5)
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.logger = logging.getLogger(__name__)

        # Create session with retry strategy
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create requests session with exponential backoff retry strategy."""
        session = requests.Session()

        # Define retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],  # Retry on these HTTP codes
            allowed_methods=["GET", "HEAD"]
        )

        # Mount adapter to session
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set user agent
        session.headers.update({
            'User-Agent': 'KGCS-Downloader/1.0 (Cybersecurity Knowledge Graph)'
        })

        return session

    def get(self, url: str, timeout: Optional[int] = None, **kwargs) -> Optional[requests.Response]:
        """
        GET request with timeout and retry logic.

        Args:
            url: URL to fetch
            timeout: Request timeout (uses default if not specified)
            **kwargs: Additional arguments to pass to requests.get()

        Returns:
            requests.Response if successful, None if all retries exhausted
        """
        if timeout is None:
            timeout = self.timeout

        try:
            self.logger.debug(f"Fetching: {url}")
            response = self.session.get(url, timeout=(30, timeout), **kwargs)
            response.raise_for_status()
            self.logger.debug(f"Success: {url} ({response.status_code})")
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to fetch {url}: {e}")
            return None

    def download_file(self, url: str, file_path: str, chunk_size: int = 8192) -> bool:
        """
        Download file from URL with streaming and retry.

        Args:
            url: URL to download from
            file_path: Path to save file
            chunk_size: Chunk size for streaming (default: 8KB)

        Returns:
            True if download successful, False otherwise
        """
        try:
            self.logger.info(f"Downloading: {url} -> {file_path}")
            response = self.get(url, stream=True)

            if response is None:
                self.logger.error(f"Download failed after {self.max_retries} retries: {url}")
                return False

            total_size = int(response.headers.get('content-length', 0))

            with open(file_path, 'wb') as f:
                downloaded = 0
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            self.logger.debug(f"Progress: {percent:.1f}% ({downloaded}/{total_size} bytes)")

            self.logger.info(f"Downloaded successfully: {file_path} ({downloaded} bytes)")
            return True

        except Exception as e:
            self.logger.error(f"Error downloading file: {e}")
            return False

    def close(self):
        """Close HTTP session."""
        self.session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
