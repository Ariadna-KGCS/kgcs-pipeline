"""
Abstract base class for all KGCS standard-specific ETL loaders.

Mirrors the AbstractDownloader pattern from downloaders/base.py:
  - log_success / log_warning / log_error helpers
  - Returns {success, errors, stats} dicts — never raises
  - Path-based file access

Subclass contract:
  1. Declare standard_name property
  2. Implement extract()             → raw data (any type)
  3. Implement transform(raw_data)   → List[Dict] (Neo4j-ready records)
  4. Implement load_nodes(records)   → Dict result
  5. Implement load_relationships(records) → Dict result

The base run() method orchestrates these four steps and catches all errors.
Each step is independently retryable via run_all_etl.py --step NAME.
"""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List


class AbstractETL(ABC):
    """Base class for all KGCS standard ETL loaders.

    Every loader reads raw files from raw_data_dir/{standard_name}/,
    transforms to canonical Neo4j-ready dicts, and loads via the writer.

    Return contract for all load_* methods:
        {
            "success": bool,
            "errors":  List[str],
            "stats":   {"nodes_created": int, "rels_created": int, ...}
        }
    """

    def __init__(self, raw_data_dir: str, writer, batch_size: int = 1000):
        """
        Args:
            raw_data_dir: Base raw data directory (e.g. 'data/raw').
            writer:       Neo4jWriter instance (ETL write client).
            batch_size:   Rows per Neo4j transaction batch.
        """
        self.raw_data_dir = Path(raw_data_dir)
        self.writer = writer
        self.batch_size = batch_size
        self.logger = logging.getLogger(self.__class__.__name__)

    # ------------------------------------------------------------------
    # Abstract interface — must be implemented by each standard loader
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def standard_name(self) -> str:
        """Return canonical standard name used as subdirectory (e.g. 'CVE')."""
        pass

    @abstractmethod
    def extract(self) -> Any:
        """Read raw source files.

        Must never raise. On read error: log, return partial data or empty.
        Returns any type appropriate for the standard (list, dict, generator).
        """
        pass

    @abstractmethod
    def transform(self, raw_data: Any) -> List[Dict]:
        """Convert raw data to canonical Neo4j-ready record dicts.

        Returns an empty list on transform failure (with logged errors).
        Each dict must contain exactly the fields used in the Cypher queries
        of load_nodes() and load_relationships().
        """
        pass

    @abstractmethod
    def load_nodes(self, records: List[Dict]) -> Dict[str, Any]:
        """MERGE node records into Neo4j in batches.

        Returns result dict: {success, errors, stats}.
        """
        pass

    @abstractmethod
    def load_relationships(self, records: List[Dict]) -> Dict[str, Any]:
        """MERGE relationship records into Neo4j in batches.

        Must be called AFTER load_nodes() for this standard.
        Returns result dict: {success, errors, stats}.
        """
        pass

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        """Execute the full ETL cycle: extract → transform → load_nodes → load_relationships.

        Returns:
            {
                "success": bool,
                "errors":  List[str],
                "stats":   dict with nodes_created, rels_created, and any extras
            }
        """
        result: Dict[str, Any] = {"success": False, "errors": [], "stats": {}}

        try:
            self.log_success("Starting ETL")

            raw = self.extract()
            records = self.transform(raw)

            if not records:
                self.log_warning("No records produced after transform — nothing to load.")
                result["success"] = True
                result["stats"] = {"nodes_created": 0, "rels_created": 0}
                return result

            self.log_success(f"Transformed {len(records)} records — loading nodes")
            node_r = self.load_nodes(records)

            self.log_success(f"Loading relationships")
            rel_r = self.load_relationships(records)

            result["success"] = node_r["success"] and rel_r["success"]
            result["errors"] = node_r.get("errors", []) + rel_r.get("errors", [])
            result["stats"] = {
                "nodes_created": (
                    node_r.get("stats", {}).get("nodes_created", 0)
                    + rel_r.get("stats", {}).get("nodes_created", 0)
                ),
                "rels_created": (
                    node_r.get("stats", {}).get("rels_created", 0)
                    + rel_r.get("stats", {}).get("rels_created", 0)
                ),
            }
            # Merge any extra stats keys from each step
            for extra in (node_r.get("stats", {}), rel_r.get("stats", {})):
                for k, v in extra.items():
                    if k not in result["stats"]:
                        result["stats"][k] = v

            if result["success"]:
                self.log_success(f"Complete: {result['stats']}")
            else:
                self.log_error(f"Completed with errors: {result['errors']}")

        except Exception as exc:
            self.log_error(f"Unhandled exception: {exc}")
            result["errors"].append(str(exc))

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def standard_dir(self) -> Path:
        """Resolved path to the raw data directory for this standard."""
        return self.raw_data_dir / self.standard_name

    def _empty_result(self, **extra_stats) -> Dict[str, Any]:
        """Return a successful no-op result dict."""
        return {
            "success": True,
            "errors": [],
            "stats": {"nodes_created": 0, "rels_created": 0, **extra_stats},
        }

    def _error_result(self, *errors: str) -> Dict[str, Any]:
        """Return a failed result dict with the given error messages."""
        for msg in errors:
            self.log_error(msg)
        return {
            "success": False,
            "errors": list(errors),
            "stats": {"nodes_created": 0, "rels_created": 0},
        }

    # Logging helpers — mirror AbstractDownloader exactly
    def log_success(self, message: str) -> None:
        self.logger.info(f"[{self.standard_name}] ✓ {message}")

    def log_warning(self, message: str) -> None:
        self.logger.warning(f"[{self.standard_name}] ⚠ {message}")

    def log_error(self, message: str) -> None:
        self.logger.error(f"[{self.standard_name}] ✗ {message}")
