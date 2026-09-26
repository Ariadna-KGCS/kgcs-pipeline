"""
ETL-only write client for the KGCS Neo4j knowledge graph.

THIS MODULE MUST NEVER BE IMPORTED BY THE AGENT LAYER.
Agents use a separate read-only client (agents/shared/neo4j_client.py, Phase 2C).

All connection parameters come from environment variables:
    NEO4J_URI       e.g. bolt://localhost:7687 or neo4j+s://xxxxx.databases.neo4j.io
    NEO4J_USER      e.g. neo4j
    NEO4J_PASSWORD  your database password
    NEO4J_DATABASE  target database name (optional; default neo4j instance default)

All write operations use MERGE (idempotent). Batching is done via UNWIND.
Transactions are auto-committed per batch; partial failure is logged but
does not abort the remaining batches (callers decide on failure policy).
"""

import logging
import os
from typing import Any, Dict, List

from neo4j import GraphDatabase, Driver
from neo4j.exceptions import Neo4jError, ServiceUnavailable

# Load .env if present (no-op when python-dotenv is not installed)
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(override=False)  # env vars already set take priority
except ImportError:
    pass


logger = logging.getLogger(__name__)


class Neo4jWriter:
    """ETL write client.

    Usage (preferred — context manager):
        with Neo4jWriter() as writer:
            writer.execute_batch(cypher, rows)

    Usage (manual):
        writer = Neo4jWriter()
        try:
            writer.execute_batch(cypher, rows)
        finally:
            writer.close()
    """

    def __init__(self) -> None:
        uri = os.environ["NEO4J_URI"]
        user = os.environ["NEO4J_USER"]
        password = os.environ["NEO4J_PASSWORD"]
        self._database = os.environ.get("NEO4J_DATABASE")
        self._driver: Driver = GraphDatabase.driver(uri, auth=(user, password))
        logger.info(
            "Neo4jWriter connected to %s%s",
            uri,
            f" (database={self._database})" if self._database else "",
        )

    def close(self) -> None:
        self._driver.close()

    def __enter__(self) -> "Neo4jWriter":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # ------------------------------------------------------------------
    # batch write
    # ------------------------------------------------------------------

    def execute_batch(
        self,
        cypher: str,
        params_list: List[Dict],
        batch_size: int = 1000,
    ) -> Dict[str, Any]:
        """Execute an UNWIND-based Cypher statement against batched param rows.

        The Cypher statement MUST use:
            UNWIND $batch AS row
            ...

        Args:
            cypher:       Parameterised Cypher using $batch parameter.
            params_list:  Full list of row dicts (e.g. 250 000 CVE records).
            batch_size:   Rows per transaction. Default 1000.

        Returns:
            {
                "success":       bool,
                "nodes_created": int,
                "rels_created":  int,
                "nodes_deleted": int,
                "errors":        List[str],
            }
        """
        nodes_created = 0
        rels_created = 0
        nodes_deleted = 0
        errors: List[str] = []

        if not params_list:
            return {
                "success": True,
                "nodes_created": 0,
                "rels_created": 0,
                "nodes_deleted": 0,
                "errors": [],
            }

        total = len(params_list)
        logger.debug(f"execute_batch: {total} rows, batch_size={batch_size}")

        for start in range(0, total, batch_size):
            chunk = params_list[start : start + batch_size]
            batch_num = start // batch_size + 1
            try:
                with self._driver.session(database=self._database) as session:
                    summary = session.execute_write(
                        lambda tx, b=chunk: tx.run(cypher, {"batch": b}).consume()
                    )
                nodes_created += summary.counters.nodes_created
                rels_created += summary.counters.relationships_created
                nodes_deleted += summary.counters.nodes_deleted
                logger.debug(
                    f"Batch {batch_num}: nodes={summary.counters.nodes_created} "
                    f"rels={summary.counters.relationships_created}"
                )
            except (Neo4jError, ServiceUnavailable) as exc:
                msg = f"Batch {batch_num} (rows {start}–{start+len(chunk)-1}): {exc}"
                logger.error(msg)
                errors.append(msg)
            except Exception as exc:
                msg = f"Batch {batch_num} unexpected error: {exc}"
                logger.error(msg)
                errors.append(msg)

        return {
            "success": len(errors) == 0,
            "nodes_created": nodes_created,
            "rels_created": rels_created,
            "nodes_deleted": nodes_deleted,
            "errors": errors,
        }

    # ------------------------------------------------------------------
    # single write (constraints, indexes, one-off operations)
    # ------------------------------------------------------------------

    def execute_one(self, cypher: str, params: Dict | None = None) -> Dict[str, Any]:
        """Execute a single parameterised Cypher write statement.

        Used for constraint creation, index creation, and one-off writes.

        Returns:
            {
                "success": bool,
                "counters": dict,
                "errors":   List[str],
            }
        """
        params = params or {}
        try:
            with self._driver.session(database=self._database) as session:
                summary = session.execute_write(
                    lambda tx: tx.run(cypher, params).consume()
                )
            return {
                "success": True,
                "counters": dict(vars(summary.counters)),
                "errors": [],
            }
        except (Neo4jError, ServiceUnavailable) as exc:
            logger.error(f"execute_one failed: {exc}\nCypher: {cypher[:200]}")
            return {"success": False, "counters": {}, "errors": [str(exc)]}
        except Exception as exc:
            logger.error(f"execute_one unexpected error: {exc}")
            return {"success": False, "counters": {}, "errors": [str(exc)]}

    # ------------------------------------------------------------------
    # read (stats, verification)
    # ------------------------------------------------------------------

    def read_one(self, cypher: str, params: Dict | None = None) -> Any:
        """Execute a single read query and return the first record's first value.

        Returns None if no records match or on error.
        """
        params = params or {}
        try:
            with self._driver.session(database=self._database) as session:
                result = session.run(cypher, params)
                record = result.single()
                return record[0] if record else None
        except Exception as exc:
            logger.error(f"read_one failed: {exc}")
            return None

    def read_rows(self, cypher: str, params: Dict | None = None) -> List[Dict]:
        """Execute a read query and return every record as a dict (read session)."""
        params = params or {}
        with self._driver.session(
            database=self._database, default_access_mode="READ"
        ) as session:
            return [record.data() for record in session.run(cypher, params)]
