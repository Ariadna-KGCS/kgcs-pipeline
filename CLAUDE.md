# kgcs-pipeline — Agent Instructions

This repo builds the KGCS Neo4j graph. It consumes the KGCS standard from `kgcs-spec` at the version pinned in `SPEC_VERSION`.

## Spec Pin

- `SPEC_VERSION` holds the pinned `kgcs-spec` release tag (without the `v` prefix).
- Materialize it locally: `python scripts/sync_spec.py` (idempotent; wipes and rebuilds the gitignored `spec/` from the tag; `--check` verifies without syncing). CI runs it unconditionally before tests so no result can depend on a hand-edited copy.
- Never read spec artifacts from a sibling checkout's working tree; only from the pinned materialization.
- Upgrading the pin is an explicit, reviewed change: bump `SPEC_VERSION`, re-run full validation.

## Hard Rules

1. **Causal chain order.** Load constraints first, then nodes and relationships in `CPE → CVE/CVSS → CWE → CAPEC → ATT&CK → {D3FEND, CAR, SHIELD, ENGAGE}` order. No shortcut edges, ever.
   Spec 1.2 adds steps outside the chain: decision leaves (`kev`, `epss`, `ssvc`) right after `cvss`, adhered only to `Vulnerability`; ATLAS (`atlas`) right after `attck`, whose only edge out of ATLAS is `ADAPTED_FROM`. Neither may write a chain edge type (post-load checks `decision_no_chain_edges`, `atlas_boundary`).
2. **Idempotency.** Parameterized Cypher and `MERGE` only; never string-built queries. Re-running a loader must not duplicate nodes or edges.
3. **Cardinality.** Deduplicate in Python before batch writes when graph cardinality invariants depend on it.
4. **Memory.** Stream or process file-by-file for large datasets (CPE ~15 chunks, CPE-MATCH ~56 chunks, CVE per-year files); never accumulate everything in memory.
5. **External schemas.** Verify raw-data schemas from actually downloaded files (`data/schemas/` documents the feeds) before coding extraction logic.
6. **Provenance.** Source-specific identifiers stay separate; CVSS versions never merge into a single value.

## Layout

Entrypoints in `scripts/` (`download.py`, `download_schemas.py`, `run_all_etl.py`, `sync_spec.py`) with packages `downloaders/`, `etl/`, `validation/`, `utils/`. Paths like `data/raw` are CWD-relative: always run from the repo root.

## Verification

- Unit tests: `pytest tests/` (pure-Python transform logic; no Neo4j needed).
- Post-load: `python validation/validate_all_standards.py --post-load` and `python validation/extract_neo4j_stats.py --pretty --check-minimums` (no skipped hops, no duplicate cardinality edges, node/relationship minimums).
- SHACL/OWL validation runs against `spec/` (pinned), not local copies.

Part of the Ariadna umbrella (`../README.md`).
