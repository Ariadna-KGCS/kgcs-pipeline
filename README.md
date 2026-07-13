# kgcs-pipeline

Builds the KGCS Neo4j graph from the 10 authoritative sources (NVD and MITRE feeds), following the causal chain defined by [kgcs-spec](https://github.com/Ariadna-KGCS/kgcs-spec). Part of the [Ariadna-KGCS organization](https://github.com/Ariadna-KGCS).

## Quickstart

```bash
git clone https://github.com/Ariadna-KGCS/kgcs-pipeline.git
cd kgcs-pipeline
pip install -r requirements.txt
python sync_spec.py                        # materialize the pinned kgcs-spec release
python download.py --standard all          # download raw datasets (~GBs)
cp .env.example .env                       # set NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD
python run_all_etl.py                      # constraints → nodes → relationships
```

Requires Python 3.11+ and a running Neo4j 5.x instance.

## Layout

- `download.py`, `run_all_etl.py` — entrypoints (run from repo root; `data/raw` paths are CWD-relative)
- `downloaders/` — per-source download clients (NVD, MITRE) + universal downloader and validators
- `etl/` — constraint init + per-standard loaders, executed in causal-chain order
- `validation/` — SHACL/post-load validation + graph stats (`extract_neo4j_stats.py`)
- `utils/` — shared HTTP client (retries, backoff)
- `data/raw/` — downloaded datasets (gitignored; reproducible via `python download.py --standard all`)
- `data/schemas/` — JSON schemas of the *external* feeds (NVD/MITRE), used to validate raw data
- `spec/` — pinned `kgcs-spec` materialization (gitignored; see below)
- `tests/` — unit tests for transform logic (no Neo4j required)

## Spec Pin

`SPEC_VERSION` pins the `kgcs-spec` release this pipeline builds against (currently **1.0.0**). Materialize it with:

```bash
python sync_spec.py   # or: python sync_spec.py --url <kgcs-spec-url>
```

The script is idempotent: it wipes and rebuilds the gitignored `spec/` from the pinned tag (hand-edits cannot survive), records tag+commit in `spec/.pin`, and `--check` verifies the pin without syncing. CI runs it unconditionally before tests. SHACL/OWL validation reads from `spec/shapes/` and `spec/ontology/` by default.

## Rules

- Pins a released `kgcs-spec` version; graph shape must match its contracts.
- Load order: constraints → nodes → relationships, following the causal chain; no skipped hops.
- Parameterized Cypher + `MERGE` only; dedupe in Python before batch writes; stream large datasets.
- Verify external feed schemas from actual downloaded files before coding extraction logic.

## Status

Migrated from the seed repo (Release B baseline). Pinned to `kgcs-spec` **v1.0.0**. Raw data not migrated — re-download with `python download.py --standard all`.

## License

[Apache 2.0](LICENSE). The downloaded datasets (NVD, MITRE) remain subject to their own terms of use.
