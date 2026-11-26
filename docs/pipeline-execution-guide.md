# Pipeline Execution Guide

Authoritative steps for download → ETL → validation → statistics. Re-measured
on 2026-11-27 from `scripts/run_all_etl.py`, `etl/`, `validation/` and
`downloaders/` of the `devel` branch (spec pin in `SPEC_VERSION`); where a
number comes from a run instead of the code, the run is named. The order and
the gates of a full rebuild are in [`fresh-load.md`](fresh-load.md); this page
documents each script.

## Prerequisites

Set Neo4j connection credentials as environment variables before running any pipeline script:

```powershell
# Windows PowerShell
$env:NEO4J_URI      = "bolt://localhost:7687"
$env:NEO4J_USER     = "neo4j"
$env:NEO4J_PASSWORD = "yourpassword"
$env:NEO4J_DATABASE = "<database>"      # optional; without it the server's default database is used
```

```bash
# Linux / macOS
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=yourpassword
export NEO4J_DATABASE=<database>        # optional
```

`etl/neo4j_writer.py` reads the four variables (and a `.env` file when
`python-dotenv` is installed; variables already set win). Always run from the
repo root: `data/raw` and `spec/` are CWD-relative.

Raw data must already be downloaded to `data/raw/`; see
[Downloaders](#downloaders-scriptsdownloadpy) below.

---

## ETL Pipeline Orchestrator

`scripts/run_all_etl.py` runs the 16 steps of its `STEPS` list in order and
exits 1 on the first failure (a step that returns `success: false`, or raises).
A step that returns `None` is logged as a warning and counted as success. The
2026-11-01 run (`docs/fresh-load/runs/2026-11-01-kgcs-2026-11/etl.log`) executed
`STEP 1/16` to `STEP 16/16` and ended with `Pipeline complete — all steps succeeded.`

```powershell
# Run the full pipeline (recommended on first load or after re-downloading)
python scripts/run_all_etl.py

# Run with a non-default data directory
python scripts/run_all_etl.py --raw-data-dir <raw-dir>

# Preview what would run without connecting to Neo4j
python scripts/run_all_etl.py --dry-run

# Re-run a single step (the step runs alone; constraints are not re-applied)
python scripts/run_all_etl.py --step cve

# Verbose debug output (also enables the Neo4j driver's logger: very large logs)
python scripts/run_all_etl.py --log-level DEBUG
```

### Parameters

| Flag | Default | Description |
|---|---|---|
| `--raw-data-dir PATH` | `data/raw` | Base directory for downloaded raw data (resolved to an absolute path) |
| `--batch-size INT` | `1000` | Neo4j transaction batch size (rows per `UNWIND`) |
| `--step NAME` | _(all)_ | Run only the named step; names are in the step registry below |
| `--dry-run` | false | Print the selected steps, `raw_data_dir` and `batch_size`; no connection, no environment check |
| `--skip-constraints` | false | Drop the `constraints` step from a full run. Has no effect with `--step` (a single step is selected as is) |
| `--log-level LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

Stdout and stderr are forced to UTF-8 so the `✓`/`→`/`—` glyphs survive a
redirect. `--dry-run` does not print the target database.

### Step Registry

The 16 steps, exactly as `STEPS` declares them. Step *n* of 16 is the `STEP n/16`
line in the log. Each step requires the ones before it (hard stop on first failure).
The "Where" column says whether the step is in the causal chain
(`CPE → CVE/CVSS → CWE → CAPEC → ATT&CK → {D3FEND, CAR, SHIELD, ENGAGE}`) or outside it.

| # | Step name | Implementation | Reads (under `--raw-data-dir`) | Writes | Where |
|---|---|---|---|---|---|
| 1 | `constraints` | `init_constraints.run_constraints()` | — | 27 unique constraints and 3 lookup indexes (`Tactic.phaseName`, `Vulnerability.published`, `Score.version`), all `IF NOT EXISTS` | setup |
| 2 | `cpe` | `CPELoader` | `CPE/nvdcpe-2.0-chunks/*.json`, `CPE-MATCH/nvdcpematch-2.0-chunks/*.json` (one chunk at a time) | `Platform`, `PlatformConfiguration`; `MATCHES_PLATFORM` | chain |
| 3 | `cve` | `CVELoader` | `CVE/nvdcve-2.0-modified.json` first, then `CVE/nvdcve-2.0-YYYY.json` in order | `Vulnerability`, `Reference`, `VulnerabilityConfiguration`, `VulnerabilityConfigurationNode`; `HAS_CONFIGURATION`, `HAS_NODE`, `MATCHES_CRITERIA`, `AFFECTS`, `REFERENCES` | chain |
| 4 | `cvss` | `CVSSLoader` | the same CVE files | `Score` (one node per CVE and version, `scoreId = <cveId>_<version>`); `HAS_SCORE` | chain |
| 5 | `kev` | `KEVLoader` | `KEV/known_exploited_vulnerabilities.json` | `KevEntry`; `HAS_KEV_ENTRY` | decision leaf |
| 6 | `epss` | `EPSSLoader` | `EPSS/epss_scores-<date>.csv.gz` (every dated file; the undated `-current` file only if no dated one exists) | `EpssScore` (append-only, `epssId = <cve>::EPSS::<scoreDate>`); `HAS_EPSS` | decision leaf |
| 7 | `ssvc` | `SSVCLoader` | the CVE files again, `metrics.ssvcV203[]` of declared ADP entries | `SsvcDecision` (`ssvcId = <cveId>::SSVC::<timestamp>`); `HAS_SSVC` | decision leaf |
| 8 | `cwe` | `CWELoader` | `CWE/cwec_v*.xml` (newest version wins, namespace read from the root element) and the CVE files (`weaknesses[]`) | `Weakness` (with the spec 1.1 enrichment), `Consequence`; `CAUSED_BY`, `HAS_CONSEQUENCE` | chain |
| 9 | `capec` | `CAPECLoader` | `CAPEC/capec_latest.xml` | `AttackPattern`, `Consequence`; `DEMONSTRATED_BY`, `CHILD_OF`, `HAS_CONSEQUENCE` | chain |
| 10 | `attck` | `ATTCKLoader` | the enterprise, ICS and mobile STIX bundles in `ATTCK-STIX/` (the loader also accepts `ATTCK`, `ATT&CK`, `ATTACK`, `attack`, `attck`) and `CAPEC/capec_latest.xml` (taxonomy mappings) | `Technique`, `SubTechnique`, `Tactic`; `PART_OF`, `SUBTECHNIQUE_OF`, `IMPLEMENTS` (CAPEC → ATT&CK) | chain |
| 11 | `atlas` | `ATLASLoader` | `ATLAS/ATLAS-<release>.yaml` (newest release present; never `ATLAS-latest.yaml`) | `AtlasTactic`, `AtlasTechnique`, `AtlasSubTechnique`, `AtlasMitigation`; `ACHIEVES`, `SPECIALIZES`, `MITIGATES`, `ADAPTED_FROM` (only edge into ATT&CK) | parallel matrix |
| 12 | `d3fend` | `D3FENDLoader` | `D3FEND/d3fend-full-mappings.json`, `D3FEND/d3fend.json` | `DefensiveTechnique`; `MITIGATED_BY` | chain |
| 13 | `car` | `CARLoader` | `car/analytics/*.yaml` (falls back to `CAR/analytics`) | `DetectionAnalytic`; `DETECTED_BY` (with `coverageLevel`) | chain |
| 14 | `shield` | `SHIELDLoader` | `SHIELD/techniques.json`, `SHIELD/attack_mapping.json` | `DeceptionTechnique`; `COUNTERED_BY` | chain |
| 15 | `engage` | `ENGAGELoader` | `ENGAGE/activities.json`, `approaches.json`, `goals.json`, `attack_mapping.json` | `EngagementConcept`; `DISRUPTS` (only from `EAC` activities) | chain |
| 16 | `build_metadata` | `build_metadata.run_build_metadata()` | the raw files of the 13 sources, `SPEC_VERSION`, `git rev-parse HEAD` | the single `BuildMetadata` node, no edges | postscript |

Notes:

- **Outside the chain.** The decision leaves (`kev`, `epss`, `ssvc`; spec 1.2.0,
  ADR-0003) load right after `cvss` and hang only off `Vulnerability`. The ATLAS
  matrix (`atlas`; spec 1.2.1, ADR-0004) loads right after `attck` because
  `ADAPTED_FROM` needs the ATT&CK nodes. Neither writes a chain edge type; the
  post-load checks `decision_no_chain_edges` and `atlas_boundary` enforce it.
  `build_metadata` is a postscript.
- **Orphan leaves are never created.** KEV, EPSS and SSVC rows whose CVE has no
  `Vulnerability` node are dropped and counted (`dropped_no_vulnerability`;
  2026-11-01: KEV 1 of 1,766, EPSS 0, SSVC 0).
- **ATT&CK revocations.** `attck`, `d3fend` and `atlas` resolve ATT&CK ids
  through one shared revoked-by remap (`etl/attck_revocations.py`): revoked ids
  are remapped to their live successor, deprecated ones dropped, unknown ids
  counted as unresolved; all three counts are logged.
- **Not steps.** `etl/consequences.py`, `etl/cve_applicability.py`,
  `etl/decision_common.py` and `etl/attck_revocations.py` are shared helpers;
  `etl/base.py` is the loader base class and `etl/neo4j_writer.py` the
  write client (`MERGE` and `UNWIND` only). The `Step N of the KGCS load order`
  lines in some loader docstrings predate the 16-step list; `STEPS` is the order.
- **Per-step counters of the last validated run** (`summary.json`, from
  `etl.log`, 2026-11-01): see [Graph Statistics](#graph-statistics).

### Build Metadata (spec 1.1.0; spec 1.2 keys)

The last step writes one `BuildMetadata` node: `specVersion` (`SPEC_VERSION`),
`buildTimestamp` (UTC completion instant), `pipelineCommit` (`git rev-parse HEAD`;
a warning is logged when the working tree is dirty) and `sourceSnapshots`, one
`<SOURCE>=<snapshot>` per source, 13 in all (`SOURCES` in `etl/build_metadata.py`:
CPE, CVE, CVSS, CWE, CAPEC, ATTCK, D3FEND, CAR, SHIELD, ENGAGE, KEV, EPSS,
ATLAS), read from the same raw files the loaders read. Preview it offline with
`python -m etl.build_metadata`.

Rule: the release when the source states one; dates or ranges only when it has none.

| SOURCE | Snapshot | 2026-11-01 raw data (`etl.log`) |
|---|---|---|
| CWE, CAPEC | catalog `Version` attribute (the catalog `Date` is only logged) | `CWE=5.0`, `CAPEC=3.9` |
| D3FEND | `owl:versionInfo` of `d3fend.json` | `D3FEND=1.3.0` |
| ATTCK | the `x-mitre-collection` `x_mitre_version` if all three bundles carry the same one, else `download:<file date>;modified-max:<max modified>` | `ATTCK=download:2026-11-01;modified-max:2026-10-13` |
| CVE, CVSS | NVD feed `timestamp` of the CVE files: one value when all files agree, else `<min>..<max>` (UTC, seconds, `Z`) | `CVE=2026-10-21T03:05:10Z..2026-11-01T10:00:04Z` |
| CPE | same rule over the CPE and CPE-MATCH chunks together | `CPE=2026-10-30T23:50:01Z..2026-10-31T23:48:52Z` |
| CAR, SHIELD, ENGAGE | no release in the files: `download:<file date>` | `CAR=download:2026-11-01` |
| KEV | catalog `catalogVersion` | `KEV=2026.10.30` |
| EPSS | header `score_date` (date part) and `model_version` | `EPSS=2026-11-01;model:v2026.06.15` |
| ATLAS | release of the loaded `ATLAS-<release>.yaml` | `ATLAS=2026.09` |

The range matters: the yearly CVE feeds lag the modified feed by up to nine days,
so the max alone would overstate freshness. "File date" is the UTC date of the
newest file mtime; the downloader records nothing else, so a validated load
keeps a listing of every `data/raw` file (path, size, mtime, sha256) as the
evidence: `fresh-load.md` step 6 writes it as `manifest.csv`.

---

## Downloaders (`scripts/download.py`)

`scripts/download.py` fetches every source into `data/raw/` through
`downloaders.universal_downloader.UniversalDownloader`; every URL lives in
`downloaders/ingest_config.py` (`APIEndpoints`), and `data/README.md` tabulates
them with the official schema of each.

```powershell
python scripts/download.py --standard all          # the fresh-load command
python scripts/download.py --standard all --no-validate --output-report <prefix>
python scripts/download_schemas.py --list          # schema sources; schemas are not read by the ETL
python scripts/sync_spec.py --check                # spec pin materialized and matching SPEC_VERSION
```

What the code does, as measured (not what the flags suggest):

- **13 downloads per run.** `UniversalDownloader.download()` fetches `cve`, `cwe`,
  `cpe`, `cpematch`, `capec`, `attck`, `car`, `engage`, `d3fend`, `shield`, `kev`,
  `epss`, `atlas` every time. `--standard` is parsed and logged ("for information
  purposes") but does not narrow the download; `cvss` is accepted by the flag
  and has no download of its own (the scores are inside the CVE files).
- **Directories written:** `CVE/`, `CWE/`, `CPE/` (+ `nvdcpe-2.0-chunks/`),
  `CPE-MATCH/` (+ `nvdcpematch-2.0-chunks/`), `CAPEC/`, `ATTCK-STIX/`, `car/`,
  `ENGAGE/`, `SHIELD/`, `D3FEND/`, `KEV/`, `EPSS/`, `ATLAS/`.
- **Soft success.** The downloader reports success when at least 7 of the 13 sources
  download, and `validate()` only checks that a source's directory has files
  (also with a threshold of 7); `download.py` exits 0 unless an exception escapes.
  A partial or stale `data/raw` therefore passes: the gate is the per-source date
  check in `fresh-load.md`, step 0.
- It overwrites but never cleans, so start from an empty `data/raw`.
- **ATLAS** is the pinned release `APIEndpoints.atlas_release` (`ATLAS-<release>.yaml`,
  not `ATLAS-latest.yaml`); **EPSS** is saved as `epss_scores-<score date>.csv.gz`.
  ATLAS, EPSS and KEV also run on their own: `python -m downloaders.mitre_atlas`,
  `python -m downloaders.first_epss`, `python -m downloaders.cisa_kev`.
- **Source owners:** NIST (NVD: CVE, CVSS, CPE, CPE-MATCH; SSVC decisions are
  read from the NVD CVE files), MITRE (CWE, CAPEC, ATT&CK, D3FEND, CAR, ENGAGE,
  SHIELD, ATLAS), CISA (KEV), FIRST (EPSS).

---

## Validation

Every script below only reads from Neo4j. Run them in
the same session that loaded the database, with `NEO4J_DATABASE` set, and check the
`Neo4jWriter connected ... (database=...)` log line.

| Script | Needs Neo4j | What it checks | Exit 1 when |
|---|---|---|---|
| `validation/validate_all_standards.py` | SHACL: no; `--post-load`: yes | SHACL of the pinned shapes in `spec/shapes/` (the 10 chain standards plus `core.shacl.ttl` invariants), then the post-load Cypher checks | any violation |
| `validation/expected_v12_deltas.py` | only with `--compare-neo4j` | offline expected nodes and edges of KEV, EPSS, SSVC and ATLAS from `data/raw`; with `--compare-neo4j`, the same read from the graph | any difference (compare mode) |
| `validation/expected_graph_deltas.py` | no | offline expected edge counts (`PART_OF`, `SUBTECHNIQUE_OF`, `IMPLEMENTS`, `MITIGATED_BY`, `CAUSED_BY`, `DEMONSTRATED_BY`, `CHILD_OF`) in two modes, v1.0 (pre-fix rules) and v1.1 (fixed loaders) | `--check-v10` and v1.0 ≠ the kgcs-demo counts |
| `validation/check_graph_quality.py` | yes | live edge counts against an `expected-graph.json`, and that no `IMPLEMENTS` / `MITIGATED_BY` endpoint carries a revoked or deprecated ATT&CK id | any check fails |
| `validation/shacl_export_check.py` | default yes; `--from-raw` no | SHACL on an RDF export of `Weakness`, `AttackPattern`, `Consequence`, `BuildMetadata` against `cwe`, `capec`, `core` and `build` shapes | export does not conform |
| `validation/shacl_export_v12.py` | default yes; `--from-raw` no | SHACL on an export of the decision leaves and the ATLAS module against `decision.shacl.ttl` and `atlas.shacl.ttl` (`--limit` samples the decision labels, default 500; ATLAS always whole) | export does not conform |
| `validation/extract_neo4j_stats.py` | yes | label and relationship counts, freshness, minimums (see [Graph Statistics](#graph-statistics)) | `--check-minimums` below a floor |
| `pytest tests` | no | transform logic of every loader, the build metadata, the SHACL exports; pure Python | any failure |

### SHACL + Post-Load Checks

`validation/validate_all_standards.py` runs pySHACL for the ten standards
(`cpe`, `cve`, `cvss`, `cwe`, `capec`, `attck`, `d3fend`, `car`, `shield`,
`engage`) plus `core invariants`, and optionally the Cypher post-load checks.

```powershell
# Validate all SHACL shapes against the pinned spec
python validation/validate_all_standards.py

# Validate a single standard only
python validation/validate_all_standards.py --standard attck

# Run post-load Cypher integrity checks (requires Neo4j connection)
python validation/validate_all_standards.py --post-load

# Skip SHACL; run post-load checks only
python validation/validate_all_standards.py --skip-shacl --post-load

# Development / partial loads (--step) only: tolerate a missing BuildMetadata node
python validation/validate_all_standards.py --skip-shacl --post-load --partial-load
```

Other options: `--shapes-dir` (default `spec/shapes`), `--owl-dir` (default
`spec/ontology`), `--log-level`.

**`--partial-load` rule.** A full load has exactly one `BuildMetadata` node.
Without the flag, 0 nodes fails (known causes: a graph loaded by a pipeline older
than spec 1.1, or a partial load with `--step`). With the flag, 0 nodes is a
warning and the report says why. More than one node always fails. Q7 and any
pre-release validation run **without** `--partial-load`; the flag exists only for
development and partial loads.

### Post-Load Integrity Checks

`--post-load` first checks that every uniqueness constraint of
`init_constraints.UNIQUE_CONSTRAINTS` exists (`constraints_present`; 27 in the
2026-11-01 log), then runs the 35 named Cypher assertions of `_POST_LOAD_CHECKS`;
each must return 0 to pass. The 2026-11-01 log shows 34 of the 35 passing; the
red one, `cwe_consequence_vocabulary`, is CWE 5.0 data outside the spec 1.2.1 vocabulary.

| Group | Check names | Invariant enforced |
|---|---|---|
| ATT&CK | `subtech_cardinality`, `technique_in_tactic`, `part_of_domain_coherence` | every SubTechnique has exactly one `SUBTECHNIQUE_OF` parent (SH-CORE-07); every Technique has a `PART_OF` Tactic (SH-CORE-06); each `PART_OF` tactic's domains are among the technique's |
| CVE / CPE / CVSS | `no_direct_platform_affects`, `no_duplicate_cvss_per_cve`, `affects_backed_by_applicability`, `expanded_criteria_have_platform_targets`, `configuration_nodes_have_parent` | no `Vulnerability`→`AFFECTS`→`Platform` (SH-CORE-01); one Score per CVE and version; every `AFFECTS` edge backed by a non-negated vulnerable applicability leaf; criteria resolve to canonical platforms; every configuration node has one parent |
| Chain integrity | `no_cve_to_attck_shortcut`, `no_platform_shortcut`, `no_cwe_to_attck_shortcut`, `caused_by_provenance_aligned` | no shortcut edges across the chain; `CAUSED_BY` provenance lists non-empty and index-aligned (ADR-0002) |
| CWE / CAPEC enrichment | `weakness_required_enrichment`, `consequence_one_parent`, `consequence_is_leaf`, `consequence_key_matches_parent`, `consequence_ordinals_contiguous`, `consequence_scopes_present`, `cwe_consequence_impacts_present`, `cwe_consequence_vocabulary`, `capec_consequence_vocabulary` | spec 1.1.0 enrichment and `Consequence` sub-node rules (ADR-0001), per-standard vocabularies never merged |
| Decision extension | `decision_leaf_adherence`, `decision_no_chain_edges`, `kev_one_per_vulnerability`, `epss_one_per_cve_date`, `epss_values`, `ssvc_values` | leaves have exactly one incoming `has_*` edge from their `Vulnerability`; nothing leaves a leaf; value ranges and key formats |
| ATLAS | `atlas_boundary`, `atlas_no_attck_hierarchy_types`, `adapted_from_targets`, `adapted_from_provenance`, `adapted_from_at_most_one`, `atlas_technique_achieves`, `atlas_subtechnique_specializes`, `atlas_mitigation_mitigates` | only outgoing `ADAPTED_FROM` crosses into ATT&CK; ATLAS never uses `PART_OF` / `SUBTECHNIQUE_OF`; edge provenance and cardinalities |
| Build | `build_metadata_singleton` | exactly one `BuildMetadata` node (see `--partial-load`) |

### Offline expected counts and the graph-quality gate

The comparison target is computed from `data/raw` with the loaders' own
transform functions, before the graph exists:

```powershell
python validation\expected_v12_deltas.py --json <run-dir>\expected-v12.json 2>&1 | Out-File -Encoding utf8 <run-dir>\expected-v12.md
python validation\expected_v12_deltas.py --skip-cve                  # no ~3 GB NVD scan; KEV/EPSS/SSVC not computed
python validation\expected_v12_deltas.py --compare-neo4j --skip-cve  # read the graph, exit 1 on any difference

python validation\expected_graph_deltas.py --skip-cve --json <run-dir>\expected-graph.json
python validation\check_graph_quality.py --expected <run-dir>\expected-graph.json
python validation\check_graph_quality.py --expected <run-dir>\expected-graph.json --edges PART_OF,CHILD_OF
```

`check_graph_quality.py` defaults to `--edges PART_OF,IMPLEMENTS,MITIGATED_BY,CHILD_OF`
and `--raw-data-dir data/raw`; with the four edges it makes 6 checks (4 counts,
2 bridge-endpoint checks), the "6/6" of the 2026-11-01 run. An expected file
older than the raw data fails on purpose when a feed moved (that run: `PART_OF`
441 against the 2026-09 file's 436, the October ATT&CK release).

### SHACL on exports

```powershell
# Weakness / AttackPattern / Consequence / BuildMetadata
python validation\shacl_export_check.py                     # from NEO4J_DATABASE, read-only
python validation\shacl_export_check.py --from-raw data/raw # loader transforms, no Neo4j

# KevEntry / EpssScore / SsvcDecision and the ATLAS module
python validation\shacl_export_v12.py --limit 500
python validation\shacl_export_v12.py --from-raw data/raw --limit 500
```

Both take `--shapes-dir` (default `spec/shapes`) and `--ttl-out` to keep the
export as Turtle; `shacl_export_check.py` also takes `--limit`.

---

## Graph Statistics

`validation/extract_neo4j_stats.py` queries node/relationship counts and freshness dates.

```powershell
# Pretty-printed table (requires rich library)
python validation/extract_neo4j_stats.py --pretty

# JSON output (for CI/CD parsing)
python validation/extract_neo4j_stats.py --json

# Exit 1 if any label count falls below the expected minimum
python validation/extract_neo4j_stats.py --check-minimums
```

It counts 23 node labels (`NODE_LABELS`) and 21 relationship types
(`REL_TYPES`). **Known gap:** the lists are fixed and omit the labels
`VulnerabilityConfiguration` and `VulnerabilityConfigurationNode` and the types
`CHILD_OF`, `HAS_CONFIGURATION`, `HAS_NODE` and `MATCHES_CRITERIA`
(finding h of `docs/analysis/etl-coverage-2026-11.md`); the 2026-11-01 graph has
25 labels and 25 types. Reconcile total nodes with
`MATCH (n) RETURN labels(n)[0] AS l, count(*)` and the counters in `etl.log`.

### Expected Minimums

`EXPECTED_MINIMUMS` has 14 floors; `--check-minimums` exits 1 if any label is
below its floor.

| Label | Minimum | | Label | Minimum |
|---|---|---|---|---|
| Vulnerability | 250,000 | | KevEntry | 1,500 |
| Platform | 50,000 | | EpssScore | 300,000 |
| AttackPattern | 500 | | SsvcDecision | 150,000 |
| Technique | 350 | | AtlasTactic | 14 |
| SubTechnique | 400 | | AtlasTechnique | 100 |
| Tactic | 14 | | AtlasSubTechnique | 70 |
| Weakness | 900 | | AtlasMitigation | 30 |

### Counters of the last validated run

From `docs/fresh-load/runs/2026-11-01-kgcs-2026-11/summary.json` (`etl.log`
counters; minutes are step durations, 109 in all):

| Step | Nodes | Relationships | Minutes |
|---|---|---|---|
| constraints | — | — | 0.1 |
| cpe | 2,538,896 | 31,775,150 | 71 |
| cve | 3,339,362 | 9,281,356 | 28 |
| cvss | 566,912 | 566,912 | 3.6 |
| kev | 1,765 | 1,765 | — |
| epss | 398,784 | 398,784 | — |
| ssvc | 210,258 | 210,258 | — |
| cwe | 984 (+1,278 consequences) | 362,316 | 2.9 |
| capec | 615 | 2,559 | — |
| attck | 974 | 1,237 | — |
| atlas | 264 | 718 | — |
| d3fend | 145 | 3,087 | — |
| car | 102 | 278 | — |
| shield | 33 | 255 | — |
| engage | 45 | 593 | — |
| build_metadata | 1 | — | — |

The graph held 7,061,232 nodes, reconciled with the sum of the step counters.
A `—` in the minutes column means the run did not record that step on its own
in `summary.json`.

---

## Smoke Test (Log4Shell)

After a full pipeline run, verify the end-to-end causal chain in Neo4j Browser:

```cypher
MATCH (pc:PlatformConfiguration)<-[:AFFECTS]-(v:Vulnerability {cveId:'CVE-2021-44228'})
-[:CAUSED_BY]->(w:Weakness)
-[:DEMONSTRATED_BY]->(ap:AttackPattern)
-[:IMPLEMENTS]->(t:Technique)
RETURN v.cveId, w.cweId, ap.capecId, t.attackId
```

This must return at least one row. A zero-result response indicates a failure in one of the CPE, CVE, CWE, CAPEC, or ATT&CK steps.

---

## Loader Mapping Note (Systems Standards Namespaces)

*Written against the 1.0 layout; the term names below still exist in the pinned
`spec/ontology/`. The authoritative contracts are the mappings in `spec/mappings/`
(`<standard>-to-owl-v1.0.md`, `mapping-coverage-matrix-v1.2.md`); this table is
the systems-agent compatibility view only.*

Use this mapping during ETL/Neo4j load so graph artifacts stay aligned with the standards OWLs under `spec/ontology/standards/`.

| Graph Artifact | Ontology Term | Notes |
| --- | --- | --- |
| `(:Vulnerability)-[:AFFECTS]->(:PlatformConfiguration)` | `cve:affects` (inverse of `kgcs:affected_by`) | Systems-agent compatibility projection over vulnerable applicability leaves |
| `(:Vulnerability)-[:HAS_SCORE]->(:Score)` | `cvss:hasScore` (subPropertyOf `kgcs:scored_by`) | Keep CVSS versioned score nodes |
| `(:Vulnerability)-[:REFERENCES]->(:Reference)` | `cve:references` (subPropertyOf `kgcs:references`) | Preserve reference provenance |
| `Platform.cpeUri` | `cpe:cpeUri` | Canonical CPE URI |
| `PlatformConfiguration.cpeUri` | `cpe:cpeUri` | Optional compatibility/derived field; `criteria` + `MATCHES_PLATFORM` remain authoritative |
| `Platform.cpeNameId` | `cpe:cpeNameId` | NVD CPE name identifier |
| `Platform.part` / `vendor` / `product` / `version` | `cpe:part` / `cpe:vendor` / `cpe:product` / `cpe:version` | CPE identity decomposition fields |
| `PlatformConfiguration.matchCriteriaId` | `cpe:matchCriteriaId` | NVD criteria identity |
| `PlatformConfiguration.criteria` | `cpe:criteria` | Raw NVD CPE criteria expression |
| `(:PlatformConfiguration)-[:MATCHES_PLATFORM]->(:Platform)` | `cpe:matchesPlatform` | Structural join expansion via CPE Match `matches[]` |
| `PlatformConfiguration.configStatus` | `cpe:configStatus` | Vulnerable/fixed/unknown status |
| `PlatformConfiguration.vulnerable` | `cpe:vulnerable` | CVE cpeMatch applicability flag |
| `PlatformConfiguration.versionStartIncluding` / `versionStartExcluding` | `cpe:versionStartIncluding` / `cpe:versionStartExcluding` | Lower version bounds |
| `PlatformConfiguration.versionEndIncluding` / `versionEndExcluding` | `cpe:versionEndIncluding` / `cpe:versionEndExcluding` | Upper version bounds |
| `PlatformConfiguration.created` / `lastModified` / `cpeLastModified` | `cpe:created` / `cpe:lastModified` / `cpe:cpeLastModified` | CPE Match lifecycle timestamps |
| `Vulnerability.cveId` | `cve:cveId` | Canonical CVE identifier |
| `Vulnerability.published` / `Vulnerability.lastModified` | `cve:published` / `cve:lastModified` | Authoritative CVE timestamps |
| `Weakness.cweId` / `Weakness.abstraction` | `cwe:cweId` / `cwe:abstraction` | Root-cause metadata used by systems views |
| `Score.scoreId` / `Score.version` / `Score.baseScore` | `cvss:scoreId` / `cvss:version` / `cvss:baseScore` | CVSS identity and numeric severity |

Core causality terms remain unchanged (`kgcs:caused_by`, `kgcs:exploited_by`, `kgcs:implemented_as`).

## OWL Imports Checklist (Systems-Focused Loader)

Load modules in this order for systems-agent-aligned graph generation (paths
inside the materialized `spec/`):

1. `ontology/core/core-ontology-v1.0.owl` — authoritative frozen backbone (`kgcs:`).
2. `ontology/standards/cpe-ontology-v1.0.owl` — platform/config identifiers and status fields (`cpe:`).
3. `ontology/standards/cve-ontology-v1.0.owl` — vulnerability identifiers/metadata and compatibility predicates (`cve:`).
4. `ontology/standards/cwe-ontology-v1.0.owl` — weakness identifiers and abstraction fields (`cwe:`).
5. `ontology/standards/cvss-ontology-v1.0.owl` — score class alias, score predicates, and CVSS fields (`cvss:`).
6. `ontology/extensions/asset-extension-v1.0.owl` — organizational asset context layered on top of standards/core (`asset:`).

Guardrails:

* Do not modify `ontology/core/core-ontology-v1.0.owl` (and never hand-edit `spec/`: `sync_spec.py` rebuilds it).
* Keep standards semantics in `ontology/standards/`; keep organizational context in `ontology/extensions/`.
* Ensure loaded graph edges/properties follow the mapping table above.
