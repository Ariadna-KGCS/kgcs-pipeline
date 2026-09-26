# Pipeline Execution Guide

Authoritative steps for download → ETL → SHACL → Neo4j load.

## Prerequisites

Set Neo4j connection credentials as environment variables before running any pipeline script:

```powershell
# Windows PowerShell
$env:NEO4J_URI      = "bolt://localhost:7687"
$env:NEO4J_USER     = "neo4j"
$env:NEO4J_PASSWORD = "yourpassword"
```

```bash
# Linux / macOS
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=yourpassword
```

Raw data must already be downloaded to `data/raw/`. If not, run the downloader scripts first (see `downloaders/`).

---

## ETL Pipeline Orchestrator

`scripts/run_all_etl.py` runs all 11 ETL steps in strict causal-chain order and exits 1 on the first failure.

```powershell
# Run the full pipeline (recommended on first load or after re-downloading)
python scripts/run_all_etl.py

# Run with a non-default data directory
python scripts/run_all_etl.py --raw-data-dir D:\data\raw

# Preview what would run without connecting to Neo4j
python scripts/run_all_etl.py --dry-run

# Re-run a single step (skip constraints if already applied)
python scripts/run_all_etl.py --step cve --skip-constraints

# Verbose debug output
python scripts/run_all_etl.py --log-level DEBUG
```

### Parameters

| Flag | Default | Description |
|---|---|---|
| `--raw-data-dir PATH` | `data/raw` | Base directory for downloaded raw data |
| `--batch-size INT` | `1000` | Neo4j transaction batch size (rows per UNWIND) |
| `--step NAME` | _(all)_ | Run only one named step; see step registry below |
| `--dry-run` | false | Print step order without touching Neo4j |
| `--skip-constraints` | false | Skip the `constraints` step (it is idempotent but slow) |
| `--log-level LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

### Step Registry

Steps execute in this exact order. Each step requires all prior steps to have succeeded (hard stop on first failure).

| Order | Step name | Loader | Creates |
|---|---|---|---|
| 0 | `constraints` | `init_constraints.run_constraints()` | 14 unique constraints + 3 lookup indexes |
| 1 | `cpe` | `CPELoader` | Platform, PlatformConfiguration; MATCHES_PLATFORM |
| 2 | `cve` | `CVELoader` | Vulnerability, Reference; AFFECTS, REFERENCES |
| 3 | `cvss` | `CVSSLoader` | Score; HAS_SCORE |
| 4 | `cwe` | `CWELoader` | Weakness (+ spec 1.1 enrichment), Consequence; CAUSED_BY, HAS_CONSEQUENCE |
| 5 | `capec` | `CAPECLoader` | AttackPattern, Consequence; DEMONSTRATED_BY, CHILD_OF, HAS_CONSEQUENCE |
| 6 | `attck` | `ATTCKLoader` | Technique, SubTechnique, Tactic; PART_OF, SUBTECHNIQUE_OF |
| 7 | `d3fend` | `D3FENDLoader` | DefensiveTechnique; MITIGATED_BY |
| 8 | `car` | `CARLoader` | DetectionAnalytic; DETECTED_BY |
| 9 | `shield` | `SHIELDLoader` | DeceptionTechnique; COUNTERED_BY |
| 10 | `engage` | `ENGAGELoader` | EngagementConcept; DISRUPTS |
| 11 | `build_metadata` | `build_metadata.run_build_metadata()` | the single BuildMetadata node (postscript, no edges) |

### Build Metadata (spec 1.1.0)

The last step writes one `BuildMetadata` node: `specVersion` (`SPEC_VERSION`),
`buildTimestamp` (UTC completion instant), `pipelineCommit` (`git rev-parse HEAD`)
and `sourceSnapshots`, one `<SOURCE>=<snapshot>` per standard, read from the same
raw files the loaders read. Preview it offline with `python -m etl.build_metadata`.

Rule: the release when the source states one; dates or ranges only when it has none.

| SOURCE | Snapshot | 2026-09-06 raw data |
|---|---|---|
| CWE, CAPEC | catalog `Version` attribute (the catalog `Date` is only logged) | `CWE=4.20`, `CAPEC=3.9` |
| D3FEND | `owl:versionInfo` of `d3fend.json` | `D3FEND=1.3.0` |
| ATTCK | the `x-mitre-collection` `x_mitre_version` if all three bundles carry the same one, else `download:<file date>;modified-max:<max modified>` | `ATTCK=download:2026-09-06;modified-max:2026-08-04` |
| CVE, CVSS | NVD feed `timestamp` of the CVE files: one value when all files agree, else `<min>..<max>` (UTC, seconds, `Z`) | `CVE=2026-08-28T03:03:23Z..2026-09-06T08:00:03Z` |
| CPE | same rule over the CPE and CPE-MATCH chunks together | `CPE=2026-09-05T23:40:00Z..2026-09-05T23:52:08Z` |
| CAR, SHIELD, ENGAGE | no release in the files: `download:<file date>` | `CAR=download:2026-09-06` |

The range matters: the yearly CVE feeds lag the modified feed by up to nine days,
so the max alone would overstate freshness. "File date" is the UTC date of the
newest file mtime; the downloader records nothing else, so a validated load keeps
a listing of every `data/raw` file (path, size, mtime, sha256) as the evidence.

---

## Validation

### SHACL + Post-Load Checks

`validation/validate_all_standards.py` runs pySHACL against OWL ontology files and optionally runs Cypher post-load integrity checks.

```powershell
# Validate all SHACL shapes against OWL ontology files
python validation/validate_all_standards.py

# Validate a single standard only
python validation/validate_all_standards.py --standard attck

# Run post-load Cypher integrity checks (requires Neo4j connection)
python validation/validate_all_standards.py --post-load

# Skip SHACL; run post-load checks only
python validation/validate_all_standards.py --skip-shacl --post-load

# Development / partial loads (--step) only: tolerate a missing BuildMetadata node
python validation/validate_all_standards.py --skip-shacl --post-load --partial-load

# SHACL on an export of Weakness / AttackPattern / Consequence / BuildMetadata
python validation/shacl_export_check.py                     # from NEO4J_DATABASE, read-only
python validation/shacl_export_check.py --from-raw data/raw # loader transforms, no Neo4j
```

**`--partial-load` rule.** A full load has exactly one `BuildMetadata` node.
Without the flag, 0 nodes fails (known causes: a graph loaded by a pipeline older
than spec 1.1, or a partial load with `--step`). With the flag, 0 nodes is a
warning and the report says why. More than one node always fails. Q7 and any
pre-release validation run **without** `--partial-load`; the flag exists only for
development and partial loads.

### Post-Load Integrity Checks

The `--post-load` mode runs Cypher assertions; each must return 0 to pass. The
full list is `_POST_LOAD_CHECKS` in `validation/validate_all_standards.py`; spec 1.1.0
adds `weakness_required_enrichment`, the `consequence_*` checks (one parent, leaf,
key, contiguous ordinals, scopes/impacts present, per-standard vocabularies) and
`build_metadata_singleton`. The original four:

| Check name | Invariant enforced |
|---|---|
| `subtech_cardinality` | Every SubTechnique has exactly 1 SUBTECHNIQUE_OF parent (SH-CORE-07) |
| `no_direct_platform_affects` | No Vulnerability→AFFECTS→Platform edge; only PlatformConfiguration allowed (SH-CORE-01) |
| `technique_in_tactic` | Every Technique has at least one PART_OF→Tactic edge (SH-CORE-06) |
| `no_duplicate_cvss_per_cve` | No CVE has more than one Score of the same version |

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

### Expected Minimums

| Label | Minimum |
|---|---|
| Vulnerability | 250,000 |
| Platform | 50,000 |
| AttackPattern | 500 |
| Technique | 350 |
| SubTechnique | 400 |
| Tactic | 14 |
| Weakness | 900 |

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

Use this mapping during ETL/Neo4j load so graph artifacts stay aligned with standards OWLs under `standards/`.

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

Load modules in this order for systems-agent-aligned graph generation:

1. `core/core-ontology-v1.0.owl` — authoritative frozen backbone (`kgcs:`).
2. `standards/cpe/cpe-ontology-v1.0.owl` — platform/config identifiers and status fields (`cpe:`).
3. `standards/cve/cve-ontology-v1.0.owl` — vulnerability identifiers/metadata and compatibility predicates (`cve:`).
4. `standards/cwe/cwe-ontology-v1.0.owl` — weakness identifiers and abstraction fields (`cwe:`).
5. `standards/cvss/cvss-ontology-v1.0.owl` — score class alias, score predicates, and CVSS fields (`cvss:`).
6. `extensions/asset-extension-v1.0.owl` — organizational asset context layered on top of standards/core (`asset:`).

Guardrails:

* Do not modify `core/core-ontology-v1.0.owl`.
* Keep standards semantics in `standards/`; keep organizational context in `extensions/`.
* Ensure loaded graph edges/properties follow the mapping table above.
