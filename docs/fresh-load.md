# Fresh load — procedure

How to rebuild the KGCS graph from scratch on a **new** Neo4j database and
prove the result, in four gated steps. Every step fails hard before the next
one starts; "it ran" is never the acceptance criterion. Each run leaves its
evidence in `docs/fresh-load/runs/<date>-<database>/` (see
[`fresh-load/README.md`](fresh-load/README.md)), so two builds months apart
can be compared line by line.

Commands are PowerShell, run from the repo root with the repo's Python
(`.\.conda\python.exe` here; `python` elsewhere). `pipeline-execution-guide.md`
documents each script's options; this page is the order and the gates.

## Step 0 — Preflight and fresh raw data

Why: the feeds are rolling (`*_latest`, yearly NVD files) and the downloader
**overwrites but never cleans** `data/raw/`. A stale file from a previous run
passes the download validation (it only checks "directory has files"), and a
second `cwec_v*.xml` or an extra chunk directory is silently picked up by the
loaders.

```powershell
git status --short                       # clean tree, on the branch you mean to build from
python sync_spec.py --check              # spec pin materialized and matching SPEC_VERSION
python -m pytest tests -q                # all green

# Snapshot the previous raw data OUTSIDE the repo, then start empty
Move-Item data\raw <local-archive>\raw-<previous-date>
New-Item -ItemType Directory data\raw | Out-Null
python download.py --standard all 2>&1 | Out-File -Encoding utf8 <run-dir>\download.log
```

Gate — every standard has files dated today, and exactly one CWE and one
CAPEC catalog:

```powershell
Get-ChildItem data\raw -Directory | ForEach-Object {
  $f = Get-ChildItem $_.FullName -Recurse -File | Sort-Object LastWriteTime | Select-Object -Last 1
  "{0,-12} {1:yyyy-MM-dd HH:mm}  {2,5} files" -f $_.Name, $f.LastWriteTime, (Get-ChildItem $_.FullName -Recurse -File).Count
}
Get-ChildItem data\raw\CWE, data\raw\CAPEC -File | Select-Object Name, Length
```

Then **diff the feed versions against the previous snapshot** before loading
anything (repo rule: verify external schemas from the downloaded files). At
minimum: CWE catalog `Version=` and `xmlns`, CAPEC `Version=`, ATT&CK bundle
object counts, KEV `catalogVersion`/`count`, NVD 2026 `totalResults`, CPE and
CPE-MATCH chunk counts. A namespace or major-version change means reading the
loader before running it — CWE 5.0 (2026-10) moved from `cwe-7` to `cwe-8` and
would have loaded zero weaknesses with the previous `load_cwe.py`.

## Step 1 — Expected counts, offline

Why: the comparison target must exist *before* the graph does, computed from
the raw files by the loaders' own transform functions. Otherwise the only
check available afterwards is "looks plausible".

```powershell
python validation\expected_v12_deltas.py --json <run-dir>\expected-v12.json 2>&1 | Out-File -Encoding utf8 <run-dir>\expected-v12.md
```

Gate — the numbers are in the same order of magnitude as the previous run's
`expected-v12.json`, and any large move is explained by a feed change seen in
step 0 (e.g. KEV grows monotonically; ADAPTED_FROM drops only if ATT&CK retired
a technique ATLAS references).

## Step 2 — ETL into a new database

Why a new database: `MERGE` is idempotent for what exists, but entries retired
upstream are never deleted, so reloading over an old database cannot give a
clean delta. The previous database stays as the reference it already is.

In Neo4j (database `system`): ``CREATE DATABASE `<database>` IF NOT EXISTS;``

Before launching, make sure **no other loader is alive**: a PowerShell pipeline
whose `Tee-Object`/`Out-File` fails still starts `python.exe`, and Ctrl+C on a
pipeline does not reliably kill it. A survivor keeps writing after
`DROP`/`CREATE DATABASE` (the driver retries transient errors) and shows up as
`DeadlockDetected` retries and `clientId` pairs in the log (2026-11-01, F5).

```powershell
Get-Process python* | Where-Object Path -like "*kgcs-pipeline*"   # must be empty
```

Write logs with `Out-File -Encoding utf8` (PowerShell 5.1's `Tee-Object` uses
the system code page) and follow them from a second window with
`Get-Content <run-dir>\etl.log -Wait -Tail 5`. Set
`[Console]::OutputEncoding = [System.Text.Encoding]::UTF8` for the ✓/— glyphs.

```powershell
$env:NEO4J_DATABASE = '<database>'       # session only; .env keeps pointing at the reference db
python run_all_etl.py --dry-run          # lists every step and the target database
python run_all_etl.py 2>&1 | Out-File -Encoding utf8 <run-dir>\etl.log
```

Gate — last lines read `STEP N/N: build_metadata` and
`Pipeline complete — all steps succeeded.`; no `✗`, no `DOWN`. Keep the log at
INFO: `--log-level DEBUG` also enables the Neo4j driver's logger (a 6 GB Bolt
trace in the 2026-09-06 run).

## Step 3 — Post-load validation

Same PowerShell session (`$env:NEO4J_DATABASE` still set). All without
`--partial-load`: a full load has exactly one `BuildMetadata` node.

```powershell
python validation\validate_all_standards.py --post-load 2>&1 | Out-File -Encoding utf8 <run-dir>\postload.log
python validation\shacl_export_v12.py 2>&1 | Out-File -Encoding utf8 <run-dir>\shacl-v12.log
python validation\expected_v12_deltas.py --compare-neo4j --skip-cve 2>&1 | Out-File -Encoding utf8 <run-dir>\compare-v12.log
python validation\expected_graph_deltas.py --skip-cve --json <run-dir>\expected-graph.json
python validation\check_graph_quality.py --expected <run-dir>\expected-graph.json 2>&1 | Out-File -Encoding utf8 <run-dir>\graph-quality.log
python validation\extract_neo4j_stats.py --pretty --check-minimums 2>&1 | Out-File -Encoding utf8 <run-dir>\stats.log
python validation\extract_neo4j_stats.py --json > <run-dir>\stats.json
```

Gate — every script exits 0; `compare-v12` reports no difference against
step 1; stats minimums pass. Known gap: `extract_neo4j_stats.py` omits
`VulnerabilityConfiguration` / `VulnerabilityConfigurationNode`; reconcile
total nodes with `MATCH (n) RETURN labels(n)[0] AS l, count(*)` and the ETL
counters in `etl.log`.

## Step 4 — Sample, not just aggregates

Why: an aggregate that matches is not validation. Before signing off, read a
handful of individual records next to the evidence that produced them, on the
new database (via the read-only MCP connector or Neo4j Browser):

- one CVE published this month: CVSS 4.0 score present, KEV/EPSS/SSVC leaves
  attached, CWE reachable through `CAUSED_BY`;
- one weakness with consequences: `HAS_CONSEQUENCE` ordinals contiguous;
- one ATLAS technique: `ADAPTED_FROM` points at a live ATT&CK technique;
- one technique touched by the latest ATT&CK release: still `PART_OF` its
  tactic, sub-techniques intact;
- the single `BuildMetadata` node: source versions match step 0.

Write what was checked **and what was not** into the run's `summary.json` and
`README.md`. Then `gitleaks detect --source docs\fresh-load` and commit the run
directory.
