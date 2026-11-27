# Fresh load — procedure

How to rebuild the KGCS graph from scratch on a **new** Neo4j database, prove
the result and archive what was built, in gated steps 0 to 6. Every step fails
hard before the next one starts; "it ran" is never the acceptance criterion.
Each run leaves its evidence in `docs/fresh-load/runs/<date>-<database>/` (see
[`fresh-load/README.md`](fresh-load/README.md)), so two builds months apart
can be compared line by line.

Commands are PowerShell, run from the repo root with the repo's Python
(`.\.conda\python.exe` here; `python` elsewhere). `pipeline-execution-guide.md`
documents each script's options; this page is the order and the gates.
Placeholders: `<run-dir>` is `docs\fresh-load\runs\<date>-<database>`;
`<archive-root>` is a folder you choose, outside the repository, that outlives
the machine's working data (step 6).

## Step 0 — Preflight and fresh raw data

Why: the feeds are rolling (`*_latest`, yearly NVD files) and the downloader
**overwrites but never cleans** `data/raw/`. A stale file from a previous run
passes the download validation (it only checks "directory has files"), and a
second `cwec_v*.xml` or an extra chunk directory is silently picked up by the
loaders.

The previous build is already archived: its step 6 copied its `data/raw`,
`data/schemas` and run directory to `<archive-root>\standards\<previous-YYYYMMDD>\`
with a `manifest.csv`. Start from that fact, check it, then start empty:

```powershell
git status --short                       # clean tree, on the branch you mean to build from
python scripts/sync_spec.py --check              # spec pin materialized and matching SPEC_VERSION
python -m pytest tests -q                # all green

# The previous build must already be archived (step 6 of its run); never delete data\raw before
$previous = '<archive-root>\standards\<previous-YYYYMMDD>'
Test-Path "$previous\manifest.csv"       # must print True; if False, do step 6 of the previous build first

Remove-Item data\raw -Recurse -Force
New-Item -ItemType Directory data\raw | Out-Null
python scripts/download.py --standard all 2>&1 | Out-File -Encoding utf8 <run-dir>\download.log
if ($LASTEXITCODE -ne 0) { throw "download.py failed (exit $LASTEXITCODE): failed sources are named in download.log" }
python scripts/download_schemas.py       # so the schemas archived in step 6 are this build's own
```

Gate — `download.py` must have exited 0 (the `throw` above stops the run otherwise).
The exit code does not detect stale files, so also check that every standard has files dated today, and
exactly one CWE and one CAPEC catalog:

```powershell
Get-ChildItem data\raw -Directory | ForEach-Object {
  $f = Get-ChildItem $_.FullName -Recurse -File | Sort-Object LastWriteTime | Select-Object -Last 1
  "{0,-12} {1:yyyy-MM-dd HH:mm}  {2,5} files" -f $_.Name, $f.LastWriteTime, (Get-ChildItem $_.FullName -Recurse -File).Count
}
Get-ChildItem data\raw\CWE, data\raw\CAPEC -File | Select-Object Name, Length
```

Then **diff the feed versions against the previous snapshot** (the archived
`raw\` of the previous build) before loading anything (repo rule: verify
external schemas from the downloaded files). At
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

Size the server's memory before loading. With the stock configuration of a
desktop installation (heap 1 GiB, page cache 512 MiB) the load completes, but
the relationship phases slow down once the store outgrows the page cache: on
2026-11-01 the `MATCHES_PLATFORM` rate halved from about file 13 of 74 and
stayed there. The same inputs and the same loaders took 109 min with
1 GiB / 512 MiB and five other databases online (2026-11-01), and 70 min with
8 GiB / 12 GiB and those databases stopped (2026-11-27, run
`2026-11-27-kgcs-2026-11-rc`, a workstation with 64 GB of RAM). The two changes
were made together; which one matters is not separated. In `neo4j.conf`, replace
the existing lines (do not add duplicates) and restart the server:

```
server.memory.heap.initial_size=8g
server.memory.heap.max_size=8g
server.memory.pagecache.size=12g
```

The page cache should hold at least the store being loaded (4.5 GB on disk for
this graph). Stop the databases the load does not need (`STOP DATABASE`;
`START DATABASE` brings them back), and write down what the server itself
reports, for the run's `summary.json`:

```cypher
CALL dbms.components() YIELD name, versions, edition RETURN name, versions, edition;
SHOW SETTINGS YIELD name, value WHERE name STARTS WITH 'server.memory' RETURN name, value;
```

The load is serial: during the relationship phases one server thread does most
of the work (about 0.8 core for the server and 0.3 for the Python client,
2026-11-27), so more cores, a higher process priority or closing other programs
do not shorten it. It is sensitive to that one core being disturbed, though: in
the 2026-11-27 build the relationship rate was 0.69 min per file while the
workstation was in interactive use and 0.42 once it was left alone (one
observation, mechanism not measured). Leave the machine alone during the load.

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
python scripts/run_all_etl.py --dry-run          # lists every step (it does not print the target database)
python scripts/run_all_etl.py 2>&1 | Out-File -Encoding utf8 <run-dir>\etl.log
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
`README.md`. The report (step 5) reads them, so use their conventions: the
keys of the schema in [`fresh-load/README.md`](fresh-load/README.md), and in
`README.md` the headings `## Findings` (paragraphs that start
`**F1 — title.**`), `## Sample` (a numbered list) and `## Not verified` (a
bullet list).

## Step 5 — Report

Why: the human-readable record must come from the machine-comparable one, or the
two drift. `scripts/build_run_report.py` reads `<run-dir>\summary.json` (every
figure) and `<run-dir>\README.md` (findings, sample, not verified) and writes
`<run-dir>\report.html`: one self-contained file, no web font, no CDN, no
network request. It invents nothing and computes nothing; with `--compare-siblings`
it puts the figures of every earlier run in the same `runs\` folder beside this one.

```powershell
python scripts\build_run_report.py <run-dir> --compare-siblings
```

Gate — exit 0 and `report.html` written. The script fails hard and writes nothing
(an existing `report.html` stays as it was) when the run directory or
`summary.json` is missing, `summary.json` is not valid JSON or lacks a required
key, or a comparison file cannot be read; the message names the key. Open the
file and read it next to `README.md`. `python -m pytest tests\test_build_run_report.py -q`
also fails when a committed `report.html` is not what the script generates from
its `summary.json`.

## Step 6 — Archive the inputs and the evidence

Why: the build can only be reproduced or audited if the exact files it read
still exist, and the next build deletes `data\raw` (step 0). Copy `data\raw`,
`data\schemas` and the run directory (with its `report.html`) to
`<archive-root>\standards\<YYYYMMDD>\` (the run's date, one folder per build,
never overwritten), with a manifest of SHA-256 hashes, and verify the copy
file by file. `<archive-root>` is a parameter: any folder outside the repository
on storage you keep. The manifest is also the "listing of every `data/raw` file
(path, size, mtime, sha256)" that `BuildMetadata` snapshots such as
`download:<file date>` rely on.

```powershell
$archiveRoot = '<archive-root>'
$day  = '<YYYYMMDD>'                                   # the run's date
$run  = '<run-dir>'
$dest = Join-Path $archiveRoot "standards\$day"
$src  = [ordered]@{ raw = 'data\raw'; schemas = 'data\schemas'; run = $run }

if (Test-Path $dest) { throw "$dest exists: an archive is never overwritten" }
$src.Values | ForEach-Object { if (-not (Test-Path $_)) { throw "missing source: $_" } }
New-Item -ItemType Directory $dest | Out-Null
```

Manifest of the sources (SHA-256, size, UTC modification time; paths relative to
`$dest`, forward slashes):

```powershell
$rows = foreach ($key in $src.Keys) {
  $base = (Resolve-Path $src[$key]).Path
  Get-ChildItem $base -Recurse -File | ForEach-Object {
    [pscustomobject]@{
      sha256       = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
      size         = $_.Length
      lastWriteUtc = $_.LastWriteTimeUtc.ToString('o')
      path         = "$key/" + $_.FullName.Substring($base.Length + 1).Replace('\', '/')
    }
  }
}
$rows | Export-Csv -LiteralPath "$dest\manifest.csv" -NoTypeInformation -Encoding utf8
"{0} files in the manifest" -f @($rows).Count
```

Copy (robocopy keeps file times; exit codes 0 to 7 are success):

```powershell
foreach ($key in $src.Keys) {
  robocopy $src[$key] (Join-Path $dest $key) /E /COPY:DAT /DCOPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
  if ($LASTEXITCODE -ge 8) { throw "robocopy failed for $($src[$key]): exit code $LASTEXITCODE" }
}
```

Verify the copy against the manifest (hash and modification time of every
listed file, and no file in the copy that is not listed):

```powershell
$listed = Import-Csv -LiteralPath "$dest\manifest.csv"
$bad = foreach ($r in $listed) {
  $f = Join-Path $dest ($r.path -replace '/', '\')
  if (-not (Test-Path -LiteralPath $f)) { "MISSING  $($r.path)"; continue }
  $item = Get-Item -LiteralPath $f
  if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne $r.sha256) { "DIFFERS  $($r.path)" }
  elseif ($item.LastWriteTimeUtc.ToString('o') -ne $r.lastWriteUtc) { "MTIME    $($r.path)" }
}
$top = (Resolve-Path $dest).Path
$copied = @(Get-ChildItem $dest -Recurse -File | Where-Object { $_.Name -ne 'manifest.csv' -or $_.DirectoryName -ne $top }).Count
if ($bad -or $copied -ne @($listed).Count) { $bad; throw "archive verification failed: $copied files copied, $(@($listed).Count) in the manifest" }
"archive verified: {0} files, {1}" -f $copied, "$dest\manifest.csv"
```

Gate — the last line reads `archive verified`, with the same file count as the
manifest. Only then is the next build allowed to empty `data\raw` (its step 0).
The archive holds the raw data and is not committed; what is committed is the
run directory (`gitleaks detect --source docs\fresh-load`, then commit it), and
no archive path is written into the repository.
