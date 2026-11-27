# Release check 2026-11-27 — `kgcs-2026-11-rc`

**Verdict: GREEN.** The code to be released (`9723057`, branch `devel`)
reloads the inputs of the 2026-11-01 build into an empty database and produces
the same graph count for count: 7,061,232 nodes in 25 labels, the 16 ETL step
counters, the same single post-load red. This is a check of the code, not a new
build: the 13 source snapshots are those of
[`2026-11-01-kgcs-2026-11`](../2026-11-01-kgcs-2026-11/README.md), read from
the same `data/raw` (273 files, 7,981,096,722 bytes, archived with a manifest).
Procedure: [`../../../fresh-load.md`](../../../fresh-load.md).

| | 2026-11-01 `kgcs-2026-11` | 2026-11-27 `kgcs-2026-11-rc` |
| --- | --- | --- |
| Pipeline commit / spec | `803dc01` / 1.2.1 | `9723057` / 1.2.1 |
| Source snapshots | 13 | the same 13 |
| Neo4j, as reported by the server | not recorded (noted as 2026.07.x) | 2026.09.0 enterprise |
| Server memory (heap max / page cache) | 1 GiB / 512 MiB | 8 GiB / 12 GiB |
| Other databases online in the instance | 5 | 0 |
| ETL duration | 109.3 min | **69.5 min** |
| `cpe` / `cve` step | 70.8 / 27.7 min | 47.3 / 13.9 min |
| Nodes / labels | 7,061,232 / 25 | 7,061,232 / 25 |
| `MATCHES_PLATFORM` | 31,775,150 | 31,775,150 |
| Post-load checks | 34/35 | 34/35, the same red |

## What ran

| Step | Gate | Result |
| --- | --- | --- |
| 0 Preflight | clean tree at `9723057`, spec pin in sync, no other loader, target database empty, server memory read from the server | PASS. No download into `data/raw`: the inputs are the archived ones |
| 1 Expected offline | — | not re-run (same inputs as 2026-11-01) |
| 2 ETL | 16/16, 0 deadlocks, 0 errors | PASS — `etl.log` (04:32 → 05:42), launched as `scripts/run_all_etl.py` |
| 3 Post-load | postload, shacl-v12, compare-v12, graph-quality, stats | 34/35 (F5) · CONFORMS, 1 known warning · EQUAL 8/8 · 6/6 · minimums 14/14 |
| 3b Reference build | `stats.json`, labels, relationship types, ETL counters, `BuildMetadata` against 2026-11-01 | EQUAL (F1) |
| 4 Sample | the 5 records of the 2026-11-01 sample, read on this database | 5/5 (below) |
| — Download test | `scripts/download.py --standard all --output-dir <scratch>` | 13/13 sources, exit code 0, 3.1 min; `data/raw` untouched (F4) |

## Findings

**F1 — the released code reproduces the 2026-11-01 build.** Between `803dc01`
and `9723057` no file under `etl/` or `validation/` changed; what changed is
the entry points (moved to `scripts/`) and the downloader. Equal to the
reference run: the 25 label counts, the 22 relationship types its summary
recorded, the 48 values of `stats.json`, the counters of the 16 ETL steps, the
11 loader warnings, and the 13 `sourceSnapshots` of `BuildMetadata` (read on
both databases). The only differences are `pipelineCommit`, `buildTimestamp`
and the absence of the "uncommitted changes" warning: the tree was clean.

**F2 — load time: 69.5 min against 109.3, with two things changed at once.**
The server ran with 8 GiB of heap and 12 GiB of page cache instead of the
stock 1 GiB / 512 MiB, and the five other databases of the instance were
stopped. On 2026-11-01 the `MATCHES_PLATFORM` rate started at about 0.5 min per
file and doubled from about file 13 of 74; here it stayed at about 0.47 min per
file to the end. That is what a store outgrowing a 512 MiB page cache looks
like, but the two changes were not separated, so the cause is narrowed, not
proven. This is the follow-up of F6 of the 2026-11-01 run. `docs/fresh-load.md`
step 2 now states the memory settings.

**F3 — the load is serial and bounded by one server thread.** Sampled over
about 10 s during `MATCHES_PLATFORM`: the Neo4j process used about 0.8 core and
the Python client about 0.3, on a machine that was 95 % idle. Raising the
process priority and closing other programs during the step changed nothing
measurable (0.46 to 0.47 min per file before and after). The node phases of
the `cpe` step were 16 to 29 % slower than on 2026-11-01; not explained.

**F4 — the entry points work from `scripts/` and the downloader reports all
13 sources.** `scripts/run_all_etl.py` and the validation scripts ran with the
repository's own interpreter from the repository root. `scripts/download.py`
wrote only under its `--output-dir`. Its log disagrees with its own summary in
three texts (`Validation: 12/12 standards`, `CPE: 19 files`, `CAR: 125 files`
against 13, 18 and 122 in the per-source table): wording, not results.

**F5 — `cwe_consequence_vocabulary` FAIL, 3 violations, unchanged.** The same
three values as F3 of the 2026-11-01 run (`DoS: Prevent Access` twice,
`Undefined Behavior` once). The fix belongs to the spec vocabulary.

**F6 — the server version was never read from the server before.** The
2026-11-01 summary says `2026.07.x`, taken from the instance's label; the
server reported `2026.09.0` on 2026-11-27. Whether it was upgraded in between
is not known. The procedure now asks for `CALL dbms.components()` in the
evidence.

## Sample (step 4, read-only, via the MCP connector with `USE`)

1. **CVE-2026-114625** (published 2026-10-22): CVSS 3.1 (9.9) **and 4.0**
   (9.4); KEV added 2026-10-23 (catalog 2026.10.30); EPSS 2026-11-01, model
   v2026.06.15; SSVC `active / automatable=no / total`; `CAUSED_BY` → CWE-89
   with source role `cna`. Same as the 2026-11-01 sample.
2. **Consequences out of vocabulary**: CWE-1260-C1 and CWE-1476-C1 carry
   `DoS: Prevent Access`, CWE-1335-C2 carries `Undefined Behavior`; scopes and
   the other impacts read as loaded.
3. **ATT&CK October release**: T1696 (2 sub-techniques), T1697, T1698, T1699,
   T1700 in `enterprise`, T1476 in `mobile`, T1701 (6 sub-techniques) in `ics`,
   each `PART_OF` one tactic of its own domain; T0807 and T0853 are absent.
4. **ADAPTED_FROM warning**: AML.T0073 *Impersonation* → T1684.001, with
   `attackReferenceId` T1656 kept on the edge.
5. **BuildMetadata**: one node, spec 1.2.1, commit `9723057`, 13 source
   snapshots identical to those of `kgcs-2026-11` (`CWE=5.0`, `CAPEC=3.9`,
   `D3FEND=1.3.0`, `KEV=2026.10.30`, `EPSS=2026-11-01`, `ATLAS=2026.09`).

## Not verified

- Step 1 (expected counts offline, full CVE scan) was not re-run: the inputs are those of 2026-11-01; `compare-v12` ran with `--skip-cve`.
- Node-by-node equality with `kgcs-2026-11`: counts, ETL counters and five records were compared, not every node and property.
- Which of the two changes shortened the load (server memory; the other databases stopped).
- Why the node phases of the `cpe` step were slower than on 2026-11-01 (F3).
- `download.py` failure path (exit code 1 when a source fails): unit tests only, every source answered.
- The data downloaded on 2026-11-27 was not loaded (CPE-MATCH: 76 chunks, 74 in this build).
- `download_schemas.py` was not run.
- Nothing about `kgcs-server` against this database: its spec pin is still 1.0.0.
