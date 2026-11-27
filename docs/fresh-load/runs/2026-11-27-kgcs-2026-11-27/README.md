# Fresh load 2026-11-27 — `kgcs-2026-11-27`

**Verdict: GREEN.** 16/16 ETL steps, 7,203,640 nodes equal to the sum of the
step counters, 34/35 post-load checks, decision/ATLAS ABox SHACL conforms,
offline expected counts equal the graph. The one red is the CWE 5.0 vocabulary
gap already known (F3). This is the first build made from a fresh download by
the code released as v1.2.1 (`683f42b`); the same code had reproduced the
2026-11-01 build count for count a few hours earlier
([`2026-11-27-kgcs-2026-11-rc`](../2026-11-27-kgcs-2026-11-rc/README.md)).
Procedure: [`../../../fresh-load.md`](../../../fresh-load.md). Previous build:
[`2026-11-01-kgcs-2026-11`](../2026-11-01-kgcs-2026-11/README.md).

| | 2026-11-01 `kgcs-2026-11` | 2026-11-27 `kgcs-2026-11-27` |
| --- | --- | --- |
| Pipeline commit / spec | `803dc01` / 1.2.1 | `683f42b` / 1.2.1 |
| CWE · CAPEC · D3FEND · ATLAS | 5.0 · 3.9 · 1.3.0 · 2026.09 | the same |
| ATT&CK bundle | modified-max 2026-10-13 | modified-max 2026-11-04, same counts |
| KEV catalog · EPSS date | 2026.10.30 · 2026-11-01 | **2026.11.25** · **2026-11-26** |
| Raw inputs | 273 files, 7.98 GB | 275 files, 8.06 GB |
| ETL duration | 109.3 min | 72.5 min (cpe step 53.9) |
| Nodes | 7,061,232 | **7,203,640** |
| Vulnerability / Platform | 417,654 / 1,866,213 | 433,070 / 1,884,010 |
| Weakness / CAUSED_BY | 984 / 362,316 | 984 / 379,138 |
| Technique / SubTechnique / PART_OF | 383 / 552 / 441 | 383 / 552 / 441 |
| KEV / EPSS / SSVC leaves | 1,765 / 398,784 / 210,258 | 1,805 / 413,377 / 227,528 |
| CVE → CWE coverage | 77.55 % | 78.28 % |
| CVE without CVSS · CVSS 4.0 scores | 5.63 % · 44,430 | 5.46 % · 49,860 |

## What ran

| Step | Gate | Result |
| --- | --- | --- |
| 0 Preflight + raw | clean tree, spec pin, 156 tests, previous inputs archived with a manifest, server memory read from the server; 13/13 sources dated today; 1 CWE, 1 CAPEC; source snapshots diffed against 2026-11-01 | PASS — 9 of 13 snapshots moved, no catalog changed version |
| 1 Expected offline | KEV/EPSS/SSVC/ATLAS counts from raw, full scan | PASS — KEV 1,805 · EPSS 413,377 · SSVC 227,528 · ATLAS 264/718 (`expected-v12.*`) |
| 2 ETL | 16/16, 0 deadlocks, 0 errors | PASS — `etl.log` (08:38 → 09:50) |
| 3 Post-load | postload, shacl-v12, compare-v12, graph-quality, stats | 34/35 (F3) · CONFORMS, 1 known warning (F4) · EQUAL 8/8 · 6/6 · minimums 14/14 |
| 4 Sample | 6 records read against their evidence | 6/6 (below) |
| 5 Report | `scripts/build_run_report.py --compare-siblings` | `report.html` |
| 6 Archive | inputs, schemas and this directory, with a manifest | done after this file was written |

Steps 0 to 5 ran unattended, each gate stopping the run on failure. The
wrapper and the generator of `summary.json` are not in this repository yet.

## Findings

**F1 — a month of upstream growth and nothing else.** Against 2026-11-01:
+15,416 `Vulnerability`, +17,797 `Platform`, +8,198 `PlatformConfiguration`,
+616,406 `MATCHES_PLATFORM`, +14,593 `EpssScore`, +17,270 `SsvcDecision`,
+40 `KevEntry`. Every layer whose source did not publish a new release is
identical node for node in count: `Weakness`, `Consequence`, `AttackPattern`,
the ATT&CK and ATLAS labels, D3FEND, CAR, SHIELD, ENGAGE, and all their
relationship types.

**F2 — KEV: 1,805 of 1,805 entries attached, none dropped.** On 2026-11-01 one
entry had no `Vulnerability` to hang from (CVE-2026-118527, in KEV since
2026-10-30). NVD published that CVE on 2026-11-03 and the entry is now loaded.
39 entries were added to the catalog since 2026-11-02; 39 + 1 = the +40.

**F3 — `cwe_consequence_vocabulary` FAIL, 3 violations, unchanged.** The same
three CWE 5.0 impact values as on 2026-11-01 (`DoS: Prevent Access` in
CWE-1260-C1 and CWE-1476-C1, `Undefined Behavior` in CWE-1335-C2). Loaded
verbatim and flagged. The fix belongs to the spec vocabulary.

**F4 — one `ADAPTED_FROM` warning, known.** AML.T0073 *Impersonation* cites
T1656, revoked in favour of T1684.001; the loader remapped it and kept the
cited id on the edge. 44 edges, 39 distinct ATT&CK targets, 1 remap, as the
offline expectation says.

**F5 — the relationship rate depends on what else the workstation is doing.**
`MATCHES_PLATFORM` ran at 0.69 min per file while the machine was in
interactive use (files 1 to 53 of 76) and at 0.42 once it was left alone
(files 54 to 76; the unattended run earlier that morning held 0.47). One
observation; the mechanism was not measured. The load is bounded by a single
server thread, so it is sensitive to anything that slows that one core.

**F6 — `BuildMetadata` warns about uncommitted changes: a schema-mirror file,
not loader code.** The tree was verified clean before the run. Step 0 then ran
`download_schemas.py`, which refreshed `data/schemas/CWE/cwe_schema_latest.xsd`
from the CWE 7.3 schema to 8.0. `data/schemas/` is ignored, but five files of
that mirror were still tracked, so the refresh showed up as a tracked change
(the check ignores untracked files, so the run's own logs are not the cause).
Nothing reads the mirror; the loader code is the one of `683f42b`. The five
files were untracked right after this run. The schemas archived with the
2026-11-01 build still carry the 7.3 schema: the mirror was not refreshed for
that build.

**F7 — `compare-v12` covers 8 of the 14 expected items.** The procedure runs it
with `--skip-cve`, which leaves out the KEV, EPSS and SSVC totals. The full
scan of step 1 took 0.8 min here, and its three totals were compared with the
graph by hand (equal). Dropping `--skip-cve` in step 3 would make the gate do
it; not changed in this run.

## Sample (step 4, read-only, via the MCP connector with `USE`)

1. **CVE-2026-134624** (published 2026-11-22): CVSS 3.1 (8.7) **and 4.0**
   (9.3); KEV added 2026-11-23 (catalog 2026.11.25); EPSS 2026-11-26; SSVC
   `active / automatable=no / total`; `CAUSED_BY` → CWE-918 with source role
   `cna`.
2. **CVE-2026-132165** (published 2026-11-26, a day before the build): in KEV
   since 2026-11-24 and with an EPSS score, `CAUSED_BY` → CWE-306, no CVSS and
   no SSVC yet. The leaves attach as soon as the CVE exists.
3. **CVE-2026-118527**: the KEV entry dropped on 2026-11-01 is attached (F2).
4. **Consequences out of vocabulary**: exactly the 3 of F3, read with scopes
   and impacts.
5. **ADAPTED_FROM**: 44 edges, all into ATT&CK technique or sub-technique
   nodes; AML.T0073 → T1684.001 with `attackReferenceId` T1656.
6. **BuildMetadata**: one node, spec 1.2.1, commit `683f42b`, 13 source
   snapshots equal to the ones computed from the raw data before loading
   (`KEV=2026.11.25`, `EPSS=2026-11-26`, `ATTCK modified-max 2026-11-04`,
   `CWE=5.0`, `CAPEC=3.9`, `D3FEND=1.3.0`, `ATLAS=2026.09`).

## Not verified

- Which ATT&CK objects the November edits touched: the technique, sub-technique and tactic counts are unchanged.
- Node-by-node content: the gates compare counts, shapes and expected totals; six records were read.
- The schemas written by `download_schemas.py` (exit code 0, files not inspected).
- Why interactive use slows the relationship phase (F5).
- `CAUSED_BY` provenance alignment beyond the sampled CVEs (the Cypher check covers all).
- Nothing about `kgcs-server` against this database: its spec pin is still 1.0.0.
