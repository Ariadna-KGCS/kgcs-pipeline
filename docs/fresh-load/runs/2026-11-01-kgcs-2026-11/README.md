# Fresh load 2026-11-01 — `kgcs-2026-11`

**Verdict: GREEN.** 16/16 ETL steps, 7,061,232 nodes reconciled label by label
with the ETL counters, 34/35 post-load checks, decision/ATLAS ABox SHACL
conforms, offline expected counts equal the graph 8/8. The two reds are both
newer upstream releases detected correctly, not load defects (see Findings).
Procedure: [`../../../fresh-load.md`](../../../fresh-load.md). Reference
builds: [`2026-09-28-kgcs-v12`](../2026-09-28-kgcs-v12/summary.json) (spec
1.2.1), [`2026-09-06-kgcs-demo`](../2026-09-06-kgcs-demo/summary.json) (v1.0).

| | 2026-09-28 `kgcs-v12` | 2026-11-01 `kgcs-2026-11` |
| --- | --- | --- |
| Pipeline commit / spec | `c40616f` / 1.2.1 | `803dc01` / 1.2.1 |
| NVD snapshot · CWE · ATT&CK · KEV | 09-06 · 4.20 · Sept bundle · 2026.09.25 | 11-01 · **5.0** · **Oct release** · 2026.10.30 |
| ETL duration | 1 h 17 | 1 h 49 (cpe step 71 min) |
| Vulnerability / Platform | — / — | 417,654 / 1,866,213 |
| Weakness / CAUSED_BY | 969 / 331,107 | **984** / 362,316 |
| Technique / SubTechnique / PART_OF | 378 / 540 / 436 | 383 / 552 / 441 |
| KEV / EPSS / SSVC leaves | 1,711 / 368,628 / 182,047 | 1,765 / 398,784 / 210,258 |
| CVE → CWE coverage | 76.7 % (09-06) | 77.55 % |
| CVE without CVSS · CVSS 4.0 scores | 5.3 % · ~35k (09-06) | 5.63 % · 44,430 |

## What ran

| Step | Gate | Result |
| --- | --- | --- |
| 0 Preflight + raw | 13/13 standards dated today; 1 CWE, 1 CAPEC; feed versions diffed vs 2026-09-06 snapshot | PASS — CWE 4.20→**5.0** (xmlns `cwe-7`→`cwe-8`) caught *before* loading |
| 1 Expected offline | KEV/EPSS/SSVC/ATLAS counts from raw | PASS — KEV 1,765 · EPSS 398,784 · SSVC 210,258 · ATLAS 264/718 (full scan to stdout; the saved `expected-v12.*` is the `--skip-cve` re-run) |
| 2 ETL | 16/16, 0 deadlocks, 0 errors | PASS — `etl.log` (19:47 → 21:36) |
| 3 Post-load | postload, shacl-v12, compare-v12, graph-quality, stats | 34/35 (F3) · CONFORMS, 1 known warning (F4) · EQUAL 8/8 · 6/6 after F2 · minimums 12/12 |
| 4 Sample | 5 records read against their evidence | 5/5 (below) |

## Findings

**F1 — CWE 5.0 moved the catalog namespace (`cwe-7` → `cwe-8`).**
`load_cwe.py` had the namespace hard-coded; it would have iterated zero
`Weakness` elements and reported success with an empty CWE layer. Fixed in
`803dc01` (namespace read from the root element; zero weaknesses now fails
the step). Step 0's version diff is what caught it. CWE 5.0 also removes
`Category` (422 → 0) in favour of `Groupings`/`Dimensions` (431/395) — not
loaded today, spec-level decision.

**F2 — `check_graph_quality` FAIL `PART_OF` 441 vs 436 (expected file from
September).** The October ATT&CK release adds 7 techniques and retires 2:
+T1696 Anti-Automation Evasion (2 subs), T1697, **T1698 Indirect Prompt
Injection, T1699 Direct Prompt Injection, T1700 AI-Enabled Exfiltration**
(enterprise), T1476 (mobile), T1701 Command and Scripting Interpreter (ICS, 6
subs, replacing T0807 and T0853). 378 + 7 − 2 = 383; each new technique has
one `PART_OF` → 436 + 5 = 441. `technique_in_tactic` and
`part_of_domain_coherence` pass. Re-checked against `expected-graph.json`
computed from today's raw (`graph-quality.log`).

**F3 — `cwe_consequence_vocabulary` FAIL, 3 violations.** CWE 5.0 introduces
impact values the spec 1.2.1 vocabulary lacks: `DoS: Prevent Access`
(CWE-1260-C1, CWE-1476-C1 — the latter a new weakness) and `Undefined
Behavior` (CWE-1335-C2). Loaded verbatim as designed; SHACL and the Cypher
check flag them. Fix belongs to the spec vocabulary (next release + pin bump).

**F4 — one `ADAPTED_FROM` warning, known.** AML.T0073 *Impersonation* cites
T1656, revoked in the bundle (`revoked-by → T1684.001`, same name); the loader
remapped and reported it. Same case as `docs/spec-v1.2-deltas.md` §"44, not 43".

**F5 — a second `run_all_etl.py` was alive during the first attempt.**
A PowerShell pipeline whose `Tee-Object` failed to open its file left the
`python.exe` running; it survived `DROP/CREATE DATABASE` (driver retries) and
produced `DeadlockDetected` retries in the second attempt. Killed, database
recreated, this run is single-process (0 deadlocks). Procedure updated: check
`Get-Process python*` before launching and after cancelling.

**F6 — the `cpe` step took 71 min (≈45 in September)** for +4.7 % more
`MATCHES_PLATFORM`. Not diagnosed (same instance hosts `kgcs-v12` and
`kgcs-demo`; no Bolt-level timing kept).

## Sample (step 4, read-only, via the MCP connector with `USE`)

1. **CVE-2026-114625** (published 2026-10-22): CVSS 3.1 **and
   4.0**; KEV added 2026-10-23 (catalog 2026.10.30); EPSS 2026-11-01; SSVC
   `active / automatable=no / total`; `CAUSED_BY` → CWE-89.
2. **Consequences out of vocabulary**: exactly the 3 of F3, read with scopes
   and impacts.
3. **ATT&CK October release**: the 7 added / 2 retired techniques of F2, each
   with its tactic and domain.
4. **ADAPTED_FROM warning**: AML.T0073 → T1684.001, cited T1656; `revoked-by`
   confirmed in `enterprise-attack.json`.
5. **BuildMetadata**: spec 1.2.1, commit `803dc01`, 13 source snapshots
   (`CWE=5.0`, `KEV=2026.10.30`, `EPSS=2026-11-01`, `ATTCK modified-max
   2026-10-13`). The "working tree has uncommitted changes" warning refers to
   this documentation, not to loader code.

## Not verified

- Raw download byte total (`download.log` not kept — recorded only "13/13 standards dated today").
- Cause of the slower `cpe` step (F6).
- Neo4j server version read from the server (taken from the instance already hosting `kgcs-v12`).
- `CAUSED_BY` provenance alignment sampled on 2 CVEs only (the Cypher check covers all).
- Nothing about `kgcs-server` against this database: its spec pin is still 1.0.0.
