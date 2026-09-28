# Spec v1.2 loaders: expected graph deltas

**Session:** Q18 (2026-09-27/28), branch `feat/spec-v1.2-loaders` from
`devel` (`55e0a57`), spec pin `1.2.1` (`kgcs-spec` `5ef42e5`).
**Scope:** the decision extension (ADR-0003: `load_kev.py`, `load_epss.py`,
`load_ssvc.py`) and the ATLAS module (ADR-0004: `load_atlas.py`).
**Inputs:**

- CVE, ATT&CK: `data/raw` of the 2026-09-06 download, the same raw data as
  `kgcs-v11` (unchanged).
- KEV, EPSS, ATLAS: downloaded 2026-09-27 by the new downloaders:
  - KEV `catalogVersion` 2026.09.25, 1,726 entries;
  - EPSS `epss_scores-2026-09-27.csv.gz`, model `v2026.06.15`;
  - ATLAS `ATLAS-2026.09.yaml`, SHA-256 `935efa93…6688`, byte-identical to
    the file profiled by the spec.

**Method:** computed offline, without Neo4j, by
[`validation/expected_v12_deltas.py`](../validation/expected_v12_deltas.py).
It calls the loaders' own transform functions and applies their `MATCH`
semantics:

- a decision leaf counts only if its CVE is a `Vulnerability`, i.e. an id in
  the NVD files;
- an `ADAPTED_FROM` counts only if its target, after the revoked-by remap, is
  a live ATT&CK id.

The full output is in [`spec-v1.2-expected.json`](spec-v1.2-expected.json).

```bash
python validation/expected_v12_deltas.py --json docs/spec-v1.2-expected.json
# against a loaded graph (read-only; set the database in the same command)
$env:NEO4J_DATABASE='kgcs-q-smoke'; python validation/expected_v12_deltas.py --compare-neo4j
```

**Cross-check.** A second profile of the raw files (session scratchpad; it
imports no pipeline code) gives the same numbers:

- the `Vulnerability` base is 386,939, equal to `count(:Vulnerability)` on
  `kgcs-v11` (2026-09-27);
- KEV 1,711, EPSS 368,628 and SSVC 182,047 distinct ADP pairs;
- the per-file SSVC figures quoted by `ssvc-to-owl-v1.0.md`:
  - 2024: 38,130 entries, 38,126 by the CISA ADP;
  - 2026: 47,324 entries, 47,237 by the CISA ADP.

## Expected counts (new labels and edge types)

On a chain equal to `kgcs-v11`, each count is also the delta against it:
`kgcs-v11` has none of these labels or types.

| Item | Expected | Observed on `kgcs-q-smoke` (2026-09-27) |
| --- | ---: | ---: |
| `KevEntry` / `HAS_KEV_ENTRY` | 1,711 / 1,711 | 1,711 / 1,711 |
| `EpssScore` / `HAS_EPSS` | 368,628 / 368,628 | 368,628 / 368,628 |
| `SsvcDecision` / `HAS_SSVC` | 182,047 / 182,047 | 182,047 / 182,047 |
| `AtlasTactic` | 16 | 16 |
| `AtlasTechnique` | 120 | 120 |
| `AtlasSubTechnique` | 88 | 88 |
| `AtlasMitigation` | 40 | 40 |
| `ACHIEVES` | 225 | 225 |
| `SPECIALIZES` | 88 | 88 |
| `MITIGATES` | 361 | 361 |
| `ADAPTED_FROM` | **44** | 44 |

The new nodes total 552,650.

## Chain counts: delta 0

No v1.2 loader writes a chain label or a chain edge type. The chain loaders
(`load_cpe/cve/cvss/cwe/capec/attck/d3fend/car/shield/engage.py`, plus
`attck_revocations.py`, `cve_applicability.py`, `consequences.py`,
`neo4j_writer.py` and `base.py`) have an **empty diff** against `devel`.

On `kgcs-q-smoke`, after the ATT&CK and ATLAS steps:

- `PART_OF` is 436, both label-qualified and unqualified;
- `SUBTECHNIQUE_OF` is 540;
- `IMPLEMENTS` is 244.

These equal `kgcs-v11`. The ATLAS edges are `ACHIEVES` / `SPECIALIZES`
(v1.2.1), so no unqualified ATT&CK count moves.

`BuildMetadata` gains three `sourceSnapshots` keys:

- `KEV=2026.09.25`
- `EPSS=2026-09-27;model:v2026.06.15`
- `ATLAS=2026.09`

The ten chain keys are unchanged: `test_v12_keys_leave_the_chain_keys_unchanged`,
and the offline preview shows the same ten values as `kgcs-v11`. The Q19
equivalence gate compares `BuildMetadata` minus these three keys.

## KEV (1,711 of 1,726)

- `count` = 1,726 = entries, with 0 duplicate `cveID`.
- **15 dropped** because the CVE has no `Vulnerability`. All 15 are
  2026 CVEs newer than the 2026-09-06 NVD snapshot:

  ```text
  CVE-2026-58704, CVE-2026-75650, CVE-2026-76460, CVE-2026-76461,
  CVE-2026-81963, CVE-2026-84869, CVE-2026-85102, CVE-2026-85706,
  CVE-2026-85880, CVE-2026-87491, CVE-2026-87886, CVE-2026-87902,
  CVE-2026-93616, CVE-2026-93952, CVE-2026-94127
  ```

  A CVE refresh before Q19 would change this number, not the rule.
- Every entry carries all twelve fields. The ransomware field is `Unknown`
  on 1,365 entries and `Known` on 361; `forensicTriage` is `No` on 1,659 and
  `Yes` on 67.
- The load is a full refresh (`SET k = row.props`); re-running it creates 0
  nodes and 0 edges.

## EPSS (368,628 of 380,066)

- One file: score date 2026-09-27, timestamp `2026-09-27T12:00:21Z`, model
  `v2026.06.15`.
- 380,066 rows; 0 duplicate CVEs and 0 values outside [0, 1].
- **11,438 dropped** because the CVE has no `Vulnerability`. EPSS scores
  CVEs that the 2026-09-06 NVD files do not hold.
- The load is append-only (`ON CREATE SET`). A re-run creates 0 nodes, and
  `count(EpssScore)` goes 368,628 → 368,628.
- History depth = the dated files in `data/raw/EPSS/`: one here. This is
  ADR-0003 Open question 3, answered for Q20 by the "offline baseline" plan.

## SSVC (182,047 decisions)

| Quantity | Count |
| --- | ---: |
| `ssvcV203` entries in the 26 NVD files (modified + 2002–2026) | 186,737 |
| loadable CISA-ADP entries (`134c704f-…`) | 186,562 |
| duplicates collapsed on `ssvcId` | 4,515 |
| distinct `(cveId, timestamp)` decisions | **182,047** |
| distinct CVEs | 182,039 |
| dropped, no `Vulnerability` | 0 |

Two notes on the table:

- The collapsed duplicates are consistent with the 4,541 ADP entries of
  the `modified` file reappearing, with the same timestamp, in the yearly
  files, plus in-record repeats (e.g. CVE-2026-2771). This split was not
  itemised.
- 8 CVEs keep two decisions, because they carry distinct ADP timestamps.

Dropped by source, 175 entries in total (ADR-0003 Open question 1):

| Source | Entries |
| --- | ---: |
| `9119a7d8-…` (CISA as CNA) | 144 |
| `ics-cert@hq.dhs.gov` | 12 |
| `87c8e6ad-…` | 11 |
| `44488dab-…` | 3 |
| `cve@takeonme.org` | 3 |
| `2fdefc65-…` | 1 |
| `2ffdacf6-…` | 1 |

The ADP entries do not trigger any of the loader's other drop rules:

- every one has a `timestamp` and an `id` equal to its CVE;
- every one has three options, all at `version` 2.0.3;
- the 30 entries without a timestamp are all non-ADP (29 with `role` `CNA`,
  one `Coordinator`).

Timestamp lexical forms (all entries): 181,525 end in `Z`, 5,037 carry
`+00:00`. Both are kept verbatim in the key.

## ATLAS 2026.09 (264 nodes, 718 edges)

The counts equal the spec's source profile: 16 / 120 / 88 / 40 nodes and
225 / 88 / 361 edges.

Not loaded (Exclusions of `mapping-coverage-matrix-v1.2.md`):

- 14 tactic `attack-reference`;
- 4 mitigation `attack-reference`;
- 73 case studies and 665 `employs` rows.

### ADAPTED_FROM = 44, not 43 (finding)

The Q18 session card and `atlas-to-owl-v1.0.md` expected **43** edges plus
**1 unresolved** (`T1656`, "absent from the loaded ATT&CK bundle").

The loaded enterprise bundle does contain `T1656` "Impersonation". It is
`revoked: true`, with `revoked-by` → `T1684.001` "Impersonation", a
sub-technique of `T1684` "Social Engineering":

- `T1656` modified 2026-04-14;
- `T1684.001` modified 2026-05-12, live, and present on `kgcs-v11` with
  `domains = ["enterprise"]`.

`kgcs-v11` has no `T1656` node only because `load_attck.py` skips revoked
objects. The spec's 43/44 count checked the literal ids against the graph
without applying the revoked-by remap. The mapping's own rule 5, the shared
v1.1 bridge rule, remaps revoked targets. Applied, it gives:

- 44 rows and **44 edges**: 43 live, 1 remapped (`AML.T0073`: `T1656` →
  `T1684.001`);
- 0 deprecated and 0 unresolved;
- 39 distinct targets, 9 of them `SubTechnique`.

The edge keeps the cited id: `attackReferenceId = T1656`,
`attackReferenceUrl = https://attack.mitre.org/techniques/T1656/`. This
raises the one `atlas:AdaptedFromReferenceAgreementShape` **Warning** that
the shape reserves for a legitimate remap.

No ATT&CK bundle refresh is needed for this edge. The spec text (43 / 1
unresolved in `atlas-to-owl-v1.0.md` and the v1.2 matrix) is a v1.2.x
erratum candidate for `kgcs-spec`.

## Smoke load (`kgcs-q-smoke`, 2026-09-27)

`kgcs-q-smoke` started with the Q6 load only: AttackPattern 615, Weakness
969, Consequence 2,051, BuildMetadata 1. Every command set
`NEO4J_DATABASE=kgcs-q-smoke` explicitly, because `.env` defaults to
`kgcs-demo`. Each log shows `Neo4jWriter connected … (database=kgcs-q-smoke)`.

1. `run_all_etl.py --step constraints`: 30/30. That is 27 uniqueness
   constraints, 7 of them new, plus 3 indexes.
2. **Seed, not a loader:** 386,939 `(:Vulnerability {cveId})` stubs. The
   seed MERGEs the ids of the NVD files, a session-scratchpad script that
   refuses any other database. The decision loaders need only the join key.
   The full CVE loader is Q19's job.
3. `--step attck` (unchanged loader): Technique 378, SubTechnique 540, Tactic
   39, `PART_OF` 436, `IMPLEMENTS` 244.
4. `--step kev`, `epss`, `ssvc`, `atlas`: the counts in the tables above.
   Wall time ≈ 5 min, of which EPSS takes 2 min 21 s and SSVC 2 min 30 s.
5. Re-run of the four steps creates 0 nodes and 0 edges (idempotent).
6. `expected_v12_deltas.py --compare-neo4j`: **EQUAL** on all 14 items.
7. `validate_all_standards.py --post-load --partial-load`: exit 0.
   - All 14 new checks pass. The decision checks cover adherence, no chain
     edges, one KEV per CVE, EPSS and SSVC keys and vocabularies. The ATLAS
     checks cover the boundary, no `PART_OF`/`SUBTECHNIQUE_OF`,
     `ADAPTED_FROM` targets, provenance and cardinality, `ACHIEVES`,
     `SPECIALIZES` and `MITIGATES`.
   - The chain checks pass trivially on this partial graph.
8. `shacl_export_v12.py --limit 2000` (from Neo4j) **CONFORMS** against the
   pinned `decision.shacl.ttl` and `atlas.shacl.ttl`.
   - The sample: all 1,711 KevEntry, 2,000 EpssScore, 2,000 SsvcDecision,
     the whole ATLAS module and the 44 bridges with their statements.
   - Result: 0 Violations and 1 Warning, the remap above.
