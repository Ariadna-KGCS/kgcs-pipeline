# Graph-quality fixes 2026-09: expected edge deltas

**Session:** Q5 (2026-09-26), branch `fix/graph-quality-2026-09`, spec pin `1.1.0`.
**Inputs:** `data/raw` downloaded 2026-09-06, unchanged (no `download.py` run).
**Method:** computed offline, without Neo4j, by
[`validation/expected_graph_deltas.py`](../validation/expected_graph_deltas.py).
The full output is in [`graph-quality-2026-09-expected.json`](graph-quality-2026-09-expected.json).

```bash
python validation/expected_graph_deltas.py --check-v10 --json docs/graph-quality-2026-09-expected.json
```

The script has two modes:

- **v1.0** replays the pre-fix loader rules. Its counts are checked against
  the kgcs-demo counts of 2026-09-26 (`--check-v10` exits 1 on any mismatch).
- **v1.1** calls the fixed loaders' own transform functions.

Both modes apply the loaders' `MATCH` semantics: an edge counts only if the
load creates both of its endpoint nodes.

## Expected counts

| Edge type | kgcs-demo 2026-09-26 | v1.0 offline | v1.0 = kgcs-demo | v1.1 offline | Delta |
| --- | ---: | ---: | :---: | ---: | ---: |
| `PART_OF` | 1,054 | 1,054 | yes | 436 | -618 |
| `SUBTECHNIQUE_OF` | 540 | 540 | yes | 540 | +0 |
| `IMPLEMENTS` | 235 | 235 | yes | 244 | +9 |
| `MITIGATED_BY` | 3,010 | 3,010 | yes | 3,087 | +77 |
| `CAUSED_BY` | 331,107 | 331,107 | yes | 331,107 | +0 |
| `DEMONSTRATED_BY` | 1,212 | 1,212 | yes | 1,212 | +0 |
| `CHILD_OF` | 519 | 519 | yes | 533 | +14 |

Node counts do not change: Tactic 39, Technique 378, SubTechnique 540,
AttackPattern 615, Weakness 969, DefensiveTechnique 145.

## PART_OF (−618)

- **v1.0.** Matched `Tactic {phaseName}`. There are 618 cross-domain edges:
  enterprise→mobile 185, enterprise→ics 159, mobile→enterprise 75,
  mobile→ics 67, ics→enterprise 66, ics→mobile 66.
- **v1.1.** Each `kill_chain_phases` entry resolves to the tactic `attackId`
  of the same bundle, matched on `x_mitre_shortname` and kill chain.
  - 436 edges, one per kill-chain entry: 436 entries, 0 unresolved.
  - 0 cross-domain edges; every Technique keeps at least one `PART_OF`
    (SH-CORE-06).
  - v1.1 is an exact subset of v1.0: no edge is added, and none is missing
    against the STIX kill chains.

## IMPLEMENTS (+9, none removed)

There is one shared `revoked-by` remap built from the three bundles:

- 196 revoked ids have a live successor;
- 25 ids are deprecated;
- 1 id is revoked with no successor.

`IMPLEMENTS` is now written only by `load_attck.py`. Each cited id is
remapped first, then a sub-technique is rolled up to its parent.

| Source | Distinct refs | Remapped | Dropped (deprecated) | Unresolved |
| --- | ---: | ---: | ---: | ---: |
| CAPEC 3.9 XML `Taxonomy_Mappings` (ATTACK) | 271 | 14 | 0 | 0 |
| STIX `capec` refs on revoked/deprecated techniques | 36 | 33 | 3 | 0 |
| STIX `capec` refs on live techniques | 0 | — | — | — |

- **CAPEC XML adds 7 edges.** These are the 4 CAPEC entries the v1.0 roll-up
  lost to the revoked `T1562`:
  - `CAPEC-13 → T1690`
  - `CAPEC-268 → T1685`, `T1690`
  - `CAPEC-571 → T1685`
  - `CAPEC-578 → T1685`, `T1686`, `T1688`

  Remapped taxonomy ids: `T1562.001→T1685`, `T1562.002→T1685.001`,
  `T1562.003→T1690`, `T1562.004→T1686`, `T1562.006→T1685`,
  `T1562.007→T1686.001`, `T1562.008→T1685.002`, `T1562.009→T1688`,
  `T1574.002→T1574.001`. The last one rolls up to `T1574`, which v1.0
  already linked.
- **STIX refs add 2 edges:** `CAPEC-564 → T1647` (via `T1162`) and
  `CAPEC-570 → T1027` (via `T1009 → T1027.001`). The other 31 remapped STIX
  refs land on edges the CAPEC XML already gives.
- **Dropped as deprecated:** `CAPEC-159/T1034`, `CAPEC-552/T1062` and
  `CAPEC-563/T1051`.

## MITIGATED_BY (+77, none removed)

The D3FEND mappings give 3,109 distinct (ATT&CK, D3FEND) pairs.

- **v1.0** lost 99 of them: its `OPTIONAL MATCH` found no node for ids that
  are revoked or deprecated.
- **v1.1** handles those 99 rows as follows:
  - 88 are remapped. Eleven ids are involved: `T1070.001→T1685.005`,
    `T1070.002→T1685.006`, `T1142→T1555.001`, `T1547.011→T1647`,
    `T1562.001→T1685`, `T1562.002→T1685.001`, `T1562.003→T1690`,
    `T1562.004→T1686`, `T1562.009→T1688`, `T1562.010→T1689`,
    `T1574.002→T1574.001`.
  - 11 are dropped as deprecated, all `T1053.004`.
  - 0 are unresolved.
- Of the 88 remapped pairs, 11 collapse onto pairs that already exist, so
  77 edges are new. Targets keep their label: a SubTechnique successor gets
  the edge, with no roll-up.

## CAUSED_BY (±0; properties added)

- There is still one edge per (CVE, CWE): 331,107.
- Each edge now carries `sources`, `sourceRoles` and `types`. The lists
  are aligned on all 331,107 edges; 0 edges have unequal lengths.
- **Assignment entries:**

  | Role | Entries |
  | --- | ---: |
  | `nvd` | 165,993 |
  | `cna` | 165,740 |
  | `adp` | 38,463 |

  | Type | Entries |
  | --- | ---: |
  | `Primary` | 162,988 |
  | `Secondary` | 207,208 |

- **Edges by the set of roles on them:**

  | Roles | Edges |
  | --- | ---: |
  | `nvd` only | 128,359 |
  | `cna` only | 139,019 |
  | `adp` only | 25,401 |
  | `cna` + `nvd` | 25,266 |
  | `adp` + `nvd` | 12,089 |
  | `adp` + `cna` | 694 |
  | all three | 279 |

  38,798 edges have more than one distinct source.
- **Several records of one CVE.** A CVE can appear in
  `nvdcve-2.0-modified.json` and in its per-year file. For each CVE, the
  record with the greatest `lastModified` supplies the lists of every pair it
  names. The edge set stays the union of all records, as in v1.0.
  - 5,656 pairs are named by both records; only the newest record's lists
    are kept.
  - 0 pairs appear only in an older record (the loader logs this count).
  - 5,461 CVEs are in the modified feed; 5,440 of them are also in a
    per-year file. 34 per-year records are older and each lacks one CWE (a
    CISA ADP assignment) that the modified record adds. 66 pairs are named
    only by the modified feed.
- These figures include the modified feed and apply the loader filters, so
  they differ from ADR-0002's raw per-year evidence (345,368 pairs,
  38,420 ADP assignments).

## CHILD_OF (+14, none removed; second commit)

- **Cause.** `load_capec.py` used to flush nodes and edges together
  whenever any buffer reached `--batch-size`. With the default 1,000 there
  was one mid-file flush, triggered by `DEMONSTRATED_BY`. At that flush,
  14 `CHILD_OF` edges whose parent comes later in the XML found no parent
  node:
  - `CAPEC-13→77`, `140→74`, `162→77`, `163→98`, `164→98`
  - `219→94`, `384→94`, `386→94`, `463→97`, `466→94`
  - `608→97`, `656→98`, `662→94`, `663→74`

  A second `--step capec` run would then add them, so kgcs-demo holds 519.
- **Fix.** The fixed loader streams every AttackPattern node first, then
  writes the deduplicated `DEMONSTRATED_BY` and `CHILD_OF` edges. One run
  gives 533, every ChildOf between existing AttackPatterns in CAPEC 3.9, and
  a second run changes nothing.
- **v1.0 mode** replays the old flush order and still reproduces 519.
- **Impact.** The 2026-09-26 snapshot exports `bridge_child_of.csv`, but E1b
  only counts it in its gate, so there is no paper impact.

## Input files (sha256 prefix)

| File | sha256 |
| --- | --- |
| `ATTCK-STIX/enterprise-attack.json` | `f7eaf37fe53b5040` |
| `ATTCK-STIX/ics-attack.json` | `8a462b5d0103fba3` |
| `ATTCK-STIX/mobile-attack.json` | `e69c3886a3c55311` |
| `CAPEC/capec_latest.xml` (CAPEC 3.9, 2023-01-24) | `70279a2dff0cb0ad` |
| `D3FEND/d3fend-full-mappings.json` | `671377151dd28828` |
| `CWE/cwec_v4.20.xml` | `1f5a78bd62e00f86` |
