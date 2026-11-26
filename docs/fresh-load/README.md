# Fresh-load runs

One directory per full build, named `<YYYY-MM-DD>-<database>`. Procedure:
[`../fresh-load.md`](../fresh-load.md).

## What a run directory holds

| File | Produced by | Kept because |
| ---- | ----------- | ------------ |
| `README.md` | hand-written | what was built, what passed, what was *not* verified, findings |
| `summary.json` | step 4, hand-written from the logs (schema below) | the machine-comparable record; the report's only source of figures |
| `expected-v12.json` / `.md` | step 1 | the target the graph was measured against |
| `etl.log` | step 2 (INFO) | per-step counters and timing |
| `postload.log`, `shacl-v12.log`, `compare-v12.log`, `graph-quality.log`, `stats.log`, `stats.json` | step 3 | the evidence behind every PASS |
| `report.html` | step 5: `python scripts\build_run_report.py <run-dir> --compare-siblings`, from `summary.json` (figures) and `README.md` (findings, sample, not verified) | human-readable report, one self-contained file, with the figures of the earlier runs beside this one; never edited by hand |

Not kept in the repository: `download.log` (volume, no decisions in it),
anything at DEBUG, dumps, and the raw data, which step 6 of the procedure
archives outside the repository (`<archive-root>/standards/<YYYYMMDD>/` with a
`manifest.csv` of SHA-256 hashes). `.gitignore` whitelists `*.log` under this
tree only.

## `summary.json` schema (v1)

```json
{
  "run": {"date": "YYYY-MM-DD", "database": "...", "neo4j": "2026.x", "pipeline_commit": "sha", "spec_version": "1.2.1"},
  "sources": {"cwe": "5.0", "capec": "3.9", "attck": {"enterprise": "...", "ics": "...", "mobile": "..."}, "kev": "2026.10.30", "epss": "2026-11-01", "atlas": "2026.09", "nvd_snapshot": "2026-11-01"},
  "etl": {"steps": 16, "duration_min": 0, "per_step": {"cpe": {"nodes": 0, "rels": 0, "min": 0}}},
  "graph": {"total_nodes": 0, "labels": {"Vulnerability": 0}, "rel_types": {"CAUSED_BY": 0}},
  "chain": {"cve_to_cwe_pct": 0.0, "cve_without_cvss_pct": 0.0, "cvss4_scores": 0},
  "validation": {"postload": "PASS", "shacl_v12": "PASS", "compare_v12": "PASS", "graph_quality": "PASS", "minimums": "PASS"},
  "not_verified": ["..."]
}
```

The example shows the shape, not every key: committed runs add `verdict`,
`etl.started` / `finished` / `deadlocks` / `errors`, `graph.reconciled_with_etl`,
`chain.cves` / `cve_with_cwe` / `cve_without_cvss` and
`chain.cvss_scores_by_version` (the report reads it, or `chain.cvss4_scores`),
extra per-step counters (`dropped_no_vulnerability`, ...), and `validation`
entries named for the check they record, each a text that starts with
`PASS`, `FAIL`, `CONFORMS` or `EQUAL`.

Older builds predating this layout get a `summary.json` reconstructed from
their reports, and nothing else.

## What `scripts/build_run_report.py` requires

It stops with exit code 1, naming the key, and writes nothing, when one of these
is absent or has the wrong type: `run.date`, `run.database`,
`run.pipeline_commit`, `run.spec_version` (strings); `sources` and `validation`
(objects); `etl.steps`, `etl.duration_min` (numbers) and `etl.per_step` (a
non-empty object of objects); `graph.total_nodes` (number), `graph.labels`,
`graph.rel_types` (objects of numbers); `chain.cve_to_cwe_pct`,
`chain.cve_without_cvss_pct` (numbers); `not_verified` (a list of strings).
Everything else is optional and shown when present. Runs given for comparison
(`--compare`, `--compare-siblings`) need only `run.date` and `run.database`;
a figure they lack is shown as a dash. `README.md` is optional; the report reads
its `## Findings` paragraphs (`**F1 — title.** text`), `## Sample` (numbered
list) and `## Not verified` (bullet list).
