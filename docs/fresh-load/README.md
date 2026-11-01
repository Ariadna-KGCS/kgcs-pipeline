# Fresh-load runs

One directory per full build, named `<YYYY-MM-DD>-<database>`. Procedure:
[`../fresh-load.md`](../fresh-load.md).

## What a run directory holds

| File | Produced by | Kept because |
| ---- | ----------- | ------------ |
| `README.md` | hand-written | what was built, what passed, what was *not* verified, findings |
| `summary.json` | hand-written from the logs (schema below) | the machine-comparable record |
| `expected-v12.json` / `.md` | step 1 | the target the graph was measured against |
| `etl.log` | step 2 (INFO) | per-step counters and timing |
| `postload.log`, `shacl-v12.log`, `compare-v12.log`, `graph-quality.log`, `stats.log`, `stats.json` | step 3 | the evidence behind every PASS |
| `report.html` | optional, generated from the summaries | human-readable comparison across runs |

Not kept: `download.log` (volume, no decisions in it), anything at DEBUG, raw
data, dumps. `.gitignore` whitelists `*.log` under this tree only.

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

Older builds predating this layout get a `summary.json` reconstructed from
their reports, and nothing else.
