# KGCS Pipeline Data

Everything under `data/` is **reproducible and gitignored**. Nothing here is
hand-maintained: delete it and the two download entrypoints rebuild it from
the official sources.

```text
data/
├── raw/       ← python scripts/download.py --standard all      (the datasets, ~GBs)
└── schemas/   ← python scripts/download_schemas.py             (official schema defs, small)
```

- `raw/` is what the ETL (`run_all_etl.py`) consumes.
- `schemas/` is **not** consumed by the ETL or validation. It exists so the
  raw-data contracts can be diffed when an upstream version bumps (e.g.
  CWE 4.19.1 → 4.20) *before* touching extraction code — see the repo rule
  "verify external feed schemas from actual downloaded files before coding
  extraction logic".

Ontology mappings, OWL modules, and SHACL shapes are **not** here: they are
[kgcs-spec](https://github.com/Ariadna-KGCS/kgcs-spec) territory, pinned into
`spec/` by `sync_spec.py`.

---

## Sources per standard

All URLs live in `downloaders/ingest_config.py` (`APIEndpoints`) — single source of
truth. This table is the human-readable view of it.
`config/download_config.yaml` is an *optional* overrides file (`--config`): timeouts,
retries, output dir and which standards to enable. It holds no URLs.

| Standard | Raw data (download.py) | Official schema (download_schemas.py) |
| -------- | ---------------------- | ------------------------------------- |
| CVE | [NVD JSON 2.0 yearly feeds](https://nvd.nist.gov/feeds/json/cve/2.0/) (2002–2026 + modified) | [cve_api_json_2.0.schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema) |
| CVSS | (embedded in CVE feeds) | [v2.0](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v2.0.json) · [v3.0](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.0.json) · [v3.1](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.1.json) · [v4.0](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v4.0.json) |
| CPE | [nvdcpe-2.0.zip](https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip) | [cpe_api_json_2.0.schema](https://csrc.nist.gov/schema/nvd/api/2.0/cpe_api_json_2.0.schema) |
| CPE-MATCH | [nvdcpematch-2.0.zip](https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.zip) | [cpematch_api_json_2.0.schema](https://csrc.nist.gov/schema/nvd/api/2.0/cpematch_api_json_2.0.schema) |
| CWE | [cwec_latest.xml.zip](https://cwe.mitre.org/data/xml/cwec_latest.xml.zip) | [cwe_schema_latest.xsd](https://cwe.mitre.org/data/xsd/cwe_schema_latest.xsd) |
| CAPEC | [capec_latest.xml](https://capec.mitre.org/data/xml/capec_latest.xml) | [ap_schema_latest.xsd](https://capec.mitre.org/data/xsd/ap_schema_latest.xsd) |
| ATT&CK | STIX 2.0 bundles from [mitre/cti](https://github.com/mitre/cti) (enterprise, ics, mobile) | [OASIS STIX 2.0 JSON Schemas](https://github.com/oasis-open/cti-stix2-json-schemas) (branch zip; schemas cross-reference each other) |
| D3FEND | [d3fend.mitre.org/ontologies 1.3.0](https://d3fend.mitre.org/ontologies/d3fend/1.3.0/) (OWL, TTL, JSON, full mappings) | — the OWL ontology *is* the schema |
| CAR | YAML analytics/data_model/sensors from [mitre-attack/car](https://github.com/mitre-attack/car) | — prose-defined YAML format, no JSON/XSD published |
| ENGAGE | JSON exports from [mitre/engage](https://github.com/mitre/engage) | — no schema published |
| SHIELD | Static JSON dumps from [MITRECND/mitrecnd.github.io](https://github.com/MITRECND/mitrecnd.github.io) (retired SHIELD site) | — no schema published |

`python scripts/download_schemas.py --list` prints this same schema inventory,
including the no-machine-schema reasons.

---

## Layout the ETL expects

Loaders read from `data/raw/{STANDARD}/` (CWD-relative; run from repo root):

```text
raw/CVE/nvdcve-2.0-{2002..2026}.json + nvdcve-2.0-modified.json
raw/CPE/nvdcpe-2.0-chunks/*.json            ← chunked, ~17 files
raw/CPE-MATCH/nvdcpematch-2.0-chunks/*.json ← chunked, ~66 files
raw/CWE/cwec_v*.xml
raw/CAPEC/capec_latest.xml
raw/ATTCK-STIX/{enterprise,ics,mobile}-attack.json
raw/D3FEND/d3fend.{owl,ttl,json} + d3fend-full-mappings.json
raw/car/{analytics,data_model,sensors}/*.yaml
raw/ENGAGE/*.json
raw/SHIELD/*.json
```

> **Note on chunks:** the NVD zips ship the chunked layout directly
> (verified 2026-08-07). If NVD ever reverts to a single large JSON,
> the downloader falls back to `downloaders/chunker.py` (ijson streaming)
> to produce the same layout.

---

## Reproducing from zero

```bash
python scripts/download.py --standard all        # raw datasets (~GBs, be patient)
python scripts/download_schemas.py               # official schema definitions
```

Both are idempotent and re-runnable per standard
(`--standard cve,attck`, `--standard cwe`, …). Download validation
(`--validate`, on by default) checks format and record counts of the raw
files; it does not require `schemas/`.

Versions are whatever the official sources serve at run time — the feeds are
rolling (`*_latest`, yearly NVD files). For reproducible experiments, pin a
snapshot outside this repo rather than freezing files here.

---

## License and attribution

Downloaded content remains subject to its source's terms: MITRE standards
per MITRE terms of use, NIST/NVD data as U.S. public domain work product.
This repo's code is Apache 2.0; the datasets are not redistributed by it.
