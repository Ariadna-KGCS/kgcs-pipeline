# ETL coverage of build `kgcs-2026-11`

Scope updated 2026-11-27 (Humbert Costas): kgcs-spec v1.3.0 keeps candidates a, c (vocabulary), d, f, g and the pipeline-only fixes; candidates b (CWE hierarchy, ADR-0006) and e (CVSS provenance, ADR-0007) move to v1.4.0 together with the ADR on edge classes.

Analysis only. Nothing was changed, committed, pushed or reloaded.

- Build: database `kgcs-2026-11`, built 2026-11-01, pipeline `803dc01`, spec 1.2.1
  (read from `BuildMetadata`; `spec/` matches tag `v1.2.1`, `sync_spec.py --check` OK).
- Date of this analysis: 2026-11-14.
- Evidence: the live graph (read-only, `USE kgcs-2026-11`), the raw feeds in
  `data/raw` (the files the build read), the loaders in `etl/`, the pinned spec in `spec/`.
- Every number below was measured for this document unless it is marked
  *(etl.log)* or *(estimate)*. Section 8 lists what was not checked.

## 1. Result in short

1. **Counts reconcile exactly.** 22 node labels and 17 relationship types were
   recomputed from the raw files and equal the graph, `CAUSED_BY` (362,316)
   included. The 8 relationship types not recomputed are listed in section 8.
   No `MATCH … MATCH … MERGE` statement of the CPE and CVE steps lost a row
   (0 of 31,775,150 / 3,275,711 / 2,642,684 / 1,355,732).
2. **The 18,839 isolated `Vulnerability` nodes are all NVD `Rejected` records.**
   The feed has 18,859 Rejected CVEs; 18,839 carry nothing else and 20 keep one or
   more `CAUSED_BY` edges. The graph cannot tell them apart today (no `vulnStatus`).
3. **One third of the `Score` nodes are not NVD scores and the graph does not say so.**
   190,924 of 566,912 `Score` nodes (33.7 %) come from a `Secondary` metric entry
   (a CNA or the CISA ADP); for CVSS 4.0 it is 44,425 of 44,430. Another 83,475
   metric entries (12.8 % of 650,387) are not loaded.
4. **The CAUSED_BY skip counters are right but count entries, not pairs.**
   66,975 placeholder entries and 14,496 entries to 43 ids; per distinct (CVE, id)
   pair it is 66,423 and 14,413. On CWE 5.0 the 43 ids are 40 `Grouping` ids
   (the former Categories) and 3 `View` ids, not "category/view".
5. **ADR-0003 requires the SSVC filter** (D3, alternative A8 rejected, open
   question 1 resolved to "declared ADPs only"). The 286 dropped entries are by design.
6. **Findings outside the candidate list** (section 4): descriptions are cut at
   1,000 characters on 582 of 935 ATT&CK techniques and at 500 on 57 of 102 CAR
   analytics; all 197,044 CVSS 2.0 scores have an empty `baseSeverity`; a second
   CWE 5.0 value is outside the spec vocabulary and no check covers it;
   CAR / SHIELD / ENGAGE drop 22 mappings to ATT&CK ids that are no longer live
   without counting them.
7. **Proposal:** one additive release, **kgcs-spec v1.3.0**, covering a, b, c
   (vocabulary), d (accounting), e, f, g; h and the loader fixes are pipeline-only.
   Estimated 8 to 9 working days across both repos, then one reload of about
   3.5 hours end to end *(estimate)*.

## 2. Baseline (measured on the live graph)

| | Value |
| --- | --- |
| Nodes | 7,061,232 in 25 labels |
| Relationships | 42,606,546 in 25 types |
| Neo4j | Kernel 2026.09.0 enterprise, store format `block` (`summary.json` says "2026.07.x") |
| Store on disk | 4,784,908,696 bytes, plus 2,364,529,764 bytes of transaction logs |
| ETL duration *(etl.log)* | 109 min: cpe 70.8, cve 27.7, cvss 3.6, epss 1.5, ssvc 2.5, cwe 2.9, all other steps under 0.5 |

NVD record status of the 417,654 CVEs, with what each status carries (raw feed,
union of the records of a CVE):

| `vulnStatus` | CVEs | with mapped CWE | with CVSS | with configuration | with EPSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| Modified | 245,056 | 180,368 | 245,052 | 244,930 | 245,056 |
| Analyzed | 78,045 | 75,332 | 78,045 | 78,044 | 78,045 |
| Deferred | 60,138 | 57,849 | 58,846 | 0 | 60,138 |
| Rejected | 18,859 | 20 | 0 | 0 | 0 |
| Awaiting Analysis | 9,386 | 8,924 | 9,040 | 0 | 9,386 |
| Received | 5,029 | 446 | 2,127 | 0 | 5,018 |
| Undergoing Analysis | 1,141 | 955 | 1,014 | 255 | 1,141 |
| **Total** | **417,654** | **323,894** | **394,124** | **323,229** | **398,784** |

Consequence for the paper: the published ratios include Rejected records.
CVE to CWE coverage is 77.55 % over all nodes and 81.21 % over the 398,795
non-rejected ones (323,874 / 398,795). CVEs without CVSS are 5.63 % over all
nodes and 1.17 % over non-rejected ones (4,671 / 398,795).

## 3. Field coverage matrix

Legend for the **Spec** column (kgcs-spec v1.2.1, read from `spec/`):
**O** declared in an OWL module of the owning namespace, **C** named in
`contracts/agent-consumable-schema.md`, **M** only in a mapping document,
**none** not defined anywhere. "Graph" was checked with `keys(n)` over every
node of the label; a count is given when the property is not on every node.

### 3.1 `load_cpe.py`: NVD CPE dictionary (18 chunks) and CPE-MATCH (74 chunks)

| Upstream field (presence in raw) | Graph | Spec |
| --- | --- | --- |
| `cpe.cpeName` (1,866,213) | `Platform.cpeUri`, lower-cased (no name changed case, no collision) | O C |
| `cpe.cpeNameId` | `Platform.cpeNameId` | O C |
| name components 2 to 5 | `Platform.part`, `vendor`, `product`, `version` | O C |
| `cpe.lastModified` | `Platform.lastModified` | O |
| `cpe.deprecated` (true on 102,226) | `Platform.deprecated` | **none** |
| `cpe.created`, `cpe.titles[]` (1,873,327), `cpe.refs[]` (on 1,789,924), `cpe.deprecatedBy[]` (102,222), `cpe.deprecates[]` (96,996), name components 6 to 12 as properties | dropped | none |
| `matchString.matchCriteriaId` (672,683) | `PlatformConfiguration.matchCriteriaId` | O C |
| `criteria`, `status`, `created`, `lastModified` | `criteria`, `configStatus` (Active 590,903 / Inactive 81,780), `created`, `lastModified` | O (C for `criteria`, `configStatus`) |
| `cpeLastModified` (616,645) | `cpeLastModified`; empty string on the other 56,038 | O |
| `versionStart/End Including/Excluding` (82,748 / 607 / 70,080 / 153,463) | same four properties; **empty string where the feed has no bound** | O |
| `matches[].cpeName` (31,775,150 pairs) | `MATCHES_PLATFORM` 31,775,150 (all resolved; 216,257 criteria have no match) | O C |
| `matches[].cpeNameId` | dropped (redundant with the Platform key) | none |

### 3.2 `load_cve.py` and `cve_applicability.py`: NVD CVE 2.0 (26 files, 441,297 records, 417,654 CVEs)

| Upstream field (presence in records) | Graph | Spec |
| --- | --- | --- |
| `id`, `published`, `lastModified`, `sourceIdentifier` | `Vulnerability.cveId`, `published`, `lastModified`, `source` | O C |
| **`vulnStatus`** (all records, 7 values) | **dropped** | none |
| **`descriptions[]`** (`en` on every CVE, `es` on 316,249) | **dropped** | none |
| `cveTags[]` (3,284 CVEs: disputed 1,524, unsupported-when-assigned 1,500, exclusively-hosted-service 529) | dropped | none |
| `affected[]` (422,135 records; CNA-supplied vendor / product / versions) | dropped | none |
| `cisaExploitAdd`, `cisaActionDue`, `cisaRequiredAction`, `cisaVulnerabilityName` (1,765 CVEs) | dropped; same content as the KEV catalog | none |
| `evaluatorComment` (2,523), `evaluatorSolution` (1,222), `evaluatorImpact` (638), `vendorComments` (1,454) | dropped | none |
| `references[].url` (2,338,629 entries, 914,479 URLs, 1,355,732 (CVE, URL) pairs) | `Reference.referenceUrl` 914,479; `REFERENCES` 1,355,732 | O C |
| `references[].source` | `Reference.source`: the first source seen for the URL; 569,662 URLs (62.3 %) are cited by two or more sources | O (single-valued) |
| `references[].tags[]` (on 1,302,926 entries; 19 values, e.g. Patch 300,357, Exploit 208,361) | dropped | none |
| `configurations[i]` `.operator`, `.negate` | `VulnerabilityConfiguration` 778,251 (`vcId`, `cveId`, `configIndex`, `operator`, `negate`); `HAS_CONFIGURATION` 778,251 | O C |
| `nodes[j]` `.operator`, `.negate` | `VulnerabilityConfigurationNode` 1,228,978; `HAS_NODE` 1,228,978 | O C |
| `cpeMatch[k].matchCriteriaId`, `.vulnerable` | `MATCHES_CRITERIA {vulnerable, matchIndex}` 3,275,711 (every id exists in CPE-MATCH); `AFFECTS` 2,642,684 | O C (`matchIndex` M) |
| `cpeMatch[k].criteria`, version bounds | not on the CVE side; they are on `PlatformConfiguration` | n/a |

### 3.3 `load_cvss.py`: `metrics.cvssMetricV2 | V30 | V31 | V40`

| Upstream field | Graph | Spec |
| --- | --- | --- |
| one entry per (CVE, version), `Primary` preferred, else the first | `Score` 566,912 (2.0 197,044; 3.0 54,791; 3.1 270,647; 4.0 44,430); `HAS_SCORE` 566,912 | O C |
| `cvssData.version`, `cvssData.baseScore` | `Score.version`, `baseScore` | O C |
| derived | `Score.scoreId` (`<cveId>_<version>`), `Score.cveId` | O C (`cveId` none in `cvss:`) |
| `cvssData.vectorString` | `Score.vectorString` | **none** |
| `cvssData.baseSeverity` (3.x, 4.0) | `Score.baseSeverity` | **none** |
| `cvssMetricV2[].baseSeverity` (entry level, all 198,752 entries) | **not read**: `Score.baseSeverity` is `''` on all 197,044 CVSS 2.0 nodes | none |
| **`source`, `type`** of the selected entry | **dropped** | none (matrix v1.2: "planned, candidate ADR") |
| the other 83,475 entries of a (CVE, version) | dropped, not counted by the loader | none |
| `exploitabilityScore`, `impactScore`, vector components (6 to 33 fields per version), CVSS 2.0 flags | dropped | none |

### 3.4 `load_kev.py`, `load_epss.py`, `load_ssvc.py` (decision extension)

| Upstream field | Graph | Spec |
| --- | --- | --- |
| KEV: 12 entry fields (1,766 entries) | `KevEntry` 1,765 with all 12 (`cwes` absent on the 175 entries whose list is empty) plus `catalogVersion`, `dateReleased` | O C |
| KEV: `title`, `count` | not stored (`count` is a loader check) | excluded (matrix v1.2) |
| KEV entry whose CVE is not in NVD (1: CVE-2026-118527) | dropped, counted | by rule |
| EPSS: `cve`, `epss`, `percentile`, header `model_version`, `score_date` (398,784 rows) | `EpssScore` 398,784, 7 properties; 0 rows dropped | O C |
| SSVC: `ssvcData.options[]`, `timestamp`, `id`, `version`, `role`, entry `source` (230,669 entries) | `SsvcDecision` 210,258 (230,383 ADP entries, 20,125 exact duplicates collapsed) | O C |
| SSVC entries of non-ADP sources (286, 8 sources) | dropped, counted per source | excluded (ADR-0003 D3) |

### 3.5 `load_cwe.py` and `consequences.py`: CWE 5.0 catalog and NVD `weaknesses[]`

| Upstream field (presence, 984 Weakness elements) | Graph | Spec |
| --- | --- | --- |
| `@ID`, `@Name`, `@Abstraction`, `@Structure`, `@Status` | `Weakness.cweId`, `name`, `abstraction`, `structure`, `status` | O C |
| `Description`, `Extended_Description` (178) | `description`, `extendedDescription` (178) | O C |
| `Mapping_Notes/Usage`, `/Reasons/Reason/@Type` | `mappingUsage`, `mappingReasons` | O C |
| `Alternate_Terms` (129), `Likelihood_Of_Exploit` (184), `Functional_Areas` (119), `Affected_Resources` (115), `Modes_Of_Introduction` (956), `Weakness_Ordinalities` (942) | `alternateTerms` 129, `likelihoodOfExploit` 184, `functionalAreas` 119, `affectedResources` 115, `modesOfIntroduction` 954, `ordinalities` 942 | O C |
| `Common_Consequences/Consequence` (1,278 records) | `Consequence` 1,278 with `scopes`, `impacts`, `likelihood`, `note`; `HAS_CONSEQUENCE` 1,278 | O C |
| **`Related_Weaknesses`** (948 weaknesses, 1,622 rows: ChildOf 1,324, CanPrecede 148, PeerOf 103, CanAlsoBe 28, Requires 13, Overlaps 3, StartsWith 3) | **dropped**; no Weakness to Weakness relationship exists | none ("out of scope" in the enrichment mapping) |
| `Related_Attack_Patterns` (336) | not read here; `DEMONSTRATED_BY` is written from the CAPEC side | O C |
| `Dimensions/Dimension` (new in 5.0: 360 rows on 107 weaknesses, 17 types), `Technical_Nuance` (new, 53), `@Diagram` (89) | dropped | none |
| `Applicable_Platforms` (956), `Potential_Mitigations` (692), `Detection_Methods` (605), `Observed_Examples` (596), `Demonstrative_Examples` (604), `Taxonomy_Mappings` (651), `Background_Details` (177), `Notes` (377), `References` (629), `Content_History` | dropped | none |
| `Groupings` (431, new in 5.0; the 422 Categories of 4.20 plus 9), `Views` (62), `External_References` (1,081) | dropped | none |
| NVD `weaknesses[].description[].value` naming a loaded Weakness | `CAUSED_BY` 362,316, one per (CVE, CWE) | O C |
| NVD `weaknesses[].source`, `.type` | `CAUSED_BY.sources`, `sourceRoles`, `types` on every edge | C (reified in OWL) |
| values `NVD-CWE-Other`, `NVD-CWE-noinfo` (66,975 entries) | dropped, counted | by rule |
| values naming a Grouping or View (14,496 entries, 43 ids) | dropped, counted | by rule |

### 3.6 `load_capec.py`: CAPEC 3.9 (615 Attack_Pattern elements)

| Upstream field | Graph | Spec |
| --- | --- | --- |
| `@ID`, `@Name`, `@Status`, `@Abstraction` | `AttackPattern.capecId`, `name`, `status`, `abstraction` | O C |
| `Likelihood_Of_Attack` (345), `Typical_Severity` (490) | `attackLikelihood` 345, `typicalSeverity` 490 | O |
| `Consequences/Consequence` | `Consequence` 814; `HAS_CONSEQUENCE` 814 | O C |
| `Related_Weaknesses` (1,214 rows, 1,212 pairs) | `DEMONSTRATED_BY` 1,212 (every CWE id is a loaded Weakness) | O C |
| `Related_Attack_Patterns` ChildOf (533) | `CHILD_OF` 533 | O C |
| `Related_Attack_Patterns` CanPrecede 162, PeerOf 19, CanFollow 10, CanAlsoBe 3 | dropped | O (`capec:canPrecede` etc. declared, not loaded) |
| `Description`, `Extended_Description` (130), `Prerequisites` (490), `Mitigations` (400), `Execution_Flow` (239), `Skills_Required` (296), `Resources_Required` (272), `Example_Instances` (269), `Indicators` (56), `Alternate_Terms` (17), `References`, `Notes` | dropped | O for most (declared in the frozen CAPEC module, not loaded) |
| `Taxonomy_Mappings` ATTACK (272 rows) | read by `load_attck.py` | O C |
| `Taxonomy_Mappings` OWASP (39), WASC (37); `Categories` (78), `Views` (13) | dropped | O (classes declared, not loaded) |

### 3.7 `load_attck.py`: ATT&CK STIX, three bundles

| Upstream field | Graph | Spec |
| --- | --- | --- |
| live `attack-pattern` (383 techniques, 552 sub-techniques), `x-mitre-tactic` (39) | `Technique` 383, `SubTechnique` 552, `Tactic` 39 | O C |
| `external_references[mitre-attack].external_id`, `name` | `attackId`, `name` | O C |
| `description` | `description`, **cut at 1,000 characters** (210 techniques and 372 sub-techniques are longer) | external (`dct:description`) |
| bundle file name | `domains` | O C |
| `x_mitre_shortname` (tactic) | `Tactic.phaseName` | O C |
| `kill_chain_phases` | `PART_OF` 441 (techniques only) | O C |
| `relationship` subtechnique-of | `SUBTECHNIQUE_OF` 552 | O C |
| CAPEC taxonomy mappings plus STIX capec references | `IMPLEMENTS` 244 (47 remapped, 3 dropped as deprecated *(etl.log)*) | O C |
| revoked or deprecated objects | skipped: 575 *(etl.log)* | by rule |
| `x_mitre_platforms`, `x_mitre_version`, `created`, `modified`, `x_mitre_contributors`, `x_mitre_tactic_type`, `x_mitre_impact_type`, `x_mitre_remote_support`, tactic `description` | dropped | O for some (declared, not loaded) |
| every other object type: `relationship` uses 20,847, mitigates 2,068, targets 933, detects 931, attributed-to 32; `malware` 909, `course-of-action` 336, `intrusion-set` 231, `tool` 97, `campaign` 71, `x-mitre-analytic` 2,283, `x-mitre-detection-strategy` 935, `x-mitre-data-component` 174, `x-mitre-data-source` 61, `x-mitre-asset` 18 | dropped | classes partly declared, not loaded |

### 3.8 `load_atlas.py`: ATLAS 2026.09

| Upstream field | Graph | Spec |
| --- | --- | --- |
| tactics 16, techniques 208, mitigations 40 with `id`, `name`, `description`, `created-date`, `modified-date`, `maturity`, `platforms`, `categories`, `lifecycle-phases`, matrix position | `AtlasTactic` 16, `AtlasTechnique` 120, `AtlasSubTechnique` 88, `AtlasMitigation` 40, all listed properties on every node | O C |
| relationships achieves, specializes, mitigates; technique `attack-reference` (44) | `ACHIEVES` 225, `SPECIALIZES` 88, `MITIGATES` 361, `ADAPTED_FROM` 44 with three edge properties | O C |
| case studies (73), `employs`, tactic `attack-reference` (14), mitigation `attack-reference` (4), `references`, `uuid` | dropped | excluded (matrix v1.2) |

### 3.9 `load_d3fend.py`, `load_car.py`, `load_shield.py`, `load_engage.py`

| Upstream field | Graph | Spec |
| --- | --- | --- |
| D3FEND `def_tech`, `def_tech_label`, `off_tech_id` (13,574 rows, 145 techniques, 3,109 distinct pairs) | `DefensiveTechnique` 145 (`d3fendId`, `name`); `MITIGATED_BY` 3,087 (88 remapped, 11 dropped as deprecated *(etl.log)*) | O C |
| D3FEND IRI fragment | `DefensiveTechnique.fragment` | **none** |
| D3FEND the other 23 binding fields (defensive tactic, artifacts, relations), the ontology itself | dropped | O for some (declared, not loaded) |
| CAR `id`, `title` (102 analytics) | `DetectionAnalytic.analyticId`, `title` | O C |
| CAR `description` | `description`, **cut at 500 characters** (57 of 102 are longer) | none in `car:` |
| CAR `platforms` | `platform` (one comma-joined string) | none under that name (`car:applicablePlatforms` declared) |
| CAR `coverage[]` (291 distinct pairs) | `DETECTED_BY {coverageLevel}` 278; **13 pairs to revoked or deprecated ATT&CK ids dropped, not counted** | O C |
| CAR `submission_date`, `information_domain`, `subtypes`, `analytic_types`, `contributors`, `implementations` (99), `d3fend_mappings` (100), `data_model_references` (91), `unit_tests` (38); 13 data-model and 7 sensor files | dropped | O for some (declared, not loaded) |
| SHIELD `techniques.json` `id`, `name`, `description` (33) | `DeceptionTechnique.techniqueId`, `name`, `description` (longest 160, the 500 cut never applies) | O C (`description` none) |
| SHIELD `attack_mapping.json` (261 distinct pairs) | `COUNTERED_BY` 255; **6 pairs dropped, not counted** (4 revoked or deprecated ids, 2 ids in no bundle) | O C |
| SHIELD `long_description`, tactics (8), opportunities (81), use cases (198), procedures (65), attack groups (109) | dropped | O for some (declared, not loaded) |
| ENGAGE activities 31, approaches 9, goals 5 with `id`, `name`, `description` | `EngagementConcept` 45 (`activityId` 31, `approachId` 9, `goalId` 5, `name`, `description`) | O C (`description` none) |
| ENGAGE `attack_mapping.json` (596 distinct pairs) | `DISRUPTS` 593; **3 pairs to revoked or deprecated ids dropped, not counted** | O C |
| ENGAGE `long_description`, goal / approach / activity mappings (9 + 51), references (67), EAVs | dropped | O for some (declared, not loaded) |

### 3.10 `build_metadata.py`

`BuildMetadata` holds `specVersion`, `buildTimestamp`, `pipelineCommit` and 13
`sourceSnapshots` (O C). No loader counter is stored in the graph.

## 4. Findings outside the candidate list

These came out of building the matrix. None needs a spec change except F-4.

| Id | Finding | Evidence | Fix |
| --- | --- | --- | --- |
| F-1 | ATT&CK `description` is cut at 1,000 characters (`load_attck.py:522`). | 210 of 383 `Technique` and 372 of 552 `SubTechnique` nodes have exactly 1,000 characters; the bundles have the same 210 and 372 longer descriptions. | Remove the slice. Pipeline only. |
| F-2 | CAR `description` is cut at 500 (`load_car.py:83`). The same slice in `load_shield.py:88` and `load_engage.py:134` never applies today. | 57 of 102 nodes have exactly 500 characters. | Remove the three slices. |
| F-3 | `Score.baseSeverity` is `''` on all 197,044 CVSS 2.0 nodes. NVD puts the 2.0 severity on the metric entry, not in `cvssData`. | Graph count; raw key inventory. | Read the entry-level field for 2.0. |
| F-4 | CWE 5.0 has a second value outside the spec vocabularies: mapping reason `Frequently-Resultant` on 3 weaknesses (CWE-668, CWE-804, CWE-1461). It is absent from CWE 4.20. No post-load check covers the Weakness enumerations, so the build reported only the 3 consequence violations. | Graph; both catalogs; `cwe.shacl.ttl` `ReasonEnumeration` (12 values). | Spec vocabulary (candidate c) and a post-load check. |
| F-5 | `Vulnerability.lastModified` goes backwards when the year file is older than the modified feed: `ON MATCH SET` overwrites the value written from the modified feed. | 6 CVEs in this build, e.g. CVE-2023-42756: graph `2026-06-17T06:24:27.037`, modified feed `2026-11-01T11:18:55.300`. | Keep the greater value (the rule `load_cwe.py` already applies). |
| F-6 | Absent optional values are stored as empty strings, not left out: the four version bounds and `cpeLastModified` on `PlatformConfiguration`. | `versionStartExcluding` is non-empty on 607 of 672,683 nodes but present on all. | Send `null`. Changes property presence, so decide with the spec (shapes say nothing). |
| F-7 | CAR, SHIELD and ENGAGE have no revoked-by remap and no drop counter (D3FEND has both). | 13 + 6 + 3 = 22 mappings lost; the graph counts equal the raw pairs minus these. | Reuse `attck_revocations.py`, count the drops. |
| F-8 | Graph properties the spec does not define: `Score.baseSeverity`, `Score.vectorString`, `Platform.deprecated`, `DefensiveTechnique.fragment`, `DetectionAnalytic.description` and `.platform`, `DeceptionTechnique.description`, `EngagementConcept.description`, ATT&CK `description`. | Section 3. | Declare the two `Score` properties in v1.3.0 (candidate e); list the rest in the coverage matrix. |
| F-9 | `Reference.source` keeps one source per URL although 62.3 % of URLs have several, and reference tags are dropped. | 569,662 of 914,479 URLs; 1,302,926 tagged entries. | Not proposed now; a `REFERENCES` edge property would be the place. |

## 5. Candidates

Cost columns: **Spec** (module, shape, contract, ADR), **Loader**, **Tests**,
**Load and store** (estimates, nothing was loaded), **Older builds**.

### a. `Vulnerability.vulnStatus`: do now

Measured: the property is absent from all 417,654 nodes; the feed has it on every
record with 7 values (section 2). 18,839 nodes have no relationship; computed
from the raw feed, exactly 18,839 CVEs have no reference, configuration, score,
mapped weakness, ADP SSVC entry, EPSS row or KEV entry, and all are `Rejected`.
A random sample of 150 isolated nodes from the graph: 150 Rejected in the feed.
The other 20 Rejected CVEs keep `CAUSED_BY` edges and nothing else.

| | |
| --- | --- |
| Spec | New module `ontology/standards/cve-enrichment-v1.0.owl` (namespace `cve:`), property `cve:vulnStatus`, shared with candidate g. `shapes/cve.shacl.ttl`: one property shape, `sh:in` with the 7 observed values. Companion mapping `cve-enrichment-to-owl-v1.0.md`. Contract: `vulnStatus` on the Vulnerability line and a note that Rejected records carry no decision or applicability data. No ADR (precedent: `cwe-enrichment-v1.0.owl` in v1.1.0). |
| Loader | `load_cve.py`: one field; SET on create and on match under the newest-record rule (fixes F-5 in the same statement). About 10 lines. |
| Tests | 2 unit tests; post-load checks `vuln_status_present` and `isolated_vulnerabilities_are_rejected`; expected count per status from raw. |
| Load and store | No extra pass. Under 10 MB *(estimate)*. |
| Older builds | Additive. Counts and keys unchanged. Older builds cannot answer status questions. |

### b. CWE parent / child hierarchy as edges: do now, needs an ADR

Measured: no Weakness to Weakness relationship exists; `CHILD_OF` has 533
edges, all AttackPattern to AttackPattern. The catalog has 1,324 `ChildOf` rows
on 947 weaknesses, 1,176 distinct (child, parent) pairs, every parent a loaded
Weakness (0 dangling).

| View | Pairs | Note |
| --- | ---: | --- |
| 1000 Research Concepts | 1,106 | 946 of 984 weaknesses have a parent here; 152 have two or more |
| 1003 Simplified Mapping (the view NVD maps to) | 93 | |
| 1340 | 52 | |
| 1305 | 48 | |
| 700 | 24 | |
| 928 | 1 | |
| Distinct over all views | 1,176 | 70 pairs exist only outside view 1000 |

View dependence is real: the hierarchy is a different graph per view, and even
inside view 1000 it is a DAG, not a tree.

| | |
| --- | --- |
| Spec | New module `ontology/standards/cwe-hierarchy-v1.0.owl`: object property `cwe:child_of` (Weakness to Weakness) and, following ADR-0002, a statement class carrying index-aligned lists `viewIds` and `ordinals`. One edge per pair, the views as edge property: `WHERE '1000' IN r.viewIds`. **A new relationship type name, not `CHILD_OF`**: `check_graph_quality.py` and `expected_graph_deltas.py` count `CHILD_OF` unqualified, the reason ATLAS got its own names in v1.2.1. Working name `WEAKNESS_CHILD_OF`. Shape (endpoints, no self-loop, list alignment), mapping doc, contract relationship plus an invariant: the edge is declared by MITRE, stays inside the CWE hop, and a template that walks it names it in `provenance`. **ADR-0006** (name, all views with a property versus view 1000 only, the other six relation natures left out). |
| Loader | `load_cwe.py`: read `Related_Weaknesses` in `_weakness_record`, write after every Weakness exists (the CAPEC ordering lesson). About 50 lines. |
| Tests | 4 unit tests; expected count from the XML (1,176); post-load checks for the endpoints (the new type touches only Weakness nodes) and for self-loops. |
| Load and store | Under 1 second; 1,176 edges. |
| Older builds | Every existing type keeps its count; the total relationship count grows by 1,176. |

Not an inferred shortcut: each edge is one source row. Inheriting a CAPEC
mapping from a parent weakness would be inference and stays a query-time
decision, as `inherited_via_parent_capec` already is for CAPEC.

### c. CWE 5.0 vocabulary and the Category to Grouping change: vocabulary do now, Groupings defer

Measured: the failing check counts 3 Consequence nodes; read from the graph they
are CWE-1260-C1 and CWE-1476-C1 (`DoS: Prevent Access`) and CWE-1335-C2
(`Undefined Behavior`). The catalog uses 27 impact values; the shape and the XSD
on disk have 25. Plus F-4: `Frequently-Resultant`. The other nine Weakness
enumerations in the graph are inside the spec lists.

CWE 5.0 structure against 4.20: Weaknesses 969 to 984 (15 added, 0 removed);
`Categories` 422 to 0; `Groupings` 0 to 431 (the same 422 ids plus 9 new);
Views 59 to 62; new per-weakness `Dimensions` (360 rows, 395 `Dimension`
elements catalog-wide) and `Technical_Nuance` (53). KGCS never loaded
Categories, so the rename breaks nothing. It only changes what the dropped
`CAUSED_BY` ids are called (candidate d).

| | |
| --- | --- |
| Spec | `shapes/cwe.shacl.ttl`: `TechnicalImpactEnumeration` 25 to 27 and `ReasonEnumeration` 12 to 13, re-derived from the v8.0 XSD, which is not on disk (`data/schemas/CWE/cwe_schema_latest.xsd` is v7.3). The frozen `cwe-consequences-v1.0.owl` comment lists the 25 values: leave it and state that the shape is normative, the register already used for `build:source_snapshot`. Matrix and mapping docs: "Categories" becomes "Categories (4.x) / Groupings (5.0)". No ADR. |
| Loader | `consequences.py` tuple plus 2; refresh the XSD with `download_schemas.py`; one new post-load check for the Weakness enumerations. |
| Tests | `test_consequences.py` asserts 25: update to the pinned spec. |
| Load and store | None. The values are already loaded verbatim. |
| Older builds | No graph change. The check turns green on the next build. |

Groupings as nodes (431, with 4,350 view-scoped `Has_Member` rows) and
`Dimensions` as properties: defer. That is a new class with its own ADR, and no
current query needs it.

### d. Accounting for dropped `CAUSED_BY` pairs: counters do now, per-CVE trace defer

Measured, two ways of counting:

| | As the loader counts (every record of every file) | Per distinct (CVE, value), newest record |
| --- | ---: | ---: |
| `NVD-CWE-noinfo` | 36,935 | 36,423 |
| `NVD-CWE-Other` | 30,040 | 30,000 |
| Placeholders | **66,975** | **66,423** |
| Ids naming a Grouping (40 ids) | 14,481 | 14,399 |
| Ids naming a View (3 ids: CWE-701, CWE-702, CWE-1026) | 15 | 14 |
| Not a Weakness | **14,496** | **14,413** |

The loader figures match the build log. They are higher because 23,643 CVEs
appear in both the modified feed and a year file and are counted twice. The top
five ids hold 88.6 % of the entries: CWE-264 5,518, CWE-399 2,700, CWE-310 2,548,
CWE-189 1,280, CWE-255 791. All 40 Grouping ids were Categories in CWE 4.20.

Effect per CVE (93,760 without `CAUSED_BY`): 27,046 have no weakness value at
all, 53,536 only placeholders, 12,708 only Grouping or View ids, 470 both.
So 13,178 CVEs (3.2 %) have a CWE assertion in NVD that the graph does not show.

| Option | Verdict |
| --- | --- |
| Store the counters in `BuildMetadata`, counted per distinct pair (candidate f) and report them in the paper | **Do now.** No chain change. |
| Keep the ids on the node (`Vulnerability.unmappedWeaknessIds`, string list) | Defer. Cheap in the loader, but it needs a decision on name and meaning; it fits `cve-enrichment` later. |
| `CAUSED_BY` to a Grouping node | Drop. `CAUSED_BY` targets `Weakness` (SH-CORE). |
| Map a Grouping to its member weaknesses | Drop. Inference. |

Loader: count through `_NewestRecordRule` so that a CVE is counted once (about
15 lines, 2 tests). Wording: "Categories/Views" becomes "Groupings/Views".

### e. Provenance on `Score`: do now, as properties on the selected entry

Measured (newest record per CVE; the loader keeps the first record seen, which
differs for at most 6 CVEs):

| CVSS | Score nodes | from `Primary` | from `Secondary` | entries not loaded |
| --- | ---: | ---: | ---: | ---: |
| 2.0 | 197,044 | 180,075 | 16,969 | 123 |
| 3.0 | 54,791 | 41,457 | 13,334 | 1,807 |
| 3.1 | 270,647 | 154,451 | 116,196 | 81,541 |
| 4.0 | 44,430 | 5 | 44,425 | 4 |
| Total | 566,912 | 375,988 | 190,924 | 83,475 |

By role of the selected entry: NVD 374,883, CNA 166,078, CISA ADP 25,951. Of the
83,475 entries not loaded (on 82,699 CVEs): CNA 61,823, ADP 19,234, NVD 2,418.
Spot check in the graph: CVE-2024-0181 holds the NVD 4.8 and not the CNA 2.4;
CVE-2024-0056 holds a CNA 8.7 with nothing to mark it as such.

| | |
| --- | --- |
| Spec | New module `ontology/standards/cvss-provenance-v1.0.owl`: `cvss:source`, `cvss:sourceRole` (`nvd` / `cna` / `adp`, the ADR-0002 list), `cvss:type` (`Primary` / `Secondary`), and the two properties the loader already writes undeclared, `cvss:baseSeverity` and `cvss:vectorString`. Shape with closed vocabularies. Contract Score line. **ADR-0007** (short): annotate the selected entry and keep one Score per (CVE, version); the matrix already lists this as "candidate ADR". |
| Loader | `load_cvss.py`: three fields, SET on match as well (today `ON CREATE` only), the 2.0 severity fallback (F-3), a counter for entries not selected. About 25 lines. |
| Tests | 3 unit tests; post-load check that every Score has the three properties; expected distribution from raw. |
| Load and store | No extra pass. 15 to 25 MB *(estimate)*. |
| Older builds | Additive. `Score` count and `scoreId` unchanged. `baseSeverity` changes on 197,044 nodes from `''` to a value. |

One Score per metric entry (plus 83,475 nodes, a new `scoreId` pattern, and the
"no duplicate version per CVE" check gone): defer. It breaks the key and every
count comparison, and belongs to a major release if it is ever wanted.

### f. Loader drop counters in `BuildMetadata`: do now

Measured: KEV 1 dropped (CVE-2026-118527, in the catalog and in no NVD file);
EPSS 0; SSVC 286 entries from 8 sources, none of them the declared ADP.

| SSVC source | Entries | Shape |
| --- | ---: | --- |
| `9119a7d8-…` (CISA acting as CNA) | 184 | role `CISA Coordinator`, with timestamp |
| 7 other sources | 102 | role `CNA` in the 3 entries read; the roles of the rest were not tabulated |

**ADR-0003 requires the filter**: D3 "v1.0 scope: declared ADPs only";
alternative A8 (load all sources) rejected; open question 1 resolved to
"declared ADPs only"; the matrix lists non-ADP entries under Exclusions. One
detail has moved since the ADR was written: it says CNA-role entries have no
timestamp, but only 64 of the 286 lack one (and 100 lack `id`), so at least 38
CNA entries are keyable today. That is material for reopening question 1, not a
loader defect.

Today the counters exist only in `etl.log` and in the hand-built `summary.json`.

| | |
| --- | --- |
| Spec | New file `ontology/extensions/build-metadata-v1.1.owl` (v1.0 is sealed; this also fixes the stale comment the matrix records as "OWL v1.1 candidate") with `build:load_counter`. Graph: `BuildMetadata.loadCounters`, a string list `<STEP>.<counter>=<n>` in the style of `sourceSnapshots` (a node property cannot be a map). `shapes/build.shacl.ttl`: pattern and one value per key. Contract line. A counter vocabulary in the matrix. No ADR. |
| Loader | `run_all_etl.py` passes each step's stats to `run_build_metadata`; a step run alone replaces only its own keys. Missing counters to add: CVSS entries not selected, CAR / SHIELD / ENGAGE drops (F-7), `CAUSED_BY` per distinct pair (d). About 80 lines. |
| Tests | 4 unit tests (formatting, merge by step); post-load check that the counters equal the offline expected values. |
| Load and store | None. |
| Older builds | Additive. Older builds keep their counters in `etl.log` only. |

Proposed first vocabulary: `KEV.dropped_no_vulnerability`,
`EPSS.dropped_no_vulnerability`, `SSVC.dropped_non_adp`,
`SSVC.duplicates_collapsed`, `SSVC.dropped_no_vulnerability`,
`CVSS.entries_not_selected`, `CWE.caused_by_placeholder`,
`CWE.caused_by_not_a_weakness`, `ATTCK.skipped_revoked`,
`ATTCK.implements_dropped_deprecated`, `ATTCK.implements_unresolved`,
`D3FEND.mitigated_by_dropped_deprecated`, `CAR.detected_by_dropped`,
`SHIELD.countered_by_dropped`, `ENGAGE.disrupts_dropped`.

### g. `Vulnerability.description`: do now

Measured: every CVE has exactly one English description (417,654; none missing,
none with two); 316,249 also have a Spanish one. English text: 148,218,307
characters, 148,284,418 bytes in UTF-8; mean 355, median 263, 95th percentile
854, 99th 1,832, longest 3,998. The 18,859 that start with "Rejected reason"
are exactly the Rejected records.

| | |
| --- | --- |
| Spec | `cve:description` in the same `cve-enrichment-v1.0.owl` as candidate a. Shape: one string, required. Mapping rule: the `en` value verbatim, no truncation and no flattening; `es` is listed under Exclusions. Contract line. No ADR. |
| Loader | `load_cve.py`: one field in the same statement as `vulnStatus`. |
| Tests | 2 unit tests; post-load check `vulnerability_description_present`; a length check against raw on a sample, so that a silent cut like F-1 cannot recur. |
| Load and store | No extra pass; about 148 MB more payload in the cve step, 1 to 3 minutes on a 28-minute step *(estimate)*. Store plus 150 to 250 MB on 4.78 GB, 3 to 5 % *(estimate)*. No full-text index is proposed. |
| Older builds | Additive. |

### h. `stats.json` and `summary.json` omissions: do now, pipeline only

Measured: `validation/extract_neo4j_stats.py` has fixed lists. They lack the
labels `VulnerabilityConfiguration` (778,251) and
`VulnerabilityConfigurationNode` (1,228,978), and the types `HAS_CONFIGURATION`
(778,251), `HAS_NODE` (1,228,978), `MATCHES_CRITERIA` (3,275,711) and `CHILD_OF`
(533). `stats.json` therefore reports 5,054,003 of 7,061,232 nodes (28.4 %
missing) and 37,323,073 of 42,606,546 relationships (12.4 % missing).
`summary.json` was completed by hand: it has all 25 labels and `CHILD_OF`, and
lacks the three applicability types (5,282,940 relationships).

| | |
| --- | --- |
| Spec | None. All six names are already in the contract. |
| Change | Count what the graph has (`db.labels()`, `db.relationshipTypes()`), then fail if a label or type is in the graph and not in the contract, or the reverse. Generate `summary.json` from it. About 40 lines, 2 tests. |
| Load and store | None. No reload: the corrected script can be run against `kgcs-2026-11` today, read-only. |
| Older builds | Their `stats.json` files stay incomplete; rerun the script on the databases that are still online (`kgcs-v12`, `kgcs-demo`). |

## 6. Proposed release: kgcs-spec v1.3.0

Minor release, additive, no frozen file touched, no new chain hop, no inferred edge.

| # | Artifact | Covers |
| --- | --- | --- |
| 1 | `ontology/standards/cve-enrichment-v1.0.owl`: `cve:vulnStatus`, `cve:description` | a, g |
| 2 | `ontology/standards/cvss-provenance-v1.0.owl`: `cvss:source`, `cvss:sourceRole`, `cvss:type`, `cvss:baseSeverity`, `cvss:vectorString`; ADR-0007 | e, F-8 |
| 3 | `ontology/standards/cwe-hierarchy-v1.0.owl`: `cwe:child_of` with view provenance; ADR-0006 | b |
| 4 | `ontology/extensions/build-metadata-v1.1.owl`: `build:load_counter` | f, d |
| 5 | `shapes/`: `cve`, `cvss`, `cwe` (hierarchy shape; impacts 27, reasons 13), `build` | a, b, c, e, f, g |
| 6 | `mappings/`: `cve-enrichment-to-owl-v1.0.md`, `cvss-provenance-to-owl-v1.0.md`, `cwe-hierarchy-to-owl-v1.0.md`, `mapping-coverage-matrix-v1.3.md` with the counter vocabulary and new Exclusions rows (Groupings and Dimensions, per-CVE unmapped ids, one Score per entry, `es` descriptions, reference tags, `cveTags`) | all |
| 7 | `contracts/agent-consumable-schema.md` and `.json`: additive lines and definitions | a, b, e, f, g |
| 8 | Fixtures: a focus node per new shape and at least one negative each (about 8 to 10 new negatives) | rule |

Upgrade note to write: the Vulnerability and Score shapes become stricter
(`vulnStatus`, `description`, score provenance required), as `Weakness` did in
v1.1.0. A v1.2 graph does not validate against v1.3 shapes and stays valid
against its own pin, which `BuildMetadata.specVersion` records.

**Scope decision (HC, 2026-11-14): item 3, the CWE hierarchy edges, stays in
v1.3.0.** ADR-0006 still has to settle the relationship name and the view policy.

Had the release needed to shrink, item 3 would have gone first: it is the only one
whose ADR has an open naming question, and nothing else depends on it. Items 1, 4 and the
vocabulary lines of 5 are the floor: without them the next build repeats the
red check and the unexplained isolated nodes.

Not in the release: h, F-1, F-2, F-3, F-5, F-7 (pipeline only, in the pin-bump
branch). The existing unreleased commit on kgcs-spec (`0bc9944`, ADR-0005,
Proposed) would ship with the tag as it stands.

Order: spec branch, ADR-0006 and ADR-0007 accepted, harness green, tag `v1.3.0`;
then pipeline branch, `SPEC_VERSION` 1.3.0, loaders, tests; then the reload.

## 7. Effort and reload (estimates)

| Work | Days |
| --- | ---: |
| Spec: `cve-enrichment` (module, shape, mapping, contract, fixtures) | 0.5 |
| Spec: `cvss-provenance` and ADR-0007 | 0.75 |
| Spec: `cwe-hierarchy` and ADR-0006 | 1.0 |
| Spec: vocabulary from the v8.0 XSD | 0.25 |
| Spec: `build-metadata-v1.1` and counter vocabulary | 0.5 |
| Spec: matrix v1.3, changelog, README files, harness, tag | 0.75 |
| **Spec total** | **3.75** |
| Pipeline: `load_cve.py` (a, g, F-5) | 0.5 |
| Pipeline: `load_cvss.py` (e, F-3) | 0.5 |
| Pipeline: `load_cwe.py` (b, d, vocabulary) | 0.75 |
| Pipeline: counters through `run_all_etl.py` and `build_metadata.py` (f, F-7) | 1.0 |
| Pipeline: stats script (h), truncation fixes (F-1, F-2) | 0.5 |
| Pipeline: expected-count scripts and post-load checks for the new items | 0.75 |
| Pipeline: pin bump, full test run, dry run on a scratch database | 0.5 |
| **Pipeline total** | **4.5** |
| **Both repos** | **about 8 to 9** |

Reload, taking 2026-11-01 as the reference:

| Phase | 2026-11-01 | Next build |
| --- | --- | --- |
| Download, preflight, offline expected counts | 18:30 to 19:47 (about 75 min, including the aborted first attempt of finding F5) | 60 to 75 min |
| ETL | 109 min | 110 to 115 min: the description payload adds 1 to 3 min; the other items add no pass |
| Post-load, sample, evidence | 21:36 to 21:56 (about 20 min) | 25 to 30 min with the new checks |
| **End to end** | about 3 h 25 | **about 3.5 h** |
| Store | 4.78 GB plus 2.36 GB transaction logs | about 5.0 GB plus logs |

The cpe step is 65 % of the ETL time and nothing proposed here touches it.

## 8. Not verified

- **Load time and store size.** Every figure in the "Load and store" rows and in
  section 7 is an estimate. Nothing was loaded; no scratch database was built.
- **Store size** was read from the store files on disk, not
  from Neo4j (`apoc.monitor.store` is not installed).
- **The CWE 5.0 schema.** `cwe_schema_v8.0.xsd` is not on disk. The 27 impact
  values and 13 reasons are the values present in the catalog, not the full
  enumerations. The same applies to `vulnStatus`: 7 values observed, and the NVD
  JSON schema types it as a free string.
- **Property values were compared with the raw feed on samples only**: 150
  isolated nodes, 7 CVEs for scores and `CAUSED_BY`, 6 CVEs for `lastModified`,
  3 consequences. Counts and property presence were checked on every node.
  EPSS, KEV and SSVC property values were not compared record by record.
- **Taken from `etl.log`, not recomputed:** ATT&CK revoked objects skipped (575),
  `IMPLEMENTS` remapped and dropped (47, 3), `MITIGATED_BY` remapped and dropped
  (88, 11), the ATLAS exclusion counts. For D3FEND only the 3,109 distinct raw
  pairs were recomputed, not the path to 3,087.
- **Not recomputed from raw:** the relationship types `PART_OF`,
  `SUBTECHNIQUE_OF`, `IMPLEMENTS`, `MITIGATED_BY`, `ACHIEVES`, `SPECIALIZES`,
  `MITIGATES`, `ADAPTED_FROM`, and the split of the 208 ATLAS techniques into
  120 techniques and 88 sub-techniques. Their graph counts equal the build's
  own evidence (`compare-v12`, `graph-quality`), which was not rerun.
- **Score selection statistics** use the newest record per CVE; the loader keeps
  the first record seen. They can differ for the 6 CVEs with two different records.
- **Tests were not run** in either repository. The harness size after v1.3.0
  (151 tests and 55 negatives at v1.2.1 according to the changelog) is not estimated.
- **Consumers.** `kgcs-server` and the `kgcs-research` snapshot and gate scripts
  were not read. "Older builds stay comparable" rests on the pipeline's own
  validation scripts and on the fact that no existing label, type, key or count changes.
- **Older builds.** Only `kgcs-2026-11` was measured. Whether `kgcs-v12` and
  `kgcs-demo` show the same drops and truncations was not checked.
- **ADR-0005** (unreleased commit after `v1.2.1`) was not read.
- **Whether the six relation natures other than ChildOf** (CanPrecede, PeerOf,
  and so on) are wanted was not evaluated beyond counting them.

## 9. How the numbers were produced

- Graph: read-only Cypher through the `kgcs-v12` connector with
  `USE kgcs-2026-11`: counts per label and type, `keys()` over every node of
  each label, endpoint labels and property keys per relationship type, and the
  targeted queries quoted in the text.
- Raw feeds: throwaway Python scripts that read `data/raw` the way the
  loaders do (modified feed first, then year files): four passes over the CVE
  feed, one over CPE and CPE-MATCH, one over the CWE and CAPEC catalogs, plus
  inline inventories of the ATT&CK, ATLAS, D3FEND, CAR, SHIELD, ENGAGE and KEV
  files. They are not part of the repository.
- CWE 4.20 comparison: the `cwec_v4.20.xml` catalog of the 2026-09-06 raw snapshot (kept outside this repository).
- Spec: the materialized `spec/` at tag `v1.2.1`.
