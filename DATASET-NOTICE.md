# Notice for the KGCS graph datasets

This notice applies to the Neo4j database dumps published as `dataset-*`
releases of this repository, and to any graph built with this pipeline.

The pipeline code is licensed under [Apache 2.0](LICENSE). **The data is not
ours.** A KGCS graph is a transformation into nodes and relationships of the
published sources listed below, each under its owner's terms. KGCS adds no
data of its own, computes no score and combines none: third-party values are
stored as published, with their date and version. NIST, MITRE, CISA and FIRST
do not endorse or certify KGCS or these datasets.

## Sources and terms

| Source | Owner | In the graph as | Terms | Text kept here |
| --- | --- | --- | --- | --- |
| CVE records, CVSS, CPE and CPE match criteria (NVD JSON 2.0 feeds) | NIST, National Vulnerability Database; the CVE List is run by the CVE Program | `Vulnerability`, `Score`, `Reference`, `Platform`, `PlatformConfiguration`, the vulnerability configuration nodes | NVD data is a NIST publication in the public domain; NVD asks for the notice below. CVE: [terms of use](https://www.cve.org/Legal/TermsOfUse) | `CVE-terms-of-use.html` |
| SSVC decisions (CISA Vulnrichment, carried in the NVD records) | CISA | `SsvcDecision` | [CC0 1.0](https://github.com/cisagov/vulnrichment/blob/develop/LICENSE) | `VULNRICHMENT-LICENSE.txt` |
| Known Exploited Vulnerabilities catalog | CISA | `KevEntry` | [CC0 1.0](https://github.com/cisagov/kev-data/blob/develop/LICENSE) | `KEV-LICENSE.txt` |
| EPSS scores | FIRST | `EpssScore` | [EPSS usage agreement](https://www.first.org/epss/): free use, attribution requested | — |
| CWE | The MITRE Corporation | `Weakness`, `Consequence` | [CWE terms of use](https://cwe.mitre.org/about/termsofuse.html) | `CWE-terms-of-use.html` |
| CAPEC | The MITRE Corporation | `AttackPattern`, `Consequence` | [CAPEC terms of use](https://capec.mitre.org/about/termsofuse.html) | `CAPEC-terms-of-use.html` |
| ATT&CK | The MITRE Corporation | `Tactic`, `Technique`, `SubTechnique` | [ATT&CK licence](https://github.com/mitre/cti/blob/master/LICENSE.txt) | `ATTACK-LICENSE.txt` |
| ATLAS | The MITRE Corporation | `AtlasTactic`, `AtlasTechnique`, `AtlasSubTechnique`, `AtlasMitigation` | [Apache 2.0](https://github.com/mitre-atlas/atlas-data/blob/main/LICENSE) | `ATLAS-LICENSE.txt` |
| D3FEND | The MITRE Corporation | `DefensiveTechnique` | [MIT](https://github.com/d3fend/d3fend/blob/gh-pages/LICENSE) | `D3FEND-LICENSE.txt` |
| CAR | The MITRE Corporation | `DetectionAnalytic` | [Apache 2.0](https://github.com/mitre-attack/car/blob/master/LICENSE.txt) | `CAR-LICENSE.txt` |
| ENGAGE | The MITRE Corporation | `EngagementConcept` | [Apache 2.0](https://github.com/mitre/engage/blob/main/LICENSE.md) | `ENGAGE-LICENSE.md` |
| SHIELD (retired by its owner) | The MITRE Corporation | `DeceptionTechnique` | [Apache 2.0](https://github.com/MITRECND/mitrecnd.github.io/blob/master/LICENSE) | `SHIELD-LICENSE.txt` |

The files of the last column are in [`third-party-licenses/`](third-party-licenses/),
copied unmodified from their owners. Where a source's terms ask that its
copyright designation and its licence accompany every copy (CVE, CWE, CAPEC,
ATT&CK), those files are that copy. The version of each source in a given
dataset is in the release notes and in the graph itself, on the single
`BuildMetadata` node (`sourceSnapshots`).

## Notices the owners ask for

- **NVD.** This dataset uses data from the NVD but is not endorsed or certified by the NVD.
- **EPSS.** See EPSS at https://www.first.org/epss.
- **KEV.** The use of KEV data here does not authorise the use of the CISA logo or the DHS seal and is not an endorsement by CISA or DHS. The third-party links inside KEV entries are bound by the policies of the sites they point to.
- **MITRE.** CVE, CWE, CAPEC, ATT&CK, ATLAS, D3FEND, CAR, ENGAGE and SHIELD are works and marks of The MITRE Corporation, used under the terms above.

## What was changed

Nothing was edited in the sources. The pipeline selects fields, renames them
to the property names of `kgcs-spec`, and writes them as a property graph; it
drops what the specification does not model. The loaders, the validation and
the evidence of each build are in this repository
([`docs/fresh-load.md`](docs/fresh-load.md)).

## If you redistribute a dataset

Keep this notice and the `third-party-licenses/` folder with it, and check
the owners' current terms: the links above are the authority, not this file.
