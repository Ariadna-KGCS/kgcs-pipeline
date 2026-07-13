# KGCS Data Schemas

This directory contains source schema definitions for all cybersecurity standards integrated into the KGCS (Cyber Knowledge Graph Core Schema) ontology system.

---

## Overview

Each subdirectory corresponds to a cybersecurity standard and contains the authoritative schema files that define the structure of that standard's data. These schemas are mapped to OWL ontologies in the `standards/` directory via the mapping documents in `mappings/`.

---

## Standards and Schemas

### CPE (Common Platform Enumeration)

- **Directory:** `CPE/`
- **Format:** XML
- **Purpose:** Platform and software identification
- **Mapping:** `mappings/cpe-cpematch-to-owl-v1.0.md`
- **Ontology:** `standards/cpe/cpe-ontology-v1.0.owl`
- **Key References:** National Vulnerability Database (NVD)

### CVE (Common Vulnerabilities and Exposures)

- **Directory:** `CVE/`
- **Format:** JSON/XML
- **Purpose:** Vulnerability identification and tracking
- **Mapping:** `mappings/cve-to-owl-v1.0.md`
- **Ontology:** `standards/cve/cve-ontology-v1.0.owl`
- **Key References:** MITRE CVE Program, NVD

### CWE (Common Weakness Enumeration)

- **Directory:** `CWE/`
- **Format:** XML
- **Purpose:** Software weakness and vulnerability root cause classification
- **Mapping:** `mappings/cwe-to-owl-v1.0.md`
- **Ontology:** `standards/cwe/cwe-ontology-v1.0.owl`
- **Key References:** MITRE CWE Program

### CVSS (Common Vulnerability Scoring System)

- **Directory:** `CVSS/`
- **Format:** XML
- **Purpose:** Vulnerability severity quantification and scoring
- **Mapping:** `mappings/cvss-to-owl-v1.0.md`
- **Ontology:** `standards/cvss/cvss-ontology-v1.0.owl`
- **Key References:** NIST NVD, CVSS v3.1 specification

### ATT&CK (Adversarial Tactics, Techniques & Common Knowledge)

- **Directory:** `ATTCK-STIX/`
- **Format:** JSON (STIX 2.0)
- **Purpose:** Offensive cyber attack knowledge base and technique framework
- **Mapping:** `mappings/attck-to-owl-v1.0.md`
- **Ontology:** `standards/attck/attck-ontology-v1.0.owl`
- **Key References:** MITRE ATT&CK Framework (Enterprise, Mobile, ICS)
- **Coverage:** Tactics, Techniques, Subtechniques, Groups, Software, Data Sources

### CAPEC (Common Attack Pattern Expression and Enumeration)

- **Directory:** `CAPEC/`
- **Format:** XML
- **Purpose:** Attack pattern methodology and standardization
- **Mapping:** `mappings/capec-to-owl-v1.0.md`
- **Ontology:** `standards/capec/capec-ontology-v1.0.owl`
- **Key References:** MITRE CAPEC v3.5.0
- **Coverage:** Patterns (Meta/Standard/Detailed), Categories, Views, CWE links

### D3FEND (Detection, Defeasibility, Deception, Defensive)

- **Directory:** `D3FEND/`
- **Format:** OWL
- **Purpose:** Defensive countermeasures and detection techniques knowledge graph
- **Mapping:** `mappings/d3fend-to-owl-v1.0.md`
- **Ontology:** `standards/d3fend/d3fend-ontology-v1.0.owl` (integration layer)
- **Key References:** MITRE D3FEND v1.3.0
- **Architecture:** Knowledge graph passthrough (official D3FEND OWL authoritative)
- **Coverage:** 4,279 defensive techniques, 7 tactical categories (Detect, Deceive, Evict, Harden, Isolate, Model, Restore)

### CAR (Cyber Analytics Repository)

- **Directory:** `CAR/`
- **Format:** JSON Schema v7
- **Purpose:** Detection analytics and data model definitions
- **Schema Files:**
  - `car-schema-v1.0.json` - Master JSON Schema (analytics, data models, sensors)
  - `car-types.md` - Type definitions, enumerations, constraints
- **Mapping:** `mappings/car-to-owl-v1.0.md`
- **Ontology:** `standards/car/car-ontology-v1.0.owl`
- **Key References:** MITRE CAR Program
- **Coverage:** 100+ detection analytics, data models for cyber observables, sensor mappings

### ENGAGE (Defender Adversary Engagement)

- **Directory:** `ENGAGE/`
- **Format:** JSON
- **Purpose:** Framework for adversary engagement operations including deception, denial, and detection activities
- **Schema Files:**
  - `engage-schema-v1.0.json` - Master JSON Schema (activities, approaches, goals, references)
  - `engage-types.md` - Type definitions, enumerations, constraints, hierarchy
- **Mapping:** `mappings/engage-to-owl-v1.0.md` ✅ Complete
- **Ontology:** `standards/engage/engage-ontology-v1.0.owl` ✅ Complete
- **Key References:** MITRE ENGAGE Framework
- **Coverage:** 20+ engagement activities, 9 approaches, 5 goals, 30+ research references, ATT&CK alignment with Engagement Adversarial Vulnerabilities

### SHIELD (Active Defense Framework)

- **Directory:** `SHIELD/`
- **Format:** JSON Schema v7
- **Purpose:** Active defense framework defining defensive tactics, techniques, opportunities, use cases, and procedures
- **Schema Files:**
  - `shield-schema-v1.0.json` - Master JSON Schema (tactics, techniques, opportunities, use cases, procedures, ATT&CK mappings)
  - `shield-types.md` - Type definitions, enumerations, constraints, hierarchy
- **Mapping:** `mappings/shield-to-owl-v1.0.md` ✅ Complete
- **Ontology:** `standards/shield/shield-ontology-v1.0.owl` ✅ Complete
- **Key References:** MITRE SHIELD Framework
- **Coverage:** 8 defensive tactics, 36+ defensive techniques, 100+ opportunities, 260+ use cases, 66 procedures, comprehensive ATT&CK defensive alignment

---

## Schema Organization

Each standard directory typically contains:

### Source Schemas

- **Official format**: The authoritative schema in its native format (XML, JSON, OWL, etc.)
- **Version info**: Specific version/release date of the source standard
- **Examples**: Sample data files validating against the schema

### Documentation

- **README.md** (optional): Schema-specific documentation
- **Version notes**: Changes and updates from previous versions
- **Usage examples**: Sample structures and valid data

---

## Mapping Workflow

The general workflow for incorporating a new standard into KGCS is:

```text
1. Source Schema (this directory)
   ↓
2. Mapping Document (mappings/)
   - Field-by-field mapping to OWL properties
   - Entity type mapping to KGCS classes
   - Relationship mapping definitions
   - ETL transformation notes
   ↓
3. Ontology File (standards/)
   - OWL 2.0 implementation of mapping
   - Properties, classes, constraints
   - Core ontology imports and alignment
   ↓
4. Integration
   - Bidirectional relationship support
   - SPARQL query capability
   - Federation with other standards
```

---

## Validation and Testing

### Schema Validation

**For XML schemas:**

```bash
xmllint --schema <schema>.xsd <instance>.xml
```

**For JSON schemas:**

```bash
ajv validate -s <schema>.json -d <instance>.json
```

**For OWL ontologies:**

```bash
rapper -i turtle <ontology>.owl -o turtle
```

### Consistency Checks

1. **Namespace consistency** - All ontologies use consistent URI patterns
2. **Import chain validation** - No circular dependencies, proper core imports
3. **Cardinality enforcement** - ID properties have exactly-1 constraints
4. **Semantic alignment** - Inverse properties properly declared
5. **Documentation completeness** - All properties have labels and comments

---

## Version Tracking

Each schema maintains version information:

| Standard | Current Version | Release Date | Last Updated |
| -------- | --------------- | ------------ | ------------ |
| CPE | 2.3 | 2011-12-29 | 2026-02-24 |
| CVE | 1.0+ | Ongoing | 2026-02-24 |
| CWE | 4.x | 2024 | 2026-02-24 |
| CVSS | 3.1 | 2019-06 | 2026-02-24 |
| ATT&CK | 13.1+ | 2020+ | 2026-02-27 |
| CAPEC | 3.5.0 | 2021-10 | 2026-02-24 |
| D3FEND | 1.3.0 | 2025-12-16 | 2026-03-01 |
| CAR | Latest | Ongoing | 2026-03-01 |
| ENGAGE | Latest | Ongoing | 2026-03-01 |
| SHIELD | Latest | Ongoing | 2026-03-01 |

---

## Federation and Integration

The schemas in this directory enable:

- **Cross-schema analysis**: Link CVEs to CWEs to techniques to defenses
- **Coverage mapping**: Understand which analytics detect which techniques
- **Defense alignment**: Map offensive ATT&CK techniques to D3FEND mitigations
- **Vulnerability tracking**: From CVE → CPE → CWE → ATT&CK → CAPEC
- **Detection efficiency**: Find optimal analytics for given threat models

### Example Queries

**Find all techniques and their defenses:**

```sparql
SELECT ?technique ?defense WHERE {
  ?defense d3fend:mitigates_technique ?technique .
}
```

**Find analytics covering a specific tactic:**

```sparql
SELECT ?analytic ?technique WHERE {
  ?analytic car:coverage_technique ?technique .
  ?technique attack:belongs_to attack:Reconnaissance .
}
```

---

## Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [MITRE CAPEC](https://capec.mitre.org)
- [MITRE D3FEND](https://d3fend.mitre.org)
- [MITRE CAR](https://car.mitre.org)
- [Common Vulnerabilities and Exposures (CVE)](https://cve.mitre.org)
- [Common Weakness Enumeration (CWE)](https://cwe.mitre.org)
- [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe)
- [CVSS - Common Vulnerability Scoring System](https://www.first.org/cvss/)
- [National Vulnerability Database (NVD)](https://nvd.nist.gov)

---

## Contributing

When adding a new standard to KGCS:

1. Place source schema in appropriate subdirectory
2. Create mapping document in `mappings/` with `{standard}-to-owl-v1.0.md` naming
3. Implement OWL ontology in `standards/{standard}/`
4. Update this README with standard entry
5. Update `mappings/README.md` with implementation status
6. Ensure all ontologies validate with `rapper`

---

## License and Attribution

Schema definitions are maintained per their respective source organizations' licenses:

- MITRE standards: Licensed per MITRE usage terms
- NIST standards: Public domain (NIST work product)
- Community standards: Licensed per their respective terms

All mapping and ontology implementations: KGCS project licensing applies
