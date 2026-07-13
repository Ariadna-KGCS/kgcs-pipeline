# SHIELD Schema Types and Constraints

## Overview

This document defines the enumeration types, identifier patterns, and cardinality rules for the MITRE SHIELD schema (`shield-schema-v1.0.json`).

---

## SHIELD Entity Types

### Tactic Entity Types

**Fixed Set of 8 Core Tactics:**

| Tactic ID | Name | Description |
| --------- | ---- | ----------- |
| DTA0001 | Channel | Guide an adversary down a specific path to achieve defensive objectives |
| DTA0002 | Collect | Gather adversary tools, behaviors, and intelligence through controlled operations |
| DTA0003 | Contain | Prevent adversary from moving outside designated boundaries or systems |
| DTA0004 | Detect | Establish awareness and detection of adversary activity and capabilities |
| DTA0005 | Disrupt | Prevent adversary from conducting their intended mission or objectives |
| DTA0006 | Facilitate | Enable adversary to conduct operations in controlled, monitored environments |
| DTA0007 | Legitimize | Add authenticity and credibility to deceptive components and infrastructure |
| DTA0008 | Test | Determine adversary interests, capabilities, and operational parameters |

**Field Constraints:**

- `id`: Pattern `DTA[0-9]{4}` - exactly 8 valid values (DTA0001 through DTA0008)
- `name`: Enum - one of the 8 fixed tactic names above
- `description`: Required, minimum 10 characters
- `long_description`: Required, minimum 50 characters
- `technique_ids`: Required array, minimum 1 technique per tactic, maximum 50

**Strategic Roles:**

- **Channel**: Deception-based tactics that misdirect adversary activity
- **Collect**: Intelligence gathering through controlled engagement
- **Contain/Detect/Disrupt**: Defensive core - limit, identify, and stop threats
- **Facilitate/Legitimize**: Tactical deception to enable controlled operations
- **Test**: Capability assessment and vulnerability discovery

---

## Technique Entity Types

**SHIELD Defensive Techniques (36+ instances):**

Examples of technique categories:

- **Decoy-based:** Decoy Account, Decoy Content, Decoy System, Decoy Persona, Decoy Password
- **Monitoring-based:** Network Monitoring, System Activity Monitoring, File Monitoring
- **Control-based:** Admin Access Manipulation, Security Policy Manipulation
- **Training-based:** User Training, Security Awareness
- **Analysis-based:** Behavioral Analysis, Forensics

**Field Constraints:**

- `id`: Pattern `DTE[0-9]{4}` - extensible (DTE0001-DTE0036+)
- `name`: Required string (human-readable name)
- `description`: Required, minimum 10 characters
- `long_description`: Required, minimum 50 characters
- `opportunity_ids`: Optional array of DOS#### references, 0+ items
- `tactics`: Optional array for back-reference to parent tactics

**Design Pattern:**

- Techniques organize concrete defensive actions
- Techniques are organized BY tactics (reverse reference in tactic_ids field)
- Techniques enable opportunities (forward reference in opportunity_ids)
- Allow deprecated/retired techniques with gaps in numbering

---

## Opportunity Entity Types

**SHIELD Strategic Opportunities (100+ instances, DOS0001-DOS0253+):**

Opportunities represent specific defensive scenarios or contexts where techniques apply.

Examples:

- DOS0001: "Study adversary and collect observations"
- DOS0027: "Create detection with moderately high probability"
- DOS0074: "Influence adversary to move toward desired systems"
- DOS0253: "Introduce decoy information to influence future actions"

**Field Constraints:**

- `id`: Pattern `DOS[0-9]{4}` - extensible with sparse numbering
- `description`: Required, minimum 10 characters describing the opportunity
- `use_case_ids`: **REQUIRED** array, minimum 1 use case per opportunity, maximum 50
- `technique_ids`: Optional array for back-reference to supporting techniques

**CRITICAL CARDINALITY RULE:**
Every opportunity MUST have at least one associated use case (minItems: 1). This ensures every strategic opportunity has concrete implementation scenarios.

**Semantic Pattern:**

- Opportunities describe contexts where defensive approaches apply
- Opportunities are implemented via use cases (mandatory relationship)
- Opportunities are supported by techniques (optional back-reference)

---

## Use Case Entity Types

**SHIELD Practical Use Cases (260+ instances, DUC0001-DUC0261+):**

Use cases provide concrete, practical scenarios demonstrating how to apply techniques within opportunities.

Examples:

- DUC0001: "Defender can use decoy system to access compromised website"
- DUC0016: "Move suspicious emails to decoy system"
- DUC0087: "Setup networks using Kerberos to test ticket theft"
- DUC0261: "Deploy decoy website for deception operation"

**Field Constraints:**

- `id`: Pattern `DUC[0-9]{4}` - extensible with sparse numbering
- `description`: Required, minimum 10 characters describing practical scenario
- `procedure_ids`: Optional array of DPR#### references, 0-20 items
- `opportunity_id`: Optional DOS#### back-reference to parent opportunity

**Design Pattern:**

- Use cases are implementation scenarios
- Use cases MAY reference procedures (optional, 0 or more)
- Use cases support opportunities (many use cases per opportunity)
- Procedures are concrete technical implementation details (optional)

---

## Procedure Entity Types

**SHIELD Technical Procedures (66 instances, DPR0001-DPR0066+):**

Procedures define concrete technical steps, code, or implementation details.

Examples:

- DPR0001: "Remove admin access to reveal privilege escalation techniques"
- DPR0006: "Hook Win32 DeleteFile() function to log deletion attempts"
- DPR0027: "Create isolated network with decoy systems"
- DPR0066: "Run user applications in isolated containers"

**Field Constraints:**

- `id`: Pattern `DPR[0-9]{4}` - extensible with sparse numbering
- `description`: Required, minimum 10 characters describing technical procedure

**Design Pattern:**

- Procedures are standalone (not required by use cases, but can be referenced)
- Procedures provide implementation depth for use cases
- Procedures are concrete technical steps/details
- Procedures are optional (many use cases lack explicit procedures)

---

## ATT&CK Mapping Entity Types

**SHIELD to ATT&CK Cross-References:**

SHIELD defensive entities map to MITRE ATT&CK offensive techniques and tactics for defensive-offensive alignment.

**Field Constraints:**

- `shieldId`: Pattern `(DTA|DTE|DOS|DUC|DPR)[0-9]{4}` - any SHIELD entity type
- `shieldType`: Enum [tactic, technique, opportunity, useCase, procedure]
- `attackId`: Pattern `T[0-9]{4}(\\.[0-9]{3})?` - ATT&CK technique with optional subtechnique
- `attackTactic`: Pattern `TA[0-9]{4}` - associated ATT&CK tactic
- `relationshipType`: Enum with 5 values (see below)
- `coverage`: Enum [Low, Moderate, High] - optional coverage level

**Relationship Types (5 total):**

| Type | Semantics | Example |
| ---- | --------- | ------- |
| **detects** | SHIELD entity detects this ATT&CK technique | Monitoring technique detects T1007 |
| **mitigates** | SHIELD entity reduces impact of technique | Defense technique mitigates T1021 |
| **enables** | SHIELD entity allows controlled execution | Decoy enables T1592 in sandbox |
| **tests** | SHIELD entity probes for capability | Test technique probes T1595 |
| **engages_with** | SHIELD entity actively engages with technique | Deception engages_with T1598 |

**Design Pattern:**

- Separate mapping entity (not embedded in SHIELD entities)
- Supports bidirectional queries: "What SHIELD techniques detect T1234?"
- Enables defensive-offensive alignment analysis
- Coverage levels indicate effectiveness span

---

## Identifier Patterns

### SHIELD Identifier Pattern Constraints

| Entity | Prefix | Pattern | Example | Range | Notes |
| ------ | ------ | ------- | ------- | ----- | ----- |
| Tactic | DTA | `DTA[0-9]{4}` | DTA0001 | 0001-0008 (fixed 8) | Never exceeds 8 |
| Technique | DTE | `DTE[0-9]{4}` | DTE0001 | 0001-9999 (extensible) | Allow gaps for deprecation |
| Opportunity | DOS | `DOS[0-9]{4}` | DOS0001 | 0001-9999 (extensible) | Sparse numbering OK |
| Use Case | DUC | `DUC[0-9]{4}` | DUC0001 | 0001-9999 (extensible) | Sparse numbering OK |
| Procedure | DPR | `DPR[0-9]{4}` | DPR0001 | 0001-9999 (extensible) | Allow capability versioning |

### ATT&CK Reference Patterns

| Framework | Pattern | Example | Subtechnique | Notes |
| --------- | ------- | ------- | ------------- | ----- |
| ATT&CK Technique | `T[0-9]{4}` | T1039 | Optional `.###` | T1021.002 with subtechnique |
| ATT&CK Tactic | `TA[0-9]{4}` | TA0009 | N/A | Fixed reference to killchain |

**Validation Rules:**

- All identifiers use exactly 4 digits after prefix
- No leading zeros are stripped (DTE0001 is valid, DTE01 is invalid)
- Uppercase prefix and numbers only
- Patterns are enforced via JSON Schema regex

---

## Cardinality Rules

### Critical Requirements

| Constraint | Entity | Rule | Rationale |
| --------- | ------ | ---- | --------- |
| **Tactic-to-Technique** | Tactic | minItems: 1 | Every tactic must organize ≥1 technique |
| **Opportunity-to-UseCase** | Opportunity | **minItems: 1** | CRITICAL: Every opportunity must have ≥1 use case |
| **UseCase-to-Procedure** | UseCase | minItems: 0 | Procedure is optional implementation detail |
| **Technique-to-Opportunity** | Technique | minItems: 0 | Optional enrichment |

### Optional Fields

- `opportunity_ids` in Technique: Optional, 0 or more
- `technique_ids` in Opportunity: Optional back-reference
- `procedure_ids` in UseCase: Optional, 0-20 items
- `tactics` in Technique: Optional back-reference
- `opportunity_id` in UseCase: Optional back-reference
- `attackTactic` in Mapping: Optional (if provided with attackId)

### Required by Type

| Entity Type | Always Required | Conditionally Required |
| ----------- | --------------- | -------------------- |
| Tactic | id, name, description, long_description, technique_ids | - |
| Technique | id, name, description, long_description | - |
| Opportunity | id, description, use_case_ids | - |
| UseCase | id, description | - |
| Procedure | id, description | - |
| Mapping | shieldId, shieldType, attackId, relationshipType | attackTactic (recommended) |

---

## ATT&CK Mapping Semantics

### Defensive-Offensive Alignment

SHIELD defensive entities map to ATT&CK offensive techniques to enable:

1. **Defensive Coverage Analysis**: "What SHIELD techniques defend against technique X?"
2. **Offensive Alignment**: "What ATT&CK techniques does tactic Y engage with?"
3. **Coverage Assessment**: "What is our defensive coverage against tactic Z?"
4. **Bidirectional Queries**: Support both directions of relationship navigation

### Relationship Type Usage Patterns

**Detects Relationship:**

- Use case: Monitoring/detection techniques that identify offensive behavior
- Example: Network monitoring technique "detects" T1040 (Network Sniffing)
- Enables: "What SHIELD techniques detect this technique?"

**Mitigates Relationship:**

- Use case: Defensive techniques that reduce attack effectiveness
- Example: Defense technique "mitigates" T1110 (Brute Force)
- Enables: "What SHIELD techniques mitigate this technique?"

**Enables Relationship:**

- Use case: Controlled execution for deception/testing
- Example: Decoy system "enables" controlled T1592 execution (Gather Victim Identity Information)
- Enables: "What SHIELD systems enable this technique in controlled environment?"

**Tests Relationship:**

- Use case: Testing defender capabilities against techniques
- Example: Test procedure "tests" T1595 (Active Scanning)
- Enables: "What SHIELD procedures test this technique?"

**Engages-With Relationship:**

- Use case: Active engagement/deception targeting specific techniques
- Example: Deception "engages_with" T1598 (Phishing for Information)
- Enables: "What SHIELD tactics actively engage with this technique?"

---

## Schema Validation Rules

### Valid Structure Examples

**Valid Tactic:**

```json
{
  "id": "DTA0001",
  "name": "Channel",
  "description": "Guide an adversary down a specific path.",
  "long_description": "Provide route options to misdirect adversary away from critical assets.",
  "technique_ids": ["DTE0001", "DTE0010", "DTE0017"]
}
```

**Valid Opportunity (with critical relationship):**

```json
{
  "id": "DOS0027",
  "description": "Create detection with moderately high probability.",
  "use_case_ids": ["DUC0040", "DUC0041", "DUC0123"]
}
```

**Valid Mapping:**

```json
{
  "shieldId": "DTE0027",
  "shieldType": "technique",
  "attackId": "T1039",
  "attackTactic": "TA0009",
  "relationshipType": "detects",
  "coverage": "High"
}
```

### Validation Constraints

- All required fields must be present (no null values)
- All IDs must match their respective patterns exactly
- Enum fields must be one of the allowed values
- Array items must match their item patterns (e.g., DOS#### in use_case_ids)
- Cardinality limits enforced (minItems, maxItems)
- `additionalProperties: false` prevents unknown fields

---

## Integration Notes

### Data Type Specifications

- All string fields are UTF-8 text
- All IDs are uppercase alphanumeric
- No special characters in IDs
- Descriptions support plain text (may include punctuation and newlines)

### Version Tracking

- Schema Version: 1.0
- SHIELD Framework Reference: MITRE SHIELD v1.0
- ATT&CK Integration: Full bidirectional mapping support
- Extensibility: All entity types except Tactics (fixed 8) support sparse numbering for future growth

### Federation Capability

- SHIELD can be federated with:
  - ATT&CK (via attackId/attackTactic mappings)
  - D3FEND (via defensive technique alignment)
  - CAR (via detection analytics)
  - ENGAGE (via engagement operations)
- Cross-standard queries enabled via common ontology base classes

---
