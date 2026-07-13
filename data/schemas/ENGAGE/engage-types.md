# ENGAGE Schema Types and Constraints

## Overview

This document defines the enumeration types, identifier patterns, and cardinality rules for the MITRE ENGAGE (Defender Adversary Engagement) schema (`engage-schema-v1.0.json`).

---

## Activity Entity Types

### Activity Types

The `type` field classifies the activity category:

- **Engagement** - Activities used during active engagement operations (collection, detection, prevention, direction, disruption, reassurance, motivation)
- **Strategic** - Activities related to strategic planning and analysis

### Goal References (from activity)

Activities can support one or more goals:

**Engagement Goals (EGOxxxx):**
- `EGO0001` - Expose: Reveal the presence of ongoing adversary operations
- `EGO0002` - Affect: Negatively impact the adversaries' operations
- `EGO0003` - Elicit: Learn about adversaries' tactics, techniques, and procedures (TTPs)

**Strategic Goals (SGOxxxx):**
- `SGO0001` - Prepare: Help the defender think about what they want to accomplish with operations
- `SGO0002` - Understand: Make sure that the defender is capturing, utilizing, and refining knowledge learned

---

## Approach Entity Types

### Approach Categories

**Engagement Approaches (EAPxxxx):**

Tactical approaches supporting engagement goals:
- `EAP0001` - Collect: Gather adversary tools, observe tactics, and collect intelligence
- `EAP0002` - Detect: Establish or maintain awareness regarding adversary activity
- `EAP0003` - Prevent: Stop all or part of the adversary's ability to conduct operations
- `EAP0004` - Direct: Encourage or discourage adversary from conducting operations
- `EAP0005` - Disrupt: Impair an adversary's ability to conduct operations
- `EAP0006` - Reassure: Add authenticity to deceptive components
- `EAP0007` - Motivate: Encourage an adversary to conduct part or all of their mission

**Strategic Approaches (SAPxxxx):**

Strategic approaches supporting strategic goals:
- `SAP0001` - Plan: Identify and align an operation with a desired end-state
- `SAP0002` - Analysis: Turn raw operational outputs into useful intelligence

---

## Goal Entity Types

### Goal Categories

**Engagement Goals (EGOxxxx):**
Tactical objectives for active engagement operations
- `EGO0001` - Expose
- `EGO0002` - Affect
- `EGO0003` - Elicit

**Strategic Goals (SGOxxxx):**
Long-term objectives for engagement program planning
- `SGO0001` - Prepare
- `SGO0002` - Understand

---

## Engagement Adversarial Vulnerability (EAV) Types

### EAV Identifier Pattern

Format: `EAV[0-9]{4}` (exactly 4 digits)

Examples:
- `EAV0001` - When adversaries interact with environment/personas, vulnerable to revealing behaviors
- `EAV0016` - When adversaries utilize system features, vulnerable to monitoring/MitM
- `EAV0010` - When adversaries interact with resources, vulnerable to tripwires/detection

### EAV Semantics

Engagement Adversarial Vulnerabilities define specific ways that defenders can exploit adversary behavior through engagement activities. Each EAV describes a vulnerability that adversaries have when operating in engagement environments.

---

## ATT&CK Mapping Patterns

### Technique Identifier Pattern

Format: `T[0-9]{4}` (exactly 4 digits) or `T[0-9]{4}\.[0-9]{3}` (subtechnique)

Examples:
- `T1007` - System Service Discovery
- `T1021` - Remote Services
- `T1021.001` - Remote Services: RDP
- `T1021.002` - Remote Services: SMB/Windows Admin Shares

### Tactic Identifier Pattern

Format: Common ATT&CK tactic names (lowercase, no spaces)

Examples:
- `discovery` - Discovery techniques
- `execution` - Execution techniques
- `persistence` - Persistence techniques
- `defense-evasion` - Defense Evasion techniques
- `collection` - Collection techniques

---

## Activity Identifier Patterns

### ENGAGE Activity ID

Format: `EAC[0-9]{4}` (exactly 4 digits)

Examples:
- `EAC0001` - API Monitoring
- `EAC0005` - Lures
- `EAC0014` - Software Manipulation
- `EAC0021` - Change Default Credentials

### Approach ID

Format: `EAP[0-9]{4}` (Engagement Approach) or `SAP[0-9]{4}` (Strategic Approach)

Examples:
- `EAP0001` - Collect approach
- `SAP0001` - Plan approach

### Goal ID

Format: `EGO[0-9]{4}` (Engagement Goal) or `SGO[0-9]{4}` (Strategic Goal)

Examples:
- `EGO0001` - Expose goal
- `SGO0001` - Prepare goal

### Reference ID

Format: `REF[0-9]{4}` (exactly 4 digits)

Examples:
- `REF0001` - Academic paper reference
- `REF0005` - Documentation reference

---

## Cardinality Rules

### Activity Entity

**Required (must be present):**
- `id` - Exactly 1 (unique identifier)
- `name` - Exactly 1 (human-readable name)
- `description` - Exactly 1 (short description)
- `long_description` - Exactly 1 (detailed description)
- `type` - Exactly 1 (Engagement or Strategic)

**Optional (0 or more):**
- `goals` - 0+ goal IDs (which goals this activity supports)
- `vulnerabilities` - 0+ EAV objects (which vulnerabilities it exploits)
- `attack_techniques` - 0+ ATT&CK technique objects (which techniques it engages with)

### Approach Entity

**Required:**
- `id` - Exactly 1 (EAPxxxx or SAPxxxx format)
- `name` - Exactly 1
- `description` - Exactly 1
- `long_description` - Exactly 1

### Goal Entity

**Required:**
- `id` - Exactly 1 (EGOxxxx or SGOxxxx format)
- `name` - Exactly 1
- `description` - Exactly 1
- `long_description` - Exactly 1

**Optional:**
- `goal_type` - 0-1 (Engagement or Strategic)

### Reference Entity

**Required:**
- `id` - Exactly 1 (REFxxxx format)
- `title` - Exactly 1 (reference title)
- `url` - Exactly 1 (valid URI to reference material)
- `activity_id` - Exactly 1 (links to EACxxxx activity)

---

## Data Type Specifications

| Field | Type | Format | Constraints |
| ----- | ---- | ------ | ----------- |
| Activity ID | string | EAC[0-9]{4} | Pattern enforced |
| Approach ID | string | (EAP\|SAP)[0-9]{4} | Pattern enforced |
| Goal ID | string | (EGO\|SGO)[0-9]{4} | Pattern enforced |
| EAV ID | string | EAV[0-9]{4} | Pattern enforced |
| Reference ID | string | REF[0-9]{4} | Pattern enforced |
| Technique ID | string | T[0-9]{4}(\.[0-9]{3})? | Pattern enforced, supports subtechniques |
| Tactic name | string | lowercase, hyphenated | Examples: discovery, execution, persistence |
| URL | string | URI | Valid HTTP/HTTPS URL |
| Activity type | string | Enum | "Engagement" or "Strategic" only |
| Goal type | string | Enum | "Engagement" or "Strategic" only |

---

## Schema Validation Rules

### Activity Validation

- Activity ID must be unique and globally consistent
- Goal references must point to valid goal IDs (EGOxxxx or SGOxxxx)
- EAV references must point to valid vulnerability IDs (EAVxxxx)
- ATT&CK technique IDs must follow T[0-9]{4} pattern
- Type must be either "Engagement" or "Strategic"

### Approach-Goal Validation

- Approach IDs must follow (EAP|SAP)[0-9]{4} pattern
- Approaches must be linked to goals via mapping files
- Each approach must support at least one goal

### Hierarchy Validation

- Strategic Goals (SGO) have Strategic Approaches (SAP)
- Engagement Goals (EGO) have Engagement Approaches (EAP)
- Approaches link to Activities (EAC)
- Activities can cross multiple goals/approaches

### Cross-Reference Consistency

- All goal_id references in activities must exist in goals.json
- All approach_id references must exist in approaches.json
- All activity_id references in references must exist in activities.json
- All ATT&CK technique IDs must be valid techniques

---

## ENGAGE Hierarchy

```
Strategic Goals (SGO)
├── Prepare (SGO0001)
│   └── Plan (SAP0001)
│       └── Activities (various EAC)
└── Understand (SGO0002)
    └── Analysis (SAP0002)
        └── Activities (various EAC)

Engagement Goals (EGO)
├── Expose (EGO0001)
│   ├── Collect (EAP0001)
│   │   └── Activities (EAC0001, EAC0003, EAC0004, etc.)
│   └── Detect (EAP0002)
│       └── Activities (various EAC)
├── Affect (EGO0002)
│   ├── Prevent (EAP0003)
│   ├── Direct (EAP0004)
│   └── Disrupt (EAP0005)
└── Elicit (EGO0003)
    ├── Reassure (EAP0006)
    └── Motivate (EAP0007)
```

---

## Usage Examples

### Valid Activity with Vulnerabilities and Techniques

```json
{
  "id": "EAC0001",
  "name": "API Monitoring",
  "description": "Monitor local APIs that might be used by adversary tools and activity.",
  "long_description": "API Monitoring involves capturing an internal OS function...",
  "type": "Engagement",
  "goals": ["EGO0001"],
  "vulnerabilities": [
    {
      "id": "EAV0001",
      "eav": "When adversaries interact with the environment or personas, they are vulnerable when they collect, observe, or manipulate system artifacts or information."
    },
    {
      "id": "EAV0010",
      "eav": "When adversaries interact with network or system resources, they are vulnerable to triggering tripwires or engaging in easily detectable, anomalous behavior."
    }
  ],
  "attack_techniques": [
    {
      "id": "T1007",
      "name": "System Service Discovery",
      "attack_tactics": ["discovery"]
    },
    {
      "id": "T1016",
      "name": "System Network Configuration Discovery",
      "attack_tactics": ["discovery"]
    }
  ]
}
```

### Valid Reference

```json
{
  "id": "REF0005",
  "title": "Designing Robust API Monitoring Solutions",
  "url": "https://arxiv.org/pdf/2005.00323",
  "activity_id": "EAC0001"
}
```

### Valid Goal-Approach Mapping

Two-column mapping:
```json
[
  {
    "goal_id": "EGO0001",
    "approach_id": "EAP0001"
  },
  {
    "goal_id": "EGO0001",
    "approach_id": "EAP0002"
  }
]
```

---

## Version History

- **v1.0** (March 2026) - Initial JSON Schema definition for ENGAGE standard with Activity, Approach, Goal, and Reference entities
