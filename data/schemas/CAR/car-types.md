# CAR Schema Types and Constraints

## Overview

This document defines the enumeration types, identifier patterns, and cardinality rules for the MITRE CAR (Cyber Analytics Repository) schema (`car-schema-v1.0.json`).

---

## Analytic Entity Types

### Information Domains (Required, Single Value)

The `information_domain` field classifies the primary data source domain for a CAR analytic:

| Domain | Description | Example Data Sources |
| ------ | ------ | ----- |
| **Network** | Network traffic and protocol analysis | PCAP, Flow data, NetFlow |
| **Host** | Host-based system activity (processes, threads, system calls) | Process creation events, System calls, DLLs |
| **File** | File system operations and file metadata | File creation, modification, deletion events |
| **Object** | Object operations (registry, WMI, etc.) | Registry changes, WMI events |
| **Launched Script** | Script execution and interpreter activity | PowerShell, VBScript, JavaScript execution |
| **Process** | Process-level activities and interactions | Process creation, termination, memory access |
| **User** | User authentication and session management | Logon events, session creation, privilege changes |
| **Cloud** | Cloud platform operations and API activity | AWS CloudTrail, Azure activity logs |

### Analytic Types

The `analytic_types` array classifies the detection strategy:

- **Situational Awareness** - Monitoring for normal/expected activity patterns
- **Detection** - Active detection of suspicious/malicious behavior
- **Evasion Detection** - Detection of anti-forensics or evasion techniques
- **Threat Hunting** - Proactive search for indicators of compromise

### Platform Values

The `platforms` array specifies target operating systems:

- Windows
- Linux
- macOS
- Kubernetes
- AWS
- Azure
- N/A (if platform-independent or not applicable)

### Coverage Levels

The `coverage` array `coverage` field specifies detection effectiveness:

- **Low** - Minimal or occasional coverage of the technique
- **Moderate** - Reasonable coverage, may have gaps
- **High** - Comprehensive coverage of the technique

### Implementation Types

The `implementations` array `type` field specifies code format:

- **pseudocode** - Language-agnostic pseudocode
- **sql** - SQL or database query language
- **splunk** - Splunk SPL (Search Processing Language)
- **eql** - Event Query Language (EQL)
- **other** - Other implementation languages

---

## ATT&CK Mapping Patterns (Used in coverage)

### Technique Identifier Pattern

Format: `T[0-9]{4}` (exactly 4 digits)

Examples:

- `T1039` - Data from Local System (without Tactical Group)
- `T1021` - Remote Services
- `T1543` - Create or Modify System Process

### Tactic Identifier Pattern

Format: `TA[0-9]{4}` (exactly 4 digits)

Common tactics:

- `TA0001` - Initial Access
- `TA0003` - Persistence
- `TA0004` - Privilege Escalation
- `TA0008` - Lateral Movement
- `TA0009` - Collection

### Subtechnique Identifier Pattern

Format: `T[0-9]{4}\.[0-9]{3}` (exactly 4 digits, dot, then 3 digits)

Examples:

- `T1021.001` - Remote Services: RDP
- `T1021.002` - Remote Services: SMB/Windows Admin Shares
- `T1543.003` - Create or Modify System Process: Windows Service

---

## CAR Analytic Identifier Pattern

Format: `CAR-YYYY-MM-NNN` (exactly as specified)

Components:

- `CAR` - Fixed prefix
- `YYYY` - Year submitted (4 digits)
- `MM` - Month submitted (2 digits, 01-12)
- `NNN` - Sequential number within month (3 digits, 001-999)

Examples:

- `CAR-2013-01-002` - Second analytic submitted in January 2013
- `CAR-2020-04-001` - First analytic submitted in April 2020

---

## Data Model Entity Types

### Actions (Per Entity Type)

Actions vary by data model entity:

**Process Entity Actions:**

- `create` - Process creation
- `terminate` - Process termination/exit
- `access` - Inter-process memory access

**File Entity Actions:**

- `create` - File creation
- `modify` - File modification
- `delete` - File deletion
- `timestomp` - File metadata modification
- `execute` - File execution

**Registry Entity Actions:**

- `create` - Registry key/value creation
- `modify` - Registry value modification
- `delete` - Registry key/value deletion

**Flow Entity Actions:**

- `start` - Communication initiation
- `message` - Message send/receive
- `terminate` - Communication termination

**Driver Entity Actions:**

- `load` - Driver/kernel module load
- `unload` - Driver/kernel module unload

---

## Sensor Definition Constraints

### Sensor Name

Standard sensor names (case-sensitive):

- Sysmon
- osquery
- auditd
- Autoruns
- WmiTrace
- ETW (Windows Event Tracing)
- AWS CloudTrail
- Azure Monitor

### Sensor Version

Free-form version string matching the source documentation:

- Examples: "11.0", "4.6.0", "2.8", "13.98"

### Sensor Developer

Organization responsible for the sensor:

- Microsoft
- Osquery Foundation
- Linux Foundation
- Sysinternals
- AWS
- Microsoft Azure

---

## D3FEND Mapping Format

The optional `d3fend_mappings` array in analytics provides links to MITRE D3FEND defensive techniques:

### Fields

- **iri** (string) - D3FEND IRI reference (e.g., `d3f:IPCTrafficAnalysis`)
- **id** (string) - D3FEND identifier (e.g., `D3-IPCTA`)
- **label** (string) - Human-readable label (e.g., `IPC Traffic Analysis`)

### Semantics

A D3FEND mapping indicates that this CAR analytic detects or supports the implementation of the corresponding D3FEND defensive technique.

Example:

```json
{
  "iri": "d3f:IPCTrafficAnalysis",
  "id": "D3-IPCTA",
  "label": "IPC Traffic Analysis"
}
```

---

## Cardinality Rules

### Analytic Entity

**Required (must be present):**

- `id` - Exactly 1
- `title` - Exactly 1
- `submission_date` - Exactly 1
- `information_domain` - Exactly 1
- `description` - Exactly 1
- `coverage` - At least 1

**Optional (0 or more):**

- `platforms` - 0+ items
- `subtypes` - 0+ items
- `analytic_types` - 0+ items
- `implementations` - 0+ items
- `data_model_references` - 0+ items
- `d3fend_mappings` - 0+ items

**Conditional:**

- `contributors` - At least 1 (minimum 1 required)

### DataModel Entity

**Required:**

- `name` - Exactly 1
- `description` - Exactly 1
- `actions` - At least 1
- `fields` - At least 1

### Sensor Entity

**Required:**

- `sensor_name` - Exactly 1
- `sensor_version` - Exactly 1
- `sensor_developer` - Exactly 1
- `sensor_url` - Exactly 1
- `sensor_description` - Exactly 1
- `mappings` - At least 1

---

## Schema Validation Rules

### Coverage Array Validation

Each coverage object must have:

- Exactly 1 `technique` field with T[0-9]{4} pattern
- At least 1 `tactics` entry with TA[0-9]{4} pattern
- At most 1 `coverage` field with enum value
- Optional `subtechniques` array if subtechniques apply

Invalid: Coverage with no technique ID
Invalid: Coverage with multiple technique IDs
Valid: Multiple coverage objects for multiple techniques

### Identifier Uniqueness

- All CAR analytic IDs must be globally unique
- All Data Model entity names must be unique within their domain
- All Sensor definitions are identified by (sensor_name, sensor_version) tuple

### Cross-Reference Consistency

- All `data_model_references` must point to valid data model entities
- All `d3fend_mappings` must reference valid D3FEND IRIs
- All technique references must use valid ATT&CK identifiers

---

## Data Type Specifications

| Field | Type | Format | Constraints |
| ----- | ---- | ------ | ----------- |
| id (Analytic) | string | CAR-YYYY-MM-NNN | Pattern enforced |
| technique | string | T[0-9]{4} | 4-digit code required |
| tactics | string | TA[0-9]{4} | 4-digit code required |
| subtechniques | string | T[0-9]{4}\\.[0-9]{3} | 4-digit.3-digit format |
| sensor_url | string | URI | Valid HTTP/HTTPS URL |
| coverage level | string | Enum | Low, Moderate, or High only |
| submission_date | string | YYYY/MM/DD | Date format with slashes |

---

## Usage Examples

### Valid Analytic Coverage

```json
"coverage": [
  {
    "technique": "T1039",
    "tactics": ["TA0009"],
    "coverage": "Moderate"
  },
  {
    "technique": "T1021",
    "tactics": ["TA0008"],
    "subtechniques": ["T1021.002"],
    "coverage": "Moderate"
  }
]
```

### Valid D3FEND Mapping

```json
"d3fend_mappings": [
  {
    "iri": "d3f:IPCTrafficAnalysis",
    "id": "D3-IPCTA",
    "label": "IPC Traffic Analysis"
  }
]
```

### Valid Sensor Mapping

```json
"mappings": [
  {
    "object": "file",
    "action": "create",
    "notes": "Mapped to Event 11: SYSMON_FILE_CREATE",
    "fields": ["fqdn", "image_path", "pid", "file_path", "creation_time"]
  }
]
```

---

## Version History

- **v1.0** (March 2026) - Initial JSON Schema definition for CAR standard, including Analytic, DataModel, and Sensor entities
