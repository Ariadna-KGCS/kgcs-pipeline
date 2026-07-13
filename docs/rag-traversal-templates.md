
# 🧭 RAG Traversal Templates

**For Cybersecurity Core Ontology v1.0**

**Baseline:** frozen Core OWL v1.0 semantics only.

Below is a **clean, formal definition of RAG traversal templates** that is **strictly derived from Core Ontology v1.0** and aligned with its authoritative class/edge tables and invariants.

These templates align with the Core v1.0 specification in `docs/02-ontology/core-ontology-v1.0.md` and the namespace policy in `docs/02-ontology/namespace-policy-v1.0.md`.

This is **not prose guidance** — these are **machine-usable reasoning contracts**.

---

## 0. What a “Traversal Template” Is (Formal Definition)

A **RAG Traversal Template** is a **bounded, directional, typed graph walk** with:

1. **Allowed start node types**
2. **Allowed edge sequence**
3. **Explicit stop conditions**
4. **Guaranteed semantic outcome**
5. **Forbidden shortcuts**

> If a traversal violates a template, the answer **must be rejected**, not rephrased.

---

## 1. Canonical Constraints (Global)

These apply to **all** templates.

### 1.1 Allowed Node Set

Only Core Ontology classes:

```text
PlatformConfiguration
Vulnerability
VulnerabilityScore
Weakness
AttackPattern
Technique
SubTechnique
Tactic
DefensiveTechnique
DetectionAnalytic
DeceptionTechnique
EngagementConcept
Reference
```

### 1.2 Forbidden Nodes

```text
Asset
ThreatActor
Incident
Exploit
AttackInstance
RiskAssessment
Probability / Likelihood
```

### 1.3 Edge Integrity Rule

Every traversed edge **must exist verbatim** in the Core Ontology edge table .

---

## 2. Template T1 — Vulnerability Impact Explanation

### Intent

Explain **what a vulnerability is**, **why it exists**, and **how it manifests** — without operational advice.

### Start

```text
Vulnerability (CVE)
```

### Traversal

```text
Vulnerability
 → caused_by → Weakness
 → exploited_by → AttackPattern
 → implemented_as → Technique
 → belongs_to → Tactic
```

### Stop Conditions

* First `Tactic` reached
* Do not traverse mitigations or detections

### Guaranteed Output

* Root cause (CWE)
* Abstract exploitation logic (CAPEC)
* Concrete adversary behavior (ATT&CK)
* Operational intent (Tactic)

### Forbidden

❌ CVSS interpretation
❌ Mitigation advice
❌ Threat actor attribution

---

## 3. Template T2 — Severity & Scoring Explanation

### Intent

Explain **how severe** a vulnerability is and **why**, without prioritization.

### Start

```text
Vulnerability
```

### Traversal

```text
Vulnerability
 → scored_by → VulnerabilityScore (one or more)
```

### Stop Conditions

* One node per CVSS version

### Guaranteed Output

* Versioned severity values
* Vector strings
* Score provenance

### Forbidden

❌ Risk ranking
❌ Asset context
❌ “Critical for you” language

---

## 4. Template T3 — Detection-Centric Reasoning

### Intent

Answer: *“How could this be detected?”* (not *is it detected now*)

### Start (one of)

```text
Vulnerability
Technique
```

### Traversal (expanded)

```text
Vulnerability
 → caused_by → Weakness
 → exploited_by → AttackPattern
 → implemented_as → Technique
 → detected_by → DetectionAnalytic
```

### Alternative (if starting at Technique)

```text
Technique
 → detected_by → DetectionAnalytic
```

### Stop Conditions

* DetectionAnalytic reached

### Guaranteed Output

* Detection logic references (CAR)
* Technique-level observability

### Forbidden

❌ Telemetry availability
❌ Log source guarantees
❌ SOC-specific logic

---

## 5. Template T4 — Mitigation-Centric Reasoning

### Intent

Answer: *“What mitigates this behavior?”* at a **knowledge level**.

### Start

```text
Vulnerability
```

### Traversal

```text
Vulnerability
 → caused_by → Weakness
 → exploited_by → AttackPattern
 → implemented_as → Technique
 → mitigated_by → DefensiveTechnique
```

### Stop Conditions

* DefensiveTechnique reached

### Guaranteed Output

* Abstract defensive controls (D3FEND)
* Technique-to-defense mapping

### Forbidden

❌ Configuration steps
❌ Product recommendations
❌ Effectiveness claims

---

## 6. Template T5 — Deception & Adversary Disruption

### Intent

Explain **how an adversary could be disrupted or deceived**.

### Start

```text
Technique
```

### Traversal

```text
Technique
 → countered_by → DeceptionTechnique
```

### Optional Extension

```text
DeceptionTechnique
 ← disrupts ← EngagementConcept
```

### Stop Conditions

* EngagementConcept reached

### Guaranteed Output

* Deception options (SHIELD)
* Strategic engagement framing (ENGAGE)

### Forbidden

❌ Active defense execution
❌ Attribution
❌ Campaign claims

---

## 7. Template T6 — Reference & Evidence Grounding

### Intent

Provide **primary sources** supporting any claim.

### Start

```text
Vulnerability
```

### Traversal

```text
Vulnerability
 → references → Reference
```

### Stop Conditions

* All references collected

### Guaranteed Output

* URLs
* Source authority
* Verifiability

### Forbidden

❌ External enrichment
❌ Blog summaries
❌ Analyst opinion

---

## 8. Template T7 — End-to-End Defensive Reasoning (Gold Path)

### Intent

Answer:

> “What is this issue, how is it exploited, and how is it detected and mitigated?”

### Traversal (full chain)

```text
Vulnerability
 → caused_by → Weakness
 → exploited_by → AttackPattern
 → implemented_as → Technique
   ├─ detected_by → DetectionAnalytic
   └─ mitigated_by → DefensiveTechnique
```

### Stop Conditions

* Both detection and mitigation branches resolved

### Guarantees

* Fully explainable
* No hallucinated causality
* Standards-only grounding

---

## 9. Template Violation Matrix (Hard Fail)

| Violation              | Result           |
| ---------------------- | ---------------- |
| Skipping Weakness      | ❌ Reject answer |
| CVE → Technique direct | ❌ Reject        |
| Adding probability     | ❌ Reject        |
| Asset-based inference  | ❌ Reject        |
| Threat actor naming    | ❌ Reject        |

---

## 10. Why These Templates Work for RAG

Derived directly from:

* Core class table
* Authoritative edge table
* Provenance guarantees

They ensure:

* **Deterministic traversal**
* **Explainable answers**
* **Zero semantic leakage**
* **Safe LLM grounding**

---

## 11. Recommended Next Steps

Logical continuations (in order):

1. 🔐 **Traversal enforcement rules (JSON / Cypher)**
2. 🧠 Prompt → Template compiler
3. 📏 Max-hop policies
4. 🕸 Neo4j stored procedures
5. 🧪 Gold test questions per template
