# 🧠 RAG Traversal Templates

> **(Query-Safe Paths)**

Below is a **formal set of RAG traversal templates** designed to be **query-safe, non-hallucinatory, and ontology-governed**, explicitly aligned with:

* **Core Ontology v1.0**
* **Asset Extension v1.0** (implemented)
* **Incident Extension** (planned)
* **Risk Extension** (planned)
* **ThreatActor Extension** (planned)

These templates are **not examples** — they are **approved traversal contracts** that an LLM (or agent) is allowed to follow.

Implementation rule: templates requiring planned extensions MUST be treated as unavailable until the corresponding extension OWL and shapes are present.

---

## 0. Why Traversal Templates Exist (Non-Negotiable)

> **RAG systems must not “reason freely” over graphs**
> They must follow **pre-approved paths** to avoid:

* invented causality
* probabilistic leakage
* attribution hallucination
* business logic pollution

A **Traversal Template** defines:

* allowed **start nodes**
* allowed **edge sequence**
* allowed **end nodes**
* **forbidden shortcuts**

---

## 1. Core Traversal Invariants (Global Rules)

These apply to **all templates**:

1. ❌ Never skip layers (e.g. CVE → Technique directly)
2. ❌ Never cross extensions unless explicitly allowed
3. ✅ Traverse from extension nodes into Core only through explicitly declared mapping edges
4. ❌ Never infer “used”, “caused”, or “exploited” unless edge exists
5. ✅ Always terminate on authoritative Core nodes for explanations

---

## 2. Core + Asset Baseline Traversal Templates

### T-CORE-01 — *Vulnerability → Defensive Options*

#### **Question answered**

> “How can this vulnerability be mitigated or detected?”

#### **Traversal**

```text
Vulnerability
 → Weakness
 → AttackPattern
 → Technique
 → (DefensiveTechnique | DetectionAnalytic | DeceptionTechnique)
```

#### **Why safe**

* Follows the causal backbone
* No incident or attribution inference

---

### T-CORE-02 — *Asset Exposure Analysis*

#### **Question answered**

> “What attack techniques are relevant to this asset?”

#### **Traversal**

```text
Asset
 → PlatformConfiguration
 → Vulnerability
 → Weakness
 → AttackPattern
 → Technique
```

#### **Forbidden**

* ❌ Asset → Technique (direct)

---

### T-CORE-03 — *Technique Context*

#### **Question answered**

> “What is this technique, and how is it usually handled?”

#### **Traversal**

```text
Technique
 → Tactic
 → DefensiveTechnique
 → DetectionAnalytic
 → DeceptionTechnique
```

---

## 3. Incident Extension Traversal Templates

Status: **planned** (activate only when Incident extension artifacts are available).

### T-INC-01 — *Incident → What Happened*

#### **Question answered**

> “What techniques were observed in this incident?”

#### **Traversal**

```text
Incident
 → ObservedTechnique
 → Technique
```

#### **Rule**

* `ObservedTechnique` is mandatory (no abstraction jumps)

---

## 4. ThreatActor Extension Traversal Templates

Status: **planned** (activate only when ThreatActor extension artifacts are available).

### T-TA-01 — *Attribution Reasoning*

#### **Question answered**

> “Who might be responsible for this incident?”

#### **Traversal**

```text
Incident
 → AttributionClaim
 → ThreatActor
```

#### **Hard rule**

* ❌ Incident → ThreatActor (direct) is illegal

---

## 5. Risk Extension Traversal Templates

Status: **planned** (activate only when Risk extension artifacts are available).

### T-RISK-01 — *Risk Prioritization*

#### **Question answered**

> “Which vulnerabilities should we fix first?”

#### **Traversal**

```text
Asset
 → Vulnerability
 → RiskScenario
 → RiskScore
```

#### **Rule**

* CVSS is referenced, never overridden

---

## 6. Cross-Extension (Explicitly Allowed) Templates

Status: **planned** (requires Incident + Risk extensions).

### T-X-01 — *Incident → Risk Escalation*

#### **Question answered**

> “How does this incident affect our risk posture?”

#### **Traversal**

```text
Incident
 → ObservedTechnique
 → Technique
 → RiskScenario
 → RiskScore
```

---

## 7. Forbidden Traversals (Global Blacklist)

These must be **hard-blocked** in RAG:

❌ CVE → ThreatActor
❌ Incident → Vulnerability
❌ ThreatActor → Weakness
❌ RiskScore → Technique
❌ Detection → ThreatActor
❌ Incident → Decision

If a user asks a question that *requires* one of these paths → **the system must answer with uncertainty**.

---

## 8. How to Enforce This in Practice

### Option A — Static Path Registry

* Encode templates as allowed edge sequences
* Reject queries outside registry

### Option B — Query Planner + Validator

1. LLM proposes traversal
2. Validator checks against template list
3. Only then execute graph query

### Option C — Prompt-Bound RAG

Inject templates directly into system prompt:

> “You may only answer by following one of the approved traversal templates…”

---

## 🔜 Natural Next Steps (High Value)

1. 🛡️ **SHACL validation rules** per template
2. 🧠 **Traversal-aware prompt engineering**
3. ⚙️ **Automatic query planner** (LLM → Cypher/SPARQL)
4. 📊 **Decision dashboards driven by Risk templates**
