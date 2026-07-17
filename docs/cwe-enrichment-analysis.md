# CWE Enrichment Analysis — kgcs-pipeline

**Status:** working draft (branch `feature/cwe-enrichment`, uncommitted)
**Source schema:** `data/schemas/CWE/cwe_schema_latest.xsd` (Core Definition v7.3, 2025-12-11)
**Raw data:** `data/raw/CWE/cwec_v4.20.xml`
**Current baseline:** `etl/load_cwe.py` + `spec/ontology/standards/cwe-ontology-v1.0.owl` + `spec/shapes/cwe.shacl.ttl`

---

## 1. Current state

What KGCS loads today from CWE:

| Artifact | Content |
| --- | --- |
| `Weakness` node | `cweId`, `name`, `abstraction` (ON CREATE only) |
| `CAUSED_BY` rel | `(Vulnerability)-[:CAUSED_BY]->(Weakness)` from NVD `weaknesses[]` |

Notes on the baseline:

- The spec module (`cwe-ontology-v1.0.owl`) only declares `cweId` and `abstraction`; `name` is set by the loader but is not in the CWE module (presumably covered by core). Any enrichment must land **spec-first** as a versioned successor/extension (v1.0 is frozen).
- `Categories` and `Views` from the catalog are not loaded. The loader already logs the consequence: legacy NVD mappings to Category IDs (CWE-16, CWE-19, CWE-254…) are counted as `skipped_unmapped_cwe` and dropped.
- The Cypher uses `ON CREATE SET` only, so re-runs never refresh `name`/`abstraction`. Any enrichment pass should revisit this (`ON CREATE SET … ON MATCH SET …`) or properties will go stale across CWE releases.

## 2. What the XSD offers (WeaknessType inventory)

Weakness attributes: `ID`, `Name`, `Abstraction` (loaded) — plus `Structure`, `Status`, `Diagram` (not loaded).

Weakness child elements, grouped by what they would become in the graph:

**A. Scalar / array node properties (cheap):** Description, Extended_Description, Likelihood_Of_Exploit, Alternate_Terms, Functional_Areas, Affected_Resources, Weakness_Ordinalities, Modes_Of_Introduction, Mapping_Notes (Usage/Reasons), Background_Details.

**B. Intra-standard relationships:** Related_Weaknesses (ChildOf, ParentOf, StartsWith, CanFollow, CanPrecede, RequiredBy, Requires, CanAlsoBe, PeerOf — with View_ID, Ordinal=Primary, Chain_ID).

**C. Structured sub-records:** Common_Consequences (Scope/Impact/Likelihood), Detection_Methods (Method/Effectiveness), Potential_Mitigations (Phase/Strategy/Effectiveness), Applicable_Platforms (Language/OS/Architecture/Technology × Prevalence, optional CPE_ID).

**D. Cross-standard references:** Observed_Examples (CVE IDs), Related_Attack_Patterns (CAPEC IDs), Taxonomy_Mappings (OWASP Top Ten, CERT, ISA/IEC 62443…).

**E. Catalog-level entities:** Categories, Views, External_References, Content_History.

**F. Long-form content:** Demonstrative_Examples (XHTML + code), Notes, References.

## 3. Enrichment-by-enrichment evaluation

### E1. Related_Weaknesses → CWE↔CWE hierarchy and chain edges

The single highest-value gap. CWE is a graph, and KGCS currently loads it as a flat list.

- **Pros:** Enables abstraction traversal — NVD maps most CVEs to Base/Variant CWEs while CAPEC's `Related_Weaknesses` often attaches at Class/Base level; without `CHILD_OF` edges, a CVE grounded at a Variant can be unreachable from any CAPEC node, silently truncating the causal chain in practice. Chain edges (`CanPrecede`/`CanFollow`) and composite edges (`Requires`/`RequiredBy`) model CWE Chains/Composites explicitly (matches the `Structure` attribute). Fully intra-standard: **no causal-chain violation** — the chain constrains hops *between* standards, not within one.
- **Cons / risks:** Relationships are view-scoped (`View_ID`); loading all views mixes perspectives. Mitigation: load only View 1000 (Research Concepts, the complete weakness hierarchy) and keep `viewId` + `ordinal` as edge properties. `CanFollow`/`CanPrecede` can form long chains — traversal templates must bound depth. Targets can be Deprecated entries — filter by `Status`.
- **KGCS impact:** New object properties in a CWE extension module (e.g. `child_of`, `can_precede`, `requires`, `peer_of` → Neo4j `CHILD_OF`, `CAN_PRECEDE`, `REQUIRES`, `PEER_OF`), SHACL shapes, loader pass 2 (after all Weakness nodes exist), new post-load invariants (no dangling targets, one Primary ChildOf per weakness per view), and an update to RAG traversal templates so agents may climb the hierarchy before crossing to CAPEC. Spec release required.

### E2. Description + Extended_Description

- **Pros:** This is a *grounding* project and the graph currently has no definitional text for weaknesses. Descriptions are what agents quote instead of hallucinating. Required in the XSD, so 100% coverage. Trivially cheap for `Description`.
- **Cons:** `Extended_Description` is StructuredText (embedded XHTML) — needs flattening to plain text; some are long. Node property size grows but stays modest (~30 MB XML total).
- **KGCS impact:** Two datatype properties in the extension module + SHACL (`description` minCount 1), loader change is a few lines. No topology change. Spec release required (small).

### E3. Mapping_Notes → `usage` (Allowed / Allowed-with-Review / Discouraged / Prohibited)

- **Pros:** Directly operational: tells agents whether a CWE is a legitimate mapping target for real-world vulnerabilities. Explains *why* NVD data maps to odd entries and lets the Systems agent qualify confidence. Cheap enum property; `Mapping_Notes` is mandatory in the XSD.
- **Cons:** None material. Optionally also store `Reasons` types as an array.
- **KGCS impact:** One datatype property + SHACL `sh:in` (4 values). Confidence logic in agents can consume it later (aligned with "confidence logic aligned with query type").

### E4. Weakness attributes: `Structure`, `Status` (and `Diagram`)

- **Pros:** `Status=Deprecated/Obsolete` lets the loader and agents filter dead entries (today deprecated weaknesses load like live ones). `Structure` (Simple/Chain/Composite) is the semantic companion to E1's chain/composite edges. Near-zero cost.
- **Cons:** None. `Diagram` is a filename with little standalone value — skip.
- **KGCS impact:** Two enum datatype properties + SHACL. Decide policy: still load Deprecated nodes (NVD legacy CVEs may point at them — keep, flagged) but exclude them from agent-facing templates.

### E5. Common_Consequences (Scope / Impact / Likelihood)

- **Pros:** Structured impact semantics (Confidentiality/Integrity/Availability/Access Control… × 26 technical impacts). Bridges naturally to CVSS interpretation and to defensive reasoning ("weaknesses whose exploitation yields code execution"). Enum-controlled, so queryable without free text.
- **Cons:** One weakness has N consequences each with M scopes × impacts — flattening to arrays loses the per-consequence grouping. Modeling as `Consequence` nodes adds a node type not in the 10 standards (acceptable as CWE-internal detail, but it's schema surface). Middle ground: JSON-ish flattened arrays `consequences: ["Confidentiality:Read Application Data", …]` keeps it on the node at the cost of elegance.
- **KGCS impact:** Requires a modeling decision in the spec (property arrays vs. sub-nodes) before any loader work — this is exactly the schema-first case. Post-load check: values within the two enums.

### E6. Categories (and the legacy-NVD coverage hole)

- **Pros:** Recovers the CAUSED_BY pairs currently dropped (`skipped_unmapped_cwe`): legacy CVEs mapped to CWE-16/19/254 etc. would finally resolve. Categories also give agents a navigation/grouping layer.
- **Cons:** MITRE is explicit that Categories "should not be mapped to by external sources" — the graph would be encoding a known-legacy practice. Mixing Categories into `:Weakness` would corrupt semantics; they need their own label (e.g. `:WeaknessCategory`) and a distinct edge for the legacy links (e.g. `CAUSED_BY` with `provenance:"nvd-legacy-category"` or a separate `CATEGORIZED_AS`), plus `MEMBER_OF` structure edges.
- **KGCS impact:** New class in the spec, new SHACL shape, loader third pass, and agent templates must *not* treat categories as weaknesses (usage=Prohibited maps cleanly here). Worth doing, but strictly after E3 so the Prohibited/Discouraged machinery exists.

### E7. Alternate_Terms

- **Pros:** Synonym list ("XSS", "SQLi", "Path Traversal"…) — high leverage for entity resolution when agents parse user questions or third-party reports into cweIds. Very cheap (string array).
- **Cons:** Sparse (only well-known weaknesses have terms). None otherwise.
- **KGCS impact:** One array property + SHACL. Immediately usable by the server's lookup layer.

### E8. Likelihood_Of_Exploit

- **Pros:** Coarse prioritization signal (High/Medium/Low/Unknown) at the weakness level; complements CVSS (vuln-level) and future EPSS (KGCS 2.0). One enum property.
- **Cons:** Sparse and static; MITRE hasn't curated it consistently. Must not be confused with EPSS-style probabilities — name it `likelihoodOfExploit` verbatim to keep provenance clear.
- **KGCS impact:** Trivial. SHACL `sh:in` + optionality.

### E9. Potential_Mitigations

- **Pros:** Rich defensive content (Phase × Strategy enum × Effectiveness enum + description) — the Defensive agent could ground "how do I prevent this class of bug" answers, an area where D3FEND coverage via the full chain is sparse.
- **Cons:** Long descriptions (StructuredText); several mitigations per weakness. Strong temptation to auto-link Strategy values to D3FEND techniques — that would be an **inferred shortcut edge and is prohibited**; mitigations must stay as CWE-internal data. Modeling question same as E5 (arrays vs. sub-nodes).
- **KGCS impact:** Spec modeling decision needed; if sub-nodes, new node type + shapes. Loader straightforward. No topology risk if kept internal.

### E10. Detection_Methods

- **Pros:** Method (19-value enum) + Effectiveness — grounds "how would you detect this weakness" answers; complements CAR analytics (which enter via ATT&CK, several hops away). Enum-controlled and compact.
- **Cons:** Same shortcut-edge temptation toward CAR/D3FEND — keep as node data. Sparse for hardware CWEs.
- **KGCS impact:** Small; same modeling pattern as E9 (decide once, apply to both).

### E11. Observed_Examples (curated CVE references)

- **Pros:** MITRE-curated CVE↔CWE exemplar pairs with descriptions — first-party provenance, richer than NVD's sometimes-mechanical mappings. Could add `CAUSED_BY` edges with `provenance:"cwe-observed-example"` where the CVE node exists, cross-validating NVD.
- **Cons:** Many referenced CVEs are ancient; some won't exist as nodes (MATCH-only, count misses — same pattern as today's unmapped counter). Edge property provenance must not overwrite NVD provenance when both agree (MERGE on edge + set-union of sources).
- **KGCS impact:** No new edge type (reuses `CAUSED_BY`), but the provenance-merging pattern needs a small design note; post-load check that no `CAUSED_BY` lost its source. Medium effort, medium value.

### E12. Applicable_Platforms

- **Pros:** Language/OS/Architecture/Technology applicability with Prevalence — lets agents scope answers ("memory-unsafe language weaknesses", "ICS/OT-relevant weaknesses").
- **Cons:** **Highest guardrail risk in the whole schema.** The optional `CPE_ID` attribute on Operating_System invites a `Platform → Weakness` edge — that is exactly the prohibited shortcut (`CPE` must reach `Weakness` only through `CVE`). Must be loaded as node properties/classes only, never as edges to CPE nodes. Also: four sub-structures × (Name|Class) × Prevalence flattens awkwardly.
- **KGCS impact:** Properties-only modeling, explicit note in the mapping doc forbidding CPE linkage. Medium effort for modest query value — the honest platform signal in KGCS remains CPE→CVE.

### E13. Taxonomy_Mappings (OWASP Top Ten, CERT, ISA/IEC 62443…)

- **Pros:** Compliance-flavored queries ("weaknesses in OWASP Top Ten") become possible; ISA/IEC 62443 mapping is interesting for ICS work.
- **Cons:** Introduces external taxonomies that are not among the 10 KGCS standards — scope creep for the 1.x line; provenance rules demand keeping them clearly separated. Mapping_Fit adds nuance that's hard to encode compactly.
- **KGCS impact:** If done, store as structured properties (`taxonomyMappings: ["OWASP Top Ten:A03", …]`) rather than nodes, or defer to a 2.0 extension where external overlays (KEV/EPSS/SSVC) are already planned. Defer.

### E14. Functional_Areas + Affected_Resources + Modes_Of_Introduction + Weakness_Ordinalities

- **Pros:** All enum-controlled, all cheap array/scalar properties; each adds a legitimate query facet (lifecycle phase of introduction, affected resource, primary-vs-resultant ordinality).
- **Cons:** Individually low value; collectively they widen the SHACL surface. Ordinalities and Modes carry optional free-text notes — drop the notes, keep the enums.
- **KGCS impact:** Bundle them into the same spec release as other property work; near-zero loader complexity (same iterparse pass).

### E15. Demonstrative_Examples, References/External_References, Background_Details, Notes, Content_History, Views

- **Pros:** Demonstrative code examples are great LLM few-shot material; references support research citation; Content_History provides versioning provenance.
- **Cons:** Heavy XHTML/free text; graph bloat with little traversal value; code examples belong in a document store or are fetchable from cwe.mitre.org at answer time (the agent can cite the CWE URL). Views are meta-organizational; External_References would add a node type with weak query value.
- **KGCS impact:** Skip for the graph. If few-shot code examples are ever wanted, serve them from raw XML at runtime rather than Neo4j.

### E16. Related_Attack_Patterns (CAPEC_ID)

- **Pros:** Same CWE→CAPEC linkage that `load_capec.py` presumably builds from the CAPEC side; loading from both directions enables cross-validation.
- **Cons:** Duplicate source for the same edge — loading both risks provenance mixing and duplicate-edge accounting; the causal chain edge should have one authoritative loader.
- **KGCS impact:** Do **not** load as edges here. Use it in `validation/` as a consistency check (symmetric difference between CWE-side and CAPEC-side declarations), which fits the post-load-invariants philosophy.

## 4. Cross-cutting implications

1. **Spec-first sequencing.** Everything above requires a kgcs-spec release first (new `cwe-extension-v1.1` module or successor ontology + SHACL + mapping doc + CHANGELOG), then a `SPEC_VERSION` bump here and `sync_spec.py --check` green. The frozen `cwe-ontology-v1.0.owl` is untouched.
2. **Loader architecture.** `load_cwe.py` grows from one streaming pass to: pass 1 nodes (with new properties), pass 2 intra-CWE relationships, pass 3 (optional) categories + observed-example provenance. iterparse must switch to capturing full `Weakness` subtrees (`end` events) instead of start-event attributes only.
3. **Idempotency fix.** Move enrichable properties to `ON CREATE SET … ON MATCH SET …` so CWE catalog updates propagate.
4. **Naming discipline.** OWL snake_case (`child_of`, `likelihood_of_exploit`) vs Neo4j SCREAMING_CASE (`CHILD_OF`) vs node props camelCase (`likelihoodOfExploit`); SHACL `sh:path` uses OWL names.
5. **Guardrails to encode in tests:** no `Platform/CPE → Weakness` edges (E12), no CWE-mitigation → D3FEND inferred edges (E9/E10), category nodes never targeted by agent weakness templates (E6), bounded chain traversal (E1).

## 5. Priority table

Criteria: **G** = grounding value for agents (1–5), **C** = implementation cost (1=low, 5=high), **R** = risk to KGCS invariants (1=none, 5=high). Priority = judgment over the three, not a formula.

| # | Priority | Enrichment | G | C | R | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| E1 | **P1** | Related_Weaknesses (CHILD_OF + chain/composite edges, View 1000) | 5 | 3 | 2 | Unlocks abstraction traversal CVE→…→CAPEC; biggest structural gap |
| E2 | **P1** | Description + Extended_Description | 5 | 1 | 1 | Core grounding text; trivial cost, 100% coverage |
| E3 | **P1** | Mapping_Notes → `usage` (+ reasons) | 4 | 1 | 1 | Agents learn which CWEs are legitimate mapping targets |
| E4 | **P1** | `Structure` + `Status` attributes | 3 | 1 | 1 | Deprecated filtering + companion to E1 chains; near-free |
| E7 | **P2** | Alternate_Terms | 4 | 1 | 1 | Entity resolution for agent input parsing |
| E5 | **P2** | Common_Consequences | 4 | 3 | 2 | Impact semantics; needs arrays-vs-subnodes spec decision first |
| E8 | **P2** | Likelihood_Of_Exploit | 3 | 1 | 1 | Cheap prioritization signal; keep provenance-distinct from EPSS |
| E6 | **P2** | Categories (+ legacy NVD coverage) | 3 | 3 | 3 | Fixes `skipped_unmapped_cwe`; needs own label + Prohibited semantics |
| E9 | **P3** | Potential_Mitigations | 4 | 3 | 3 | Defensive grounding; strict no-D3FEND-inference guardrail |
| E10 | **P3** | Detection_Methods | 3 | 2 | 2 | Detection grounding; same modeling pattern as E9 |
| E11 | **P3** | Observed_Examples → CAUSED_BY provenance | 3 | 3 | 2 | Cross-validates NVD; needs provenance-merge pattern |
| E14 | **P3** | Functional_Areas, Affected_Resources, Modes_Of_Introduction, Ordinalities | 2 | 1 | 1 | Cheap facets; bundle with any P1/P2 spec release |
| E12 | **P4** | Applicable_Platforms (properties only) | 2 | 3 | 4 | Modest value; highest shortcut-edge temptation (CPE_ID) |
| E13 | **P4** | Taxonomy_Mappings | 2 | 3 | 2 | Scope creep for 1.x; candidate for 2.0 overlays |
| E16 | **P4** | Related_Attack_Patterns | 2 | 1 | 3 | Don't load as edges; use as validation cross-check only |
| E15 | — | Demonstrative_Examples, References, Notes, Content_History, Views | 1 | 4 | 1 | Skip: graph bloat; serve from raw XML if ever needed |

**Suggested first increment (one spec release + one loader change):** E1 + E2 + E3 + E4, with E7/E8/E14 bundled opportunistically since they ride the same parsing pass. E5/E6 as a second increment once the sub-node modeling decision is made.
