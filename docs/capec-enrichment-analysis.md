# CAPEC Enrichment Analysis — kgcs-pipeline

**Status:** working draft (branch `feature/capec-enrichment`)
**Source schema:** `data/schemas/CAPEC/ap_schema_latest.xsd` (Core Attack Pattern schema v3.5.0, 2021-10-21)
**Raw data:** `data/raw/CAPEC/capec_latest.xml` (catalog v3.9, 2023-01-24 — content version, conforms to schema 3.5)
**Current baseline:** `etl/load_capec.py` + `spec/ontology/standards/capec-ontology-v1.0.owl` + `spec/shapes/capec.shacl.ttl`

---

## 1. Current state

What KGCS loads today from CAPEC (verified against the live graph, 2026-07-17):

| Artifact | Content | Graph evidence |
| --- | --- | --- |
| `AttackPattern` node | `capecId`, `name`, `status` | 615 nodes (56 Deprecated) |
| `DEMONSTRATED_BY` rel | `(Weakness)-[:DEMONSTRATED_BY]->(AttackPattern)` from `Related_Weaknesses` | 1,212 edges |
| `CHILD_OF` rel | `(AttackPattern)-[:CHILD_OF]->(AttackPattern)` from `Related_Attack_Patterns[Nature=ChildOf]` | 519 edges |
| `IMPLEMENTS` rel | `(AttackPattern)-[:IMPLEMENTS]->(Technique/SubTechnique)` from ATT&CK `Taxonomy_Mapping` | 235 edges |

Notes on the baseline:

- Unlike the CWE loader, `load_capec.py` already refreshes on re-run (`ON CREATE SET … ON MATCH SET …`) — no staleness debt here.
- **Key structural fact:** `capec-ontology-v1.0.owl` already declares essentially *every* property and helper class the XSD offers (`description`, `extendedDescription`, `abstraction`, `typicalSeverity`, `attackLikelihood`, `prerequisites`, `mitigations`, `indicators`, `canPrecede`, `hasConsequence`, `ExecutionStep`, `SkillRequirement`, `Consequence`, `Category`, `View`, …). The frozen spec anticipated this enrichment. Loading these fields **implements** the sealed v1.0 semantics rather than changing them; only SHACL shape additions (`capec.shacl.ttl` covers just `capecId` + `name` today) require a minor spec release.
- `Abstraction` is a *required* XSD attribute and the ontology declares `capec:abstraction`, but the loader never reads it — the graph cannot currently distinguish Meta from Detailed patterns even though `CHILD_OF` encodes that hierarchy.

## 2. What the XSD offers (AttackPatternType inventory)

Attributes: `ID`, `Name`, `Status` (loaded) — plus `Abstraction` (**required in XSD, not loaded**).

Child elements, grouped by what they would become in the graph, with real coverage measured over the 559 non-deprecated patterns of catalog v3.9:

**A. Scalar / enum node properties (cheap):** Description (100%), Extended_Description (23%), Typical_Severity (87%, enum Very High…Very Low), Likelihood_Of_Attack (62%, enum High/Medium/Low/Unknown), Alternate_Terms (3%).

**B. Intra-standard relationships** (`Related_Attack_Patterns`, 91% of patterns): ChildOf 533 (loaded), CanPrecede 162, PeerOf 19, CanFollow 10, CanAlsoBe 3 — plus `Exclude_Related` exception annotations.

**C. Text-array node properties:** Prerequisites (88%, 747 items), Mitigations (72%, 1,172 items), Resources_Required (49%), Indicators (10%, 96 items), Example_Instances (48%, 388 items).

**D. Structured sub-records:** Consequences (66%, 814 records: Scope×Impact×Likelihood, all enum-controlled), Skills_Required (53%, 403 records: Level enum + text), Execution_Flow (43%, 815 Attack_Steps with Step/Phase/Description + 1,148 Technique texts — none carry a `CAPEC_ID` ref in v3.9).

**E. Cross-taxonomy:** Taxonomy_Mappings (40%): ATT&CK 272 (loaded as `IMPLEMENTS`), OWASP Attacks 39, WASC 37. **`Mapping_Fit` is empty in 348/348 real mappings** — the XSD offers it, the data doesn't populate it.

**F. Catalog-level entities:** 78 Categories, 13 Views, 440 External_References, Content_History, Notes (3%).

## 3. Enrichment-by-enrichment evaluation

### E1. Description + Extended_Description

- **Pros:** Same argument as CWE E2, and it holds even more strongly here: CAPEC is the *narrative* hop of the causal chain — the point where an agent explains *how* a weakness is exploited. Today the graph offers only a pattern name. `Description` is required in the XSD (100% coverage). This is the single cheapest way to reduce hallucination pressure on agents that reach an AttackPattern and have nothing to quote.
- **Cons:** StructuredText (embedded XHTML) needs flattening — same helper the CWE branch already wrote can be shared via a common utility rather than duplicated (`agents/shared/` rule applies to ETL too: extract to a shared `etl/` text-flattening helper).
- **KGCS impact:** Two datatype properties already in OWL v1.0. Loader: a few lines. SHACL: add `description` (minCount 1, Violation) + `extendedDescription` (optional) → minor spec release. No topology change.

### E2. Scalar attributes: `abstraction`, `typicalSeverity`, `attackLikelihood`

- **Pros:** `abstraction` (Meta 61 / Standard 181 / Detailed 317) is the semantic key that makes the existing `CHILD_OF` hierarchy interpretable — agents can climb from a Detailed pattern to its Meta ancestor and know what kind of generalization they performed. `typicalSeverity` (87%) and `attackLikelihood` (62%) are the only native prioritization signals CAPEC carries; they feed defensive triage queries ("high-likelihood, high-severity patterns exploiting CWEs present in my stack") and align with the SSVC/prioritization direction of KGCS 2.0. All three are closed enums — queryable without free text, SHACL-checkable with `sh:in`.
- **Cons:** None material. Missing values (13%/38%) simply stay absent — SHACL must keep them optional.
- **KGCS impact:** Three datatype properties already in OWL v1.0. Loader reads two attributes and two child elements. SHACL `sh:in` shapes → same minor spec release as E1.

### E3. Complete the intra-CAPEC relationship set (`CanPrecede`, `CanFollow`, `PeerOf`, `CanAlsoBe`)

- **Pros:** `CanPrecede` (162 edges) is the standout: it encodes **multi-stage attack sequencing** (e.g. footprinting → fingerprinting → exploitation), which no other standard in the chain expresses. It turns the CAPEC layer from a taxonomy into an attack-flow graph, enabling "what typically comes next" defensive reasoning. Fully intra-standard: no causal-chain violation. `PeerOf`/`CanAlsoBe` are cheap to include in the same pass but low-volume (19+3).
- **Cons:** `CanFollow` (10) is largely the inverse of `CanPrecede` declared on the other side — normalize to a single `CAN_PRECEDE` direction in Python (dedup before write, per pipeline rules) rather than storing both directions. `Exclude_Related` exceptions exist in the data; at minimum preserve them as an edge property, or defer with an explicit note. Chains can be walked unboundedly — agent traversal templates must bound depth (same guardrail as CWE E1).
- **KGCS impact:** Object properties already in OWL v1.0 → Neo4j `CAN_PRECEDE`, `PEER_OF`, `CAN_ALSO_BE`. Loader: extend the existing `Related_Attack_Patterns` walk (currently filters to ChildOf only). Post-load invariants: no dangling targets, no self-loops. Agent templates updated to expose sequencing.

### E4. Consequences (Scope × Technical_Impact × Likelihood)

- **Pros:** 814 structured records under closed enums — the same shape as CWE's Common_Consequences, so the two standards should take the **same modeling decision** (consistency across the graph beats local optimization). Gives agents impact semantics at the attack level ("patterns whose success yields privilege gain"), bridging naturally to CVSS interpretation on the CVE side and to D3FEND selection on the defensive side.
- **Cons:** Same flattening dilemma as CWE E5: arrays on the node (`consequences: ["Integrity:Modify Data", …]`) lose per-consequence grouping; `Consequence` sub-nodes add schema surface. OWL v1.0 already declares the `Consequence` class + `hasConsequence`, so sub-nodes are spec-sanctioned — but the decision must be taken **once, jointly with the CWE branch**, before either loader writes.
- **KGCS impact:** Modeling decision first (schema-first rule), then loader + SHACL + post-load enum checks. If sub-nodes: new label in constraints init, load order after AttackPattern nodes.

### E5. Prerequisites, Skills_Required, Resources_Required

- **Pros:** Feasibility context: what must be true (Prerequisites, 88%), what the adversary must know (Skills with Level enum, 53%) and possess (Resources, 49%). Lets defensive agents reason about attack difficulty and lets the Systems agent qualify exposure ("prerequisite requires local access — not reachable from the internet-facing surface"). Prerequisites' 88% coverage is among the highest of the unloaded fields.
- **Cons:** All free text except the skill Level — grounding value is quotational, not queryable. Skills' Level-plus-text structure either flattens (`skillsRequired: ["High: Knowledge of XML parsing", …]`) or follows the `SkillRequirement` sub-node route — should ride on whatever E4 decides.
- **KGCS impact:** Properties/classes already in OWL v1.0. Text arrays are loader-trivial; skills follow the E4 modeling decision. SHACL optional arrays.

### E6. Mitigations + Indicators

- **Pros:** Textual defensive grounding attached directly to the pattern. The chain's defensive tail (D3FEND/CAR/SHIELD/ENGAGE) covers *techniques*; CAPEC Mitigations (1,172 items, 72%) speak at the *pattern* level and often say concrete things ("use parameterized queries") an agent can quote verbatim. Indicators feed detection reasoning alongside CAR.
- **Cons:** Free text, occasional overlap/near-duplication with CWE Potential_Mitigations one hop upstream — agents quoting both layers must attribute provenance per source (standards-alignment rule). Indicators' coverage is thin (10%) — set expectations accordingly.
- **KGCS impact:** Two array properties already in OWL v1.0; loader-trivial; SHACL optional. No topology change.

### E7. Execution_Flow → ExecutionStep sub-nodes

- **Pros:** The richest structure CAPEC has: ordered steps with an Explore/Experiment/Exploit phase enum. For 239 (mostly Detailed) patterns, an agent could narrate the attack step-by-step with full provenance. OWL v1.0 already models `ExecutionStep` + `hasExecutionStep` + `stepNumber/stepPhase/stepDescription`.
- **Cons:** Highest cost of the list: ~815 sub-nodes plus ordered edges, XHTML flattening, constraints for a new label, and 1,148 Technique texts that in v3.9 carry no machine-readable refs (`CAPEC_ID` attr: 0 occurrences) — they'd load as plain step text. Coverage is 43% and skews Detailed. The narrative payoff partially duplicates what E1's Description already gives.
- **KGCS impact:** New node label (`ExecutionStep`) in `init_constraints.py`, ordered relationship (`HAS_STEP` with `stepNumber`), SHACL shape, post-load invariants (step numbering contiguous per pattern). Worth doing *after* the cheap layers prove useful — not alongside them.

### E8. Taxonomy mappings beyond ATT&CK (OWASP Attacks, WASC) — and `Mapping_Fit`

- **Pros:** OWASP/WASC labels aid entity resolution when users speak OWASP vocabulary.
- **Cons:** **Evidence kills the headline feature:** `Mapping_Fit` — the quality qualifier the XSD advertises and the v1.0 mapping doc planned for confidence scoring — is empty in all 348 real mappings. There is nothing to load. OWASP/WASC targets have no node types in the 10-standard graph; they'd be string properties (`owaspMapping: ["Injection", …]`) of modest value (39+37 occurrences).
- **KGCS impact:** If loaded: two array properties, no edges (no shortcut risk — these are annotations, not graph hops). Defer without regret; revisit if a future catalog populates Mapping_Fit.

### E9. Alternate_Terms

- **Pros:** Synonym support for NL entity resolution ("XSS" → CAPEC-63). Near-zero cost, already in OWL.
- **Cons:** Near-zero coverage too: 17 patterns, 27 terms. The payoff is real but tiny.
- **KGCS impact:** One array property; piggyback on any loader pass touching the same elements — not worth its own effort.

### E10. Example_Instances — with an explicit causal-chain guardrail

- **Pros:** Concrete narrative examples (48% coverage) an agent can quote.
- **Cons:** **42 patterns embed CVE identifiers in example text.** The temptation is to extract them into `(AttackPattern)→(Vulnerability)` edges — that is precisely the shortcut edge the causal chain prohibits (`CVE→CAPEC` bypassing CWE), and unlike curated third-party mappings these are illustrative anecdotes, not provenance-graded links. If loaded, examples must stay **opaque text**; the ETL must not parse IDs out of them, and this prohibition should be stated in the loader docstring.
- **KGCS impact:** One array property (already in OWL) + a documented guardrail. Value is decent, risk is procedural — priority stays low but non-zero.

### E11. Categories and Views

- **Pros:** Navigation/grouping layer (78 Categories, 13 Views incl. the Mechanisms/Domains of Attack graphs); OWL classes already exist.
- **Cons:** Unlike CWE (where Categories rescue dropped legacy NVD links), nothing external references CAPEC Categories — there is no coverage hole to fix. Pure additive surface: two new labels, membership edges, constraints.
- **KGCS impact:** New labels + `MEMBER_OF` edges; defer until an agent use-case (browse-by-mechanism) actually demands it.

### E12. References, Notes, Content_History

- Provenance/editorial metadata; Notes at 3%. External_References (440) only matter if a research use-case needs bibliography. **Skip** for the enrichment; `Content_History` is CAPEC-internal editorial trail, not graph knowledge.

## 4. Cross-cutting decisions surfaced by this analysis

1. **Status policy must differ from the CWE mapping doc's advice.** The v1.0 mapping doc says Draft entries should not be processed — but 402 of 615 patterns (72% of the non-deprecated catalog) are Draft. CAPEC has been majority-Draft for years; filtering them would gut the layer. Keep loading all statuses (current behavior), keep `status` on the node, and let agent templates decide exposure. Record this as an explicit, justified deviation from the mapping doc.
2. **Consequence/Skill modeling must be decided jointly with the CWE enrichment branch** (arrays vs sub-nodes) — one decision, two loaders, consistent graph.
3. **Shared XHTML flattening helper** — both branches need StructuredText→plain-text; extract once (e.g. `etl/textutil.py`) instead of duplicating.
4. **Spec impact is smaller than it looks:** OWL v1.0 already declares everything; only `capec.shacl.ttl` grows. One minor spec release (SHACL additions for CWE + CAPEC together) can cover both enrichment branches.
5. **Schema file vs catalog drift:** the stored XSD is 3.5 (2021) while the catalog content is v3.9 (2023). Structures used here exist in both; when the downloader is next touched, fetch the matching schema version alongside the catalog.

## 5. Priority table

| # | Enrichment | Coverage (real, non-depr.) | Value for KGCS | Cost | Chain risk | Priority |
| --- | --- | --- | --- | --- | --- | --- |
| E1 | Description + Extended_Description | 100% / 23% | Grounding text for the narrative hop — anti-hallucination core | Low (shared flattener) | None | **P0** |
| E2 | abstraction, typicalSeverity, attackLikelihood | 100% / 87% / 62% | Makes CHILD_OF interpretable; native prioritization enums | Very low | None | **P0** |
| E3 | CanPrecede (+CanFollow normalized), PeerOf, CanAlsoBe | 162+10 / 19 / 3 edges | Multi-stage attack sequencing — unique to CAPEC | Low-medium | None (intra-standard) | **P1** |
| E4 | Consequences (Scope×Impact×Likelihood) | 66%, 814 records | Structured impact semantics; CVSS/D3FEND bridge | Medium (modeling decision w/ CWE) | None | **P1** |
| E5 | Prerequisites, Skills, Resources | 88% / 53% / 49% | Attack feasibility context | Low (rides E4 decision for skills) | None | **P2** |
| E6 | Mitigations + Indicators | 72% / 10% | Pattern-level defensive text; detection hints | Low | None | **P2** |
| E7 | Execution_Flow → ExecutionStep sub-nodes | 43%, 815 steps | Step-by-step attack narration | High (new label, ordering invariants) | None | **P3** |
| E10 | Example_Instances (opaque text only) | 48% | Quotable concrete examples | Low + guardrail | **High if IDs extracted — forbidden** | **P3** |
| E9 | Alternate_Terms | 3% | NL synonym resolution | Trivial | None | **P3** (piggyback) |
| E11 | Categories + Views | 78 / 13 entities | Navigation layer, no coverage hole to fix | Medium | None | **Defer** |
| E8 | OWASP/WASC mappings, Mapping_Fit | 39+37; **Fit: 0/348 populated** | Marginal; headline field is empty in data | Low | None | **Defer** |
| E12 | References, Notes, Content_History | 61% / 3% / — | Editorial metadata | — | None | **Skip** |

**Suggested execution:** one loader pass shipping P0+P1 behind a single minor SHACL spec release (coordinated with the CWE branch), then reassess P2 against actual agent-query demand before touching P3.
