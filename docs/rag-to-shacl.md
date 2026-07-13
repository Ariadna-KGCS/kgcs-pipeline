RAG template → SHACL shape mapping
=================================

This file maps each RAG traversal template to the primary SHACL shapes that should be validated or enforced before using the template for reasoning or RAG responses.

- Template T1 (Vulnerability Impact Explanation):
  - Validate NodeShapes targeting: `kgcs:Vulnerability`, `kgcs:Weakness`, `kgcs:AttackPattern`, `kgcs:Technique`, `kgcs:Tactic`

- Template T2 (Severity & Scoring Explanation):
  - Validate NodeShapes targeting: `kgcs:Vulnerability`, `kgcs:VulnerabilityScore`

- Template T3 (Detection-Centric Reasoning):
  - Validate NodeShapes targeting: `kgcs:Technique`, `kgcs:DetectionAnalytic`

- Template T4 (Mitigation-Centric Reasoning):
  - Validate NodeShapes targeting: `kgcs:Technique` and `kgcs:DefensiveTechnique` (if present)

- Template T5 (Deception & Adversary Disruption):
  - Validate NodeShapes targeting: `kgcs:Technique`, `kgcs:Tactic`, and deception classes (future)

- Template T6 (Reference & Evidence Grounding):
  - Validate NodeShape targeting `kgcs:Vulnerability` and `kgcs:Reference` presence (via `kgcs:references`)

- Template T7 (End-to-End Defensive Reasoning):
  - Validate: all classes from T1 plus `kgcs:DetectionAnalytic`, `kgcs:DefensiveTechnique`, and `kgcs:VulnerabilityScore`

Notes:

- The SHACL bundle `kgcs-shapes.ttl` provides core coverage; project teams should extend it with additional shapes for `DefensiveTechnique`, `Reference`, `DeceptionTechnique`, and extension-specific constraints as needed.

- This repository baseline uses canonical `kgcs:*` terms for Core concepts and validates against versioned shapes in `shapes/`.

- CI should run the relevant shape subset for the RAG path being used in retrieval/response.
