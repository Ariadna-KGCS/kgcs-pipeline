# docs/historical

Documents inherited from the seed repo (July 2026) that no longer describe
the current pipeline. Kept for traceability; nothing here is normative.

| File | Why it is here | Current home of the topic |
| ---- | -------------- | ------------------------- |
| `DOWNLOAD_IMPLEMENTATION.md` | Build-time summary of the download scripts | `../../data/README.md`, `../pipeline-execution-guide.md` |
| `rag-traversal-templates.md` | Approved RAG traversal templates (query-safe paths) | **Pending migration to `kgcs-spec`** — see ROADMAP D7 |
| `rag-traversal-templates-extension.md` | Extension of the above | idem |
| `rag-to-shacl.md` | RAG template → SHACL shape-group mapping | idem; `kgcs-spec` `shapes/README.md` still links here |

The three RAG documents are the only copy in the Ariadna family (verified
2026-11-01: `kgcs-server` and `kgcs-spec` mention "approved traversal
templates" but do not contain them). They describe how agents *query* the
graph, not how the pipeline *builds* it, so their home is the spec. Until that
release happens, they stay here unchanged.
