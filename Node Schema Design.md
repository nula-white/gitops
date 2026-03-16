@dataclass
class NormalizedNode:
    node_id: str          # deterministic hash(file+line+col+type)
    node_type: NodeType   # PROGRAM, FUNCTION, BLOCK, ASSIGN, etc.
    raw_type: str         # original tree-sitter node type (for debugging)
    language: Language    # source language enum
    name: str | None      # identifier name if applicable
    value: str | None     # literal value if applicable
    file_path: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    raw_text: str         # source snippet (for tokenization)
    depth: int            # depth in AST tree
    security_label: SecurityLabel | None  # SOURCE, SINK, SANITIZER, None
    parent_id: str | None
    children_ids: list[str]
    attributes: dict      # language-specific extras
```

---

## 5. The Security Annotation Strategy

This is the most security-critical part. We need a **tiered annotation system**:

**Tier 1 — Syntactic (AST-level, language-agnostic):**
- Any CALL node whose name matches known sink patterns (e.g., `exec`, `eval`, `system`, `db.execute`)
- Any IDENTIFIER that receives external input patterns

**Tier 2 — Semantic (will be enriched in DFG stage):**
- Nodes tagged with `POTENTIAL_SOURCE`, `POTENTIAL_SINK` at parse time get resolved in DFG

**Language-specific sink/source registries** per language — this is a config-driven approach so we can extend without code changes.

---

## 6. Output Format Decisions

The output must serve **three downstream consumers**:
1. **CFG builder** — needs FUNCTION/BLOCK/IF/LOOP nodes with children
2. **DFG builder** — needs ASSIGN/CALL/IDENTIFIER nodes with data relationships
3. **GraphCodeBERT** — needs `(token_sequence, dfg_edges)` pairs

Therefore the output is a `ParsedGraphOutput` containing:
- The full normalized node list (for graph storage in Neo4j/Joern)
- The edge list (AST_CHILD edges, ready to be extended with CFG/DFG edges)
- A flat token sequence (for transformer input)
- File-level metadata
- Security annotations summary

---

## 8. Azure Replacement Strategy (Free/Open Source)

Since you have no Azure account, here's the mapping:

| PRISM Azure Component               |                      Free Alternative                    |
|-------------------------------------|---------------------------------------------------------------------|
| Azure Container Instances (sandbox) | **Docker + gVisor** (rootless, sandboxed)                           |
| Azure Container Registry            | **Local Docker registry** or **GitHub Container Registry (free)**   |
| Azure Key Vault                     | **HashiCorp Vault (OSS)** or **SOPS + age encryption** |
| Azure Monitor                       | **Prometheus + Grafana (OSS stack)** |
| Azure Blob Storage                  | **MinIO** (S3-compatible, self-hosted) |
| ACI ephemeral VMs                   | **Firecracker microVMs** (local) or **Docker --rm containers** |

---

## 9. File Structure Plan
```
prism/
└── parser/
    ├── __init__.py
    ├── language_detector.py       # file → Language enum
    ├── registry.py                # ParserRegistry (strategy attern)
    ├── base.py                    # AbstractParser protocol
    ├── models.py                  # All dataclasses (NormalizedNode, Edge, etc.)
    ├── normalizer.py              # RawAST → NormalizedNode mapping
    ├── security_annotator.py      # SOURCE/SINK/SANITIZER labeling
    ├── graph_builder.py           # Assembles ParsedGraphOutput
    ├── token_extractor.py         # Produces token sequence for GraphCodeBERT
    ├── parsers/
    │   ├── treesitter_parser.py   # Rust, HCL, YAML, TSX
    │   ├── joern_delegate.py      # Delegates to Joern for C/C++/Java/JS/Go/Py
    │   └── fallback_parser.py     # Graceful degradation
    ├── sinks/
    │   ├── __init__.py
    │   ├── python_sinks.py
    │   ├── javascript_sinks.py
    │   ├── java_sinks.py
    │   ├── rust_sinks.py
    │   ├── go_sinks.py
    │   └── iac_sinks.py           # Terraform/YAML misconfigs
    └── tests/
        ├── test_parser.py
        └── fixtures/              # sample vulnerable code per language