# PRISM — Zero-Trust Architecture for Confidential Code Analysis and Secure Infrastructure Generation

PRISM is a security analysis platform that examines application source code, constructs a Code Property Graph (CPG), detects vulnerabilities using static analysis and a fine-tuned GraphCodeBERT model, and generates secure Infrastructure-as-Code (IaC) recommendations. All processing runs inside ephemeral sandbox environments. Every critical pipeline event is recorded in an immutable audit ledger.

---

## Architecture Overview

```
Source Code
    ↓
Secure Repository Ingestion (TLS, ephemeral credentials)
    ↓
Ephemeral Sandbox (Azure Container / Docker)
    ↓
Parsing Layer — Tree-sitter AST (+ Joern for C/C++/Java/JS/Go/Python)
    ↓
AST Normalization (language-agnostic NodeType schema)
    ↓
CFG Construction (execution paths)
    ↓
DFG Construction (data propagation)
    ↓
Code Property Graph (CPG) — stored in Neo4j
    ↓
Hybrid AI Reasoning Layer
  ├── CodeQL (deterministic — known vulnerability signatures)
  └── GraphCodeBERT + LoRA (behavioral — emerging patterns)
    ↓
Vulnerability Risk Scoring + HITL checkpoint
    ↓
IaC Generation (Terraform + Ansible)
    ↓
HITL checkpoint
    ↓
Blockchain Audit Logging (Ethereum Sepolia / Hyperledger Fabric)
```

---

## Project Structure

```
prism/
├── backend/                        FastAPI analysis server
│   ├── main.py                     REST + WebSocket endpoints, pipeline orchestration
│   ├── requirements.txt
│   ├── .env.example
│   ├── core/
│   │   ├── models.py               CPGNode, CPGEdge, VulnerabilityFinding, WSEvent, enums
│   │   ├── cpg_builder.py          Async pipeline generator — AST/CFG/DFG + 8 vuln patterns
│   │   └── config.py               Pydantic-settings (Neo4j, Joern, sandbox, WS config)
│   ├── db/
│   │   └── neo4j_client.py         Async Neo4j driver — upsert, query, session cleanup
│   └── api/
│       └── session_manager.py      WebSocket registry, broadcast, heartbeat loop
│
├── frontend/                       React + TypeScript CPG live viewer
│   ├── index.html
│   ├── vite.config.ts              Dev proxy: /api + /ws → localhost:8000
│   ├── package.json
│   └── src/
│       ├── App.tsx
│       ├── main.tsx
│       ├── types/
│       │   └── index.ts            All types mirroring backend models exactly
│       ├── hooks/
│       │   ├── useCPGStream.ts     WebSocket hook — all 8 event types, node/edge/finding state
│       │   └── useGraphCanvas.ts   Canvas render loop — force physics, bezier edges, vuln glow
│       ├── components/
│       │   ├── CPGViewer.tsx       Full layout: header, stage bar, canvas, sidebar, legend
│       │   ├── FindingCard.tsx     Expandable card: severity, CWE, code snippet, remediation
│       │   ├── NodeTooltip.tsx     Hover tooltip: type, file:line, snippet, vuln status
│       │   ├── StageBar.tsx        8-phase pipeline progress indicator
│       │   └── CodeEditor.tsx      Source input with language selector + sample loader
│       └── tests/
│           └── frontend.test.ts    Vitest suite (type shapes, routing, sorting)
│
├── tests/
│   ├── run_tests.py                66-test standalone runner (zero external deps)
│   └── test_backend.py             pytest suite for live FastAPI + mocked Neo4j
│
├── ingestion/                      Repository ingestion layer
│   ├── pipeline.py                 7-stage orchestrator: validate→credential→fetch→verify→deliver→cleanup→audit
│   ├── models.py                   IngestionRequest, IngestionResult, RepoManifest, FileEntry
│   ├── validators.py               SSRF blocklist, URL scheme check, branch/SHA validation
│   ├── credential_provider.py      SecureString + Vault/env providers
│   ├── git_client.py               TLS-secured git clone with commit SHA pinning
│   ├── integrity_verifier.py       4-layer check: commit pin, symlink escape, Merkle manifest, size limits
│   ├── sandbox_delivery.py         Copy verified files to sandbox, enforce PathPolicy
│   ├── submodule_resolver.py       Recursive submodule fetch with SSRF validation
│   ├── adapters/                   GitHub, GitLab, Bitbucket, Azure DevOps adapters
│   ├── providers/                  Platform-specific provider implementations
│   ├── exceptions/                 Full exception hierarchy (48 classes, 7 layers)
│   └── tests/                      504 ingestion tests
│
├── parser/                         Parser layer
│   ├── registry.py                 Routes each file: Joern → Tree-sitter → Fallback
│   ├── models.py                   NormalizedNode, Edge, ParsedGraphOutput, GraphCodeBERTInput
│   ├── language_detector.py        Extension + content sniffing → Language enum
│   ├── input_validator.py          5 threats: resource exhaustion, ReDoS, path traversal, encoding, Trojan Source
│   ├── sandbox_config.py           Resource limits, PATH_POLICY, subprocess safe env, CodeQL flags
│   ├── security_annotator.py       Labels nodes SOURCE/SINK/SANITIZER/SENSITIVE
│   ├── normalizer.py               Language-specific AST → unified NodeType schema
│   ├── token_extractor.py          AST nodes → flat CodeToken list for GraphCodeBERT
│   ├── parsers/
│   │   ├── base.py                 AbstractParser interface
│   │   ├── treesitter_parser.py    Primary for Rust, HCL, YAML, TSX; fallback for others
│   │   ├── joern_delegate.py       CPG topology for C/C++/Java/JS/Go/Python via joern-parse
│   │   ├── codeql_parser.py        SARIF oracle — creates DB, runs security queries
│   │   └── fallback_parser.py      Regex tokeniser — always available, no external tools
│   ├── sinks/                      Security sink databases per language
│   └── tests/                      Parser + security hardening tests
│
├── graph_builder/                  CPG assembly layer
│   ├── graph_builder.py            Orchestrator: AST→CFG→DFG→sanitise→assemble→SARIF→Neo4j
│   ├── models.py                   CPGNode, CPGEdge, GraphBuildResult, NodeType/EdgeType enums
│   ├── cfg_builder.py              CFG edges (NEXT/TRUE/FALSE/LOOP/EXCEPTION)
│   ├── dfg_builder.py              DFG edges (FLOW/KILLS/DEPENDS) via intra-procedural symbol table
│   ├── sarif_injector.py           Maps CodeQL SARIF findings onto CPG nodes by file:line:col
│   ├── neo4j_writer.py             Batched Cypher MERGE writes, session namespacing, retry logic
│   ├── normalizer.py               Joern/Tree-sitter raw types → unified NodeType
│   ├── text_sanitizer.py           sanitize_for_llm(): strips comments/strings, removes bidi chars
│   └── tests/                      167 CPG build tests
│
├── ui/                             Flask dashboard (legacy)
│   ├── app.py                      /api/analyze, SSE event stream, graph JSON endpoint
│   └── templates/
│       └── index.html              vis.js graph, live log console, findings panel, stage dots
│
└── vault/                          HashiCorp Vault — local secret management
    ├── docker-compose.yml          Vault 1.17 container
    ├── .env.example
    └── vault-init/
        └── setup_prism_secrets.sh  KV v2 engine, AppRole, audit log setup
```

---

## Quick Start

### Prerequisites

- Python 3.11 or 3.12
- Node.js 18+
- Neo4j (local or Docker) — bolt://localhost:7687
- Java 11+ (required by Joern)
- Joern, CodeQL

### Backend

```bash
cd backend
cp .env.example .env           # fill in NEO4J_PASSWORD
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev                    # http://localhost:5173
```

### Run tests (zero external deps)

```bash
python3 tests/run_tests.py
# Expected: 66 passed | 0 failed | 66 total
```

---

## WebSocket Protocol

The frontend connects to `WS /ws/{session_id}` and sends a start event:

```json
{ "action": "start", "code": "...", "language": "python", "filename": "app.py" }
```

The backend streams `WSEvent` JSON objects in phase order:

| Event type    | Payload                                                      |
|---------------|--------------------------------------------------------------|
| `phase`       | `{ stage, label }` — pipeline phase transition              |
| `node`        | Full `CPGNode` object — appears as node is extracted        |
| `edge`        | Full `CPGEdge` object — CFG or DFG edge                     |
| `annotation`  | `{ node_id, annotated, vuln_id, severity }` — post-analysis |
| `finding`     | Full `VulnerabilityFinding` with snippet + remediation       |
| `complete`    | `{ node_count, edge_count, finding_count }`                  |
| `heartbeat`   | Empty — keep-alive every 15 seconds                         |
| `error`       | `{ message }`                                               |

Pipeline phase order: `PARSE → AST → NORMALIZE → CFG → DFG → CPG_MERGE → GRAPHCODEBERT → ANNOTATE → COMPLETE`

---

## Vulnerability Detection

PRISM detects 8 vulnerability classes out of the box. Each finding includes full metadata:

| Pattern                  | CWE       | Severity |
|--------------------------|-----------|----------|
| SQL Injection            | CWE-89    | HIGH     |
| Command Injection        | CWE-78    | HIGH     |
| Insecure Deserialisation | CWE-502   | HIGH     |
| Path Traversal           | CWE-22    | MEDIUM   |
| Hardcoded Secret         | CWE-798   | MEDIUM   |
| Cross-Site Scripting     | CWE-79    | MEDIUM   |
| Missing Authentication   | CWE-306   | MEDIUM   |
| Unsafe Regex (ReDoS)     | CWE-1333  | LOW      |

Every finding carries: `vuln_type`, `cwe`, `severity`, `confidence`, `file`, `line_start/end`, `function_name`, `description`, `code_snippet` (the actual triggering source lines), `data_flow_path`, `remediation`, and `references[]` (OWASP/CWE links).

---

## Neo4j Integration

Neo4j is never exposed directly to the frontend. The chain is always:

```
Neo4j ← FastAPI backend ← WebSocket/REST ← React frontend
```

**Schema:**

```cypher
(:CPGNode {id, session_id, node_type, language, file, line_start, line_end,
           col_start, col_end, name, code_snippet, phase, annotated, vuln_id})

(:CPGEdge {id, session_id, source_id, target_id, kind, label})

(:Finding {id, session_id, node_id, vuln_type, cwe, severity, confidence,
           file, line_start, line_end, function_name, description,
           code_snippet, data_flow_path, remediation, references})
```

The backend degrades gracefully when Neo4j is offline — the pipeline runs in-memory only and the frontend still receives all events. Set `NEO4J_URI`, `NEO4J_USER`, and `NEO4J_PASSWORD` in `backend/.env` to enable persistence.

**REST endpoints for graph retrieval:**

```
GET /api/session/{id}/graph     → { nodes: [...], edges: [...] }
GET /api/session/{id}/findings  → { findings: [...] }
```

---

## GraphCodeBERT Training Strategy

The model is trained in three stages using LoRA (Low-Rank Adaptation) for parameter-efficient fine-tuning:

| Stage       | Datasets                       | Purpose                                      |
|-------------|--------------------------------|----------------------------------------------|
| Pretrain    | VDISC (Draper), Big-Vul, SARD, CodeSearchNet | General vulnerability patterns + multi-language semantics |
| Fine-tune   | Devign, ReVeal, DiverseVul, Vul4J, IaC Security Dataset | Task-specific vulnerability classification   |
| Evaluate    | Devign test split, ReVeal test split, Big-Vul holdout, IaC test subset | Precision / Recall / F1, cross-project generalisation |

**Metrics:** Precision, Recall, F1-score on vulnerable vs non-vulnerable nodes. Additionally: hotspot detection accuracy, vulnerable data-flow path coverage, and forward/backward transfer across languages.

Most public vulnerability datasets (Devign, Big-Vul, VDISC, ReVeal) are C/C++ centric due to the historical focus on memory-safety vulnerabilities. For multi-language coverage, PRISM supplements these with CodeSearchNet (multi-language semantics) and a custom IaC security dataset (Terraform HCL, Kubernetes YAML).

---

## Benchmarked Platforms

| Platform | Primary Focus | Key Limitation vs PRISM |
|---|---|---|
| GitHub Advanced Security | GitHub-integrated DevSecOps | Code processed in GitHub infra; no zero-trust isolation |
| Snyk | Dependency + container scanning | Cloud-based; limited structural code reasoning |
| SonarQube | Code quality + SAST | Rule-based detection; no AI-driven behavioral analysis |
| Checkmarx | Enterprise SAST | Rule-based; no immutable audit trail |
| Veracode | Cloud SAST + DAST + SCA | Code uploaded to external platform; no confidentiality guarantees |
| Terraform Cloud | IaC lifecycle management | No source-code security analysis |
| Pulumi | IaC with general-purpose languages | No vulnerability detection; no tamper-proof audit |

**PRISM differentiators:** ephemeral sandbox execution (no persistent code storage), graph-based behavioral analysis via CPG, AI-assisted reasoning with GraphCodeBERT, immutable blockchain audit logging, and automated secure Terraform/Ansible generation from analysis results.

---

## IaC Generation

After security analysis and policy validation, the IaC Generation Agent produces Terraform and Ansible scripts based on detected application architecture and the `DeploymentContext` form (validated by Pydantic v2 before any infrastructure is provisioned).

The `DeploymentContext` collects: target resource group, Azure region, VNet/subnet names, container image URI, target environment (dev/staging/prod), monitoring and database requirements, and whether target infrastructure already exists. This last flag determines whether the generator produces `resource` blocks (new infra) or `data` source blocks (referencing existing infra).

Generated IaC is validated with Terraform static validation and policy checks before being presented for human review. PRISM does not auto-deploy.

---

## Advanced Features (Roadmap)

- **Cognitive Zero-Trust** — `ZeroTrustResponseValidator` on every MCP tool result (schema compliance, prompt injection check, rate limit enforcement); `CapabilityToken` per agent limiting exact tool IDs callable
- **SentinelAgent** — sidecar container observing agent external behaviour through LangGraph message state and MCP tool call log
- **RedTeamAgent** — runs every 6 hours generating adversarial IR samples based on MITRE ATT&CK patterns, measures detection rate continuously
- **Firecracker MicroVMs** — stronger isolation than Azure Container instances (future)
- **Continual Learning** — incremental model updates from newly discovered vulnerabilities without full retraining
- **Automatic vulnerability class discovery** — graph mining on CPGs to identify emerging patterns
- **Full DevSecOps integration** — CI/CD hooks, SBOM generation, dependency scanning, runtime policy enforcement

---

## Evaluation

| Dimension | Method |
|---|---|
| Vulnerability detection | Juliet Test Suite + Devign labeled datasets; Precision / Recall / F1 |
| IaC quality | Terraform static validation; least-privilege and secure config checks |
| System performance | Analysis latency, graph construction time, model inference time across repo sizes |
| Qualitative | Manual review of findings and generated IaC for actionability |

---

## Environment Variables

```env
# backend/.env
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password

ENABLE_JOERN=false           # true when Joern binary is available
JOERN_BIN=/opt/joern/joern-cli/joern
JOERN_HOME=$HOME/tools/joern/joern-cli
JOERN_TIMEOUT=300
JOERN_MAX_HEAP=4G

CODEQL_CLI_PATH=$HOME/tools/codeql-home/codeql/codeql
CODEQL_SEARCH_PATH=$HOME/tools/codeql-home/codeql-repo

VAULT_ADDR=http://127.0.0.1:8200
VAULT_ROLE_ID=<from vault setup script>
VAULT_SECRET_ID=<from vault setup script>

MAX_FILE_SIZE_MB=10
SANDBOX_TIMEOUT_SECONDS=120
WS_HEARTBEAT_INTERVAL=15
```

---

## Supported Languages

Python · Java · JavaScript · TypeScript (TSX) · Go · Rust · C · C++ · Terraform (HCL) · YAML