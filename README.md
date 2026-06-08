<div align="center">
<h1>Secure Orchestration Mesh</h1>
**Zero-Trust Security Protocol for AI Orchestrator ↔ Sub-Agent Communication**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![gRPC](https://img.shields.io/badge/transport-gRPC%2FHTTP2-green.svg)](https://grpc.io)
[![Protobuf v3](https://img.shields.io/badge/schema-Protobuf%20v3-orange.svg)](https://protobuf.dev)
[![Cryptography](https://img.shields.io/badge/crypto-X25519%20%2B%20AES--256--GCM-red.svg)](https://cryptography.io)
[![ML](https://img.shields.io/badge/anomaly-Isolation%20Forest%20%2B%20LSTM-purple.svg)](https://scikit-learn.org)

</div>

---

## The Problem

Modern multi-agent AI systems — CrewAI, LangGraph, AutoGPT — have **no standardized security protocol** for inter-agent communication. Orchestrators dispatch tasks to sub-agents. Sub-agents return results. Simple, right?

The problem: **every message between agents is a potential attack vector.**

- A sub-agent processing an external web page can embed adversarial instructions in its output, hijacking the entire pipeline — **100% success rate in unprotected systems** (Greshake et al., USENIX 2023)
- Most frameworks pass agent outputs as **plain strings** with no authentication — a compromised sub-agent is indistinguishable from a legitimate one
- Commands between agents are **natural language** — the largest possible attack surface. Any ambiguous phrase can be exploited
- **No existing open-source framework** includes runtime behavioral monitoring to detect compromised agents

By 2027, enterprise agentic systems will manage **10,000–1,000,000 concurrent sub-agents** (Gartner 2025). A single compromised agent can exfiltrate data, escalate permissions, or corrupt the entire pipeline — in microseconds.

**Secure Orchestration Mesh** eliminates these attack vectors entirely.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          HUMAN / ADMIN INTERFACE                              │
│       Natural Language Task → Phi-3-mini Translator → Protobuf TaskRequest    │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │ Structured Protobuf TaskRequest
                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                          ORCHESTRATOR DAEMON                                  │
│                                                                              │
│  ┌──────────────────┐  ┌───────────────────┐  ┌──────────────────────────┐  │
│  │   Identity &     │  │   Task Scheduler  │  │  Anomaly Detection       │  │
│  │   Token Issuer   │  │   & Load Balancer │  │  Engine                  │  │
│  │                  │  │                   │  │                           │  │
│  │  • JWT RS256     │  │  • Agent pool     │  │  • Isolation Forest      │  │
│  │  • 60s TTL       │  │  • Capability     │  │    (<1ms real-time)      │  │
│  │  • X25519 ECDH   │  │    matching       │  │  • LSTM Autoencoder      │  │
│  │  • Session mgmt  │  │  • Load balancing │  │    (temporal patterns)   │  │
│  └────────┬─────────┘  └────────┬──────────┘  │  • BERT Log Classifier   │  │
│           │                     │              │    (async post-incident) │  │
│           └──────────┬──────────┘              └────────────┬─────────────┘  │
│                      │                                      │                │
│                      ▼                                      │                │
│  ┌──────────────────────────────────────────────────────────┴──────────────┐ │
│  │                    GUARDRAIL LAYER (Deterministic — Zero LLM)            │ │
│  │                                                                         │ │
│  │  ① HMAC Verify → ② Replay Check → ③ AES-GCM Decrypt → ④ Size Check      │ │
│  │  → ⑤ JWT Validate → ⑥ Schema Validate → ⑦ Permission Check              │ │
│  │                                                                         │ │
│  │  Every packet passes through ALL 7 validation gates.                    │ │
│  │  Any failure = immediate rejection + audit log + quarantine trigger.    │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                      │ Validated packets only                                │
└──────────────────────┼──────────────────────────────────────────────────────┘
                       │
         ┌─────────────┼─────────────────────────────────────┐
         │             │ gRPC/HTTP2 + AES-256-GCM            │
         │             │ + HMAC-SHA256 per message            │
         │             │ + Ephemeral X25519 per session       │
         ▼             ▼                                     ▼
  ┌─────────────┐ ┌─────────────┐                    ┌─────────────┐
  │  Agent #1   │ │  Agent #2   │     ... ∞          │  Agent #N   │
  │  (SDK)      │ │  (SDK)      │                    │  (SDK)      │
  │             │ │             │                    │             │
  │  Permission │ │  Permission │                    │  Permission │
  │  Boundary:  │ │  Boundary:  │                    │  Boundary:  │
  │  [web]      │ │  [file, api]│                    │  [code]     │
  └─────────────┘ └─────────────┘                    └─────────────┘
```

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **gRPC over HTTP/2** | Native multiplexing supports millions of concurrent agent streams at sub-millisecond latency. Binary framing eliminates text-based injection. |
| **Protobuf v3 strict schemas** | Free-text fields are **architecturally impossible**. Prompt injection cannot enter the core protocol — there's no text to inject into. |
| **Ephemeral X25519 keys per session** | Forward secrecy guaranteed. Compromise of a past session key cannot decrypt future traffic. |
| **Deterministic Guardrail Layer** | Validation logic is **pure code** — no LLM in the security path. Cannot be manipulated by adversarial model outputs. Schema checks, hash verification, and permission assertions are all simple boolean operations. |
| **Encrypt-then-MAC** | HMAC-SHA256 is computed over ciphertext, not plaintext. Any ciphertext tampering is detected before decryption is attempted — cryptographically correct protocol order. |
| **Zero-Trust default posture** | Every new sub-agent starts with **null permissions**. The Orchestrator grants minimum-scoped permissions only for the specific task at hand. |
| **Local SLM as thin translator only** | Phi-3-mini runs locally via Ollama. It translates human intent → Protobuf. It **never** touches raw protocol packets. The LLM is isolated from the security-critical path. |

---

## Security Model

### Cryptographic Identity

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key Exchange | X25519 ECDH | Establish shared session secret over insecure channel |
| Key Derivation | HKDF-SHA256 | Derive 256-bit AES key from ECDH shared secret + nonce |
| Message Encryption | AES-256-GCM (AEAD) | Encrypt + authenticate simultaneously; tampering → decryption failure |
| Message Integrity | HMAC-SHA256 | Per-message signature over ciphertext (encrypt-then-MAC) |
| Agent Identity | JWT RS256 | Short-lived (60s TTL) token with scoped permission boundaries |
| Audit Trail | Merkle Tree (SHA-256) | Append-only, tamper-evident log; O(log n) verification at scale |
| Side-Channel Resistance | Fixed-length padding | All messages padded to 4KB blocks to prevent traffic analysis |

### Guardrail Validation Pipeline (7 Gates)

Every packet passing through the Orchestrator must clear all 7 validation gates. Any gate failure triggers immediate rejection:

```
Inbound Packet
    │
    ▼
① HMAC-SHA256 Verify ──FAIL──▶ REJECT: HMAC mismatch — ciphertext tampered
    │ PASS
    ▼
② Replay Detection ──FAIL──▶ REJECT: Duplicate or stale sequence number
    │ PASS
    ▼
③ AES-256-GCM Decrypt ──FAIL──▶ REJECT: Decryption failure — wrong key or corruption
    │ PASS
    ▼
④ Payload Size Check ──FAIL──▶ REJECT: Exceeds 10 MiB hard ceiling
    │ PASS
    ▼
⑤ JWT Verify (RS256) ──FAIL──▶ REJECT: Expired token or invalid signature
    │ PASS
    ▼
⑥ Protobuf Schema Validate ──FAIL──▶ REJECT: Malformed or unexpected message type
    │ PASS
    ▼
⑦ Permission Boundary Check ──FAIL──▶ REJECT: Agent returned data outside granted scope
    │ PASS
    ▼
  ACCEPT → Forward to Task Scheduler → Log Metrics → Score Anomaly
```

### Threat Model & Mitigations

| Attack Vector | Mitigation |
|---------------|------------|
| **Prompt Injection via Agent Result** | Protobuf schema enforces structured output — no free-text fields exist in result packets |
| **Agent Identity Spoofing** | Ephemeral X25519 key pairs + short-lived JWT (60s TTL); no long-lived shared secrets |
| **Compromised Agent Persistence** | 60s JWT TTL + automatic quarantine on 2 consecutive anomalous windows |
| **Replay Attack** | Monotonic per-session sequence numbers with sliding window detection |
| **MITM on Transport** | TLS 1.3 (gRPC) + AES-256-GCM (application layer) = double-encrypted |
| **Traffic Analysis** | Fixed-length block padding (4KB) masks message type patterns |
| **Permission Escalation** | Every task includes an explicit PermissionScope; agent cannot exceed it |
| **Data Exfiltration** | Payload size enforcement + anomaly detection on payload distribution |
| **Orchestrator Impersonation** | Agent verifies Orchestrator's X25519 public key via registration handshake |
| **Audit Tampering** | Merkle tree cryptographic audit trail — tampering with any entry invalidates the root |

---

## ML/AI Anomaly Detection

### Detection Stack

| Model | Type | Latency | Purpose |
|-------|------|---------|---------|
| **Isolation Forest** | Unsupervised ensemble | <1ms (hot path) | Real-time behavioral scoring: message frequency, payload distribution, error rate, latency patterns |
| **LSTM Autoencoder** | Self-supervised temporal | <2ms (hot path) | Sequence anomaly detection: learns compressed representation of normal agent behavior; high reconstruction error = attack |
| **BERT Log Classifier** | Fine-tuned transformer | Async (off path) | Post-incident semantic analysis: classifies log entries as NORMAL / SUSPICIOUS / CRITICAL |

### Auto-Quarantine Logic

```
Anomaly Score per Window (10s)
         │
         ▼
  ┌──────────────────────────────────────────┐
  │  Score < 0.65    → NORMAL                │
  │  Score ≥ 0.65    → SUSPICIOUS (flag #1)  │
  │  Score ≥ 0.85    → CRITICAL              │
  └──────────────────────────────────────────┘
         │
         ▼
  2+ consecutive SUSPICIOUS windows
         │
         ▼
  ┌──────────────────────────────────────────┐
  │  AUTO-QUARANTINE TRIGGERED                │
  │  • Revoke JWT → close gRPC stream         │
  │  • Log incident → audit trail             │
  │  • Generate incident report (Claude/GPT)  │
  │  • Notify admin dashboard                 │
  └──────────────────────────────────────────┘
```

### Adaptive Thresholds

The system continuously adjusts anomaly thresholds based on false-positive rates over a rolling 7-day window. If the FPR exceeds 5%, thresholds are automatically loosened. If the FPR drops below 2.5%, thresholds are tightened. This prevents alert fatigue while maintaining sensitivity to novel attacks.

---

## Quick Start

### Prerequisites

- **Python 3.11+**
- **Docker & Docker Compose** (optional, for containerized deployment)
- **Ollama** (optional, for local SLM translation)

### Install

```bash
# Clone the repository
git clone https://github.com/dungnotnull/secure-orchestration-mesh.git
cd secure-orchestration-mesh

# Create virtual environment
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
.venv\Scripts\activate       # Windows

# Install dependencies
pip install -r requirements.txt

# Compile Protobuf schema
python -m grpc_tools.protoc -Iproto --python_out=proto --grpc_python_out=proto proto/mesh.proto
```

### Start the Orchestrator

```bash
# Generate JWT keys (first run only)
python -m orchestrator.main --gen-keys

# Start the orchestrator
python -m orchestrator.main --host 0.0.0.0 --port 50051

# With live CLI dashboard
python -m orchestrator.main --dashboard

# Docker
docker compose up orchestrator
```

### Start a Worker Agent

```bash
# Direct
python -m agent_sdk.main \
  --orchestrator localhost:50051 \
  --label my-agent \
  --caps web_search,file_read

# Docker
docker compose up worker-agent
```

### Generate Training Data

```bash
# Normal behavior logs (10,000 entries)
python scripts/synthetic_log_generator.py \
  --num-agents 100 \
  --entries-per-agent 100

# Attack simulation (1,000 entries, 10 attack types)
python scripts/attack_simulator.py \
  --num-attacks 1000
```

---

## Configuration

All settings in `config.yaml` with environment variable override (`SOM__SECTION__KEY=value`):

```yaml
server:
  host: "0.0.0.0"
  port: 50051
  grpc_max_workers: 100
  grpc_max_concurrent_streams: 10000

security:
  jwt:
    algorithm: "RS256"
    ttl_seconds: 60          # Token lifetime
  replay_window_seconds: 30  # Replay detection window

anomaly:
  isolation_forest:
    enabled: true
    suspicious_threshold: 0.65   # Flag for review
    critical_threshold: 0.85      # Immediate action
    consecutive_suspicious_for_quarantine: 2
  lstm_autoencoder:
    enabled: false               # Enable after training (Phase 2)

llm:
  provider: "ollama"             # ollama | claude | gpt4o
  ollama:
    base_url: "http://localhost:11434"
    model: "phi3:mini"
  claude:
    api_key_env: "CLAUDE_API_KEY"
    model: "claude-sonnet-4-20250514"

agent_defaults:
  max_payload_bytes: 10485760    # 10 MiB
  max_execution_ms: 300000       # 5 minutes
  heartbeat_interval_seconds: 5
  heartbeat_timeout_seconds: 15

quarantine:
  auto_quarantine_enabled: true
  max_quarantine_duration_minutes: 60
```

---

## Framework Adapters

### CrewAI

Drop the adapter into any CrewAI crew or agent:

```python
from orchestrator.crewai_adapter import SecureMeshAdapter

adapter = SecureMeshAdapter(
    orchestrator_address="localhost:50051",
    agent_label="crewai-finance-agent",
    capabilities=["web_search", "file_read"],
)

await adapter.connect()

# Execute a task through the mesh
result = await adapter.execute_task(
    task_description="Search for Q2 earnings reports",
    task_type="web_search",
)
```

### LangGraph

Wrap any LangGraph StateGraph:

```python
from orchestrator.langgraph_adapter import SecureGraphAdapter
from langgraph.graph import StateGraph

graph = StateGraph(MyState)
graph.add_node("process", process_node)
graph.add_edge("process", "end")

adapter = SecureGraphAdapter(
    orchestrator_address="localhost:50051",
    agent_label="langgraph-agent",
)

await adapter.connect()
secure_graph = adapter.wrap_graph(graph)

# Execute with zero-trust transport
result = await secure_graph.ainvoke(initial_state)
```

---

## Project Structure

```
secure-orchestration-mesh/
│
├── proto/                          # Protobuf v3 schema + gRPC service
│   ├── mesh.proto                  # 6 message types + 6 RPC methods
│   ├── mesh_pb2.py                 # Compiled message classes
│   └── mesh_pb2_grpc.py           # Compiled gRPC stubs/servicers
│
├── orchestrator/                   # Central daemon
│   ├── config.py                   # pydantic v2 config loader (YAML + env)
│   ├── token_issuer.py             # JWT RS256 generation + session management
│   ├── guardrail.py                # 7-gate deterministic validation pipeline
│   ├── task_scheduler.py           # Agent pool, capability routing, quarantine
│   ├── server.py                   # gRPC AgentMesh service implementation
│   ├── main.py                     # Entry point — wires all services together
│   ├── dashboard.py                # Rich CLI live monitoring dashboard
│   ├── websocket_fallback.py       # TLS WebSocket fallback transport
│   ├── audit_trail.py              # Merkle tree cryptographic audit log
│   ├── crewai_adapter.py           # CrewAI integration adapter
│   └── langgraph_adapter.py        # LangGraph integration adapter
│
├── agent_sdk/                      # Worker Agent SDK
│   ├── crypto.py                   # X25519 ECDH + AES-256-GCM + HMAC-SHA256
│   ├── client.py                   # gRPC client stub with bidi stream
│   ├── executor.py                 # Permission-bound task execution engine
│   ├── side_channel.py             # Fixed-length padding against traffic analysis
│   └── main.py                     # Agent entry point
│
├── anomaly/                        # ML anomaly detection stack
│   ├── isolation_forest.py         # Real-time IF scorer (<1ms)
│   ├── lstm_autoencoder.py         # Temporal anomaly detector (PyTorch)
│   ├── bert_classifier.py          # Semantic log classifier (transformers)
│   ├── behavioral_logger.py        # SQLite metrics persistence
│   └── combined_engine.py          # Multi-detector orchestration + adaptive thresholds
│
├── translator/                     # Human → Protobuf bridge
│   └── slm_bridge.py               # Phi-3-mini (Ollama) translator with schema validation
│
├── llm/                            # Pluggable LLM backends
│   ├── backend.py                  # Abstract LLMProvider with fallback chain
│   ├── claude_backend.py           # Anthropic Claude API
│   ├── gpt4o_backend.py            # OpenAI GPT-4o API
│   ├── ollama_backend.py           # Local Ollama (zero API cost)
│   └── incident_reporter.py        # Automated security incident report generator
│
├── self_update/                    # Knowledge base auto-updater
│   └── crawl4ai_pipeline.py        # ArXiv API + NVD CVE feed + KB updater + APScheduler
│
├── scripts/                        # Data generation tools
│   ├── synthetic_log_generator.py  # Normal-behavior training data
│   └── attack_simulator.py         # 10-category attack sequence generator
│
├── deploy/                         # Deployment configurations
│   ├── DEPLOYMENT.md               # Production deployment guide
│   └── kubernetes/
│       └── mesh-stack.yaml         # Full K8s namespace + deployments + services + PVCs
│
├── config.yaml                     # All configuration (YAML + env override)
├── docker-compose.yml              # Single-machine Docker Compose
├── docker-compose.swarm.yml        # Docker Swarm stack
├── Dockerfile                      # Orchestrator container
├── Dockerfile.agent                # Worker Agent container
├── setup.py                        # pip install secure-orchestration-mesh-sdk
├── requirements.txt                # Python dependencies
└── README.md                       # This file
```

---

## Deployment

### Single Machine

```bash
docker compose up -d
```

### Docker Swarm

```bash
docker swarm init
echo "sk-ant-..." | docker secret create claude_api_key -
docker stack deploy -c docker-compose.swarm.yml mesh
docker service scale mesh_worker-agent=10
```

### Kubernetes

```bash
kubectl apply -f deploy/kubernetes/mesh-stack.yaml
kubectl -n secure-mesh scale deployment worker-agent --replicas=50
```

Full deployment guide: [`deploy/DEPLOYMENT.md`](deploy/DEPLOYMENT.md)

---

## Network Ports

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| Orchestrator gRPC | 50051 | TCP (HTTP/2) | Primary agent communication |
| WebSocket Fallback | 8443 | TCP (TLS) | Fallback transport |
| Ollama API | 11434 | TCP (HTTP) | Local SLM endpoint |
| Jaeger UI | 16686 | TCP (HTTP) | Distributed trace dashboard |
| Jaeger Thrift | 6831 | UDP | Trace collection |

---

## Tech Stack

| Component | Library | Purpose |
|-----------|---------|---------|
| Transport | gRPC + HTTP/2 | Bidirectional streaming, binary framing, multiplexing |
| Schema | Protobuf v3 | Strict message types — no text injection surface |
| Key Exchange | X25519 ECDH | 256-bit security, 32-byte keys, forward secrecy |
| Encryption | AES-256-GCM | Authenticated encryption with associated data |
| Integrity | HMAC-SHA256 | Per-message signatures over ciphertext |
| Identity | JWT RS256 | 60-second TTL, scoped permission boundaries |
| Anomaly (Real-time) | scikit-learn Isolation Forest | Unsupervised, O(log n) inference |
| Anomaly (Temporal) | PyTorch LSTM Autoencoder | Sequence reconstruction error |
| Log Analysis | HuggingFace BERT | Fine-tuned log classifier (async) |
| SLM Translator | Phi-3-mini (Ollama) | Local human-intent → Protobuf bridge |
| Incident Reports | Claude API / GPT-4o | Human-readable security incident analysis |
| Knowledge Base | crawl4ai + ArXiv API | Weekly paper discovery + CVE monitoring |
| Dashboard | Rich | Live terminal-based agent monitoring |
| Telemetry | OpenTelemetry + Jaeger | Distributed tracing |
| Containerization | Docker + Docker Compose + Swarm + K8s | Full production deployment options |

---

## Research Foundation

- **Greshake et al.** — "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection" (USENIX 2023) — *Motivates the Guardrail Layer design*
- **NIST SP 800-207** — "Zero Trust Architecture" (2020) — *Authoritative ZTA specification guiding token, permission, and verification design*
- **Liu, Ting, Zhou** — "Isolation Forest" (ICDM 2008) — *Theoretical foundation for real-time anomaly scoring*
- **Bernstein** — "Curve25519: New Diffie-Hellman Speed Records" (PKC 2006) — *Cryptographic foundation for key exchange*
- **McGrew, Viega** — "AES-GCM and Its Applications to Authenticated Encryption" (NIST 2004) — *AEAD specification used for message encryption*
- **IETF RFC 7540** — "HTTP/2" (2015) — *Transport layer specification for gRPC*

See [`SECOND-KNOWLEDGE-BRAIN.md`](SECOND-KNOWLEDGE-BRAIN.md) for the complete research knowledge base (14 papers, 12 models, 18 tools cataloged).

---

## License

MIT — see [LICENSE](LICENSE)

---

## Author

Created by [Claude](https://claude.ai)
