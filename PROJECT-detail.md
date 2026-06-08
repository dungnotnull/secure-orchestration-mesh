# PROJECT-detail.md — secure-orchestration-mesh

## Executive Summary
**secure-orchestration-mesh** is a production-grade, zero-trust security protocol and runtime layer for multi-agent AI systems. It provides cryptographically authenticated, end-to-end encrypted communication between a central Orchestrator and thousands of concurrent Worker Agents, enforces structured (non-natural-language) command schemas at the protocol boundary, and runs inline ML-powered anomaly detection to detect agent hijacking or prompt injection attacks in real time. The result is a hardened communication fabric that can be embedded into any multi-agent AI application — personal automation systems, enterprise agentic workflows, or large-scale AI pipelines.

---

## Problem Statement

### The Unsolved Inter-Agent Security Problem
The emergence of multi-agent AI architectures (AutoGPT, CrewAI, LangGraph, etc.) has exposed a fundamental security gap: **there is no standard, secure communication protocol for agent-to-agent messaging**. Current systems suffer from:

- **Prompt Injection at Scale**: Sub-agents processing external data (web pages, documents, emails) can embed adversarial instructions that get forwarded to the Orchestrator as legitimate output, hijacking the entire pipeline (OWASP LLM Top 10 #1, 2025).
- **No Cryptographic Identity**: Most frameworks pass agent outputs as plain strings with no authentication — a compromised sub-agent is indistinguishable from a legitimate one.
- **Natural Language Command Surface**: Agents commanding each other in plain English creates an enormous attack surface — any ambiguous phrasing can be exploited or misinterpreted.
- **No Behavioral Monitoring**: No existing open-source agent framework includes runtime anomaly detection to flag agents whose behavior diverges from their established baseline.

**Research context**: A 2024 study by Greshake et al. demonstrated that indirect prompt injection can compromise multi-agent pipelines with 100% success in unprotected systems. The 2025 NIST AI Risk Management Framework explicitly calls out agent-to-agent trust as an emerging AI system risk category.

### Scale of the Problem
- Enterprise agentic systems are projected to manage 10,000–1,000,000 concurrent sub-agents by 2027 (Gartner, 2025)
- A single compromised agent can exfiltrate data, escalate permissions, or corrupt the entire pipeline if no guardrail layer exists
- Microsecond latency requirements (real-time agent coordination) conflict with heavyweight cryptographic protocols — this project solves both simultaneously

---

## Target Users & Use Cases

| User Type | Use Case | Scale |
|-----------|---------|-------|
| AI Application Developers | Embed secure-orchestration-mesh as the transport layer in a CrewAI / LangGraph application | 10–100 agents |
| Enterprise AI Teams | Harden internal automation pipelines against insider-threat agent compromise | 100–10,000 agents |
| AI Safety Researchers | Study inter-agent trust boundaries and test attack/defense scenarios in a controlled environment | Any scale |
| Personal AI Power Users | Secure a personal "digital twin" system (e.g., linked with Folder 3 Omni-Brain + Folder 5 Soulmate) | 5–50 agents |
| Multi-Agent Platform Builders | Use the Orchestrator daemon as a foundation for a proprietary agent coordination service | 10,000+ agents |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        HUMAN / ADMIN INTERFACE                          │
│   (Natural Language Task Input → Local SLM Translator → Protobuf)       │
└────────────────────────────┬────────────────────────────────────────────┘
                             │ Structured Protobuf TaskRequest
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        ORCHESTRATOR DAEMON                               │
│  ┌───────────────┐  ┌──────────────────┐  ┌──────────────────────────┐ │
│  │ Identity &    │  │  Task Scheduler  │  │  Anomaly Detection Engine│ │
│  │ Token Issuer  │  │  & Load Balancer │  │  (Isolation Forest +     │ │
│  │ (JWT + X25519)│  │                  │  │   LSTM Autoencoder)      │ │
│  └───────┬───────┘  └────────┬─────────┘  └──────────────────────────┘ │
│          │                   │                          ▲               │
│          └──────────┬────────┘                          │               │
│                     │ gRPC/HTTP2 + AES-256-GCM          │               │
│                     ▼                                   │               │
│  ┌──────────────────────────────────────────────────────┤               │
│  │              GUARDRAIL LAYER (Deterministic)          │               │
│  │  Schema Validation → Permission Boundary Check →     │               │
│  │  Hash Integrity Verify → Behavioral Log → Pass/Reject│               │
│  └──────────────────────────────────────────────────────┘               │
│                     │ Validated packets only            │               │
└─────────────────────┼───────────────────────────────────────────────────┘
                      │ Encrypted gRPC streams (per-agent TLS session)
          ┌───────────┼─────────────────────────────────┐
          ▼           ▼                                 ▼
   ┌─────────────┐ ┌─────────────┐             ┌─────────────┐
   │  Worker     │ │  Worker     │    . . .    │  Worker     │
   │  Agent #1   │ │  Agent #2   │             │  Agent #N   │
   │  (SDK)      │ │  (SDK)      │             │  (SDK)      │
   │ ephemeral   │ │ ephemeral   │             │ ephemeral   │
   │ key pair    │ │ key pair    │             │ key pair    │
   └─────────────┘ └─────────────┘             └─────────────┘
```

---

## Tech Stack

| Component | Technology | Source |
|-----------|-----------|--------|
| Transport Protocol | gRPC over HTTP/2 | [grpc.io](https://grpc.io) |
| Fallback Transport | WebSocket (TLS 1.3) | websockets library |
| Message Schema | Protobuf v3 | [protobuf.dev](https://protobuf.dev) |
| Key Exchange | X25519 ECDH (Diffie-Hellman) | `cryptography` Python lib |
| Message Encryption | AES-256-GCM (AEAD) | `cryptography` Python lib |
| Integrity Verification | HMAC-SHA256 | `cryptography` Python lib |
| Agent Identity | JWT (RS256, 60s TTL) | `python-jose` |
| Anomaly Detection | Isolation Forest | scikit-learn |
| Temporal Anomaly | LSTM Autoencoder | PyTorch |
| Semantic Analysis | BERT-base (fine-tuned) | HuggingFace Transformers |
| Local SLM Translator | Phi-3-mini via Ollama | Ollama + HuggingFace |
| Report Generation LLM | Claude API / GPT-4o | Anthropic / OpenAI SDK |
| Logging & Telemetry | OpenTelemetry + Jaeger | opentelemetry-python |
| Service Config | Pydantic v2 + YAML | pydantic.dev |
| Testing | pytest + pytest-asyncio | PyPI |
| Containerization | Docker + Docker Compose | Docker |

---

## ML/DL Models Section

### Anomaly Detection — Isolation Forest
- **Library**: scikit-learn `IsolationForest`
- **Input features**: message frequency, payload size distribution, permission request patterns, inter-message timing, error rate per agent
- **Training data**: synthetic normal-behavior logs generated by running benign agent workloads (auto-generated via simulation script)
- **Output**: anomaly score per agent per time window; threshold triggers quarantine action
- **Contamination parameter**: starts at 0.01 (1% expected anomalies), tunable via config

### Temporal Anomaly — LSTM Autoencoder
- **Library**: PyTorch
- **Architecture**: 2-layer LSTM encoder (hidden=128) → bottleneck (32) → 2-layer LSTM decoder
- **Input**: time-series sequences of agent communication events (sequence length = 50 events)
- **Training**: self-supervised reconstruction loss on normal-behavior sequences
- **Output**: reconstruction error — high error → behavioral deviation → alert
- **When added**: Phase 2 (requires sufficient real log data from Phase 1 production)

### Semantic Protocol Log Analyzer — BERT (fine-tuned)
- **Model ID**: `google-bert/bert-base-uncased`
- **Fine-tuning task**: classify agent log entries as NORMAL / SUSPICIOUS / CRITICAL
- **Training data**: synthetic labeled logs + augmentation via GPT-4o (Phase 2)
- **HF link**: https://huggingface.co/google-bert/bert-base-uncased

### Local SLM Translator — Phi-3-mini
- **Model ID**: `microsoft/phi-3-mini-4k-instruct` (served via Ollama)
- **Task**: parse free-text human task descriptions → validated Protobuf `TaskRequest` JSON payload
- **Prompt engineering**: strict system prompt constrains output to JSON-only, schema-referenced format
- **HF link**: https://huggingface.co/microsoft/phi-3-mini-4k-instruct
- **Note**: this model NEVER receives raw agent protocol packets — it operates only on human-provided input

---

## External LLM API Integration

### Pluggable LLM Backend Design
All LLM-dependent features use an abstract `LLMBackend` interface with three concrete implementations:

```python
class LLMBackend(Protocol):
    async def generate(self, prompt: str, schema: dict | None) -> str: ...

class ClaudeBackend(LLMBackend):    # Anthropic SDK
class GPT4oBackend(LLMBackend):     # OpenAI SDK
class OllamaBackend(LLMBackend):    # Local, no API cost
```

**Fallback chain**: Claude → GPT-4o → Ollama (configurable via `LLM_PROVIDER`)

### LLM Use Cases (LLM is NOT on the security-critical path)
| Use Case | Why LLM | LLM Provider |
|---------|---------|-------------|
| Incident report generation | Summarize anomaly logs in human-readable format | Claude API (preferred) |
| Human task → Protobuf | Parse free-text task descriptions | Ollama Phi-3-mini (local) |
| Threat intelligence summaries | Summarize crawled security papers | Claude API |
| Agent onboarding assistant | Help developers configure new agent types | Ollama (local) |

---

## Feature Specification

### MVP Features (Phase 0–2)
- [x] Protobuf v3 schema definitions for all core message types
- [ ] X25519 ECDH ephemeral key exchange on agent initialization
- [ ] AES-256-GCM end-to-end encryption on all Orchestrator ↔ Agent messages
- [ ] JWT-based dynamic token issuance with 60s TTL and permission scope
- [ ] gRPC server (Orchestrator) + gRPC client SDK (Agent)
- [ ] Deterministic Guardrail Layer (schema validation + permission boundary check)
- [ ] Isolation Forest anomaly detector trained on synthetic logs
- [ ] Agent quarantine action: revoke token + terminate gRPC stream
- [ ] Basic admin dashboard (CLI) for monitoring agent states

### Advanced Features (Phase 3–5)
- [ ] LSTM Autoencoder temporal anomaly detection
- [ ] BERT-based semantic log classification
- [ ] Automatic threat escalation ladder (flag → isolate → terminate → alert admin)
- [ ] WebSocket fallback transport with identical security guarantees
- [ ] Multi-Orchestrator federation (for Cluster A integration with Folder 1 P2P mesh)
- [ ] Plugin API: embed secure-orchestration-mesh into any existing agent framework (CrewAI adapter, LangGraph adapter)
- [ ] Cryptographic audit trail (tamper-evident append-only log of all agent actions)
- [ ] crawl4ai self-update pipeline for SECOND-KNOWLEDGE-BRAIN.md
- [ ] Claude API-powered automated security incident reports

---

## Full E2E Data Flow

1. **Human inputs task** in natural language via CLI or API
2. **Local SLM Translator** (Phi-3-mini/Ollama) parses intent → outputs strictly validated Protobuf `TaskRequest` JSON
3. **Orchestrator** receives `TaskRequest`, validates against JSON-schema, rejects on any schema violation
4. **Orchestrator selects Worker Agent(s)** based on task type and current agent availability
5. **Ephemeral key exchange**: Orchestrator performs X25519 ECDH handshake with target Agent(s); shared session key derived
6. **Orchestrator issues short-lived JWT token** to Agent(s) encoding: `agent_id`, `task_id`, `permissions_boundary`, `expiry=now+60s`
7. **Orchestrator encrypts** `TaskPacket` with AES-256-GCM using shared session key, signs with HMAC-SHA256
8. **Encrypted packet sent** over gRPC stream to Worker Agent
9. **Worker Agent decrypts** packet, verifies HMAC integrity, validates JWT token (rejects if expired or permission scope exceeded)
10. **Worker Agent executes task** within its permission boundary
11. **Worker Agent encrypts** `ResultPacket` with same session key, signs with HMAC
12. **ResultPacket transmitted** back to Orchestrator over gRPC stream
13. **Guardrail Layer intercepts** ResultPacket:
    - Decrypts and verifies HMAC
    - Validates Protobuf schema (any extra fields → reject)
    - Checks permission boundary consistency
    - Logs behavioral metrics (payload size, latency, error codes)
14. **Anomaly Detection Engine** scores the agent's behavior for this task session:
    - Isolation Forest checks current metrics against trained baseline
    - Score above threshold → SUSPICIOUS flag logged
    - Two consecutive SUSPICIOUS flags → AUTO-QUARANTINE triggered
15. **Auto-Quarantine**: Orchestrator revokes agent JWT, closes gRPC stream, logs incident
16. **Clean result** forwarded to human interface or calling application
17. **Periodic self-update**: crawl4ai pipeline fetches new security research → updates SECOND-KNOWLEDGE-BRAIN.md → Orchestrator reload policy

---

## Privacy & Security

| Concern | Solution |
|---------|---------|
| Data in transit | AES-256-GCM encryption + TLS 1.3 transport layer (double-encrypted) |
| Agent identity spoofing | Ephemeral X25519 key pairs + short-lived JWT; no long-lived shared secrets |
| Prompt injection via sub-agent results | Guardrail Layer enforces strict Protobuf schema; free-text fields are structurally impossible in result packets |
| Compromised agent persistence | 60s JWT TTL means a compromised token expires quickly; quarantine auto-revokes immediately |
| Audit trail integrity | Append-only cryptographic log (hash chaining) — tampering with any log entry invalidates all subsequent entries |
| Config secrets | All API keys loaded from environment variables; never written to disk in plaintext |
| Local-first | No agent behavioral data sent to external services; anomaly models run fully locally |

---

## Key Python Dependencies

```
grpcio>=1.64.0
grpcio-tools>=1.64.0
protobuf>=4.25.0
cryptography>=42.0.0
python-jose[cryptography]>=3.3.0
scikit-learn>=1.5.0
torch>=2.3.0
transformers>=4.41.0
httpx>=0.27.0
anthropic>=0.28.0
openai>=1.30.0
ollama>=0.2.0
crawl4ai>=0.3.0
pydantic>=2.7.0
opentelemetry-sdk>=1.24.0
pytest>=8.2.0
pytest-asyncio>=0.23.0
```

---

## Improvement Suggestions (Beyond Original Idea)

1. **Federated Orchestrators**: Extend the protocol to support multiple Orchestrators forming a consensus cluster — necessary for high-availability enterprise deployments and for integration with Folder 1's P2P mesh
2. **Hardware Security Module (HSM) integration**: Optionally store master keys in TPM/HSM chips for zero-software-exfiltration key protection
3. **Differential Privacy on behavioral logs**: Add noise to aggregated agent metrics before training anomaly models — prevents reconstructing individual agent task content from behavioral patterns
4. **Capability Negotiation Protocol**: Before each task, Orchestrator and Agent negotiate a minimum capability set — prevents capability creep attacks
5. **Cryptographic audit trail with Merkle tree**: Replace linear hash chain with Merkle tree for O(log n) tamper proof verification — necessary at 1M+ agent event scale
6. **WASM agent sandbox**: Compile Worker Agent SDK to WebAssembly for OS-level isolation in addition to protocol-level zero-trust
7. **Adaptive anomaly thresholds**: Use online learning (Hoeffding Trees) to update Isolation Forest boundaries without full retraining as agent workloads evolve
8. **Side-channel attack resistance**: Pad all Protobuf messages to fixed-length blocks to prevent traffic analysis from revealing task types via packet size patterns
