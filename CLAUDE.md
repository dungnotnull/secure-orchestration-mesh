---
project: secure-orchestration-mesh
tagline: Zero-Trust Security Protocol for AI Orchestrator ↔ Sub-Agent Communication
status: Phase 0 — Research & Environment Setup
---

# CLAUDE.md — secure-orchestration-mesh

## Core Problem
Modern multi-agent AI systems (one Orchestrator + many Worker Agents) have no standardized security protocol for inter-agent communication. Natural language commands between agents create attack surfaces for prompt injection, agent hijacking, and data exfiltration. This project builds an enterprise-grade, zero-trust communication layer that eliminates these attack vectors through cryptographic identity, structured message schemas, and ML-powered anomaly detection — targeting latency in the microsecond range even at millions of concurrent agent streams.

## Architecture Summary
- **Platform**: Python 3.11+ orchestrator daemon + lightweight agent SDK (Python/Rust bindings)
- **Transport**: gRPC over HTTP/2 (primary) + TLS-encrypted WebSocket (fallback)
- **Protocol**: Protobuf v3 strict message schemas — no natural language permitted at the protocol layer
- **Security**: Ephemeral key pairs (X25519 ECDH) + AES-256-GCM message encryption + HMAC-SHA256 integrity checks
- **Anomaly Detection**: Isolation Forest + LSTM Autoencoder running inline at coordination layer
- **Local SLM**: Phi-3-mini (via Ollama) used exclusively as human-intent → Protobuf translator; never touches raw protocol packets
- **Identity**: Short-lived JWT tokens (60s TTL) issued per agent per task, with scoped permission boundaries

## Key Technical Decisions
1. **gRPC + HTTP/2** chosen over REST/HTTP1.1 — native multiplexing supports millions of concurrent agent streams at sub-millisecond latency with binary framing
2. **Protobuf v3 schema compiled at build time** — free-text fields are architecturally impossible; prompt injection cannot enter the core protocol
3. **Ephemeral X25519 keys rotated per task session** — forward secrecy guaranteed; past session compromise cannot decrypt future traffic
4. **Deterministic Guardrail Layer (no LLM)** — validation logic is pure code (schema checks, hash verification, permission boundary assertions); cannot be manipulated by adversarial model outputs
5. **Isolation Forest** for anomaly detection at launch — unsupervised, requires zero labeled attack examples; LSTM Autoencoder added in Phase 2 for temporal pattern analysis
6. **Zero-Trust default posture** — every new sub-agent starts with null permissions; Orchestrator grants minimum-scoped permissions only for the specific task at hand
7. **Local SLM as thin translator only** — LLM layer is isolated from security-critical path; it produces a structured Protobuf payload that is then independently validated before execution

## External LLM API Integrations

| Provider | Purpose | Config Key |
|----------|---------|------------|
| Claude API (Anthropic) | Human-readable security incident report generation | `CLAUDE_API_KEY` |
| Local Ollama (Phi-3-mini) | Primary human intent → Protobuf schema translation | `OLLAMA_BASE_URL` |
| GPT-4o (OpenAI) | Fallback for incident report generation when Claude unavailable | `OPENAI_API_KEY` |

LLM provider chain controlled by: `LLM_PROVIDER=claude|gpt4o|ollama` (default: `ollama`)

## HuggingFace Models in Use

| Model ID | Purpose | HF Link |
|----------|---------|---------|
| `microsoft/phi-3-mini-4k-instruct` | Local SLM: parse human task descriptions → validated Protobuf payloads | [Link](https://huggingface.co/microsoft/phi-3-mini-4k-instruct) |
| `google-bert/bert-base-uncased` | Semantic baseline for protocol log anomaly scoring (fine-tuned on synthetic logs) | [Link](https://huggingface.co/google-bert/bert-base-uncased) |
| Custom scikit-learn Isolation Forest | Unsupervised behavioral anomaly detection on agent communication patterns | N/A (trained locally) |
| Custom LSTM Autoencoder (PyTorch) | Temporal sequence anomaly detection for time-series agent behavior | N/A (trained locally) |

## Current Active Development Tasks
- [ ] Define complete Protobuf v3 schema for all message types (TaskRequest, TaskResult, HeartBeat, ErrorReport, PermissionGrant)
- [ ] Implement X25519 ECDH ephemeral key exchange handshake module
- [ ] Build gRPC server (Orchestrator) and matching gRPC client stub (Agent SDK)
- [ ] Implement Guardrail Layer — deterministic schema validation + permission boundary checker
- [ ] Generate synthetic normal-behavior logs and train initial Isolation Forest model
- [ ] Integrate Phi-3-mini via Ollama as the human → Protobuf translation service
- [ ] Build anomaly alerting pipeline: detect → score → quarantine agent → notify Orchestrator
- [ ] Wire crawl4ai self-update pipeline to populate SECOND-KNOWLEDGE-BRAIN.md weekly

## Related Files
- `PROJECT-detail.md` — Full technical specification and data flow
- `PROJECT-DEVELOPMENT-PHASE-TRACKING.md` — Phase roadmap with milestones and success criteria
- `SECOND-KNOWLEDGE-BRAIN.md` — Research papers, SOTA models, and self-update knowledge base
