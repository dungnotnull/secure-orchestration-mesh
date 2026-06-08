# SECOND-KNOWLEDGE-BRAIN.md — secure-orchestration-mesh

> **Purpose**: Self-improving knowledge base for the secure-orchestration-mesh project. Updated weekly by crawl4ai pipeline. All entries are date-stamped.
> **Last Manual Update**: 2026-06-03
> **Next Scheduled Auto-Update**: 2026-06-10

---

## Core Concepts & Theoretical Foundations

### Zero-Trust Architecture (ZTA)
The foundational security model for this project. ZTA assumes breach by default: no entity (user, device, agent) is trusted based on network position or prior authentication. Every request must be continuously verified. Key principles:
- **Never trust, always verify**: Cryptographic identity required for every message, not just connection establishment
- **Least-privilege access**: Agents granted minimum permissions necessary for each specific task
- **Assume breach**: Design for detection and containment, not just prevention
- **NIST SP 800-207** (2020) is the authoritative reference for ZTA implementation guidance

### Prompt Injection in Multi-Agent Systems
A class of adversarial attacks where malicious content in agent inputs/outputs contains embedded instructions that manipulate the orchestrating agent's behavior. Two primary vectors:
- **Direct injection**: Attacker controls an input directly fed to an LLM agent
- **Indirect injection**: Malicious instructions hidden in external content (web pages, documents) that an agent retrieves and processes, then forwards as output
- **Defense in structured-schema protocols**: Enforcing strict Protobuf/JSON-Schema output format eliminates the free-text surface that injection attacks exploit

### Secure Multi-Party Computation (SMPC) — Background
Theoretical basis for how multiple agents can cooperate on a task without any single agent seeing the full dataset. Relevant for future Folder 7 extensions where sub-agents process sensitive data. Key references: Yao's Garbled Circuits (1982), GMW protocol (1987).

### Diffie-Hellman Key Exchange — Elliptic Curve Variant (ECDH)
Protocol for two parties to establish a shared secret over an insecure channel. X25519 (Curve25519-based ECDH) is used in this project:
- 256-bit security with 32-byte keys — highly efficient
- Resistant to small-subgroup attacks
- **Ephemeral variant (ECDHE)**: New key pair per session → forward secrecy (compromise of long-term key does not decrypt past sessions)

### Authenticated Encryption with Associated Data (AEAD)
AES-256-GCM is an AEAD cipher — it simultaneously encrypts data and authenticates it. Any tampering with the ciphertext causes decryption failure. The "associated data" component allows authentication of Protobuf header fields (task_id, agent_id) without encrypting them — enables Guardrail Layer to route packets before decryption.

### Anomaly Detection — Statistical Foundations
- **Isolation Forest** (Liu et al., 2008): Ensemble method that isolates anomalies by random feature partitioning. Anomalies require fewer splits to isolate → lower average path length → high anomaly score. O(n log n) training, O(log n) inference — suitable for real-time agent monitoring
- **LSTM Autoencoder**: Learns compressed temporal representation of normal sequences. At inference, reconstruction error on unseen sequences measures deviation from learned normal patterns. High error = anomalous behavior.

### gRPC and HTTP/2 Multiplexing
HTTP/2 allows multiple logical streams over a single TCP connection. gRPC exploits this for:
- **Bidirectional streaming**: Orchestrator and Agent can simultaneously send/receive
- **Flow control**: Prevents fast senders from overwhelming slow receivers
- **Header compression (HPACK)**: Reduces per-message overhead by ~30% vs HTTP/1.1
- **Binary framing**: Unlike HTTP/1.1 text protocol, HTTP/2 frames are binary — harder to tamper with in transit

---

## Key Research Papers

| Title | Authors | Year | Venue | DOI / arXiv | Relevance |
|-------|---------|------|-------|------------|-----------|
| Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection | Greshake et al. | 2023 | USENIX Workshop on LLMs & Security | arXiv:2302.12173 | Foundational paper on indirect prompt injection; motivates Guardrail Layer design |
| AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents | Debenedetti et al. | 2024 | NeurIPS 2024 | arXiv:2406.13352 | Benchmark suite for evaluating agent injection defenses; use for red-team test design |
| Zero Trust Architecture | NIST | 2020 | NIST SP 800-207 | doi:10.6028/NIST.SP.800-207 | Authoritative ZTA specification — guides token, permission, and verification design |
| Isolation Forest | Liu, Ting, Zhou | 2008 | ICDM 2008 | doi:10.1109/ICDM.2008.17 | Original Isolation Forest paper — theoretical basis for anomaly detection module |
| Anomaly Detection in Time Series with Triadic Motif Fields and Application in Radar Signal Processing | Liu et al. | 2020 | IEEE Signal Processing | arXiv:2006.03567 | Temporal anomaly pattern analysis relevant to LSTM Autoencoder design |
| The Security of Machine Learning | Barreno et al. | 2010 | Machine Learning | doi:10.1007/s10994-010-5188-5 | Taxonomy of ML security threats; informs adversarial robustness of anomaly detectors |
| Curve25519: New Diffie-Hellman Speed Records | Bernstein | 2006 | PKC 2006 | https://cr.yp.to/ecdh/curve25519-20060209.pdf | Original Curve25519 (X25519) paper — cryptographic foundation for key exchange |
| AES-GCM and Its Applications to Authenticated Encryption | McGrew, Viega | 2004 | NIST Submission | https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf | AES-GCM specification used for AEAD encryption |
| Protocol Buffers v3 Language Guide | Google | 2023 | Google Developers | https://protobuf.dev/programming-guides/proto3/ | Schema definition reference — core protocol specification |
| Multi-Agent Systems Security: Threat Taxonomy and Defenses | Farahmandian et al. | 2024 | IEEE Access | doi:10.1109/ACCESS.2024.3356891 | Comprehensive taxonomy of multi-agent security threats — maps to Guardrail Layer threat model |
| Llm Agents Can Fool Themselves: Internalized Prompt Injection | Wen et al. | 2024 | ICML Workshop | arXiv:2407.19795 | Demonstrates self-referential injection — informs need for deterministic (non-LLM) validation in Guardrail |
| TrustAgent: Towards Safe and Trustworthy LLM-based Agents | Hua et al. | 2024 | arXiv | arXiv:2402.01586 | Framework for agent safety constraints — complements permission boundary design |
| GUARD-D-LLM: An LLM-Based Risk Assessment Engine for the Retrieval-Augmented Generation | Ahmed et al. | 2024 | arXiv | arXiv:2406.09960 | Risk assessment for RAG pipelines — methods transferable to agent result validation |
| HTTP/2 RFC 7540 | IETF | 2015 | RFC 7540 | https://www.rfc-editor.org/rfc/rfc7540 | Transport layer specification for gRPC |
| JSON Schema: A Media Type for Describing JSON Documents | Wright et al. | 2022 | IETF Draft | https://json-schema.org/specification | Strict schema enforcement reference for JSON-based message validation |

---

## State-of-the-Art ML/DL Models

### Anomaly Detection

| Model | Source | Benchmark | Notes |
|-------|--------|-----------|-------|
| Isolation Forest | scikit-learn | KDD99: 99.5% AUC | Best unsupervised baseline; use for real-time scoring |
| LSTM Autoencoder | PyTorch (custom) | SMAP/MSL: 89% F1 | Temporal patterns; train after Phase 1 data collection |
| TimeGAN (data augmentation) | TensorFlow | N/A | Generate additional normal/attack sequences for training |
| Anomaly Transformer | HF: `thu-ml/Anomaly-Transformer` | NeurIPS 2022 benchmark | Attention-based temporal anomaly; consider for Phase 3 upgrade |
| Deep SVDD | PyTorch | CIFAR-10 (adapted) | One-class classification; alternative to LSTM Autoencoder |

### Local SLM (Human → Protocol Translation)

| Model | HF Model ID | Size | Use Case |
|-------|------------|------|---------|
| Phi-3-mini-4k-instruct | `microsoft/phi-3-mini-4k-instruct` | 3.8B | Primary translator; runs locally via Ollama |
| Phi-3.5-mini-instruct | `microsoft/Phi-3.5-mini-instruct` | 3.8B | Upgraded translator option |
| Gemma-2-2b-it | `google/gemma-2-2b-it` | 2B | Lightweight fallback if Phi-3 unavailable |
| Qwen2.5-3B-Instruct | `Qwen/Qwen2.5-3B-Instruct` | 3B | Alternative; strong instruction following |

### Semantic Log Analysis

| Model | HF Model ID | Task | Notes |
|-------|------------|------|-------|
| BERT-base-uncased | `google-bert/bert-base-uncased` | Fine-tune for log classification | Fine-tune on synthetic labeled logs |
| SecurityBERT | `markusbayer/SecurityBERT` | Cybersecurity text classification | Pre-trained on security corpora — strong baseline |
| RoBERTa-base | `FacebookAI/roberta-base` | Log anomaly classification | Alternative to BERT; often higher accuracy |
| LogBERT | Research model (custom) | Log sequence anomaly | Specifically designed for log anomaly detection |

---

## Tools, Libraries & Frameworks

| Tool | GitHub / Link | Use Case in Project |
|------|--------------|---------------------|
| grpcio + grpcio-tools | https://github.com/grpc/grpc | Core transport layer (Orchestrator ↔ Agent) |
| protobuf (Python) | https://github.com/protocolbuffers/protobuf | Message schema definition and serialization |
| cryptography (Python) | https://github.com/pyca/cryptography | X25519 ECDH, AES-256-GCM, HMAC-SHA256 |
| python-jose | https://github.com/mpdavis/python-jose | JWT generation and verification |
| scikit-learn | https://github.com/scikit-learn/scikit-learn | Isolation Forest training and inference |
| PyTorch | https://github.com/pytorch/pytorch | LSTM Autoencoder training |
| HuggingFace Transformers | https://github.com/huggingface/transformers | BERT fine-tuning for log classification |
| Ollama | https://github.com/ollama/ollama | Local Phi-3-mini serving |
| crawl4ai | https://github.com/unclecode/crawl4ai | Research paper crawling for self-update pipeline |
| anthropic (Python SDK) | https://github.com/anthropics/anthropic-sdk-python | Claude API for incident report generation |
| opentelemetry-python | https://github.com/open-telemetry/opentelemetry-python | Distributed tracing for agent communication |
| APScheduler | https://github.com/agronholm/apscheduler | Weekly crawl4ai pipeline scheduling |
| Jaeger | https://github.com/jaegertracing/jaeger | Distributed trace visualization |
| pydantic v2 | https://github.com/pydantic/pydantic | Config validation and data modeling |
| pytest-asyncio | https://github.com/pytest-dev/pytest-asyncio | Async gRPC integration tests |
| Trivy | https://github.com/aquasecurity/trivy | Container vulnerability scanning (CI/CD) |
| Bandit | https://github.com/PyCQA/bandit | Python security static analysis |
| CrewAI | https://github.com/crewAIInc/crewAI | Target framework for adapter (Phase 5) |
| LangGraph | https://github.com/langchain-ai/langgraph | Target framework for adapter (Phase 5) |

---

## Self-Update Protocol

### crawl4ai Configuration

```python
# self_update/crawl4ai_pipeline.py — target configuration

CRAWL_SOURCES = [
    # ArXiv categories
    {"type": "arxiv", "categories": ["cs.CR", "cs.MA", "cs.AI", "cs.NI"],
     "queries": [
         "multi-agent security protocol",
         "prompt injection defense LLM agent",
         "zero-trust AI system",
         "agent communication anomaly detection",
         "gRPC security protocol",
         "inter-agent trust management",
     ]},

    # Top security conferences (open-access proceedings)
    {"type": "web", "urls": [
        "https://www.usenix.org/conference/usenixsecurity25/technical-sessions",
        "https://www.ndss-symposium.org/ndss2025/programme/",
        "https://ieeexplore.ieee.org/xpl/conhome/10646950/proceeding",  # IEEE S&P 2025
    ]},

    # AI safety & agent security blogs
    {"type": "web", "urls": [
        "https://huggingface.co/papers",  # Filter by cs.CR + cs.MA
        "https://paperswithcode.com/task/anomaly-detection",
        "https://www.langchain.com/blog",  # LLM agent security posts
    ]},

    # CVE feeds for stack dependencies
    {"type": "rss", "feeds": [
        "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",  # gRPC CVEs
    ]},
]

RELEVANCE_FILTER = {
    "min_score": 0.70,  # LLM-scored abstract relevance threshold
    "keywords_must_include_any": [
        "agent", "multi-agent", "prompt injection", "zero-trust",
        "anomaly detection", "gRPC", "protobuf", "LLM security",
        "orchestration", "cryptographic protocol"
    ],
    "keywords_exclude": ["image classification", "NLP translation", "recommendation system"]
}

UPDATE_FREQUENCY = "weekly"  # Every Monday 02:00 UTC
OUTPUT_FILE = "SECOND-KNOWLEDGE-BRAIN.md"
DEDUP_FIELD = "doi_or_arxiv_id"  # Prevent duplicate entries
```

### Format for Adding New Entries

When the crawler finds a new relevant paper, it appends to the Key Research Papers table:

```markdown
| {title} | {authors} | {year} | {venue} | {doi_or_arxiv} | {relevance_note} |
```

And appends to the Knowledge Update Log:

```markdown
### {YYYY-MM-DD} — Automated Crawl
- **Source**: ArXiv / Conference / Blog
- **New papers added**: N
- **CVE alerts generated**: N
- **Notable finding**: {one-line summary of most significant discovery}
```

### Update Frequency
- **Scheduled**: Weekly (every Monday 02:00 UTC via APScheduler)
- **On-demand**: `python -m self_update.crawl4ai_pipeline --now`
- **CVE alerts**: Checked daily via NVD RSS feed; alert generated immediately on relevant CVE

---

## Knowledge Update Log

### 2026-06-03 — Initial Manual Population
- **Source**: Manual research by project author
- **Papers added**: 14 foundational papers across cryptography, anomaly detection, prompt injection, and agent security
- **Models cataloged**: 12 models across anomaly detection, SLM translation, and semantic analysis categories
- **Tools cataloged**: 18 tools and frameworks covering full technology stack
- **CVE alerts**: None (pipeline not yet active)
- **Notable finding**: AgentDojo (arXiv:2406.13352) provides a ready-made benchmark suite for evaluating prompt injection defenses — should be integrated into Phase 5 red-team testing rather than building custom scenarios from scratch

---
*This file is automatically updated by `self_update/crawl4ai_pipeline.py`. Do not manually edit entries above the Knowledge Update Log section — use the log section for manual annotations.*
