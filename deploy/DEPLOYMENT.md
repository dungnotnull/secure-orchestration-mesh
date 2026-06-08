# Deployment Guide — secure-orchestration-mesh

## Overview

This guide covers deploying the secure-orchestration-mesh in production across three environments:
single-machine Docker Compose, Docker Swarm, and Kubernetes.

Each deployment mode provides identical security guarantees: AES-256-GCM encryption, X25519 key exchange, JWT-based identity, deterministic guardrail validation, and ML anomaly detection.

---

## 1. Single Machine (Docker Compose)

**Best for**: Development, testing, small-scale production (< 100 concurrent agents)

### Prerequisites
- Docker Engine 24+
- Docker Compose v2
- 4GB RAM minimum (8GB recommended with Ollama)

### Setup

```bash
# Clone and build
git clone https://github.com/secure-orchestration-mesh/secure-orchestration-mesh.git
cd secure-orchestration-mesh

# Generate keys (first time only)
mkdir -p config
python -m orchestrator.main --gen-keys

# Set environment variables
cp .env.example .env
# Edit .env with your API keys if using Claude/GPT-4o

# Build and start
docker compose build
docker compose up -d

# Pull Phi-3-mini (optional, for SLM translation)
docker exec mesh-ollama ollama pull phi3:mini

# Verify
docker compose ps
docker compose logs orchestrator
```

### Configuration
Edit `config.yaml` for customization:
- `server.port`: gRPC port (default: 50051)
- `llm.provider`: `ollama` | `claude` | `gpt4o`
- `anomaly.isolation_forest.enabled`: toggle anomaly detection
- `security.jwt.ttl_seconds`: token lifetime (60s default)

### Stopping
```bash
docker compose down
```

---

## 2. Docker Swarm

**Best for**: Production multi-node, high availability, 100-10,000 concurrent agents

### Prerequisites
- Docker Swarm initialized (`docker swarm init`)
- 3+ nodes recommended
- Shared storage or NFS for persistent volumes

### Setup

```bash
# Initialize swarm (once per cluster)
docker swarm init

# Create secrets (from secure source — never commit to git)
echo "sk-ant-..." | docker secret create claude_api_key -
echo "sk-..." | docker secret create openai_api_key -

# Build images and push to registry
docker build -t secure-orchestration-mesh-orchestrator:latest .
docker build -f Dockerfile.agent -t secure-orchestration-mesh-agent:latest .
docker tag secure-orchestration-mesh-orchestrator:latest registry.example.com/mesh/orchestrator:latest
docker tag secure-orchestration-mesh-agent:latest registry.example.com/mesh/agent:latest
docker push registry.example.com/mesh/orchestrator:latest
docker push registry.example.com/mesh/agent:latest

# Update image references in docker-compose.swarm.yml to match your registry

# Deploy stack
docker stack deploy -c docker-compose.swarm.yml mesh

# Verify
docker stack services mesh
docker service logs mesh_orchestrator
```

### Scaling Agents
```bash
docker service scale mesh_worker-agent=10
```

### Updating
```bash
# Rolling update with zero-downtime
docker service update --image registry.example.com/mesh/orchestrator:latest mesh_orchestrator
```

---

## 3. Kubernetes

**Best for**: Enterprise production, 10,000+ concurrent agents, auto-scaling

### Prerequisites
- Kubernetes 1.28+
- kubectl configured
- Container registry access

### Setup

```bash
# Build and push images
docker build -t secure-orchestration-mesh-orchestrator:latest .
docker build -f Dockerfile.agent -t secure-orchestration-mesh-agent:latest .
docker tag secure-orchestration-mesh-orchestrator:latest registry.example.com/mesh/orchestrator:latest
docker tag secure-orchestration-mesh-agent:latest registry.example.com/mesh/agent:latest
docker push registry.example.com/mesh/orchestrator:latest
docker push registry.example.com/mesh/agent:latest

# Update image references in deploy/kubernetes/mesh-stack.yaml

# Create secrets
kubectl create secret generic mesh-secrets \
  --namespace secure-mesh \
  --from-literal=claude-api-key=sk-ant-... \
  --from-literal=openai-api-key=sk-...

# Deploy
kubectl apply -f deploy/kubernetes/mesh-stack.yaml

# Verify
kubectl -n secure-mesh get pods
kubectl -n secure-mesh get services
kubectl -n secure-mesh logs deployment/orchestrator
```

### Scaling
```bash
kubectl -n secure-mesh scale deployment worker-agent --replicas=50
kubectl -n secure-mesh scale deployment orchestrator --replicas=3
```

### Auto-Scaling (HPA)
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: orchestrator-hpa
  namespace: secure-mesh
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: orchestrator
  minReplicas: 1
  maxReplicas: 5
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

---

## Networking

### Ports

| Service | Port | Protocol | Purpose |
|---------|------|---------|---------|
| Orchestrator gRPC | 50051 | TCP | Primary agent communication |
| WebSocket fallback | 8443 | TCP (TLS) | Fallback transport |
| Ollama | 11434 | TCP | Local SLM endpoint |
| Jaeger UI | 16686 | TCP | Telemetry dashboard |
| Jaeger Thrift | 6831 | UDP | Trace collection |

### Firewall Rules
```
# Inbound to orchestrator
tcp/50051  # gRPC agents
tcp/8443   # WebSocket fallback

# Internal only
udp/6831   # Jaeger telemetry
tcp/11434  # Ollama (localhost or internal network only — never exposed)
```

---

## Monitoring

### Jaeger Tracing
Access the Jaeger UI at `http://<host>:16686` to view distributed traces of agent communication.

### CLI Dashboard
```bash
# Start orchestrator with live dashboard
python -m orchestrator.main --dashboard
```

Shows real-time:
- Agent pool state (idle/busy/quarantined/offline)
- Anomaly scores per agent
- Task throughput and failure rates
- Recent alerts and quarantine events

### Logs
Logs are structured JSON (configurable in `config.yaml`):
```json
{"timestamp": "2026-06-08T12:00:00Z", "level": "INFO", "message": "Agent registered: abc123"}
```

Output options: `stdout` (default) or `file` (to `logs/orchestrator.log`).

---

## Security Checklist

Before deploying to production, ensure:

- [ ] JWT keys generated and stored securely (not in git)
- [ ] TLS certificates configured for gRPC and WebSocket
- [ ] API keys stored in secrets manager (Docker secrets / K8s secrets), never in config files
- [ ] Firewall restricts Ollama port to internal network only
- [ ] Audit trail database backed up regularly
- [ ] Quarantine auto-trigger configured with appropriate thresholds
- [ ] Incident reports directory (`reports/`) has write permissions
- [ ] All containers run as non-root user
- [ ] Docker images scanned for vulnerabilities (Trivy recommended)

---

## Troubleshooting

### Agents can't connect to Orchestrator
```bash
# Check orchestrator is listening
docker compose logs orchestrator | grep "Starting"
netstat -an | grep 50051

# Verify agent can reach orchestrator
python -c "import grpc; grpc.insecure_channel('localhost:50051')"
```

### Ollama not responding
```bash
# Check Ollama is running
curl http://localhost:11434/api/tags
docker exec mesh-ollama ollama list

# Pull required model
docker exec mesh-ollama ollama pull phi3:mini
```

### Anomaly scores too high (false positives)
```bash
# Adjust thresholds in config.yaml
anomaly:
  isolation_forest:
    suspicious_threshold: 0.75  # Increase from 0.65
    critical_threshold: 0.90    # Increase from 0.85
```

### Protobuf compilation errors
```bash
# Recompile proto files
python -m grpc_tools.protoc -Iproto --python_out=proto --grpc_python_out=proto proto/mesh.proto

# Verify generated files exist
ls -la proto/mesh_pb2.py proto/mesh_pb2_grpc.py
```
