"""
Production config loader using pydantic v2 + YAML with env var override.

Every setting is typed and validated at startup. Environment variables
take precedence over YAML values following the pattern: SOM__SECTION__KEY.
"""

from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Optional, List, Dict
from dataclasses import dataclass, field

import yaml
from pydantic import BaseModel, Field, field_validator


logger = logging.getLogger(__name__)


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 50051
    grpc_max_workers: int = 100
    grpc_max_concurrent_streams: int = 10000
    stream_lease_seconds: int = 300


class JWTConfig(BaseModel):
    algorithm: str = "RS256"
    ttl_seconds: int = 60
    issuer: str = "secure-orchestration-mesh"
    private_key_path: str = "config/jwt_private.pem"
    public_key_path: str = "config/jwt_public.pem"


class TLSConfig(BaseModel):
    enabled: bool = True
    cert_path: str = "config/server.crt"
    key_path: str = "config/server.key"
    ca_cert_path: str = "config/ca.crt"


class SecurityConfig(BaseModel):
    jwt: JWTConfig = Field(default_factory=JWTConfig)
    tls: TLSConfig = Field(default_factory=TLSConfig)
    replay_window_seconds: int = 30


class IsolationForestConfig(BaseModel):
    enabled: bool = True
    model_path: str = "models/isolation_forest.pkl"
    contamination: float = 0.01
    n_estimators: int = 100
    suspicious_threshold: float = 0.65
    critical_threshold: float = 0.85
    consecutive_suspicious_for_quarantine: int = 2
    window_size_seconds: int = 10


class LSTMAutoencoderConfig(BaseModel):
    enabled: bool = False
    model_path: str = "models/lstm_autoencoder.pt"
    sequence_length: int = 50
    hidden_size: int = 128
    bottleneck_size: int = 32
    num_layers: int = 2
    reconstruction_error_threshold: float = 0.15


class LogClassifierConfig(BaseModel):
    enabled: bool = False
    model_path: str = "models/bert_log_classifier"
    bert_model_id: str = "google-bert/bert-base-uncased"


class AnomalyConfig(BaseModel):
    isolation_forest: IsolationForestConfig = Field(default_factory=IsolationForestConfig)
    lstm_autoencoder: LSTMAutoencoderConfig = Field(default_factory=LSTMAutoencoderConfig)
    log_classifier: LogClassifierConfig = Field(default_factory=LogClassifierConfig)


class OllamaLLMConfig(BaseModel):
    base_url: str = "http://localhost:11434"
    model: str = "phi3:mini"
    timeout_seconds: float = 30.0
    max_tokens: int = 1024


class ClaudeLLMConfig(BaseModel):
    api_key_env: str = "CLAUDE_API_KEY"
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 4096
    timeout_seconds: float = 60.0


class GPT4oLLMConfig(BaseModel):
    api_key_env: str = "OPENAI_API_KEY"
    model: str = "gpt-4o"
    max_tokens: int = 4096
    timeout_seconds: float = 60.0


class LLMConfig(BaseModel):
    provider: str = "ollama"
    ollama: OllamaLLMConfig = Field(default_factory=OllamaLLMConfig)
    claude: ClaudeLLMConfig = Field(default_factory=ClaudeLLMConfig)
    gpt4o: GPT4oLLMConfig = Field(default_factory=GPT4oLLMConfig)


class SelfUpdateArxivConfig(BaseModel):
    categories: List[str] = Field(default_factory=lambda: ["cs.CR", "cs.MA", "cs.AI", "cs.NI"])
    max_results_per_query: int = 50


class SelfUpdateSecurityConferencesConfig(BaseModel):
    enabled: bool = True
    urls: List[str] = Field(default_factory=list)


class SelfUpdateCVEFeedConfig(BaseModel):
    enabled: bool = True
    url: str = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"


class SelfUpdateSourcesConfig(BaseModel):
    arxiv: SelfUpdateArxivConfig = Field(default_factory=SelfUpdateArxivConfig)
    security_conferences: SelfUpdateSecurityConferencesConfig = Field(default_factory=SelfUpdateSecurityConferencesConfig)
    cve_feed: SelfUpdateCVEFeedConfig = Field(default_factory=SelfUpdateCVEFeedConfig)


class SelfUpdateConfig(BaseModel):
    enabled: bool = False
    schedule: str = "weekly"
    output_file: str = "SECOND-KNOWLEDGE-BRAIN.md"
    relevance_threshold: float = 0.70
    sources: SelfUpdateSourcesConfig = Field(default_factory=SelfUpdateSourcesConfig)


class DatabaseConfig(BaseModel):
    path: str = "data/behavioral_metrics.db"
    pool_size: int = 5


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "json"
    output: str = "stdout"
    file_path: str = "logs/orchestrator.log"


class JaegerConfig(BaseModel):
    host: str = "localhost"
    port: int = 6831
    service_name: str = "secure-orchestration-mesh"


class TelemetryConfig(BaseModel):
    enabled: bool = True
    jaeger: JaegerConfig = Field(default_factory=JaegerConfig)


class AgentDefaultsConfig(BaseModel):
    max_payload_bytes: int = 10485760
    max_execution_ms: int = 300000
    heartbeat_interval_seconds: float = 5.0
    heartbeat_timeout_seconds: float = 15.0
    registration_timeout_seconds: float = 30.0


class QuarantineConfig(BaseModel):
    auto_quarantine_enabled: bool = True
    manual_review_required: bool = False
    max_quarantine_duration_minutes: int = 60


class SideChannelConfig(BaseModel):
    enabled: bool = False
    block_size: int = 4096
    pad_byte: int = 0x00


class AuditTrailConfig(BaseModel):
    enabled: bool = True
    path: str = "data/audit_trail.db"
    merkle_branching: int = 2


class AppConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    anomaly: AnomalyConfig = Field(default_factory=AnomalyConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    self_update: SelfUpdateConfig = Field(default_factory=SelfUpdateConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    agent_defaults: AgentDefaultsConfig = Field(default_factory=AgentDefaultsConfig)
    quarantine: QuarantineConfig = Field(default_factory=QuarantineConfig)
    side_channel: SideChannelConfig = Field(default_factory=SideChannelConfig)
    audit_trail: AuditTrailConfig = Field(default_factory=AuditTrailConfig)


def _env_override(raw: dict, prefix: str = "SOM") -> dict:
    for key, value in os.environ.items():
        if not key.startswith(f"{prefix}__"):
            continue
        config_path = key[len(prefix) + 2:].lower().split("__")
        d = raw
        for part in config_path[:-1]:
            d = d.setdefault(part, {})
        env_val = value
        if env_val.lower() in ("true", "false"):
            env_val = env_val.lower() == "true"
        elif env_val.isdigit():
            env_val = int(env_val)
        elif env_val.replace(".", "", 1).isdigit():
            env_val = float(env_val)
        d[config_path[-1]] = env_val
    return raw


def load_config(config_path: Optional[str] = None) -> AppConfig:
    config_path = config_path or os.getenv("CONFIG_PATH", "config.yaml")
    raw: dict = {}
    if os.path.exists(config_path):
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
    raw = _env_override(raw)
    config = AppConfig(**raw)
    logger.info("Config loaded from %s (provider=%s)", config_path, config.llm.provider)
    return config
