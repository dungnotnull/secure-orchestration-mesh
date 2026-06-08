"""
Orchestrator main entry point with full production integration.

Wires together: gRPC server, WebSocket fallback, Guardrail Layer, Token Issuer,
Task Scheduler, Combined Anomaly Engine, Audit Trail, Dashboard, Incident Reporter,
and Self-Update Pipeline.

Usage:
    python -m orchestrator.main                    # Start all services
    python -m orchestrator.main --gen-keys         # Generate keys and exit
    python -m orchestrator.main --dashboard        # Start with live CLI dashboard
    python -m orchestrator.main --no-websocket     # Disable WebSocket fallback
"""

from __future__ import annotations

import asyncio
import argparse
import logging
import os
import signal
import sys
import uuid

from orchestrator.config import load_config, AppConfig
from orchestrator.token_issuer import TokenIssuer
from orchestrator.guardrail import GuardrailLayer
from orchestrator.task_scheduler import TaskScheduler
from orchestrator.server import OrchestratorServer
from orchestrator.websocket_fallback import WebsocketServer
from orchestrator.audit_trail import AuditTrail
from orchestrator.dashboard import CLIDashboard
from anomaly.isolation_forest import IsolationForestScorer
from anomaly.lstm_autoencoder import LSTMAutoencoder
from anomaly.bert_classifier import BERTLogClassifier
from anomaly.combined_engine import CombinedAnomalyEngine
from anomaly.behavioral_logger import BehavioralLogger
from translator.slm_bridge import SLMBridge
from llm.backend import LLMProvider
from llm.claude_backend import ClaudeBackend
from llm.gpt4o_backend import GPT4oBackend
from llm.ollama_backend import OllamaBackend
from llm.incident_reporter import IncidentReportGenerator
from self_update.crawl4ai_pipeline import SelfUpdatePipeline
from agent_sdk.side_channel import SideChannelPadder

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("orchestrator.main")


async def run(config: AppConfig, enable_dashboard: bool = False, enable_websocket: bool = True):
    logger.info("=== Secure Orchestration Mesh v0.1.0 ===")
    logger.info("Provider chain: %s", config.llm.provider)

    # ── Core Security Components ──────────────────────────────────────
    token_issuer = TokenIssuer(
        private_key_path=config.security.jwt.private_key_path,
        public_key_path=config.security.jwt.public_key_path,
        ttl_seconds=config.security.jwt.ttl_seconds,
    )

    guardrail = GuardrailLayer(
        token_issuer=token_issuer,
        max_payload_bytes=config.agent_defaults.max_payload_bytes,
    )

    scheduler = TaskScheduler()
    scheduler.HEARTBEAT_TIMEOUT_SECONDS = config.agent_defaults.heartbeat_timeout_seconds

    side_channel = SideChannelPadder(
        block_size=config.side_channel.block_size,
    ) if config.side_channel.enabled else None

    # ── Behavioral Logger ─────────────────────────────────────────────
    behavioral_logger = BehavioralLogger(
        db_path=config.database.path,
    )
    await behavioral_logger.initialize()

    # ── Anomaly Detection Stack ───────────────────────────────────────
    if_scorer = IsolationForestScorer(
        model_path=config.anomaly.isolation_forest.model_path,
        suspicious_threshold=config.anomaly.isolation_forest.suspicious_threshold,
        critical_threshold=config.anomaly.isolation_forest.critical_threshold,
        contamination=config.anomaly.isolation_forest.contamination,
        n_estimators=config.anomaly.isolation_forest.n_estimators,
    )
    if_scorer.load_model()

    lstm_autoencoder = LSTMAutoencoder(
        model_path=config.anomaly.lstm_autoencoder.model_path,
        sequence_length=config.anomaly.lstm_autoencoder.sequence_length,
        hidden_size=config.anomaly.lstm_autoencoder.hidden_size,
        bottleneck_size=config.anomaly.lstm_autoencoder.bottleneck_size,
        num_layers=config.anomaly.lstm_autoencoder.num_layers,
        reconstruction_error_threshold=config.anomaly.lstm_autoencoder.reconstruction_error_threshold,
    )
    if config.anomaly.lstm_autoencoder.enabled:
        lstm_autoencoder.load_model()

    bert_classifier = BERTLogClassifier(
        model_path=config.anomaly.log_classifier.model_path,
        bert_model_id=config.anomaly.log_classifier.bert_model_id,
    )
    if config.anomaly.log_classifier.enabled:
        bert_classifier.load_model()

    combined_anomaly = CombinedAnomalyEngine(
        if_scorer=if_scorer,
        lstm_autoencoder=lstm_autoencoder,
        behavioral_logger=behavioral_logger,
        suspicious_threshold=config.anomaly.isolation_forest.suspicious_threshold,
        critical_threshold=config.anomaly.isolation_forest.critical_threshold,
        consecutive_for_quarantine=config.anomaly.isolation_forest.consecutive_suspicious_for_quarantine,
    )

    # ── Audit Trail ───────────────────────────────────────────────────
    audit_trail = AuditTrail(
        db_path=config.audit_trail.path,
        merkle_branching=config.audit_trail.merkle_branching,
    )
    if config.audit_trail.enabled:
        audit_trail.initialize()
        audit_trail.record("AGENT_REGISTERED", agent_id="orchestrator", task_id="boot", detail="Orchestrator daemon started")

    # ── LLM Provider Chain ────────────────────────────────────────────
    llm_provider = LLMProvider(provider=config.llm.provider)
    claude = ClaudeBackend(
        api_key_env=config.llm.claude.api_key_env,
        model=config.llm.claude.model,
        max_tokens=config.llm.claude.max_tokens,
        timeout_seconds=config.llm.claude.timeout_seconds,
    )
    gpt4o = GPT4oBackend(
        api_key_env=config.llm.gpt4o.api_key_env,
        model=config.llm.gpt4o.model,
        max_tokens=config.llm.gpt4o.max_tokens,
        timeout_seconds=config.llm.gpt4o.timeout_seconds,
    )
    ollama = OllamaBackend(
        base_url=config.llm.ollama.base_url,
        model=config.llm.ollama.model,
        max_tokens=config.llm.ollama.max_tokens,
        timeout_seconds=config.llm.ollama.timeout_seconds,
    )
    llm_provider.register("claude", claude)
    llm_provider.register("gpt4o", gpt4o)
    llm_provider.register("ollama", ollama)

    incident_reporter = IncidentReportGenerator(
        llm_provider=llm_provider,
        behavioral_logger=behavioral_logger,
        reports_dir="reports",
    )

    slm_bridge = SLMBridge(llm_provider=llm_provider)

    # ── gRPC Server ───────────────────────────────────────────────────
    server = OrchestratorServer(
        host=config.server.host,
        port=config.server.port,
        max_workers=config.server.grpc_max_workers,
        token_issuer=token_issuer,
        guardrail=guardrail,
        scheduler=scheduler,
        anomaly_engine=combined_anomaly,
        behavioral_logger=behavioral_logger,
        audit_trail=audit_trail if config.audit_trail.enabled else None,
        incident_reporter=incident_reporter,
        bert_classifier=bert_classifier if config.anomaly.log_classifier.enabled else None,
    )
    await server.start()

    # ── WebSocket Fallback Server ─────────────────────────────────────
    ws_server = None
    if enable_websocket:
        ws_server = WebsocketServer(
            host=config.server.host,
            port=8443,
            token_issuer=token_issuer,
            guardrail=guardrail,
            scheduler=scheduler,
            tls_cert_path=config.security.tls.cert_path if config.security.tls.enabled else "",
            tls_key_path=config.security.tls.key_path if config.security.tls.enabled else "",
        )
        await ws_server.start()

    # ── CLI Dashboard ─────────────────────────────────────────────────
    dashboard = None
    if enable_dashboard:
        dashboard = CLIDashboard(scheduler=scheduler, behavioral_logger=behavioral_logger, anomaly_scorer=if_scorer)
        dash_task = asyncio.create_task(dashboard.start())

    # ── Self-Update Pipeline ──────────────────────────────────────────
    update_pipeline = None
    if config.self_update.enabled:
        update_pipeline = SelfUpdatePipeline(
            output_file=config.self_update.output_file,
            relevance_threshold=config.self_update.relevance_threshold,
            categories=config.self_update.sources.arxiv.categories,
        )
        await update_pipeline.start(schedule=config.self_update.schedule)

    # ── Ready ─────────────────────────────────────────────────────────
    logger.info("All services started — orchestrator is ready")
    logger.info("  gRPC:       %s:%d", config.server.host, config.server.port)
    if ws_server:
        logger.info("  WebSocket:  %s:%d", config.server.host, 8443)
    logger.info("  LLM:        %s", config.llm.provider)
    logger.info("  Anomaly IF: %s", "enabled" if config.anomaly.isolation_forest.enabled else "disabled")
    logger.info("  Audit Trail: %s", "enabled" if config.audit_trail.enabled else "disabled")
    logger.info("  Dashboard:  %s", "enabled" if enable_dashboard else "disabled")

    # ── Wait for shutdown signal ──────────────────────────────────────
    stop_event = asyncio.Event()

    def _signal_handler():
        logger.info("Received shutdown signal")
        stop_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            pass

    await stop_event.wait()

    # ── Graceful Shutdown ─────────────────────────────────────────────
    logger.info("Shutting down all services...")

    if update_pipeline:
        await update_pipeline.stop()
    if dashboard:
        dashboard.stop()
    if ws_server:
        await ws_server.stop()
    await server.stop(grace=5.0)

    if audit_trail and config.audit_trail.enabled:
        is_valid, err = audit_trail.verify_chain()
        if not is_valid:
            logger.error("Audit trail integrity CHECK FAILED: %s", err)
        audit_trail.close()
        logger.info("Audit trail closed — integrity: %s", "VALID" if is_valid else "INVALID")

    logger.info("Orchestrator shut down cleanly")


def main():
    parser = argparse.ArgumentParser(description="Secure Orchestration Mesh — Orchestrator Daemon")
    parser.add_argument("--host", default="", help="Override bind address")
    parser.add_argument("--port", type=int, default=0, help="Override gRPC port")
    parser.add_argument("--config", default="", help="Path to config.yaml")
    parser.add_argument("--gen-keys", action="store_true", help="Generate JWT keys and exit")
    parser.add_argument("--dashboard", action="store_true", help="Enable live CLI dashboard")
    parser.add_argument("--no-websocket", action="store_true", help="Disable WebSocket fallback")

    args = parser.parse_args()

    if args.gen_keys:
        config = load_config(args.config or None)
        TokenIssuer(
            private_key_path=config.security.jwt.private_key_path,
            public_key_path=config.security.jwt.public_key_path,
        )
        logger.info("JWT keys generated")
        return

    config = load_config(args.config or None)

    if args.host:
        config.server.host = args.host
    if args.port:
        config.server.port = args.port

    asyncio.run(run(
        config,
        enable_dashboard=args.dashboard,
        enable_websocket=not args.no_websocket,
    ))


if __name__ == "__main__":
    main()
