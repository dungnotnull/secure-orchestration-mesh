"""
gRPC server for the Orchestrator — the central daemon.

Implements the AgentMesh service: agent registration, bidirectional task stream,
heartbeat monitoring, permission grants, error reporting, and quarantine issuance.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import AsyncIterator

import grpc
from concurrent import futures

from proto import mesh_pb2
from proto import mesh_pb2_grpc

from agent_sdk.crypto import CryptoSession
from orchestrator.token_issuer import TokenIssuer
from orchestrator.guardrail import GuardrailLayer, ValidationOutcome
from orchestrator.task_scheduler import TaskScheduler, AgentState
from anomaly.isolation_forest import IsolationForestScorer
from anomaly.combined_engine import CombinedAnomalyEngine
from anomaly.behavioral_logger import BehavioralLogger
from anomaly.bert_classifier import BERTLogClassifier

logger = logging.getLogger(__name__)


class AgentMeshServicer(mesh_pb2_grpc.AgentMeshServicer):
    """gRPC service implementation for the secure orchestration mesh."""

    def __init__(
        self,
        token_issuer: TokenIssuer,
        guardrail: GuardrailLayer,
        scheduler: TaskScheduler,
        anomaly_engine: CombinedAnomalyEngine,
        behavioral_logger: BehavioralLogger,
        audit_trail=None,
        incident_reporter=None,
        bert_classifier: BERTLogClassifier = None,
    ):
        self.token_issuer = token_issuer
        self.guardrail = guardrail
        self.scheduler = scheduler
        self.anomaly_engine = anomaly_engine
        self.behavioral_logger = behavioral_logger
        self.audit_trail = audit_trail
        self.incident_reporter = incident_reporter
        self.bert_classifier = bert_classifier
        self._stream_agent_map: dict[int, str] = {}

    def _extract_agent_id(self, context: grpc.aio.ServicerContext) -> str:
        metadata = dict(context.invocation_metadata())
        return metadata.get("x-agent-id", metadata.get("agent-id", ""))

    async def Register(
        self,
        request: mesh_pb2.AgentRegistrationRequest,
        context: grpc.aio.ServicerContext,
    ) -> mesh_pb2.AgentRegistrationResponse:
        logger.info(
            "Registration request agent_id=%s label=%s caps=%s",
            request.agent_id, request.agent_label, list(request.capabilities),
        )

        await self.scheduler.register(request)

        crypto = CryptoSession.init_for_orchestrator(
            session_id=request.agent_id,
            agent_public_bytes=request.public_key,
        )
        self.token_issuer.register_session(request.agent_id, crypto)

        token, expires_at = self.token_issuer.issue(
            agent_id=request.agent_id,
            task_id=str(uuid.uuid4()),
            permissions=set(request.capabilities),
        )

        if self.audit_trail:
            self.audit_trail.record("AGENT_REGISTERED", agent_id=request.agent_id, detail=f"caps={request.capabilities}")

        return mesh_pb2.AgentRegistrationResponse(
            agent_id=request.agent_id,
            orchestrator_public_key=crypto.agent_public.public_bytes_raw(),
            nonce=crypto.nonce_base,
            access_token=token,
            token_expires_at=expires_at,
            stream_lease_seconds=300,
        )

    async def TaskStream(
        self,
        request_iterator: AsyncIterator[mesh_pb2.SignedPacket],
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[mesh_pb2.SignedPacket]:
        agent_id = self._extract_agent_id(context)

        async for signed_packet in request_iterator:
            agent = self.scheduler.get_agent(agent_id)
            if agent is None or agent.state == AgentState.QUARANTINED:
                yield self._build_quarantine_notice(agent_id, "Agent quarantined or unknown")
                continue

            session = self.token_issuer.get_session(agent_id)
            if session is None:
                yield self._build_error_packet("MISSING_SESSION")
                continue

            result = self.guardrail.validate_inbound(signed_packet, session, "")
            if not result.passed:
                logger.warning("Guardrail reject agent=%s: %s — %s", agent_id, result.outcome, result.detail)
                if self.audit_trail:
                    self.audit_trail.record("GUARDRAIL_REJECTED", agent_id=agent_id, detail=result.outcome)
                yield self._build_error_packet(result.outcome)
                continue

            task_result = mesh_pb2.TaskResult()
            task_result.ParseFromString(session.decrypt(signed_packet.payload, signed_packet.sequence_number))

            success = task_result.state == mesh_pb2.TASK_STATE_COMPLETED
            await self.scheduler.complete_task(agent_id, success)

            if self.audit_trail:
                event = "TASK_COMPLETED" if success else "TASK_FAILED"
                self.audit_trail.record(event, agent_id=agent_id, task_id=task_result.task_id)

            for metric in self.guardrail.drain_metrics():
                await self.behavioral_logger.log_metric(metric["agent_id"], metric["task_id"],
                    metric["payload_bytes"], metric["latency_us"], metric["error_code"])

            score_result = await self.anomaly_engine.score(agent_id)
            await self.scheduler.update_anomaly_score(agent_id, score_result.combined_score)

            if score_result.level != "NORMAL":
                await self.behavioral_logger.log_anomaly_event(
                    agent_id=agent_id, anomaly_level=score_result.level,
                    score=score_result.combined_score, detector_name="combined",
                    task_id=task_result.task_id,
                )

            if self.anomaly_engine.should_quarantine(agent_id):
                await self.scheduler.quarantine(agent_id, f"Auto-quarantine: score={score_result.combined_score:.3f}")
                if self.audit_trail:
                    self.audit_trail.record("AGENT_QUARANTINED", agent_id=agent_id,
                        detail=f"auto score={score_result.combined_score:.4f}")
                if self.incident_reporter:
                    asyncio.create_task(self._generate_incident_report(agent_id, score_result))

            ack = mesh_pb2.GrantAck(agent_id=agent_id, accepted=True, reason="TASK_ACKNOWLEDGED")
            yield self._sign_and_encrypt(ack, session)

    async def HeartBeatStream(
        self,
        request_iterator: AsyncIterator[mesh_pb2.HeartBeat],
        context: grpc.aio.ServicerContext,
    ) -> mesh_pb2.HeartBeatAck:
        async for heartbeat in request_iterator:
            await self.scheduler.heartbeat(heartbeat.agent_id, heartbeat.status)
            return mesh_pb2.HeartBeatAck(
                agent_id=heartbeat.agent_id,
                acknowledged=True,
                last_sequence_received=heartbeat.sequence_number,
            )
        return mesh_pb2.HeartBeatAck(acknowledged=False)

    async def PushPermissionGrant(
        self,
        request: mesh_pb2.PermissionGrant,
        context: grpc.aio.ServicerContext,
    ) -> mesh_pb2.GrantAck:
        if self.audit_trail:
            self.audit_trail.record("PERMISSION_GRANTED", agent_id=request.agent_id)
        return mesh_pb2.GrantAck(agent_id=request.agent_id, accepted=True, reason="")

    async def ReportError(
        self,
        request: mesh_pb2.ErrorReport,
        context: grpc.aio.ServicerContext,
    ) -> mesh_pb2.ErrorAck:
        logger.error("Error agent=%s [%s]: %s", request.agent_id, request.error_code, request.error_summary)
        return mesh_pb2.ErrorAck(agent_id=request.agent_id, logged=True)

    async def IssueQuarantine(
        self,
        request: mesh_pb2.QuarantineNotice,
        context: grpc.aio.ServicerContext,
    ) -> mesh_pb2.QuarantineAck:
        await self.scheduler.quarantine(request.agent_id, request.reason_detail)
        if self.audit_trail:
            self.audit_trail.record("AGENT_QUARANTINED", agent_id=request.agent_id, detail=request.reason_detail)
        return mesh_pb2.QuarantineAck(agent_id=request.agent_id, shutdown_initiated=True)

    async def _generate_incident_report(self, agent_id: str, score_result):
        try:
            entries = await self.behavioral_logger.get_recent_metrics(agent_id, limit=50)
            report = await self.incident_reporter.generate(
                quarantine_event={
                    "agent_id": agent_id,
                    "reason": f"Auto-quarantine: anomaly score {score_result.combined_score:.4f}",
                    "scores": [{
                        "detector_name": "isolation_forest",
                        "score": score_result.isolation_forest_score,
                        "threshold": self.anomaly_engine.suspicious_threshold,
                    }],
                },
                behavioral_entries=entries,
            )
            await self.incident_reporter.save(report)
            logger.info("Incident report generated: %s", report.report_id)
        except Exception as e:
            logger.error("Failed to generate incident report: %s", e)

    def _build_error_packet(self, error_code: str) -> mesh_pb2.SignedPacket:
        err = mesh_pb2.ErrorReport(
            error_code=error_code, severity=mesh_pb2.LOG_SEVERITY_ERROR,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        return mesh_pb2.SignedPacket(payload=err.SerializeToString())

    def _build_quarantine_notice(self, agent_id: str, reason: str) -> mesh_pb2.SignedPacket:
        notice = mesh_pb2.QuarantineNotice(
            agent_id=agent_id, reason_code="AUTO_QUARANTINE", reason_detail=reason,
            quarantined_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), automatic=True,
        )
        return mesh_pb2.SignedPacket(payload=notice.SerializeToString())

    def _sign_and_encrypt(self, message, session: CryptoSession) -> mesh_pb2.SignedPacket:
        raw = message.SerializeToString()
        ciphertext = session.encrypt(raw)
        hmac_sig = session.sign(ciphertext)
        return mesh_pb2.SignedPacket(
            payload=ciphertext, hmac_signature=hmac_sig,
            sequence_number=session.sequence_counter,
        )


class OrchestratorServer:
    """Manages the gRPC server lifecycle."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 50051,
        max_workers: int = 100,
        token_issuer: TokenIssuer | None = None,
        guardrail: GuardrailLayer | None = None,
        scheduler: TaskScheduler | None = None,
        anomaly_engine: CombinedAnomalyEngine | None = None,
        behavioral_logger: BehavioralLogger | None = None,
        audit_trail=None,
        incident_reporter=None,
        bert_classifier: BERTLogClassifier | None = None,
    ):
        self.host = host
        self.port = port
        self.max_workers = max_workers
        self.token_issuer = token_issuer or TokenIssuer()
        self.guardrail = guardrail or GuardrailLayer(self.token_issuer)
        self.scheduler = scheduler or TaskScheduler()
        self.anomaly_engine = anomaly_engine or CombinedAnomalyEngine()
        self.behavioral_logger = behavioral_logger or BehavioralLogger()
        self.audit_trail = audit_trail
        self.incident_reporter = incident_reporter
        self.bert_classifier = bert_classifier
        self._server: grpc.aio.Server | None = None
        self._stale_check_task: asyncio.Task | None = None

    async def start(self):
        self._server = grpc.aio.server(
            futures.ThreadPoolExecutor(max_workers=self.max_workers),
            options=[
                ("grpc.max_send_message_length", 100 * 1024 * 1024),
                ("grpc.max_receive_message_length", 100 * 1024 * 1024),
                ("grpc.keepalive_time_ms", 10000),
                ("grpc.keepalive_timeout_ms", 5000),
                ("grpc.http2.max_pings_without_data", 0),
            ],
        )

        servicer = AgentMeshServicer(
            token_issuer=self.token_issuer,
            guardrail=self.guardrail,
            scheduler=self.scheduler,
            anomaly_engine=self.anomaly_engine,
            behavioral_logger=self.behavioral_logger,
            audit_trail=self.audit_trail,
            incident_reporter=self.incident_reporter,
            bert_classifier=self.bert_classifier,
        )

        mesh_pb2_grpc.add_AgentMeshServicer_to_server(servicer, self._server)
        listen_addr = f"{self.host}:{self.port}"
        self._server.add_insecure_port(listen_addr)

        logger.info("Starting orchestrator on %s", listen_addr)
        await self._server.start()
        self._stale_check_task = asyncio.create_task(self._stale_agent_check())

    async def stop(self, grace: float = 5.0):
        logger.info("Shutting down orchestrator...")
        if self._stale_check_task:
            self._stale_check_task.cancel()
        if self._server:
            await self._server.stop(grace)

    async def wait_for_termination(self):
        if self._server:
            await self._server.wait_for_termination()

    async def _stale_agent_check(self):
        while True:
            try:
                await asyncio.sleep(10)
                await self.scheduler.mark_offline_stale()
            except asyncio.CancelledError:
                break
