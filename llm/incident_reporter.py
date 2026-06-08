"""
Automated security incident report generator using Claude / GPT-4o / Ollama.

Takes a quarantine event + behavioral log entries and produces:
1. Structured JSON report (machine-readable)
2. Human-readable Markdown summary with remediation recommendations

Supports prompt caching on Claude for repeated report structures.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from llm.backend import LLMProvider, LLMBackend
from anomaly.behavioral_logger import BehavioralLogger, MetricEntry

logger = logging.getLogger(__name__)


CACHE_DIR = "reports/cache"
CACHE_TTL_SECONDS = 86400

REPORT_SYSTEM_PROMPT = """You are a senior security incident analyst for a zero-trust multi-agent AI orchestration system.
Your task is to analyze a quarantine event and produce an incident report.

RULES:
1. Output ONLY valid JSON. No explanatory text, no preamble, no markdown fences.
2. Identify the most likely attack type from the behavioral data.
3. Provide specific, actionable remediation steps.
4. Assign a severity score (1-10) based on attack sophistication and impact.
5. Include a timeline of the key events leading to quarantine.

OUTPUT SCHEMA:
{
  "report_id": "<uuid>",
  "timestamp": "<ISO-8601>",
  "severity_score": <integer 1-10>,
  "attack_type": "<classified attack type>",
  "attack_confidence": <float 0.0-1.0>,
  "affected_agent_id": "<agent id>",
  "quarantine_reason": "<reason from quarantine event>",
  "timeline": [
    {"time": "<ISO-8601>", "event": "<description>"}
  ],
  "anomaly_scores": [
    {"detector": "<name>", "score": <float>, "threshold": <float>}
  ],
  "behavioral_summary": {
    "total_entries_analyzed": <integer>,
    "avg_payload_bytes": <float>,
    "avg_latency_us": <float>,
    "error_rate": <float>,
    "unusual_patterns": ["<pattern1>", "<pattern2>"]
  },
  "recommended_actions": ["<action1>", "<action2>"],
  "false_positive_likelihood": <float 0.0-1.0>
}
"""


@dataclass
class IncidentReport:
    report_id: str
    timestamp: str
    severity_score: int
    attack_type: str
    attack_confidence: float
    affected_agent_id: str
    quarantine_reason: str
    timeline: List[Dict[str, str]]
    anomaly_scores: List[Dict[str, float]]
    behavioral_summary: Dict[str, Any]
    recommended_actions: List[str]
    false_positive_likelihood: float
    raw_markdown: str = ""

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "severity_score": self.severity_score,
            "attack_type": self.attack_type,
            "attack_confidence": self.attack_confidence,
            "affected_agent_id": self.affected_agent_id,
            "quarantine_reason": self.quarantine_reason,
            "timeline": self.timeline,
            "anomaly_scores": self.anomaly_scores,
            "behavioral_summary": self.behavioral_summary,
            "recommended_actions": self.recommended_actions,
            "false_positive_likelihood": self.false_positive_likelihood,
        }

    def to_markdown(self) -> str:
        if self.raw_markdown:
            return self.raw_markdown
        return self._build_markdown()

    def _build_markdown(self) -> str:
        lines = [
            f"# Security Incident Report — {self.report_id}",
            "",
            f"**Timestamp**: {self.timestamp}",
            f"**Severity**: {self.severity_score}/10",
            f"**Attack Type**: {self.attack_type} (confidence: {self.attack_confidence:.2f})",
            f"**Affected Agent**: `{self.affected_agent_id}`",
            f"**Quarantine Reason**: {self.quarantine_reason}",
            "",
            "## Timeline",
        ]
        for entry in self.timeline:
            lines.append(f"- **{entry['time']}**: {entry['event']}")
        lines.append("")
        lines.append("## Anomaly Scores")
        for score in self.anomaly_scores:
            lines.append(f"- **{score['detector']}**: {score['score']:.4f} (threshold: {score['threshold']:.4f})")
        lines.append("")
        lines.append("## Behavioral Summary")
        bs = self.behavioral_summary
        lines.append(f"- Entries analyzed: {bs.get('total_entries_analyzed', 0)}")
        lines.append(f"- Avg payload: {bs.get('avg_payload_bytes', 0):.0f} bytes")
        lines.append(f"- Avg latency: {bs.get('avg_latency_us', 0):.0f} μs")
        lines.append(f"- Error rate: {bs.get('error_rate', 0):.2%}")
        if bs.get("unusual_patterns"):
            lines.append("- Unusual patterns:")
            for pattern in bs["unusual_patterns"]:
                lines.append(f"  - {pattern}")
        lines.append("")
        lines.append("## Recommended Actions")
        for i, action in enumerate(self.recommended_actions, 1):
            lines.append(f"{i}. {action}")
        lines.append("")
        lines.append(f"**False positive likelihood**: {self.false_positive_likelihood:.2%}")
        return "\n".join(lines)


class IncidentReportGenerator:
    """Generates security incident reports using configured LLM backend."""

    def __init__(
        self,
        llm_provider: LLMProvider,
        behavioral_logger: Optional[BehavioralLogger] = None,
        reports_dir: str = "reports",
    ):
        self._llm = llm_provider
        self._behavioral_logger = behavioral_logger
        self.reports_dir = reports_dir
        self._prompt_cache: Dict[str, tuple] = {}
        os.makedirs(reports_dir, exist_ok=True)
        os.makedirs(CACHE_DIR, exist_ok=True)

    async def generate(
        self,
        quarantine_event: dict,
        behavioral_entries: Optional[List[Dict[str, Any]]] = None,
    ) -> IncidentReport:
        agent_id = quarantine_event.get("agent_id", "unknown")
        reason = quarantine_event.get("reason", "unknown")
        scores = quarantine_event.get("scores", [])

        if behavioral_entries is None and self._behavioral_logger is not None:
            behavioral_entries = await self._behavioral_logger.get_recent_metrics(agent_id, limit=50)

        if behavioral_entries is None:
            behavioral_entries = []

        prompt = self._build_prompt(agent_id, reason, scores, behavioral_entries)

        cache_key = hashlib.sha256(prompt.encode()).hexdigest()
        if cache_key in self._prompt_cache:
            cached_time, cached_response = self._prompt_cache[cache_key]
            if time.time() - cached_time < CACHE_TTL_SECONDS:
                logger.info("Using cached incident report for %s", agent_id)
                return self._parse_response(cached_response, agent_id, reason, scores, behavioral_entries)

        try:
            response = await self._llm.generate(
                prompt=prompt,
                system_prompt=REPORT_SYSTEM_PROMPT,
                max_tokens=2048,
                temperature=0.2,
                json_mode=False,
            )
            self._prompt_cache[cache_key] = (time.time(), response.text)
            return self._parse_response(response.text, agent_id, reason, scores, behavioral_entries)
        except Exception as e:
            logger.error("LLM incident report generation failed: %s", e)
            return self._fallback_report(agent_id, reason, scores, behavioral_entries)

    def _build_prompt(
        self,
        agent_id: str,
        reason: str,
        scores: list,
        entries: list,
    ) -> str:
        entry_summaries = []
        for e in entries:
            if isinstance(e, dict):
                entry_summaries.append(
                    f"- {e.get('timestamp', '?')} | payload={e.get('payload_bytes', 0)}B | "
                    f"latency={e.get('latency_us', 0):.0f}us | error={e.get('error_code', 'none')}"
                )
            else:
                entry_summaries.append(str(e))

        score_text = "\n".join(
            f"- {s.get('detector_name', 'unknown')}: {s.get('score', 0):.4f} "
            f"(threshold: {s.get('threshold', 0)})"
            for s in scores
        ) if scores else "No anomaly scores available"

        entries_text = "\n".join(entry_summaries[:50]) if entry_summaries else "No behavioral entries available"

        return f"""ANALYZE THIS QUARANTINE EVENT:

Agent ID: {agent_id}
Quarantine Reason: {reason}

ANOMALY SCORES:
{score_text}

BEHAVIORAL LOG (last 50 entries):
{entries_text}

Classify the attack type, assess severity, and recommend remediation actions."""

    def _parse_response(
        self,
        text: str,
        agent_id: str,
        reason: str,
        scores: list,
        entries: list,
    ) -> IncidentReport:
        try:
            text_clean = text.strip()
            if text_clean.startswith("```"):
                lines = text_clean.split("\n")
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip().startswith("```"):
                    lines = lines[:-1]
                text_clean = "\n".join(lines)
            data = json.loads(text_clean)
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM JSON, using fallback report structure")
            return self._fallback_report(agent_id, reason, scores, entries)

        import uuid

        return IncidentReport(
            report_id=data.get("report_id", str(uuid.uuid4())),
            timestamp=data.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
            severity_score=int(data.get("severity_score", 5)),
            attack_type=data.get("attack_type", "unknown"),
            attack_confidence=float(data.get("attack_confidence", 0.5)),
            affected_agent_id=data.get("affected_agent_id", agent_id),
            quarantine_reason=data.get("quarantine_reason", reason),
            timeline=data.get("timeline", []),
            anomaly_scores=data.get("anomaly_scores", scores),
            behavioral_summary=data.get("behavioral_summary", {
                "total_entries_analyzed": len(entries),
                "avg_payload_bytes": 0,
                "avg_latency_us": 0,
                "error_rate": 0,
                "unusual_patterns": [],
            }),
            recommended_actions=data.get("recommended_actions", ["Review agent activity manually"]),
            false_positive_likelihood=float(data.get("false_positive_likelihood", 0.3)),
        )

    def _fallback_report(
        self,
        agent_id: str,
        reason: str,
        scores: list,
        entries: list,
    ) -> IncidentReport:
        total = len(entries)
        avg_payload = sum(e.get("payload_bytes", 0) for e in entries) / max(total, 1) if entries else 0
        avg_latency = sum(e.get("latency_us", 0) for e in entries) / max(total, 1) if entries else 0
        error_count = sum(1 for e in entries if e.get("error_code", "")) if entries else 0
        error_rate = error_count / max(total, 1)

        import uuid

        return IncidentReport(
            report_id=str(uuid.uuid4()),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            severity_score=5,
            attack_type="unclassified",
            attack_confidence=0.5,
            affected_agent_id=agent_id,
            quarantine_reason=reason,
            timeline=[{"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": f"Agent quarantined: {reason}"}],
            anomaly_scores=scores,
            behavioral_summary={
                "total_entries_analyzed": total,
                "avg_payload_bytes": avg_payload,
                "avg_latency_us": avg_latency,
                "error_rate": error_rate,
                "unusual_patterns": [],
            },
            recommended_actions=["Review agent activity", "Check for false positive", "Inspect recent task results"],
            false_positive_likelihood=0.3,
        )

    async def save(self, report: IncidentReport):
        json_path = os.path.join(self.reports_dir, f"{report.report_id}.json")
        md_path = os.path.join(self.reports_dir, f"{report.report_id}.md")
        with open(json_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        with open(md_path, "w") as f:
            f.write(report.to_markdown())
        logger.info("Incident report saved: %s", report.report_id)


class PromptCacheManager:
    """Manages Claude API prompt caching for repeated incident report templates."""

    def __init__(self, cache_dir: str = CACHE_DIR):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    def get_cached_template(self, template_key: str) -> Optional[str]:
        cache_path = os.path.join(self.cache_dir, f"{template_key}.json")
        if os.path.exists(cache_path):
            with open(cache_path) as f:
                data = json.load(f)
            if time.time() - data.get("cached_at", 0) < CACHE_TTL_SECONDS:
                return data.get("template")
        return None

    def cache_template(self, template_key: str, template: str):
        cache_path = os.path.join(self.cache_dir, f"{template_key}.json")
        with open(cache_path, "w") as f:
            json.dump({"template": template, "cached_at": time.time()}, f)

    def invalidate(self, template_key: str):
        cache_path = os.path.join(self.cache_dir, f"{template_key}.json")
        if os.path.exists(cache_path):
            os.remove(cache_path)
