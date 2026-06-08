"""
CLI monitoring dashboard for real-time agent status, task tracking, and anomaly scores.

Uses Rich for terminal rendering. Connects to the Orchestrator via its internal
API to display live agent pool state, recent tasks, and alert events.
"""

from __future__ import annotations

import asyncio
import time
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from collections import deque

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.spinner import Spinner
from rich import box

logger = logging.getLogger(__name__)

ANOMALY_COLORS = {
    "NORMAL": "green",
    "SUSPICIOUS": "yellow",
    "CRITICAL": "red",
    "UNKNOWN": "dim",
}

AGENT_STATE_COLORS = {
    "idle": "green",
    "busy": "cyan",
    "quarantined": "red",
    "offline": "dim",
    "registering": "yellow",
}


@dataclass
class DashboardState:
    agents: List[dict] = field(default_factory=list)
    recent_tasks: deque = field(default_factory=lambda: deque(maxlen=20))
    alerts: deque = field(default_factory=lambda: deque(maxlen=50))
    orchestrator_uptime: float = 0.0
    total_tasks: int = 0
    total_failures: int = 0
    avg_latency_us: float = 0.0


class CLIDashboard:
    """Real-time CLI monitoring dashboard built with Rich."""

    def __init__(self, scheduler=None, behavioral_logger=None, anomaly_scorer=None):
        self._scheduler = scheduler
        self._behavioral_logger = behavioral_logger
        self._anomaly_scorer = anomaly_scorer
        self._console = Console()
        self._state = DashboardState()
        self._start_time = time.time()
        self._refresh_interval = 0.5
        self._running = False

    async def start(self):
        self._running = True
        self._start_time = time.time()
        with Live(self._build_layout(), console=self._console, refresh_per_second=4, screen=True) as live:
            while self._running:
                await self._refresh()
                live.update(self._build_layout())
                await asyncio.sleep(self._refresh_interval)

    def stop(self):
        self._running = False

    async def _refresh(self):
        if self._scheduler:
            agents = self._scheduler.get_all_agents()
            self._state.agents = [
                {
                    "id": a.agent_id[:12],
                    "label": a.label,
                    "state": a.state.value,
                    "caps": ", ".join(sorted(a.capabilities)[:3]),
                    "score": a.anomaly_score,
                    "suspicion": a.suspicion_count,
                    "tasks": a.tasks_completed + a.tasks_failed,
                    "heartbeat": f"{time.time() - a.last_heartbeat:.0f}s",
                }
                for a in agents
            ]
            self._state.total_tasks = sum(a.tasks_completed for a in agents)
            self._state.total_failures = sum(a.tasks_failed for a in agents)
        self._state.orchestrator_uptime = time.time() - self._start_time

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="agents", ratio=3),
            Layout(name="side", ratio=2),
        )
        layout["side"].split(
            Layout(name="stats"),
            Layout(name="alerts"),
        )
        layout["header"].update(self._header_panel())
        layout["agents"].update(self._agents_table())
        layout["stats"].update(self._stats_panel())
        layout["alerts"].update(self._alerts_panel())
        layout["footer"].update(self._footer_bar())
        return layout

    def _header_panel(self):
        uptime = f"{self._state.orchestrator_uptime:.0f}s"
        text = Text(f"SECURE ORCHESTRATION MESH  |  Uptime: {uptime}  |  Agents: {len(self._state.agents)}", style="bold white on blue")
        return Panel(text, box=box.SIMPLE)

    def _agents_table(self):
        table = Table(title="Agent Pool", box=box.SIMPLE, expand=True)
        table.add_column("ID", style="dim", width=12)
        table.add_column("Label", width=16)
        table.add_column("State", width=12)
        table.add_column("Capabilities", width=22)
        table.add_column("Score", justify="right", width=7)
        table.add_column("Tasks", justify="right", width=6)
        table.add_column("HB Age", justify="right", width=7)

        for a in self._state.agents:
            state_color = AGENT_STATE_COLORS.get(a["state"], "dim")
            score_color = (
                "red" if a["score"] > 0.85 else
                "yellow" if a["score"] > 0.65 else
                "green"
            )
            table.add_row(
                a["id"],
                a["label"],
                f"[{state_color}]{a['state']}[/{state_color}]",
                a["caps"],
                f"[{score_color}]{a['score']:.3f}[/{score_color}]",
                str(a["tasks"]),
                a["heartbeat"],
            )
        return Panel(table, border_style="blue")

    def _stats_panel(self):
        idle = sum(1 for a in self._state.agents if a["state"] == "idle")
        busy = sum(1 for a in self._state.agents if a["state"] == "busy")
        quarantined = sum(1 for a in self._state.agents if a["state"] == "quarantined")
        offline = sum(1 for a in self._state.agents if a["state"] == "offline")

        text = Text()
        text.append("AGENT STATES\n", style="bold underline")
        text.append(f"  Idle:        [green]{idle}[/green]\n")
        text.append(f"  Busy:        [cyan]{busy}[/cyan]\n")
        text.append(f"  Quarantined: [red]{quarantined}[/red]\n")
        text.append(f"  Offline:     [dim]{offline}[/dim]\n")
        text.append(f"\nTHROUGHPUT\n", style="bold underline")
        text.append(f"  Completed:  [green]{self._state.total_tasks}[/green]\n")
        text.append(f"  Failed:     [red]{self._state.total_failures}[/red]\n")
        return Panel(text, title="Stats", border_style="green")

    def _alerts_panel(self):
        text = Text()
        text.append("RECENT ALERTS\n", style="bold underline")
        if not self._state.alerts:
            text.append("  No alerts", style="dim")
        else:
            for alert in list(self._state.alerts)[-10:]:
                color = ANOMALY_COLORS.get(alert.get("level", "UNKNOWN"), "dim")
                text.append(f"  [{color}]{alert.get('level', '?')}[/{color}] {alert.get('detail', '')}\n")
        return Panel(text, title="Alerts", border_style="yellow")

    def _footer_bar(self):
        return Panel(
            Text("q: quit  |  r: refresh  |  k: quarantine agent  |  h: help", style="dim"),
            box=box.SIMPLE,
        )

    def add_alert(self, level: str, detail: str):
        self._state.alerts.append({
            "level": level,
            "detail": detail,
            "time": time.strftime("%H:%M:%S"),
        })
