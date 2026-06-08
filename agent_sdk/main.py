"""
Worker Agent main entry point.

Usage:
    python -m agent_sdk.main
"""

from __future__ import annotations

import asyncio
import argparse
import logging
import os
import signal
import sys

from agent_sdk.client import MeshAgent, AgentConfig

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("agent_sdk.main")


async def run_agent(config: AgentConfig):
    agent = MeshAgent(config)

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

    run_task = asyncio.create_task(agent.run())
    await stop_event.wait()
    run_task.cancel()
    await agent.disconnect()
    logger.info("Agent shut down")


def main():
    parser = argparse.ArgumentParser(description="Secure Orchestration Mesh — Worker Agent")
    parser.add_argument("--orchestrator", default="localhost:50051", help="Orchestrator address")
    parser.add_argument("--label", default="worker-agent-01", help="Agent label")
    parser.add_argument("--caps", default="web_search,file_read", help="Comma-separated capabilities")
    parser.add_argument("--heartbeat", type=float, default=5.0, help="Heartbeat interval in seconds")

    args = parser.parse_args()

    config = AgentConfig(
        agent_label=args.label,
        capabilities=[c.strip() for c in args.caps.split(",")],
        orchestrator_address=args.orchestrator,
        heartbeat_interval=args.heartbeat,
    )

    asyncio.run(run_agent(config))


if __name__ == "__main__":
    main()
