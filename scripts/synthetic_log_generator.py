"""
Synthetic behavioral log generator for training anomaly detection models.

Generates realistic agent communication patterns with configurable
normal and anomalous behavior profiles. Produces CSV output that can
be used to train the Isolation Forest and LSTM Autoencoder models.

Phase 0: Generates the 10,000 synthetic log sequences needed to verify
the data generation pipeline is working.
Phase 2: Used to train actual ML models.
"""

from __future__ import annotations

import csv
import os
import time
import uuid
import random
import argparse
from dataclasses import dataclass, field
from typing import List, Optional, Iterator

import numpy as np


@dataclass
class LogEntry:
    agent_id: str
    task_id: str
    timestamp: str
    payload_bytes: int
    latency_us: float
    error_code: str
    task_type: str
    anomaly_score: float


class SyntheticLogGenerator:
    """
    Generates synthetic agent communication logs for anomaly detection training.

    Normal behavior profile:
      - Payload: ~10KB avg, normal distribution
      - Latency: ~2ms avg, log-normal distribution
      - Error rate: < 1%
      - Task types: evenly distributed among common actions

    Anomalous behavior profile (injected at configurable rate):
      - Oversized payloads (50KB–10MB)
      - High latency (100ms–5s)
      - High error rate (> 20%)
      - Unusual task type patterns
    """

    TASK_TYPES = [
        "web_search", "file_read", "file_write",
        "code_execution", "api_call", "data_analysis",
    ]

    ERROR_CODES = [
        "",  # No error
        "TIMEOUT",
        "PERMISSION_DENIED",
        "RESOURCE_NOT_FOUND",
        "RATE_LIMITED",
        "INTERNAL_ERROR",
    ]

    def __init__(
        self,
        num_agents: int = 100,
        entries_per_agent: int = 100,
        anomaly_ratio: float = 0.01,
        seed: int = 42,
    ):
        self.num_agents = num_agents
        self.entries_per_agent = entries_per_agent
        self.anomaly_ratio = anomaly_ratio
        self.seed = seed

        self.rng = np.random.RandomState(seed)
        random.seed(seed)

    def generate(self) -> List[LogEntry]:
        """Generate the full synthetic log dataset."""
        entries: List[LogEntry] = []

        agent_ids = [str(uuid.uuid4()) for _ in range(self.num_agents)]

        for agent_id in agent_ids:
            # Each agent has a slightly different normal profile
            base_payload = self.rng.normal(10240, 2048)  # ~10KB
            base_latency = self.rng.lognormal(7.6, 0.3)  # ~2ms

            for i in range(self.entries_per_agent):
                is_anomalous = random.random() < self.anomaly_ratio

                entry = self._generate_entry(
                    agent_id=agent_id,
                    base_payload=base_payload,
                    base_latency=base_latency,
                    is_anomalous=is_anomalous,
                    entry_index=i,
                )
                entries.append(entry)

        # Sort by timestamp
        entries.sort(key=lambda e: e.timestamp)
        return entries

    def _generate_entry(
        self,
        agent_id: str,
        base_payload: float,
        base_latency: float,
        is_anomalous: bool,
        entry_index: int,
    ) -> LogEntry:
        if is_anomalous:
            # Anomalous: oversized payload or extreme latency or high errors
            anomaly_type = random.choice(["payload", "latency", "error", "combined"])

            if anomaly_type == "payload":
                payload_bytes = int(self.rng.uniform(50000, 10_000_000))
                latency_us = float(self.rng.lognormal(7.6, 0.3))
                error_code = ""
            elif anomaly_type == "latency":
                payload_bytes = int(abs(self.rng.normal(base_payload, 2048)))
                latency_us = float(self.rng.uniform(100000, 5_000_000))
                error_code = ""
            elif anomaly_type == "error":
                payload_bytes = int(abs(self.rng.normal(base_payload, 2048)))
                latency_us = float(self.rng.lognormal(7.6, 0.3))
                error_code = random.choice(self.ERROR_CODES[1:])  # Non-empty error
            else:  # combined
                payload_bytes = int(self.rng.uniform(50000, 5_000_000))
                latency_us = float(self.rng.uniform(100000, 3_000_000))
                error_code = random.choice(self.ERROR_CODES[1:])
        else:
            # Normal behavior
            payload_bytes = int(abs(self.rng.normal(base_payload, 2048)))
            latency_us = float(abs(self.rng.lognormal(7.6, 0.3)))
            error_code = "" if random.random() > 0.005 else random.choice(self.ERROR_CODES[1:])

        timestamp = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - (self.entries_per_agent - entry_index) * 5),
        )

        return LogEntry(
            agent_id=agent_id,
            task_id=str(uuid.uuid4()),
            timestamp=timestamp,
            payload_bytes=payload_bytes,
            latency_us=latency_us,
            error_code=error_code,
            task_type=random.choice(self.TASK_TYPES),
            anomaly_score=1.0 if is_anomalous else self.rng.uniform(0.0, 0.15),
        )

    def to_csv(self, entries: List[LogEntry], output_path: str):
        """Write generated entries to CSV."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "agent_id", "task_id", "timestamp", "payload_bytes",
                "latency_us", "error_code", "task_type", "anomaly_score",
            ])
            for entry in entries:
                writer.writerow([
                    entry.agent_id, entry.task_id, entry.timestamp,
                    entry.payload_bytes, f"{entry.latency_us:.2f}",
                    entry.error_code, entry.task_type, f"{entry.anomaly_score:.4f}",
                ])
        print(f"Generated {len(entries)} entries -> {output_path}")

    def to_feature_matrix(self, entries: List[LogEntry]) -> np.ndarray:
        """
        Convert log entries to a feature matrix suitable for Isolation Forest training.

        Features per agent per window:
          [message_frequency, avg_payload_size, avg_latency, error_rate, payload_variance]
        """
        features = []
        for entry in entries:
            features.append([
                1.0,
                float(entry.payload_bytes),
                entry.latency_us,
                1.0 if entry.error_code else 0.0,
                float(entry.payload_bytes) ** 0.5,  # proxy for variance
            ])
        return np.array(features, dtype=np.float32)


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic agent communication logs for anomaly detection training."
    )
    parser.add_argument(
        "--num-agents", type=int, default=100,
        help="Number of simulated agents (default: 100)"
    )
    parser.add_argument(
        "--entries-per-agent", type=int, default=100,
        help="Entries per agent (default: 100, total = agents * entries_per_agent)"
    )
    parser.add_argument(
        "--anomaly-ratio", type=float, default=0.01,
        help="Fraction of entries that should exhibit anomalous behavior (default: 0.01)"
    )
    parser.add_argument(
        "--output", type=str, default="data/synthetic_logs.csv",
        help="Output CSV path (default: data/synthetic_logs.csv)"
    )
    parser.add_argument(
        "--features-output", type=str, default="data/synthetic_features.csv",
        help="Output feature matrix CSV path (default: data/synthetic_features.csv)"
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42)"
    )

    args = parser.parse_args()

    generator = SyntheticLogGenerator(
        num_agents=args.num_agents,
        entries_per_agent=args.entries_per_agent,
        anomaly_ratio=args.anomaly_ratio,
        seed=args.seed,
    )

    total = args.num_agents * args.entries_per_agent
    print(f"Generating {total} synthetic log entries "
          f"({args.num_agents} agents × {args.entries_per_agent} entries, "
          f"{args.anomaly_ratio*100:.1f}% anomalous)...")

    entries = generator.generate()

    # Write CSV log
    generator.to_csv(entries, args.output)

    # Write feature matrix
    features = generator.to_feature_matrix(entries)
    os.makedirs(os.path.dirname(args.features_output) or ".", exist_ok=True)
    np.savetxt(args.features_output, features, delimiter=",", fmt="%.4f")
    print(f"Feature matrix ({features.shape[0]} x {features.shape[1]}) -> {args.features_output}")

    # Statistics
    anomalous = sum(1 for e in entries if e.anomaly_score > 0.5)
    print(f"\nStatistics:")
    print(f"  Total entries:     {len(entries)}")
    print(f"  Normal entries:    {len(entries) - anomalous}")
    print(f"  Anomalous entries: {anomalous}")
    print(f"  Unique agents:     {len(set(e.agent_id for e in entries))}")


if __name__ == "__main__":
    main()

