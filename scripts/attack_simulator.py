"""
Attack simulation log generator for anomaly detection validation.

Produces realistic attack sequences: oversized payloads, permission boundary
probing, high error rates, replay attack patterns, and timing anomalies.
Used to validate Isolation Forest and LSTM Autoencoder in Phase 2.
"""

from __future__ import annotations

import csv
import os
import time
import uuid
import random
import argparse
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import numpy as np


@dataclass
class AttackEntry:
    agent_id: str
    task_id: str
    timestamp: str
    payload_bytes: int
    latency_us: float
    error_code: str
    task_type: str
    attack_type: str
    is_attack: bool = True


class AttackSimulator:
    """
    Generates 1,000 simulated attack sequences across 10 attack categories.

    Attack types:
    1. oversized_payload: 5MB+ payloads, normal latency
    2. payload_flood: many small payloads very fast (DoS pattern)
    3. permission_probe: trying different task_types rapidly (enumeration)
    4. high_error_rate: >50% errors over sustained window
    5. latency_spike: sudden 100x normal latency
    6. credential_probe: tasks targeting auth/jwt resources
    7. data_exfiltration: large payloads returned after file_read tasks
    8. timing_evasion: anomalous timing patterns to evade thresholds
    9. mixed_anomaly: combination of multiple attack vectors
    10. slow_drip: slow, sustained anomalous activity below single-window thresholds
    """

    ATTACK_TYPES = [
        "oversized_payload",
        "payload_flood",
        "permission_probe",
        "high_error_rate",
        "latency_spike",
        "credential_probe",
        "data_exfiltration",
        "timing_evasion",
        "mixed_anomaly",
        "slow_drip",
    ]

    TASK_TYPES = [
        "web_search", "file_read", "file_write",
        "code_execution", "api_call", "data_analysis",
    ]

    ERROR_CODES = [
        "PERMISSION_DENIED", "RATE_LIMITED", "INTERNAL_ERROR",
        "AUTH_FAILED", "RESOURCE_NOT_FOUND", "TIMEOUT",
    ]

    def __init__(
        self,
        num_attacks: int = 1000,
        attacks_per_type: int = 100,
        seed: int = 42,
    ):
        self.num_attacks = num_attacks
        self.attacks_per_type = attacks_per_type
        self.rng = np.random.RandomState(seed)
        random.seed(seed)

    def generate(self) -> List[AttackEntry]:
        entries: List[AttackEntry] = []
        for attack_type in self.ATTACK_TYPES:
            agent_id = str(uuid.uuid4())
            entries.extend(self._generate_attack_type(agent_id, attack_type))
        return entries

    def _generate_attack_type(self, agent_id: str, attack_type: str) -> List[AttackEntry]:
        entries: List[AttackEntry] = []
        base_time = time.time() - 3600

        if attack_type == "oversized_payload":
            for i in range(self.attacks_per_type):
                payload = int(self.rng.uniform(5_000_000, 50_000_000))
                latency = float(self.rng.uniform(1000, 5000))
                entries.append(self._make_entry(
                    agent_id, attack_type, payload, latency, "", base_time, i, 5
                ))

        elif attack_type == "payload_flood":
            for i in range(self.attacks_per_type):
                payload = int(self.rng.uniform(100, 500))
                latency = float(self.rng.uniform(50, 200))
                entries.append(self._make_entry(
                    agent_id, attack_type, payload, latency, "", base_time, i, 0.1
                ))

        elif attack_type == "permission_probe":
            for i in range(self.attacks_per_type):
                payload = int(self.rng.uniform(1000, 5000))
                latency = float(self.rng.uniform(500, 2000))
                entries.append(self._make_entry(
                    agent_id, attack_type, payload, latency, "PERMISSION_DENIED", base_time, i, 2
                ))

        elif attack_type == "high_error_rate":
            for i in range(self.attacks_per_type):
                payload = int(self.rng.uniform(500, 10000))
                latency = float(self.rng.uniform(200, 1000))
                error = random.choice(self.ERROR_CODES)
                entries.append(self._make_entry(
                    agent_id, attack_type, payload, latency, error, base_time, i, 3
                ))

        elif attack_type == "latency_spike":
            for i in range(self.attacks_per_type):
                payload = int(self.rng.uniform(1000, 10000))
                latency = float(self.rng.uniform(100_000, 5_000_000))
                entries.append(self._make_entry(
                    agent_id, attack_type, payload, latency, "", base_time, i, 3
                ))

        elif attack_type == "credential_probe":
            for i in range(self.attacks_per_type):
                payload = int(self.rng.uniform(200, 2000))
                latency = float(self.rng.uniform(200, 800))
                entries.append(self._make_entry(
                    agent_id, attack_type, payload, latency, "AUTH_FAILED", base_time, i, 1
                ))

        elif attack_type == "data_exfiltration":
            for i in range(self.attacks_per_type):
                payload = int(self.rng.uniform(1_000_000, 20_000_000))
                latency = float(self.rng.uniform(5000, 30000))
                entries.append(self._make_entry(
                    agent_id, attack_type, payload, latency, "", base_time, i, 8
                ))

        elif attack_type == "timing_evasion":
            for i in range(self.attacks_per_type):
                payload = int(self.rng.uniform(5000, 50000))
                latency = float(self.rng.uniform(10000, 50000))
                entries.append(self._make_entry(
                    agent_id, attack_type, payload, latency, "", base_time, i, 15
                ))

        elif attack_type == "mixed_anomaly":
            for i in range(self.attacks_per_type):
                payload = int(self.rng.uniform(500_000, 10_000_000))
                latency = float(self.rng.uniform(50_000, 2_000_000))
                error = random.choice(self.ERROR_CODES) if i % 3 == 0 else ""
                entries.append(self._make_entry(
                    agent_id, attack_type, payload, latency, error, base_time, i, 2
                ))

        elif attack_type == "slow_drip":
            for i in range(self.attacks_per_type):
                payload = int(self.rng.uniform(20000, 100000))
                latency = float(self.rng.uniform(5000, 30000))
                entries.append(self._make_entry(
                    agent_id, attack_type, payload, latency, "", base_time, i, 30
                ))

        return entries

    def _make_entry(
        self,
        agent_id: str,
        attack_type: str,
        payload_bytes: int,
        latency_us: float,
        error_code: str,
        base_time: float,
        index: int,
        interval_seconds: float,
    ) -> AttackEntry:
        ts = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(base_time + index * interval_seconds),
        )
        return AttackEntry(
            agent_id=agent_id,
            task_id=str(uuid.uuid4()),
            timestamp=ts,
            payload_bytes=payload_bytes,
            latency_us=latency_us,
            error_code=error_code,
            task_type=random.choice(self.TASK_TYPES),
            attack_type=attack_type,
            is_attack=True,
        )

    def to_csv(self, entries: List[AttackEntry], output_path: str):
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "agent_id", "task_id", "timestamp", "payload_bytes",
                "latency_us", "error_code", "task_type", "attack_type", "is_attack",
            ])
            for e in entries:
                writer.writerow([
                    e.agent_id, e.task_id, e.timestamp,
                    e.payload_bytes, f"{e.latency_us:.2f}",
                    e.error_code, e.task_type, e.attack_type, str(e.is_attack),
                ])
        print(f"Generated {len(entries)} attack entries -> {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate simulated attack log sequences.")
    parser.add_argument("--num-attacks", type=int, default=1000)
    parser.add_argument("--output", type=str, default="data/attack_logs.csv")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    simulator = AttackSimulator(num_attacks=args.num_attacks, attacks_per_type=args.num_attacks // 10, seed=args.seed)
    entries = simulator.generate()
    simulator.to_csv(entries, args.output)

    by_type = {}
    for e in entries:
        by_type[e.attack_type] = by_type.get(e.attack_type, 0) + 1
    print("\nAttack distribution:")
    for atype, count in sorted(by_type.items()):
        print(f"  {atype}: {count}")


if __name__ == "__main__":
    main()
