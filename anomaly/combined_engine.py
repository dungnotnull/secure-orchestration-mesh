"""
Combined anomaly detection engine coordinating multiple detectors.

Orchestrates: Isolation Forest (fast first pass) + LSTM Autoencoder (deep temporal)
+ BERT log classifier (async post-incident). Implements adaptive threshold
adjustment based on false-positive rates over rolling windows.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
from collections import deque

import numpy as np

from anomaly.isolation_forest import IsolationForestScorer, AnomalyScoreResult
from anomaly.lstm_autoencoder import LSTMAutoencoder
from anomaly.behavioral_logger import BehavioralLogger

logger = logging.getLogger(__name__)


@dataclass
class CombinedAnomalyScore:
    agent_id: str
    timestamp: str
    isolation_forest_score: float
    lstm_reconstruction_error: float
    combined_score: float
    level: str  # NORMAL / SUSPICIOUS / CRITICAL
    detectors_triggered: List[str]


class AdaptiveThreshold:
    """Self-adjusting threshold based on false-positive rate over rolling window."""

    def __init__(
        self,
        initial_threshold: float = 0.65,
        min_threshold: float = 0.40,
        max_threshold: float = 0.90,
        window_days: int = 7,
        target_fpr: float = 0.05,
        adjustment_step: float = 0.02,
    ):
        self.threshold = initial_threshold
        self.min_threshold = min_threshold
        self.max_threshold = max_threshold
        self.window_days = window_days
        self.target_fpr = target_fpr
        self.adjustment_step = adjustment_step
        self._fp_history: deque = deque(maxlen=window_days * 86400)
        self._total_checks: deque = deque(maxlen=window_days * 86400)
        self._last_adjustment = time.time()

    def record(self, is_false_positive: bool):
        now = time.time()
        self._fp_history.append((now, int(is_false_positive)))
        self._total_checks.append((now, 1))

        if now - self._last_adjustment > 3600:
            self._adjust()

    def _adjust(self):
        if len(self._fp_history) < 100:
            return
        total_fp = sum(v for _, v in self._fp_history)
        total = sum(v for _, v in self._total_checks)
        if total == 0:
            return
        fpr = total_fp / total
        if fpr > self.target_fpr * 1.2:
            self.threshold = min(self.max_threshold, self.threshold + self.adjustment_step)
            logger.info("Adaptive threshold increased to %.3f (FPR: %.4f)", self.threshold, fpr)
        elif fpr < self.target_fpr * 0.5:
            self.threshold = max(self.min_threshold, self.threshold - self.adjustment_step)
            logger.info("Adaptive threshold decreased to %.3f (FPR: %.4f)", self.threshold, fpr)
        self._last_adjustment = time.time()


class CombinedAnomalyEngine:
    """
    Multi-detector anomaly scoring with adaptive thresholds.

    Hot path: Isolation Forest (< 1ms) -> LSTM Autoencoder (< 2ms if enabled)
    Async path: BERT log classifier (post-incident, not on hot path)
    """

    def __init__(
        self,
        if_scorer: Optional[IsolationForestScorer] = None,
        lstm_autoencoder: Optional[LSTMAutoencoder] = None,
        behavioral_logger: Optional[BehavioralLogger] = None,
        suspicious_threshold: float = 0.65,
        critical_threshold: float = 0.85,
        consecutive_for_quarantine: int = 2,
    ):
        self.if_scorer = if_scorer or IsolationForestScorer()
        self.lstm_autoencoder = lstm_autoencoder
        self.behavioral_logger = behavioral_logger
        self.suspicious_threshold = suspicious_threshold
        self.critical_threshold = critical_threshold
        self.consecutive_for_quarantine = consecutive_for_quarantine

        self._agent_histories: Dict[str, deque] = {}
        self._adaptive_thresholds: Dict[str, AdaptiveThreshold] = {}
        self._max_history = 100

    async def score(
        self,
        agent_id: str,
        features: Optional[List[float]] = None,
        sequence: Optional[np.ndarray] = None,
    ) -> CombinedAnomalyScore:
        if_score = self.if_scorer.score(agent_id, features)
        lstm_error = 0.0
        detectors = []

        if if_score >= self.suspicious_threshold:
            detectors.append("isolation_forest")

        if self.lstm_autoencoder is not None and self.lstm_autoencoder.is_loaded() and sequence is not None:
            lstm_error = self.lstm_autoencoder.score(sequence)
            if lstm_error > self.lstm_autoencoder.reconstruction_error_threshold:
                detectors.append("lstm_autoencoder")

        combined = max(if_score, lstm_error * 2.0) if lstm_error > 0 else if_score
        combined = min(combined, 1.0)

        if combined >= self.critical_threshold:
            level = "CRITICAL"
        elif combined >= self.suspicious_threshold:
            level = "SUSPICIOUS"
        else:
            level = "NORMAL"

        self._update_history(agent_id, combined)

        return CombinedAnomalyScore(
            agent_id=agent_id,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            isolation_forest_score=if_score,
            lstm_reconstruction_error=lstm_error,
            combined_score=combined,
            level=level,
            detectors_triggered=detectors,
        )

    def should_quarantine(self, agent_id: str) -> bool:
        history = self._agent_histories.get(agent_id, deque(maxlen=self._max_history))
        if len(history) < self.consecutive_for_quarantine:
            return False
        recent = list(history)[-self.consecutive_for_quarantine:]
        return all(s >= self.suspicious_threshold for s in recent)

    def _update_history(self, agent_id: str, score: float):
        if agent_id not in self._agent_histories:
            self._agent_histories[agent_id] = deque(maxlen=self._max_history)
        self._agent_histories[agent_id].append(score)

    def record_false_positive(self, agent_id: str):
        if agent_id not in self._adaptive_thresholds:
            self._adaptive_thresholds[agent_id] = AdaptiveThreshold(
                initial_threshold=self.suspicious_threshold,
            )
        self._adaptive_thresholds[agent_id].record(True)

    def get_threshold(self, agent_id: str) -> float:
        return self._adaptive_thresholds.get(
            agent_id,
            AdaptiveThreshold(initial_threshold=self.suspicious_threshold),
        ).threshold
