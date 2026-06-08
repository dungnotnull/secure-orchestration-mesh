"""
Isolation Forest anomaly detection for agent communication patterns.

Scaffold implementation — model training is deferred to Phase 2.
Provides a stub scorer that returns placeholder scores for Phase 0/MVP testing.
"""

from __future__ import annotations

import os
import logging
import pickle
from typing import Optional, List
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class AnomalyScoreResult:
    score: float  # 0.0 = normal, 1.0 = maximally anomalous
    threshold: float
    level: str  # "NORMAL", "SUSPICIOUS", "CRITICAL"
    detector_name: str = "isolation_forest"


class IsolationForestScorer:
    """
    Real-time anomaly scorer using Isolation Forest.

    In Phase 0/MVP, provides a stub implementation that returns normal scores.
    Phase 2: train on synthetic log data and replace the stub.
    """

    def __init__(
        self,
        model_path: str = "models/isolation_forest.pkl",
        suspicious_threshold: float = 0.65,
        critical_threshold: float = 0.85,
        contamination: float = 0.01,
        n_estimators: int = 100,
    ):
        self.model_path = model_path
        self.suspicious_threshold = suspicious_threshold
        self.critical_threshold = critical_threshold
        self.contamination = contamination
        self.n_estimators = n_estimators
        self._model = None
        self._n_features = 5  # [freq, avg_payload, avg_latency, error_rate, payload_var]

    def is_loaded(self) -> bool:
        return self._model is not None

    def load_model(self):
        """Load a trained Isolation Forest model from disk."""
        if os.path.exists(self.model_path):
            with open(self.model_path, "rb") as f:
                self._model = pickle.load(f)
            logger.info("Isolation Forest model loaded from %s", self.model_path)
        else:
            logger.warning(
                "No Isolation Forest model found at %s — using stub scorer. "
                "Train a model with scripts/synthetic_log_generator.py in Phase 2.",
                self.model_path,
            )

    def score(self, agent_id: str, features: Optional[List[float]] = None) -> float:
        """
        Score a feature vector for anomaly likelihood.
        Returns a value in [0.0, 1.0] where higher means more anomalous.

        Stub behavior: returns ~0.1 (normal) with slight random noise
        to simulate realistic scoring until a trained model is loaded.
        """
        if self._model is not None and features is not None:
            arr = np.array(features).reshape(1, -1)
            if arr.shape[1] == self._n_features:
                raw = self._model.decision_function(arr)[0]
                normalized = float(np.clip(1.0 - (raw + 0.5), 0.0, 1.0))
                return normalized

        # Stub: simulate normal behavior with mild noise
        return float(np.clip(np.random.normal(0.08, 0.03), 0.0, 0.5))

    def score_batch(
        self, agent_ids: List[str], feature_batch: Optional[List[List[float]]] = None
    ) -> List[float]:
        """Score multiple agents at once."""
        if feature_batch is None:
            return [self.score(aid) for aid in agent_ids]
        return [self.score(aid, feats) for aid, feats in zip(agent_ids, feature_batch)]

    def classify(self, score: float) -> str:
        """Map a numeric score to anomaly level."""
        if score >= self.critical_threshold:
            return "CRITICAL"
        if score >= self.suspicious_threshold:
            return "SUSPICIOUS"
        return "NORMAL"

    def train_from_logs(self, log_data_path: str, output_path: Optional[str] = None):
        """
        Train an Isolation Forest model from behavioral log data.
        This is a placeholder — full implementation in Phase 2.
        """
        try:
            from sklearn.ensemble import IsolationForest

            # Load training data
            data = np.loadtxt(log_data_path, delimiter=",")
            if data.ndim == 1:
                data = data.reshape(-1, 1)
            if data.shape[1] != self._n_features:
                logger.error(
                    "Expected %d features, got %d", self._n_features, data.shape[1]
                )
                return

            model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1,
            )
            model.fit(data)
            self._model = model

            save_path = output_path or self.model_path
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with open(save_path, "wb") as f:
                pickle.dump(model, f)

            logger.info(
                "Isolation Forest trained on %d samples, saved to %s",
                len(data),
                save_path,
            )
        except ImportError:
            logger.error("scikit-learn not available — cannot train Isolation Forest")
        except Exception as e:
            logger.error("Training failed: %s", e)
