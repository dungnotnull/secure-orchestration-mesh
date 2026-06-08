"""
LSTM Autoencoder for temporal anomaly detection on agent behavior sequences.

Phase 2 implementation — scaffold only in Phase 0.
Detects behavioral pattern deviations over time by measuring
reconstruction error on sequences of agent communication events.
"""

from __future__ import annotations

import os
import logging
from typing import Optional, List, Tuple

import numpy as np

logger = logging.getLogger(__name__)


class LSTMAutoencoder:
    """
    LSTM-based autoencoder for temporal anomaly detection.

    Architecture (Phase 2):
        Encoder: 2-layer LSTM (hidden=128) -> bottleneck (32)
        Decoder: bottleneck (32) -> 2-layer LSTM (hidden=128) -> output

    The model is trained on normal-behavior sequences; high reconstruction
    error at inference time indicates anomalous temporal patterns.
    """

    def __init__(
        self,
        model_path: str = "models/lstm_autoencoder.pt",
        sequence_length: int = 50,
        hidden_size: int = 128,
        bottleneck_size: int = 32,
        num_layers: int = 2,
        reconstruction_error_threshold: float = 0.15,
    ):
        self.model_path = model_path
        self.sequence_length = sequence_length
        self.hidden_size = hidden_size
        self.bottleneck_size = bottleneck_size
        self.num_layers = num_layers
        self.reconstruction_error_threshold = reconstruction_error_threshold
        self._model: Optional["torch.nn.Module"] = None  # noqa: F821
        self._device: str = "cpu"

    def is_loaded(self) -> bool:
        return self._model is not None

    def load_model(self):
        """Load a trained LSTM Autoencoder model from disk. Phase 2."""
        try:
            import torch

            if os.path.exists(self.model_path):
                self._model = self._build_model()
                self._model.load_state_dict(
                    torch.load(self.model_path, map_location=self._device, weights_only=True)
                )
                self._model.eval()
                logger.info("LSTM Autoencoder loaded from %s", self.model_path)
            else:
                logger.info(
                    "No LSTM Autoencoder model at %s — will be trained in Phase 2",
                    self.model_path,
                )
        except ImportError:
            logger.warning("PyTorch not available — LSTM Autoencoder disabled")
        except Exception as e:
            logger.error("Failed to load LSTM Autoencoder: %s", e)

    def score(self, sequence: np.ndarray) -> float:
        """
        Compute reconstruction error for a sequence.
        High error = anomalous.

        Stub: returns ~0.05 (normal) with slight noise until model is trained.
        """
        if self._model is not None:
            return self._compute_reconstruction_error(sequence)

        return float(np.clip(np.random.normal(0.04, 0.02), 0.0, 0.3))

    def is_anomalous(self, score: float) -> bool:
        return score > self.reconstruction_error_threshold

    def _build_model(self):
        """Build the LSTM Autoencoder architecture. Phase 2."""
        try:
            import torch
            import torch.nn as nn

            class LSTMAutoencoderModel(nn.Module):
                def __init__(
                    self,
                    input_size: int,
                    hidden_size: int,
                    bottleneck_size: int,
                    num_layers: int,
                ):
                    super().__init__()
                    self.encoder_lstm = nn.LSTM(
                        input_size=input_size,
                        hidden_size=hidden_size,
                        num_layers=num_layers,
                        batch_first=True,
                    )
                    self.encoder_fc = nn.Linear(hidden_size, bottleneck_size)
                    self.decoder_fc = nn.Linear(bottleneck_size, hidden_size)
                    self.decoder_lstm = nn.LSTM(
                        input_size=hidden_size,
                        hidden_size=hidden_size,
                        num_layers=num_layers,
                        batch_first=True,
                    )
                    self.output_fc = nn.Linear(hidden_size, input_size)

                def forward(self, x):
                    enc_out, _ = self.encoder_lstm(x)
                    bottleneck = self.encoder_fc(enc_out[:, -1, :])
                    dec_input = self.decoder_fc(bottleneck).unsqueeze(1).repeat(
                        1, x.size(1), 1
                    )
                    dec_out, _ = self.decoder_lstm(dec_input)
                    return self.output_fc(dec_out)

            return LSTMAutoencoderModel(
                input_size=self._n_features,
                hidden_size=self.hidden_size,
                bottleneck_size=self.bottleneck_size,
                num_layers=self.num_layers,
            )
        except ImportError:
            return None

    def _compute_reconstruction_error(self, sequence: np.ndarray) -> float:
        try:
            import torch

            tensor = torch.tensor(sequence, dtype=torch.float32).unsqueeze(0)
            with torch.no_grad():
                reconstructed = self._model(tensor.to(self._device))
            error = torch.mean((tensor.to(self._device) - reconstructed) ** 2).item()
            return float(error)
        except Exception as e:
            logger.error("Reconstruction error computation failed: %s", e)
            return 1.0

    def train(self, normal_sequences: np.ndarray, epochs: int = 50, batch_size: int = 32):
        """
        Train the LSTM Autoencoder on normal-behavior sequences. Phase 2.
        """
        try:
            import torch
            import torch.nn as nn
            from torch.utils.data import DataLoader, TensorDataset

            self._n_features = normal_sequences.shape[2]
            self._model = self._build_model()
            if self._model is None:
                return

            self._model.train()
            optimizer = torch.optim.Adam(self._model.parameters(), lr=1e-3)
            criterion = nn.MSELoss()

            dataset = TensorDataset(
                torch.tensor(normal_sequences, dtype=torch.float32)
            )
            loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

            for epoch in range(epochs):
                total_loss = 0.0
                for (batch,) in loader:
                    optimizer.zero_grad()
                    reconstructed = self._model(batch.to(self._device))
                    loss = criterion(reconstructed, batch.to(self._device))
                    loss.backward()
                    optimizer.step()
                    total_loss += loss.item()

                if (epoch + 1) % 10 == 0:
                    logger.info(
                        "Epoch %d/%d — loss: %.6f",
                        epoch + 1,
                        epochs,
                        total_loss / len(loader),
                    )

            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            torch.save(self._model.state_dict(), self.model_path)
            logger.info("LSTM Autoencoder trained and saved to %s", self.model_path)

        except ImportError:
            logger.error("PyTorch not available — cannot train LSTM Autoencoder")
        except Exception as e:
            logger.error("LSTM Autoencoder training failed: %s", e)
