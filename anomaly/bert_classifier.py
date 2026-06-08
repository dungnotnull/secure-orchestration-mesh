"""
BERT-based semantic log classifier for async post-incident analysis.

Fine-tunes google-bert/bert-base-uncased on labeled synthetic log entries
(NORMAL / SUSPICIOUS / CRITICAL). Runs asynchronously — not on the hot path.
Provides semantic analysis of log entries after an anomaly is detected.
"""

from __future__ import annotations

import logging
import os
import json
from typing import Optional, List, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LogClassificationResult:
    log_entry: str
    predicted_label: str  # NORMAL, SUSPICIOUS, CRITICAL
    confidence: float
    attention_tokens: List[str]


class BERTLogClassifier:
    """
    Semantic analysis of agent log entries for post-incident investigation.

    Runs asynchronously — not on the security-critical hot path.
    Phase 2: full training and integration.
    """

    LABELS = ["NORMAL", "SUSPICIOUS", "CRITICAL"]

    def __init__(
        self,
        model_path: str = "models/bert_log_classifier",
        bert_model_id: str = "google-bert/bert-base-uncased",
        max_length: int = 256,
        batch_size: int = 16,
    ):
        self.model_path = model_path
        self.bert_model_id = bert_model_id
        self.max_length = max_length
        self.batch_size = batch_size
        self._model = None
        self._tokenizer = None
        self._device = "cpu"

    def is_loaded(self) -> bool:
        return self._model is not None

    def load_model(self):
        try:
            import torch
            from transformers import (
                AutoTokenizer,
                AutoModelForSequenceClassification,
            )
            if os.path.exists(self.model_path):
                self._tokenizer = AutoTokenizer.from_pretrained(self.model_path)
                self._model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_path,
                    num_labels=len(self.LABELS),
                )
                self._model.eval()
                logger.info("BERT log classifier loaded from %s", self.model_path)
            else:
                logger.info("No BERT classifier at %s — training needed (Phase 2)", self.model_path)
        except ImportError:
            logger.warning("transformers not available — BERT classifier disabled")
        except Exception as e:
            logger.error("Failed to load BERT classifier: %s", e)

    async def classify(self, log_entries: List[str]) -> List[LogClassificationResult]:
        if not self.is_loaded():
            return [
                LogClassificationResult(
                    log_entry=entry,
                    predicted_label="NORMAL",
                    confidence=0.5,
                    attention_tokens=[],
                )
                for entry in log_entries
            ]

        try:
            import torch

            results = []
            for i in range(0, len(log_entries), self.batch_size):
                batch = log_entries[i:i + self.batch_size]
                inputs = self._tokenizer(
                    batch,
                    padding=True,
                    truncation=True,
                    max_length=self.max_length,
                    return_tensors="pt",
                ).to(self._device)

                with torch.no_grad():
                    outputs = self._model(**inputs)
                    probs = torch.softmax(outputs.logits, dim=-1)
                    preds = torch.argmax(probs, dim=-1)

                for entry, pred, prob in zip(batch, preds, probs):
                    results.append(LogClassificationResult(
                        log_entry=entry,
                        predicted_label=self.LABELS[pred.item()],
                        confidence=prob[pred].item(),
                        attention_tokens=[],
                    ))

            return results

        except Exception as e:
            logger.error("BERT classification failed: %s", e)
            return []

    def train(
        self,
        texts: List[str],
        labels: List[int],
        val_texts: Optional[List[str]] = None,
        val_labels: Optional[List[int]] = None,
        epochs: int = 3,
        learning_rate: float = 2e-5,
    ):
        try:
            import torch
            from torch.utils.data import Dataset, DataLoader
            from transformers import (
                AutoTokenizer,
                AutoModelForSequenceClassification,
                AdamW,
                get_linear_schedule_with_warmup,
            )

            self._tokenizer = AutoTokenizer.from_pretrained(self.bert_model_id)
            self._model = AutoModelForSequenceClassification.from_pretrained(
                self.bert_model_id,
                num_labels=len(self.LABELS),
            )
            self._model.train()

            class LogDataset(Dataset):
                def __init__(self, texts, labels, tokenizer, max_length):
                    self.encodings = tokenizer(texts, truncation=True, padding=True, max_length=max_length)
                    self.labels = labels

                def __getitem__(self, idx):
                    item = {k: torch.tensor(v[idx]) for k, v in self.encodings.items()}
                    item["labels"] = torch.tensor(self.labels[idx])
                    return item

                def __len__(self):
                    return len(self.labels)

            dataset = LogDataset(texts, labels, self._tokenizer, self.max_length)
            loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)

            optimizer = AdamW(self._model.parameters(), lr=learning_rate)
            total_steps = len(loader) * epochs
            scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=total_steps // 10, num_training_steps=total_steps)

            for epoch in range(epochs):
                total_loss = 0.0
                for batch in loader:
                    optimizer.zero_grad()
                    outputs = self._model(**{k: v.to(self._device) for k, v in batch.items()})
                    loss = outputs.loss
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(self._model.parameters(), 1.0)
                    optimizer.step()
                    scheduler.step()
                    total_loss += loss.item()

                logger.info("Epoch %d/%d — loss: %.4f", epoch + 1, epochs, total_loss / len(loader))

            os.makedirs(self.model_path, exist_ok=True)
            self._model.save_pretrained(self.model_path)
            self._tokenizer.save_pretrained(self.model_path)
            logger.info("BERT classifier trained and saved to %s", self.model_path)

        except ImportError as e:
            logger.error("Required package not available: %s", e)
        except Exception as e:
            logger.error("BERT training failed: %s", e)

    def generate_synthetic_labels(self, log_entries: List[str]) -> List[int]:
        labels = []
        for entry in log_entries:
            entry_lower = entry.lower()
            if any(kw in entry_lower for kw in ["permission denied", "auth failed", "quarantin", "injection", "oversized", "anomal", "attack"]):
                if any(kw in entry_lower for kw in ["quarantin", "injection", "attack"]):
                    labels.append(2)
                else:
                    labels.append(1)
            else:
                labels.append(0)
        return labels
