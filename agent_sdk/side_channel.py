"""
Side-channel attack resistance via fixed-length message padding.

All Protobuf messages are padded to fixed-length blocks to prevent
traffic analysis from revealing task types or content via packet size patterns.
"""

from __future__ import annotations

import os
import struct
import logging

logger = logging.getLogger(__name__)


class SideChannelPadder:
    """
    Pads messages to fixed block size to resist traffic analysis.

    An attacker observing packet sizes might infer:
    - Which task type is being dispatched (different task types have different payload sizes)
    - Whether results contain large data (data exfiltration via size pattern)
    - Agent capabilities based on typical message sizes

    Fix: every message is padded to the next block boundary with random bytes,
    making all messages within the same block size indistinguishable.
    """

    BLOCK_SIZE = 4096

    def __init__(self, block_size: int = BLOCK_SIZE):
        self.block_size = block_size

    def pad(self, data: bytes) -> bytes:
        if len(data) >= self.block_size:
            blocks = (len(data) // self.block_size) + 1
            target = blocks * self.block_size
        else:
            target = self.block_size

        padding_needed = target - len(data) - 2
        if padding_needed < 0:
            padding_needed += self.block_size
            target += self.block_size

        padding = os.urandom(padding_needed)
        prefix = struct.pack("!H", len(data))
        return prefix + data + padding

    def unpad(self, padded: bytes) -> bytes:
        if len(padded) < 2:
            raise ValueError("Padded message too short for length prefix")
        original_length = struct.unpack("!H", padded[:2])[0]
        if original_length > len(padded) - 2:
            raise ValueError(f"Declared length {original_length} exceeds payload {len(padded) - 2}")
        return padded[2:2 + original_length]
