"""
Four mutation dimensions (from the paper):

  1. Position  — handled in protocol.build_packet() via position_frac
  2. Encoding  — per-packet codec selection (this module)
  3. Chunking  — payload split strategy (this module)
  4. Timing    — inter-query delay (this module)
"""

import random
import time
from typing import List

from .protocol import choose_codec


# ── Dimension 2: Encoding ─────────────────────────────────────────────────────

ENCODING_STRATEGIES = ('weighted', 'hex', 'base32', 'base64')

# Default weights from the paper: hex 60%, base32 30%, base64 10%
_WEIGHTS_DEFAULT = {'hex': 60, 'base32': 30, 'base64': 10}


def select_encoding(strategy: str = 'weighted') -> str:
    """
    Return a codec name for a single packet.

    strategy:
      'weighted' — probabilistic (hex 60%, base32 30%, base64 10%)
      'hex'      — always hex
      'base32'   — always base32
      'base64'   — always base64
    """
    if strategy in ('hex', 'base32', 'base64'):
        return strategy
    return choose_codec(_WEIGHTS_DEFAULT)


# ── Dimension 3: Chunking ─────────────────────────────────────────────────────

CHUNKING_STRATEGIES = ('variable', 'fixed40', 'fixed35', 'fixed16')

_VARIABLE_SIZES = [8, 12, 16, 20, 35, 40]


def chunk_data(data: bytes, strategy: str = 'variable') -> List[bytes]:
    """
    Split data into a list of byte chunks.

    strategy:
      'fixed40'  — fixed 40-byte chunks
      'fixed35'  — fixed 35-byte chunks
      'fixed16'  — fixed 16-byte chunks
      'variable' — random size per chunk drawn from [8,12,16,20,35,40]
    """
    if strategy == 'fixed40':
        size = 40
        return [data[i:i + size] for i in range(0, len(data), size)]
    if strategy == 'fixed35':
        size = 35
        return [data[i:i + size] for i in range(0, len(data), size)]
    if strategy == 'fixed16':
        size = 16
        return [data[i:i + size] for i in range(0, len(data), size)]

    # variable
    chunks: List[bytes] = []
    i = 0
    while i < len(data):
        size = random.choice(_VARIABLE_SIZES)
        chunks.append(data[i:i + size])
        i += size
    return chunks


# ── Dimension 4: Timing ───────────────────────────────────────────────────────

TIMING_STRATEGIES = ('burst', 'steady', 'random', 'human', 'burst_pause')


def _burst() -> float:
    return 0.0


def _steady() -> float:
    return 1.0


def _random_delay() -> float:
    return random.uniform(0.0, 0.4)


def _human() -> float:
    """8% probability of a long pause (5-25 s), otherwise 200 ms – 3 s."""
    if random.random() < 0.08:
        return random.uniform(5.0, 25.0)
    return random.uniform(0.2, 3.0)


def _burst_pause() -> float:
    """85% quick burst (0-200 ms), 15% long pause (5-15 s)."""
    if random.random() < 0.85:
        return random.uniform(0.0, 0.2)
    return random.uniform(5.0, 15.0)


_TIMING_FNS = {
    'burst':       _burst,
    'steady':      _steady,
    'random':      _random_delay,
    'human':       _human,
    'burst_pause': _burst_pause,
}


def apply_timing(strategy: str) -> None:
    """Sleep for the duration dictated by the timing strategy."""
    fn = _TIMING_FNS.get(strategy, _burst)
    delay = fn()
    if delay > 0:
        time.sleep(delay)


def get_delay(strategy: str) -> float:
    """Return the delay in seconds without sleeping (useful for testing)."""
    fn = _TIMING_FNS.get(strategy, _burst)
    return fn()
