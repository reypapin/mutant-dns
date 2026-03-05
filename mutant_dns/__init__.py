"""
mutant-dns: DNS tunnel with 4-dimensional structural mutations.

Based on: "Simple Payload Mutations Break Machine Learning Based DNS
Tunneling Detection" (Leyva La O & Catania, 2025).

Mutations:
  1. Position  — header injected at 70-80% of payload (not byte 0-20)
  2. Encoding  — per-packet: hex (60%), base32 (30%), base64 (10%)
  3. Chunking  — variable or fixed chunk sizes
  4. Timing    — realistic inter-query delays
"""
__version__ = '0.2.0'
