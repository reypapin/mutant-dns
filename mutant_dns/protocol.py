"""
mutant-dns protocol core.

Header format (9 bytes, big-endian):
  magic(2)      0xC1AE  — locates header at any position in payload
  tunnel_id(2)  session identifier
  seq(2)        packet sequence number
  codec(1)      encoding: 0x01=hex  0x02=base32  0x03=base64
  checksum(2)   first 2 bytes of MD5(payload)

Position:
  Header is inserted at int(len(payload) * U(0.70, 0.80)) instead of
  byte 0-20 used by standard tools (Iodine, Dnscat2). This breaks
  positional overfitting in ML detectors.
"""

import base64
import hashlib
import random
import struct
from typing import Optional, Tuple

# ── Constants ─────────────────────────────────────────────────────────────────

MAGIC       = b'\xC1\xAE'
HEADER_SIZE = 9
HEADER_FMT  = '>2sHHBH'   # big-endian: 2s H H B H

CODEC_HEX    = 0x01
CODEC_BASE32 = 0x02
CODEC_BASE64 = 0x03

CODEC_MAP   = {'hex': CODEC_HEX, 'base32': CODEC_BASE32, 'base64': CODEC_BASE64}
CODEC_NAMES = {v: k for k, v in CODEC_MAP.items()}

DNS_LABEL_MAX = 63    # RFC 1035: max chars per DNS label
DNS_NAME_MAX  = 253   # RFC 1035: max FQDN length

# Control message prefixes (must be valid DNS label characters)
FIN_PREFIX = 'cnfin'    # end-of-tunnel signal


# ── Encoding / Decoding ───────────────────────────────────────────────────────

def encode_bytes(data: bytes, codec: str) -> str:
    """Encode bytes to a DNS-safe string using the specified codec."""
    if codec == 'hex':
        return data.hex()
    if codec == 'base32':
        return base64.b32encode(data).decode().rstrip('=').lower()
    if codec == 'base64':
        # URL-safe base64, lowercase — survives DNS case-folding
        s = base64.urlsafe_b64encode(data).decode().rstrip('=')
        return s.lower()
    raise ValueError('Unknown codec: {}'.format(codec))


def decode_str(s: str, codec: str) -> bytes:
    """Decode a DNS-label string back to bytes."""
    if codec == 'hex':
        return bytes.fromhex(s)
    if codec == 'base32':
        s = s.upper()
        pad = (-len(s)) % 8
        return base64.b32decode(s + '=' * pad)
    if codec == 'base64':
        # Restore URL-safe base64 (lowercase → uppercase handled by urlsafe decoder)
        s = s.upper().replace('-', '+').replace('_', '/')
        # urlsafe_b64decode also accepts standard base64 after mapping
        s = s.lower()
        # Re-map back for urlsafe
        pad = (-len(s)) % 4
        return base64.urlsafe_b64decode(s + '=' * pad)
    raise ValueError('Unknown codec: {}'.format(codec))


# ── Checksum ──────────────────────────────────────────────────────────────────

def _checksum(data: bytes) -> int:
    """First 2 bytes of MD5(data), interpreted as big-endian uint16."""
    return struct.unpack('>H', hashlib.md5(data).digest()[:2])[0]


# ── Packet building ───────────────────────────────────────────────────────────

def build_packet(payload: bytes, tunnel_id: int, seq: int, codec: str,
                 position_frac: Optional[float] = None) -> str:
    """
    Build a DNS-ready encoded string for one data chunk.

    Steps:
      1. Build 9-byte header
      2. Insert header at position_frac * len(payload)  [default: U(0.70, 0.80)]
      3. Encode the combined bytes with codec

    Returns an encoded string to be split into DNS labels.
    """
    if position_frac is None:
        position_frac = random.uniform(0.70, 0.80)

    header = struct.pack(
        HEADER_FMT,
        MAGIC,
        tunnel_id & 0xFFFF,
        seq & 0xFFFF,
        CODEC_MAP[codec],
        _checksum(payload),
    )

    ins = int(len(payload) * position_frac)
    combined = payload[:ins] + header + payload[ins:]
    return encode_bytes(combined, codec)


# ── Packet parsing ────────────────────────────────────────────────────────────

def parse_packet(encoded: str) -> Optional[Tuple[bytes, int, int, str]]:
    """
    Try to decode an encoded label string (trying all codecs in order).

    The codec used for encoding is stored in the header's codec field, but
    we don't know it until we decode. We try hex → base32 → base64 and
    accept the first one that contains valid magic bytes + passing checksum.

    Returns:
        (payload, tunnel_id, seq, codec_name)  or  None if not a tunnel packet.
    """
    for codec in ('hex', 'base32', 'base64'):
        try:
            raw = decode_str(encoded, codec)
        except Exception:
            continue

        idx = raw.find(MAGIC)
        if idx == -1:
            continue
        if len(raw) < idx + HEADER_SIZE:
            continue

        _, tunnel_id, seq, codec_byte, chk = struct.unpack(
            HEADER_FMT, raw[idx:idx + HEADER_SIZE]
        )

        payload = raw[:idx] + raw[idx + HEADER_SIZE:]

        if _checksum(payload) != chk:
            continue

        codec_name = CODEC_NAMES.get(codec_byte, codec)
        return payload, tunnel_id, seq, codec_name

    return None


# ── DNS name helpers ──────────────────────────────────────────────────────────

def encoded_to_qname(encoded: str, domain: str) -> str:
    """
    Split encoded string into ≤63-char DNS labels and prepend to domain.

    'aabbcc...'.domain.example.com  →  'aabb.cc...'.domain.example.com
    Total FQDN is clipped to DNS_NAME_MAX (253) if needed.
    """
    labels = [encoded[i:i + DNS_LABEL_MAX]
              for i in range(0, len(encoded), DNS_LABEL_MAX)]
    subdomain = '.'.join(labels)
    fqdn = '{}.{}'.format(subdomain, domain.lstrip('.'))
    return fqdn[:DNS_NAME_MAX]


def qname_to_encoded(qname: str, domain: str) -> str:
    """
    Strip base domain from FQDN and concatenate remaining labels.

    'a1b2.c3d4.tunnel.example.com'  (domain='tunnel.example.com')
    →  'a1b2c3d4'
    """
    qname  = qname.rstrip('.').lower()
    domain = domain.rstrip('.').lower()
    suffix = '.' + domain

    if qname.endswith(suffix):
        subdomain = qname[: -len(suffix)]
    elif qname == domain:
        return ''
    else:
        subdomain = qname

    return subdomain.replace('.', '')


def choose_codec(weights: Optional[dict] = None) -> str:
    """Weighted codec selection. Default: hex 60%, base32 30%, base64 10%."""
    if weights is None:
        weights = {'hex': 60, 'base32': 30, 'base64': 10}
    return random.choices(list(weights.keys()), weights=list(weights.values()), k=1)[0]
