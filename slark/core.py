"""
watermark.py — Invisible text watermarking for marking AI/LLM-generated content.

Technique: zero-width Unicode steganography.
  - Metadata (a small JSON payload) is serialized to bytes.
  - A CRC32 checksum is appended for integrity verification on decode.
  - The byte stream is converted to bits, and each bit is mapped to one of
    two invisible Unicode characters:
        0 -> ZERO WIDTH SPACE       (U+200B)
        1 -> ZERO WIDTH NON-JOINER  (U+200C)
  - The whole payload is wrapped between two ZERO WIDTH JOINER (U+200D)
    sentinels so a decoder can locate it even if surrounded by normal text.
  - The payload is inserted once, right after the first whitespace character
    in the text (or at the very start if there is none). Because the marker
    characters have zero width and no glyph, the visible text is completely
    unchanged when rendered — it reads identically, copies identically as
    plain text, but carries the hidden payload.

This is invisible-to-the-eye but NOT cryptographically secure and NOT
guaranteed to survive aggressive re-formatting (e.g. pasting into a system
that strips zero-width characters, OCR, or manual retyping). It's meant for
lightweight, low-friction provenance marking — not tamper-proof DRM.

Public API:
    encode(text, metadata=None, **kwargs) -> str
    decode(text) -> dict | None
    has_watermark(text) -> bool
    strip(text) -> str
"""

from __future__ import annotations

import json
import time
import zlib
from typing import Optional

ZW0 = "\u200b"  # zero width space      -> bit 0
ZW1 = "\u200c"  # zero width non-joiner -> bit 1
SENTINEL = "\u200d"  # zero width joiner -> start/end marker

_MARK_CHARS = {ZW0, ZW1, SENTINEL}


def _bytes_to_bits(data: bytes) -> str:
    return "".join(format(b, "08b") for b in data)


def _bits_to_bytes(bits: str) -> bytes:
    # truncate to a whole number of bytes just in case
    n = len(bits) - (len(bits) % 8)
    bits = bits[:n]
    return bytes(int(bits[i:i + 8], 2) for i in range(0, n, 8))


def _payload_to_zerowidth(payload: bytes) -> str:
    bits = _bytes_to_bits(payload)
    body = "".join(ZW1 if b == "1" else ZW0 for b in bits)
    return SENTINEL + body + SENTINEL


def _find_insert_index(text: str) -> int:
    """Insert after the first run of leading content's first whitespace,
    so the marker doesn't sit visibly at position 0 before punctuation-
    sensitive contexts. Falls back to index 0 for empty/whitespace-only text.
    """
    idx = text.find(" ")
    if idx == -1:
        idx = text.find("\n")
    return idx + 1 if idx != -1 else 0


def _default_metadata(
    metadata: Optional[dict],
    model: Optional[str],
    generator: str,
    timestamp: Optional[int],
    extra: Optional[dict],
) -> dict:
    if metadata is not None:
        return metadata
    meta = {"g": generator, "ts": timestamp or int(time.time())}
    if model:
        meta["m"] = model
    if extra:
        meta.update(extra)
    return meta


def encode(
    text: str,
    metadata: Optional[dict] = None,
    *,
    model: Optional[str] = None,
    generator: str = "ai",
    timestamp: Optional[int] = None,
    extra: Optional[dict] = None,
) -> str:
    """Embed an invisible watermark into `text`.

    Args:
        text: the text to watermark.
        metadata: full payload dict to embed verbatim (overrides the
            convenience kwargs below if provided).
        model: optional model name/id to record (e.g. "claude-sonnet-5").
        generator: short tag identifying the source type, default "ai".
        timestamp: unix epoch seconds; defaults to now.
        extra: any additional fields to merge into the payload.

    Returns:
        The watermarked text (visually identical to the input).
    """
    metadata = _default_metadata(metadata, model, generator, timestamp, extra)

    # Compact separators + raw non-ASCII match JavaScript's JSON.stringify
    # byte-for-byte, keeping payloads interoperable with the browser playground.
    payload_json = json.dumps(
        metadata, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    checksum = zlib.crc32(payload_json) & 0xFFFFFFFF
    framed = len(payload_json).to_bytes(2, "big") + checksum.to_bytes(4, "big") + payload_json

    zw = _payload_to_zerowidth(framed)
    idx = _find_insert_index(text)
    return text[:idx] + zw + text[idx:]


def decode(text: str) -> Optional[dict]:
    """Extract and verify the watermark payload from `text`.

    Returns the metadata dict if a valid, checksum-verified watermark is
    found, otherwise None.
    """
    start = text.find(SENTINEL)
    if start == -1:
        return None
    end = text.find(SENTINEL, start + 1)
    if end == -1:
        return None

    body = text[start + 1:end]
    bits = "".join("1" if ch == ZW1 else "0" for ch in body if ch in (ZW0, ZW1))
    raw = _bits_to_bytes(bits)

    if len(raw) < 6:
        return None

    plen = int.from_bytes(raw[0:2], "big")
    checksum = int.from_bytes(raw[2:6], "big")
    payload_json = raw[6:6 + plen]

    if len(payload_json) != plen:
        return None
    if (zlib.crc32(payload_json) & 0xFFFFFFFF) != checksum:
        return None

    try:
        return json.loads(payload_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def has_watermark(text: str) -> bool:
    """Fast check: is there a verifiable watermark present?"""
    return decode(text) is not None


def strip(text: str) -> str:
    """Remove any zero-width watermark characters, returning clean text."""
    return "".join(ch for ch in text if ch not in _MARK_CHARS)


def count_hidden_chars(text: str) -> int:
    """Number of invisible watermark characters present (0 if none)."""
    return sum(1 for ch in text if ch in _MARK_CHARS)
