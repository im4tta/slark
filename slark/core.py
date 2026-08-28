"""
core.py — Invisible text watermarking for marking AI/LLM-generated content.

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

Real-world Unicode caveat handled here: U+200D (ZWJ) legitimately appears
inside emoji sequences (e.g. family emoji 👨\u200d👩\u200d👧). The decoder
therefore scans *every* sentinel pair — not just the first — and only
accepts a span whose checksum verifies, so emoji in the surrounding text
never break decoding. Likewise ``strip()`` removes only verified watermark
spans (plus stray bit characters), never the ZWJs that hold an emoji
together.

Optional authenticity (v0.3): pass ``key=`` to ``encode()`` and the payload
gains a ``sig`` field — a truncated HMAC-SHA256 over the canonical JSON of
the other fields. ``verify(text, key)`` then distinguishes three states:
    "signed"   — mark present, signature valid for this key
    "invalid"  — mark present, has a sig that does NOT match this key
                 (forged, tampered, or wrong key)
    "unsigned" — mark present but carries no signature
    "none"     — no mark at all
The CRC32 protects against *accidental* corruption; the HMAC protects
against *deliberate* forgery — someone who doesn't hold the key cannot
mint a mark that verifies.

This remains invisible-to-the-eye but NOT guaranteed to survive aggressive
re-formatting (systems that strip zero-width characters, OCR, retyping).
It's lightweight provenance marking — not tamper-proof DRM.

Public API:
    encode(text, metadata=None, *, key=None, replace=False, **kwargs) -> str
    decode(text) -> dict | None
    decode_all(text) -> list[dict]
    verify(text, key) -> str            ("signed"|"invalid"|"unsigned"|"none")
    verify_meta(meta, key) -> bool
    sign_metadata(meta, key) -> dict
    has_watermark(text) -> bool
    strip(text, aggressive=False) -> str
    count_hidden_chars(text) -> int
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import time
import zlib
from typing import Iterator, List, Optional, Tuple, Union

ZW0 = "\u200b"  # zero width space      -> bit 0
ZW1 = "\u200c"  # zero width non-joiner -> bit 1
SENTINEL = "\u200d"  # zero width joiner -> start/end marker

_MARK_CHARS = {ZW0, ZW1, SENTINEL}
_BIT_CHARS = {ZW0, ZW1}

# Frame: [2B payload length (BE)][4B CRC32 of payload (BE)][payload JSON]
_HDR_BYTES = 6
MAX_PAYLOAD = 0xFFFF  # hard limit imposed by the 2-byte length prefix

SIG_FIELD = "sig"
SIG_BYTES = 8  # truncated HMAC-SHA256 -> 16 hex chars


# ---------------------------------------------------------------- bits


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
    """Insert after the first whitespace character so the marker doesn't sit
    visibly at position 0 before punctuation-sensitive contexts. Falls back
    to index 0 for text without spaces/newlines.
    """
    idx = text.find(" ")
    if idx == -1:
        idx = text.find("\n")
    return idx + 1 if idx != -1 else 0


# ---------------------------------------------------------------- payload


def _serialize_payload(metadata: dict) -> bytes:
    # Compact separators + raw non-ASCII match JavaScript's JSON.stringify
    # byte-for-byte, keeping payloads interoperable with the browser playground.
    return json.dumps(
        metadata, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _frame_payload(payload_json: bytes) -> bytes:
    if len(payload_json) > MAX_PAYLOAD:
        raise ValueError(
            f"payload must be <= {MAX_PAYLOAD} bytes, got {len(payload_json)}"
        )
    checksum = zlib.crc32(payload_json) & 0xFFFFFFFF
    return len(payload_json).to_bytes(2, "big") + checksum.to_bytes(4, "big") + payload_json


def _parse_frame(raw: bytes) -> Optional[dict]:
    """Parse and checksum-verify a decoded frame. None if invalid."""
    if len(raw) < _HDR_BYTES:
        return None
    plen = int.from_bytes(raw[0:2], "big")
    checksum = int.from_bytes(raw[2:6], "big")
    payload_json = raw[_HDR_BYTES:_HDR_BYTES + plen]
    if len(payload_json) != plen:
        return None
    if (zlib.crc32(payload_json) & 0xFFFFFFFF) != checksum:
        return None
    try:
        meta = json.loads(payload_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    # A watermark payload is always a JSON object.
    return meta if isinstance(meta, dict) else None


def _scan(text: str) -> Iterator[Tuple[dict, int, int]]:
    """Yield every verified watermark as (metadata, start, end).

    `start`..`end` are inclusive indices of the wrapping sentinels, so
    text[start:end + 1] is the exact hidden span.

    Scans every *consecutive* pair of sentinel characters rather than only
    the first, because U+200D also occurs in legitimate text (emoji ZWJ
    sequences). A span is only yielded if its checksum verifies, so emoji
    joiners never produce false positives.
    """
    sentinels = [i for i, ch in enumerate(text) if ch == SENTINEL]
    used_until = -1
    for a, b in zip(sentinels, sentinels[1:]):
        if a <= used_until:
            continue  # inside/overlapping an already-accepted span
        body = text[a + 1:b]
        bits = "".join("1" if ch == ZW1 else "0" for ch in body if ch in _BIT_CHARS)
        meta = _parse_frame(_bits_to_bytes(bits))
        if meta is not None:
            used_until = b
            yield meta, a, b


# ---------------------------------------------------------------- signing


def _key_bytes(key: Union[str, bytes]) -> bytes:
    return key.encode("utf-8") if isinstance(key, str) else bytes(key)


def _compute_sig(meta_without_sig: dict, key: Union[str, bytes]) -> str:
    """Truncated HMAC-SHA256 (hex) over the canonical compact JSON of the
    metadata *excluding* the sig field, preserving key insertion order —
    identical bytes in Python and JavaScript, so signatures interoperate."""
    msg = _serialize_payload(meta_without_sig)
    digest = _hmac.new(_key_bytes(key), msg, hashlib.sha256).digest()
    return digest[:SIG_BYTES].hex()


def sign_metadata(metadata: dict, key: Union[str, bytes]) -> dict:
    """Return a copy of `metadata` with a truncated-HMAC ``sig`` field
    appended (always last, so verification re-serializes identically)."""
    base = {k: v for k, v in metadata.items() if k != SIG_FIELD}
    signed = dict(base)
    signed[SIG_FIELD] = _compute_sig(base, key)
    return signed


def verify_meta(metadata: Optional[dict], key: Union[str, bytes]) -> bool:
    """True iff `metadata` carries a ``sig`` that matches this key."""
    if not isinstance(metadata, dict) or SIG_FIELD not in metadata:
        return False
    sig = metadata[SIG_FIELD]
    if not isinstance(sig, str):
        return False
    base = {k: v for k, v in metadata.items() if k != SIG_FIELD}
    expected = _compute_sig(base, key)
    return _hmac.compare_digest(expected, sig)


def verify(text: str, key: Union[str, bytes]) -> str:
    """Classify the first mark in `text` against `key`.

    Returns one of:
        "signed"   — mark present, signature valid for this key
        "invalid"  — mark present with a sig that does not match this key
        "unsigned" — mark present but has no sig field
        "none"     — no verifiable mark found
    """
    meta = decode(text)
    if meta is None:
        return "none"
    if SIG_FIELD not in meta:
        return "unsigned"
    return "signed" if verify_meta(meta, key) else "invalid"


# ---------------------------------------------------------------- metadata


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


# ---------------------------------------------------------------- public


def encode(
    text: str,
    metadata: Optional[dict] = None,
    *,
    model: Optional[str] = None,
    generator: str = "ai",
    timestamp: Optional[int] = None,
    extra: Optional[dict] = None,
    replace: bool = False,
    key: Optional[Union[str, bytes]] = None,
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
        replace: if True, remove any existing verified watermark(s) before
            embedding, so the text carries exactly one mark.
        key: optional secret; when given, an HMAC-SHA256 ``sig`` field is
            added so ``verify(text, key)`` can authenticate the mark.

    Returns:
        The watermarked text (visually identical to the input).

    Raises:
        ValueError: if the serialized payload exceeds 65535 bytes.
    """
    metadata = _default_metadata(metadata, model, generator, timestamp, extra)
    if key is not None:
        metadata = sign_metadata(metadata, key)
    if replace:
        text = strip(text)

    framed = _frame_payload(_serialize_payload(metadata))
    zw = _payload_to_zerowidth(framed)
    idx = _find_insert_index(text)
    return text[:idx] + zw + text[idx:]


def decode(text: str) -> Optional[dict]:
    """Extract and verify the first watermark payload in `text`.

    Returns the metadata dict if a valid, checksum-verified watermark is
    found, otherwise None. Robust to emoji ZWJ sequences elsewhere in the
    text and to multiple embedded marks (returns the first valid one).
    """
    for meta, _start, _end in _scan(text):
        return meta
    return None


def decode_all(text: str) -> List[dict]:
    """Extract every verified watermark payload in `text`, in order.

    Returns an empty list when no valid mark is present.
    """
    return [meta for meta, _s, _e in _scan(text)]


def has_watermark(text: str) -> bool:
    """Check whether a verifiable watermark is present."""
    return decode(text) is not None


def strip(text: str, aggressive: bool = False) -> str:
    """Remove watermarks, returning clean text.

    Default (safe) behavior:
      1. Remove every checksum-verified watermark span exactly.
      2. Remove any leftover stray bit characters (ZWSP/ZWNJ) — e.g. the
         remains of a mark that a pipeline partially mangled.
      Legitimate ZWJs (emoji sequences like 👨\u200d👩\u200d👧) are preserved.

    Args:
        aggressive: also remove *all* U+200D characters, matching the
            blunt legacy behavior. This breaks emoji ZWJ sequences —
            only use it when you want every zero-width character gone.
    """
    # 1) remove verified spans (inclusive of their sentinels)
    spans = [(s, e) for _m, s, e in _scan(text)]
    if spans:
        parts = []
        prev = 0
        for s, e in spans:
            parts.append(text[prev:s])
            prev = e + 1
        parts.append(text[prev:])
        text = "".join(parts)

    # 2) remove stray bit characters (never legitimate watermark leftovers
    #    we want to keep); optionally nuke ZWJ too.
    drop = _MARK_CHARS if aggressive else _BIT_CHARS
    return "".join(ch for ch in text if ch not in drop)


def count_hidden_chars(text: str) -> int:
    """Number of characters that ``strip()`` would remove (0 if none)."""
    return len(text) - len(strip(text))
