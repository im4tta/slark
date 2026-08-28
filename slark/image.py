"""
image.py — invisible image tagging via PNG least-significant bits.

Mirrors the playground's "SLK1" format exactly, so files stamped in the
browser decode here and vice versa:

  Frame layout (per copy):
      [4B magic "SLK1"][2B payload length (big-endian)]
      [4B CRC32 of payload (big-endian)][payload JSON bytes]

  Embedding:
      - The frame's bits are written, most-significant first, into the
        least-significant bit of each pixel's R, G, B channel in row-major
        order. The alpha channel is never touched.
      - The same frame is written repeatedly into evenly spaced chunks of
        the slot space (up to 512 copies), so local damage — an overlay,
        a crop — rarely destroys every copy. The decoder scans every chunk,
        and a payload is only accepted if its CRC32 verifies.

  Recovery (v0.3):
      - If no single copy verifies, the decoder can perform bitwise
        MAJORITY VOTING across all copies: for each bit position, take the
        value most copies agree on, then re-verify the checksum. Sparse
        random noise that damages every copy a little (but most copies
        agree on any given bit) is thereby survivable. This is a stronger
        read strategy on the *same* format — no encoder change.

  Layout derivation uses only the image's capacity and fixed constants,
  never the payload size alone, so encoder and decoder agree without
  communicating. (Because a frame can never exceed the reserved slot size,
  the chunk layout is identical for every payload — which also means
  re-encoding an already-tagged image cleanly overwrites the old tag.)

This shares text watermarking's honesty: LSB tags are invisible but die
on any lossy re-encode (JPEG, WebP, screenshots, platform re-uploads).
Save and share as PNG end-to-end.

Public API:
    encode(source, metadata=None, *, key=None, **kwargs) -> PIL.Image.Image
    decode(source, vote=True) -> dict | None
    decode_info(source, vote=True) -> DecodeResult | None
    verify(source, key) -> str        ("signed"|"invalid"|"unsigned"|"none")
    has_watermark(source) -> bool
    erase(source) -> PIL.Image.Image
    capacity(source) -> dict

Requires Pillow: pip install "slark[image]"
"""

from __future__ import annotations

import json
import zlib
from typing import NamedTuple, Optional, Union

from .core import SIG_FIELD, _default_metadata, sign_metadata, verify_meta

MAGIC = b"SLK1"
HDR_BYTES = 10
MAX_PAYLOAD = 256
RESERVE_BITS = (HDR_BYTES + MAX_PAYLOAD) * 8
MAX_COPIES = 512


class DecodeResult(NamedTuple):
    """Rich decode outcome.

    metadata:     the verified payload dict
    copy_index:   index of the first intact copy, or -1 when the payload
                  was reconstructed by majority vote
    total_copies: number of redundant copies in the layout
    via_vote:     True when recovered by cross-copy majority voting
    """
    metadata: dict
    copy_index: int
    total_copies: int
    via_vote: bool


def _require_pil():
    try:
        from PIL import Image  # noqa: F401
        return Image
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            'Image support requires Pillow: pip install "slark[image]"'
        ) from e


def _load(source):
    """Accept a path, file-like object, or PIL.Image; return (PIL.Image, had_alpha)."""
    Image = _require_pil()
    if isinstance(source, Image.Image):
        img = source
    else:
        img = Image.open(source)
    img.load()
    had_alpha = img.mode in ("RGBA", "LA", "PA") or (
        img.mode == "P" and "transparency" in img.info
    )
    return img, had_alpha


def _to_rgba_bytes(source):
    """Load `source` and return (bytearray RGBA pixels, width, height, had_alpha)."""
    img, had_alpha = _load(source)
    rgba = img.convert("RGBA")
    w, h = rgba.size
    return bytearray(rgba.tobytes()), w, h, had_alpha


def _frame_for(payload_json: bytes) -> bytes:
    if not 0 < len(payload_json) <= MAX_PAYLOAD:
        raise ValueError(
            f"payload must be 1..{MAX_PAYLOAD} bytes after framing, "
            f"got {len(payload_json)}"
        )
    checksum = zlib.crc32(payload_json) & 0xFFFFFFFF
    return (
        MAGIC
        + len(payload_json).to_bytes(2, "big")
        + checksum.to_bytes(4, "big")
        + payload_json
    )


def _copies_for(total_slots: int, frame_bits: int) -> int:
    need = max(frame_bits, RESERVE_BITS)
    return min(MAX_COPIES, total_slots // need)


def _slot_index(pos: int) -> int:
    """Map a bit-slot position to its byte index in RGBA pixel data."""
    return (pos // 3) * 4 + (pos % 3)


def _parse_payload(payload_json: bytes, expected_crc: int) -> Optional[dict]:
    if (zlib.crc32(payload_json) & 0xFFFFFFFF) != expected_crc:
        return None
    try:
        meta = json.loads(payload_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return meta if isinstance(meta, dict) else None


# ---------------------------------------------------------------- encode


def encode(
    source,
    metadata: Optional[dict] = None,
    *,
    model: Optional[str] = None,
    generator: str = "ai",
    timestamp: Optional[int] = None,
    extra: Optional[dict] = None,
    key: Optional[Union[str, bytes]] = None,
):
    """Embed an invisible SLK1 tag into an image.

    Re-encoding an already-tagged image overwrites the previous tag —
    the chunk layout depends only on image capacity, never payload size.

    Args:
        source: path, file-like object, or PIL.Image.Image.
        metadata: full payload dict to embed verbatim (overrides the
            convenience kwargs below if provided).
        model: optional model name/id to record.
        generator: short tag identifying the source type, default "ai".
        timestamp: unix epoch seconds; defaults to now.
        extra: additional fields merged into the payload.
        key: optional secret; adds an HMAC-SHA256 ``sig`` field so
            ``verify(image, key)`` can authenticate the tag.

    Returns:
        A new PIL.Image.Image (RGB, or RGBA if the source had alpha).
        Save it as PNG — any lossy format erases the tag.

    Raises:
        ValueError: payload too large or image too small to hold one copy.
    """
    Image = _require_pil()

    meta = _default_metadata(metadata, model, generator, timestamp, extra)
    if key is not None:
        meta = sign_metadata(meta, key)
    # Compact separators match JavaScript's JSON.stringify byte-for-byte,
    # keeping payloads interoperable with the browser playground.
    payload_json = json.dumps(meta, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    frame = _frame_for(payload_json)

    raw, width, height, had_alpha = _to_rgba_bytes(source)

    total_slots = width * height * 3
    frame_bits = len(frame) * 8
    copies = _copies_for(total_slots, frame_bits)
    if copies < 1:
        raise ValueError("image has too few pixels to hold a tag")

    # Precompute each frame bit once; reuse across every copy.
    frame_bit_values = [
        (frame[b >> 3] >> (7 - (b & 7))) & 1 for b in range(frame_bits)
    ]
    chunk = total_slots // copies
    for c in range(copies):
        base = c * chunk
        for b, want in enumerate(frame_bit_values):
            idx = _slot_index(base + b)
            raw[idx] = (raw[idx] & 0xFE) | want

    out = Image.frombytes("RGBA", (width, height), bytes(raw))
    if not had_alpha:
        out = out.convert("RGB")
    return out


# ---------------------------------------------------------------- decode


def _read_bytes(raw, base: int, count: int) -> bytes:
    out = bytearray(count)
    for b in range(count * 8):
        pos = base + b
        out[b >> 3] |= (raw[(pos // 3) * 4 + (pos % 3)] & 1) << (7 - (b & 7))
    return bytes(out)


def _try_copy(raw, base: int, chunk: int) -> Optional[dict]:
    """Attempt to read + verify one frame copy starting at slot `base`."""
    hdr = _read_bytes(raw, base, HDR_BYTES)
    if hdr[:4] != MAGIC:
        return None
    plen = int.from_bytes(hdr[4:6], "big")
    if not 0 < plen <= MAX_PAYLOAD:
        return None
    if (HDR_BYTES + plen) * 8 > chunk:
        return None
    frame = _read_bytes(raw, base, HDR_BYTES + plen)
    stored = int.from_bytes(frame[6:10], "big")
    return _parse_payload(frame[HDR_BYTES:], stored)


def _vote_decode(raw, copies: int, chunk: int) -> Optional[dict]:
    """Bitwise majority vote across every copy, then verify the result.

    Reconstructs the full reserved slot region (header + max payload) by
    per-bit voting, so it works even when NO individual copy is intact —
    as long as, for each bit, more copies are right than wrong.
    """
    if copies < 3:  # voting needs a meaningful majority
        return None
    vote_bits = min(RESERVE_BITS, chunk)
    nbytes = vote_bits // 8
    counts = [0] * (nbytes * 8)
    for c in range(copies):
        base = c * chunk
        for b in range(nbytes * 8):
            pos = base + b
            counts[b] += raw[(pos // 3) * 4 + (pos % 3)] & 1

    half = copies / 2
    voted = bytearray(nbytes)
    for b, cnt in enumerate(counts):
        if cnt > half:
            voted[b >> 3] |= 1 << (7 - (b & 7))

    if bytes(voted[:4]) != MAGIC:
        return None
    plen = int.from_bytes(voted[4:6], "big")
    if not 0 < plen <= MAX_PAYLOAD or HDR_BYTES + plen > nbytes:
        return None
    stored = int.from_bytes(voted[6:10], "big")
    return _parse_payload(bytes(voted[HDR_BYTES:HDR_BYTES + plen]), stored)


def _decode_raw(raw: bytearray, width: int, height: int, vote: bool = True):
    """Scan chunks for a verifiable frame; fall back to majority voting.

    Returns a DecodeResult or None.
    """
    total_slots = width * height * 3
    copies = _copies_for(total_slots, RESERVE_BITS)
    if copies < 1:
        return None
    chunk = total_slots // copies

    for c in range(copies):
        meta = _try_copy(raw, c * chunk, chunk)
        if meta is not None:
            return DecodeResult(meta, c, copies, False)

    if vote:
        meta = _vote_decode(raw, copies, chunk)
        if meta is not None:
            return DecodeResult(meta, -1, copies, True)
    return None


def decode(source, vote: bool = True) -> Optional[dict]:
    """Extract and verify an SLK1 tag from an image.

    Args:
        source: path, file-like object, or PIL.Image.Image.
        vote: when no single copy is intact, attempt bitwise majority-vote
            reconstruction across all copies (default True).

    Returns:
        The metadata dict if a valid, checksum-verified tag is found,
        otherwise None.
    """
    raw, w, h, _ = _to_rgba_bytes(source)
    found = _decode_raw(raw, w, h, vote=vote)
    return found.metadata if found else None


def decode_info(source, vote: bool = True) -> Optional[DecodeResult]:
    """Like decode(), but returns the full DecodeResult (or None)."""
    raw, w, h, _ = _to_rgba_bytes(source)
    return _decode_raw(raw, w, h, vote=vote)


def verify(source, key: Union[str, bytes]) -> str:
    """Classify an image tag against `key`: "signed" | "invalid" |
    "unsigned" | "none" — same semantics as core.verify()."""
    meta = decode(source)
    if meta is None:
        return "none"
    if SIG_FIELD not in meta:
        return "unsigned"
    return "signed" if verify_meta(meta, key) else "invalid"


def has_watermark(source) -> bool:
    """Fast check: is there a verifiable SLK1 tag present?"""
    return decode(source) is not None


# ---------------------------------------------------------------- utility


def erase(source):
    """Remove any SLK1 tag by scrubbing the magic bytes of every chunk.

    Only the 32 magic-bit slots at the start of each chunk are touched
    (their LSBs are zeroed), so at most 32 sub-pixel values per chunk shift
    by 1/255 — visually nothing, but no decoder can find a frame afterwards
    (voting included: the voted magic can no longer match).

    Returns:
        A new PIL.Image.Image (RGB, or RGBA if the source had alpha).
    """
    Image = _require_pil()
    raw, width, height, had_alpha = _to_rgba_bytes(source)

    total_slots = width * height * 3
    copies = _copies_for(total_slots, RESERVE_BITS)
    if copies >= 1:
        chunk = total_slots // copies
        magic_bits = len(MAGIC) * 8
        for c in range(copies):
            base = c * chunk
            for b in range(magic_bits):
                idx = _slot_index(base + b)
                raw[idx] &= 0xFE

    out = Image.frombytes("RGBA", (width, height), bytes(raw))
    if not had_alpha:
        out = out.convert("RGB")
    return out


def capacity(source) -> dict:
    """Report how much tag redundancy an image can hold.

    Returns a dict:
        width, height     — pixel dimensions
        total_slots       — embeddable bit slots (w*h*3)
        copies            — redundant copies the layout will use
        max_payload_bytes — per-copy JSON payload cap (constant, 256)
        taggable          — True if at least one copy fits
    """
    img, _ = _load(source)
    w, h = img.size
    total_slots = w * h * 3
    copies = _copies_for(total_slots, RESERVE_BITS)
    return {
        "width": w,
        "height": h,
        "total_slots": total_slots,
        "copies": copies,
        "max_payload_bytes": MAX_PAYLOAD,
        "taggable": copies >= 1,
    }
