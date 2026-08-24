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

  Layout derivation uses only the image's capacity and fixed constants,
  never the payload size alone, so encoder and decoder agree without
  communicating.

This shares text watermarking's honesty: LSB tags are invisible but die
on any lossy re-encode (JPEG, WebP, screenshots, platform re-uploads).
Save and share as PNG end-to-end.

Public API:
    encode(source, metadata=None, **kwargs) -> PIL.Image.Image
    decode(source) -> dict | None
    has_watermark(source) -> bool

Requires Pillow: pip install "slark[image]"
"""

from __future__ import annotations

import json
import zlib
from typing import Optional

from .core import _default_metadata

MAGIC = b"SLK1"
HDR_BYTES = 10
MAX_PAYLOAD = 256
RESERVE_BITS = (HDR_BYTES + MAX_PAYLOAD) * 8
MAX_COPIES = 512


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


def encode(
    source,
    metadata: Optional[dict] = None,
    *,
    model: Optional[str] = None,
    generator: str = "ai",
    timestamp: Optional[int] = None,
    extra: Optional[dict] = None,
):
    """Embed an invisible SLK1 tag into an image.

    Args:
        source: path, file-like object, or PIL.Image.Image.
        metadata: full payload dict to embed verbatim (overrides the
            convenience kwargs below if provided).
        model: optional model name/id to record.
        generator: short tag identifying the source type, default "ai".
        timestamp: unix epoch seconds; defaults to now.
        extra: additional fields merged into the payload.

    Returns:
        A new PIL.Image.Image (RGB, or RGBA if the source had alpha).
        Save it as PNG — any lossy format erases the tag.

    Raises:
        ValueError: payload too large or image too small to hold one copy.
    """
    Image = _require_pil()

    meta = _default_metadata(metadata, model, generator, timestamp, extra)
    # Compact separators match JavaScript's JSON.stringify byte-for-byte,
    # keeping payloads interoperable with the browser playground.
    payload_json = json.dumps(meta, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    frame = _frame_for(payload_json)

    img, had_alpha = _load(source)
    rgba = img.convert("RGBA")
    width, height = rgba.size
    raw = bytearray(rgba.tobytes())

    total_slots = width * height * 3
    frame_bits = len(frame) * 8
    copies = _copies_for(total_slots, frame_bits)
    if copies < 1:
        raise ValueError("image has too few pixels to hold a tag")

    chunk = total_slots // copies
    for c in range(copies):
        base = c * chunk
        for b in range(frame_bits):
            pos = base + b
            idx = (pos // 3) * 4 + (pos % 3)
            want = (frame[b >> 3] >> (7 - (b & 7))) & 1
            raw[idx] = (raw[idx] & 0xFE) | want

    out = Image.frombytes("RGBA", (width, height), bytes(raw))
    if not had_alpha:
        out = out.convert("RGB")
    return out


def _decode_raw(raw: bytearray, width: int, height: int):
    """Scan chunks for a verifiable frame. Return (meta, copy_index, copies) or None."""
    total_slots = width * height * 3
    copies = _copies_for(total_slots, RESERVE_BITS)
    if copies < 1:
        return None
    chunk = total_slots // copies

    def read_bytes(base: int, count: int) -> bytes:
        out = bytearray(count)
        for b in range(count * 8):
            pos = base + b
            out[b >> 3] |= (raw[(pos // 3) * 4 + (pos % 3)] & 1) << (7 - (b & 7))
        return bytes(out)

    for c in range(copies):
        base = c * chunk
        hdr = read_bytes(base, HDR_BYTES)
        if hdr[:4] != MAGIC:
            continue
        plen = int.from_bytes(hdr[4:6], "big")
        if not 0 < plen <= MAX_PAYLOAD:
            continue
        if (HDR_BYTES + plen) * 8 > chunk:
            continue
        frame = read_bytes(base, HDR_BYTES + plen)
        stored = int.from_bytes(frame[6:10], "big")
        payload_json = frame[HDR_BYTES:]
        if (zlib.crc32(payload_json) & 0xFFFFFFFF) != stored:
            continue
        try:
            meta = json.loads(payload_json.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        return meta, c, copies
    return None


def decode(source) -> Optional[dict]:
    """Extract and verify an SLK1 tag from an image.

    Args:
        source: path, file-like object, or PIL.Image.Image.

    Returns:
        The metadata dict if a valid, checksum-verified tag is found,
        otherwise None.
    """
    Image = _require_pil()
    if isinstance(source, Image.Image):
        img = source
    else:
        img = Image.open(source)
    rgba = img.convert("RGBA")
    raw = bytearray(rgba.tobytes())
    found = _decode_raw(raw, rgba.size[0], rgba.size[1])
    return found[0] if found else None


def decode_info(source):
    """Like decode(), but returns (metadata, copy_index, total_copies) or None."""
    Image = _require_pil()
    if isinstance(source, Image.Image):
        img = source
    else:
        img = Image.open(source)
    rgba = img.convert("RGBA")
    raw = bytearray(rgba.tobytes())
    return _decode_raw(raw, rgba.size[0], rgba.size[1])


def has_watermark(source) -> bool:
    """Fast check: is there a verifiable SLK1 tag present?"""
    return decode(source) is not None
