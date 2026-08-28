"""Tests for the v0.2 image improvements: erase(), re-encode overwrite,
non-dict payload rejection."""

import pytest

pytest.importorskip("PIL")

from PIL import Image

from slark import image as imgmod


def make_image(w=96, h=72, alpha=False):
    mode = "RGBA" if alpha else "RGB"
    raw = bytearray()
    for p in range(w * h):
        x, y = p % w, p // w
        raw += bytes([(x * 7 + y * 13) & 255, (x * 5 + y * 29) & 255, (x * 11 + y * 3) & 255, 255])
    return Image.frombytes(mode, (w, h), bytes(raw))


# ---------- erase ----------


def test_erase_removes_tag():
    marked = imgmod.encode(make_image(), metadata={"k": "v"})
    assert imgmod.has_watermark(marked)
    clean = imgmod.erase(marked)
    assert imgmod.decode(clean) is None
    assert not imgmod.has_watermark(clean)


def test_erase_is_visually_negligible():
    marked = imgmod.encode(make_image(), metadata={"k": "v"})
    clean = imgmod.erase(marked)
    a = marked.convert("RGBA").tobytes()
    b = clean.convert("RGBA").tobytes()
    diffs = [abs(x - y) for x, y in zip(a, b) if x != y]
    assert diffs, "erase should change something on a tagged image"
    assert max(diffs) == 1  # every change is a single LSB flip


def test_erase_preserves_mode_and_alpha():
    marked = imgmod.encode(make_image(alpha=True), metadata={"k": "v"})
    clean = imgmod.erase(marked)
    assert clean.mode == "RGBA"
    assert set(clean.tobytes()[3::4]) == {255}

    marked_rgb = imgmod.encode(make_image(), metadata={"k": "v"})
    assert imgmod.erase(marked_rgb).mode == "RGB"


def test_erase_on_clean_image_is_harmless():
    clean = imgmod.erase(make_image())
    assert imgmod.decode(clean) is None


def test_erase_file_roundtrip(tmp_path):
    p = tmp_path / "marked.png"
    imgmod.encode(make_image(), model="m").save(p)
    out = tmp_path / "clean.png"
    imgmod.erase(p).save(out)
    assert not imgmod.has_watermark(out)


# ---------- overwrite semantics ----------


def test_reencode_overwrites_previous_tag():
    first = imgmod.encode(make_image(), metadata={"v": 1})
    second = imgmod.encode(first, metadata={"v": 2})
    assert imgmod.decode(second) == {"v": 2}
    # every redundant copy must agree — scan info shows the first copy wins
    info = imgmod.decode_info(second)
    assert info.metadata == {"v": 2} and info.copy_index == 0


# ---------- fail-closed ----------


def test_non_dict_payload_rejected():
    import json, zlib

    payload = json.dumps([1, 2, 3]).encode()
    frame = (
        imgmod.MAGIC
        + len(payload).to_bytes(2, "big")
        + (zlib.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "big")
        + payload
    )
    img = make_image()
    raw = bytearray(img.convert("RGBA").tobytes())
    total_slots = img.width * img.height * 3
    copies = imgmod._copies_for(total_slots, imgmod.RESERVE_BITS)
    chunk = total_slots // copies
    for c in range(copies):
        base = c * chunk
        for b in range(len(frame) * 8):
            idx = imgmod._slot_index(base + b)
            raw[idx] = (raw[idx] & 0xFE) | ((frame[b >> 3] >> (7 - (b & 7))) & 1)
    assert imgmod._decode_raw(raw, img.width, img.height) is None
