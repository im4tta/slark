import json
import struct
from pathlib import Path

import pytest

pytest.importorskip("PIL")

from PIL import Image

from slark import core
from slark import image as imgmod

FIXTURES = Path(__file__).parent / "fixtures"
W, H = 48, 48
JS_META = {"g": "ai", "m": "js-vector", "ts": 1234567890}


def make_image(w=96, h=72, alpha=False):
    mode = "RGBA" if alpha else "RGB"
    raw = bytearray()
    for p in range(w * h):
        x, y = p % w, p // w
        raw += bytes([(x * 7 + y * 13) & 255, (x * 5 + y * 29) & 255, (x * 11 + y * 3) & 255, 255])
    return Image.frombytes(mode, (w, h), bytes(raw))


# ---------- cross-implementation parity with the browser playground ----------


def test_js_fixture_decodes_in_python():
    marked = FIXTURES / "slk1_marked_rgba.bin"
    img = Image.frombytes("RGBA", (W, H), marked.read_bytes())
    assert imgmod.decode(img) == JS_META


def test_python_encode_is_byte_identical_to_js():
    src = Image.frombytes("RGBA", (W, H), (FIXTURES / "slk1_input_rgba.bin").read_bytes())
    expected = (FIXTURES / "slk1_marked_rgba.bin").read_bytes()
    out = imgmod.encode(src, metadata=dict(JS_META))
    assert out.mode == "RGBA"
    assert out.tobytes() == expected


# ---------- roundtrips ----------


def test_roundtrip_rgb_image_default_metadata():
    out = imgmod.encode(make_image(), model="claude-sonnet-5")
    meta = imgmod.decode(out)
    assert meta["g"] == "ai"
    assert meta["m"] == "claude-sonnet-5"
    assert isinstance(meta["ts"], int)


def test_roundtrip_rgba_preserves_alpha_and_payload():
    src = make_image(alpha=True)
    payload = {"foo": "bar", "n": 42}
    out = imgmod.encode(src, metadata=payload)
    assert out.mode == "RGBA"
    alphas = out.tobytes()[3::4]
    assert set(alphas) == {255}  # alpha untouched by embedding
    assert imgmod.decode(out) == payload


def test_unicode_metadata_roundtrip():
    out = imgmod.encode(make_image(), extra={"note": "héllo 日本語"})
    assert imgmod.decode(out)["note"] == "héllo 日本語"


def test_png_file_roundtrip(tmp_path):
    path = tmp_path / "in.png"
    make_image().save(path)
    out_path = tmp_path / "out.png"
    imgmod.encode(path, model="m1").save(out_path)
    assert imgmod.has_watermark(out_path)
    assert imgmod.decode(out_path)["m"] == "m1"


# ---------- robustness semantics ----------


def test_single_copy_corruption_still_decodes_via_redundancy():
    src = make_image(200, 150)
    out = imgmod.encode(src, metadata={"k": "v"})
    raw = bytearray(out.convert("RGBA").tobytes())

    total_slots = 200 * 150 * 3
    copies = min(imgmod.MAX_COPIES, total_slots // imgmod.RESERVE_BITS)
    chunk = total_slots // copies
    # destroy every bit of the FIRST copy only
    for b in range((imgmod.HDR_BYTES + 7) * 8):
        pos = b
        raw[(pos // 3) * 4 + (pos % 3)] ^= 1

    found = imgmod._decode_raw(raw, 200, 150)
    assert found is not None
    assert found.metadata == {"k": "v"}
    assert found.copy_index > 0 and found.total_copies == copies
    assert found.via_vote is False


def test_all_copies_corrupted_returns_none():
    src = make_image(200, 150)
    out = imgmod.encode(src, metadata={"k": "v"})
    raw = bytearray(out.convert("RGBA").tobytes())

    total_slots = 200 * 150 * 3
    copies = min(imgmod.MAX_COPIES, total_slots // imgmod.RESERVE_BITS)
    chunk = total_slots // copies
    # flip the SAME relative frame bit in every copy -> no intact copy remains
    for c in range(copies):
        pos = c * chunk + 40
        raw[(pos // 3) * 4 + (pos % 3)] ^= 1

    assert imgmod._decode_raw(raw, 200, 150) is None


def test_clean_image_has_no_tag():
    assert imgmod.decode(make_image()) is None
    assert imgmod.has_watermark(make_image()) is False


# ---------- guards ----------


def test_oversized_payload_raises():
    with pytest.raises(ValueError):
        imgmod.encode(make_image(), extra={"pad": "x" * 300})


def test_tiny_image_raises():
    with pytest.raises(ValueError):
        imgmod.encode(make_image(16, 16), model="m")


def test_missing_pillow_hint(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **kw):
        if name.startswith("PIL"):
            raise ImportError("No module named 'PIL'")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ImportError, match=r"slark\[image\]"):
        imgmod.encode(make_image(), model="m")


# ---------- text/image payload builder consistency ----------


def test_shared_metadata_builder_matches_core_defaults():
    """Same convenience kwargs must produce identical payloads in both codecs."""
    ts = 1787322082
    text_marked = core.encode("hello world", model="claude-sonnet-5", timestamp=ts)
    text_meta = core.decode(text_marked)
    img_out = imgmod.encode(make_image(), model="claude-sonnet-5", timestamp=ts)
    assert imgmod.decode(img_out) == text_meta
