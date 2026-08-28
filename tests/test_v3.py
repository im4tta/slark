"""Tests for the v0.3 features: HMAC signing/verification (text + image),
majority-vote image recovery, capacity reporting."""

import json

import pytest

import slark
from slark import core as wm


SAMPLE = "Renewable energy adoption keeps accelerating worldwide."
KEY = "team-secret-2026"


# ---------------- text signing ----------------


def test_signed_encode_adds_sig_and_verifies():
    marked = slark.encode(SAMPLE, model="m1", key=KEY)
    meta = slark.decode(marked)
    assert "sig" in meta and len(meta["sig"]) == 16
    assert slark.verify(marked, KEY) == "signed"


def test_wrong_key_is_invalid():
    marked = slark.encode(SAMPLE, model="m1", key=KEY)
    assert slark.verify(marked, "wrong-key") == "invalid"


def test_unsigned_mark_reports_unsigned():
    marked = slark.encode(SAMPLE, model="m1")
    assert slark.verify(marked, KEY) == "unsigned"


def test_no_mark_reports_none():
    assert slark.verify(SAMPLE, KEY) == "none"


def test_tampered_payload_fails_verification():
    """Re-embedding modified metadata without the key must not verify."""
    marked = slark.encode(SAMPLE, model="m1", key=KEY)
    meta = slark.decode(marked)
    meta["m"] = "totally-different-model"  # forge attempt, keeps old sig
    forged = slark.encode(SAMPLE, metadata=meta)
    assert slark.verify(forged, KEY) == "invalid"


def test_sign_metadata_is_deterministic_and_order_preserving():
    m1 = slark.sign_metadata({"a": 1, "b": 2}, KEY)
    m2 = slark.sign_metadata({"a": 1, "b": 2}, KEY)
    assert m1 == m2
    assert list(m1.keys())[-1] == "sig"  # sig always appended last


def test_verify_meta_direct():
    signed = slark.sign_metadata({"g": "ai", "m": "x"}, KEY)
    assert slark.verify_meta(signed, KEY) is True
    assert slark.verify_meta(signed, "nope") is False
    assert slark.verify_meta({"g": "ai"}, KEY) is False
    assert slark.verify_meta(None, KEY) is False


def test_signed_roundtrip_survives_strip_and_restamp():
    marked = slark.encode(SAMPLE, model="m1", key=KEY)
    restamped = slark.encode(slark.strip(marked), model="m2", key=KEY, replace=True)
    assert slark.verify(restamped, KEY) == "signed"
    assert slark.decode(restamped)["m"] == "m2"


def test_bytes_key_equals_str_key():
    a = slark.encode(SAMPLE, metadata={"x": 1}, key="k")
    b = slark.encode(SAMPLE, metadata={"x": 1}, key=b"k")
    assert slark.decode(a)["sig"] == slark.decode(b)["sig"]


# ---------------- image signing / voting / capacity ----------------


pil = pytest.importorskip("PIL")
from PIL import Image  # noqa: E402

from slark import image as imgmod  # noqa: E402


def make_image(w=200, h=150, alpha=False):
    mode = "RGBA" if alpha else "RGB"
    raw = bytearray()
    for p in range(w * h):
        x, y = p % w, p // w
        raw += bytes([(x * 7 + y * 13) & 255, (x * 5 + y * 29) & 255, (x * 11 + y * 3) & 255, 255])
    return Image.frombytes(mode, (w, h), bytes(raw))


def test_image_signing_roundtrip():
    out = imgmod.encode(make_image(), model="m1", key=KEY)
    assert imgmod.verify(out, KEY) == "signed"
    assert imgmod.verify(out, "wrong") == "invalid"
    unsigned = imgmod.encode(make_image(), model="m1")
    assert imgmod.verify(unsigned, KEY) == "unsigned"
    assert imgmod.verify(make_image(), KEY) == "none"


def test_text_and_image_sigs_interoperate():
    """Same metadata + key produce the same sig in both codecs."""
    meta = {"g": "ai", "ts": 1787322082, "m": "claude-sonnet-5"}
    text_meta = slark.decode(slark.encode("hello world", metadata=dict(meta), key=KEY))
    img_meta = imgmod.decode(imgmod.encode(make_image(), metadata=dict(meta), key=KEY))
    assert text_meta["sig"] == img_meta["sig"]


def test_majority_vote_recovers_when_every_copy_damaged():
    """Flip a DIFFERENT bit in every copy: no copy is intact, but each bit
    is correct in all-but-one copy, so voting reconstructs the tag."""
    out = imgmod.encode(make_image(), metadata={"k": "v"})
    raw = bytearray(out.convert("RGBA").tobytes())
    total_slots = 200 * 150 * 3
    copies = imgmod._copies_for(total_slots, imgmod.RESERVE_BITS)
    assert copies >= 3
    chunk = total_slots // copies
    for c in range(copies):
        pos = c * chunk + c  # different relative offset per copy
        raw[(pos // 3) * 4 + (pos % 3)] ^= 1

    # every individual copy now fails …
    assert imgmod._decode_raw(raw, 200, 150, vote=False) is None
    # … but voting reconstructs it
    found = imgmod._decode_raw(raw, 200, 150, vote=True)
    assert found is not None
    assert found.metadata == {"k": "v"}
    assert found.via_vote is True and found.copy_index == -1


def test_vote_can_be_disabled():
    out = imgmod.encode(make_image(), metadata={"k": "v"})
    raw = bytearray(out.convert("RGBA").tobytes())
    total_slots = 200 * 150 * 3
    copies = imgmod._copies_for(total_slots, imgmod.RESERVE_BITS)
    chunk = total_slots // copies
    for c in range(copies):
        pos = c * chunk + c
        raw[(pos // 3) * 4 + (pos % 3)] ^= 1
    img = Image.frombytes("RGBA", (200, 150), bytes(raw))
    assert imgmod.decode(img, vote=False) is None
    assert imgmod.decode(img, vote=True) == {"k": "v"}


def test_vote_rejects_garbage():
    """Voting must fail closed on a clean image (no false positives)."""
    raw = bytearray(make_image().convert("RGBA").tobytes())
    total_slots = 200 * 150 * 3
    copies = imgmod._copies_for(total_slots, imgmod.RESERVE_BITS)
    chunk = total_slots // copies
    assert imgmod._vote_decode(raw, copies, chunk) is None


def test_erase_defeats_voting_too():
    out = imgmod.encode(make_image(), metadata={"k": "v"})
    clean = imgmod.erase(out)
    assert imgmod.decode(clean, vote=True) is None


def test_capacity_report():
    info = imgmod.capacity(make_image())
    assert info["width"] == 200 and info["height"] == 150
    assert info["total_slots"] == 200 * 150 * 3
    assert info["copies"] == min(512, info["total_slots"] // imgmod.RESERVE_BITS)
    assert info["taggable"] is True

    tiny = imgmod.capacity(make_image(16, 16))
    assert tiny["taggable"] is False and tiny["copies"] == 0


def test_capacity_accepts_path(tmp_path):
    p = tmp_path / "img.png"
    make_image().save(p)
    assert imgmod.capacity(p)["taggable"] is True
