"""Tests for the v0.2 core improvements: emoji-ZWJ robustness,
multi-mark scanning, decode_all, replace, safe strip, payload limits."""

import json

import pytest

from slark import core as wm


SAMPLE = "This article discusses the future of renewable energy."
FAMILY = "\U0001F468\u200d\U0001F469\u200d\U0001F467"  # 👨‍👩‍👧 (ZWJ sequence)


# ---------- emoji / legitimate-ZWJ robustness ----------


def test_decode_survives_emoji_before_watermark():
    """A ZWJ emoji EARLIER in the text used to poison the naive first-pair
    decoder. The scanner must skip unverifiable spans and find the real one."""
    text = f"Family {FAMILY} photo caption with more words here."
    marked = wm.encode(text, model="claude-sonnet-5")
    meta = wm.decode(marked)
    assert meta is not None
    assert meta["m"] == "claude-sonnet-5"


def test_decode_survives_emoji_after_watermark():
    marked = wm.encode(SAMPLE, model="m1") + f" love it {FAMILY}{FAMILY}"
    assert wm.decode(marked)["m"] == "m1"


def test_decode_survives_emoji_on_both_sides():
    marked = FAMILY + " " + wm.encode(SAMPLE, model="m2") + " " + FAMILY
    assert wm.decode(marked)["m"] == "m2"


def test_strip_preserves_emoji_zwj_sequences():
    text = f"Family {FAMILY} photo."
    marked = wm.encode(text, model="x")
    stripped = wm.strip(marked)
    assert stripped == text          # emoji intact, watermark gone
    assert FAMILY in stripped
    assert wm.decode(stripped) is None


def test_strip_aggressive_removes_all_zero_width():
    text = f"Family {FAMILY} photo."
    marked = wm.encode(text, model="x")
    stripped = wm.strip(marked, aggressive=True)
    assert "\u200d" not in stripped
    assert "\u200b" not in stripped and "\u200c" not in stripped


def test_strip_removes_stray_bit_chars():
    """Leftover ZWSP/ZWNJ from a mangled mark still get cleaned up."""
    dirty = "Hello\u200b\u200c world\u200b"
    assert wm.strip(dirty) == "Hello world"


def test_count_hidden_chars_matches_strip_delta():
    text = f"Family {FAMILY} photo."
    marked = wm.encode(text, model="x")
    assert wm.count_hidden_chars(marked) == len(marked) - len(wm.strip(marked))
    # plain emoji text: nothing to remove
    assert wm.count_hidden_chars(text) == 0


# ---------- multiple marks / decode_all ----------


def test_decode_all_finds_multiple_marks():
    a = wm.encode("First sentence here.", metadata={"id": 1})
    b = wm.encode("Second sentence here.", metadata={"id": 2})
    combined = a + " " + b
    metas = wm.decode_all(combined)
    assert metas == [{"id": 1}, {"id": 2}]
    assert wm.decode(combined) == {"id": 1}


def test_decode_all_empty_for_plain_text():
    assert wm.decode_all(SAMPLE) == []
    assert wm.decode_all("") == []


def test_encode_replace_leaves_single_mark():
    once = wm.encode(SAMPLE, metadata={"v": 1})
    twice = wm.encode(once, metadata={"v": 2}, replace=True)
    metas = wm.decode_all(twice)
    assert metas == [{"v": 2}]
    assert wm.strip(twice) == SAMPLE


def test_encode_without_replace_stacks_marks():
    once = wm.encode(SAMPLE, metadata={"v": 1})
    twice = wm.encode(once, metadata={"v": 2})
    assert len(wm.decode_all(twice)) == 2


# ---------- guards / fail-closed behavior ----------


def test_oversized_payload_raises():
    with pytest.raises(ValueError):
        wm.encode(SAMPLE, metadata={"blob": "x" * 70000})


def test_non_dict_payload_rejected_on_decode():
    """A frame whose JSON isn't an object must not decode as a watermark."""
    framed = wm._frame_payload(json.dumps([1, 2, 3]).encode())
    text = "Hello " + wm._payload_to_zerowidth(framed) + "world"
    assert wm.decode(text) is None


def test_sentinels_without_bits_return_none():
    assert wm.decode("a\u200d\u200db") is None


def test_tampered_mark_then_valid_mark_still_decodes():
    """A corrupted first mark must not mask a valid later one."""
    good = wm.encode("Second part of text.", metadata={"ok": True})
    # build a corrupt span: sentinel + garbage bits + sentinel
    corrupt = "\u200d" + "\u200c" * 40 + "\u200d"
    combined = "Lead " + corrupt + " middle " + good
    assert wm.decode(combined) == {"ok": True}
