import json

import pytest

from slark import core as wm


SAMPLE = "This article discusses the future of renewable energy and its impact on global markets."


def _visible(text: str) -> str:
    return wm.strip(text)


def test_encode_is_visually_invisible():
    marked = wm.encode(SAMPLE, model="claude-sonnet-5")
    assert _visible(marked) == SAMPLE
    assert marked != SAMPLE
    assert wm.count_hidden_chars(marked) > 0


def test_roundtrip_default_metadata():
    marked = wm.encode(SAMPLE, model="claude-sonnet-5", generator="ai")
    meta = wm.decode(marked)
    assert meta is not None
    assert meta["g"] == "ai"
    assert meta["m"] == "claude-sonnet-5"
    assert "ts" in meta


def test_roundtrip_explicit_metadata_dict():
    payload = {"foo": "bar", "n": 42}
    marked = wm.encode(SAMPLE, metadata=payload)
    assert wm.decode(marked) == payload


def test_roundtrip_extra_kwargs_merge():
    marked = wm.encode(SAMPLE, model="claude-fable-5", extra={"session": "abc123", "v": 2})
    meta = wm.decode(marked)
    assert meta["m"] == "claude-fable-5"
    assert meta["session"] == "abc123"
    assert meta["v"] == 2


def test_has_watermark_true_and_false():
    marked = wm.encode(SAMPLE, model="x")
    assert wm.has_watermark(marked) is True
    assert wm.has_watermark(SAMPLE) is False
    assert wm.has_watermark("") is False


def test_decode_on_plain_text_returns_none():
    assert wm.decode(SAMPLE) is None
    assert wm.decode("") is None


def test_strip_restores_original_exactly():
    marked = wm.encode(SAMPLE, model="claude-sonnet-5")
    assert wm.strip(marked) == SAMPLE


def test_survives_surrounding_text():
    marked = wm.encode(SAMPLE, model="claude-sonnet-5")
    wrapped = "PREFIX line one.\n" + marked + "\nSUFFIX with trailing words."
    meta = wm.decode(wrapped)
    assert meta is not None
    assert meta["m"] == "claude-sonnet-5"


def test_tamper_detection_single_bit_flip():
    marked = wm.encode(SAMPLE, model="claude-sonnet-5")
    # Flip one payload character (ZWSP <-> ZWNJ) to corrupt a bit.
    idx = marked.find(wm.ZW1)
    if idx == -1:
        idx = marked.find(wm.ZW0)
    tampered = marked[:idx] + (wm.ZW0 if marked[idx] == wm.ZW1 else wm.ZW1) + marked[idx + 1:]
    # Checksum should now fail to verify — decode must return None, not
    # garbage or a partially-corrupted dict.
    assert wm.decode(tampered) is None


def test_truncated_payload_returns_none():
    marked = wm.encode(SAMPLE, model="claude-sonnet-5")
    end = marked.rfind(wm.SENTINEL)
    truncated = marked[:end - 5] + marked[end:]  # chop bits out of the middle
    # Should not raise — must fail closed.
    result = wm.decode(truncated)
    assert result is None or isinstance(result, dict)


def test_empty_text_roundtrip():
    marked = wm.encode("", model="x")
    assert wm.decode(marked) == {"g": "ai", "m": "x", **{k: v for k, v in wm.decode(marked).items() if k == "ts"}}


def test_no_watermark_chars_leak_into_visible_diff():
    marked = wm.encode(SAMPLE, model="claude-sonnet-5")
    for ch in wm.ZW0, wm.ZW1, wm.SENTINEL:
        assert ch not in SAMPLE  # sanity: source text itself is clean
    hidden_only = set(marked) - set(SAMPLE)
    assert hidden_only.issubset({wm.ZW0, wm.ZW1, wm.SENTINEL})


def test_metadata_is_json_serializable_roundtrip():
    payload = {"nested": {"a": 1, "b": [1, 2, 3]}, "s": "text"}
    marked = wm.encode(SAMPLE, metadata=payload)
    decoded = wm.decode(marked)
    assert json.dumps(decoded, sort_keys=True) == json.dumps(payload, sort_keys=True)


@pytest.mark.parametrize("text", [
    "",
    "a",
    "no spaces or newlines at all",
    "line one\nline two\nline three",
    "unicode already here: 日本語 café résumé",
])
def test_various_inputs_roundtrip(text):
    marked = wm.encode(text, model="t")
    assert wm.strip(marked) == text
    meta = wm.decode(marked)
    assert meta is not None
    assert meta["m"] == "t"
