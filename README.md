# Slark

Invisible text watermarking — embed a hidden, checksum-verified payload into
any text using zero-width Unicode characters. The visible text is unchanged;
the mark travels with the text as long as those characters survive.
The web playground applies the same idea to images, hiding tags in the
least-significant bits of PNG pixels.

The name is a nod to *"slak"* (ស្លាក), Khmer for **tag** or **label** —
which is exactly what this attaches, invisibly.

**Live playground:** [im4tta.github.io/slark](https://im4tta.github.io/slark/)

Originally built to mark AI/LLM-generated text with provenance metadata
(model name, timestamp), but the payload is arbitrary JSON — use it for
leak-tracing, authorship tagging, or any lightweight text provenance need.

## How it works

Each byte of a small JSON payload (plus a length prefix and a CRC32
checksum) is converted to bits. Each bit becomes one of two invisible
Unicode characters, wrapped in zero-width-joiner sentinels so a decoder can
locate the payload anywhere in the text:

| Character | Unicode | Meaning |
|---|---|---|
| Zero Width Space | U+200B | bit `0` |
| Zero Width Non-Joiner | U+200C | bit `1` |
| Zero Width Joiner | U+200D | payload start/end sentinel |

The payload is inserted once, right after the first whitespace character.
None of these characters render a glyph, so the text reads, copies, and
displays identically — but `decode()` can recover the hidden metadata, and
verifies it against the embedded checksum before returning anything.

## Install

```bash
pip install slark
```

Or from source:

```bash
git clone https://github.com/im4tta/slark
cd slark
pip install -e ".[dev]"
```

## Usage

### Library

```python
import slark

marked = slark.encode("Renewable energy adoption is accelerating.", model="claude-sonnet-5")
marked == "Renewable energy adoption is accelerating."  # False — but looks identical when printed

slark.decode(marked)
# {'g': 'ai', 'ts': 1787322082, 'm': 'claude-sonnet-5'}

slark.has_watermark(marked)   # True
slark.has_watermark("plain text")  # False

slark.strip(marked)  # returns the original clean text
```

Arbitrary metadata:

```python
slark.encode(text, metadata={"session": "abc123", "reviewed": True})
```

### Images (PNG, optional extra)

The same hidden-tag idea for images: the payload is written into the least-
significant bit of each pixel's R/G/B channels — every channel shifts by at
most 1/255, invisible to any eye. The frame is embedded redundantly (up to
512 copies), so local damage rarely destroys every copy, and the checksum is
verified before anything is believed. Format matches the web playground
exactly — files stamp in one and decode in the other.

```bash
pip install "slark[image]"
```

```python
from slark import image

marked = image.encode("photo.png", model="claude-sonnet-5")
marked.save("photo-marked.png")          # PNG only — JPEG erases the tag

image.decode("photo-marked.png")
# {'g': 'ai', 'ts': 1787322082, 'm': 'claude-sonnet-5'}

image.has_watermark("photo.png")         # False
```

CLI:

```bash
slark encode-image --file photo.png --model claude-sonnet-5 --output out.png
slark check-image --file out.png     # exit code 0 = watermarked, 1 = not
```

> **Keep it PNG end-to-end.** Every lossy hop — JPEG, WebP, screenshots,
> most social platforms' re-encoding — rewrites low-order bits and strips
> the tag by design. This is provenance marking, not DRM.

### CLI

```bash
slark encode --text "Hello world" --model claude-sonnet-5 --output out.txt
slark decode --file out.txt
slark check --file out.txt      # exit code 0 = watermarked, 1 = not
slark strip --file out.txt --output clean.txt
```

## Running tests

```bash
pip install -e ".[dev]"
pytest
```

## Limitations — read before relying on this

This is a lightweight provenance tag, **not tamper-proof DRM**:

- **Zero-width characters get stripped by a lot of real-world pipelines** —
  many chat UIs, some CMS/sanitizers, and some copy-paste paths normalize or
  strip invisible Unicode. If the surface you're publishing to does this,
  the mark won't survive.
- **Doesn't survive retyping or translation.** If a human retypes the text
  or it goes through machine translation, the hidden payload is gone.
  There's no statistical signal in the wording itself.
- **Not adversarially robust.** Anyone who knows this technique exists can
  trivially strip it with `slark.strip()` or any zero-width-character filter.
  It protects against accidental loss of provenance, not a motivated actor
  trying to remove it.
- **For adversarially robust AI-text watermarking** (surviving paraphrasing,
  translation, and deliberate removal attempts), you'd want a statistical
  watermark baked into token sampling at generation time — a fundamentally
  different and heavier approach.

Use this where you control the text pipeline end-to-end and just need a
low-friction "this came from X" tag — not where you need to prove provenance
against someone actively trying to hide it.

## License

MIT — see [LICENSE](LICENSE).
