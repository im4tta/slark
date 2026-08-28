# Slark

Invisible text watermarking — embed a hidden, checksum-verified payload into
any text using zero-width Unicode characters. The visible text is unchanged;
the mark travels with the text as long as those characters survive.
The web playground applies the same idea to images, hiding tags in the
least-significant bits of PNG pixels.

Since v0.4 it also works in reverse: `slark scan` answers the *inverse*
question — **"has any tool hidden a payload in this text or image?"** —
detecting Stable Diffusion's frequency-domain watermark, invisible-Unicode
smuggling, homoglyph substitution, LSB steganography and C2PA/generator
metadata, whoever produced them.

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

Because U+200D also occurs in legitimate text (emoji ZWJ sequences like
👨‍👩‍👧), the decoder scans **every** sentinel pair and only accepts spans
whose checksum verifies — emoji anywhere in the text never break decoding,
and `strip()` removes only verified marks, leaving emoji intact.

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

slark.strip(marked)  # returns the original clean text (emoji-safe)
slark.strip(marked, aggressive=True)  # also removes ALL zero-width joiners

slark.decode_all(text)  # every verified mark in the text, in order
```

Re-stamping without stacking marks:

```python
slark.encode(already_marked, model="new-model", replace=True)
# old mark removed, exactly one mark present
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

image.decode_info("photo-marked.png")    # (metadata, copy_index, total_copies)
image.erase("photo-marked.png").save("clean.png")  # scrub the tag (≤1/255 per touched channel)
```

CLI:

```bash
slark encode-image --file photo.png --model claude-sonnet-5 --output out.png
slark decode-image --file out.png    # pretty JSON (+ which redundant copy verified)
slark decode-image --file out.png --json   # single-line machine-readable JSON
slark check-image --file out.png     # exit code 0 = watermarked, 1 = not
slark strip-image --file out.png --output clean.png   # erase the tag
```

> **Keep it PNG end-to-end.** Every lossy hop — JPEG, WebP, screenshots,
> most social platforms' re-encoding — rewrites low-order bits and strips
> the tag by design. This is provenance marking, not DRM.


## Detecting *other* tools' watermarks (v0.4)

Everything above marks *your* content. `slark.detect` does the opposite: it
scans content you did not create and reports what it finds — from Slark, and
from other tools.

```bash
pip install "slark[detect]"       # adds numpy + pillow
```

```python
import slark

report = slark.scan_text(suspicious_text)
report.verdict          # 'watermarked' | 'suspicious' | 'clean' | 'inconclusive'
report.confidence       # 0..1, from the strongest finding
report.attributions()   # e.g. ['Stable Diffusion 1.x']

for f in report.detected:
    print(f.technique, f.detail, f.evidence)

slark.scan_image("photo.png").attributions()   # ['Midjourney']
slark.scan(anything)                           # dispatches on type
```

CLI:

```bash
slark scan --file suspicious.txt          # human-readable report
slark scan --file photo.png               # images auto-detected by extension
slark scan --text "..." --json            # machine-readable
slark scan --file x.txt --verbose         # include raw evidence
cat article.txt | slark scan              # reads stdin
```

Exit codes: `0` something detected, `1` clean, `3` suspicious only,
`4` inconclusive (nothing found, but some detectors could not run).

### What it detects

**Text**

| Technique | What it finds |
|---|---|
| `slark_zero_width` | Slark's own checksum-verified marks |
| `invisible_unicode_payload` | zero-width payloads from *other* tools |
| `unicode_tag_chars` | U+E0000 TAG-block ASCII smuggling — **decoded back to plaintext** |
| `variation_selectors` | data hidden in variation selectors |
| `homoglyph_substitution` | Cyrillic/Greek/fullwidth lookalikes swapped into ASCII words |
| `bidi_controls` | bidi overrides / Trojan Source |
| `lookalike_whitespace` | non-standard spaces used as a bit channel |

**Images**

| Technique | What it finds |
|---|---|
| `dwt_dct` | the DWT-DCT mark `invisible-watermark` embeds — **Stable Diffusion's default** |
| `slark_slk1` | Slark's own SLK1 pixel tag |
| `lsb_redundancy` | repeated frames in the LSB plane (any redundant LSB tool) |
| `lsb_anomaly` | an LSB plane too uniform to be natural |
| `container_metadata` | C2PA / XMP / EXIF / PNG text naming ~25 generators |
| `generation_parameters` | diffusion params (`Steps:`, `Sampler:`, `CFG scale`…) |

### Two design decisions worth knowing

**Findings carry evidence, not just verdicts.** Every finding exposes the raw
measurement behind it (bit error rate, agreement ratio, decoded bytes), so a
result can be audited rather than trusted blindly.

**"Unknown" is never reported as "clean".** Detectors that cannot run report
`status="unavailable"`, which makes the verdict `inconclusive` instead of
`clean`. Notably:

- **Statistical token-sampling watermarks** (Google SynthID-Text and similar)
  are keyed. Without the provider's secret there is no public test — any tool
  claiming otherwise is guessing.
- **Neural pixel watermarks** (SynthID-Image) need the vendor's private
  detector model. Metadata *naming* SynthID is found; the pixel mark is not
  verified.

Pass `include_notes=False` (or `--no-notes`) to suppress those and get a
plain `clean` verdict.

### Accuracy, measured

The DWT-DCT reader is reimplemented in pure numpy and validated **bit-exact
against the reference `invisible-watermark` library**: it recovers the exact
payload `b"StableDiffusionV1"` from reference-encoded images. Both directions
are cross-checked in the test suite when that library is installed.

| Input | Bit error | Result |
|---|---|---|
| reference-encoded watermark | ~0.08–0.11 | detected |
| clean image | ~0.43–0.50 (chance) | not detected |

On a synthetic set of photo / noise / flat / gradient images: **20/20 true
positives, 0/20 false positives.**

Robustness of the DWT-DCT mark (inherited from the algorithm, not the
detector — the reference decoder fails on exactly the same inputs):

| Transformation | Survives |
|---|---|
| brightness shift, 3×3 blur, mild Gaussian noise | ✅ |
| JPEG (any quality), resize, crop | ❌ |

So a *negative* image result means "no detectable mark in these pixels" —
not "this wasn't AI-generated". Lossy re-encoding erases these marks by
design.

### Honest limits

- **Metadata is declared, not proven.** `container_metadata` findings mean a
  file *says* which tool made it. That is trivially stripped and trivially
  forged. C2PA manifest presence is reported; its cryptographic signature is
  **not** validated (that needs the full trust list).
- **Nothing here proves absence.** These detectors find *structural* traces.
  Retyping, paraphrasing, screenshotting or re-encoding removes most of them.
- **Not a general "was this AI-written?" detector.** It finds deliberately
  embedded payloads. Text with no watermark returns `inconclusive`, which is
  the honest answer — not evidence of human authorship.

### CLI

```bash
slark encode --text "Hello world" --model claude-sonnet-5 --output out.txt
slark encode --file out.txt --model new-model --replace   # swap the mark, don't stack
slark decode --file out.txt
slark decode --file out.txt --json      # single-line JSON (prints `null` if clean)
slark decode --file out.txt --all       # every mark in the text
slark check --file out.txt      # exit code 0 = watermarked, 1 = not
slark strip --file out.txt --output clean.txt
slark strip --file out.txt --aggressive  # also remove ALL ZWJs (breaks emoji)
```

Text subcommands read stdin when neither `--text` nor `--file` is given,
so they pipe:

```bash
echo "Hello world" | slark encode --model gpt-5 | slark decode --json
```

Exit codes: `0` success/watermarked, `1` no watermark, `2` usage or
dependency error.

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

## Changelog

### 0.4.0
- **`slark.detect` — detect other tools' watermarks.** `scan_text()`,
  `scan_image()`, `scan()` return a `Report` of `Finding` objects carrying
  calibrated confidence *and* the raw evidence behind each call.
- **Stable Diffusion DWT-DCT reader**, reimplemented in pure numpy and
  validated bit-exact against the reference `invisible-watermark` library
  (recovers `b"StableDiffusionV1"`; 20/20 true positives, 0/20 false
  positives on a synthetic image set).
- **New text detectors**: foreign zero-width payloads, Unicode TAG-block
  ASCII smuggling (decoded to plaintext), variation-selector stego,
  homoglyph substitution, bidi/Trojan-Source, lookalike whitespace.
- **New image detectors**: redundant-LSB frame structure (format-agnostic),
  LSB-plane anomaly analysis, and C2PA/XMP/EXIF/PNG metadata for ~25
  generators plus diffusion parameter keys.
- **Fail-open honesty**: untestable classes (keyed statistical watermarks,
  neural pixel marks) report `unavailable`, so the verdict is
  `inconclusive` rather than an overstated `clean`.
- **New `slark scan` CLI** with `--json`, `--verbose`, `--no-notes` and
  distinct exit codes (0/1/3/4).
- **Playground**: two new "Detect others" tabs, running the same detectors
  in-browser with verified Python↔JS parity.
- 62 new tests (146 total).

### 0.3.0
- **Signed marks** — `encode(..., key=...)` adds a truncated HMAC-SHA256
  `sig` field; `verify(text, key)` classifies a mark as `signed` /
  `invalid` / `unsigned` / `none`. The CRC32 guards against accidental
  corruption; the HMAC guards against deliberate forgery.
- **Majority-vote image recovery** — `image.decode()` reconstructs a payload
  bit-by-bit across all redundant copies when no single copy survives.
- **`image.capacity()`** and richer `DecodeResult` (`via_vote`).
- **New CLI**: `verify`, `verify-image`, `capacity`, `--key`, `--no-vote`.
- 21 new tests (84 total).

### 0.2.0
- **Emoji-safe decoding** — the decoder now scans every sentinel pair and
  only accepts checksum-verified spans, so ZWJ emoji (👨‍👩‍👧, 🏳️‍🌈) anywhere
  in the text can no longer prevent a mark from being found.
- **Emoji-safe `strip()`** — removes only verified marks plus stray bit
  characters; emoji ZWJ sequences survive. Old blunt behavior available via
  `strip(text, aggressive=True)` / `slark strip --aggressive`.
- **`decode_all()`** — recover every mark in a text; `slark decode --all`.
- **`encode(..., replace=True)`** — re-stamp without stacking marks;
  `slark encode --replace`.
- **Fail-closed hardening** — non-object JSON payloads are rejected in both
  the text and image decoders (and in the playground JS).
- **`image.erase()`** — scrub an image tag by zeroing only the magic-bit
  LSBs (≤1/255 per touched channel); `slark strip-image`.
- **New CLI** — `decode-image`, `strip-image`, `--json` machine output,
  `--version`, JSON validation for `--extra`, documented exit codes.
- **Playground** — same emoji-safe scanning ported to the browser, plus an
  "Emoji ZWJ neighbors" robustness-lab test.
- 32 new tests (63 total), including CLI integration tests and Python↔JS
  parity checks.

### 0.1.0
- Initial release.
