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
| `dwt_dct_svd` | the same library's `dwtDctSvd` mode — markedly **more robust**, used by several SD forks |
| `rivagan` | `invisible-watermark`'s learned 32-bit mode — scored **only with an expected payload** (keyed; see below) |
| `slark_slk1` | Slark's own SLK1 pixel tag |
| `lsb_redundancy` | repeated frames in the LSB plane (any redundant LSB tool) |
| `lsb_anomaly` | an LSB plane too uniform to be natural |
| `container_metadata` | C2PA / XMP / EXIF / PNG text: ~30 generators, IPTC `digitalSourceType`, and tools that never write their own name |
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
- **RivaGAN** is keyed. Given the expected 32 bits we score it for real; with
  no key we report `unavailable`. Blind RivaGAN detection was implemented,
  measured, and **rejected** — see below.

Pass `include_notes=False` (or `--no-notes`) to suppress those and get a
plain `clean` verdict.

### Accuracy, measured

Every threshold below was picked from a *measured* separation between true and
false positives, never guessed. All three `invisible-watermark` algorithms are
reimplemented in pure numpy and cross-checked against the reference library's
own decoder on library-generated fixtures.

**`dwt_dct`** (Stable Diffusion's default) — recovers the exact payload
`b"StableDiffusionV1"` from reference-encoded images:

| Input | Bit error | Result |
|---|---|---|
| reference-encoded watermark | ~0.08–0.11 | detected |
| clean image | ~0.43–0.50 (chance) | not detected |

**`dwt_dct_svd`** — our reader agrees with the reference decoder on
**100.00% of bits**, giving *zero* bit error on payload recovery. The
separation is total, so the 0.20 threshold sits inside a wide empty gap:

| Population | n | Bit error | Result |
|---|---|---|---|
| watermarked (reference-encoded) | 24 | **0.0000** (all) | detected |
| photos, noise, flat fills, gradients, `dwtDct`-marked | 21 | ≥ 0.3125 | not detected |

On identical images `dwt_dct` manages only ~0.30 bit error where `dwtDctSvd`
reaches 0.000 — the SVD mode really is the more robust of the two, which is
why forks that want the mark to survive editing choose it.

**`rivagan`** — keyed mode only, scored against an expected 32-bit payload:

| Population | n | Bit error |
|---|---|---|
| true positives | 15 | ≤ 0.344 |
| negatives incl. **wrong-key** marked images | 23 | ≥ 0.406 |

The 0.25 threshold comes from the binomial null rather than that gap: at
8/32 bits the chance a random image matches a given key is 3.5e-03, for 87%
recall on measured true positives. JPEG q95→q70 costs 0.062–0.156 bit error.

**Why RivaGAN has no blind mode.** Three blind statistics were implemented and
measured, and all three failed:

| Attempted statistic | Marked | Unmarked | Verdict |
|---|---|---|---|
| decoder logit magnitude | 9.4–13.5 | photos 0.77–1.13, but **noise 9.9–14.2, textures 13.7–18.4** | overlaps |
| + spatial-roughness guard | — | excludes noise, **not textures** | insufficient |
| bit stability under ±2 / JPEG q92 | 0.953–0.992 | clean textures **0.984–1.000** | overlaps |

The network reports high confidence on out-of-distribution input it has never
watermarked. Shipping a blind verdict would mean claiming accuracy we measured
and could not achieve — so blind mode returns `unavailable`.

**Metadata signatures, validated against real files.** The signature list was
rebuilt from observed bytes: real signed C2PA JPEGs (the `c2pa-rs` and
`c2pa-org/public-testfiles` corpora), the IPTC `digitalsourcetype` vocabulary,
and the metadata-writing source of ComfyUI and AUTOMATIC1111. That pass found
two real bugs in the previous guessed list:

1. **The most authoritative AI marker was missing entirely.** Real manifests
   declare generative origin with an IPTC URI (`trainedAlgorithmicMedia`,
   `algorithmicMedia`, …). ComfyUI and IPTC fixtures both returned
   `inconclusive`. Also confirmed by reading their writers: ComfyUI never
   writes the string "comfyui" (it writes `prompt`/`workflow` chunks) and
   AUTOMATIC1111 never writes its own name (just a `parameters` chunk) — so
   both are now identified by chunk key.
2. **6 of 6 innocent captions were falsely attributed to AI**, because bare
   dictionary words matched anywhere in the file: *"una **imagen** de mi
   perro"* → Google Imagen, *"magnetic **flux**"* → FLUX, *"I finally
   **grok** this lens"* → xAI Grok, *"a **firefly** at dusk"* → Adobe Firefly,
   *"the **Gemini** constellation"* → Google Gemini.

Ambiguous names now only count inside a field that actually *asserts*
provenance (`Software`, `CreatorTool`, `claim_generator`, `softwareAgent`, …)
and never inside free-text captions. Result after the fix: **11/11 true
positives, 0/10 false positives**, with all five real C2PA files attributed
correctly (and `cloud.jpg`, which carries no such claim, correctly
`inconclusive`).

Robustness of these marks (inherited from the algorithms, not the detectors —
the reference decoders fail on exactly the same inputs):

| Transformation | `dwt_dct` | `dwt_dct_svd` | `rivagan` |
|---|---|---|---|
| brightness shift, 3×3 blur, mild noise | ✅ | ✅ | ✅ |
| JPEG q70–q95 | ❌ | ❌ | ✅ (0.06–0.16 BER) |
| resize, crop | ❌ | ❌ | ❌ |

So a *negative* image result means "no detectable mark in these pixels" —
not "this wasn't AI-generated". Lossy re-encoding erases most of these marks
by design.

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
- **`dwtDctSvd` reader** (`detect_dwt_dct_svd`) — the library's more robust
  classical mode, reimplemented in numpy at **100.00% bit agreement** with
  the reference decoder (0.000 BER payload recovery; negatives ≥ 0.3125).
- **`rivagan` reader** (`detect_rivagan`) — runs the vendor ONNX decoder
  without torch. Keyed scoring is real (threshold from the binomial null,
  P=3.5e-03); **blind detection was implemented, measured and rejected**
  because the decoder is equally confident on unmarked noise and textures,
  so it reports `unavailable` instead of guessing.
- **Metadata signatures rebuilt from real files** — added IPTC
  `digitalSourceType`, and chunk-key identification for ComfyUI and
  AUTOMATIC1111 (neither writes its own name). Fixed **6/6 false positives**
  on ordinary captions by scoping ambiguous names ("imagen", "flux", "grok",
  "firefly", "gemini") to provenance-asserting fields only. Now 11/11 true
  positives, 0/10 false positives.
- Optional `slark[rivagan]` extra for `onnxruntime`.
- 33 further tests (179 total), and Python↔JS parity re-verified bit-for-bit
  on library-generated fixtures.

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
