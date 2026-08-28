"""
detect.py — detect *other* tools' watermarks and hidden-payload techniques.

Slark's own ``core``/``image`` modules answer "is *my* mark here?". This
module answers the broader question: **"has anything hidden a payload in
this text or image?"** — including marks left by other AI tools,
steganography libraries, and generator metadata.

Design principles
-----------------
1. **Evidence, not verdicts.** Every detector returns a ``Finding`` with a
   calibrated confidence and the raw evidence behind it, so a caller can
   audit *why* something was flagged instead of trusting a boolean.
2. **Fail quiet, not loud.** A detector that cannot run (missing numpy,
   unreadable file) is reported as ``unavailable`` — never as "clean".
   Silence and absence are different answers.
3. **Calibrated against ground truth.** The DWT-DCT reader below was
   validated bit-for-bit against the reference ``invisible-watermark``
   implementation used by Stable Diffusion: it recovers the exact payload
   ``b"StableDiffusionV1"`` and returns near-chance bit error on clean
   images. Thresholds here come from those measurements, not guesswork.

What it can and cannot do
-------------------------
Detectable: payload-bearing techniques that leave a *structural* trace —
zero-width/invisible Unicode, Unicode TAG-character smuggling, homoglyph
substitution, bidi controls, redundant LSB frames, DWT-DCT quantization
marks, and generator metadata (C2PA/XMP/EXIF/PNG text).

**Not** detectable: statistical token-sampling watermarks such as Google
SynthID-Text or OpenAI-style sampling marks. Those are keyed — without the
provider's secret key there is no public test, and any tool claiming to
detect them from the text alone is guessing. ``scan_text`` reports this
class as ``unavailable`` rather than pretending. Likewise SynthID for
images is a learned model, not a public format: metadata naming it can be
found, but the pixel mark itself cannot be verified here.

Public API::

    scan_text(text)                 -> Report
    scan_image(source)              -> Report
    scan(obj)                       -> Report        (dispatches on type)
    detect_dwt_dct(source)          -> Finding | None
    detect_lsb_redundancy(source)   -> Finding | None
    detect_image_metadata(source)   -> list[Finding]
"""

from __future__ import annotations

import json
import re
import struct
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import core as _core

# --------------------------------------------------------------- constants

#: Confidence levels are coarse on purpose — a detector claiming "0.87"
#: implies precision these heuristics do not have.
HIGH = 0.95      # a payload was decoded / a known signature matched
MEDIUM = 0.60    # a strong structural anomaly, but no payload recovered
LOW = 0.25       # weak/ambiguous signal, worth reporting but not asserting


@dataclass
class Finding:
    """One piece of evidence about hidden content.

    Attributes:
        technique: stable machine-readable id (e.g. ``"dwt_dct"``).
        label: short human-readable name.
        confidence: 0..1 — see HIGH/MEDIUM/LOW. ``0.0`` with
            ``status="unavailable"`` means "could not test", not "clean".
        detail: one-line explanation of what was actually observed.
        attribution: the tool/model this points to, when identifiable.
        evidence: structured raw measurements backing the finding.
        status: ``"detected"`` | ``"suspicious"`` | ``"unavailable"``.
    """
    technique: str
    label: str
    confidence: float
    detail: str
    attribution: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    status: str = "detected"

    def to_dict(self) -> dict:
        return {
            "technique": self.technique,
            "label": self.label,
            "confidence": round(self.confidence, 3),
            "detail": self.detail,
            "attribution": self.attribution,
            "evidence": self.evidence,
            "status": self.status,
        }


@dataclass
class Report:
    """Aggregate result of a scan.

    ``findings`` holds everything observed. ``verdict`` summarises:
        "watermarked"  — a payload was decoded or a known signature matched
        "suspicious"   — structural anomalies, nothing decoded
        "clean"        — every detector ran and found nothing
        "inconclusive" — nothing found, but some detectors could not run
    """
    target: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def detected(self) -> List[Finding]:
        return [f for f in self.findings if f.status == "detected"]

    @property
    def suspicious(self) -> List[Finding]:
        return [f for f in self.findings if f.status == "suspicious"]

    @property
    def unavailable(self) -> List[Finding]:
        return [f for f in self.findings if f.status == "unavailable"]

    @property
    def verdict(self) -> str:
        if self.detected:
            return "watermarked"
        if self.suspicious:
            return "suspicious"
        return "inconclusive" if self.unavailable else "clean"

    @property
    def confidence(self) -> float:
        """Confidence of the strongest actionable finding (0.0 if none)."""
        pool = self.detected or self.suspicious
        return max((f.confidence for f in pool), default=0.0)

    def attributions(self) -> List[str]:
        """Distinct tools/models implicated, strongest first."""
        seen: List[str] = []
        for f in sorted(self.findings, key=lambda f: -f.confidence):
            if f.attribution and f.attribution not in seen:
                seen.append(f.attribution)
        return seen

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "attributions": self.attributions(),
            "findings": [f.to_dict() for f in self.findings],
        }

    def __bool__(self) -> bool:  # truthy when something was actually found
        return bool(self.detected)


# =============================================================== TEXT
#
# Invisible / non-rendering characters used to carry payloads. Slark's own
# scheme uses only U+200B/C/D; other tools use a wider set, and several of
# these also appear in prompt-injection and leak-tracing payloads.

INVISIBLE_CHARS: Dict[str, str] = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u00ad": "SOFT HYPHEN",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u2061": "FUNCTION APPLICATION",
    "\u2062": "INVISIBLE TIMES",
    "\u2063": "INVISIBLE SEPARATOR",
    "\u2064": "INVISIBLE PLUS",
    "\u061c": "ARABIC LETTER MARK",
    "\u115f": "HANGUL CHOSEONG FILLER",
    "\u1160": "HANGUL JUNGSEONG FILLER",
    "\u3164": "HANGUL FILLER",
    "\uffa0": "HALFWIDTH HANGUL FILLER",
}

#: Bidirectional controls. Invisible, and able to reorder rendered text —
#: the "Trojan Source" class of attack, not just watermarking.
BIDI_CHARS: Dict[str, str] = {
    "\u200e": "LEFT-TO-RIGHT MARK",
    "\u200f": "RIGHT-TO-LEFT MARK",
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

#: Cyrillic/Greek/punctuation lookalikes for ASCII. A cheap, survivable
#: channel: substituting these encodes bits that live through copy-paste
#: and even most sanitizers, unlike zero-width characters.
HOMOGLYPHS: Dict[str, str] = {
    # Cyrillic uppercase
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X", "\u0406": "I", "\u0408": "J", "\u0405": "S",
    # Cyrillic lowercase
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    # Greek
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O",
    "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X", "\u03bf": "o",
    # Fullwidth Latin
    **{chr(0xFF21 + i): chr(ord("A") + i) for i in range(26)},
    **{chr(0xFF41 + i): chr(ord("a") + i) for i in range(26)},
}

#: Lookalike spaces and dashes. Used both as a watermark channel and to
#: defeat naive string matching.
LOOKALIKE_PUNCT: Dict[str, str] = {
    "\u00a0": "NO-BREAK SPACE",
    "\u2007": "FIGURE SPACE",
    "\u2008": "PUNCTUATION SPACE",
    "\u2009": "THIN SPACE",
    "\u200a": "HAIR SPACE",
    "\u202f": "NARROW NO-BREAK SPACE",
    "\u205f": "MEDIUM MATHEMATICAL SPACE",
    "\u3000": "IDEOGRAPHIC SPACE",
    "\u2010": "HYPHEN",
    "\u2011": "NON-BREAKING HYPHEN",
    "\u2012": "FIGURE DASH",
    "\u2013": "EN DASH",
    "\u2014": "EM DASH",
    "\u2212": "MINUS SIGN",
}

_TAG_BASE = 0xE0000          # Unicode TAG block: E0000..E007F
_VS_RANGE = (0xFE00, 0xFE0F)  # variation selectors 1..16
_VSUP_RANGE = (0xE0100, 0xE01EF)  # variation selectors 17..256


def _positions(text: str, table: Dict[str, str]) -> List[Tuple[int, str, str]]:
    return [(i, ch, table[ch]) for i, ch in enumerate(text) if ch in table]


def _counter(items: Iterable[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for it in items:
        out[it] = out.get(it, 0) + 1
    return out


def decode_tag_chars(text: str) -> str:
    """Decode Unicode TAG-block characters (U+E0000..U+E007F) to ASCII.

    This block is invisible in essentially every renderer, and maps 1:1 onto
    ASCII — making it a favourite channel for smuggling instructions past a
    human reviewer while an LLM still reads them. Returns the recovered
    ASCII string (empty if none present).
    """
    return "".join(
        chr(ord(ch) - _TAG_BASE)
        for ch in text
        if _TAG_BASE <= ord(ch) <= _TAG_BASE + 0x7F
    )


def _detect_slark_marks(text: str) -> List[Finding]:
    marks = _core.decode_all(text)
    if not marks:
        return []
    return [Finding(
        technique="slark_zero_width",
        label="Slark zero-width mark",
        confidence=HIGH,
        detail=(
            f"{len(marks)} checksum-verified Slark mark(s) decoded"
            + (f"; model={marks[0].get('m')!r}" if marks[0].get("m") else "")
        ),
        attribution=marks[0].get("m") or marks[0].get("g"),
        evidence={"marks": marks, "count": len(marks)},
    )]


def _remove_slark_spans(text: str) -> str:
    """Drop only *verified* Slark mark spans, keeping everything else.

    Deliberately not ``core.strip()``: that also removes stray ZWSP/ZWNJ
    characters, which are exactly the evidence another tool's payload leaves
    behind. Subtracting only verified spans means a Slark-marked text does
    not double-report, while a foreign zero-width payload stays visible.
    """
    spans = [(s, e) for _m, s, e in _core._scan(text)]
    if not spans:
        return text
    parts: List[str] = []
    prev = 0
    for s, e in spans:
        parts.append(text[prev:s])
        prev = e + 1
    parts.append(text[prev:])
    return "".join(parts)


def _detect_invisible(text: str) -> List[Finding]:
    """Invisible characters that are *not* part of a verified Slark mark.

    Slark's own span is subtracted first, so a legitimately marked text
    doesn't double-report. Emoji ZWJ sequences are also discounted: a ZWJ
    between two pictographic characters is doing its real job.
    """
    residue = _remove_slark_spans(text)
    hits = _positions(residue, INVISIBLE_CHARS)

    # Discount ZWJ that legitimately joins two emoji/pictographs.
    def _is_emoji_join(idx: int) -> bool:
        if residue[idx] != "\u200d":
            return False
        prev = residue[idx - 1] if idx > 0 else ""
        nxt = residue[idx + 1] if idx + 1 < len(residue) else ""
        return bool(prev and nxt and ord(prev) > 0x2000 and ord(nxt) > 0x2000)

    hits = [h for h in hits if not _is_emoji_join(h[0])]
    if not hits:
        return []

    names = _counter(n for _i, _c, n in hits)
    # A long run of two alternating invisibles is a bit-encoded payload.
    runs = re.findall(r"[\u200b\u200c\u2060\ufeff\u00ad]{8,}", residue)
    if runs:
        longest = max(len(r) for r in runs)
        return [Finding(
            technique="invisible_unicode_payload",
            label="Invisible-character payload",
            confidence=HIGH,
            detail=(
                f"run of {longest} consecutive invisible characters "
                f"(~{longest // 8} bytes) — an encoded payload from another tool"
            ),
            attribution="unknown zero-width tool",
            evidence={"characters": names, "longest_run": longest,
                      "runs": len(runs), "total": len(hits)},
        )]
    return [Finding(
        technique="invisible_unicode",
        label="Stray invisible characters",
        confidence=MEDIUM if len(hits) > 2 else LOW,
        detail=(f"{len(hits)} invisible character(s) with no verified payload — "
                "a stripped/partial mark, or formatting residue"),
        evidence={"characters": names, "total": len(hits),
                  "positions": [i for i, _c, _n in hits][:64]},
        status="suspicious",
    )]


def _detect_tag_chars(text: str) -> List[Finding]:
    hidden = decode_tag_chars(text)
    if not hidden:
        return []
    printable = "".join(c for c in hidden if c.isprintable())
    return [Finding(
        technique="unicode_tag_chars",
        label="Unicode TAG-block smuggling",
        confidence=HIGH,
        detail=(f"{len(hidden)} TAG characters decode to ASCII: {printable[:120]!r}"
                " — invisible to readers, readable by an LLM"),
        attribution="ASCII smuggling / prompt injection",
        evidence={"decoded": printable, "count": len(hidden)},
    )]


def _detect_variation_selectors(text: str) -> List[Finding]:
    sel = [(i, ch) for i, ch in enumerate(text)
           if _VS_RANGE[0] <= ord(ch) <= _VS_RANGE[1]
           or _VSUP_RANGE[0] <= ord(ch) <= _VSUP_RANGE[1]]
    if not sel:
        return []
    # VS16/VS15 after a pictograph are legitimate emoji presentation marks.
    def _legit(idx: int) -> bool:
        if text[idx] not in ("\ufe0e", "\ufe0f"):
            return False
        return idx > 0 and ord(text[idx - 1]) > 0x2000
    suspect = [s for s in sel if not _legit(s[0])]
    if not suspect:
        return []
    return [Finding(
        technique="variation_selectors",
        label="Variation-selector payload",
        confidence=HIGH if len(suspect) >= 8 else MEDIUM,
        detail=(f"{len(suspect)} variation selector(s) not serving emoji "
                f"presentation (~{len(suspect)} bytes of hidden data)"),
        attribution="variation-selector steganography",
        evidence={"count": len(suspect),
                  "codepoints": [f"U+{ord(c):04X}" for _i, c in suspect][:32]},
        status="detected" if len(suspect) >= 8 else "suspicious",
    )]


def _detect_bidi(text: str) -> List[Finding]:
    hits = _positions(text, BIDI_CHARS)
    if not hits:
        return []
    overrides = [h for h in hits if h[1] in ("\u202d", "\u202e", "\u202a", "\u202b")]
    return [Finding(
        technique="bidi_controls",
        label="Bidirectional control characters",
        confidence=MEDIUM if overrides else LOW,
        detail=(f"{len(hits)} bidi control(s)"
                + (f", {len(overrides)} of them directional overrides that can "
                   "reorder how this text renders (Trojan Source)" if overrides else "")),
        attribution="bidi/Trojan-Source technique" if overrides else None,
        evidence={"characters": _counter(n for _i, _c, n in hits),
                  "overrides": len(overrides)},
        status="suspicious",
    )]


def _detect_homoglyphs(text: str) -> List[Finding]:
    """Homoglyph substitution: Latin letters swapped for lookalikes.

    Only flagged when the substituted characters sit *inside* otherwise-ASCII
    words — genuine Cyrillic or Greek prose is full of these characters and
    must not be flagged. The give-away is a script boundary mid-word.
    """
    hits = _positions(text, HOMOGLYPHS)
    if not hits:
        return []

    ascii_letters = sum(1 for c in text if c.isascii() and c.isalpha())
    if ascii_letters < 8:
        return []  # not predominantly Latin text — no conclusion to draw

    mixed: List[Tuple[int, str, str]] = []
    for i, ch, latin in hits:
        prev = text[i - 1] if i > 0 else ""
        nxt = text[i + 1] if i + 1 < len(text) else ""
        # mid-word: an ASCII letter directly beside a non-ASCII lookalike
        if (prev.isascii() and prev.isalpha()) or (nxt.isascii() and nxt.isalpha()):
            mixed.append((i, ch, latin))
    if not mixed:
        return []

    words = sorted({
        m for m in re.findall(r"\S*[^\x00-\x7F]\S*", text) if any(
            ch in HOMOGLYPHS for ch in m)
    })[:8]
    return [Finding(
        technique="homoglyph_substitution",
        label="Homoglyph substitution",
        confidence=HIGH if len(mixed) >= 4 else MEDIUM,
        detail=(f"{len(mixed)} lookalike character(s) inside otherwise-ASCII words "
                f"(e.g. {words[:3]}) — a copy-paste-survivable hidden channel"),
        attribution="homoglyph watermarking",
        evidence={"count": len(mixed), "affected_words": words,
                  "substitutions": _counter(
                      f"U+{ord(c):04X}->{l}" for _i, c, l in mixed)},
        status="detected" if len(mixed) >= 4 else "suspicious",
    )]


def _detect_lookalike_punct(text: str) -> List[Finding]:
    hits = _positions(text, LOOKALIKE_PUNCT)
    if len(hits) < 4:
        return []
    names = _counter(n for _i, _c, n in hits)
    spaces = sum(v for k, v in names.items() if "SPACE" in k)
    if spaces < 4:
        return []
    return [Finding(
        technique="lookalike_whitespace",
        label="Unusual whitespace characters",
        confidence=LOW,
        detail=(f"{spaces} non-standard space character(s) — can encode bits, "
                "but also common in text copied from PDFs or word processors"),
        evidence={"characters": names},
        status="suspicious",
    )]


def _detect_statistical_note() -> Finding:
    return Finding(
        technique="statistical_token_watermark",
        label="Statistical token-sampling watermark",
        confidence=0.0,
        detail=("cannot be tested without the provider's secret key — "
                "SynthID-Text and similar sampling marks leave no publicly "
                "verifiable signal, so this is unknown, not absent"),
        attribution=None,
        evidence={"reason": "keyed detector not publicly available"},
        status="unavailable",
    )


def scan_text(text: str, *, include_notes: bool = True) -> Report:
    """Scan text for hidden payloads from Slark **and other tools**.

    Args:
        text: the text to examine.
        include_notes: also report detector classes that cannot be tested
            (statistical token watermarks), so "clean" is never overstated.

    Returns:
        A :class:`Report`. ``report.verdict`` is one of ``"watermarked"``,
        ``"suspicious"``, ``"clean"``, ``"inconclusive"``.
    """
    findings: List[Finding] = []
    findings += _detect_slark_marks(text)
    findings += _detect_invisible(text)
    findings += _detect_tag_chars(text)
    findings += _detect_variation_selectors(text)
    findings += _detect_bidi(text)
    findings += _detect_homoglyphs(text)
    findings += _detect_lookalike_punct(text)
    if include_notes:
        findings.append(_detect_statistical_note())
    return Report(target="text", findings=findings)


# =============================================================== IMAGE
#
# Image detectors need numpy for the transform work. Pillow is needed to
# load pixels. Both are optional: when missing, the affected detectors
# report "unavailable" instead of silently returning "clean".


def _require_numpy():
    try:
        import numpy  # noqa: F811
        return numpy
    except ImportError:
        return None


def _load_pixels(source) -> Optional[Tuple[Any, int, int]]:
    """Load `source` into an (H, W, 4) uint8 numpy array. None if unavailable.

    Accepts a path, file-like object, raw PNG/JPEG ``bytes``, or a PIL image.
    Raw bytes are wrapped in a stream, and file-like objects are rewound and
    restored, so the same source can be handed to several detectors in turn.
    """
    np = _require_numpy()
    if np is None:
        return None
    try:
        from PIL import Image
    except ImportError:
        return None

    if isinstance(source, Image.Image):
        img = source
    elif isinstance(source, (bytes, bytearray)):
        import io
        img = Image.open(io.BytesIO(bytes(source)))
    elif hasattr(source, "read"):
        pos = None
        try:
            pos = source.tell()
            source.seek(0)
        except (OSError, ValueError):
            pos = None
        img = Image.open(source)
        img.load()
        if pos is not None:
            try:
                source.seek(pos)
            except (OSError, ValueError):
                pass
    else:
        img = Image.open(source)
    img.load()
    rgba = img.convert("RGBA")
    w, h = rgba.size
    arr = np.frombuffer(rgba.tobytes(), dtype=np.uint8).reshape(h, w, 4)
    return arr, w, h


def _unavailable(technique: str, label: str, why: str) -> Finding:
    return Finding(
        technique=technique, label=label, confidence=0.0,
        detail=why, evidence={}, status="unavailable",
    )


# --------------------------------------------------------- DWT-DCT (SD)
#
# Reimplements the read path of the `invisible-watermark` DWT-DCT scheme
# that Stable Diffusion 1.x/2.x ships by default, in pure numpy.
#
# Verified bit-for-bit against the reference implementation: it recovers the
# exact payload b"StableDiffusionV1" from a reference-encoded image, and
# yields ~0.43-0.50 bit error (chance) on clean images versus ~0.08 on
# watermarked ones. That gap is what makes a *calibrated* threshold possible.
#
# Note the reference's `infer_dct_matrix` applies no DCT despite its name —
# it quantizes the Haar DWT coefficients directly. This mirrors that exactly;
# doing the "correct" DCT here would fail to read real SD images.

#: Payloads shipped by known generators, as raw signature bytes.
KNOWN_DWT_SIGNATURES: Dict[bytes, str] = {
    b"StableDiffusionV1": "Stable Diffusion 1.x",
    b"StableDiffusionV2": "Stable Diffusion 2.x",
    b"SDV1": "Stable Diffusion (short tag)",
}

_DWT_SCALE = 36.0
_DWT_BLOCK = 4
#: Bit error at or below this counts as a match. Measured separation is
#: wide (~0.08 watermarked vs ~0.43 clean), so 0.20 sits safely between.
_DWT_MAX_BER = 0.20


def _bgr_to_yuv_u(arr) -> Any:
    """Return the U (chroma) plane, matching cv2.COLOR_BGR2YUV to <=1 LSB.

    The reference embeds into YUV channel 1 (scales [0, 36, 36] with
    `range(2)` means channels 0 and 1, and channel 0's scale is 0).
    """
    np = _require_numpy()
    r = arr[:, :, 0].astype(np.float64)
    g = arr[:, :, 1].astype(np.float64)
    b = arr[:, :, 2].astype(np.float64)
    y = 0.299 * r + 0.587 * g + 0.114 * b
    u = 0.492 * (b - y) + 128.0
    return np.clip(np.rint(u), 0, 255)


def _haar_ca1(plane) -> Any:
    """Single-level 2-D Haar approximation (LL) band — matches pywt.dwt2."""
    np = _require_numpy()
    a = plane.astype(np.float64)
    even, odd = a[0::2, :], a[1::2, :]
    n = min(even.shape[0], odd.shape[0])
    rows = (even[:n] + odd[:n]) / np.sqrt(2.0)
    e2, o2 = rows[:, 0::2], rows[:, 1::2]
    m = min(e2.shape[1], o2.shape[1])
    return (e2[:, :m] + o2[:, :m]) / np.sqrt(2.0)


def _dwt_read_bits(arr, wm_len: int) -> Optional[Tuple[Any, Any]]:
    """Read `wm_len` voted bits from the DWT band. (bits, per-bit means)."""
    np = _require_numpy()
    h, w = arr.shape[:2]
    if min(h, w) < 2 * _DWT_BLOCK * 2:
        return None
    u = _bgr_to_yuv_u(arr)[: h // 4 * 4, : w // 4 * 4]
    ca = _haar_ca1(u)
    rows, cols = ca.shape
    nb_r, nb_c = rows // _DWT_BLOCK, cols // _DWT_BLOCK
    if nb_r * nb_c < wm_len:
        return None

    # Vectorised: reshape into (nb_r, nb_c, 4, 4) blocks.
    blocks = (ca[: nb_r * _DWT_BLOCK, : nb_c * _DWT_BLOCK]
              .reshape(nb_r, _DWT_BLOCK, nb_c, _DWT_BLOCK)
              .transpose(0, 2, 1, 3)
              .reshape(-1, _DWT_BLOCK * _DWT_BLOCK))
    # Reference picks argmax|coeff| over positions 1.. (skipping DC).
    pos = np.argmax(np.abs(blocks[:, 1:]), axis=1) + 1
    vals = np.abs(blocks[np.arange(blocks.shape[0]), pos])
    votes = ((vals % _DWT_SCALE) > 0.5 * _DWT_SCALE).astype(np.float64)

    # Bit i is carried by every block where index % wm_len == i.
    idx = np.arange(votes.size) % wm_len
    sums = np.bincount(idx, weights=votes, minlength=wm_len)
    counts = np.bincount(idx, minlength=wm_len).astype(np.float64)
    means = np.divide(sums, counts, out=np.full(wm_len, 0.5), where=counts > 0)
    return (means * 255 > 127).astype(np.uint8), means


def _sig_to_bits(sig: bytes) -> Any:
    np = _require_numpy()
    return np.array([(byte >> (7 - i)) & 1 for byte in sig for i in range(8)],
                    dtype=np.uint8)


def _bits_to_bytes_np(bits) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) // 8 * 8, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | int(b)
        out.append(byte)
    return bytes(out)


def detect_dwt_dct(source) -> Optional[Finding]:
    """Detect an `invisible-watermark` DWT-DCT mark (Stable Diffusion default).

    Reads the quantization votes and compares the recovered bitstream against
    known generator signatures by bit error rate, so a partially damaged mark
    (resize, mild recompression) still attributes correctly.

    Returns:
        A Finding when a signature matches or the votes are anomalously
        structured; None when the image reads as clean. A Finding with
        ``status="unavailable"`` means numpy/Pillow were missing.
    """
    np = _require_numpy()
    if np is None:
        return _unavailable("dwt_dct", "DWT-DCT (Stable Diffusion)",
                            "requires numpy: pip install \"slark[detect]\"")
    loaded = _load_pixels(source)
    if loaded is None:
        return _unavailable("dwt_dct", "DWT-DCT (Stable Diffusion)",
                            "requires numpy + Pillow: pip install \"slark[detect]\"")
    arr, _w, _h = loaded

    best: Optional[Tuple[str, float, bytes, int]] = None
    for sig, name in KNOWN_DWT_SIGNATURES.items():
        wm_len = len(sig) * 8
        read = _dwt_read_bits(arr, wm_len)
        if read is None:
            continue
        bits, _means = read
        ref = _sig_to_bits(sig)
        ber = float(np.mean(bits != ref))
        if best is None or ber < best[1]:
            best = (name, ber, _bits_to_bytes_np(bits), wm_len)

    if best is None:
        return None
    name, ber, payload, wm_len = best
    if ber > _DWT_MAX_BER:
        return None

    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in payload)
    return Finding(
        technique="dwt_dct",
        label="DWT-DCT frequency-domain watermark",
        confidence=HIGH if ber <= 0.05 else MEDIUM,
        detail=(f"recovered {payload!r} from DWT chroma quantization "
                f"(bit error {ber:.1%}; chance is ~50%) — matches {name}"),
        attribution=name,
        evidence={"payload_bytes": printable, "bit_error_rate": round(ber, 4),
                  "signature_matched": name, "bits_read": wm_len,
                  "algorithm": "invisible-watermark dwtDct"},
    )


# --------------------------------------------------- generic LSB redundancy
#
# Many LSB stego/watermark tools (Slark's own image format included) write
# the same frame repeatedly so local damage can't destroy every copy. That
# redundancy is a structural fingerprint: bits at stride S agree far above
# chance. Measured: ~0.51 agreement on clean/noise images, 0.91-1.00 on
# redundantly embedded ones.
#
# Guard: perfectly flat regions trivially agree (all-zero LSBs) and would
# false-positive, so images whose LSB plane carries almost no entropy are
# excluded — there is no payload to find in a constant plane.

_LSB_WINDOW = 512          # bits compared per chunk (~64 bytes of frame)
_LSB_MIN_AGREEMENT = 0.75  # measured clean ~0.51; watermarked >=0.91
_LSB_MIN_ENTROPY = 0.10    # below this the LSB plane is effectively constant


def detect_lsb_redundancy(source) -> Optional[Finding]:
    """Detect repeated frames in the LSB plane (redundant LSB embedding).

    Scans candidate copy counts, measuring how strongly the first chunk's
    bits agree with every later chunk. Structural — it finds redundant LSB
    payloads from *any* tool, without knowing the format.

    Returns:
        A Finding, or None when no periodic structure stands out.
    """
    np = _require_numpy()
    if np is None:
        return _unavailable("lsb_redundancy", "Redundant LSB embedding",
                            "requires numpy: pip install \"slark[detect]\"")
    loaded = _load_pixels(source)
    if loaded is None:
        return _unavailable("lsb_redundancy", "Redundant LSB embedding",
                            "requires numpy + Pillow: pip install \"slark[detect]\"")
    arr, _w, _h = loaded

    # RGB channels in row-major order = the slot order used by LSB embedders.
    bits = (arr[:, :, :3].reshape(-1) & 1).astype(np.uint8)
    n = bits.size
    if n < _LSB_WINDOW * 4:
        return None

    p = float(bits.mean())
    if p <= 0.0 or p >= 1.0:
        return None
    entropy = -(p * np.log2(p) + (1 - p) * np.log2(1 - p))
    if entropy < _LSB_MIN_ENTROPY:
        return None  # near-constant LSB plane: flat art, not a payload

    best: Tuple[float, int, int] = (0.0, 0, 0)
    for copies in range(3, 513):
        stride = n // copies
        if stride < _LSB_WINDOW:
            break
        f = min(_LSB_WINDOW, stride)
        ref = bits[:f]
        offs = np.arange(1, copies) * stride
        offs = offs[offs + f <= n]
        if offs.size == 0:
            continue
        segs = bits[offs[:, None] + np.arange(f)[None, :]]
        agree = float(np.mean(segs == ref))
        if agree > best[0]:
            best = (agree, copies, stride)

    agreement, copies, stride = best
    if agreement < _LSB_MIN_AGREEMENT:
        return None
    return Finding(
        technique="lsb_redundancy",
        label="Redundant LSB embedding",
        confidence=HIGH if agreement >= 0.90 else MEDIUM,
        detail=(f"LSB plane repeats a frame {copies}x at stride {stride} with "
                f"{agreement:.1%} bit agreement (chance is ~50%) — a redundant "
                "hidden payload"),
        attribution="LSB steganography tool",
        evidence={"agreement": round(agreement, 4), "copies": copies,
                  "stride_bits": stride, "lsb_entropy": round(float(entropy), 4)},
    )


# ---------------------------------------------------------- LSB uniformity


def detect_lsb_anomaly(source) -> Optional[Finding]:
    """Flag an LSB plane that is statistically too uniform.

    In natural images the LSB correlates with local structure. Wholesale LSB
    replacement destroys that correlation. Compares the real LSB plane's
    horizontal-neighbour agreement against the plane above it (bit 1), which
    a bit-0 embedder leaves untouched — a self-calibrating comparison that
    needs no absolute threshold tuned per image type.
    """
    np = _require_numpy()
    if np is None:
        return _unavailable("lsb_anomaly", "LSB plane anomaly",
                            "requires numpy: pip install \"slark[detect]\"")
    loaded = _load_pixels(source)
    if loaded is None:
        return _unavailable("lsb_anomaly", "LSB plane anomaly",
                            "requires numpy + Pillow: pip install \"slark[detect]\"")
    arr, w, h = loaded
    if w < 16 or h < 16:
        return None

    rgb = arr[:, :, :3]

    def _neighbour_agreement(plane_bit: int) -> float:
        p = ((rgb >> plane_bit) & 1).astype(np.int8)
        return float(np.mean(p[:, :-1, :] == p[:, 1:, :]))

    a0 = _neighbour_agreement(0)
    a1 = _neighbour_agreement(1)
    # Bit 1 is the control: if bit 0 is markedly less correlated than bit 1,
    # something overwrote it. Natural images have a0 >= a1.
    delta = a1 - a0
    if delta < 0.06 or a0 > 0.56:
        return None
    return Finding(
        technique="lsb_anomaly",
        label="LSB plane anomaly",
        confidence=MEDIUM if delta >= 0.12 else LOW,
        detail=(f"bit-0 plane is far less spatially correlated than bit-1 "
                f"({a0:.1%} vs {a1:.1%}) — consistent with LSB data replacing "
                "the natural low bit"),
        attribution="LSB steganography (format unknown)",
        evidence={"lsb_neighbour_agreement": round(a0, 4),
                  "bit1_neighbour_agreement": round(a1, 4),
                  "delta": round(delta, 4)},
        status="suspicious",
    )


# ------------------------------------------------------- container metadata
#
# The loudest provenance signal is usually not in the pixels at all. C2PA
# manifests, XMP blocks, EXIF tags and PNG text chunks routinely name the
# generating tool outright. This is *declared* provenance: trivially strippable,
# and equally trivially forgeable, so it is reported as metadata rather than
# as a pixel-level watermark. A C2PA manifest's cryptographic signature is
# NOT validated here (that needs the full trust list) — presence is reported,
# authenticity is not asserted.

#: Byte signatures -> the tool they indicate. Matched case-insensitively
#: against raw container bytes.
GENERATOR_SIGNATURES: List[Tuple[bytes, str]] = [
    (b"c2pa", "C2PA / Content Credentials"),
    (b"jumbf", "JUMBF (C2PA container)"),
    (b"contentcredentials", "Content Credentials"),
    (b"midjourney", "Midjourney"),
    (b"dall-e", "OpenAI DALL-E"),
    (b"dalle", "OpenAI DALL-E"),
    (b"openai", "OpenAI"),
    (b"stable diffusion", "Stable Diffusion"),
    (b"stablediffusion", "Stable Diffusion"),
    (b"stable-diffusion", "Stable Diffusion"),
    (b"automatic1111", "AUTOMATIC1111 WebUI"),
    (b"comfyui", "ComfyUI"),
    (b"invokeai", "InvokeAI"),
    (b"novelai", "NovelAI"),
    (b"firefly", "Adobe Firefly"),
    (b"adobe stock", "Adobe"),
    (b"synthid", "Google SynthID"),
    (b"imagen", "Google Imagen"),
    (b"gemini", "Google Gemini"),
    (b"ideogram", "Ideogram"),
    (b"flux", "Black Forest Labs FLUX"),
    (b"leonardo.ai", "Leonardo.AI"),
    (b"playground ai", "Playground AI"),
    (b"recraft", "Recraft"),
    (b"grok", "xAI Grok"),
    (b"nano banana", "Google Nano Banana"),
    (b"seedream", "ByteDance Seedream"),
    (b"qwen-image", "Alibaba Qwen-Image"),
    (b"trainedmodel", "AI model metadata"),
]

#: Generation-parameter keys that betray a diffusion pipeline even when the
#: tool name is absent.
PARAM_HINTS: List[Tuple[bytes, str]] = [
    (b"sampler:", "diffusion sampler parameters"),
    (b"steps:", "diffusion step count"),
    (b"cfg scale", "classifier-free guidance scale"),
    (b"denoising strength", "diffusion denoising parameter"),
    (b"negative prompt", "diffusion negative prompt"),
    (b"model hash", "diffusion model hash"),
    (b"seed:", "generation seed"),
    (b"lora:", "LoRA adapter reference"),
]


def _png_chunks(data: bytes) -> List[Tuple[str, bytes]]:
    """Parse PNG chunks. Returns [] for non-PNG or truncated data."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return []
    out: List[Tuple[str, bytes]] = []
    i = 8
    while i + 8 <= len(data):
        try:
            length = struct.unpack(">I", data[i:i + 4])[0]
        except struct.error:
            break
        ctype = data[i + 4:i + 8].decode("latin-1", "replace")
        payload = data[i + 8:i + 8 + length]
        if len(payload) != length:
            break
        out.append((ctype, payload))
        i += 8 + length + 4
        if ctype == "IEND":
            break
    return out


def _read_bytes_source(source) -> Optional[bytes]:
    """Best-effort raw bytes for `source` (path / file-like / PIL image)."""
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    if isinstance(source, str):
        try:
            with open(source, "rb") as fh:
                return fh.read()
        except OSError:
            return None
    if hasattr(source, "read"):
        try:
            pos = source.tell()
            source.seek(0)
            data = source.read()
            source.seek(pos)
            return data if isinstance(data, bytes) else None
        except (OSError, ValueError):
            return None
    # PIL image: re-serialise so declared metadata survives the round trip.
    try:
        import io
        from PIL import Image
        if isinstance(source, Image.Image):
            buf = io.BytesIO()
            source.save(buf, "PNG")
            return buf.getvalue()
    except Exception:
        return None
    return None


def detect_image_metadata(source) -> List[Finding]:
    """Find declared AI provenance in container metadata.

    Scans PNG text chunks and, failing that, the whole byte stream (which
    covers JPEG APP segments, XMP and JUMBF/C2PA boxes) for known generator
    names and diffusion parameter keys.

    Returns:
        A list of Findings (possibly empty). Metadata findings carry
        ``status="detected"`` because the tool named itself — but the detail
        text notes that declared metadata is both strippable and forgeable.
    """
    data = _read_bytes_source(source)
    if data is None:
        return [_unavailable("container_metadata", "Container metadata",
                             "could not read raw bytes for this source")]

    findings: List[Finding] = []
    lowered = data.lower()

    # PNG text chunks: precise, and where diffusion UIs write prompts.
    text_chunks: Dict[str, str] = {}
    for ctype, payload in _png_chunks(data):
        if ctype in ("tEXt", "zTXt", "iTXt"):
            raw = payload.split(b"\x00", 1)
            key = raw[0].decode("latin-1", "replace")
            val = (raw[1] if len(raw) > 1 else b"")
            text_chunks[key] = val.decode("utf-8", "replace")[:400]

    tools = sorted({name for sig, name in GENERATOR_SIGNATURES if sig in lowered})
    params = sorted({name for sig, name in PARAM_HINTS if sig in lowered})

    if tools:
        c2pa = [t for t in tools if "C2PA" in t or "Content Credentials" in t]
        findings.append(Finding(
            technique="container_metadata",
            label="Declared AI provenance in metadata",
            confidence=HIGH,
            detail=(f"metadata names: {', '.join(tools[:6])}"
                    + ("; C2PA manifest present but its signature is NOT "
                       "validated here" if c2pa else "")
                    + " — declared metadata is easily stripped or forged"),
            attribution=tools[0],
            evidence={"tools": tools, "png_text_keys": sorted(text_chunks),
                      "text_chunks": text_chunks or None},
        ))
    if params and not tools:
        findings.append(Finding(
            technique="generation_parameters",
            label="Diffusion generation parameters",
            confidence=MEDIUM,
            detail=(f"found {', '.join(params[:5])} — characteristic of an "
                    "image-generation pipeline, though no tool is named"),
            attribution="diffusion pipeline (unnamed)",
            evidence={"parameters": params, "png_text_keys": sorted(text_chunks)},
        ))
    return findings


def _detect_slark_image(source) -> List[Finding]:
    """Slark's own SLK1 LSB tag, so scan_image reports it explicitly."""
    try:
        from . import image as _image
    except ImportError:
        return []
    try:
        target = source
        if isinstance(source, (bytes, bytearray)):
            import io
            target = io.BytesIO(bytes(source))
        result = _image.decode_info(target)
    except Exception:
        return []
    if result is None:
        return []
    meta = result.metadata
    return [Finding(
        technique="slark_slk1",
        label="Slark SLK1 image tag",
        confidence=HIGH,
        detail=(f"checksum-verified SLK1 tag decoded"
                + (" via majority vote across copies" if result.via_vote
                   else f" from copy {result.copy_index + 1}/{result.total_copies}")
                + (f"; model={meta.get('m')!r}" if meta.get("m") else "")),
        attribution=meta.get("m") or meta.get("g"),
        evidence={"metadata": meta, "copy_index": result.copy_index,
                  "total_copies": result.total_copies, "via_vote": result.via_vote},
    )]


def _synthid_note() -> Finding:
    return Finding(
        technique="learned_pixel_watermark",
        label="Learned/neural pixel watermark",
        confidence=0.0,
        detail=("SynthID-Image and similar neural watermarks need the vendor's "
                "private detector model — presence cannot be tested here, so "
                "this is unknown rather than absent"),
        evidence={"reason": "vendor detector model not publicly available"},
        status="unavailable",
    )


def scan_image(source, *, include_notes: bool = True) -> Report:
    """Scan an image for watermarks and hidden payloads from any tool.

    Runs, in order: Slark's own SLK1 tag, container/C2PA metadata, the
    Stable Diffusion DWT-DCT reader, redundant-LSB structure, and LSB-plane
    anomaly analysis.

    Args:
        source: path, file-like object, raw bytes, or ``PIL.Image.Image``.
            A path or bytes gives the best results — a bare PIL image has
            already discarded most container metadata.
        include_notes: also report undetectable classes (neural watermarks)
            so a "clean" result is never overstated.

    Returns:
        A :class:`Report`.
    """
    findings: List[Finding] = []
    findings += _detect_slark_image(source)
    findings += detect_image_metadata(source)

    # Pixel-domain detectors need decoded pixels; a PIL image works directly.
    for fn in (detect_dwt_dct, detect_lsb_redundancy, detect_lsb_anomaly):
        try:
            f = fn(source)
        except Exception as exc:  # a broken detector must not hide the others
            f = _unavailable(fn.__name__, fn.__name__,
                             f"detector error: {type(exc).__name__}: {exc}")
        if f is not None:
            findings.append(f)

    # Don't double-report: Slark's own tag *is* redundant LSB by design.
    if any(f.technique == "slark_slk1" for f in findings):
        findings = [f for f in findings
                    if f.technique not in ("lsb_redundancy", "lsb_anomaly")]

    if include_notes:
        findings.append(_synthid_note())
    return Report(target="image", findings=findings)


def scan(obj, **kwargs) -> Report:
    """Scan `obj`, dispatching on its type.

    ``str`` is treated as text unless it names an existing image file.
    """
    if isinstance(obj, str):
        import os
        if os.path.exists(obj) and os.path.isfile(obj):
            return scan_image(obj, **kwargs)
        return scan_text(obj, **kwargs)
    if isinstance(obj, (bytes, bytearray)) or hasattr(obj, "read"):
        return scan_image(obj, **kwargs)
    try:
        from PIL import Image
        if isinstance(obj, Image.Image):
            return scan_image(obj, **kwargs)
    except ImportError:
        pass
    return scan_text(str(obj), **kwargs)
