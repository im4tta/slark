"""
slark — invisible text watermarking, for marking AI-generated content
(or any text) with a hidden, checksum-verified, zero-width payload.

    >>> import slark
    >>> marked = slark.encode("Hello world", model="claude-sonnet-5")
    >>> slark.decode(marked)
    {'g': 'ai', 'ts': 1234567890, 'm': 'claude-sonnet-5'}

Image tagging (requires ``pip install "slark[image]"``):

    >>> from slark import image
    >>> image.encode("photo.png", model="claude-sonnet-5").save("out.png")
    >>> image.decode("out.png")
    {'g': 'ai', 'ts': 1234567890, 'm': 'claude-sonnet-5'}
"""

from .core import (
    decode,
    decode_all,
    encode,
    has_watermark,
    strip,
    count_hidden_chars,
)

__version__ = "0.2.0"
__all__ = [
    "encode",
    "decode",
    "decode_all",
    "has_watermark",
    "strip",
    "count_hidden_chars",
    "__version__",
]
