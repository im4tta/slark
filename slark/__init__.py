"""
slark — invisible text watermarking, for marking AI-generated content
(or any text) with a hidden, checksum-verified, zero-width payload.

    >>> import slark
    >>> marked = slark.encode("Hello world", model="claude-sonnet-5")
    >>> slark.decode(marked)
    {'g': 'ai', 'ts': 1234567890, 'm': 'claude-sonnet-5'}
"""

from .core import (
    decode,
    encode,
    has_watermark,
    strip,
    count_hidden_chars,
)

__version__ = "0.1.0"
__all__ = [
    "encode",
    "decode",
    "has_watermark",
    "strip",
    "count_hidden_chars",
    "__version__",
]
