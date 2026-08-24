#!/usr/bin/env python3
"""
cli.py — command-line interface for slark

Usage:
    # Encode
    slark encode --text "Hello world" --model claude-sonnet-5
    slark encode --file input.txt --model claude-sonnet-5 --output out.txt

    # Decode
    slark decode --text "<watermarked text>"
    slark decode --file out.txt

    # Check (boolean, exit code 0 = watermarked, 1 = not)
    slark check --file out.txt

    # Strip
    slark strip --file out.txt --output clean.txt
"""

import argparse
import json
import sys

from . import core as wm


def _read_input(args) -> str:
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            return f.read()
    if args.text is not None:
        return args.text
    return sys.stdin.read()


def _write_output(args, text: str) -> None:
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        print(text)


def cmd_encode(args):
    text = _read_input(args)
    extra = json.loads(args.extra) if args.extra else None
    result = wm.encode(text, model=args.model, generator=args.generator, extra=extra)
    _write_output(args, result)


def cmd_decode(args):
    text = _read_input(args)
    meta = wm.decode(text)
    if meta is None:
        print("No valid watermark found.", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(meta, indent=2))


def cmd_check(args):
    text = _read_input(args)
    if wm.has_watermark(text):
        print("watermarked")
        sys.exit(0)
    else:
        print("clean")
        sys.exit(1)


def cmd_strip(args):
    text = _read_input(args)
    _write_output(args, wm.strip(text))


def _load_image(path):
    try:
        from slark import image as imgmod
    except ImportError:
        print('Image support requires Pillow: pip install "slark[image]"', file=sys.stderr)
        sys.exit(2)
    return imgmod, path


def cmd_encode_image(args):
    imgmod, path = _load_image(args.file)
    from PIL import Image

    extra = json.loads(args.extra) if args.extra else None
    marked = imgmod.encode(
        path, model=args.model, generator=args.generator, extra=extra
    )
    out = args.output or "slarked.png"
    marked.save(out, format="PNG")
    print(f"Wrote {out}", file=sys.stderr)


def cmd_check_image(args):
    imgmod, path = _load_image(args.file)
    if imgmod.has_watermark(path):
        meta = imgmod.decode(path)
        print("watermarked")
        if meta is not None:
            print(json.dumps(meta, indent=2), file=sys.stderr)
        sys.exit(0)
    else:
        print("clean")
        sys.exit(1)


def build_parser():
    p = argparse.ArgumentParser(description="Invisible text watermarking tool")
    sub = p.add_subparsers(dest="command", required=True)

    def add_io_args(sp):
        src = sp.add_mutually_exclusive_group()
        src.add_argument("--text", help="Text to process (inline)")
        src.add_argument("--file", help="Path to input file")
        sp.add_argument("--output", help="Path to write result (default: stdout)")

    sp = sub.add_parser("encode", help="Embed a watermark")
    add_io_args(sp)
    sp.add_argument("--model", help="Model name/id to embed, e.g. claude-sonnet-5")
    sp.add_argument("--generator", default="ai", help="Generator tag, default 'ai'")
    sp.add_argument("--extra", help="Extra metadata as JSON string")
    sp.set_defaults(func=cmd_encode)

    sp = sub.add_parser("decode", help="Extract watermark metadata")
    add_io_args(sp)
    sp.set_defaults(func=cmd_decode)

    sp = sub.add_parser("check", help="Check if text is watermarked (exit code)")
    add_io_args(sp)
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("strip", help="Remove watermark, output clean text")
    add_io_args(sp)
    sp.set_defaults(func=cmd_strip)

    sp = sub.add_parser(
        "encode-image", help="Embed an invisible tag in an image (PNG output)"
    )
    sp.add_argument("--file", required=True, help="Path to input image")
    sp.add_argument("--output", help="Path to write PNG (default: slarked.png)")
    sp.add_argument("--model", help="Model name/id to embed")
    sp.add_argument("--generator", default="ai", help="Generator tag, default 'ai'")
    sp.add_argument("--extra", help="Extra metadata as JSON string")
    sp.set_defaults(func=cmd_encode_image)

    sp = sub.add_parser(
        "check-image", help="Check if an image carries a tag (exit code)"
    )
    sp.add_argument("--file", required=True, help="Path to image to check")
    sp.set_defaults(func=cmd_check_image)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
