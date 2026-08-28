#!/usr/bin/env python3
"""
cli.py — command-line interface for slark

Usage:
    # Text
    slark encode --text "Hello world" --model claude-sonnet-5
    slark encode --file input.txt --model claude-sonnet-5 --output out.txt
    slark decode --file out.txt [--json]
    slark check --file out.txt          # exit code 0 = watermarked, 1 = not
    slark strip --file out.txt --output clean.txt [--aggressive]

    # Images (requires slark[image])
    slark encode-image --file photo.png --model claude-sonnet-5 --output out.png
    slark decode-image --file out.png [--json]
    slark check-image --file out.png    # exit code 0 = watermarked, 1 = not
    slark strip-image --file out.png --output clean.png

    Text subcommands also read stdin when neither --text nor --file is given:
        echo "Hello world" | slark encode --model gpt-5 | slark decode

Exit codes: 0 success/watermarked, 1 no watermark, 2 usage/dependency error.
"""

import argparse
import json
import sys

from . import __version__
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


def _parse_extra(args):
    if not args.extra:
        return None
    try:
        extra = json.loads(args.extra)
    except json.JSONDecodeError as e:
        print(f"--extra is not valid JSON: {e}", file=sys.stderr)
        sys.exit(2)
    if not isinstance(extra, dict):
        print("--extra must be a JSON object, e.g. '{\"k\":\"v\"}'", file=sys.stderr)
        sys.exit(2)
    return extra


def cmd_encode(args):
    text = _read_input(args)
    result = wm.encode(
        text,
        model=args.model,
        generator=args.generator,
        extra=_parse_extra(args),
        replace=args.replace,
    )
    _write_output(args, result)


def cmd_decode(args):
    text = _read_input(args)
    metas = wm.decode_all(text) if args.all else ([m] if (m := wm.decode(text)) else [])
    if not metas:
        if args.json:
            print("null")
        else:
            print("No valid watermark found.", file=sys.stderr)
        sys.exit(1)
    out = metas if args.all else metas[0]
    print(json.dumps(out, indent=None if args.json else 2, ensure_ascii=False))


def cmd_check(args):
    text = _read_input(args)
    if wm.has_watermark(text):
        print("watermarked")
        sys.exit(0)
    print("clean")
    sys.exit(1)


def cmd_strip(args):
    text = _read_input(args)
    _write_output(args, wm.strip(text, aggressive=args.aggressive))


# ---------------------------------------------------------------- images


def _image_module():
    try:
        from slark import image as imgmod
        imgmod._require_pil()
    except ImportError:
        print('Image support requires Pillow: pip install "slark[image]"', file=sys.stderr)
        sys.exit(2)
    return imgmod


def cmd_encode_image(args):
    imgmod = _image_module()
    marked = imgmod.encode(
        args.file, model=args.model, generator=args.generator, extra=_parse_extra(args)
    )
    out = args.output or "slarked.png"
    marked.save(out, format="PNG")
    print(f"Wrote {out}", file=sys.stderr)


def cmd_decode_image(args):
    imgmod = _image_module()
    found = imgmod.decode_info(args.file)
    if found is None:
        if args.json:
            print("null")
        else:
            print("No valid watermark found.", file=sys.stderr)
        sys.exit(1)
    meta, copy_index, total_copies = found
    if args.json:
        print(json.dumps(
            {"metadata": meta, "copy_index": copy_index, "total_copies": total_copies},
            ensure_ascii=False,
        ))
    else:
        print(json.dumps(meta, indent=2, ensure_ascii=False))
        print(f"(verified copy {copy_index + 1} of {total_copies})", file=sys.stderr)


def cmd_check_image(args):
    imgmod = _image_module()
    meta = imgmod.decode(args.file)
    if meta is not None:
        print("watermarked")
        print(json.dumps(meta, indent=2, ensure_ascii=False), file=sys.stderr)
        sys.exit(0)
    print("clean")
    sys.exit(1)


def cmd_strip_image(args):
    imgmod = _image_module()
    clean = imgmod.erase(args.file)
    out = args.output or "clean.png"
    clean.save(out, format="PNG")
    print(f"Wrote {out}", file=sys.stderr)


# ---------------------------------------------------------------- parser


def build_parser():
    p = argparse.ArgumentParser(
        prog="slark",
        description="Invisible text & image watermarking tool",
    )
    p.add_argument("--version", action="version", version=f"slark {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_io_args(sp):
        src = sp.add_mutually_exclusive_group()
        src.add_argument("--text", help="Text to process (inline)")
        src.add_argument("--file", help="Path to input file")
        sp.add_argument("--output", help="Path to write result (default: stdout)")

    def add_meta_args(sp):
        sp.add_argument("--model", help="Model name/id to embed, e.g. claude-sonnet-5")
        sp.add_argument("--generator", default="ai", help="Generator tag, default 'ai'")
        sp.add_argument("--extra", help="Extra metadata as a JSON object string")

    sp = sub.add_parser("encode", help="Embed a watermark in text")
    add_io_args(sp)
    add_meta_args(sp)
    sp.add_argument("--replace", action="store_true",
                    help="Remove any existing watermark before embedding")
    sp.set_defaults(func=cmd_encode)

    sp = sub.add_parser("decode", help="Extract watermark metadata from text")
    add_io_args(sp)
    sp.add_argument("--all", action="store_true", help="Report every watermark found")
    sp.add_argument("--json", action="store_true", help="Machine-readable single-line JSON")
    sp.set_defaults(func=cmd_decode)

    sp = sub.add_parser("check", help="Check if text is watermarked (exit code)")
    add_io_args(sp)
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("strip", help="Remove watermark, output clean text")
    add_io_args(sp)
    sp.add_argument("--aggressive", action="store_true",
                    help="Also remove ALL zero-width joiners (breaks emoji sequences)")
    sp.set_defaults(func=cmd_strip)

    sp = sub.add_parser("encode-image", help="Embed an invisible tag in an image (PNG output)")
    sp.add_argument("--file", required=True, help="Path to input image")
    sp.add_argument("--output", help="Path to write PNG (default: slarked.png)")
    add_meta_args(sp)
    sp.set_defaults(func=cmd_encode_image)

    sp = sub.add_parser("decode-image", help="Extract tag metadata from an image")
    sp.add_argument("--file", required=True, help="Path to image to decode")
    sp.add_argument("--json", action="store_true", help="Machine-readable single-line JSON")
    sp.set_defaults(func=cmd_decode_image)

    sp = sub.add_parser("check-image", help="Check if an image carries a tag (exit code)")
    sp.add_argument("--file", required=True, help="Path to image to check")
    sp.set_defaults(func=cmd_check_image)

    sp = sub.add_parser("strip-image", help="Erase any tag from an image (PNG output)")
    sp.add_argument("--file", required=True, help="Path to input image")
    sp.add_argument("--output", help="Path to write PNG (default: clean.png)")
    sp.set_defaults(func=cmd_strip_image)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
