"""CLI tests for v0.3 subcommands: verify, verify-image, capacity, --key."""

import json

import pytest

from slark import cli


def run(argv, capsys):
    parser = cli.build_parser()
    args = parser.parse_args(argv)
    code = 0
    try:
        args.func(args)
    except SystemExit as e:
        code = e.code or 0
    out = capsys.readouterr()
    return code, out.out, out.err


def test_encode_with_key_then_verify(capsys, tmp_path):
    out = tmp_path / "o.txt"
    run(["encode", "--text", "Hello world", "--model", "m", "--key", "s3cret",
         "--output", str(out)], capsys)

    code, stdout, _ = run(["verify", "--file", str(out), "--key", "s3cret"], capsys)
    assert code == 0 and stdout.strip() == "signed"

    code, stdout, _ = run(["verify", "--file", str(out), "--key", "wrong"], capsys)
    assert code == 1 and stdout.strip() == "invalid"


def test_verify_unsigned_and_none(capsys, tmp_path):
    out = tmp_path / "o.txt"
    run(["encode", "--text", "Hello world", "--output", str(out)], capsys)
    code, stdout, _ = run(["verify", "--file", str(out), "--key", "k"], capsys)
    assert code == 1 and stdout.strip() == "unsigned"

    code, stdout, _ = run(["verify", "--text", "plain text", "--key", "k"], capsys)
    assert code == 1 and stdout.strip() == "none"


@pytest.fixture
def png(tmp_path):
    pytest.importorskip("PIL")
    from PIL import Image
    raw = bytes(
        b for p in range(96 * 72)
        for b in ((p * 7) & 255, (p * 5) & 255, (p * 11) & 255)
    )
    path = tmp_path / "in.png"
    Image.frombytes("RGB", (96, 72), raw).save(path)
    return path


def test_image_key_verify_capacity(capsys, tmp_path, png):
    out = tmp_path / "out.png"
    run(["encode-image", "--file", str(png), "--model", "m", "--key", "k1",
         "--output", str(out)], capsys)

    code, stdout, _ = run(["verify-image", "--file", str(out), "--key", "k1"], capsys)
    assert code == 0 and stdout.strip() == "signed"
    code, stdout, _ = run(["verify-image", "--file", str(out), "--key", "nope"], capsys)
    assert code == 1 and stdout.strip() == "invalid"

    code, stdout, _ = run(["capacity", "--file", str(png)], capsys)
    info = json.loads(stdout)
    assert code == 0 and info["taggable"] is True and info["copies"] >= 1

    # decode-image reports sig field and vote flag
    code, stdout, _ = run(["decode-image", "--file", str(out), "--json"], capsys)
    obj = json.loads(stdout)
    assert obj["metadata"]["sig"] and obj["via_vote"] is False


def test_capacity_untaggable(capsys, tmp_path):
    pytest.importorskip("PIL")
    from PIL import Image
    p = tmp_path / "tiny.png"
    Image.new("RGB", (16, 16)).save(p)
    code, stdout, _ = run(["capacity", "--file", str(p)], capsys)
    assert code == 1 and json.loads(stdout)["taggable"] is False
