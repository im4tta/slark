"""CLI integration tests — run the argparse entry point in-process."""

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


def test_encode_decode_roundtrip(capsys, tmp_path):
    src = tmp_path / "in.txt"
    src.write_text("Hello wide world", encoding="utf-8")
    out = tmp_path / "out.txt"

    code, _, err = run(
        ["encode", "--file", str(src), "--model", "m1", "--output", str(out)], capsys
    )
    assert code == 0 and "Wrote" in err

    code, stdout, _ = run(["decode", "--file", str(out)], capsys)
    assert code == 0
    assert json.loads(stdout)["m"] == "m1"


def test_decode_json_flag(capsys, tmp_path):
    out = tmp_path / "o.txt"
    run(["encode", "--text", "Hello world", "--model", "m", "--output", str(out)], capsys)
    code, stdout, _ = run(["decode", "--file", str(out), "--json"], capsys)
    assert code == 0
    assert "\n" not in stdout.strip()
    assert json.loads(stdout)["m"] == "m"


def test_decode_json_null_on_clean(capsys):
    code, stdout, _ = run(["decode", "--text", "plain text here", "--json"], capsys)
    assert code == 1
    assert stdout.strip() == "null"


def test_check_exit_codes(capsys, tmp_path):
    out = tmp_path / "o.txt"
    run(["encode", "--text", "Hello world", "--output", str(out)], capsys)
    code, stdout, _ = run(["check", "--file", str(out)], capsys)
    assert code == 0 and "watermarked" in stdout
    code, stdout, _ = run(["check", "--text", "nothing hidden"], capsys)
    assert code == 1 and "clean" in stdout


def test_strip_roundtrip(capsys, tmp_path):
    marked = tmp_path / "m.txt"
    run(["encode", "--text", "Hello world", "--output", str(marked)], capsys)
    code, stdout, _ = run(["strip", "--file", str(marked)], capsys)
    assert code == 0
    assert stdout.rstrip("\n") == "Hello world"


def test_encode_replace_flag(capsys, tmp_path):
    out1 = tmp_path / "1.txt"
    out2 = tmp_path / "2.txt"
    run(["encode", "--text", "Hello world", "--extra", '{"v":1}', "--output", str(out1)], capsys)
    run(["encode", "--file", str(out1), "--extra", '{"v":2}', "--replace",
         "--output", str(out2)], capsys)
    code, stdout, _ = run(["decode", "--file", str(out2), "--all"], capsys)
    metas = json.loads(stdout)
    assert code == 0 and len(metas) == 1 and metas[0]["v"] == 2


def test_bad_extra_json_exits_2(capsys):
    code, _, err = run(["encode", "--text", "hi there", "--extra", "{oops"], capsys)
    assert code == 2 and "valid JSON" in err


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        cli.build_parser().parse_args(["--version"])
    assert e.value.code == 0


# ---------- image subcommands ----------


@pytest.fixture
def png(tmp_path):
    PIL = pytest.importorskip("PIL")
    from PIL import Image
    raw = bytes(
        b for p in range(96 * 72)
        for b in ((p * 7) & 255, (p * 5) & 255, (p * 11) & 255)
    )
    path = tmp_path / "in.png"
    Image.frombytes("RGB", (96, 72), raw).save(path)
    return path


def test_image_cli_roundtrip(capsys, tmp_path, png):
    out = tmp_path / "out.png"
    code, _, err = run(
        ["encode-image", "--file", str(png), "--model", "m9", "--output", str(out)], capsys
    )
    assert code == 0 and "Wrote" in err

    code, stdout, err = run(["decode-image", "--file", str(out)], capsys)
    assert code == 0
    assert json.loads(stdout)["m"] == "m9"
    assert "verified copy" in err

    code, stdout, _ = run(["decode-image", "--file", str(out), "--json"], capsys)
    obj = json.loads(stdout)
    assert obj["metadata"]["m"] == "m9" and obj["total_copies"] >= 1

    code, stdout, _ = run(["check-image", "--file", str(out)], capsys)
    assert code == 0 and "watermarked" in stdout

    clean = tmp_path / "clean.png"
    code, _, err = run(["strip-image", "--file", str(out), "--output", str(clean)], capsys)
    assert code == 0
    code, stdout, _ = run(["check-image", "--file", str(clean)], capsys)
    assert code == 1 and "clean" in stdout


def test_decode_image_clean(capsys, png):
    code, _, err = run(["decode-image", "--file", str(png)], capsys)
    assert code == 1 and "No valid watermark" in err
