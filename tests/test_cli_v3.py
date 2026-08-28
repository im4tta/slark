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


# ---------------------------------------------------------------- scan (v0.4)
#
# `cmd_scan` returns its exit code rather than raising SystemExit (main()
# performs the exit), so these call it directly and check the return value.


def scan_rc(argv, capsys):
    parser = cli.build_parser()
    args = parser.parse_args(argv)
    rc = args.func(args)
    out = capsys.readouterr()
    return rc, out.out, out.err


def tagged(payload: str) -> str:
    """ASCII smuggled into the invisible Unicode TAG block."""
    return "".join(chr(0xE0000 + ord(c)) for c in payload)


def test_scan_detects_tag_smuggling(capsys):
    rc, stdout, _ = scan_rc(
        ["scan", "--text", f"Normal looking sentence.{tagged('LEAK')}"], capsys)
    assert rc == 0
    assert "watermarked" in stdout
    assert "unicode_tag_chars" in stdout
    assert "LEAK" in stdout


def test_scan_clean_text_is_inconclusive(capsys):
    """Keyed statistical marks can't be tested -> inconclusive, not clean."""
    rc, stdout, _ = scan_rc(
        ["scan", "--text", "A perfectly ordinary sentence, nothing hidden."],
        capsys)
    assert rc == 4
    assert "inconclusive" in stdout
    assert "absence NOT proven" in stdout


def test_scan_no_notes_reports_clean(capsys):
    rc, stdout, _ = scan_rc(
        ["scan", "--no-notes", "--text",
         "A perfectly ordinary sentence, nothing hidden."], capsys)
    assert rc == 1
    assert "clean" in stdout


def test_scan_bidi_is_suspicious(capsys):
    rc, stdout, _ = scan_rc(
        ["scan", "--text", "safe_code\u202ereversed\u202c plus more text."], capsys)
    assert rc == 3
    assert "suspicious" in stdout


def test_scan_json_output(capsys):
    rc, stdout, _ = scan_rc(
        ["scan", "--json", "--text", f"Body text.{tagged('X')}"], capsys)
    assert rc == 0
    payload = json.loads(stdout)
    assert payload["verdict"] == "watermarked"
    assert payload["findings"][0]["technique"] == "unicode_tag_chars"


def test_scan_finds_slark_mark(capsys, tmp_path):
    import slark
    src = tmp_path / "marked.txt"
    src.write_text(slark.encode("Content to scan here.", model="gpt-5"),
                   encoding="utf-8")
    rc, stdout, _ = scan_rc(["scan", "--file", str(src)], capsys)
    assert rc == 0
    assert "slark_zero_width" in stdout
    assert "gpt-5" in stdout


def test_scan_verbose_shows_evidence(capsys):
    rc, stdout, _ = scan_rc(
        ["scan", "--verbose", "--text", f"Body.{tagged('SECRET')}"], capsys)
    assert rc == 0
    assert "decoded" in stdout  # raw evidence key


def test_scan_image_reports_slark_tag(capsys, tmp_path):
    """A .png path routes to the image detectors automatically."""
    pytest.importorskip("numpy")
    Image = pytest.importorskip("PIL.Image")
    from slark import image as slkimg

    src = tmp_path / "plain.png"
    Image.new("RGB", (128, 128), (90, 120, 150)).save(src)
    out = tmp_path / "marked.png"
    slkimg.encode(str(src), model="claude-sonnet-5").save(out, format="PNG")

    rc, stdout, _ = scan_rc(["scan", "--file", str(out)], capsys)
    assert rc == 0
    assert "slark_slk1" in stdout
    assert "claude-sonnet-5" in stdout


def test_scan_image_flag_forces_image_mode(capsys, tmp_path):
    Image = pytest.importorskip("PIL.Image")
    p = tmp_path / "noext"
    Image.new("RGB", (64, 64), (10, 20, 30)).save(p, format="PNG")
    rc, stdout, _ = scan_rc(["scan", "--image", "--file", str(p)], capsys)
    assert "target:  image" in stdout
