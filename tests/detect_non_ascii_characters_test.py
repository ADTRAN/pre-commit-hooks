import pytest
import argparse
from pathlib import Path
from pre_commit_hooks import detect_non_ascii_characters as dna_hook


@pytest.mark.parametrize(
    "lines, expected_attrs",
    [
        (
            [
                "# comment line",
                "",
                "onlypattern",
                "pat1 binary",
                "pat2 -text filter=lfs",
                "pat3 filter=lfs",
                "pat4 filter=other",
            ],
            {
                "pat1": {"binary": True},
                "pat2": {"binary": True, "filter": "lfs"},
                "pat3": {"filter": "lfs"},
            },
        ),
        (["foo.txt binary"], {"foo.txt": {"binary": True}}),
        (["bar"], {}),
        (["baz.txt filter=other"], {}),
    ],
)
def test_parse_gitattributes_expected_attributes(tmp_path, lines, expected_attrs):
    ga = tmp_path / ".gitattributes"
    ga.write_text("\n".join(lines), encoding="utf-8")
    attrs = dna_hook.parse_gitattributes(str(ga))
    for key, expected_val in expected_attrs.items():
        assert key in attrs
        for k, v in expected_val.items():
            assert k in attrs[key]
            assert attrs[key][k] == v
    for key in attrs:
        assert key in expected_attrs


@pytest.mark.parametrize(
    "filename, gitattributes, expected",
    [
        ("test.png", {"*.png": {"binary": True}}, True),
        ("test.bin", {"*.bin": {"filter": "lfs"}}, True),
        ("test.bin", {"*.bin": {"binary": True, "filter": "lfs"}}, True),
        ("test.txt", {"*.png": {"binary": True}}, False),
        ("test.foo", {"*.foo": {"binary": True}}, True),
        ("test.bar", {"*.bar": {"filter": "other"}}, False),
        ("test.baz", {"*.baz": {"filter": "lfs"}}, True),
        ("test.txt", {}, False),
    ],
)
def test_file_is_binary_matches_expected(filename, gitattributes, expected):
    assert dna_hook.file_is_binary(filename, gitattributes) is expected


@pytest.mark.parametrize(
    "filename, content, write_mode, include, exclude, gitattributes, expected_in, expected_set",
    [
        ("file.txt", "abc", "text", ["file.txt"], [], {}, "file.txt", "to_check"),
        ("file.txt", "abc", "text", [], ["*.txt"], {}, "file.txt", "excluded"),
        ("file.txt", "abc", "text", [], ["*.txt"], {}, "file.txt", "excluded"),
        (
            ".pre-commit-config.yaml",
            "repos: []",
            "text",
            [],
            [],
            {},
            ".pre-commit-config.yaml",
            "excluded",
        ),
        (
            "test.png",
            b"\x89PNG\r\n\x1a\n" + b"\x00" * 10,
            "bytes",
            [],
            [],
            {},
            "test.png",
            "binary",
        ),
        ("data.dat", b"\x00" * 10, "bytes", [], [], {}, "data.dat", "binary"),
        (
            "data.txt",
            "hello",
            "text",
            [],
            [],
            {"*.txt": {"binary": True}},
            "data.txt",
            "binary",
        ),
        (
            "nonexistent_file.txt",
            None,
            None,
            [],
            [],
            {},
            "nonexistent_file.txt",
            "excluded",
        ),
        ("file.txt", "abc", "text", ["*.txt"], ["*.txt"], {}, "file.txt", "excluded"),
    ],
)
def test_categorize_files_by_type(
    tmp_path,
    filename,
    content,
    write_mode,
    include,
    exclude,
    gitattributes,
    expected_in,
    expected_set,
):
    fpath = tmp_path / filename
    if write_mode == "text":
        fpath.write_text(content)
    elif write_mode == "bytes":
        fpath.write_bytes(content)
    to_check, binary, excluded = dna_hook._categorize_files(
        [str(fpath)], include, exclude, gitattributes
    )
    sets = {"to_check": to_check, "binary": binary, "excluded": excluded}
    assert str(fpath) in sets[expected_set]


@pytest.mark.parametrize(
    "include, exclude, files, expected",
    [
        ([], [], [], None),
        (["*.txt"], ["*.py"], [], None),
        (["/path/file.txt"], ["/path/file.txt"], [], "Conflicting"),
        (["*.txt"], ["*.txt"], [], "Conflicting"),
    ],
)
def test_detect_conflicting_file_filters(include, exclude, files, expected):
    result = dna_hook._detect_conflicting_filters(include, exclude, files)
    if expected is None:
        assert result is None
    else:
        assert result is not None and expected in result


@pytest.mark.parametrize(
    "func, cluster, expected",
    [
        (dna_hook._cluster_allowed_balanced, [0x01], False),
        (dna_hook._cluster_allowed_balanced, [0x41, 0xE9], True),
        (dna_hook._cluster_allowed_visible_plus, [0xA0], False),
        (dna_hook._cluster_allowed_visible_plus, [0x200B], False),
        (dna_hook._cluster_allowed_visible_plus, [0x1F600, 0x200D], True),
        (dna_hook._cluster_allowed_visible_plus, [0x41, 0x200D], False),
        (dna_hook._cluster_allowed_visible_plus, [0x41], True),
        (dna_hook._cluster_allowed_ascii_only, [0x41, 0x42], True),
        (dna_hook._cluster_allowed_ascii_only, [0x41, 0xE9], False),
    ],
)
def test_grapheme_cluster_allowed_variants(func, cluster, expected):
    assert func(cluster) is expected


@pytest.mark.parametrize(
    "bstr, ustr, allowed, mode, restrict, extra, expected",
    [
        (b"A", "A", {0x41}, dna_hook.MODE_BALANCED, False, {"A"}, True),
        (
            b"\xc3\xa9",
            "\u00e9",
            {0xC3, 0xA9},
            dna_hook.MODE_ASCII_ONLY,
            True,
            set(),
            True,
        ),
        (b"A", "A", set(), dna_hook.MODE_VISIBLE_PLUS, False, set(), True),
    ],
)
def test_grapheme_cluster_allowed_param(
    bstr, ustr, allowed, mode, restrict, extra, expected
):
    assert (
        dna_hook._cluster_allowed(bstr, ustr, allowed, mode, restrict, extra)
        is expected
    )


@pytest.mark.parametrize(
    "char, expected",
    [
        (chr(0x01), "invisible"),
        (chr(0x1F600), "emoji"),
        ("\u00e9", "other"),
    ],
)
def test_categorize_offender_type(char, expected):
    assert dna_hook._categorize_offender(char) == expected


@pytest.mark.parametrize(
    "char, expected",
    [
        (chr(0x01), [0x01]),
        ("\u00e9", [0xE9]),
        ("A", [0x41]),
    ],
)
def test_get_problematic_codepoints_for_char(char, expected):
    assert dna_hook._get_problematic_codepoints(char) == expected


@pytest.mark.parametrize(
    "offenders, text, fix_mode, expected_out, expected_key, expected_count",
    [
        ([(1, 1, "\u200b")], "abc\u200bdef", True, "Removed", "invisible", 1),
        ([(1, 1, "\u200b")], "abc\u200bdef", False, "Found", "invisible", 1),
        ([(1, 1, "\U0001f600")], "abc\U0001f600def", False, None, "emoji", 1),
        ([(1, 1, "\u00e9")], "abc\u00e9def", False, "other non-ASCII", "other", 1),
        (
            [(1, 1, "\u200d\U0001f600")],
            "test\u200d\U0001f600",
            False,
            "contains problematic",
            None,
            None,
        ),
    ],
)
def test_format_offenders_output_and_counts(
    offenders, text, fix_mode, expected_out, expected_key, expected_count
):
    out, counts = dna_hook._format_offenders(offenders, text, fix_mode=fix_mode)
    if expected_out:
        assert expected_out in out
    if expected_key:
        assert counts[expected_key] == expected_count
    if expected_out == "contains problematic":
        assert "contains problematic" in out


@pytest.mark.parametrize(
    "ustr, allowed, disallowed, mode, restrict, fix_mode, extra, expected_offenders, expected_bytes",
    [
        ("A", {"A"}, set(), dna_hook.MODE_BALANCED, False, False, set(), False, b"A"),
        (
            "\u00e9",
            set(),
            set(),
            dna_hook.MODE_ASCII_ONLY,
            False,
            True,
            set(),
            True,
            b"e",
        ),
        (
            "\u00f8",
            set(),
            set(),
            dna_hook.MODE_ASCII_ONLY,
            False,
            True,
            set(),
            True,
            b"",
        ),
        (
            "\u4e2d",
            set(),
            set(),
            dna_hook.MODE_ASCII_ONLY,
            False,
            True,
            set(),
            True,
            b"",
        ),
    ],
)
def test_process_grapheme_clusters_expected_bytes(
    ustr,
    allowed,
    disallowed,
    mode,
    restrict,
    fix_mode,
    extra,
    expected_offenders,
    expected_bytes,
):
    offenders, new_chunks = dna_hook._process_grapheme_clusters(
        ustr, allowed, disallowed, mode, restrict, fix_mode, extra
    )
    if expected_offenders:
        assert offenders
    else:
        assert not offenders
    assert expected_bytes == b"".join(new_chunks)


@pytest.mark.parametrize(
    "bstr, allowed, fix_mode, expected_offenders, expected_new_chunks",
    [
        (b"abc", {0x61, 0x62, 0x63}, True, False, b"abc"),
        (b"\x01\x02", {0x61}, True, True, b""),
        (b"\x01", {0x61}, False, True, b"\x01"),
    ],
)
def test_process_bytes_expected_chunks(
    bstr, allowed, fix_mode, expected_offenders, expected_new_chunks
):
    offenders, new_chunks = dna_hook._process_bytes(bstr, allowed, fix_mode)
    if expected_offenders:
        assert offenders
    else:
        assert not offenders
    assert expected_new_chunks in b"".join(new_chunks)


@pytest.mark.parametrize(
    "bytes_content, allowed, mode, expect_offenders, expect_orig_text",
    [
        (b"abc\xff", {0x61, 0x62, 0x63}, dna_hook.MODE_ASCII_ONLY, True, None),
        (b"abc", {0x61, 0x62, 0x63}, dna_hook.MODE_ASCII_ONLY, False, "abc"),
    ],
)
def test_process_single_file_utf8_and_non_utf8(
    tmp_path, bytes_content, allowed, mode, expect_offenders, expect_orig_text
):
    f = tmp_path / "file.bin"
    f.write_bytes(bytes_content)
    offenders, new_data, orig_text = dna_hook._process_single_file(
        str(f), allowed, set(), mode, False, False, set()
    )
    if expect_offenders:
        assert offenders
    else:
        assert not offenders
    if expect_orig_text is None:
        assert orig_text is None
    else:
        assert orig_text == expect_orig_text


@pytest.mark.parametrize(
    "value",
    ["0xZZ", "300"],
)
def test_parse_byte_invalid_values_exit(value):
    parser = argparse.ArgumentParser()
    with pytest.raises(SystemExit):
        dna_hook._parse_byte(value, parser)


@pytest.mark.parametrize(
    "args_dict, expect_system_exit, expect_extra, expect_allowed",
    [
        ({"include_range": ["0x00-0xFF"], "allow_chars": []}, True, None, None),
        (
            {"include_range": None, "allow_chars": ["\u00e9"]},
            False,
            "\u00e9",
            [0xC3, 0xA9],
        ),
    ],
)
def test_build_allowed_set_and_extra(
    args_dict, expect_system_exit, expect_extra, expect_allowed
):
    parser = argparse.ArgumentParser()
    args = type("Args", (), args_dict)()
    if expect_system_exit:
        with pytest.raises(SystemExit):
            dna_hook._build_allowed(args, parser)
    else:
        allowed, restrict, extra = dna_hook._build_allowed(args, parser)
        assert expect_extra in extra
        assert any(a in allowed for a in expect_allowed)


@pytest.mark.parametrize(
    "content, mode, expected_ret, desc",
    [
        ("Aabc\x01def", "balanced", 1, "Control char in balanced"),
        ("Aabc\U0001f600def", "balanced", 1, "Emoji in balanced"),
        ("Aabc\u200bdef", "balanced", 1, "Zero-width space in balanced"),
        ("Aabcdef", "balanced", 0, "All ASCII, clean"),
        ("A", "balanced", 0, "Empty file (with ASCII)"),
        ("Acaf\u00e9", "balanced", 0, "Latin-1 allowed in balanced"),
        ("Acaf\u00e9", "ascii-only", 1, "Latin-1 blocked in ascii-only"),
        ("A\u0100\u0101", "balanced", 0, "Latin Ext-A allowed in balanced"),
        ("A\u0100\u0101", "ascii-only", 1, "Latin Ext-A blocked in ascii-only"),
    ],
)
def test_main_core_detection_modes(tmp_path, content, mode, expected_ret, desc):
    path = tmp_path / "test.txt"
    path.write_text(content, encoding="utf-8")
    assert dna_hook.main(["--mode", mode, str(path)]) == expected_ret


@pytest.mark.parametrize(
    "files, contents, expected_ret, desc",
    [
        (["clean1.txt", "clean2.txt"], ["hello\n", "world\n"], 0, "All clean"),
        (["bad1.txt", "clean.txt"], ["abc\x01def", "hello\n"], 1, "One bad file"),
        (
            ["bad1.txt", "bad2.txt"],
            ["abc\x01def", "h\u00e9llo\U0001f600\n"],
            1,
            "Multiple bad",
        ),
    ],
)
def test_main_integration_multiple_files(tmp_path, files, contents, expected_ret, desc):
    paths = []
    for fname, content in zip(files, contents):
        p = tmp_path / fname
        p.write_text(content, encoding="utf-8", errors="replace")
        paths.append(str(p))
    assert dna_hook.main(paths) == expected_ret


@pytest.mark.parametrize(
    "cli_args, expected_exit, desc",
    [
        (["--unknown-flag"], 2, "Unknown CLI argument"),
        (
            ["--include-range", '["0xZZ-0x10","0xZZ-0x11"]', "file.txt"],
            2,
            "Invalid byte range",
        ),
        (["--include-range", "0x10-0x01", "file.txt"], 2, "Descending range"),
        (
            ["--file-include", "file.txt", "--file-exclude", "file.txt", "file.txt"],
            2,
            "Conflicting explicit paths",
        ),
        (
            ["--file-include", "*.txt", "--file-exclude", "*.txt", "file.txt"],
            2,
            "Conflicting globs",
        ),
    ],
)
def test_main_error_scenarios(tmp_path, cli_args, expected_exit, desc):
    for arg in cli_args:
        if arg.endswith(".txt"):
            (tmp_path / arg).write_text("ok", encoding="utf-8")
    with pytest.raises(SystemExit) as exc_info:
        dna_hook.main(
            [str(tmp_path / arg) if arg.endswith(".txt") else arg for arg in cli_args]
        )
    assert exc_info.value.code == expected_exit


@pytest.mark.parametrize(
    "filename, content, cli_args, expected_ret, desc",
    [
        ("empty.txt", "", [], 0, "Empty file passes"),
        ("allowed.txt", "abc\t\n\r", [], 0, "Only allowed chars"),
        ("disallowed.txt", "abc\x01def", [], 1, "Disallowed control char"),
        (
            "skip.bin",
            "abc\x01def",
            ["--file-include", "*.txt"],
            0,
            "Excluded by pattern",
        ),
        (
            "take.txt",
            "xyz\x01uvw",
            ["--file-include", "*.txt"],
            1,
            "Included with issues",
        ),
        ("large.txt", "a" * 100000 + "\x01", [], 1, "Large file with offender"),
    ],
)
def test_main_file_filtering_and_edge_cases(
    tmp_path, filename, content, cli_args, expected_ret, desc
):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8", errors="replace")
    assert dna_hook.main(cli_args + [str(path)]) == expected_ret


@pytest.mark.parametrize(
    "filename, content, cli_args, expected_ret, desc, fix_mode, expected_content",
    [
        ("empty.txt", "", [], 0, "Empty file passes", False, None),
        ("allowed.txt", "abc\t\n\r", [], 0, "Only allowed chars", False, None),
        ("disallowed.txt", "abc\x01def", [], 1, "Disallowed control char", False, None),
        (
            "skip.bin",
            "abc\x01def",
            ["--file-include", "*.txt"],
            0,
            "Excluded by pattern",
            False,
            None,
        ),
        (
            "take.txt",
            "xyz\x01uvw",
            ["--file-include", ["*.txt", "*.fr"]],
            1,
            "Included with issues",
            False,
            None,
        ),
        (
            "large.txt",
            "a" * 100000 + "\x01",
            [],
            1,
            "Large file with offender",
            False,
            None,
        ),
        ("bad.txt", "abc\x01", [], 1, "Fix mode removes bad char", True, "abc"),
    ],
)
def test_main_file_filtering_and_fix_mode(
    tmp_path,
    filename,
    content,
    cli_args,
    expected_ret,
    desc,
    fix_mode,
    expected_content,
):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8", errors="replace")
    args = cli_args + (["--fix"] if fix_mode else []) + [str(path)]
    ret = dna_hook.main(args)
    assert ret == expected_ret
    if fix_mode and expected_content is not None:
        assert expected_content in path.read_text(encoding="utf-8", errors="replace")


def test_main_conflict_error_truncation(tmp_path, capsys):
    files = [str(tmp_path / f"f{i}.txt") for i in range(12)]
    for f in files:
        Path(f).write_text("ok")
    include_csv = ",".join(files)
    with pytest.raises(SystemExit) as exc_info:
        dna_hook.main(
            ["--file-include", include_csv, "--file-exclude", include_csv] + files
        )
    assert exc_info.value.code == 2
    out = capsys.readouterr().out
    assert "..." in out


@pytest.mark.parametrize(
    "contents, cli_args, expected_ret, desc",
    [
        (
            ["abc", "abc", "abc", "abc"],
            ["--mode", "ascii-only"],
            0,
            "ASCII-only, all clean",
        ),
        (
            ["abc", "abc\x01", "abc", "abc"],
            ["--mode", "ascii-only"],
            1,
            "ASCII-only, control char",
        ),
        (
            ["abc💻", "abc", "abc", "abc"],
            ["--mode", "ascii-only", "--allow-chars", "💻"],
            0,
            "ASCII-only, allow emoji",
        ),
        (
            ["abc💻🚀🍴°₂", "abc", "abc", "abc"],
            [
                "--mode",
                "ascii-only",
                "--allow-chars",
                "💻🚀🍴",
                "--allow-chars",
                "°",
                "--allow-chars",
                "₂",
            ],
            0,
            "ASCII-only, allow all three",
        ),
        (
            ["abc💻🚀🍴°₂", "abc", "abc", "abc"],
            [
                "--mode",
                "visible-plus",
                "--fix",
                "--allow-chars",
                "💻🚀🍴",
                "--allow-chars",
                "°",
                "--allow-chars",
                "₂",
            ],
            0,
            "Visible-plus, fix, allow all three",
        ),
        (
            ["abc💻🚀🍴°₂", "abc", "abc", "abc"],
            ["--allow-chars", "💻,🚀,🍴", "--allow-chars", "°", "--allow-chars", "₂"],
            0,
            "Balanced, allow all three comma-separated",
        ),
        (
            ["abc\t\n\r", "abc", "abc", "abc"],
            [
                "--mode",
                "ascii-only",
                "--include-range",
                "0x20-0x7E",
                "--include-range",
                "0x09",
                "--include-range",
                "0x0A",
                "--include-range",
                "0x0D",
            ],
            0,
            "ASCII-only, multiple include-range",
        ),
        (
            ["abc💻🚀🍴°₂", "abc", "abc", "abc"],
            [
                "--fix",
                "--allow-chars",
                "💻🚀🍴",
                "--allow-chars",
                "°₂",
                "--file-exclude",
                "*.md",
            ],
            0,
            "Balanced, fix, allow all three, exclude md",
        ),
        (
            ["abc💻🚀🍴°₂", "abc", "abc", "abc"],
            [
                "--mode",
                "ascii-only",
                "--fix",
                "--allow-chars",
                "💻,🚀,🍴",
                "--allow-chars",
                "°",
                "--allow-chars",
                "₂",
                "--file-exclude",
                "*.py",
            ],
            0,
            "ASCII-only, fix, allow all three, exclude py",
        ),
        (
            ["abc💻", "abc", "abc", "abc"],
            ["--mode", "ascii-only", "--file-include", "*.txt", "--allow-chars", "💻"],
            0,
            "ASCII-only, file-include txt, allow emoji",
        ),
    ],
)
def test_main_argument_combinations_four_files(
    tmp_path, contents, cli_args, expected_ret, desc
):
    filenames = ["file1.txt", "file2.txt", "file3.md", "file4.py"]
    paths = []
    for fname, content in zip(filenames, contents):
        path = tmp_path / fname
        path.write_text(content, encoding="utf-8")
        paths.append(str(path))
    assert dna_hook.main(cli_args + paths) == expected_ret
