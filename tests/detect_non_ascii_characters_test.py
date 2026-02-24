import pytest
import argparse
from pathlib import Path
from pre_commit_hooks import detect_non_ascii_characters as dna_hook


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "lines": [
                    "# comment line",
                    "",
                    "onlypattern",
                    "pat1 binary",
                    "pat2 -text filter=lfs",
                    "pat3 filter=lfs",
                    "pat4 filter=other",
                ],
                "expected_attrs": {
                    "pat1": {"binary": True},
                    "pat2": {"binary": True, "filter": "lfs"},
                    "pat3": {"filter": "lfs"},
                },
            },
            id="multiple_patterns_and_attrs",
        ),
        pytest.param(
            {
                "lines": ["foo.txt binary"],
                "expected_attrs": {"foo.txt": {"binary": True}},
            },
            id="single_binary",
        ),
        pytest.param(
            {"lines": ["bar"], "expected_attrs": {}},
            id="no_attrs",
        ),
        pytest.param(
            {"lines": ["baz.txt filter=other"], "expected_attrs": {}},
            id="filter_other_ignored",
        ),
    ],
)
def test_parse_gitattributes_expected_attributes(tmp_path, case):
    ga = tmp_path / ".gitattributes"
    ga.write_text("\n".join(case["lines"]), encoding="utf-8")
    attrs = dna_hook.parse_gitattributes(str(ga))
    expected_attrs = case["expected_attrs"]
    assert attrs == expected_attrs


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "filename": "test.png",
                "gitattributes": {"*.png": {"binary": True}},
                "expected": True,
            },
            id="png_binary_true",
        ),
        pytest.param(
            {
                "filename": "test.bin",
                "gitattributes": {"*.bin": {"filter": "lfs"}},
                "expected": True,
            },
            id="bin_filter_lfs",
        ),
        pytest.param(
            {
                "filename": "test.bin",
                "gitattributes": {"*.bin": {"binary": True, "filter": "lfs"}},
                "expected": True,
            },
            id="bin_binary_and_filter_lfs",
        ),
        pytest.param(
            {
                "filename": "test.txt",
                "gitattributes": {"*.png": {"binary": True}},
                "expected": False,
            },
            id="txt_not_matched",
        ),
        pytest.param(
            {
                "filename": "test.foo",
                "gitattributes": {"*.foo": {"binary": True}},
                "expected": True,
            },
            id="foo_binary_true",
        ),
        pytest.param(
            {
                "filename": "test.bar",
                "gitattributes": {"*.bar": {"filter": "other"}},
                "expected": False,
            },
            id="bar_filter_other_false",
        ),
        pytest.param(
            {
                "filename": "test.baz",
                "gitattributes": {"*.baz": {"filter": "lfs"}},
                "expected": True,
            },
            id="baz_filter_lfs_true",
        ),
        pytest.param(
            {"filename": "test.txt", "gitattributes": {}, "expected": False},
            id="txt_empty_attrs_false",
        ),
    ],
)
def test_file_is_binary_matches_expected(case):
    assert (
        dna_hook.file_is_binary(case["filename"], case["gitattributes"])
        is case["expected"]
    )


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "filename": "file.txt",
                "content": "abc",
                "write_mode": "text",
                "include": ["file.txt"],
                "exclude": [],
                "gitattributes": {},
                "expected_in": "file.txt",
                "expected_set": "to_check",
            },
            id="include_file_txt_to_check",
        ),
        pytest.param(
            {
                "filename": "file.txt",
                "content": "abc",
                "write_mode": "text",
                "include": [],
                "exclude": ["*.txt"],
                "gitattributes": {},
                "expected_in": "file.txt",
                "expected_set": "excluded",
            },
            id="exclude_txt_pattern",
        ),
        pytest.param(
            {
                "filename": ".pre-commit-config.yaml",
                "content": "repos: []",
                "write_mode": "text",
                "include": [],
                "exclude": [],
                "gitattributes": {},
                "expected_in": ".pre-commit-config.yaml",
                "expected_set": "excluded",
            },
            id="pre_commit_config_excluded",
        ),
        pytest.param(
            {
                "filename": "test.png",
                "content": b"\x89PNG\r\n\x1a\n" + b"\x00" * 10,
                "write_mode": "bytes",
                "include": [],
                "exclude": [],
                "gitattributes": {},
                "expected_in": "test.png",
                "expected_set": "binary",
            },
            id="png_bytes_binary",
        ),
        pytest.param(
            {
                "filename": "data.dat",
                "content": b"\x00" * 10,
                "write_mode": "bytes",
                "include": [],
                "exclude": [],
                "gitattributes": {},
                "expected_in": "data.dat",
                "expected_set": "binary",
            },
            id="dat_bytes_binary",
        ),
        pytest.param(
            {
                "filename": "data.txt",
                "content": "hello",
                "write_mode": "text",
                "include": [],
                "exclude": [],
                "gitattributes": {"*.txt": {"binary": True}},
                "expected_in": "data.txt",
                "expected_set": "binary",
            },
            id="txt_gitattributes_binary",
        ),
        pytest.param(
            {
                "filename": "nonexistent_file.txt",
                "content": None,
                "write_mode": None,
                "include": [],
                "exclude": [],
                "gitattributes": {},
                "expected_in": "nonexistent_file.txt",
                "expected_set": "excluded",
            },
            id="nonexistent_file_excluded",
        ),
        pytest.param(
            {
                "filename": "file.txt",
                "content": "abc",
                "write_mode": "text",
                "include": ["*.txt"],
                "exclude": ["*.txt"],
                "gitattributes": {},
                "expected_in": "file.txt",
                "expected_set": "excluded",
            },
            id="include_and_exclude_txt",
        ),
    ],
)
def test_categorize_files_by_type(tmp_path, case):
    fpath = tmp_path / case["filename"]
    if case["write_mode"] == "text":
        fpath.write_text(case["content"])
    elif case["write_mode"] == "bytes":
        fpath.write_bytes(case["content"])
    to_check, binary, excluded = dna_hook._categorize_files(
        [str(fpath)], case["include"], case["exclude"], case["gitattributes"]
    )
    sets = {"to_check": to_check, "binary": binary, "excluded": excluded}
    assert str(fpath) in sets[case["expected_set"]]


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {"include": [], "exclude": [], "files": [], "expected": None},
            id="no_filters_no_conflict",
        ),
        pytest.param(
            {"include": ["*.txt"], "exclude": ["*.py"], "files": [], "expected": None},
            id="different_globs_no_conflict",
        ),
        pytest.param(
            {
                "include": ["/path/file.txt"],
                "exclude": ["/path/file.txt"],
                "files": [],
                "expected": "Conflicting",
            },
            id="same_path_conflict",
        ),
        pytest.param(
            {
                "include": ["*.txt"],
                "exclude": ["*.txt"],
                "files": [],
                "expected": "Conflicting",
            },
            id="same_glob_conflict",
        ),
    ],
)
def test_detect_conflicting_file_filters(case):
    result = dna_hook._detect_conflicting_filters(
        case["include"], case["exclude"], case["files"]
    )
    if case["expected"] is None:
        assert result is None
    else:
        assert result is not None and case["expected"] in result


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "func": dna_hook._cluster_allowed_balanced,
                "cluster": [0x01],  # Represents: Control character
                "expected": False,
            },
            id="balanced_control_char",
        ),
        pytest.param(
            {
                "func": dna_hook._cluster_allowed_balanced,
                "cluster": [0x41, 0xE9],  # Represents: A + é
                "expected": True,
            },
            id="balanced_ascii_latin1",
        ),
        pytest.param(
            {
                "func": dna_hook._cluster_allowed_visible_plus,
                "cluster": [0xA0],  # Represents: Non-breaking space
                "expected": False,
            },
            id="visible_plus_nbsp",
        ),
        pytest.param(
            {
                "func": dna_hook._cluster_allowed_visible_plus,
                "cluster": [0x200B],  # Represents: Zero-width space
                "expected": False,
            },
            id="visible_plus_zwsp",
        ),
        pytest.param(
            {
                "func": dna_hook._cluster_allowed_visible_plus,
                "cluster": [0x1F600, 0x200D],  # Represents: 😀 + ZWJ
                "expected": True,
            },
            id="visible_plus_emoji_zwj",
        ),
        pytest.param(
            {
                "func": dna_hook._cluster_allowed_visible_plus,
                "cluster": [0x41, 0x200D],  # Represents: A +  ZWJ
                "expected": False,
            },
            id="visible_plus_ascii_zwj",
        ),
        pytest.param(
            {
                "func": dna_hook._cluster_allowed_visible_plus,
                "cluster": [0x41],  # Represents: A
                "expected": True,
            },
            id="visible_plus_ascii",
        ),
        pytest.param(
            {
                "func": dna_hook._cluster_allowed_ascii_only,
                "cluster": [0x41, 0x42],  # Represents: A + B
                "expected": True,
            },
            id="ascii_only_ascii",
        ),
        pytest.param(
            {
                "func": dna_hook._cluster_allowed_ascii_only,
                "cluster": [0x41, 0xE9],  # Represents: A + é
                "expected": False,
            },
            id="ascii_only_latin1",
        ),
    ],
)
def test_grapheme_cluster_allowed_variants(case):
    assert case["func"](case["cluster"]) is case["expected"]


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "bstr": b"A",
                "ustr": "A",
                "allowed": {0x41},  # Represents: A
                "mode": dna_hook.MODE_BALANCED,
                "restrict": False,
                "extra": {"A"},
                "expected": True,
            },
            id="balanced_ascii_A",
        ),
        pytest.param(
            {
                "bstr": b"\xc3\xa9",
                "ustr": "\u00e9",
                "allowed": {
                    0xC3,
                    0xA9,
                },  # Represents: é in UTF-8 bytes and as a Unicode char
                "mode": dna_hook.MODE_ASCII_ONLY,
                "restrict": True,
                "extra": set(),
                "expected": True,
            },
            id="ascii_only_latin1_bytes",
        ),
        pytest.param(
            {
                "bstr": b"A",
                "ustr": "A",
                "allowed": set(),
                "mode": dna_hook.MODE_VISIBLE_PLUS,
                "restrict": False,
                "extra": set(),
                "expected": True,
            },
            id="visible_plus_ascii_A",
        ),
    ],
)
def test_grapheme_cluster_allowed_param(case):
    assert (
        dna_hook._cluster_allowed(
            case["bstr"],
            case["ustr"],
            case["allowed"],
            case["mode"],
            case["restrict"],
            case["extra"],
        )
        is case["expected"]
    )


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {"char": chr(0x01), "expected": "invisible"},
            id="control_char_invisible",  # Represents: Control character
        ),
        pytest.param(
            {"char": chr(0x1F600), "expected": "emoji"}, id="emoji_char"
        ),  # Represents: 😀
        pytest.param(
            {"char": "\u00e9", "expected": "other"}, id="latin1_other"
        ),  # Represents: é
    ],
)
def test_categorize_offender_type(case):
    assert dna_hook._categorize_offender(case["char"]) == case["expected"]


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {"char": chr(0x01), "expected": [0x01]},
            id="control_char_codepoint",  # Represents: Control character
        ),
        pytest.param(
            {"char": "\u00e9", "expected": [0xE9]}, id="latin1_codepoint"
        ),  # Represents: é
        pytest.param(
            {"char": "A", "expected": [0x41]}, id="ascii_codepoint"
        ),  # Represents: A
    ],
)
def test_get_problematic_codepoints_for_char(case):
    assert dna_hook._get_problematic_codepoints(case["char"]) == case["expected"]


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "offenders": [(1, 1, "\u200b")],
                "text": "abc\u200bdef",  # Represents: abc + zero-width space + def
                "fix_mode": True,
                "expected_out": "Removed",
                "expected_key": "invisible",
                "expected_count": 1,
            },
            id="zwsp_removed",
        ),
        pytest.param(
            {
                "offenders": [(1, 1, "\u200b")],
                "text": "abc\u200bdef",  # Represents: abc + zero-width space + def
                "fix_mode": False,
                "expected_out": "Found",
                "expected_key": "invisible",
                "expected_count": 1,
            },
            id="zwsp_found",
        ),
        pytest.param(
            {
                "offenders": [(1, 1, "\U0001f600")],
                "text": "abc\U0001f600def",  # Represents: abc + 😀 + def
                "fix_mode": False,
                "expected_out": None,
                "expected_key": "emoji",
                "expected_count": 1,
            },
            id="emoji_found",
        ),
        pytest.param(
            {
                "offenders": [(1, 1, "\u00e9")],
                "text": "abc\u00e9def",  # Represents: abc + é + def
                "fix_mode": False,
                "expected_out": "other non-ASCII",
                "expected_key": "other",
                "expected_count": 1,
            },
            id="latin1_other_found",
        ),
        pytest.param(
            {
                "offenders": [(1, 1, "\u200d\U0001f600")],
                "text": "test\u200d\U0001f600",  # Represents: test + ZWJ + 😀
                "fix_mode": False,
                "expected_out": "contains problematic",
                "expected_key": None,
                "expected_count": None,
            },
            id="zwj_emoji_problematic",
        ),
    ],
)
def test_format_offenders_output_and_counts(case):
    out, counts = dna_hook._format_offenders(
        case["offenders"], case["text"], fix_mode=case["fix_mode"]
    )
    if case["expected_out"]:
        assert case["expected_out"] in out
    if case["expected_key"]:
        assert counts[case["expected_key"]] == case["expected_count"]
    if case["expected_out"] == "contains problematic":
        assert "contains problematic" in out


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "ustr": "A",
                "allowed": {"A"},
                "disallowed": set(),
                "mode": dna_hook.MODE_BALANCED,
                "restrict": False,
                "fix_mode": False,
                "extra": set(),
                "expected_offenders": False,
                "expected_bytes": b"A",
            },
            id="balanced_ascii_A_bytes",
        ),
        pytest.param(
            {
                "ustr": "\u00e9",  # Represents: é
                "allowed": set(),
                "disallowed": set(),
                "mode": dna_hook.MODE_ASCII_ONLY,
                "restrict": False,
                "fix_mode": True,
                "extra": set(),
                "expected_offenders": True,
                "expected_bytes": b"e",
            },
            id="ascii_only_latin1_to_e",
        ),
        pytest.param(
            {
                "ustr": "\u00f8",  # Represents: ø
                "allowed": set(),
                "disallowed": set(),
                "mode": dna_hook.MODE_ASCII_ONLY,
                "restrict": False,
                "fix_mode": True,
                "extra": set(),
                "expected_offenders": True,
                "expected_bytes": b"",
            },
            id="ascii_only_o_slash_removed",
        ),
        pytest.param(
            {
                "ustr": "\u4e2d",  # Represents: 中 (a CJK character)
                "allowed": set(),
                "disallowed": set(),
                "mode": dna_hook.MODE_ASCII_ONLY,
                "restrict": False,
                "fix_mode": True,
                "extra": set(),
                "expected_offenders": True,
                "expected_bytes": b"",
            },
            id="ascii_only_cjk_removed",
        ),
    ],
)
def test_process_grapheme_clusters_expected_bytes(case):
    offenders, new_chunks = dna_hook._process_grapheme_clusters(
        case["ustr"],
        case["allowed"],
        case["disallowed"],
        case["mode"],
        case["restrict"],
        case["fix_mode"],
        case["extra"],
    )
    if case["expected_offenders"]:
        assert offenders
    else:
        assert not offenders
    assert case["expected_bytes"] == b"".join(new_chunks)


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "bstr": b"abc",
                "allowed": {0x61, 0x62, 0x63},  # Represents: a, b, c
                "fix_mode": True,
                "expected_offenders": False,
                "expected_new_chunks": b"abc",
            },
            id="ascii_bytes_no_offenders",
        ),
        pytest.param(
            {
                "bstr": b"\x01\x02",  # Represents: Control characters
                "allowed": {0x61},  # Represents: a
                "fix_mode": True,
                "expected_offenders": True,
                "expected_new_chunks": b"",
            },
            id="control_bytes_removed",
        ),
        pytest.param(
            {
                "bstr": b"\x01",  # Represents: Control character
                "allowed": {0x61},  # Represents: a
                "fix_mode": False,
                "expected_offenders": True,
                "expected_new_chunks": b"\x01",
            },
            id="control_bytes_retained_no_fix",
        ),
    ],
)
def test_process_bytes_expected_chunks(case):
    offenders, new_chunks = dna_hook._process_bytes(
        case["bstr"], case["allowed"], case["fix_mode"]
    )
    if case["expected_offenders"]:
        assert offenders
    else:
        assert not offenders
    assert case["expected_new_chunks"] in b"".join(new_chunks)


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "bytes_content": b"abc\xff",  # Represents: abc + invalid UTF-8 byte
                "allowed": {0x61, 0x62, 0x63},  # Represents: a, b, c
                "mode": dna_hook.MODE_ASCII_ONLY,
                "expect_offenders": True,
                "expect_orig_text": None,
            },
            id="non_utf8_bytes_offender",
        ),
        pytest.param(
            {
                "bytes_content": b"abc",
                "allowed": {0x61, 0x62, 0x63},  # Represents: a, b, c
                "mode": dna_hook.MODE_ASCII_ONLY,
                "expect_offenders": False,
                "expect_orig_text": "abc",
            },
            id="ascii_bytes_clean",
        ),
    ],
)
def test_process_single_file_utf8_and_non_utf8(tmp_path, case):
    f = tmp_path / "file.bin"
    f.write_bytes(case["bytes_content"])
    offenders, new_data, orig_text = dna_hook._process_single_file(
        str(f), case["allowed"], set(), case["mode"], False, False, set()
    )
    if case["expect_offenders"]:
        assert offenders
    else:
        assert not offenders
    if case["expect_orig_text"] is None:
        assert orig_text is None
    else:
        assert orig_text == case["expect_orig_text"]


@pytest.mark.parametrize(
    "case",
    [
        pytest.param({"value": "0xZZ"}, id="invalid_hex"),
        pytest.param({"value": "300"}, id="out_of_range"),
    ],
)
def test_parse_byte_invalid_values_exit(case):
    parser = argparse.ArgumentParser()
    with pytest.raises(SystemExit):
        dna_hook._parse_byte(case["value"], parser)


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "args_dict": {
                    "include_range": ["0x00-0xFF"],
                    "allow_chars": [],
                },  # Represents: Full byte range
                "expect_system_exit": True,
                "expect_extra": None,
                "expect_allowed": None,
            },
            id="full_range_exit",
        ),
        pytest.param(
            {
                "args_dict": {
                    "include_range": None,
                    "allow_chars": ["\u00e9"],
                },  # Represents: é
                "expect_system_exit": False,
                "expect_extra": "\u00e9",
                "expect_allowed": [0xC3, 0xA9],
            },
            id="allow_latin1",
        ),
    ],
)
def test_build_allowed_set_and_extra(case):
    parser = argparse.ArgumentParser()
    args = type("Args", (), case["args_dict"])()
    if case["expect_system_exit"]:
        with pytest.raises(SystemExit):
            dna_hook._build_allowed(args, parser)
    else:
        allowed, restrict, extra = dna_hook._build_allowed(args, parser)
        assert case["expect_extra"] in extra
        assert any(a in allowed for a in case["expect_allowed"])


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "content": "Aabc\x01def",  # Represents: abc + control character + def
                "mode": "balanced",
                "expected_ret": 1,
                "desc": "Control char in balanced",
            },
            id="balanced_control_char",
        ),
        pytest.param(
            {
                "content": "Aabc\U0001f600def",  #   Represents: abc + 😀 + def
                "mode": "balanced",
                "expected_ret": 1,
                "desc": "Emoji in balanced",
            },
            id="balanced_emoji",
        ),
        pytest.param(
            {
                "content": "Aabc\u200bdef",  # Represents: abc + zero-width space + def
                "mode": "balanced",
                "expected_ret": 1,
                "desc": "Zero-width space in balanced",
            },
            id="balanced_zwsp",
        ),
        pytest.param(
            {
                "content": "Aabcdef",
                "mode": "balanced",
                "expected_ret": 0,
                "desc": "All ASCII, clean",
            },
            id="balanced_ascii_clean",
        ),
        pytest.param(
            {
                "content": "A",
                "mode": "balanced",
                "expected_ret": 0,
                "desc": "Empty file (with ASCII)",
            },
            id="balanced_ascii_empty",
        ),
        pytest.param(
            {
                "content": "Acaf\u00e9",  # Represents: aca + é
                "mode": "balanced",
                "expected_ret": 0,
                "desc": "Latin-1 allowed in balanced",
            },
            id="balanced_latin1_allowed",
        ),
        pytest.param(
            {
                "content": "Acaf\u00e9",  # Represents: aca + é
                "mode": "ascii-only",
                "expected_ret": 1,
                "desc": "Latin-1 blocked in ascii-only",
            },
            id="ascii_only_latin1_blocked",
        ),
        pytest.param(
            {
                "content": "A\u0100\u0101",  # Represents: A + Ā + ā (Latin Ext-A)
                "mode": "balanced",
                "expected_ret": 0,
                "desc": "Latin Ext-A allowed in balanced",
            },
            id="balanced_latin_extA_allowed",
        ),
        pytest.param(
            {
                "content": "A\u0100\u0101",  # Represents: A + Ā + ā (Latin Ext-A)
                "mode": "ascii-only",
                "expected_ret": 1,
                "desc": "Latin Ext-A blocked in ascii-only",
            },
            id="ascii_only_latin_extA_blocked",
        ),
    ],
)
def test_main_core_detection_modes(tmp_path, case):
    path = tmp_path / "test.txt"
    path.write_text(case["content"], encoding="utf-8")
    assert dna_hook.main(["--mode", case["mode"], str(path)]) == case["expected_ret"]


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "files": ["clean1.txt", "clean2.txt"],
                "contents": ["hello\n", "world\n"],
                "expected_ret": 0,
                "desc": "All clean",
            },
            id="all_clean",
        ),
        pytest.param(
            {
                "files": ["bad1.txt", "clean.txt"],
                "contents": [
                    "abc\x01def",
                    "hello\n",
                ],  # Represents: abc + control character + def
                "expected_ret": 1,
                "desc": "One bad file",
            },
            id="one_bad_file",
        ),
        pytest.param(
            {
                "files": ["bad1.txt", "bad2.txt"],
                "contents": [
                    "abc\x01def",
                    "h\u00e9llo\U0001f600\n",
                ],  # Represents: abc + control character + def and h + é + llo + 😀
                "expected_ret": 1,
                "desc": "Multiple bad",
            },
            id="multiple_bad",
        ),
    ],
)
def test_main_integration_multiple_files(tmp_path, case):
    paths = []
    for fname, content in zip(case["files"], case["contents"]):
        p = tmp_path / fname
        p.write_text(content, encoding="utf-8", errors="replace")
        paths.append(str(p))
    assert dna_hook.main(paths) == case["expected_ret"]


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "cli_args": ["--unknown-flag"],
                "expected_exit": 2,
                "desc": "Unknown CLI argument",
            },
            id="unknown_flag",
        ),
        pytest.param(
            {
                "cli_args": [
                    "--include-range",
                    '["0xZZ-0x10","0xZZ-0x11"]',  # Represents: Invalid hex values in byte range
                    "file.txt",
                ],
                "expected_exit": 2,
                "desc": "Invalid byte range",
            },
            id="invalid_byte_range",
        ),
        pytest.param(
            {
                "cli_args": [
                    "--include-range",
                    "0x10-0x01",
                    "file.txt",
                ],  # Represents: Descending byte range
                "expected_exit": 2,
                "desc": "Descending range",
            },
            id="descending_range",
        ),
        pytest.param(
            {
                "cli_args": [
                    "--file-include",
                    "file.txt",
                    "--file-exclude",
                    "file.txt",
                    "file.txt",
                ],
                "expected_exit": 2,
                "desc": "Conflicting explicit paths",
            },
            id="conflicting_explicit_paths",
        ),
        pytest.param(
            {
                "cli_args": [
                    "--file-include",
                    "*.txt",
                    "--file-exclude",
                    "*.txt",
                    "file.txt",
                ],
                "expected_exit": 2,
                "desc": "Conflicting globs",
            },
            id="conflicting_globs",
        ),
    ],
)
def test_main_error_scenarios(tmp_path, case):
    for arg in case["cli_args"]:
        if arg.endswith(".txt") and arg.replace('.txt', '').isalnum():
            (tmp_path / arg).write_text("ok", encoding="utf-8")
    with pytest.raises(SystemExit) as exc_info:
        dna_hook.main(
            [
                str(tmp_path / arg) if arg.endswith(".txt") else arg
                for arg in case["cli_args"]
            ]
        )
    assert exc_info.value.code == case["expected_exit"]


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "filename": "empty.txt",
                "content": "",
                "cli_args": [],
                "expected_ret": 0,
                "desc": "Empty file passes",
            },
            id="empty_file_passes",
        ),
        pytest.param(
            {
                "filename": "allowed.txt",
                "content": "abc\t\n\r",  # Represents: abc + tab + newline + carriage return
                "cli_args": [],
                "expected_ret": 0,
                "desc": "Only allowed chars",
            },
            id="only_allowed_chars",
        ),
        pytest.param(
            {
                "filename": "disallowed.txt",
                "content": "abc\x01def",  # Represents: abc + control character + def
                "cli_args": [],
                "expected_ret": 1,
                "desc": "Disallowed control char",
            },
            id="disallowed_control_char",
        ),
        pytest.param(
            {
                "filename": "skip.bin",
                "content": "abc\x01def",  # Represents: abc + control character + def
                "cli_args": ["--file-include", "*.txt"],
                "expected_ret": 0,
                "desc": "Excluded by pattern",
            },
            id="excluded_by_pattern",
        ),
        pytest.param(
            {
                "filename": "take.txt",
                "content": "xyz\x01uvw",  # Represents: xyz + control character + uvw
                "cli_args": ["--file-include", "*.txt"],
                "expected_ret": 1,
                "desc": "Included with issues",
            },
            id="included_with_issues",
        ),
        pytest.param(
            {
                "filename": "large.txt",
                "content": "a" * 100000
                + "\x01",  # Represents: 100,000 'a' characters followed by a control character
                "cli_args": [],
                "expected_ret": 1,
                "desc": "Large file with offender",
            },
            id="large_file_with_offender",
        ),
    ],
)
def test_main_file_filtering_and_edge_cases(tmp_path, case):
    path = tmp_path / case["filename"]
    path.write_text(case["content"], encoding="utf-8", errors="replace")
    assert dna_hook.main(case["cli_args"] + [str(path)]) == case["expected_ret"]


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {
                "filename": "empty.txt",
                "content": "",
                "cli_args": [],
                "expected_ret": 0,
                "desc": "Empty file passes",
                "fix_mode": False,
                "expected_content": None,
            },
            id="empty_file_passes",
        ),
        pytest.param(
            {
                "filename": "allowed.txt",
                "content": "abc\t\n\r",  # Represents: abc + tab + newline + carriage return
                "cli_args": [],
                "expected_ret": 0,
                "desc": "Only allowed chars",
                "fix_mode": False,
                "expected_content": None,
            },
            id="only_allowed_chars",
        ),
        pytest.param(
            {
                "filename": "disallowed.txt",
                "content": "abc\x01def",  # Represents: abc + control character + def
                "cli_args": [],
                "expected_ret": 1,
                "desc": "Disallowed control char",
                "fix_mode": False,
                "expected_content": None,
            },
            id="disallowed_control_char",
        ),
        pytest.param(
            {
                "filename": "skip.bin",
                "content": "abc\x01def",  # Represents: abc + control character + def
                "cli_args": ["--file-include", "*.txt"],
                "expected_ret": 0,
                "desc": "Excluded by pattern",
                "fix_mode": False,
                "expected_content": None,
            },
            id="excluded_by_pattern",
        ),
        pytest.param(
            {
                "filename": "take.txt",
                "content": "xyz\x01uvw",  # Represents: xyz + control character + uvw
                "cli_args": ["--file-include", ["*.txt", "*.fr"]],
                "expected_ret": 1,
                "desc": "Included with issues",
                "fix_mode": False,
                "expected_content": None,
            },
            id="included_with_issues",
        ),
        pytest.param(
            {
                "filename": "large.txt",
                "content": "a" * 100000
                + "\x01",  # Represents: 100,000 'a' characters followed by a control character
                "cli_args": [],
                "expected_ret": 1,
                "desc": "Large file with offender",
                "fix_mode": False,
                "expected_content": None,
            },
            id="large_file_with_offender",
        ),
        pytest.param(
            {
                "filename": "bad.txt",
                "content": "abc\x01",  # Represents: abc + control character
                "cli_args": [],
                "expected_ret": 1,
                "desc": "Fix mode removes bad char",
                "fix_mode": True,
                "expected_content": "abc",
            },
            id="fix_mode_removes_bad_char",
        ),
    ],
)
def test_main_file_filtering_and_fix_mode(tmp_path, case):
    path = tmp_path / case["filename"]
    path.write_text(case["content"], encoding="utf-8", errors="replace")
    args = case["cli_args"] + (["--fix"] if case["fix_mode"] else []) + [str(path)]
    ret = dna_hook.main(args)
    assert ret == case["expected_ret"]
    if case["fix_mode"] and case["expected_content"] is not None:
        assert case["expected_content"] in path.read_text(
            encoding="utf-8", errors="replace"
        )


def test_main_conflict_error_truncation(tmp_path, capsys):
    files = [str(tmp_path / f"f{i}_valid.txt") for i in range(12)]
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
    "case",
    [
        pytest.param(
            {
                "contents": ["abc", "abc", "abc", "abc"],
                "cli_args": ["--mode", "ascii-only"],
                "expected_ret": 0,
                "desc": "ASCII-only, all clean",
            },
            id="ascii_only_all_clean",
        ),
        pytest.param(
            {
                "contents": [
                    "abc",
                    "abc\x01",
                    "abc",
                    "abc",
                ],  # Represents: abc + control character
                "cli_args": ["--mode", "ascii-only"],
                "expected_ret": 1,
                "desc": "ASCII-only, control char",
            },
            id="ascii_only_control_char",
        ),
        pytest.param(
            {
                "contents": ["abc💻", "abc", "abc", "abc"],
                "cli_args": ["--mode", "ascii-only", "--allow-chars", "💻"],
                "expected_ret": 0,
                "desc": "ASCII-only, allow emoji",
            },
            id="ascii_only_allow_emoji",
        ),
        pytest.param(
            {
                "contents": ["abc💻🚀🍴°₂", "abc", "abc", "abc"],
                "cli_args": [
                    "--mode",
                    "ascii-only",
                    "--allow-chars",
                    "💻🚀🍴",
                    "--allow-chars",
                    "°",
                    "--allow-chars",
                    "₂",
                ],
                "expected_ret": 0,
                "desc": "ASCII-only, allow all three",
            },
            id="ascii_only_allow_all_three",
        ),
        pytest.param(
            {
                "contents": ["abc💻🚀🍴°₂", "abc", "abc", "abc"],
                "cli_args": [
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
                "expected_ret": 0,
                "desc": "Visible-plus, fix, allow all three",
            },
            id="visible_plus_fix_allow_all_three",
        ),
        pytest.param(
            {
                "contents": ["abc💻🚀🍴°₂", "abc", "abc", "abc"],
                "cli_args": [
                    "--allow-chars",
                    "💻,🚀,🍴",
                    "--allow-chars",
                    "°",
                    "--allow-chars",
                    "₂",
                ],
                "expected_ret": 0,
                "desc": "Balanced, allow all three comma-separated",
            },
            id="balanced_allow_all_three_comma",
        ),
        pytest.param(
            {
                "contents": ["abc\t\n\r", "abc", "abc", "abc"],
                "cli_args": [
                    "--mode",
                    "ascii-only",
                    "--include-range",
                    "0x20-0x7E",  # Represents: Printable ASCII range
                    "--include-range",
                    "0x09",  # Represents: Tab
                    "--include-range",
                    "0x0A",  # Represents: Newline
                    "--include-range",
                    "0x0D",  # Represents: Carriage return
                ],
                "expected_ret": 0,
                "desc": "ASCII-only, multiple include-range",
            },
            id="ascii_only_multiple_include_range",
        ),
        pytest.param(
            {
                "contents": ["abc💻🚀🍴°₂", "abc", "abc", "abc"],
                "cli_args": [
                    "--fix",
                    "--allow-chars",
                    "💻🚀🍴",
                    "--allow-chars",
                    "°₂",
                    "--file-exclude",
                    "*.md",
                ],
                "expected_ret": 0,
                "desc": "Balanced, fix, allow all three, exclude md",
            },
            id="balanced_fix_allow_all_three_exclude_md",
        ),
        pytest.param(
            {
                "contents": ["abc💻🚀🍴°₂", "abc", "abc", "abc"],
                "cli_args": [
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
                "expected_ret": 0,
                "desc": "ASCII-only, fix, allow all three, exclude py",
            },
            id="ascii_only_fix_allow_all_three_exclude_py",
        ),
        pytest.param(
            {
                "contents": ["abc💻", "abc", "abc", "abc"],
                "cli_args": [
                    "--mode",
                    "ascii-only",
                    "--file-include",
                    "*.txt",
                    "--allow-chars",
                    "💻",
                ],
                "expected_ret": 0,
                "desc": "ASCII-only, file-include txt, allow emoji",
            },
            id="ascii_only_file_include_txt_allow_emoji",
        ),
    ],
)
def test_main_argument_combinations_four_files(tmp_path, case):
    filenames = ["file1.txt", "file2.txt", "file3.md", "file4.py"]
    paths = []
    for fname, content in zip(filenames, case["contents"]):
        path = tmp_path / fname
        path.write_text(content, encoding="utf-8")
        paths.append(str(path))
    assert dna_hook.main(case["cli_args"] + paths) == case["expected_ret"]
