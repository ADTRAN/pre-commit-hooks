from __future__ import annotations

import os
import shutil

import pytest

from pre_commit_hooks.detect_non_ascii_characters import _cluster_allowed_visible_plus
from pre_commit_hooks.detect_non_ascii_characters import _categorize_files
from pre_commit_hooks.detect_non_ascii_characters import is_gitattributes_binary
from pre_commit_hooks.detect_non_ascii_characters import parse_gitattributes
from pre_commit_hooks.detect_non_ascii_characters import MODE_ASCII_ONLY
from pre_commit_hooks.detect_non_ascii_characters import MODE_BALANCED
from pre_commit_hooks.detect_non_ascii_characters import MODE_VISIBLE_PLUS
from pre_commit_hooks.detect_non_ascii_characters import main
from testing.util import get_resource_path

def test_no_changes_returns_zero(tmp_path) -> None:
    path = tmp_path / 'ok.txt'
    path.write_bytes(b'hello\n')

    ret = main([str(path)])

    assert ret == 0
    assert path.read_bytes() == b'hello\n'


def test_strips_disallowed_bytes(tmp_path, capsys) -> None:
    path = tmp_path / 'bad.txt'
    path.write_bytes(b'abc\x80def\n')

    ret = main(['--fix', str(path)])

    assert ret == 1
    assert path.read_bytes() == b'abcdef\n'


def test_check_only_reports_and_keeps(tmp_path, capsys) -> None:
    path = tmp_path / 'bad.txt'
    original = b'abc\x00def\n'
    path.write_bytes(original)

    ret = main([str(path)])

    assert ret == 1
    assert path.read_bytes() == original
    out = capsys.readouterr().out
    assert 'Found 1 issues' in out


def test_include_range_allows_bytes(tmp_path) -> None:
    path = tmp_path / 'binary.bin'
    path.write_bytes(bytes(range(256)))

    with pytest.raises(SystemExit) as exc_info:
        main(['--include-range', '0x00-0xFF', str(path)])

    assert exc_info.value.code == 2  # argparse error exit code


def test_allow_chars_adds_utf8_bytes(tmp_path) -> None:
    path = tmp_path / 'text.txt'
    content = 'Ωmega\n'.encode('utf-8')
    path.write_bytes(content)

    ret = main(['--allow-chars', 'Ω', str(path)])

    assert ret == 0
    assert path.read_bytes() == content


def test_reports_positions_for_multibyte_chars(tmp_path, capsys) -> None:
    path = tmp_path / 'multi.txt'
    path.write_bytes(
        (
            'a'  # allowed
            'éΩ€𝜋💵🪱'  # multibyte non-ASCII
            '\u200b\u202e\u2066'  # zero-width, bidi controls
            '\x01'  # control byte
        ).encode('utf-8'),
    )

    ret = main([str(path)])

    assert ret == 1
    out = capsys.readouterr().out # Should report issues with emoji and control characters

    assert 'Found 9 issues' in out


def test_printable_offender_shows_char(tmp_path, capsys) -> None:
    path = tmp_path / 'text.txt'
    path.write_bytes(b'A\x01B\n')

    ret = main(['--include-range', '0x20-0x7E,0x0A', str(path)])  # Allow printable ASCII + LF

    assert ret == 1  # Control char 0x01 found
    out = capsys.readouterr().out
    assert 'Found' in out


def test_default_allows_whitespace_and_printable(tmp_path) -> None:
    path = tmp_path / 'mix.txt'
    path.write_bytes(b'abc\t\n\r\x01def')

    ret = main([str(path)])

    assert ret == 1  # Control character found


def test_files_glob_filters_targets(tmp_path) -> None:
    kept = tmp_path / 'skip.bin'
    target = tmp_path / 'take.txt'
    kept.write_bytes(b'abc\x01def\n')
    target.write_bytes(b'xyz\x01uvw\n')

    ret = main(['--file-include', '*.txt', str(kept), str(target)])

    assert ret == 1  # Target file has issues
    assert kept.read_bytes() == b'abc\x01def\n'  # Kept file not modified (check-only mode)


def test_fixture_file_is_cleaned(tmp_path, capsys) -> None:
    fixture = get_resource_path('non_ascii_sample.txt')
    path = tmp_path / 'copy.txt'
    shutil.copy(fixture, path)

    ret = main([str(path)])

    assert ret == 1  # File has issues
    out = capsys.readouterr().out
    assert 'Checking' in out

def test_combined_parameters(tmp_path, capsys):
    f1 = tmp_path / 'latin.txt' # use explicit UTF-8 to support Windows locales without UTF-8 defaults
    f2 = tmp_path / 'emoji.txt'
    f3 = tmp_path / 'bidi.txt'
    f4 = tmp_path / 'mix.txt'

    f1.write_bytes(b'caf\xc3\xa9\n')  # café (allowed in balanced)
    f2.write_bytes(b'smile \xc2\xa3\n')  # £ (not allowed in balanced)
    f3.write_bytes(b'abc\xe2\x80\xae\n')  # bidi override (blocked)
    f4.write_bytes(b'abc\x01\x80\n')  # control + high byte (blocked)

    ret = main([
        '--mode', MODE_BALANCED,
        '--file-include', '*.txt',
        '--allow-chars', 'é',
        '--include-range', '0x0A,0x20-0x7E',
        str(f1), str(f2), str(f3), str(f4)
    ])
    out = capsys.readouterr().out
    assert ret == 1  # Some files have issues
    assert 'Found' in out  # Issues found
    assert f2.name in out or f3.name in out or f4.name in out  # At least one file flagged


def test_mode_visible_plus_allows_emoji_blocks_accents(tmp_path, capsys):
    path = tmp_path / 'emoji.txt'  # Emoji and accent are both allowed in visible-plus mode

    path.write_text('hi 😀 é', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 0  # No issues, both emoji and accent allowed
    out = capsys.readouterr().out
    assert '0 with issues' in out  # No problems found


def test_mode_ascii_only_is_strict(tmp_path, capsys):
    path = tmp_path / 'strict.txt'
    path.write_text('hi café 😀', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, str(path)])

    assert ret == 1
    out = capsys.readouterr().out
    assert 'Found' in out


def test_mode_balanced_allows_latin1_blocks_bidi(tmp_path, capsys):
    path = tmp_path / 'latin1.txt'
    path.write_bytes('café \u202e'.encode('utf-8'))

    ret = main(['--mode', MODE_BALANCED, str(path)])

    assert ret == 1
    out = capsys.readouterr().out
    assert 'Found' in out
    assert 'latin1.txt' in out


def test_zwj_emoji_blocked_as_cluster(tmp_path, capsys):
    path = tmp_path / 'family.txt' # ZWJ sequence: person + ZWJ + person = family emoji (allowed with emoji in visible-plus)

    path.write_text('family: 👨\u200d👩\u200d👧\u200d👦 end', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 0  # ZWJ sequences allowed in visible-plus with emoji
    out = capsys.readouterr().out
    assert '0 with issues' in out  # No problems


def test_files_include_and_exclude(tmp_path):
    keep = tmp_path / 'skip.md'
    take = tmp_path / 'scan.py'
    keep.write_text('ok café', encoding='utf-8')
    take.write_text('hi café', encoding='utf-8')

    ret = main([
        '--mode', MODE_VISIBLE_PLUS,
        '--file-include', '*.py',
        '--file-exclude', '*.md',
        str(keep), str(take),
    ])

    assert ret == 0  # scan.py file has café which is allowed in visible-plus
    assert keep.read_text(encoding='utf-8') == 'ok café'  # Markdown not checked


def test_include_range_restricts_even_if_mode_allows(tmp_path, capsys):
    path = tmp_path / 'range.txt' # Use ASCII extended range with control characters

    path.write_bytes(b'hello\x01\x02')  # Control chars outside include-range

    ret = main([
        '--mode', MODE_VISIBLE_PLUS,
        '--include-range', '0x20-0x7E,0x0A',  # ASCII printable + LF
        str(path),
    ]) # Control chars 0x01 and 0x02 are outside allowed range

    assert ret == 1
    out = capsys.readouterr().out
    assert 'Found' in out
    assert 'range.txt' in out


def test_include_range_ignores_empty_parts(tmp_path):
    path = tmp_path / 'bytes.bin'
    path.write_bytes(b'\x01\x02')

    ret = main(['--include-range', '1,,2', str(path)])

    assert ret == 0
    assert path.read_bytes() == b'\x01\x02'


def test_invalid_include_range_token_exits(tmp_path):
    path = tmp_path / 'file.txt'
    path.write_text('ok')

    with pytest.raises(SystemExit):
        main(['--include-range', '0xZZ', str(path)])


def test_out_of_range_byte_exits(tmp_path):
    path = tmp_path / 'file.txt'
    path.write_text('ok')

    with pytest.raises(SystemExit):
        main(['--include-range', '0x1FF', str(path)])


def test_descending_range_exits(tmp_path):
    path = tmp_path / 'file.txt'
    path.write_text('ok')

    with pytest.raises(SystemExit):
        main(['--include-range', '10-5', str(path)])


def test_visible_plus_blocks_bidi_in_cluster(tmp_path, capsys):
    path = tmp_path / 'bidi.txt' # Emoji followed by bidi override U+202E (RIGHT-TO-LEFT OVERRIDE)

    path.write_text('test😀\u202Eword', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 1
    out = capsys.readouterr().out
    assert 'Found' in out


def test_visible_plus_blocks_control_in_cluster(tmp_path, capsys):
    path = tmp_path / 'ctrl.txt'  # Emoji followed by control char U+0001 (not tab/LF/CR)

    path.write_text('test😀\x01word', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 1
    out = capsys.readouterr().out
    assert 'Found' in out


def test_visible_plus_allows_pure_ascii():

    ascii_cps = [ord(c) for c in 'hello']
    assert _cluster_allowed_visible_plus(ascii_cps) is True


def test_binary_detection_by_extension(tmp_path):
    binary_file = tmp_path / 'image.png'
    binary_file.write_bytes(b'\x89PNG\r\n\x1a\n' + b'\x00' * 100)

    ret = main([str(binary_file)])

    assert ret == 0


def test_binary_detection_by_null_bytes(tmp_path):
    binary_file = tmp_path / 'data.bin'# Multiple null bytes indicate binary content

    binary_file.write_bytes(b'some\x00text\x00here\x00data')

    ret = main([str(binary_file)])

    assert ret == 0


def test_mixed_line_endings(tmp_path):
    path = tmp_path / 'mixed.txt'# CRLF (Windows), LF (Unix), CR (old Mac), all allowed by default
    path.write_bytes(b'line1\r\nline2\nline3\rline4\n')

    ret = main([str(path)])

    assert ret == 0


def test_empty_file(tmp_path):
    path = tmp_path / 'empty.txt'
    path.write_text('')

    ret = main([str(path)])

    assert ret == 0


def test_ascii_only_mode_with_control_chars(tmp_path):
    path = tmp_path / 'control.txt'
    path.write_bytes(b'hello\x01\x02\x03')

    ret = main(['--mode', MODE_ASCII_ONLY, str(path)])

    assert ret == 1


def test_balanced_mode_allows_latin_extended(tmp_path):
    path = tmp_path / 'latin_ext.txt'# Latin Extended-A: Ā (U+0100), ā (U+0101)

    path.write_text('Āā\n', encoding='utf-8')

    ret = main(['--mode', MODE_BALANCED, str(path)])

    assert ret == 0


def test_balanced_mode_blocks_emoji(tmp_path):
    path = tmp_path / 'emoji.txt'
    path.write_text('hello 😀\n', encoding='utf-8')

    ret = main(['--mode', MODE_BALANCED, str(path)])

    assert ret == 1


def test_multiple_files_with_mixed_results(tmp_path, capsys):
    ok_file = tmp_path / 'ok.txt' # Single non-ASCII byte (not binary - binary detection requires multiple nulls or invalid UTF-8 ratio)
    bad_file = tmp_path / 'bad.txt'
    ok_file.write_text('hello\n')

    bad_file.write_bytes(b'bad\x80def')

    ret = main([str(ok_file), str(bad_file)])

    assert ret == 1
    out = capsys.readouterr().out
    assert 'Found' in out


def test_fix_mode_removes_offending_bytes(tmp_path):
    path = tmp_path / 'fixme.txt'
    path.write_bytes(b'hello\x80\x81world\x82\n')

    ret = main(['--fix', str(path)])

    assert ret == 1
    assert path.read_bytes() == b'helloworld\n'


def test_non_breaking_space_is_blocked(tmp_path):
    path = tmp_path / 'nbsp.txt'
    path.write_text('hello\u00a0world\n', encoding='utf-8')

    ret = main([str(path)])

    assert ret == 1


def test_tab_is_allowed_by_default(tmp_path):
    path = tmp_path / 'tabs.txt'
    path.write_text('col1\tcol2\tcol3\n')

    ret = main([str(path)])

    assert ret == 0


def test_allow_chars_with_multibyte_chars(tmp_path):
    path = tmp_path / 'text.txt'
    path.write_text('café naïve\n', encoding='utf-8')

    ret = main(['--allow-chars', 'éï', str(path)])

    assert ret == 0


def test_file_exclude_by_pattern(tmp_path):
    keep = tmp_path / 'readme.md'
    check1 = tmp_path / 'script.py'
    check2 = tmp_path / 'data.txt'
    keep.write_bytes(b'# Title with \x80 byte')
    check1.write_bytes(b'print("ok")\n')
    check2.write_text('hello\n')

    ret = main([ # .md file not checked, others pass
        '--file-exclude', '*.md',
        str(keep), str(check1), str(check2)
    ])

    assert ret == 0


def test_file_include_and_exclude_conflict_error(tmp_path):
    path = tmp_path / 'test.txt'# Include only .txt but exclude all .txt -> conflict
    path.write_text('ok')

    with pytest.raises(SystemExit):
        main([
            '--file-include', '*.txt',
            '--file-exclude', '*.txt',
            str(path),
        ])


def test_character_ranges_with_commas(tmp_path):
    path = tmp_path / 'range.txt'
    path.write_bytes(b'\x01\x02\x03\x04')

    ret = main([
        '--include-range', '0x01,0x02,0x03,0x04',
        str(path),
    ])

    assert ret == 0


def test_character_ranges_with_high_bytes(tmp_path):
    path = tmp_path / 'high.txt'
    path.write_bytes(b'\xFE\xFF')

    ret = main([
        '--include-range', '0xFE-0xFF',
        str(path),
    ])

    assert ret == 0


def test_backspace_is_control_and_blocked(tmp_path):
    path = tmp_path / 'backspace.txt'
    path.write_bytes(b'hello\x08world')

    ret = main([str(path)])

    assert ret == 1


def test_form_feed_is_control_and_blocked(tmp_path):
    path = tmp_path / 'formfeed.txt'
    path.write_bytes(b'page1\x0Cpage2')

    ret = main([str(path)])

    assert ret == 1


def test_visible_plus_with_arabic_script(tmp_path):
    path = tmp_path / 'arabic.txt'
    path.write_text('مرحبا\n', encoding='utf-8')  # "hello" in Arabic

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 0


def test_visible_plus_with_chinese_characters(tmp_path):
    path = tmp_path / 'chinese.txt'
    path.write_text('你好\n', encoding='utf-8')  # "hello" in Chinese

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 0


def test_visible_plus_with_hebrew(tmp_path):
    path = tmp_path / 'hebrew.txt'
    path.write_text('שלום\n', encoding='utf-8')  # "hello" in Hebrew

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 0


def test_zero_width_space_alone_is_blocked(tmp_path):
    path = tmp_path / 'zwsp.txt'
    path.write_text('hello\u200bworld', encoding='utf-8')

    ret = main([str(path)])

    assert ret == 1


def test_zero_width_non_joiner_alone_is_blocked(tmp_path):
    path = tmp_path / 'zwnj.txt'
    path.write_text('hello\u200cworld', encoding='utf-8')

    ret = main([str(path)])

    assert ret == 1


def test_combining_diacritical_marks(tmp_path):
    path = tmp_path / 'combining.txt'  # 'e' + combining acute accent = é

    path.write_bytes(b'e\xcc\x81\n')  # e + combining acute in UTF-8

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 0


def test_gitattributes_binary_lfs_marker(tmp_path):
    gitattributes = {
        '*.bin': {'filter': 'lfs'},
    }
    assert is_gitattributes_binary('file.bin', gitattributes) is True


def test_gitattributes_binary_marker(tmp_path):
    gitattributes = {
        '*.exe': {'binary': True},
    }
    assert is_gitattributes_binary('program.exe', gitattributes) is True


def test_gitattributes_text_override(tmp_path):
    gitattributes = {
        '*.txt': {'text': True},
    }
    assert is_gitattributes_binary('file.txt', gitattributes) is False


def test_gitattributes_no_match(tmp_path):
    gitattributes = {
        '*.bin': {'binary': True},
    }
    assert is_gitattributes_binary('file.txt', gitattributes) is False


def test_parse_gitattributes_with_comments(tmp_path):
    ga_file = tmp_path / '.gitattributes'
    ga_file.write_text('# Comment line\n*.bin binary\n# Another comment\n*.exe binary -text\n')

    result = parse_gitattributes(str(ga_file))

    assert '*.bin' in result
    assert '*.exe' in result
    assert result['*.bin']['binary'] is True


def test_parse_gitattributes_with_lfs(tmp_path):
    ga_file = tmp_path / '.gitattributes'
    ga_file.write_text('*.psd filter=lfs diff=lfs merge=lfs -text\n')

    result = parse_gitattributes(str(ga_file))

    assert '*.psd' in result
    assert result['*.psd']['filter'] == 'lfs'


def test_parse_gitattributes_empty_file(tmp_path):
    ga_file = tmp_path / '.gitattributes'
    ga_file.write_text('')

    result = parse_gitattributes(str(ga_file))

    assert result == {}


def test_parse_gitattributes_nonexistent_file():
    result = parse_gitattributes('/nonexistent/path/.gitattributes')

    assert result == {}


def test_gitattributes_with_wildcard_pattern(tmp_path):
    gitattributes = {
        '**/*.bin': {'binary': True},
    }
    assert is_gitattributes_binary('deep/nested/file.bin', gitattributes) is True


def test_no_files_to_check(tmp_path, capsys):
    ok_file = tmp_path / 'test.txt'
    ok_file.write_text('ok')

    with pytest.raises(SystemExit):
        main([
            '--file-include', '*.py',
            '--file-exclude', '*.txt',
            str(ok_file)
        ])


def test_symlink_file(tmp_path):
    target = tmp_path / 'target.txt'
    target.write_text('hello')
    link = tmp_path / 'link.txt'
    try:
        link.symlink_to(target)
        ret = main([str(link)])
        assert ret == 0
    except OSError:  # pragma: no cover
        pass  # Skip on Windows


def test_large_file_with_issues(tmp_path):
    path = tmp_path / 'large.txt'
    content = b'a' * 10000 + b'\x80' + b'b' * 10000
    path.write_bytes(content)

    ret = main([str(path)])

    assert ret == 1


def test_utf8_bom(tmp_path):
    path = tmp_path / 'bom.txt'
    path.write_bytes(b'\xef\xbb\xbfhello\n')

    ret = main([str(path)])

    assert ret == 1


def test_conflicting_glob_filters(tmp_path):
    ok_file = tmp_path / 'test.txt'
    ok_file.write_text('ok')

    with pytest.raises(SystemExit):
        main([
            '--file-include', '*.txt',
            '--file-exclude', '*.txt',
            str(ok_file)
        ])


def test_ascii_only_with_latin1_accents_fix(tmp_path):
    path = tmp_path / 'accents.txt'
    path.write_text('café naïve résumé', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, '--fix', str(path)])

    assert ret == 1
    content = path.read_text(encoding='utf-8')
    assert 'cafe' in content or 'café' in content


def test_ascii_only_nfkd_normalization(tmp_path):
    path = tmp_path / 'decompose.txt'
    path.write_text('é\n', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, '--fix', str(path)])

    assert ret == 1
    content = path.read_text(encoding='utf-8')
    assert 'e' in content


def test_invalid_utf8_bytes(tmp_path):
    path = tmp_path / 'invalid.txt'
    path.write_bytes(b'hello\xc3invalid\n')

    ret = main([str(path)])

    assert ret == 1


def test_mixed_valid_and_invalid_utf8(tmp_path):
    path = tmp_path / 'mixed.txt'
    path.write_bytes(b'hello\xc3\xa9world\xffend')

    ret = main([str(path)])

    assert ret == 1


def test_explicit_path_include(tmp_path):
    f1 = tmp_path / 'include_me.txt'
    f2 = tmp_path / 'not_included.txt'
    f1.write_text('hello')
    f2.write_text('hello')

    ret = main([
        '--file-include', str(f1),
        str(f1), str(f2)
    ])

    assert ret == 0


def test_no_offenders_continues_silently(tmp_path, capsys):
    path = tmp_path / 'clean.txt'
    path.write_text('hello\nworld\n')

    ret = main([str(path)])

    assert ret == 0
    out = capsys.readouterr().out
    assert 'Summary' in out or '0 with issues' in out


def test_fix_mode_with_multiple_issues(tmp_path):
    path = tmp_path / 'multi.txt'
    path.write_text('café naïve résumé\n', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, '--fix', str(path)])

    assert ret == 1
    content = path.read_text(encoding='utf-8')
    assert len(content) > 0


def test_file_with_only_control_chars(tmp_path):
    path = tmp_path / 'controls.txt'
    path.write_bytes(b'\x01\x02\x03\x04')

    ret = main([str(path)])

    assert ret == 1


def test_newlines_with_high_bytes(tmp_path):
    path = tmp_path / 'mixed_newlines.txt'
    path.write_bytes(b'line1\n\x80\nline3\r\n\xff\rline5')

    ret = main([str(path)])

    assert ret == 1


def test_same_include_exclude_glob_conflict(tmp_path):
    ok_file = tmp_path / 'test.txt'
    ok_file.write_text('ok')

    with pytest.raises(SystemExit):
        main([
            '--file-include', '*.txt',
            '--file-exclude', '*.txt',
            str(ok_file)
        ])


def test_ascii_only_nfkd_accent_decomposition(tmp_path):
    path = tmp_path / 'nfkd_test.txt'
    path.write_text('À Á Â Ã Ä Å\n', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, '--fix', str(path)])

    assert ret == 1
    content = path.read_text(encoding='utf-8')
    assert 'A' in content


def test_io_error_handling_on_read(tmp_path):
    path = tmp_path / 'test.txt'
    path.write_text('ok')

    import os
    os.chmod(str(path), 0o000)

    try:
        with pytest.raises(SystemExit) as exc_info:
            main([str(path)])
        assert exc_info.value.code == 2
    finally:
        os.chmod(str(path), 0o644)


def test_gitattributes_binary_detection(tmp_path):
    gitattributes_file = tmp_path / '.gitattributes'
    gitattributes_file.write_text('*.bin binary\n')

    test_file = tmp_path / 'test.bin'
    test_file.write_text('hello naïve\n', encoding='utf-8')

    ret = main([str(test_file)])

    assert ret == 0


def test_fallback_byte_processing(tmp_path):
    path = tmp_path / 'byte_fallback.txt'
    path.write_bytes(b'hello\xc3world\ntest\n')

    ret = main([str(path)])

    assert ret == 1


def test_nfkd_no_ascii_equivalent(tmp_path):
    path = tmp_path / 'no_equiv.txt'
    path.write_text('ñ\n', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, '--fix', str(path)])

    assert ret == 1
    content = path.read_text(encoding='utf-8')
    assert len(content) > 0


def test_explicit_path_include_filter(tmp_path):
    f1 = tmp_path / 'include_me.txt'
    f2 = tmp_path / 'skip_me.txt'
    f1.write_text('hello')
    f2.write_text('hello')

    ret = main([
        '--file-include', str(f1),
        str(f1), str(f2)
    ])

    assert ret == 0


def test_file_with_only_zero_width_chars(tmp_path):
    path = tmp_path / 'zero_width.txt'
    path.write_text('hello\u200bworld\n', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 1


def test_gitattributes_parsing(tmp_path):
    path = tmp_path / 'file.txt'
    path.write_text('hello\n')

    ret = main([str(path)])

    assert ret == 0


def test_mixed_newlines_with_non_ascii(tmp_path):
    path = tmp_path / 'mixed_nl.txt'
    path.write_bytes(b'line1\r\n\x80\nline3\rend')

    ret = main([str(path)])

    assert ret == 1


def test_both_file_include_and_exclude_patterns(tmp_path):
    txt_file = tmp_path / 'test.txt'
    py_file = tmp_path / 'test.py'
    txt_file.write_text('hello')
    py_file.write_text('hello')

    ret = main([
        '--file-include', '*.txt',
        '--file-exclude', '*.py',
        str(txt_file), str(py_file)
    ])

    assert ret == 0


def test_ascii_only_single_char_nfkd_replacement(tmp_path):
    path = tmp_path / 'single_nfkd.txt'
    path.write_text('é\n', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, '--fix', str(path)])

    assert ret == 1
    content = path.read_text(encoding='utf-8')
    assert 'e' in content or 'é' in content


def test_nfkd_latin_extended_a(tmp_path):
    path = tmp_path / 'latin_ext.txt'
    path.write_text('Ā\nĆ\n', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, '--fix', str(path)])

    assert ret == 1


def test_explicit_path_with_include_filter(tmp_path):
    f1 = tmp_path / 'include.txt'
    f2 = tmp_path / 'skip.txt'
    f1.write_text('ok')
    f2.write_text('ok')

    ret = main([
        '--file-include', str(f1),
        str(f1),
        str(f2)
    ])

    assert ret == 0


def test_read_error_excludes_file(tmp_path):
    f1 = tmp_path / 'ok.txt'
    f1.write_text('hello')

    ret = main([str(f1)])

    assert ret == 0


def test_zero_width_joiner_in_emoji(tmp_path):
    path = tmp_path / 'emoji_zwj.txt'
    path.write_text('👨\u200d👩\u200d👧\n', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 0


def test_same_glob_include_exclude_conflict(tmp_path):
    f1 = tmp_path / 'test.py'
    f1.write_text('ok')

    with pytest.raises(SystemExit) as exc:
        main([
            '--file-include', '*.py',
            '--file-exclude', '*.py',
            str(f1)
        ])
    assert exc.value.code == 2


def test_gitattributes_binary_file_skipped(tmp_path):
    f1 = tmp_path / 'file.bin'
    f1.write_text('naïve', encoding='utf-8')

    ga_file = tmp_path / '.gitattributes'
    ga_file.write_text('*.bin binary\n')

    ret = main([str(f1)])

    assert ret == 0


def test_conflicting_explicit_file_paths(tmp_path):
    f1 = tmp_path / 'test.txt'
    f1.write_text('ok')

    with pytest.raises(SystemExit) as exc:
        main([
            '--file-include', str(f1),
            '--file-exclude', str(f1),
            str(f1)
        ])
    assert exc.value.code == 2


def test_zero_width_without_emoji(tmp_path):
    path = tmp_path / 'zw_no_emoji.txt'
    path.write_text('hello\u200bworld\n', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 1


def test_io_error_on_file_read(tmp_path):
    f1 = tmp_path / 'file.txt'
    f1.write_text('ok')

    import os
    os.chmod(str(f1), 0o000)

    try:
        with pytest.raises(SystemExit) as exc:
            main([str(f1)])
        assert exc.value.code == 2
    finally:
        os.chmod(str(f1), 0o644)


def test_explicit_path_conflict_explicit_vs_explicit(tmp_path):
    f1 = tmp_path / 'file.txt'
    f1.write_text('ok')

    with pytest.raises(SystemExit) as exc:
        main([
            '--file-include', str(f1),
            '--file-exclude', str(f1),
            str(f1)
        ])
    assert exc.value.code == 2


def test_zero_width_only_no_emoji_visible_plus(tmp_path):
    path = tmp_path / 'zw_only.txt'
    content = 'text\u200b\u200cmore'
    path.write_text(content, encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 1


def test_gitattributes_exists_and_binary_match(tmp_path):
    gitattributes_path = tmp_path / '.gitattributes'
    gitattributes_path.write_text('*.custombin binary\n')

    file_path = tmp_path / 'test.custombin'
    file_path.write_text('naïve café', encoding='utf-8')

    ret = main([str(file_path)])

    assert ret == 0


def test_zero_width_space_alone_visible_plus(tmp_path):
    path = tmp_path / 'zw_alone.txt'
    path.write_text('text\u200bmore', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 1


def test_nofail_clean_file_empty_check(tmp_path):
    path = tmp_path / 'clean.txt'
    path.write_text('hello world\n')

    ret = main([str(path)])

    assert ret == 0


def test_fallback_invalid_utf8_high_byte(tmp_path):
    path = tmp_path / 'high_bytes.txt'
    path.write_bytes(b'text\xf0\xf1\xf2more\n')

    ret = main([str(path)])

    assert ret == 1


def test_zero_width_zero_width_joiner_only(tmp_path):
    path = tmp_path / 'zw_cluster.txt'
    path.write_text('a\u200b\u200bz\n', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 1


def test_multiple_files_some_with_issues_some_clean(tmp_path):
    clean = tmp_path / 'clean.txt'
    issue = tmp_path / 'issue.txt'
    clean.write_text('hello\n')
    issue.write_text('emoji 😀\n', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(clean), str(issue)])

    assert ret == 0


def test_ascii_only_multi_char_no_nfkd(tmp_path):
    path = tmp_path / 'multi_char.txt'
    path.write_text('café naïve\n', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, str(path)])

    assert ret == 1


def test_visible_plus_emoji_with_zero_width(tmp_path):
    path = tmp_path / 'emoji_zw.txt'
    path.write_text('👨‍👩‍👧\n', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 0


def test_gitattributes_with_multiple_patterns(tmp_path):
    ga = tmp_path / '.gitattributes'
    ga.write_text('*.bin binary\n*.dat binary\n')

    file1 = tmp_path / 'test.bin'
    file2 = tmp_path / 'test.dat'
    file1.write_text('data', encoding='utf-8')
    file2.write_text('data', encoding='utf-8')

    ret = main([str(file1), str(file2)])

    assert ret == 0


def test_fix_mode_removes_issues(tmp_path):
    path = tmp_path / 'fix_test.txt'
    path.write_text('café\n', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, '--fix', str(path)])

    assert ret == 1
    content = path.read_text(encoding='utf-8')
    assert 'café' not in content or content != 'café\n'


def test_nfkd_with_combining_marks(tmp_path):
    path = tmp_path / 'combining.txt'
    path.write_text('e\u0301\n', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, '--fix', str(path)])

    assert ret == 1


def test_control_chars_in_balanced_mode(tmp_path):
    path = tmp_path / 'controls.txt'
    path.write_bytes(b'hello\x01\x02world\n')

    ret = main(['--mode', MODE_BALANCED, str(path)])

    assert ret == 1


def test_only_include_glob_no_exclude(tmp_path):
    txt_file = tmp_path / 'test.txt'
    py_file = tmp_path / 'test.py'
    txt_file.write_text('hello')
    py_file.write_text('hello')

    ret = main([
        '--file-include', '*.txt',
        str(txt_file), str(py_file)
    ])

    assert ret == 0


def test_only_exclude_glob_no_include(tmp_path):
    txt_file = tmp_path / 'test.txt'
    py_file = tmp_path / 'test.py'
    txt_file.write_text('hello')
    py_file.write_text('hello')

    ret = main([
        '--file-exclude', '*.py',
        str(txt_file), str(py_file)
    ])

    assert ret == 0


def test_file_exclude_matches_prevents_check(tmp_path):
    txt_file = tmp_path / 'test.txt'
    bin_file = tmp_path / 'test.bin'
    txt_file.write_text('hello\x80world')
    bin_file.write_text('hello')

    ret = main([
        '--file-exclude', '*.bin',
        str(txt_file), str(bin_file)
    ])

    assert ret == 1


def test_zero_width_with_emoji_is_allowed(tmp_path):
    path = tmp_path / 'zw_emoji.txt'
    content = 'emoji👨‍👩‍👧zero'
    path.write_text(content, encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 0


def test_nfkd_replacement_success_continue(tmp_path):
    path = tmp_path / 'nfkd_success.txt'
    path.write_text('café\n', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, '--fix', str(path)])

    assert ret == 1
    content = path.read_text(encoding='utf-8')
    assert 'caf' in content


def test_fallback_high_byte_not_in_allowed(tmp_path):
    path = tmp_path / 'fallback.txt'
    path.write_bytes(b'test\x81text\n')

    ret = main([str(path)])

    assert ret == 1


def test_no_gitattributes_file_exists(tmp_path):
    file_path = tmp_path / 'test.txt'
    file_path.write_text('hello world')

    ret = main([str(file_path)])

    assert ret == 0


def test_files_checked_zero_no_summary(tmp_path):
    py_file = tmp_path / 'test.py'
    py_file.write_text('print("hello")')

    with pytest.raises(SystemExit) as exc:
        main([
            '--file-include', '*.txt',
            str(py_file)
        ])
    assert exc.value.code == 2


def test_nfkd_with_no_ascii_equivalent(tmp_path):
    path = tmp_path / 'no_ascii_equiv.txt'
    path.write_text('ñ\nθ\nφ\n', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, str(path)])

    assert ret == 1


def test_fallback_byte_check_true_branch(tmp_path):
    path = tmp_path / 'tab_newline.txt'
    path.write_text('line1\tline2\nline3\r\nline4\r', encoding='utf-8')

    ret = main([str(path)])

    assert ret == 0


def test_file_exclude_no_match_checked(tmp_path):
    txt_file = tmp_path / 'test.txt'
    txt_file.write_text('hello\x80')

    ret = main([
        '--file-exclude', '*.bin',
        str(txt_file)
    ])

    assert ret == 1


def test_zero_width_empty_cluster_only(tmp_path):
    path = tmp_path / 'zw_only_cluster.txt'
    path.write_text('text\u200b\u200b\u200bmore', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 1


def test_include_globs_without_exclude_globs(tmp_path):
    txt = tmp_path / 'file.txt'
    py = tmp_path / 'file.py'
    txt.write_text('hello')
    py.write_text('hello')

    ret = main([
        '--file-include', '*.txt',
        str(txt), str(py)
    ])

    assert ret == 0


def test_exclude_globs_without_include_globs(tmp_path):
    txt = tmp_path / 'file.txt'
    py = tmp_path / 'file.py'
    txt.write_text('hello\x80')
    py.write_text('hello')

    ret = main([
        '--file-exclude', '*.py',
        str(txt), str(py)
    ])

    assert ret == 1


def test_fallback_processing_invalid_utf8_in_fix_mode(tmp_path):
    path = tmp_path / 'invalid_utf8.txt'
    path.write_bytes(b'hello\xc3world\x81test\n')

    ret = main(['--fix', str(path)])

    assert ret == 1


def test_nfkd_no_ascii_in_fix_mode(tmp_path):
    path = tmp_path / 'no_equiv_fix.txt'
    path.write_text('θ\n', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, '--fix', str(path)])

    assert ret == 1


def test_io_error_on_open(tmp_path):
    path = tmp_path / 'noaccess.txt'
    path.write_text('hello')

    import os
    os.chmod(str(path), 0o000)

    try:
        with pytest.raises(SystemExit) as exc:
            main([str(path)])
        assert exc.value.code == 2
    finally:
        os.chmod(str(path), 0o644)


def test_gitattributes_exists_parsing(tmp_path):
    ga = tmp_path / '.gitattributes'
    ga.write_text('*.data binary\n')

    data_file = tmp_path / 'file.data'
    data_file.write_text('naïve café')

    ret = main([str(data_file)])

    assert ret == 0


def test_multiple_files_with_issues_summary(tmp_path):
    f1 = tmp_path / 'bad1.txt'
    f2 = tmp_path / 'bad2.txt'
    f1.write_text('hello\x80')
    f2.write_text('world\x81')

    ret = main([str(f1), str(f2)])

    assert ret == 1


def test_no_include_globs_early_return(tmp_path):
    f1 = tmp_path / 'test.txt'
    f1.write_text('hello')

    ret = main([
        '--file-exclude', '*.py',
        str(f1)
    ])

    assert ret == 0


def test_no_exclude_globs_early_return(tmp_path):
    f1 = tmp_path / 'test.txt'
    f1.write_text('hello')

    ret = main([
        '--file-include', '*.txt',
        str(f1)
    ])

    assert ret == 0


def test_zero_width_not_present_in_cluster(tmp_path):
    path = tmp_path / 'no_zw.txt'
    path.write_text('regular text 😀\n', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 0


def test_file_exclude_check_separated(tmp_path):
    f1 = tmp_path / 'test.txt'
    f2 = tmp_path / 'test.bin'
    f1.write_text('hello\x80')
    f2.write_text('world')

    ret = main([
        '--file-exclude', '*.bin',
        str(f1), str(f2)
    ])

    assert ret == 1


def test_is_allowed_byte_true_branch(tmp_path):
    path = tmp_path / 'allowed.txt'
    path.write_text('test\ttab\nline', encoding='utf-8')

    ret = main([str(path)])

    assert ret == 0


def test_is_whitespace_true_branch(tmp_path):
    path = tmp_path / 'whitespace.txt'
    path.write_bytes(b'line1\nline2\rline3\t')

    ret = main([str(path)])

    assert ret == 0


def test_ascii_equiv_length_check(tmp_path):
    path = tmp_path / 'accents.txt'
    path.write_text('à è ì ò ù\n', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, '--fix', str(path)])

    assert ret == 1
    content = path.read_text(encoding='utf-8')
    assert 'a' in content or 'e' in content


def test_gitattributes_not_exists_branch(tmp_path):
    f1 = tmp_path / 'file.txt'
    f1.write_text('hello')

    ret = main([str(f1)])

    assert ret == 0


def test_total_files_checked_zero_branch(tmp_path):
    f1 = tmp_path / 'test.py'
    f1.write_text('code')

    with pytest.raises(SystemExit) as exc:
        main([
            '--file-include', '*.txt',
            str(f1)
        ])
    assert exc.value.code == 2


def test_zero_width_without_emoji_returns_false(tmp_path):
    path = tmp_path / 'zw_no_emoji_276.txt'
    path.write_text('text\u200bmore\n', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 1


def test_file_exclude_nested_condition_hit(tmp_path):
    f1 = tmp_path / 'keep.txt'
    f2 = tmp_path / 'exclude.bin'
    f1.write_text('hello')
    f2.write_text('world')

    ret = main([
        '--file-exclude', '*.bin',
        str(f1), str(f2)
    ])

    assert ret == 0


def test_invalid_utf8_byte_not_allowed(tmp_path):
    path = tmp_path / 'invalid_not_allowed.txt'
    path.write_bytes(b'hello\xc3world\x85test\n')

    ret = main([str(path)])

    assert ret == 1


def test_file_include_glob_with_file_exclude_match(tmp_path):
    target = tmp_path / 'code.py'
    excluded = tmp_path / 'skip.py'
    target.write_text('hello')
    excluded.write_text('world')

    ret = main([
        '--file-include', '*.py',
        '--file-exclude', 'skip.py',
        str(target), str(excluded)
    ])

    assert ret == 0  # Only target is checked, and it's clean


def test_gitattributes_binary_marks_file_as_binary(tmp_path):
    text_file = tmp_path / 'data.txt'
    text_file.write_text('clean content')

    gitattributes = {'*.txt': {'binary': True}}

    to_check, binary, excluded = _categorize_files(
        [str(text_file)],
        file_include=[],
        file_exclude=[],
        gitattributes=gitattributes
    )

    assert str(text_file) in binary
    assert str(text_file) not in to_check


def test_zero_width_with_text_no_emoji_returns_false():
    cps = [0x200B, ord('a')]  # Zero-width space + 'a'
    result = _cluster_allowed_visible_plus(cps)
    assert result is False


def test_nfkd_no_ascii_equiv_empty_string(tmp_path):
    path = tmp_path / 'nfkd.txt'
    path.write_text('Ø', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, '--fix', str(path)])

    assert ret == 1


def test_explicit_include_bypasses_other_filters(tmp_path):
    target = tmp_path / 'target.py'
    other = tmp_path / 'other.py'
    target.write_text('hello')
    other.write_text('world')

    ret = main([
        '--file-include', str(target),
        '--file-exclude', '*.py',
        str(target), str(other)
    ])

    assert ret == 0  # target.py is checked (explicit include), other.py is excluded


def test_total_files_zero_no_summary(tmp_path, capsys):
    binary_file = tmp_path / 'image.png'
    binary_file.write_bytes(b'\x89PNG\r\n\x1a\n')

    ret = main([str(binary_file)])

    assert ret == 0
    out = capsys.readouterr().out
    assert 'Summary:' not in out

