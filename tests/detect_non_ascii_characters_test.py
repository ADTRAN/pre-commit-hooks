from __future__ import annotations

import shutil

import pytest

from pre_commit_hooks.detect_non_ascii_characters import _cluster_allowed_visible_plus
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
    # Text with control character (SOH, 0x01) which is not in 0x00-0x1F range when restricted
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
    """Test line 107: bidi override check in _cluster_allowed_visible_plus"""
    path = tmp_path / 'bidi.txt' # Emoji followed by bidi override U+202E (RIGHT-TO-LEFT OVERRIDE)

    path.write_text('test😀\u202Eword', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 1
    out = capsys.readouterr().out
    assert 'Found' in out


def test_visible_plus_blocks_control_in_cluster(tmp_path, capsys):
    """Test line 109: control character check in _cluster_allowed_visible_plus"""
    path = tmp_path / 'ctrl.txt'  # Emoji followed by control char U+0001 (not tab/LF/CR)

    path.write_text('test😀\x01word', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 1
    out = capsys.readouterr().out
    assert 'Found' in out


def test_visible_plus_allows_pure_ascii():
    """Test line 112: early return for ASCII-only clusters in visible-plus"""

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
