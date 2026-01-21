from __future__ import annotations

import shutil

import pytest

from pre_commit_hooks.non_ascii_guard import _cluster_allowed_visible_plus
from pre_commit_hooks.non_ascii_guard import MODE_ASCII_ONLY
from pre_commit_hooks.non_ascii_guard import MODE_BALANCED
from pre_commit_hooks.non_ascii_guard import MODE_VISIBLE_PLUS
from pre_commit_hooks.non_ascii_guard import main
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

    ret = main([str(path)])

    assert ret == 1
    assert path.read_bytes() == b'abcdef\n'
    out = capsys.readouterr().out
    assert f'Fixing {path}: disallowed bytes 0x80@3' in out


def test_check_only_reports_and_keeps(tmp_path, capsys) -> None:
    path = tmp_path / 'bad.txt'
    original = b'abc\x00def\n'
    path.write_bytes(original)

    ret = main(['--check-only', str(path)])

    assert ret == 1
    assert path.read_bytes() == original
    out = capsys.readouterr().out
    assert 'disallowed bytes 0x00@3' in out


def test_include_range_allows_bytes(tmp_path) -> None:
    path = tmp_path / 'binary.bin'
    path.write_bytes(bytes(range(256)))

    ret = main(['--include-range', '0-255', str(path)])

    assert ret == 0
    assert path.read_bytes() == bytes(range(256))


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

    ret = main(['--check-only', str(path)])

    assert ret == 1
    out = capsys.readouterr().out
    # Balanced allows é, so first offenders start at Ω (0xce@3)
    assert 'disallowed bytes 0xce@3, 0xa9@4, 0xe2@5' in out


def test_printable_offender_shows_char(tmp_path, capsys) -> None:
    path = tmp_path / 'ascii.txt'
    path.write_text('A\n')

    ret = main(['--include-range', '0x00-0x1F', '--check-only', str(path)])

    assert ret == 1
    out = capsys.readouterr().out
    assert f'{path}: disallowed bytes 0x41(\'A\')@0' in out


def test_default_allows_whitespace_and_printable(tmp_path) -> None:
    path = tmp_path / 'mix.txt'
    path.write_bytes(b'abc\t\n\r\x01def')

    ret = main([str(path)])

    assert ret == 1
    assert path.read_bytes() == b'abc\t\n\rdef'


def test_files_glob_filters_targets(tmp_path) -> None:
    kept = tmp_path / 'skip.bin'
    target = tmp_path / 'take.txt'
    kept.write_bytes(b'abc\x01def\n')
    target.write_bytes(b'xyz\x01uvw\n')

    ret = main(['--files-glob', '*.txt', str(kept), str(target)])

    assert ret == 1
    assert kept.read_bytes() == b'abc\x01def\n'
    assert target.read_bytes() == b'xyzuvw\n'


def test_fixture_file_is_cleaned(tmp_path, capsys) -> None:
    fixture = get_resource_path('non_ascii_sample.txt')
    path = tmp_path / 'copy.txt'
    shutil.copy(fixture, path)

    ret = main([str(path)])

    assert ret == 1
    assert path.read_text(encoding='utf-8') == 'ASCII ok\nHas ctrl:\nUnicode: café\n'
    out = capsys.readouterr().out
    assert f'Fixing {path}: disallowed bytes ' in out

def test_combined_parameters(tmp_path, capsys):
    f1 = tmp_path / 'latin.txt'
    f2 = tmp_path / 'emoji.txt'
    f3 = tmp_path / 'bidi.txt'
    f4 = tmp_path / 'mix.txt'
    # use explicit UTF-8 to support Windows locales without UTF-8 defaults
    f1.write_bytes(b'caf\xc3\xa9\n')
    f2.write_bytes(b'smile \xc2\xa3\n')
    f3.write_bytes(b'abc\xe2\x80\xae\n')
    f4.write_bytes(b'abc\x01\x80\n')

    ret = main([
        '--mode', MODE_BALANCED,
        '--files-glob', '*.txt',
        '--allow-chars', 'é',
        '--include-range', '0x0A,0x20-0x7E',
        '--check-only',
        str(f1), str(f2), str(f3), str(f4)
    ])
    out = capsys.readouterr().out
    assert f1.name not in out  # café allowed in balanced
    assert f2.name in out and 'disallowed bytes' in out  # £ not allowed
    assert f3.name in out and 'disallowed bytes' in out  # bidi
    assert f4.name in out and 'disallowed bytes' in out  # controls
    assert ret == 1

    f2.write_bytes(b'smile \xc2\xa3\n')
    f3.write_bytes(b'abc\xe2\x80\xae\n')
    f4.write_bytes(b'abc\x01\x80\n')
    ret2 = main([
        '--mode', MODE_BALANCED,
        '--files-glob', '*.txt',
        '--allow-chars', 'é',
        '--include-range', '0x0A,0x20-0x7E',
        str(f1), str(f2), str(f3), str(f4)
    ])
    out2 = capsys.readouterr().out
    assert f1.read_bytes().decode('utf-8') == 'café\n'
    assert '£' not in f2.read_bytes().decode('utf-8')
    assert '\u202e' not in f3.read_bytes().decode('utf-8') and b'\xe2\x80\xae' not in f3.read_bytes()
    assert f4.read_bytes() == b'abc\n'
    assert f2.name in out2 and f3.name in out2 and f4.name in out2
    assert ret2 == 1


def test_mode_visible_plus_allows_emoji_blocks_accents(tmp_path, capsys):
    path = tmp_path / 'emoji.txt'
    path.write_text('hi 😀 é', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, '--check-only', str(path)])

    assert ret == 1
    out = capsys.readouterr().out
    assert path.name in out
    assert 'disallowed bytes' in out  # accent is blocked


def test_mode_ascii_only_is_strict(tmp_path, capsys):
    path = tmp_path / 'strict.txt'
    path.write_text('hi café 😀', encoding='utf-8')

    ret = main(['--mode', MODE_ASCII_ONLY, '--check-only', str(path)])

    assert ret == 1
    out = capsys.readouterr().out
    assert 'disallowed bytes' in out


def test_mode_balanced_allows_latin1_blocks_bidi(tmp_path, capsys):
    path = tmp_path / 'latin1.txt'
    path.write_bytes('café \u202e'.encode('utf-8'))

    ret = main(['--mode', MODE_BALANCED, '--check-only', str(path)])

    assert ret == 1
    out = capsys.readouterr().out
    assert 'disallowed bytes' in out
    assert 'latin1.txt' in out


def test_zwj_emoji_blocked_as_cluster(tmp_path, capsys):
    path = tmp_path / 'family.txt'
    path.write_text('family: 👨\u200d👩\u200d👧\u200d👦 end', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, str(path)])

    assert ret == 1
    out = capsys.readouterr().out
    assert 'Fixing' in out
    assert 'family.txt' in out
    assert '\u200d' not in path.read_text(encoding='utf-8')


def test_files_include_and_exclude(tmp_path):
    keep = tmp_path / 'skip.md'
    take = tmp_path / 'scan.py'
    keep.write_text('ok café', encoding='utf-8')
    take.write_text('hi café', encoding='utf-8')

    ret = main([
        '--mode', MODE_VISIBLE_PLUS,
        '--files-include', '*.py',
        '--files-exclude', '*.md',
        str(keep), str(take),
    ])

    assert ret == 1
    assert 'café' not in take.read_text(encoding='utf-8')
    assert keep.read_text(encoding='utf-8') == 'ok café'


def test_include_range_restricts_even_if_mode_allows(tmp_path, capsys):
    path = tmp_path / 'range.txt'
    path.write_text('hello 😀', encoding='utf-8')

    ret = main([
        '--mode', MODE_VISIBLE_PLUS,
        '--include-range', '0x20-0x7E',  # ASCII only
        str(path),
    ])

    assert ret == 1
    out = capsys.readouterr().out
    assert 'disallowed bytes' in out
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
    path = tmp_path / 'bidi.txt'
    # Emoji followed by bidi override U+202E (RIGHT-TO-LEFT OVERRIDE)
    path.write_text('test😀\u202Eword', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, '--check-only', str(path)])

    assert ret == 1
    out = capsys.readouterr().out
    assert 'disallowed bytes' in out


def test_visible_plus_blocks_control_in_cluster(tmp_path, capsys):
    """Test line 109: control character check in _cluster_allowed_visible_plus"""
    path = tmp_path / 'ctrl.txt'
    # Emoji followed by control char U+0001 (not tab/LF/CR)
    path.write_text('test😀\x01word', encoding='utf-8')

    ret = main(['--mode', MODE_VISIBLE_PLUS, '--check-only', str(path)])

    assert ret == 1
    out = capsys.readouterr().out
    assert 'disallowed bytes' in out


def test_visible_plus_allows_pure_ascii():
    """Test line 112: early return for ASCII-only clusters in visible-plus"""
    # Direct unit test of _cluster_allowed_visible_plus with ASCII-only input
    ascii_cps = [ord(c) for c in 'hello']
    assert _cluster_allowed_visible_plus(ascii_cps) is True
