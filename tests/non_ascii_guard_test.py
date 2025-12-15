from __future__ import annotations
import shutil
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
    content = 'café\n'.encode('utf-8')
    path.write_bytes(content)

    ret = main(['--allow-chars', 'é', str(path)])

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
    assert 'disallowed bytes 0xc3@1, 0xa9@2, 0xce@3, 0xa9@4, 0xe2@5' in out


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
    assert path.read_text() == 'ASCII ok\nHas ctrl:\nUnicode: caf\n'
    out = capsys.readouterr().out
    assert f'Fixing {path}: disallowed bytes ' in out

def test_combined_parameters(tmp_path, capsys):
    f1 = tmp_path / 'latin.txt'
    f2 = tmp_path / 'emoji.txt'
    f3 = tmp_path / 'bidi.txt'
    f4 = tmp_path / 'mix.txt'
    f1.write_text('café\n')
    f2.write_text('smile 🪱\n')
    f3.write_text('abc\u202e\n')
    f4.write_bytes(b'abc\x01\x80\n')

    ret = main([
        '--files-glob', '*.txt',
        '--allow-chars', 'é',
        '--include-range', '0x0A,0x20-0x7E',
        '--check-only',
        str(f1), str(f2), str(f3), str(f4)
    ])
    out = capsys.readouterr().out
    assert f1.name not in out
    assert f2.name in out and 'disallowed bytes' in out
    assert f3.name in out and 'disallowed bytes' in out
    assert f4.name in out and 'disallowed bytes' in out
    assert ret == 1

    f2.write_text('smile 🪱\n')
    f3.write_text('abc\u202e\n')
    f4.write_bytes(b'abc\x01\x80\n')
    ret2 = main([
        '--files-glob', '*.txt',
        '--allow-chars', 'é',
        '--include-range', '0x0A,0x20-0x7E',
        str(f1), str(f2), str(f3), str(f4)
    ])
    out2 = capsys.readouterr().out
    assert f1.read_text() == 'café\n'
    assert '🪱' not in f2.read_text()
    assert '\u202e' not in f3.read_text() and '\u202e'.encode('utf-8') not in f3.read_bytes()
    assert f4.read_bytes() == b'abc\n'
    # All files except f1 should be mentioned in output
    assert f2.name in out2 and f3.name in out2 and f4.name in out2
    assert ret2 == 1
