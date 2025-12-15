from __future__ import annotations

import argparse
import fnmatch
from collections.abc import Sequence

DEFAULT_INCLUDE_RANGE = '0x09,0x0A,0x0D,0x20-0x7E'


def _parse_byte(token: str, parser: argparse.ArgumentParser) -> int:
    base = 16 if token.lower().startswith('0x') else 10
    try:
        value = int(token, base)
    except ValueError:
        parser.error(f'invalid byte value {token!r}')
    if not 0 <= value <= 0xFF:
        parser.error(f'byte value out of range: {token!r}')
    return value


def _parse_range_spec(spec: str, parser: argparse.ArgumentParser) -> set[int]:
    allowed: set[int] = set()
    for raw_part in spec.split(','):
        part = raw_part.strip()
        if not part:
            continue
        if '-' in part:
            start_s, end_s = part.split('-', 1)
            start = _parse_byte(start_s, parser)
            end = _parse_byte(end_s, parser)
            if start > end:
                parser.error(f'invalid range {part!r}: start > end')
            allowed.update(range(start, end + 1))
        else:
            allowed.add(_parse_byte(part, parser))
    return allowed


def _build_allowed(args: argparse.Namespace, parser: argparse.ArgumentParser) -> set[int]:
    include_specs = args.include_range or [DEFAULT_INCLUDE_RANGE]
    allowed: set[int] = set()
    for spec in include_specs:
        allowed.update(_parse_range_spec(spec, parser))
    for extra in args.allow_chars:
        allowed.update(extra.encode())
    return allowed


def _filter_filenames(filenames: list[str], globs: list[str]) -> list[str]:
    if not globs:
        return filenames
    return [f for f in filenames if any(fnmatch.fnmatch(f, g) for g in globs)]


def _format_offenders(offenders: list[tuple[int, int]]) -> str:
    def _label(pos: int, b: int) -> str:
        if 0x20 <= b <= 0x7E:
            ch = chr(b)
            # use repr to surface escapes for backslash/quote while staying ASCII
            ch_repr = repr(ch)[1:-1]
            return f"0x{b:02x}('{ch_repr}')@{pos}"
        return f'0x{b:02x}@{pos}'

    preview = ', '.join(_label(i, b) for i, b in offenders[:5])
    if len(offenders) > 5:
        preview += ', ...'
    return preview


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--files-glob',
        action='append',
        default=[],
        metavar='GLOB',
        help='Optional fnmatch-style glob to further filter listed files.',
    )
    parser.add_argument(
        '--include-range',
        action='append',
        metavar='RANGE',
        help=(
            'Comma-separated byte ranges to allow. '
            'Supports decimal or 0x-prefixed hex values and START-END spans. '
            f'Default: {DEFAULT_INCLUDE_RANGE}'
        ),
    )
    parser.add_argument(
        '--allow-chars',
        action='append',
        default=[],
        metavar='CHARS',
        help='Additional characters to permit (UTF-8 bytes of the given text).',
    )
    parser.add_argument(
        '--check-only',
        action='store_true',
        help='Detect disallowed bytes but do not modify files.',
    )
    parser.add_argument('filenames', nargs='+', help='Files to check')
    args = parser.parse_args(argv)

    allowed = _build_allowed(args, parser)
    filenames = _filter_filenames(args.filenames, args.files_glob)

    retv = 0
    for filename in filenames:
        with open(filename, 'rb') as f:
            data = f.read()

        offenders = [(i, b) for i, b in enumerate(data) if b not in allowed]
        if not offenders:
            continue

        if args.check_only:
            print(f'{filename}: disallowed bytes {_format_offenders(offenders)}')
            retv = 1
            continue

        new_data = bytes(b for b in data if b in allowed)
        if new_data != data:
            with open(filename, 'wb') as f:
                f.write(new_data)
            print(
                f'Fixing {filename}: ' f'disallowed bytes {_format_offenders(offenders)}',
            )
            retv = 1
    return retv


if __name__ == '__main__':
    raise SystemExit(main())
