from __future__ import annotations

import argparse
import fnmatch
from collections.abc import Sequence

import grapheme

MODE_BALANCED = 'balanced'
MODE_VISIBLE_PLUS = 'visible-plus'
MODE_ASCII_ONLY = 'ascii-only'
MODE_CHOICES = (MODE_BALANCED, MODE_VISIBLE_PLUS, MODE_ASCII_ONLY)

DEFAULT_INCLUDE_RANGE = '0x09,0x0A,0x0D,0x20-0x7E'

ASCII_BASE = {0x09, 0x0A, 0x0D} | set(range(0x20, 0x7F))
LATIN1_VISIBLE = set(range(0xA0, 0x100))
CONTROL_C0 = set(range(0x00, 0x20))
CONTROL_C1 = set(range(0x80, 0xA0))
BIDI_OVERRIDES = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
ZERO_WIDTHS = {0x200B, 0x200C, 0x200D}
EMOJI_BASE = set(range(0x1F600, 0x1F650))
EMOJI_MODIFIERS = set(range(0x1F3FB, 0x1F400))
VARIATION_SELECTORS = {0xFE0F}


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


def _build_allowed(
        args: argparse.Namespace, parser: argparse.ArgumentParser,
) -> tuple[set[int], bool]:
    include_specs = args.include_range or [DEFAULT_INCLUDE_RANGE]
    restrict_to_includes = bool(args.include_range)
    allowed: set[int] = set()
    for spec in include_specs:
        allowed.update(_parse_range_spec(spec, parser))
    for extra in args.allow_chars:
        allowed.update(extra.encode())
    return allowed, restrict_to_includes


def _match_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def _filter_filenames(
        filenames: list[str],
        globs: list[str],
        include: list[str],
        exclude: list[str],
) -> list[str]:
    selected = filenames
    if globs:
        selected = [f for f in selected if _match_any(f, globs)]
    if include:
        selected = [f for f in selected if _match_any(f, include)]
    if exclude:
        selected = [f for f in selected if not _match_any(f, exclude)]
    return selected


def _is_control_or_null(cp: int) -> bool:
    return cp in CONTROL_C0 or cp in CONTROL_C1 or cp == 0x7F


def _cluster_allowed_balanced(cluster_cps: list[int]) -> bool:
    if any(cp in BIDI_OVERRIDES for cp in cluster_cps):
        return False
    if any(cp in ZERO_WIDTHS for cp in cluster_cps):
        return False
    if any(_is_control_or_null(cp) and cp not in {0x09, 0x0A, 0x0D} for cp in cluster_cps):
        return False
    return all(cp in ASCII_BASE or cp in LATIN1_VISIBLE for cp in cluster_cps)


def _cluster_allowed_visible_plus(cluster_cps: list[int]) -> bool:
    if any(cp in ZERO_WIDTHS for cp in cluster_cps):
        return False
    if any(cp in BIDI_OVERRIDES for cp in cluster_cps):
        return False
    if any(_is_control_or_null(cp) and cp not in {0x09, 0x0A, 0x0D} for cp in cluster_cps):
        return False

    if all(cp in ASCII_BASE for cp in cluster_cps):
        return True

    emoji_ok = all(
        cp in EMOJI_BASE
        or cp in EMOJI_MODIFIERS
        or cp in VARIATION_SELECTORS
        for cp in cluster_cps
    )
    return emoji_ok


def _cluster_allowed_ascii_only(cluster_cps: list[int]) -> bool:
    return all(cp in ASCII_BASE for cp in cluster_cps)


def _cluster_allowed(
        cluster_bytes: bytes,
        cluster_text: str,
        allowed_bytes: set[int],
        mode: str,
        restrict_to_allowed_bytes: bool,
) -> bool:
    if cluster_bytes and all(b in allowed_bytes for b in cluster_bytes):
        return True

    if restrict_to_allowed_bytes:
        return False

    cps = [ord(ch) for ch in cluster_text]
    if mode == MODE_BALANCED:
        return _cluster_allowed_balanced(cps)
    if mode == MODE_VISIBLE_PLUS:
        return _cluster_allowed_visible_plus(cps)
    return _cluster_allowed_ascii_only(cps)


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
        '--files-include',
        action='append',
        default=[],
        metavar='GLOB',
        help='Additional fnmatch-style patterns to include (after files-glob).',
    )
    parser.add_argument(
        '--files-exclude',
        action='append',
        default=[],
        metavar='GLOB',
        help='Fnmatch-style patterns to exclude (applied last).',
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
        '--mode',
        choices=MODE_CHOICES,
        default=MODE_BALANCED,
        help=(
            'Character policy: balanced (default, allow ASCII + Latin-1, block bidi/zero-width/control),'  # noqa: E501
            ' visible-plus (ASCII + emoji, block others), ascii-only (strict).'  # noqa: E501
        ),
    )
    parser.add_argument(
        '--check-only',
        action='store_true',
        help='Detect disallowed bytes but do not modify files.',
    )
    parser.add_argument('filenames', nargs='+', help='Files to check')
    args = parser.parse_args(argv)

    allowed, restrict_to_includes = _build_allowed(args, parser)
    filenames = _filter_filenames(
        args.filenames, args.files_glob, args.files_include, args.files_exclude,
    )

    retv = 0
    for filename in filenames:
        with open(filename, 'rb') as f:
            data = f.read()

        text = data.decode('utf-8', errors='surrogateescape')

        offenders: list[tuple[int, int]] = []
        new_chunks: list[bytes] = []

        byte_pos = 0
        for cluster in grapheme.graphemes(text):
            cluster_bytes = cluster.encode('utf-8', errors='surrogateescape')
            if _cluster_allowed(
                cluster_bytes, cluster, allowed, args.mode, restrict_to_includes,
            ):
                new_chunks.append(cluster_bytes)
            else:
                offenders.extend(
                    (byte_pos + i, cluster_bytes[i]) for i in range(len(cluster_bytes))
                )
            byte_pos += len(cluster_bytes)

        if not offenders:
            continue

        if args.check_only:
            print(f'{filename}: disallowed bytes {_format_offenders(offenders)}')
            retv = 1
            continue

        new_data = b''.join(new_chunks)
        with open(filename, 'wb') as f:
            f.write(new_data)
        print(
            f'Fixing {filename}: ' f'disallowed bytes {_format_offenders(offenders)}',
        )
        retv = 1
    return retv


if __name__ == '__main__':
    raise SystemExit(main())
