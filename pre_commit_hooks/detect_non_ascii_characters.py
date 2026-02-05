from __future__ import annotations
from grapheme_cluster_break import segment_grapheme_clusters
import unicodedata
import argparse
import fnmatch
import os
from collections.abc import Sequence

MIN_NULL_BYTES_FOR_BINARY = 3  # Multiple nulls indicate binary content
MAX_INVALID_UTF8_RATIO = 0.3  # If >30% invalid UTF-8, treat as binary
BINARY_DETECTION_BUFFER_SIZE = 4096  # Read first 4KB to detect binary files

MODE_BALANCED, MODE_VISIBLE_PLUS, MODE_ASCII_ONLY = 'balanced', 'visible-plus', 'ascii-only'
MODE_CHOICES = (MODE_BALANCED, MODE_VISIBLE_PLUS, MODE_ASCII_ONLY)
DEFAULT_INCLUDE_RANGE = '0x09,0x0A,0x0D,0x20-0x7E'  # tab, LF, CR, space, printable ASCII (0x20-0x7E)


# ASCII values correspond to:
#   0x09 - horizontal tab, \t
#   0x0A - line feed, \n
#   0x0D - carriage return, \r
#   0x20 - space
#   0x21-0x2F - punctuation: ! " # $ % & ' ( ) * + , - . /
#   0x30-0x39 - digits: 0-9
#   0x3A-0x40 - punctuation: : ; < = > ? @
#   0x41-0x5A - uppercase: A-Z
#   0x5B-0x60 - punctuation: [ \ ] ^ _ `
#   0x61-0x7A - lowercase: a-z
#   0x7B-0x7E - punctuation: { | } ~

ASCII_BASE = {0x09, 0x0A, 0x0D} | set(range(0x20, 0x7F))  # tab/LF/CR + space-tilde (printable ASCII)
LATIN1_VISIBLE = set(range(0xA0, 0x100))  # Latin-1 Supplement: é, ñ, ç, etc.
LATIN_EXT_A = set(range(0x0100, 0x0180))  # Latin Extended-A: Polish, Czech, Hungarian, etc.
CONTROL_C0 = set(range(0x00, 0x20))  # C0 controls (except tab, LF, CR which are in ASCII_BASE)
CONTROL_C1 = set(range(0x80, 0xA0))  # C1 controls (rarely used)
BIDI_OVERRIDES = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))  # Bidi text direction attacks
ZERO_WIDTHS = {0x200B, 0x200C, 0x200D}  # Invisible chars for hiding malicious code

EMOJI_BASE = (  # Consolidated emoji ranges
    set(range(0x1F600, 0x1F650)) | set(range(0x1F300, 0x1F6FF)) |  # Emoticons, Misc Symbols
    set(range(0x1F700, 0x1F77F)) | set(range(0x1F780, 0x1F7FF)) |  # Alchemical, Geometric
    set(range(0x1F800, 0x1F8FF)) | set(range(0x1F900, 0x1F9FF)) |  # Supplemental Arrows, Symbols
    set(range(0x1FA00, 0x1FAFF)) | set(range(0x2600, 0x26FF)) |  # Extended-A, Misc Symbols
    set(range(0x2700, 0x27BF)) | set(range(0xFE00, 0xFE0F))  # Dingbats, Variation Selectors
)
EMOJI_MODIFIERS = set(range(0x1F3FB, 0x1F400))  # Skin tone modifiers
VARIATION_SELECTORS = {0xFE0F}  # Emoji presentation selector

INVISIBLE_NAMES = {
    0x00: 'NULL',
    0x01: 'START OF HEADING',
    0x02: 'START OF TEXT',
    0x03: 'END OF TEXT',
    0x04: 'END OF TRANSMISSION',
    0x05: 'ENQUIRY',
    0x06: 'ACKNOWLEDGE',
    0x07: 'BELL',
    0x08: 'BACKSPACE',
    0x09: 'TAB',
    0x0A: 'LINE FEED',
    0x0B: 'VERTICAL TAB',
    0x0C: 'FORM FEED',
    0x0D: 'CARRIAGE RETURN',
    0x0E: 'SHIFT OUT',
    0x0F: 'SHIFT IN',
    0x10: 'DATA LINK ESCAPE',
    0x11: 'DEVICE CONTROL 1',
    0x12: 'DEVICE CONTROL 2',
    0x13: 'DEVICE CONTROL 3',
    0x14: 'DEVICE CONTROL 4',
    0x15: 'NEGATIVE ACKNOWLEDGE',
    0x16: 'SYNCHRONOUS IDLE',
    0x17: 'END OF TRANSMISSION BLOCK',
    0x18: 'CANCEL',
    0x19: 'END OF MEDIUM',
    0x1A: 'SUBSTITUTE',
    0x1B: 'ESCAPE',
    0x1C: 'FILE SEPARATOR',
    0x1D: 'GROUP SEPARATOR',
    0x1E: 'RECORD SEPARATOR',
    0x1F: 'UNIT SEPARATOR',
    0x7F: 'DELETE',
    0xA0: 'NO-BREAK SPACE',
    0x200B: 'ZERO WIDTH SPACE',
    0x200C: 'ZERO WIDTH NON-JOINER',
    0x200D: 'ZERO WIDTH JOINER',
    0x202A: 'LEFT-TO-RIGHT EMBEDDING',
    0x202B: 'RIGHT-TO-LEFT EMBEDDING',
    0x202C: 'POP DIRECTIONAL FORMATTING',
    0x202D: 'LEFT-TO-RIGHT OVERRIDE',
    0x202E: 'RIGHT-TO-LEFT OVERRIDE',
    0x2066: 'LEFT-TO-RIGHT ISOLATE',
    0x2067: 'RIGHT-TO-LEFT ISOLATE',
    0x2068: 'FIRST STRONG ISOLATE',
    0x2069: 'POP DIRECTIONAL ISOLATE',
}

RED, CYAN, BOLD, RESET = '\033[31m', '\033[36m', '\033[1m', '\033[0m'  # ANSI color codes


def is_binary_extension(filename: str) -> bool:
    """Check if file is binary based on extension."""
    BINARY_EXTENSIONS = {
        '7z', 'avi', 'bmp', 'class', 'dll', 'doc', 'docx', 'exe', 'flac', 'gif', 'ico', 'jar', 'jpeg', 'jpg', 'm4a', 'm4v',
        'mid', 'midi', 'mkv', 'mov', 'mp3', 'mp4', 'mpeg', 'mpg', 'ogg', 'otf', 'pdf', 'png', 'ppt', 'pptx', 'psd',
        'rar', 'so', 'tar', 'tif', 'tiff', 'ttf', 'wav', 'webm', 'webp', 'wma', 'wmv', 'xls', 'xlsx', 'zip',
    }
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return ext in BINARY_EXTENSIONS


def is_binary_by_content(data: bytes) -> bool:
    """Check if content is binary based on null bytes and UTF-8 validity."""
    if data.count(b'\x00') >= MIN_NULL_BYTES_FOR_BINARY:
        return True
    try:
        data.decode('utf-8')
        return False
    except UnicodeDecodeError:
        decoded = data.decode('utf-8', errors='surrogateescape')
        surrogate_count = sum(1 for ch in decoded if 0xDC80 <= ord(ch) <= 0xDCFF)
        return surrogate_count / max(1, len(data)) > MAX_INVALID_UTF8_RATIO


def is_gitattributes_binary(filename: str, gitattributes: dict) -> bool:
    """Check if file is marked as binary in .gitattributes."""
    for pattern, attrs in gitattributes.items():
        if fnmatch.fnmatch(filename, pattern):
            if attrs.get('filter') == 'lfs' or attrs.get('binary') or attrs.get('text') == False:
                return True
    return False


def parse_gitattributes(path: str) -> dict:
    """Parse .gitattributes file to extract binary/text settings."""
    attrs = {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                if not (line := line.strip()) or line.startswith('#'): continue
                parts = line.split()
                attrmap = {}
                for attr in parts[1:]:
                    if attr.startswith('filter=lfs'): attrmap['filter'] = 'lfs'
                    elif attr in ('binary', '-text'): attrmap['binary'] = True
                    elif attr == 'text': attrmap['text'] = True
                if attrmap: attrs[parts[0]] = attrmap
    except Exception: pass
    return attrs


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
    allowed = set()
    for part in (p.strip() for p in spec.split(',') if p.strip()):
        if '-' in part:
            start, end = (_parse_byte(s, parser) for s in part.split('-', 1))
            if start > end: parser.error(f'invalid range {part!r}: start > end')
            allowed.update(range(start, end + 1))
        else:
            allowed.add(_parse_byte(part, parser))
    return allowed


def _build_allowed(args: argparse.Namespace, parser: argparse.ArgumentParser) -> tuple[set[int], bool]:
    include_specs = args.include_range or [DEFAULT_INCLUDE_RANGE]
    allowed = set()
    for spec in include_specs:
        allowed.update(_parse_range_spec(spec, parser))
    for extra in args.allow_chars:
        allowed.update(extra.encode())
    if allowed == set(range(0x100)):
        parser.error('include-range would allow all bytes (0x00-0xFF), effectively disabling the checker. '
                    'This configuration is not allowed. To enable the checker, use more restrictive byte ranges via --include-range and/or --allow-chars.')
    return allowed, bool(args.include_range)


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build and configure the argument parser."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--file-include', action='append', default=[], metavar='GLOB',
                        help='Fnmatch-style glob patterns to include files. Can be repeated or comma-separated.')
    parser.add_argument('--file-exclude', action='append', default=[], metavar='GLOB',
                        help='Fnmatch-style patterns to exclude (applied last). Can be repeated or comma-separated.')
    parser.add_argument('--include-range', action='append', metavar='RANGE',
                        help=f'Comma-separated byte ranges to allow. Supports decimal or 0x-prefixed hex values and START-END spans. Default: {DEFAULT_INCLUDE_RANGE}')
    parser.add_argument('--allow-chars', action='append', default=[], metavar='CHARS',
                        help='Additional characters to permit (UTF-8 bytes of the given text).')
    parser.add_argument('--mode', choices=MODE_CHOICES, default=MODE_BALANCED,
                        help='Character policy: balanced (default, allow ASCII + Latin-1, block bidi/zero-width/control), visible-plus (ASCII + emoji, block others), ascii-only (strict).')
    parser.add_argument('--fix', action='store_true',
                        help='Modify files to fix disallowed characters (default is check-only).')
    parser.add_argument('filenames', nargs='+', help='Files to check')
    return parser


def _split_comma_list(values: list[str]) -> list[str]:
    split_values: list[str] = []
    for value in values:
        split_values.extend(part.strip() for part in value.split(',') if part.strip())
    return split_values


def _is_glob_pattern(pattern: str) -> bool:
    return any(ch in pattern for ch in ('*', '?', '['))


def _match_pattern(filename: str, pattern: str) -> bool:
    """Match a filename against a pattern using both full path and basename."""
    return fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(os.path.basename(filename), pattern)


def _match_any_pattern(filename: str, patterns: list[str]) -> bool:
    """Check if filename matches any pattern in the list."""
    return any(_match_pattern(filename, pattern) for pattern in patterns)


def _detect_conflicting_filters(include: list[str], exclude: list[str], filenames: list[str]) -> str | None:
    """Detect conflicting include/exclude filters based on explicit paths and file list."""
    if not include:
        return None
    if not exclude:
        return None
    include_explicit = {os.path.normpath(p) for p in include if p and not _is_glob_pattern(p)}
    exclude_explicit = {os.path.normpath(p) for p in exclude if p and not _is_glob_pattern(p)}
    include_globs = [p for p in include if p and _is_glob_pattern(p)]
    exclude_globs = [p for p in exclude if p and _is_glob_pattern(p)]

    conflicts = sorted(include_explicit & exclude_explicit)
    if conflicts: # Conflict 1: explicit paths in both include and exclude

        return ('Conflicting file filters: --file-include and --file-exclude both list: '
                f'{", ".join(conflicts)}.')

    if include_globs and exclude_globs:  # Conflict 2: both include and exclude are the same glob (cancels out all files)
        for inc_glob in include_globs:
            for exc_glob in exclude_globs:
                if inc_glob == exc_glob:
                    return f'Conflicting file filters: --file-include and --file-exclude both use "{inc_glob}". This would exclude all files.'

    return None


def _is_control_or_null(cp: int) -> bool:
    """Check if codepoint is a control character or null."""
    return cp in CONTROL_C0 or cp in CONTROL_C1 or cp == 0x7F


def _cluster_allowed_balanced(cluster_cps: list[int]) -> bool:
    """Check if cluster allowed in balanced mode (ASCII + Latin-1 + Latin Extended-A)."""
    if any(cp in BIDI_OVERRIDES or cp in ZERO_WIDTHS or cp == 0x00A0 for cp in cluster_cps):
        return False
    if any(_is_control_or_null(cp) and cp not in {0x09, 0x0A, 0x0D} for cp in cluster_cps):
        return False
    return all(cp in ASCII_BASE or cp in LATIN1_VISIBLE or cp in LATIN_EXT_A for cp in cluster_cps)

def _cluster_allowed_visible_plus(cluster_cps: list[int]) -> bool:
    """Check if cluster allowed in visible-plus mode (ASCII + emoji + international scripts)."""
    for cp in cluster_cps:  # Block security threats
        if cp == 0x00A0 or cp in BIDI_OVERRIDES:
            return False
        if _is_control_or_null(cp) and cp not in {0x09, 0x0A, 0x0D}:
            return False
    if all(cp in ZERO_WIDTHS for cp in cluster_cps):  # Block clusters of only zero-width chars
        return False
    has_zero_width = any(cp in ZERO_WIDTHS for cp in cluster_cps)
    if has_zero_width:  # Zero-widths only allowed with emoji
        has_emoji = any(cp in EMOJI_BASE or cp in EMOJI_MODIFIERS or cp in VARIATION_SELECTORS for cp in cluster_cps)
        if not has_emoji:
            return False
    return True


def _cluster_allowed_ascii_only(cluster_cps: list[int]) -> bool:
    """Check if cluster allowed in ascii-only mode (strict ASCII)."""
    return all(cp in ASCII_BASE for cp in cluster_cps) and 0x00A0 not in cluster_cps



def _cluster_allowed(cluster_bytes: bytes, cluster_text: str, allowed_bytes: set[int],
                     mode: str, restrict_to_allowed_bytes: bool) -> bool:
    """Check if grapheme cluster is allowed based on mode and byte allowances."""
    cps = [ord(ch) for ch in cluster_text]
    allowed_by_mode = (
        _cluster_allowed_balanced(cps) if mode == MODE_BALANCED else
        _cluster_allowed_visible_plus(cps) if mode == MODE_VISIBLE_PLUS else
        _cluster_allowed_ascii_only(cps)
    )
    if allowed_by_mode: # Allow if restrict_to_allowed_bytes is True and all bytes in allowed set (expansion/override)
        return True

    return restrict_to_allowed_bytes and cluster_bytes and all(b in allowed_bytes for b in cluster_bytes)


def _categorize_offender(cluster: str) -> str:
    """Categorize an offender as 'invisible', 'emoji', or 'other'."""
    if all(ord(c) in INVISIBLE_NAMES for c in cluster): return 'invisible'
    if any(0x1F600 <= ord(c) <= 0x1FAFF or ord(c) in EMOJI_BASE for c in cluster): return 'emoji'
    return 'other'


def _format_cluster_safe(cluster: str) -> str:
    """Format a cluster for safe display, using <XXXX> notation for invisible chars."""
    result = []
    for c in cluster:
        cp = ord(c)
        result.append(f'<{cp:04X}>' if cp in INVISIBLE_NAMES or cp < 0x20 or cp == 0x7F or (0x80 <= cp < 0xA0) else c)
    return ''.join(result)


def _get_problematic_codepoints(cluster: str) -> list[int]:
    """Identify which codepoints in the cluster are actually problematic (not innocent context)."""
    cps = [ord(c) for c in cluster]
    problematic = [cp for cp in cps if (
        (cp in CONTROL_C0 and cp not in {0x09, 0x0A, 0x0D}) or
        cp in CONTROL_C1 or cp == 0x7F or cp in BIDI_OVERRIDES or cp in ZERO_WIDTHS or cp == 0x00A0
    )]
    return problematic if problematic else [cp for cp in cps if cp >= 0x80] or cps


def _format_offenders(offenders: list[tuple[int, int, str]], text: str, fix_mode: bool = False) -> tuple[str, dict[str, int]]:
    """Format offenders grouped by category and return formatted output with counts."""
    categorized = {'invisible': [], 'emoji': [], 'other': []}
    for line, col, cluster in offenders:
        categorized[_categorize_offender(cluster)].append((line, col, cluster))

    counts_dict = {k: len(v) for k, v in categorized.items()}
    total = sum(counts_dict.values())

    summary = [f"{'Removed' if fix_mode else 'Found'} {total} {'problematic characters:' if fix_mode else 'issues:'}"]
    if counts_dict['invisible']: summary.append(f"• {counts_dict['invisible']} invisible/control characters (security risk)")
    if counts_dict['emoji']: summary.append(f"• {counts_dict['emoji']} emoji (blocked in balanced mode)")
    if counts_dict['other']: summary.append(f"• {counts_dict['other']} other non-ASCII characters")

    lines = ['\n'.join(summary), '']
    for (cat, color) in [('invisible', RED), ('emoji', CYAN), ('other', BOLD)]:
        for line, col, cluster in categorized[cat]:
            problematic_cps = _get_problematic_codepoints(cluster)
            cp_strs = [f"U+{cp:04X}" for cp in problematic_cps]
            names = [INVISIBLE_NAMES.get(cp) or unicodedata.name(chr(cp), 'UNKNOWN') for cp in problematic_cps]
            safe = _format_cluster_safe(cluster)
            if len(cluster) > 1 and len(problematic_cps) < len(cluster):
                lines.append(f"{color}Line {line}, Col {col}: '{safe}' - contains problematic: {', '.join(cp_strs)} ({', '.join(names)}){RESET}")
            else:
                lines.append(f"{color}Line {line}, Col {col}: '{safe}' ({', '.join(cp_strs)}) {', '.join(names)}{RESET}")

    return '\n'.join(lines), counts_dict


def _categorize_files(filenames: list[str], file_include: list[str], file_exclude: list[str],
                      gitattributes: dict[str, dict[str, str]]) -> tuple[list[str], list[str], list[str]]:
    """Categorize files into: to_check, binary, excluded. """
    to_check, binary, excluded = [], [], []

    explicit_includes = [p for p in file_include if p and not _is_glob_pattern(p)]

    for filename in filenames:
        matched_explicit = explicit_includes and _match_any_pattern(filename, explicit_includes)
        if matched_explicit:
            pass  # Explicitly included files bypass other filters
        elif file_include:
            if not _match_any_pattern(filename, file_include):
                excluded.append(filename)
                continue

            excluded_by_pattern = file_exclude and _match_any_pattern(filename, file_exclude)
            if excluded_by_pattern:
                excluded.append(filename)
                continue
        else:
            excluded_by_pattern = file_exclude and _match_any_pattern(filename, file_exclude)
            if excluded_by_pattern:
                excluded.append(filename)
                continue

        if is_binary_extension(filename):  # Check if binary
            binary.append(filename)
            continue
        try:  # Read file to check by content
            with open(filename, 'rb') as f:
                data = f.read(BINARY_DETECTION_BUFFER_SIZE)
                if is_binary_by_content(data):
                    binary.append(filename)
                    continue
            is_gitattr_binary = gitattributes and is_gitattributes_binary(filename, gitattributes)
            if is_gitattr_binary:  # Check .gitattributes if present
                binary.append(filename)
                continue
        except (IOError, OSError):  # pragma: no cover
            excluded.append(filename)
            continue
        to_check.append(filename)
    return to_check, binary, excluded


def _print_file_status_header(filenames: list[str], binary_files: list[str], excluded_files: list[str]) -> None:
    """Print header showing which files are being processed, ignored, or excluded."""
    if binary_files or excluded_files:
        print('Files being processed:')
        for filename in filenames:
            if filename in binary_files:
                print(f'  {filename} (ignored)')
            elif filename in excluded_files:
                print(f'  {filename} (excluded)')
            else:
                print(f'  {filename}')
        print()


def _process_single_file(filename: str, allowed: set[int], allowed_clusters: set[str],
                        mode: str, restrict_to_includes: bool, fix_mode: bool) -> tuple[list[tuple[int, int, str]], bytes, str | None]:
    """Process a single file and return offenders, fixed data, and original text."""
    with open(filename, 'rb') as f:
        data = f.read()

    try:  # Try to decode as UTF-8 first
        orig_text = data.decode('utf-8')
        use_grapheme_clusters = True
    except UnicodeDecodeError:
        use_grapheme_clusters = False
        orig_text = None

    offenders: list[tuple[int, int, str]] = []
    new_chunks: list[bytes] = []
    line, col = 1, 1

    if use_grapheme_clusters and orig_text is not None:
        for cluster in segment_grapheme_clusters(orig_text):
            if cluster in allowed_clusters:  # Always preserve explicitly allowed clusters
                new_chunks.append(cluster.encode('utf-8'))
                for ch in cluster:
                    line, col = (line + 1, 1) if ch == '\n' else (line, col + 1)
                continue
            cluster_line, cluster_col = line, col
            cluster_bytes = cluster.encode('utf-8')
            allowed_cluster = _cluster_allowed(cluster_bytes, cluster, allowed, mode, restrict_to_includes)
            if allowed_cluster:
                new_chunks.append(cluster_bytes)
            else:
                offenders.append((cluster_line, cluster_col, cluster))
                if fix_mode and mode == MODE_ASCII_ONLY and len(cluster) == 1:  # In ascii-only mode, replace Latin-1 or Latin Extended-A accented letters with ASCII equivalents
                    cp = ord(cluster)
                    if (0xC0 <= cp <= 0xFF) or (0x0100 <= cp <= 0x017F):
                        decomp = unicodedata.normalize('NFKD', cluster)
                        ascii_equiv = ''.join(c for c in decomp if ord(c) < 128)
                        if ascii_equiv:
                            new_chunks.append(ascii_equiv.encode('utf-8'))
                            continue
            for ch in cluster:  # Update line and column tracking
                line, col = (line + 1, 1) if ch == '\n' else (line, col + 1)
    else:  # Fallback for invalid UTF-8: process byte by byte
        for byte_val in data:
            if byte_val in allowed or byte_val in {0x09, 0x0A, 0x0D}:
                new_chunks.append(bytes([byte_val]))
                line, col = (line + 1, 1) if byte_val == 0x0A else (line, col + 1)
            else:
                offenders.append((line, col, f'<{byte_val:02X}>'))
                if not fix_mode:
                    new_chunks.append(bytes([byte_val]))
                col += 1

    return offenders, b''.join(new_chunks), orig_text


def main(argv: Sequence[str] | None = None) -> int:
    gitattributes = {}  # Parse .gitattributes if present
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    gitattributes_path = os.path.join(repo_root, '.gitattributes')
    if os.path.exists(gitattributes_path):  # pragma: no branch
        gitattributes = parse_gitattributes(gitattributes_path)  # pragma: no cover

    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    args.file_include = _split_comma_list(args.file_include)
    args.file_exclude = _split_comma_list(args.file_exclude)

    conflict_error = _detect_conflicting_filters(args.file_include, args.file_exclude, list(args.filenames))
    if conflict_error:
        parser.error(conflict_error)

    allowed, restrict_to_includes = _build_allowed(args, parser)
    allowed_clusters = set(args.allow_chars or [])

    files_to_check, binary_files, excluded_files = _categorize_files(
        args.filenames, args.file_include, args.file_exclude, gitattributes
    )

    _print_file_status_header(args.filenames, binary_files, excluded_files)

    if not files_to_check:
        if excluded_files:
            parser.error('no files to check after applying filters (--file-include, --file-exclude). '
                        'This configuration is not allowed. You must have at least one file to check.')
        return 0

    retv, total_files_checked, total_files_with_issues, total_issues = 0, 0, 0, 0

    for filename in files_to_check:
        offenders, new_data, orig_text = _process_single_file(
            filename, allowed, allowed_clusters, args.mode, restrict_to_includes, args.fix
        )
        total_files_checked += 1

        if not offenders:
            continue

        total_files_with_issues += 1
        total_issues += len(offenders)

        if args.fix:
            with open(filename, 'wb') as f:
                f.write(new_data)

        prefix = 'Fixed' if args.fix else 'Checking'
        formatted_output, counts = _format_offenders(
            offenders, orig_text if orig_text else new_data.decode('utf-8', errors='replace'), fix_mode=args.fix
        )
        print(f'{prefix} {filename}...')
        print(f'  {formatted_output}')

        if args.fix:
            print(f'\n⚠️  Review changes and re-stage before committing (git add {filename})')

        retv = 1

    if total_files_checked > 0:  # pragma: no branch
        status_text = (f'{total_files_with_issues} fixed, {total_issues} total problems removed' if args.fix
                      else f'{total_files_with_issues} with issues, {total_issues} total problems')
        print(f'\nSummary: {total_files_checked} files checked, {status_text}')

    return retv


if __name__ == '__main__':
    raise SystemExit(main())
