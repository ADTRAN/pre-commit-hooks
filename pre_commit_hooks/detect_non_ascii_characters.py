from __future__ import annotations
from grapheme_cluster_break import segment_grapheme_clusters
from binaryornot.check import is_binary
from pathlib import Path, PurePath
from pre_commit_hooks.util import zsplit
from collections.abc import Sequence

import unicodedata
import argparse
import sys
import re
import subprocess


BINARY_DETECTION_BUFFER_SIZE = 4096  # Read first 4KB to detect binary files

MODE_BALANCED = "balanced"
MODE_VISIBLE_PLUS = "visible-plus"
MODE_ASCII_ONLY = "ascii-only"

MODE_CHOICES = (MODE_BALANCED, MODE_VISIBLE_PLUS, MODE_ASCII_ONLY)
DEFAULT_INCLUDE_RANGE = (
    "0x09,0x0A,0x0D,0x20-0x7E"  # tab, LF, CR, space, printable ASCII (0x20-0x7E)
)
ALLOWED_WHITESPACE = {0x09, 0x0A, 0x0D}  # tab, LF, CR
MIN_BYTE_VALUE = 0x00
MAX_BYTE_VALUE = 0xFF
TOTAL_BYTE_VALUES = 0x100  # All possible byte values (0x00-0xFF)
ASCII_MAX = 0x7F  # Maximum value for ASCII characters
NON_ASCII_START = 0x80  # Start of non-ASCII range
ASCII_LIMIT = 128  # Alias for ASCII_MAX

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

ASCII_BASE = set(range(0x20, 0x7F))  #
ASCII_BASE_AND_ACCEPTABLE_WHITESPACE = (
    ASCII_BASE | ALLOWED_WHITESPACE
)  # tab,LF,CR,space-tilde + printable ASCII
LATIN1_VISIBLE = set(range(0xA0, 0x100))  # Latin-1 Supplement: é, ñ, ç, etc.
LATIN_EXT_A = set(
    range(0x0100, 0x0180)
)  # Latin Extended-A: Polish, Czech, Hungarian, etc.
CONTROL_C0 = set(range(0x00, 0x20))  # C0 controls
CONTROL_C1 = set(range(0x80, 0xA0))  # C1 controls
BIDI_OVERRIDES = set(range(0x202A, 0x202F)) | set(
    range(0x2066, 0x206A)
)  # Bidi text direction attacks
ZERO_WIDTHS = {0x200B, 0x200C, 0x200D}  # Invisible chars for hiding malicious code
LATIN_ACCENTED = LATIN1_VISIBLE | LATIN_EXT_A

EMOJI_BASE = (  # Consolidated emoji ranges
    set(range(0x1F600, 0x1F650))
    | set(range(0x1F300, 0x1F6FF))  # Emoticons, Misc Symbols
    | set(range(0x1F700, 0x1F77F))
    | set(range(0x1F780, 0x1F7FF))  # Alchemical, Geometric
    | set(range(0x1F800, 0x1F8FF))
    | set(range(0x1F900, 0x1F9FF))  # Supplemental Arrows, Symbols
    | set(range(0x1FA00, 0x1FAFF))
    | set(range(0x2600, 0x26FF))  # Extended-A, Misc Symbols
    | set(range(0x2700, 0x27BF))
    | set(range(0xFE00, 0xFE0F))  # Dingbats, Variation Selectors
)
EMOJI_MODIFIERS = set(range(0x1F3FB, 0x1F400))  # Skin tone modifiers
VARIATION_SELECTORS = {0xFE0F}  # Emoji presentation selector

INVISIBLE_NAMES = {
    0x00: "NULL",
    0x01: "START OF HEADING",
    0x02: "START OF TEXT",
    0x03: "END OF TEXT",
    0x04: "END OF TRANSMISSION",
    0x05: "ENQUIRY",
    0x06: "ACKNOWLEDGE",
    0x07: "BELL",
    0x08: "BACKSPACE",
    0x09: "TAB",
    0x0A: "LINE FEED",
    0x0B: "VERTICAL TAB",
    0x0C: "FORM FEED",
    0x0D: "CARRIAGE RETURN",
    0x0E: "SHIFT OUT",
    0x0F: "SHIFT IN",
    0x10: "DATA LINK ESCAPE",
    0x11: "DEVICE CONTROL 1",
    0x12: "DEVICE CONTROL 2",
    0x13: "DEVICE CONTROL 3",
    0x14: "DEVICE CONTROL 4",
    0x15: "NEGATIVE ACKNOWLEDGE",
    0x16: "SYNCHRONOUS IDLE",
    0x17: "END OF TRANSMISSION BLOCK",
    0x18: "CANCEL",
    0x19: "END OF MEDIUM",
    0x1A: "SUBSTITUTE",
    0x1B: "ESCAPE",
    0x1C: "FILE SEPARATOR",
    0x1D: "GROUP SEPARATOR",
    0x1E: "RECORD SEPARATOR",
    0x1F: "UNIT SEPARATOR",
    0x7F: "DELETE",
    0xA0: "NO-BREAK SPACE",
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
}

DELETE_CHAR = 0x7F  # Control character for DELETE
CONTROL_AND_DELETE_CHARS = (
    CONTROL_C0 | CONTROL_C1 | {DELETE_CHAR}
)  # All control characters plus DELETE

NOBREAK_SPACE = 0xA0  # Non-breaking space (U+00A0)
PROBLEMATIC_CODEPOINTS = (
    (CONTROL_AND_DELETE_CHARS - ALLOWED_WHITESPACE)
    | BIDI_OVERRIDES
    | ZERO_WIDTHS
    | {NOBREAK_SPACE}
)
EMOJI_ALL = EMOJI_BASE | EMOJI_MODIFIERS | VARIATION_SELECTORS

ALWAYS_EXCLUDED_FILENAMES = {".pre-commit-config.yaml"}

RED = "\033[31m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"


class SilentArgumentParser(argparse.ArgumentParser):
    def error(self, message):  # Print concise error message with the specific reason

        print("\n========== ERROR ==========")
        print(f"Argument error: {message}")
        print("Check your pre-commit config or hook usage.")
        print("==========================\n")
        sys.exit(2)


def file_is_binary(filename: str, ignored_files: set) -> bool:
    """Determine if a file should be treated as binary."""

    if (filename in ignored_files) or is_binary(filename):
        return True
    return False


def get_lfs_and_binary_tracked_files() -> set:
    """Get files tracked by git-lfs and binary files based on gitattributes."""
    result = set()
    try:
        ls_files = subprocess.run(  # Get all tracked files in the repo
            ("git", "ls-files", "-z"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            check=True,
        )
        filenames = zsplit(ls_files.stdout)
        if not filenames:
            return result

        check_attr = subprocess.run(  # Check attributes for all tracked files to find those with filter=lfs/binary/text
            ("git", "check-attr", "filter", "binary", "text", "-z", "--stdin"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            check=True,
            input="\0".join(filenames),
        )
        stdout = zsplit(check_attr.stdout)

        for i in range(0, len(stdout), 3):
            filename, attr, value = stdout[i], stdout[i + 1], stdout[i + 2]
            if (
                (attr == "filter" and value == "lfs")
                or (attr == "binary" and value == "set")
                or (attr == "text" and value == "unset")
            ):
                result.add(filename)
    except Exception:
        pass
    return result


def _parse_byte(token: str, parser: argparse.ArgumentParser) -> int:
    base = 16 if token.lower().startswith("0x") else 10
    try:
        value = int(token, base)
    except ValueError:
        parser.error(f"invalid byte value {token!r}")
    if value < MIN_BYTE_VALUE or value > MAX_BYTE_VALUE:
        parser.error(f"byte value out of range: {token!r}")
    return value


def _parse_range_spec(spec: str, parser: argparse.ArgumentParser) -> set[int]:
    allowed = set()
    for part in (p.strip() for p in spec.split(",") if p.strip()):
        if "-" in part:
            range_values = [_parse_byte(s, parser) for s in part.split("-", 1)]
            start = range_values[0]
            end = range_values[1]
            if start > end:
                parser.error(f"invalid range {part!r}: start > end")
            allowed.update(range(start, end + 1))
        else:
            allowed.add(_parse_byte(part, parser))
    return allowed


def _build_allowed(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> tuple[set[int], bool]:
    include_specs = args.include_range or [DEFAULT_INCLUDE_RANGE]
    allowed = set()
    for spec in include_specs:
        allowed.update(_parse_range_spec(spec, parser))

    extra_clusters: set[str] = set()
    for extra in args.allow_chars:
        allowed.update(extra.encode("utf-8"))
        for cluster in segment_grapheme_clusters(extra):
            extra_clusters.add(cluster)

    if allowed == set(range(TOTAL_BYTE_VALUES)):
        parser.error(
            "include-range would allow all bytes (0x00-0xFF), effectively disabling the checker. "
            "This configuration is not allowed. To enable the checker, use more restrictive byte ranges via --include-range and/or --allow-chars."
        )
    return allowed, bool(args.include_range), extra_clusters


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build and configure the argument parser."""
    parser = SilentArgumentParser()
    parser.add_argument(
        "--file-include",
        action="append",
        default=[],
        metavar="GLOB",
        help="Glob-style patterns to include files. Can be repeated or comma-separated.",
    )
    parser.add_argument(
        "--file-exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Glob-style patterns to exclude (applied last). Can be repeated or comma-separated.",
    )
    parser.add_argument(
        "--include-range",
        action="append",
        metavar="RANGE",
        help=f"Comma-separated byte ranges to allow. Supports decimal or 0x-prefixed hex values and START-END spans. Default: {DEFAULT_INCLUDE_RANGE}",
    )
    parser.add_argument(
        "--allow-chars",
        action="append",
        default=[],
        metavar="CHARS",
        help="Additional characters to permit (UTF-8 bytes of the given text).",
    )
    parser.add_argument(
        "--mode",
        choices=MODE_CHOICES,
        default=MODE_BALANCED,
        help="Character policy: balanced (default, allow ASCII + Latin-1, block bidi/zero-width/control), visible-plus (ASCII + emoji, block others), ascii-only (strict).",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Modify files to fix disallowed characters (default is check-only).",
    )
    parser.add_argument("filenames", nargs="+", help="Files to check")
    return parser


def _is_glob_pattern(pattern: str) -> bool:
    return any(ch in pattern for ch in ("*", "?", "["))


def _match_any_pattern(filename: str, patterns: list[str]) -> bool:
    """Check if filename matches any pattern in the list."""
    return any(
        PurePath(filename).match(pattern)
        or PurePath(Path(filename).name).match(pattern)
        for pattern in patterns
    )


def _detect_conflicting_filters(
    include: list[str], exclude: list[str], filenames: list[str]
) -> str | None:
    """Detect conflicting include/exclude filters based on explicit paths and file list."""
    if not include or not exclude:
        return None

    include_explicit = {
        str(Path(p).resolve()) for p in include if p and not _is_glob_pattern(p)
    }
    exclude_explicit = {
        str(Path(p).resolve()) for p in exclude if p and not _is_glob_pattern(p)
    }
    include_globs = set(p for p in include if p and _is_glob_pattern(p))
    exclude_globs = set(p for p in exclude if p and _is_glob_pattern(p))

    conflicts = include_explicit & exclude_explicit
    if conflicts:  # Conflict 1: explicit paths in both include and exclude
        return (
            "Conflicting file filters: --file-include and --file-exclude both list: "
            f"{', '.join(sorted(conflicts))}."
        )

    glob_conflicts = (
        include_globs & exclude_globs
    )  # Conflict 2: identical globs in both include and exclude
    if glob_conflicts:
        return (
            f"Conflicting file filters: --file-include and --file-exclude both use "
            f'"{min(glob_conflicts)}". This would exclude all files.'
        )

    return None


def _cluster_allowed_balanced(cluster_cps: list[int]) -> bool:
    """Check if cluster allowed in balanced mode (ASCII + Latin-1 + Latin Extended-A)."""
    cluster_set = set(cluster_cps)
    if cluster_set & PROBLEMATIC_CODEPOINTS:
        return False
    return all(
        cp in ASCII_BASE_AND_ACCEPTABLE_WHITESPACE or cp in LATIN_ACCENTED
        for cp in cluster_cps
    )


def _cluster_allowed_visible_plus(cluster_cps: list[int]) -> bool:
    """Check if cluster allowed in visible-plus mode (ASCII + emoji + international scripts)."""
    cluster_set = set(cluster_cps)
    if (
        cluster_set & (PROBLEMATIC_CODEPOINTS - ZERO_WIDTHS)
    ):  # Block security threats: NOBREAK_SPACE, BIDI_OVERRIDES, controls (except allowed whitespace)
        return False
    if (
        cluster_set and cluster_set <= ZERO_WIDTHS
    ):  # Block clusters of only zero-width chars
        return False
    if cluster_set & ZERO_WIDTHS:  # Zero-widths only allowed with emoji
        if not (cluster_set & EMOJI_ALL):
            return False
    return True


def _cluster_allowed_ascii_only(cluster_cps: list[int]) -> bool:
    """Check if cluster allowed in ascii-only mode (strict ASCII)."""
    cluster_set = set(cluster_cps)
    return cluster_set <= ASCII_BASE_AND_ACCEPTABLE_WHITESPACE


def _cluster_allowed(
    cluster_bytes: bytes,
    cluster_text: str,
    allowed_bytes: set[int],
    mode: str,
    restrict_to_allowed_bytes: bool,
    extra_clusters: set[str],
) -> bool:
    """Check if grapheme cluster is allowed based on mode and byte allowances."""

    if cluster_text in extra_clusters:
        return True

    cps = [ord(ch) for ch in cluster_text]
    if mode == MODE_BALANCED:
        allowed_by_mode = _cluster_allowed_balanced(cps)
    elif mode == MODE_VISIBLE_PLUS:
        allowed_by_mode = _cluster_allowed_visible_plus(cps)
    else:
        allowed_by_mode = _cluster_allowed_ascii_only(cps)

    if allowed_by_mode:  # Allow if restrict_to_allowed_bytes is True and all bytes in allowed set (expansion/override)
        return True

    return (
        restrict_to_allowed_bytes
        and cluster_bytes
        and all(b in allowed_bytes for b in cluster_bytes)
    )


def _categorize_offender(cluster: str) -> str:
    """Categorize an offender as 'invisible', 'emoji', or 'other'."""

    if all(ord(c) in INVISIBLE_NAMES for c in cluster):
        return "invisible"
    if any(
        ord(c) in EMOJI_BASE for c in cluster
    ):  # EMOJI_BASE already includes emoticons (0x1F600-0x1FAFF)
        return "emoji"
    return "other"


def _get_problematic_codepoints(cluster: str) -> list[int]:
    """Identify which codepoints in the cluster are actually problematic (not innocent context)."""
    cps = [ord(c) for c in cluster]
    problematic = [cp for cp in cps if cp in PROBLEMATIC_CODEPOINTS]
    return (
        problematic
        if problematic
        else [cp for cp in cps if cp >= NON_ASCII_START] or cps
    )


def _format_offenders(
    offenders: list[tuple[int, int, str]], text: str, fix_mode: bool = False
) -> tuple[str, dict[str, int]]:
    """Format offenders grouped by category and return formatted output with counts."""
    categorized = {"invisible": [], "emoji": [], "other": []}
    for line, col, cluster in offenders:
        categorized[_categorize_offender(cluster)].append((line, col, cluster))

    counts_dict = {k: len(v) for k, v in categorized.items()}
    total = sum(counts_dict.values())

    if fix_mode:
        action = "Removed"
        description = "problematic characters:"
    else:
        action = "Found"
        description = "issues:"
    summary = [f"{action} {total} {description}"]

    if counts_dict["invisible"]:
        summary.append(
            f"• {counts_dict['invisible']} invisible/control characters (security risk)"
        )
    if counts_dict["emoji"]:
        summary.append(f"• {counts_dict['emoji']} emoji (blocked in balanced mode)")
    if counts_dict["other"]:
        summary.append(f"• {counts_dict['other']} other non-ASCII characters")

    lines = ["\n".join(summary), ""]
    for cat, color in [("invisible", RED), ("emoji", CYAN), ("other", BOLD)]:
        for line, col, cluster in categorized[cat]:
            problematic_cps = _get_problematic_codepoints(cluster)
            cp_strs = [f"U+{cp:04X}" for cp in problematic_cps]
            names = [
                INVISIBLE_NAMES.get(cp) or unicodedata.name(chr(cp), "UNKNOWN")
                for cp in problematic_cps
            ]

            safe_cluster = "".join(  # Highlight problematic chars in cluster
                f"<{ord(c):04X}>" if ord(c) in PROBLEMATIC_CODEPOINTS else c
                for c in cluster
            )

            info = f"{color}Line {line}, Col {col}: '{safe_cluster}'"  # Build offender info line
            if len(cluster) > 1 and len(problematic_cps) < len(cluster):
                info += f" - contains problematic: {', '.join(cp_strs)} ({', '.join(names)})"
            else:
                info += f" ({', '.join(cp_strs)}) {', '.join(names)}"
            lines.append(f"{info}{RESET}")
    return "\n".join(lines), counts_dict


def _categorize_files(
    filenames: list[str],
    file_include: list[str],
    file_exclude: list[str],
    ignored_files: set[str],
) -> tuple[list[str], list[str], list[str]]:
    """Categorize files into: to_check, binary, excluded."""

    to_check = []
    binary = []
    excluded = []

    explicit_includes = [p for p in file_include if p and not _is_glob_pattern(p)]

    for filename in filenames:
        if PurePath(filename).name in ALWAYS_EXCLUDED_FILENAMES:
            excluded.append(filename)
            continue

        matched_explicit = explicit_includes and _match_any_pattern(
            filename, explicit_includes
        )
        if matched_explicit:
            pass  # Explicitly included files bypass other filters
        elif file_include:
            if not _match_any_pattern(filename, file_include):
                excluded.append(filename)
                continue

            excluded_by_pattern = file_exclude and _match_any_pattern(
                filename, file_exclude
            )
            if excluded_by_pattern:
                excluded.append(filename)
                continue
        else:
            excluded_by_pattern = file_exclude and _match_any_pattern(
                filename, file_exclude
            )
            if excluded_by_pattern:
                excluded.append(filename)
                continue

        try:  # Read file to check by content
            data = Path(filename).read_bytes()[:BINARY_DETECTION_BUFFER_SIZE]
            if file_is_binary(filename, ignored_files):
                binary.append(filename)
                continue
        except (IOError, OSError):
            excluded.append(filename)
            continue
        to_check.append(filename)
    return to_check, binary, excluded


def _process_grapheme_clusters(
    orig_text: str,
    allowed_clusters: set[str],
    allowed: set[int],
    mode: str,
    restrict_to_includes: bool,
    fix_mode: bool,
    extra_clusters: set[str],
) -> tuple[list[tuple[int, int, str]], list[bytes]]:
    offenders = []
    new_chunks = []
    line = 1
    col = 1
    for cluster in segment_grapheme_clusters(orig_text):
        if cluster in allowed_clusters:
            new_chunks.append(cluster.encode("utf-8"))
            for ch in cluster:
                line, col = (line + 1, 1) if ch == "\n" else (line, col + 1)
            continue
        cluster_line, cluster_col = line, col
        cluster_bytes = cluster.encode("utf-8")
        allowed_cluster = _cluster_allowed(
            cluster_bytes, cluster, allowed, mode, restrict_to_includes, extra_clusters
        )
        if allowed_cluster:
            new_chunks.append(cluster_bytes)
        else:
            offenders.append((cluster_line, cluster_col, cluster))
            if fix_mode and mode == MODE_ASCII_ONLY and len(cluster) == 1:
                cp = ord(cluster)
                if cp in LATIN_ACCENTED:
                    decomp = unicodedata.normalize("NFKD", cluster)
                    ascii_equiv = "".join(c for c in decomp if ord(c) < ASCII_LIMIT)
                    if ascii_equiv:
                        new_chunks.append(ascii_equiv.encode("utf-8"))
                        continue
        for ch in cluster:
            line, col = (line + 1, 1) if ch == "\n" else (line, col + 1)
    return offenders, new_chunks


def _process_bytes(
    data: bytes, allowed: set[int], fix_mode: bool
) -> tuple[list[tuple[int, int, str]], list[bytes]]:
    offenders = []
    new_chunks = []
    line = 1
    col = 1
    for byte_val in data:
        if byte_val in allowed or byte_val in ALLOWED_WHITESPACE:
            new_chunks.append(bytes([byte_val]))
            line, col = (line + 1, 1) if byte_val == 0x0A else (line, col + 1)
        else:
            offenders.append((line, col, f"<{byte_val:02X}>"))
            if not fix_mode:
                new_chunks.append(bytes([byte_val]))
            col += 1
    return offenders, new_chunks


def _process_single_file(
    filename: str,
    allowed: set[int],
    allowed_clusters: set[str],
    mode: str,
    restrict_to_includes: bool,
    fix_mode: bool,
    extra_clusters: set[str],
) -> tuple[list[tuple[int, int, str]], bytes, str | None]:
    """Process a single file and return offenders, fixed data, and original text."""
    data = Path(filename).read_bytes()
    try:
        orig_text = data.decode("utf-8")
        use_grapheme_clusters = True
    except UnicodeDecodeError:
        orig_text = None
        use_grapheme_clusters = False

    if use_grapheme_clusters and orig_text is not None:
        offenders, new_chunks = _process_grapheme_clusters(
            orig_text,
            allowed_clusters,
            allowed,
            mode,
            restrict_to_includes,
            fix_mode,
            extra_clusters,
        )
    else:
        offenders, new_chunks = _process_bytes(data, allowed, fix_mode)

    return offenders, b"".join(new_chunks), orig_text


def _normalize_multi_value_args(arg_list):
    """Normalize and flatten argument values into a single list."""
    if arg_list is None:
        return []
    result = []
    for v in arg_list:
        if isinstance(v, list):
            result.extend(v)
        elif isinstance(v, str) and v.startswith("[") and v.endswith("]"):
            chars = v.strip("[]").replace("'", "").split(",")
            result.extend([c.strip() for c in chars if c.strip()])
        elif isinstance(v, str) and "," in v:
            result.extend([item.strip() for item in v.split(",") if item.strip()])
        else:
            result.append(v)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    ignored_files = get_lfs_and_binary_tracked_files()

    parser = _build_arg_parser()
    try:
        args = parser.parse_args(argv)
        args.file_include = _normalize_multi_value_args(args.file_include)
        args.file_exclude = _normalize_multi_value_args(args.file_exclude)
        args.allow_chars = _normalize_multi_value_args(args.allow_chars)
        args.include_range = _normalize_multi_value_args(args.include_range)

        conflict_error = _detect_conflicting_filters(
            args.file_include, args.file_exclude, list(args.filenames)
        )
        if conflict_error:
            MAX_DISPLAY = 10  # Truncate long error outputs (e.g., file lists)

            match = re.search(
                r"list: (.+)\.", conflict_error
            )  # Find file list in error message
            if match:
                files_str = match.group(1)
                files = [f.strip() for f in files_str.split(",")]
                if len(files) > MAX_DISPLAY:
                    truncated = ", ".join(files[:MAX_DISPLAY]) + ", ..."
                    truncated_error = re.sub(
                        r"list: (.+)\.", lambda m: f"list: {truncated}.", conflict_error
                    )
                    print("\nCONFIGURATION ERROR\n" + truncated_error + "\n")
                else:
                    print("\nCONFIGURATION ERROR\n" + conflict_error + "\n")
            else:
                print("\nCONFIGURATION ERROR\n" + conflict_error + "\n")
            sys.exit(2)
    except SystemExit as e:
        sys.exit(2)

    files_to_check, binary_files, excluded_files = _categorize_files(
        list(args.filenames), args.file_include, args.file_exclude, ignored_files
    )
    allowed, restrict_to_includes, extra_clusters = _build_allowed(args, parser)
    allowed_clusters = set()
    retv = 0
    total_files_checked = 0
    total_files_with_issues = 0
    total_issues = 0

    for filename in files_to_check:
        offenders, new_data, orig_text = _process_single_file(
            filename,
            allowed,
            allowed_clusters,
            args.mode,
            restrict_to_includes,
            args.fix,
            extra_clusters,
        )
        total_files_checked += 1

        if not offenders:
            continue

        total_files_with_issues += 1
        total_issues += len(offenders)

        if args.fix:
            Path(filename).write_bytes(new_data)

        prefix = "Fixed" if args.fix else "Checking"
        formatted_output, counts = _format_offenders(
            offenders,
            orig_text if orig_text else new_data.decode("utf-8", errors="replace"),
            fix_mode=args.fix,
        )
        print(f"\n{'─' * 60}")
        print(f"{prefix}: {filename}")
        print(f"{'─' * 60}")
        print(formatted_output)

        if args.fix:
            print(
                f"⚠️  Review changes and re-stage before committing (git add {filename})"
            )

        retv = 1

    if retv or total_files_checked > 0 and total_files_with_issues == 0:
        status_text = (
            f"{total_files_with_issues} fixed, {total_issues} total problems removed"
            if args.fix
            else f"{total_files_with_issues} with issues, {total_issues} total problems"
        )

    return retv


if __name__ == "__main__":
    raise SystemExit(main())
