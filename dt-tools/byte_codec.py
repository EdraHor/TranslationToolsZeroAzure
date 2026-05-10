"""
Single-byte text codec for Trails from Zero _dt files.

Part of the Trails From Zero Toolkit. Author: Edrahor.

Source of truth for the alphabet substitution is `../font/config_font.ini`
(the same file glyph.py reads to draw the font). This module parses its
[Replacements] section at import time, so editing one file changes both
the rendered glyphs and the byte encoding together. There is no built-in
fallback: if the ini is missing or unreadable, importing this module fails
with a clear error.

The codec maps each letter of your alphabet to one SJIS byte that the
patched font.itf draws as the right glyph. Bundled defaults are configured
for Russian (33 uppercase + 30 lowercase letters fit in the SJIS halfwidth-
katakana block 0xA1..0xDF; the three overflow letters э/ю/я land in the
rare ASCII slots 0x60/0x5E/0x5F = ` ^ _). 0x7B/0x7D ({ }) are reserved
CLM block delimiters and must NOT be used.

Why this matters: the game measures string width in *bytes* for UI layout
(shop panels, map labels, centering). With this encoding each letter
occupies one byte, matching English / Japanese-halfwidth behavior — which
fixes both file-size limits (e.g. 64 KB on t_ittxt._dt) and visual layout
bugs.

Public API:
    encode_text(text)              -> bytes
    decode_text(data)              -> str
    encode_text_safe(text)         -> bytes  (plain SJIS, no halfwidth remap)
    encode_str(text, mode=...)     -> bytes  (mode-aware: 'halfwidth' | 'passthrough')
    decode_str(data, mode=...)     -> str
    remap_letters_to_clm(text)     -> str    (letters -> halfwidth/ASCII chars
                                              so calmare encodes them as 1 byte)
    unmap_clm_to_letters(text)     -> str    (inverse)
    add_mode_args(parser)          (argparse helper)
    resolve_mode(cli, interactive) (mode picker for compile)
    run_main(main_fn)              (drag-and-drop wrapper)
"""
from __future__ import annotations

import configparser
from pathlib import Path

ENCODING = 'shift_jis'

# ----- Substitution table loader --------------------------------------------
# config_font.ini lives in the sibling font/ directory.
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / 'font' / 'config_font.ini'


def load_table_from_ini(ini_path: Path,
                        encoding: str = ENCODING) -> dict[str, int]:
    """Read the [Replacements] section of a config_font.ini-style file and
    turn it into a {letter: byte} mapping suitable for the codec.

    Each `source = replacement` pair is interpreted the same way glyph.py
    interprets it: only the first character of each side is used. The
    `source` character must be encodable in SJIS as a single byte (which is
    true for halfwidth-katakana U+FF61..U+FF9F and for plain ASCII). Pairs
    that don't satisfy this are skipped silently.

    Raises FileNotFoundError / ValueError if the file is missing, malformed,
    or yields an empty table.
    """
    if not ini_path.exists():
        raise FileNotFoundError(
            f"Substitution table not found: {ini_path}. "
            f"This codec requires font/config_font.ini to exist next to the "
            f"toolkit's font/ folder."
        )

    cp = configparser.ConfigParser()
    cp.optionxform = str  # preserve key case (default lowercases everything)
    try:
        cp.read(ini_path, encoding='utf-8')
    except (configparser.Error, OSError) as e:
        raise ValueError(f"Cannot parse {ini_path}: {e}") from e

    if 'Replacements' not in cp:
        raise ValueError(
            f"{ini_path} has no [Replacements] section — "
            f"the codec needs at least one source = replacement pair."
        )

    table: dict[str, int] = {}
    for source_str, replacement_str in cp['Replacements'].items():
        if not source_str or not replacement_str:
            continue
        source_char = next(iter(source_str))
        replacement_char = next(iter(replacement_str))
        try:
            src_bytes = source_char.encode(encoding)
        except UnicodeEncodeError:
            continue
        if len(src_bytes) != 1:
            continue
        table[replacement_char] = src_bytes[0]

    if not table:
        raise ValueError(
            f"[Replacements] in {ini_path} produced no usable entries. "
            f"Source characters must encode to a single SJIS byte."
        )

    return table


# Build the active table once at import time. No fallback: if the ini is
# missing, importing this module fails with a readable error rather than
# silently using a Russian default.
LETTER_TO_BYTE: dict[str, int] = load_table_from_ini(DEFAULT_CONFIG_PATH)
BYTE_TO_LETTER: dict[int, str] = {v: k for k, v in LETTER_TO_BYTE.items()}
assert len(BYTE_TO_LETTER) == len(LETTER_TO_BYTE), \
    "mapping collision: two letters share the same byte"


# ----- Letter <-> CLM character (Unicode for calmare to encode) -------------
# When a CLM file is read by calmare, calmare encodes Unicode chars to SJIS.
# So instead of writing letters in CLM (which calmare encodes as 2-byte
# SJIS), we substitute them with the Unicode chars whose SJIS form happens
# to be the same single byte we want.
#
#   SJIS 0xA1..0xDF  <->  Unicode U+FF61..U+FF9F (Halfwidth Katakana / Punct)
#   SJIS 0x60 / 0x7B / 0x7D <-> Unicode 0x60 / 0x7B / 0x7D (ASCII pass-through)
def _byte_to_clm_unicode(byte: int) -> str:
    if 0xA1 <= byte <= 0xDF:
        return chr(0xFF61 + (byte - 0xA1))
    return chr(byte)  # ASCII passthrough for 0x60, 0x7B, 0x7D


LETTER_TO_CLM: dict[str, str] = {
    letter: _byte_to_clm_unicode(b) for letter, b in LETTER_TO_BYTE.items()
}
CLM_TO_LETTER: dict[str, str] = {v: k for k, v in LETTER_TO_CLM.items()}
assert len(CLM_TO_LETTER) == len(LETTER_TO_CLM), "remap collision in LETTER_TO_CLM"


def remap_letters_to_clm(text: str) -> str:
    """Replace every alphabet letter with its CLM-side equivalent (a
    halfwidth-katakana char or rare ASCII char). Other text is untouched."""
    if not text:
        return text
    return ''.join(LETTER_TO_CLM.get(c, c) for c in text)


def unmap_clm_to_letters(text: str) -> str:
    """Inverse of remap_letters_to_clm — turn halfwidth/ASCII single-byte
    placeholders back into normal alphabet letters. Non-mapped chars
    untouched.

    Use with care: this assumes the source CLM was produced by our pipeline.
    Plain Japanese CLMs may contain genuine halfwidth katakana that this
    function would falsely turn into alphabet letters."""
    if not text:
        return text
    return ''.join(CLM_TO_LETTER.get(c, c) for c in text)


# ----- Binary _dt flow ------------------------------------------------------
def encode_text(text: str, encoding: str = ENCODING, errors: str = 'replace') -> bytes:
    """Encode `text` to bytes. Letters from LETTER_TO_BYTE become single-byte
    codes; everything else goes through the standard SJIS encoder.

    Use this for fields rendered directly by the patched font.itf — single-
    byte halfwidth/ASCII codes are decoded one-byte-per-glyph and produce
    the correct letter."""
    out = bytearray()
    for ch in text:
        b = LETTER_TO_BYTE.get(ch)
        if b is not None:
            out.append(b)
        else:
            try:
                out.extend(ch.encode(encoding))
            except UnicodeEncodeError:
                out.append(ord('?'))
    return bytes(out)


def encode_text_safe(text: str, encoding: str = ENCODING) -> bytes:
    """Standard 2-byte SJIS encode — letters do NOT get single-byte
    substitution. Use this when you specifically need plain cp932 output."""
    return text.encode(encoding, errors='replace')


def decode_text(data: bytes, encoding: str = ENCODING, errors: str = 'replace') -> str:
    """Decode `data` to text. Single bytes that match BYTE_TO_LETTER become
    alphabet letters; remaining bytes are decoded as standard SJIS (handling
    2-byte lead bytes correctly)."""
    out: list[str] = []
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        # Letter single-byte first
        letter = BYTE_TO_LETTER.get(b)
        if letter is not None:
            out.append(letter)
            i += 1
            continue
        # SJIS lead byte? (0x81-0x9F or 0xE0-0xFC)
        if (0x81 <= b <= 0x9F) or (0xE0 <= b <= 0xFC):
            if i + 1 < n:
                chunk = bytes(data[i:i+2])
                try:
                    out.append(chunk.decode(encoding))
                except UnicodeDecodeError:
                    out.append('?')
                i += 2
                continue
        # Single byte fallback
        try:
            out.append(bytes([b]).decode(encoding, errors=errors))
        except UnicodeDecodeError:
            out.append('?')
        i += 1
    return ''.join(out)


# ----- Mode-aware helpers shared by all dt_*.py compilers -------------------
# Two encoding modes:
#   "halfwidth"  : encode_text / decode_text (1-byte letters via LETTER_TO_BYTE)
#   "passthrough": plain text.encode(encoding) / data.decode(encoding)
#                  (letters become 2-byte SJIS, works with stock font)
ENCODING_MODES = ('halfwidth', 'passthrough')


def encode_str(text: str, encoding: str = ENCODING, mode: str = 'halfwidth') -> bytes:
    """Encode a string respecting the chosen mode."""
    if mode == 'passthrough':
        return text.encode(encoding, errors='replace')
    return encode_text(text, encoding=encoding)


def decode_str(data: bytes, encoding: str = ENCODING, mode: str = 'halfwidth') -> str:
    """Decode bytes respecting the chosen mode."""
    if mode == 'passthrough':
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            return data.decode(encoding, errors='replace')
    return decode_text(data, encoding=encoding)


def resolve_mode(cli_mode, interactive=False, default='halfwidth'):
    """Pick the effective encoding mode for **compile**.

    Priority: CLI flag > interactive prompt > error.

    The mode is never read from JSON — it must be specified explicitly on
    every compile run, either via the CLI flag (`--halfwidth` /
    `--passthrough`) or interactively (when the script was launched by drag-
    and-drop with no CLI args).

    If neither is available (e.g. running from a batch script without a
    flag), this raises ValueError with a clear message instead of silently
    picking a default — explicit is better than guessed when the wrong mode
    can ship a broken build.
    """
    if cli_mode is not None:
        return cli_mode
    if interactive:
        return prompt_compile_mode(default)
    raise ValueError(
        "No encoding mode specified. Pass --halfwidth or --passthrough on the "
        "command line, or run the script without arguments to be prompted."
    )


def add_mode_args(parser):
    """Add mutually-exclusive --halfwidth / --passthrough flags to a parser."""
    enc = parser.add_mutually_exclusive_group()
    enc.add_argument("--halfwidth", dest="mode", action="store_const", const="halfwidth",
                     help="Use 1-byte halfwidth letters (needs patched font.itf and zero.exe).")
    enc.add_argument("--passthrough", dest="mode", action="store_const", const="passthrough",
                     help="Use plain cp932 SJIS (letters as 2-byte pairs, stock font).")
    parser.set_defaults(mode=None)


# ----- Interactive helpers (drag-and-drop friendly) -------------------------
# Set by run_main(): True when our process owns its console — i.e. the
# console window will close when we exit. True for .py double-click and
# Windows drag-and-drop onto a .py; False inside an existing cmd.exe / shell
# (where the console persists after we return).
_OWNS_CONSOLE = False


def is_interactive() -> bool:
    """True when stdin is a terminal — i.e. we *can* ask the user a question.

    True both for drag-and-drop / double-click AND for running from cmd.exe
    or a shell. dt_*.py scripts pass this to resolve_mode() so the compile-
    mode prompt fires whenever there's a real human to answer it. For the
    narrower "window will close when we exit" check (used by wait_on_exit)
    see _OWNS_CONSOLE / _detect_owned_console below.
    """
    import sys
    try:
        return sys.stdin.isatty()
    except Exception:
        return False


def _detect_owned_console() -> bool:
    """Windows: True when only our process is attached to the console.

    `GetConsoleProcessList` returns the count of processes sharing this
    console. Drag-and-drop onto a .py and .py double-click both spawn a
    fresh console with just python in it (count == 1) — that window
    vanishes the moment we exit, so wait_on_exit must pause. Running under
    cmd.exe gives count >= 2 (cmd + python) and the shell keeps the window
    alive after we return, so pausing would only stall batch loops.
    """
    import sys
    if sys.platform != 'win32':
        return False
    try:
        import ctypes
        buf = (ctypes.c_uint32 * 4)()
        count = ctypes.windll.kernel32.GetConsoleProcessList(buf, 4)
        return count <= 1
    except Exception:
        return False


def prompt_input_path(prompt: str = "Drop a file onto this window or paste a path: ") -> str:
    """Ask the user for an input path. Strips wrapping quotes that Windows
    sometimes adds to drag-and-drop paths."""
    raw = input(prompt).strip()
    # Windows drag-and-drop wraps paths with spaces in double quotes.
    if len(raw) >= 2 and raw[0] in ('"', "'") and raw[-1] == raw[0]:
        raw = raw[1:-1]
    return raw


def prompt_compile_mode(default: str = 'halfwidth') -> str:
    """Ask the user which encoding mode to compile in."""
    print()
    print("Which encoding mode should be used for compilation?")
    print("  1) halfwidth   - 1 byte per letter; needs patched font.itf")
    print("                   and zero.exe (recommended).")
    print("  2) passthrough - standard 2-byte SJIS; works with stock files.")
    print()
    default_choice = '1' if default == 'halfwidth' else '2'
    while True:
        ans = input(f"Enter 1 or 2 [default: {default_choice}]: ").strip().lower()
        if not ans:
            return default
        if ans in ('1', 'h', 'halfwidth'):
            return 'halfwidth'
        if ans in ('2', 'p', 'passthrough'):
            return 'passthrough'
        print(f"  Unknown answer '{ans}'. Type 1 or 2.")


def wait_on_exit(label: str = "Done.") -> None:
    """Pause so the user can read output before the window closes.

    Only pauses when our process owns the console (drag-and-drop or .py
    double-click) — those windows vanish the moment python exits, so the
    user needs a moment to read the output. Inside cmd.exe / a shell the
    console persists, and pausing would only stall bulk batch runs, so we
    return immediately.
    """
    import sys
    if not _OWNS_CONSOLE:
        return
    try:
        if sys.stdin.isatty():
            input(f"\n{label} Press Enter to exit...")
    except (EOFError, KeyboardInterrupt):
        pass


def run_main(main_fn) -> None:
    """Wrapper around a script's main() that:

      - detects whether we own our console (drag-and-drop / .py double-click)
        so wait_on_exit can pause before the window vanishes;
      - if no input path was passed AND stdin is a TTY, prompts the user
        and injects the answer into sys.argv (argparse stays unchanged);
      - keeps the console open on error or on interactive completion, so
        drag-and-drop users can read the output before it disappears.
    """
    import sys
    import traceback

    global _OWNS_CONSOLE
    _OWNS_CONSOLE = _detect_owned_console()

    if len(sys.argv) == 1 and is_interactive():
        path = prompt_input_path()
        if not path:
            print("No path entered.")
            wait_on_exit("Cancelled.")
            return
        sys.argv.append(path)

    try:
        main_fn()
    except SystemExit as e:
        # argparse exits this way for --help / bad args; honor the exit code.
        if e.code:
            wait_on_exit("Failed.")
        raise
    except KeyboardInterrupt:
        print("\nCancelled.")
    except (ValueError, FileNotFoundError) as e:
        # User-facing errors with already-clear messages -- no traceback noise.
        print(f"\nERROR: {e}")
        wait_on_exit("Failed.")
        sys.exit(1)
    except Exception as e:
        # Unexpected error -- show the full traceback so it can be reported.
        print(f"\nERROR: {e}")
        traceback.print_exc()
        wait_on_exit("Failed.")
        sys.exit(1)
    else:
        wait_on_exit("Done.")


def selftest() -> None:
    """Round-trip tests for both binary (_dt) and textual (CLM) flows.

    Uses Russian sample strings because the bundled config_font.ini ships
    with the Russian alphabet. Swap config_font.ini for another alphabet
    and update the samples accordingly to retest."""
    samples = [
        "Hello",
        "AaЯя1234ёЁ",
        "ABC123",
    ]
    print("--- binary _dt flow (encode_text / decode_text) ---")
    for s in samples:
        enc = encode_text(s)
        dec = decode_text(enc)
        sjis = s.encode(ENCODING, errors='replace')
        ok = (dec == s)
        print(f"  ok={ok}  '{s}' -> {len(enc)}b (vs {len(sjis)}b SJIS)  ->  '{dec}'")


if __name__ == '__main__':
    selftest()
