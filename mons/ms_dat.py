#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ms*.dat / as*.dat string extractor and re-inserter.
# Part of the Trails From Zero Toolkit. Author: Edrahor.
#
# Each ms*.dat file holds the data for one monster / NPC: stat block,
# control codes, then a few null-terminated SJIS strings (display name
# plus description, sometimes a couple of skill names). The file has no
# pointer table to the strings — the engine knows where they live by
# walking the fixed-format records. So we don't try to fully decode the
# format; we just splice translated strings into the binary and let the
# engine read the rest verbatim.
#
# Approach:
#   - Decompile: scan every null-terminated chunk in the file, decode
#     each as Shift_JIS, keep only the ones that look like real prose
#     (≥3 consecutive ASCII letters or any Cyrillic / kana / kanji).
#     Save those as {original, translation} pairs along with their byte
#     offsets in the file. The full file bytes are stored as hex so the
#     compile step doesn't need the original .dat next to the .json.
#   - Compile: take the saved hex blob, walk the translation entries
#     from the LAST offset to the FIRST, and splice each translation
#     (encoded with halfwidth Cyrillic) into the bytes. Walking
#     backwards keeps earlier offsets stable while the file size
#     changes. Non-translated strings (`translation` empty) keep their
#     original bytes and don't need splicing.
#
# JSON shape (matches the cook/dbmon convention):
#   {
#     "format": "ms_dat",
#     "file_info": {"filename": "...", "original_size": N, "encoding": "shift_jis"},
#     "blob_hex": "...",                  # the whole .dat as hex
#     "translations": [
#       {"offset": 203, "original": "Needle Rat", "translation": ""},
#       {"offset": 214, "original": "A rat monster that...", "translation": ""},
#       ...
#     ]
#   }

import sys
import json
import argparse
import struct
import re
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from byte_codec import (encode_str, decode_str, resolve_mode, add_mode_args,
                        ENCODING_MODES, run_main, is_interactive)

ENCODING = 'shift_jis'
DAT_EXTENSIONS = ('.dat',)
JSON_EXTENSION = '.json'

# A chunk counts as translatable text if it contains a real word. We accept
# either 3+ ASCII letters in a row (English / Geofront-translated content)
# or 2+ Japanese-script codepoints in a row (hiragana, katakana, kanji —
# for stock un-translated files).
ASCII_WORD = re.compile(r'[A-Za-z]{3,}')
JP_WORD = re.compile(r'[぀-ヿ一-鿿]{2,}')


def is_translatable(text: str) -> bool:
    """True if the decoded chunk looks like prose worth showing the
    translator. Filters out:
      - empty strings,
      - short control-code blobs that decode to a couple of letters
        ('I', 'E', '<<') without a real word,
      - stat-block bytes that the halfwidth decoder reads as stray
        Cyrillic letters (we avoid this entirely by decoding candidates
        in passthrough mode, where 0xAF is just halfwidth katakana, not
        Cyrillic Н).
    """
    if not text:
        return False
    return bool(ASCII_WORD.search(text) or JP_WORD.search(text))


def find_strings(data: bytes):
    """Yield (offset, decoded_text, raw_length_bytes) for every translatable
    null-terminated SJIS chunk in `data`.

    We pre-filter candidates by decoding in PASSTHROUGH mode (no halfwidth
    Cyrillic remap) — that way binary stat values like 0xAF don't slip
    through as fake Cyrillic words. Real translatable text is either
    plain ASCII (decodes the same in both modes) or 2-byte SJIS Japanese
    (also unaffected by halfwidth), so passthrough is the correct lens
    for spotting genuine strings.
    """
    i = 0
    while i < len(data):
        if data[i] == 0:
            i += 1
            continue
        j = data.find(b'\x00', i)
        if j < 0:
            j = len(data)
        chunk = data[i:j]
        try:
            probe = decode_str(bytes(chunk), ENCODING, 'passthrough')
        except Exception:
            probe = ''
        if is_translatable(probe):
            # Re-decode the kept chunk in halfwidth mode so any already-
            # translated Cyrillic letters round-trip back to readable text.
            text = decode_str(bytes(chunk), ENCODING, 'halfwidth')
            yield i, text, len(chunk)
        i = j + 1


def decompile_dat(dat_path: Path, json_path: Path, test_compilation: bool = False,
                  mode: str = 'halfwidth'):
    print(f"=== DECOMPILING {dat_path} ===")
    print(f"Encoding mode: {mode}")

    original_data = dat_path.read_bytes()
    print(f"File size: {len(original_data)} bytes")

    translations = []
    for off, text, raw_len in find_strings(original_data):
        translations.append({
            "offset": off,
            "original": text,
            "translation": "",
        })

    print(f"  Translatable strings: {len(translations)}")
    for t in translations:
        preview = t['original'].replace('\n', ' / ')
        print(f"    @0x{t['offset']:04X}: {preview[:60]!r}")

    result = {
        "format": "ms_dat",
        "file_info": {
            "filename": dat_path.name,
            "original_size": len(original_data),
            "encoding": ENCODING,
        },
        "blob_hex": original_data.hex(),
        "translations": translations,
    }

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nDecompiled to {json_path}")
    print("Translate by filling 'translation' fields. Empty 'translation' falls back to 'original'.")
    if mode == 'halfwidth':
        print("Letters will be encoded as single SJIS halfwidth bytes on compile.")
    else:
        print("Letters will be encoded as standard 2-byte SJIS on compile (no halfwidth remap).")

    if test_compilation:
        test_compilation_process(dat_path, json_path, original_data, mode)


def compile_dat(json_path: Path, dat_path: Path, cli_mode=None, interactive=False):
    print(f"=== COMPILING {json_path} ===")

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    info = data['file_info']
    encoding = info.get('encoding', ENCODING)
    blob = bytearray.fromhex(data['blob_hex'])
    if len(blob) != info['original_size']:
        raise ValueError(
            f"blob_hex length ({len(blob)}) doesn't match file_info.original_size "
            f"({info['original_size']}); JSON is corrupt."
        )
    translations = data['translations']
    mode = resolve_mode(cli_mode, interactive=interactive)
    print(f"Encoding mode: {mode}")
    print(f"Original size: {len(blob)} bytes")
    print(f"Translation entries: {len(translations)}")

    # Sort by offset descending — later strings are spliced first, which
    # keeps earlier offsets valid as the buffer grows or shrinks.
    entries = sorted(translations, key=lambda e: e['offset'], reverse=True)

    active = 0
    for entry in entries:
        original = entry.get('original', '')
        translation = entry.get('translation', '')
        if not translation:
            continue
        active += 1

        offset = entry['offset']
        # Verify the original text is at the recorded offset before splicing.
        # Compare on bytes (after re-encoding the original with halfwidth mode)
        # because that's what's actually in `blob` after a previous compile,
        # AND on plain SJIS because that's what's there on the very first
        # compile from a freshly-decompiled .dat.
        original_bytes_halfwidth = encode_str(original, encoding, mode='halfwidth')
        original_bytes_passthrough = encode_str(original, encoding, mode='passthrough')
        end_at_offset = blob.find(b'\x00', offset)
        if end_at_offset < 0:
            raise ValueError(f"No NUL terminator after offset 0x{offset:04X}.")
        existing = bytes(blob[offset:end_at_offset])
        if existing not in (original_bytes_halfwidth, original_bytes_passthrough):
            raise ValueError(
                f"Bytes at 0x{offset:04X} don't match the recorded original "
                f"{original!r} in either halfwidth or passthrough form. "
                f"Found: {existing!r}. JSON is out of sync with blob_hex."
            )

        new_bytes = encode_str(translation, encoding, mode)
        # Splice: replace [offset..end_at_offset) with new_bytes.
        blob[offset:end_at_offset] = new_bytes

    print(f"Translated: {active} of {len(translations)} entries")

    dat_path.write_bytes(bytes(blob))
    print(f"\nCompiled to {dat_path}")
    print(f"New size: {len(blob)} bytes")
    print(f"Size difference: {len(blob) - info['original_size']:+d} bytes")


def test_compilation_process(dat_path, json_path, original_data, mode='halfwidth'):
    print("\n=== COMPILATION TEST ===")
    test_dat_path = dat_path.parent / f"{dat_path.stem}_test{dat_path.suffix}"

    try:
        compile_dat(json_path, test_dat_path, cli_mode=mode)

        with open(test_dat_path, 'rb') as f:
            compiled = f.read()

        if compiled == original_data:
            print("TEST PASSED: byte-identical round-trip!")
            test_dat_path.unlink()
        else:
            print("TEST FAILED:")
            print(f"  Original: {len(original_data)} bytes")
            print(f"  Compiled: {len(compiled)} bytes")
            print(f"  Diff: {len(compiled) - len(original_data):+d}")
            for i in range(min(len(original_data), len(compiled))):
                if original_data[i] != compiled[i]:
                    ctx = 16
                    a = original_data[max(0, i-ctx):i+ctx].hex()
                    b = compiled[max(0, i-ctx):i+ctx].hex()
                    print(f"  First diff at 0x{i:04X}: orig={original_data[i]:02x} -> new={compiled[i]:02x}")
                    print(f"  orig: {a}")
                    print(f"  new : {b}")
                    break
            print(f"  Test file kept at: {test_dat_path}")
    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        traceback.print_exc()


def determine_file_type(input_path: Path):
    if input_path.suffix.lower() == JSON_EXTENSION:
        return 'json'
    if input_path.suffix.lower() in DAT_EXTENSIONS:
        return 'dat'
    return 'unknown'


def main():
    parser = argparse.ArgumentParser(description="ms*.dat / as*.dat string extractor and re-inserter")
    parser.add_argument("input_file", help="Input file (.dat or .json)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--test", action="store_true", help="Round-trip test after decompiling")
    add_mode_args(parser)

    args = parser.parse_args()
    input_path = Path(args.input_file)

    if not input_path.exists():
        print(f"File not found: {input_path}")
        sys.exit(1)

    ftype = determine_file_type(input_path)

    if ftype == 'json':
        out = Path(args.output) if args.output else input_path.with_suffix('.dat')
        compile_dat(input_path, out, cli_mode=args.mode, interactive=is_interactive())
    elif ftype == 'dat':
        out = Path(args.output) if args.output else input_path.with_suffix(JSON_EXTENSION)
        if args.mode is not None:
            print("Note: encoding mode is ignored on decompile "
                  "(the decoder reads halfwidth and 2-byte SJIS transparently).")
        decompile_dat(input_path, out, test_compilation=args.test, mode='halfwidth')
    else:
        print(f"Unsupported file: {input_path}")
        sys.exit(1)


if __name__ == "__main__":
    run_main(main)
