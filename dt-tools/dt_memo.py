#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# t_memo._dt decompiler / compiler (memo / detective book entries).
# Part of the Trails From Zero Toolkit. Author: Edrahor.

import sys
import json
from pathlib import Path
import argparse
import struct

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).resolve().parent))
from byte_codec import (encode_str, decode_str, resolve_mode, add_mode_args,
                        ENCODING_MODES, run_main, is_interactive)

# t_memo._dt format
# ─────────────────
# Header: u16 array of N absolute offsets, where N = (first_u16) / 2.
#         The very first u16 of the file IS both the table size in bytes AND
#         the offset of the first string (strings start right after the table).
#
# Strings section (all strings concatenated, in physical order):
#         <string_0>\0<string_1>\0...<string_{N-1}>\0
#
# Two encoding modes (CLI flag --halfwidth / --passthrough):
#   "halfwidth"   : letters go through byte_codec.encode_text. Each letter
#                   becomes ONE byte in the SJIS halfwidth zone
#                   (0xA1..0xDF) or a rare ASCII slot. The patched font.itf
#                   maps those byte codes to your alphabet's glyphs.
#                   Single-byte width fixes the 64 KB file size limit and
#                   the layout / centering bugs.
#   "passthrough" : straight cp932/SJIS encode. Letters become 2-byte SJIS
#                   pairs. Larger file but works with the stock font.

ENCODING = 'cp932'
DT_EXTENSION = '._dt'
JSON_EXTENSION = '.json'


def decompile_memo(dt_path, json_path, test_compilation=False, mode='halfwidth'):
    print(f"=== DECOMPILING {dt_path} ===")
    print(f"Encoding mode: {mode}")

    with open(dt_path, 'rb') as f:
        original_data = f.read()

    print(f"File size: {len(original_data)} bytes")

    header_size = struct.unpack('<H', original_data[0:2])[0]
    slot_count = header_size // 2
    print(f"Header size: 0x{header_size:04X} ({header_size} bytes)")
    print(f"Slot count: {slot_count}")

    offsets = list(struct.unpack(f'<{slot_count}H', original_data[:header_size]))

    # Sanity check: offsets must be strictly contiguous null-terminated strings.
    strings = []
    for i, off in enumerate(offsets):
        end = original_data.find(b'\x00', off)
        if end == -1:
            end = len(original_data)
        raw = bytes(original_data[off:end])
        text = decode_str(raw, ENCODING, mode)
        strings.append(text)

        next_expected = end + 1
        if i + 1 < slot_count:
            if offsets[i + 1] != next_expected:
                print(f"  WARN: slot {i} is not contiguous with slot {i+1} "
                      f"(end+1={next_expected}, next_offset={offsets[i+1]})")
        else:
            if next_expected != len(original_data):
                print(f"  WARN: last string end+1={next_expected}, file size={len(original_data)}")

    non_empty = sum(1 for s in strings if s)
    empty = slot_count - non_empty
    print(f"Strings: {non_empty} non-empty, {empty} empty (placeholders)")

    result = {
        "file_info": {
            "original_size": len(original_data),
            "encoding": ENCODING,
            "header_size": header_size,
            "slot_count": slot_count,
        },
        "strings": strings,
    }

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nDecompiled to {json_path}")
    print(f"Edit the 'strings' array to translate. Keep empty strings ('') as-is — they are layout placeholders.")
    if mode == 'halfwidth':
        print(f"Letters will be encoded as single SJIS halfwidth bytes on compile.")
    else:
        print(f"Letters will be encoded as standard 2-byte SJIS on compile (no halfwidth remap).")

    if test_compilation:
        test_compilation_process(dt_path, json_path, original_data, mode)


def compile_memo(json_path, dt_path, cli_mode=None, interactive=False):
    print(f"=== COMPILING {json_path} ===")

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    info = data['file_info']
    encoding = info.get('encoding', ENCODING)
    header_size = info['header_size']
    slot_count = info['slot_count']
    strings = data['strings']
    mode = resolve_mode(cli_mode, interactive=interactive)
    print(f"Encoding mode: {mode}")

    if len(strings) != slot_count:
        raise ValueError(f"strings length {len(strings)} != slot_count {slot_count}")

    print(f"Original size: {info['original_size']} bytes")
    print(f"Strings: {slot_count}")

    strings_blob = bytearray()
    new_offsets = []
    cursor = header_size
    for i, s in enumerate(strings):
        new_offsets.append(cursor)
        encoded = encode_str(s, encoding, mode) + b'\x00'
        strings_blob.extend(encoded)
        cursor += len(encoded)

    # Build the offset table.
    table = bytearray()
    for off in new_offsets:
        if off > 0xFFFF:
            raise ValueError(f"Offset 0x{off:X} doesn't fit in u16. File too large.")
        table.extend(struct.pack('<H', off))

    while len(table) < header_size:
        table.append(0)

    result = bytearray()
    result.extend(table)
    result.extend(strings_blob)

    with open(dt_path, 'wb') as f:
        f.write(result)

    print(f"\nCompiled to {dt_path}")
    print(f"New size: {len(result)} bytes")
    print(f"Size difference: {len(result) - info['original_size']:+d} bytes")


def test_compilation_process(dt_path, json_path, original_data, mode='halfwidth'):
    print("\n=== COMPILATION TEST ===")
    test_dt_path = dt_path.parent / f"{dt_path.stem}_test{dt_path.suffix}"

    try:
        compile_memo(json_path, test_dt_path, cli_mode=mode)

        with open(test_dt_path, 'rb') as f:
            compiled = f.read()

        if compiled == original_data:
            print("TEST PASSED: byte-identical round-trip!")
            test_dt_path.unlink()
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
            print(f"  Test file kept at: {test_dt_path}")
    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        traceback.print_exc()


def determine_file_type(input_path):
    if input_path.suffix.lower() == JSON_EXTENSION:
        return 'json'
    elif input_path.name.endswith(DT_EXTENSION):
        return 'dt'
    return 'unknown'


def main():
    parser = argparse.ArgumentParser(description="t_memo._dt decompiler/compiler")
    parser.add_argument("input_file", help="Input file (._dt or .json)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--test", action="store_true", help="Test round-trip after decompiling")
    add_mode_args(parser)

    args = parser.parse_args()
    input_path = Path(args.input_file)

    if not input_path.exists():
        print(f"File not found: {input_path}")
        sys.exit(1)

    ftype = determine_file_type(input_path)

    if ftype == 'json':
        out = Path(args.output) if args.output else input_path.with_suffix(DT_EXTENSION)
        compile_memo(input_path, out, cli_mode=args.mode, interactive=is_interactive())
    elif ftype == 'dt':
        out = Path(args.output) if args.output else input_path.with_suffix(JSON_EXTENSION)
        if args.mode is not None:
            print("Note: encoding mode is ignored on decompile "
                  "(the decoder reads halfwidth and 2-byte SJIS transparently).")
        decompile_memo(input_path, out, test_compilation=args.test, mode='halfwidth')
    else:
        print(f"Unsupported file: {input_path}")
        sys.exit(1)


if __name__ == "__main__":
    run_main(main)
