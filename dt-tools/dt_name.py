#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# t_name._dt decompiler / compiler (character name table).
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

# t_name._dt format
# ─────────────────
# Records section: a sequence of 20-byte records, all packed back-to-back
# starting at offset 0. Each record is 10 little-endian u16 fields:
#     [0]      id
#     [1]      name_offset (absolute, into the strings section)
#     [2..9]   eight opaque u16 fields (preserved verbatim, not interpreted)
#
# The records section ends where the strings section begins; we discover the
# boundary by scanning records and taking the minimum non-zero name_offset
# (= the lowest absolute offset any record points into).
#
# Strings section: null-terminated strings, one per record, written in the
# same physical order as the records. No deduplication.
#
# Two encoding modes (CLI flag --halfwidth / --passthrough):
#   "halfwidth"   : letters become 1-byte halfwidth codes via byte_codec
#                   (needs patched zero.exe + font.itf). Saves ~50% space.
#   "passthrough" : letters become standard 2-byte SJIS pairs (stock font).

ENCODING = 'shift_jis'
DT_EXTENSION = '._dt'
JSON_EXTENSION = '.json'
RECORD_SIZE = 20
STRINGS_OFFSET = 0x2E4  # Fallback strings section start if scan fails


def read_character_record(data, offset):
    """Read a single 20-byte character record (10 u16 fields)."""
    if offset + RECORD_SIZE > len(data):
        return None

    record_data = data[offset:offset + RECORD_SIZE]
    fields = struct.unpack('<10H', record_data)

    return {
        'id': fields[0],
        'name_offset': fields[1],
        'field1': fields[2],
        'field2': fields[3],
        'field3': fields[4],
        'field4': fields[5],
        'field5': fields[6],
        'field6': fields[7],
        'field7': fields[8],
        'field8': fields[9],
    }


def extract_string_at_offset(data, offset, mode='halfwidth'):
    if offset >= len(data):
        return ""
    null_pos = data.find(b'\x00', offset)
    if null_pos == -1:
        null_pos = len(data)
    return decode_str(bytes(data[offset:null_pos]), ENCODING, mode)


def find_strings_section_start(data):
    """Locate the records/strings boundary by taking the minimum non-zero
    name_offset across the records. Caps the records scan at 0x1000 bytes
    to avoid runaway reads on a corrupted file."""
    min_offset = len(data)
    offset = 0
    while offset < len(data) - RECORD_SIZE:
        record = read_character_record(data, offset)
        if record is None:
            break
        if 0 < record['name_offset'] < min_offset:
            min_offset = record['name_offset']
        offset += RECORD_SIZE
        if offset > 0x1000:
            break
    return min_offset if min_offset < len(data) else STRINGS_OFFSET


def decompile_characters(dt_path, json_path, test_compilation=False, mode='halfwidth'):
    print(f"=== DECOMPILING {dt_path} ===")
    print(f"Encoding mode: {mode}")

    with open(dt_path, 'rb') as f:
        original_data = f.read()

    print(f"File size: {len(original_data)} bytes")

    strings_start = find_strings_section_start(original_data)
    print(f"Strings section starts at: 0x{strings_start:04X} ({strings_start})")

    characters_data = []
    offset = 0
    while offset < strings_start:
        record = read_character_record(original_data, offset)
        if record is None:
            break

        name = extract_string_at_offset(original_data, record['name_offset'], mode)
        characters_data.append({
            'id': record['id'],
            'name': name,
            'fields': [record['field1'], record['field2'], record['field3'], record['field4'],
                       record['field5'], record['field6'], record['field7'], record['field8']],
        })
        offset += RECORD_SIZE

    print(f"Found {len(characters_data)} character records")
    non_empty_names = sum(1 for c in characters_data if c['name'].strip())
    print(f"Characters with names: {non_empty_names}")

    result = {
        "file_info": {
            "original_size": len(original_data),
            "encoding": ENCODING,
            "record_size": RECORD_SIZE,
            "strings_section_start": strings_start,
        },
        "characters": characters_data,
    }

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nDecompiled to {json_path}")
    print(f"Edit 'name' fields in 'characters' array for translation.")
    print(f"Numeric 'fields' are preserved automatically.")
    if mode == 'halfwidth':
        print(f"Letters will be encoded as single SJIS halfwidth bytes on compile.")
    else:
        print(f"Letters will be encoded as standard 2-byte SJIS on compile (no halfwidth remap).")

    if test_compilation:
        test_compilation_process(dt_path, json_path, original_data, mode)


def compile_characters(json_path, dt_path, cli_mode=None, interactive=False):
    print(f"=== COMPILING {json_path} ===")

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    info = data['file_info']
    encoding = info.get('encoding', ENCODING)
    characters = data['characters']
    mode = resolve_mode(cli_mode, interactive=interactive)
    print(f"Encoding mode: {mode}")
    print(f"Original size: {info['original_size']} bytes")
    print(f"Characters to compile: {len(characters)}")

    # Lay out strings right after the records; record their absolute offsets
    # so the records can point at them.
    records_size = len(characters) * RECORD_SIZE
    strings_data = bytearray()
    name_offsets = []
    for character in characters:
        name_offsets.append(records_size + len(strings_data))
        strings_data.extend(encode_str(character['name'], encoding, mode) + b'\x00')

    print(f"Records section: {records_size} bytes")
    print(f"Strings section: {len(strings_data)} bytes")
    print(f"Total size: {records_size + len(strings_data)} bytes")

    # Pack records with the freshly computed name offsets.
    result_data = bytearray()
    for i, character in enumerate(characters):
        fields = list(character.get('fields', []))
        while len(fields) < 8:
            fields.append(0)
        record_fields = [character['id'], name_offsets[i]] + fields[:8]
        result_data.extend(struct.pack('<10H', *record_fields))

    result_data.extend(strings_data)

    with open(dt_path, 'wb') as f:
        f.write(result_data)

    print(f"\nCompiled to {dt_path}")
    print(f"New size: {len(result_data)} bytes")
    print(f"Size difference: {len(result_data) - info['original_size']:+d} bytes")


def test_compilation_process(dt_path, json_path, original_data, mode='halfwidth'):
    print("\n=== COMPILATION TEST ===")
    test_dt_path = dt_path.parent / f"{dt_path.stem}_test{dt_path.suffix}"

    try:
        compile_characters(json_path, test_dt_path, cli_mode=mode)

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
    parser = argparse.ArgumentParser(description="t_name._dt decompiler/compiler")
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
        compile_characters(input_path, out, cli_mode=args.mode, interactive=is_interactive())
    elif ftype == 'dt':
        out = Path(args.output) if args.output else input_path.with_suffix(JSON_EXTENSION)
        if args.mode is not None:
            print("Note: encoding mode is ignored on decompile "
                  "(the decoder reads halfwidth and 2-byte SJIS transparently).")
        decompile_characters(input_path, out, test_compilation=args.test, mode='halfwidth')
    else:
        print(f"Unsupported file: {input_path}")
        sys.exit(1)


if __name__ == "__main__":
    run_main(main)
