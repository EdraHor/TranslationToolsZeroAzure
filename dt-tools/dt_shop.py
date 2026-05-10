#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
t_shop._dt decompiler / compiler.
Part of the Trails From Zero Toolkit. Author: Edrahor.

Reads the shop list at offset 0..0x200 (256-slot offset table), then per
record: name, item list, discount table. In halfwidth mode, names go
through byte_codec so each non-ASCII letter takes one byte — keeping shop
frame widths the same as English.
"""

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
                        ENCODING_MODES, ENCODING, run_main, is_interactive)

DT_EXTENSION = '._dt'
JSON_EXTENSION = '.json'

HEADER_SIZE = 0x200
SLOT_COUNT = 256
RECORD_HEADER_SIZE = 16


def read_offset_table(data):
    return list(struct.unpack(f'<{SLOT_COUNT}H', data[:HEADER_SIZE]))


def extract_string_at_offset(data, offset, mode='halfwidth'):
    if offset >= len(data):
        return ""
    null_pos = data.find(b'\x00', offset)
    if null_pos == -1:
        null_pos = len(data)
    return decode_str(data[offset:null_pos], ENCODING, mode)


def decompile_shop(dt_path, json_path, test_compilation=False, mode='halfwidth'):
    print(f"=== DECOMPILING {dt_path} ===")
    print(f"Encoding mode: {mode}")

    with open(dt_path, 'rb') as f:
        original_data = f.read()

    print(f"File size: {len(original_data)} bytes")

    offsets = read_offset_table(original_data)

    active = [(slot, off) for slot, off in enumerate(offsets) if off > 0]
    print(f"Active slots: {len(active)} / {SLOT_COUNT}")

    by_offset = sorted(active, key=lambda x: x[1])

    shops = []
    for i, (slot, start) in enumerate(by_offset):
        end = by_offset[i + 1][1] if i + 1 < len(by_offset) else len(original_data)
        rec = original_data[start:end]

        if len(rec) < RECORD_HEADER_SIZE:
            print(f"  WARNING: slot {slot} record too small ({len(rec)} bytes), skipping")
            continue

        id_val = struct.unpack('<H', rec[0:2])[0]
        type_byte = rec[2]
        param_byte = rec[3]
        discounts = rec[4:12].hex()
        items_off = struct.unpack('<H', rec[12:14])[0]
        name_off = struct.unpack('<H', rec[14:16])[0]

        name = extract_string_at_offset(original_data, name_off, mode)

        items_data = original_data[items_off:end]
        items_count = len(items_data) // 2
        items = list(struct.unpack(f'<{items_count}H', items_data[:items_count * 2])) if items_count else []

        shops.append({
            'slot': slot,
            'id': id_val,
            'type': type_byte,
            'param': param_byte,
            'discounts': discounts,
            'name': name,
            'items': items,
        })

    seen = set()
    translations = []
    for s in shops:
        if s['name'] not in seen:
            seen.add(s['name'])
            translations.append({"en": s['name'], "ru": ""})

    result = {
        "file_info": {
            "original_size": len(original_data),
            "encoding": ENCODING,
            "encoding_translated": ENCODING,
            "header_size": HEADER_SIZE,
            "slot_count": SLOT_COUNT,
        },
        "translations": translations,
        "shops": shops,
    }

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nDecompiled to {json_path}")
    print(f"Translate by filling 'ru' fields in the 'translations' block.")

    if test_compilation:
        test_compilation_process(dt_path, json_path, original_data, mode)


def compile_shop(json_path, dt_path, cli_mode=None, interactive=False):
    print(f"=== COMPILING {json_path} ===")

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    shops = data['shops']
    info = data['file_info']
    mode = resolve_mode(cli_mode, interactive=interactive)
    print(f"Encoding mode: {mode}")
    print(f"Original size: {info['original_size']} bytes")
    print(f"Shops to compile: {len(shops)}")

    translations = data.get('translations', [])
    en_to_ru = {}
    for entry in translations:
        en = entry.get('en', '')
        ru = entry.get('ru', '')
        if en and ru:
            if en in en_to_ru and en_to_ru[en] != ru:
                print(f"  WARN: duplicate translation for {en!r}: {en_to_ru[en]!r} vs {ru!r}")
            en_to_ru[en] = ru
    if translations:
        print(f"Translations: {len(en_to_ru)} active / {len(translations)} entries")

    shops_sorted = sorted(shops, key=lambda s: s['slot'])

    offsets = [0] * SLOT_COUNT
    records_data = bytearray()

    for shop in shops_sorted:
        slot = shop['slot']
        if not (0 <= slot < SLOT_COUNT):
            raise ValueError(f"Shop slot {slot} out of range 0..{SLOT_COUNT - 1}")
        if offsets[slot] != 0:
            raise ValueError(f"Duplicate slot {slot}")

        record_start = HEADER_SIZE + len(records_data)
        offsets[slot] = record_start

        if shop['name'] in en_to_ru:
            display_name = en_to_ru[shop['name']]
        else:
            display_name = shop['name']

        name_bytes = encode_str(display_name, ENCODING, mode) + b'\x00'
        name_offset = record_start + RECORD_HEADER_SIZE
        items_offset = name_offset + len(name_bytes)

        discounts = bytes.fromhex(shop['discounts'])
        if len(discounts) != 8:
            raise ValueError(f"slot {slot}: 'discounts' must be 8 bytes (got {len(discounts)})")

        header = (
            struct.pack('<H', shop['id']) +
            struct.pack('<BB', shop['type'], shop['param']) +
            discounts +
            struct.pack('<HH', items_offset, name_offset)
        )
        assert len(header) == RECORD_HEADER_SIZE

        records_data.extend(header)
        records_data.extend(name_bytes)

        for item in shop['items']:
            records_data.extend(struct.pack('<H', item))

    result_data = bytearray()
    for off in offsets:
        if off > 0xFFFF:
            raise ValueError(f"Offset 0x{off:X} doesn't fit in u16. File too large.")
        result_data.extend(struct.pack('<H', off))
    result_data.extend(records_data)

    with open(dt_path, 'wb') as f:
        f.write(result_data)

    print(f"\nCompiled to {dt_path}")
    print(f"New size: {len(result_data)} bytes")
    print(f"Size difference: {len(result_data) - data['file_info']['original_size']:+d} bytes")


def test_compilation_process(dt_path, json_path, original_data, mode='halfwidth'):
    print("\n=== ROUND-TRIP TEST ===")
    test_dt_path = dt_path.parent / f"{dt_path.stem}_test{dt_path.suffix}"

    try:
        compile_shop(json_path, test_dt_path, cli_mode=mode)

        with open(test_dt_path, 'rb') as f:
            compiled_data = f.read()

        if compiled_data == original_data:
            print("TEST PASSED: byte-identical round-trip!")
            test_dt_path.unlink()
        else:
            print("TEST FAILED:")
            print(f"  Original: {len(original_data)} bytes")
            print(f"  Compiled: {len(compiled_data)} bytes")
            print(f"  Difference: {len(compiled_data) - len(original_data):+d} bytes")
            min_len = min(len(original_data), len(compiled_data))
            for i in range(min_len):
                if original_data[i] != compiled_data[i]:
                    print(f"  First difference at 0x{i:04X}: "
                          f"{original_data[i]:02x} -> {compiled_data[i]:02x}")
                    ctx = 16
                    a = original_data[max(0, i - ctx):i + ctx].hex()
                    b = compiled_data[max(0, i - ctx):i + ctx].hex()
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
    parser = argparse.ArgumentParser(description="t_shop._dt decompiler/compiler")
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
        compile_shop(input_path, out, cli_mode=args.mode, interactive=is_interactive())
    elif ftype == 'dt':
        out = Path(args.output) if args.output else input_path.with_suffix(JSON_EXTENSION)
        if args.mode is not None:
            print("Note: encoding mode is ignored on decompile "
                  "(the decoder reads halfwidth and 2-byte SJIS transparently).")
        decompile_shop(input_path, out, test_compilation=args.test, mode='halfwidth')
    else:
        print(f"Unsupported file: {input_path}")
        sys.exit(1)


if __name__ == "__main__":
    run_main(main)
