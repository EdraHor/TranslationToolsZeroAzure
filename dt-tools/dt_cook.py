#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# t_cook._dt decompiler / compiler (cooking dish descriptions).
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

# byte_codec lives one level up (dt-tools/), this script lives in dt-tools/mons/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from byte_codec import (encode_str, decode_str, resolve_mode, add_mode_args,
                        ENCODING_MODES, run_main, is_interactive)

# t_cook._dt format
# ─────────────────
#   0x0000..0x0003 : 4-byte header
#                    u16[0] = header_size (= 4)
#                    u16[1] = stats_offset (= 4 + records_count * 48)
#   0x0004..stats  : N × 48-byte dish records.
#                    Bytes 0..43 of each record are opaque (recipe id /
#                    ingredient ids / counts / category / etc — preserved
#                    verbatim as raw_hex). Byte 44..45 is a u16 absolute
#                    offset of the dish's description string. The last
#                    record is an end-of-table sentinel with text_ptr = 0.
#   stats..text    : 104 bytes of u16 stat-boost values per dish (HP/EP/CP
#                    percentages and similar). No text pointers in here —
#                    preserved verbatim as stats_hex.
#   text..EOF      : Null-terminated description strings (one per non-stub
#                    record), in record order.
#
# Two encoding modes (CLI flag --halfwidth / --passthrough), applied
# uniformly to every translatable string:
#   "halfwidth"   : letters become 1-byte halfwidth codes via byte_codec.
#                   Saves ~50% space; needs patched font.itf + zero.exe.
#   "passthrough" : letters become standard 2-byte SJIS pairs (stock font).

ENCODING = 'shift_jis'
DT_EXTENSION = '._dt'
JSON_EXTENSION = '.json'

HEADER_SIZE = 4
RECORD_SIZE = 48
TEXT_PTR_OFF = 44   # u16 text pointer within each record
STATS_REGION_BYTES = 104  # opaque stat-boost block right before texts


def decompile_cook(dt_path, json_path, test_compilation=False, mode='halfwidth'):
    print(f"=== DECOMPILING {dt_path} ===")
    print(f"Encoding mode: {mode}")

    with open(dt_path, 'rb') as f:
        original_data = f.read()
    print(f"File size: {len(original_data)} bytes")

    header_size, stats_offset = struct.unpack_from('<HH', original_data, 0)
    if header_size != HEADER_SIZE:
        raise ValueError(f"Unexpected header_size 0x{header_size:04X} (expected 0x{HEADER_SIZE:04X}).")
    print(f"  header_size: 0x{header_size:04X}")
    print(f"  stats_offset: 0x{stats_offset:04X}")

    records_count = (stats_offset - HEADER_SIZE) // RECORD_SIZE
    text_section = stats_offset + STATS_REGION_BYTES
    print(f"  Records: {records_count} × {RECORD_SIZE} bytes")
    print(f"  Stats region: {STATS_REGION_BYTES} bytes")
    print(f"  Text section starts at: 0x{text_section:04X}")

    # First pass: collect unique text pointers in record order.
    seen_ptrs = []
    for i in range(records_count):
        off = HEADER_SIZE + i * RECORD_SIZE
        text_ptr = struct.unpack_from('<H', original_data, off + TEXT_PTR_OFF)[0]
        if text_section <= text_ptr < len(original_data) and text_ptr not in seen_ptrs:
            seen_ptrs.append(text_ptr)

    # Read each pointed-to string, in the order pointers first appeared.
    translations = []
    for ptr in seen_ptrs:
        end = original_data.find(b'\x00', ptr)
        if end == -1:
            end = len(original_data)
        text = decode_str(bytes(original_data[ptr:end]), ENCODING, mode)
        translations.append({"original": text, "translation": ""})

    # Second pass: build records list with text_idx links.
    ptr_to_idx = {p: i for i, p in enumerate(seen_ptrs)}
    records = []
    for i in range(records_count):
        off = HEADER_SIZE + i * RECORD_SIZE
        raw = original_data[off:off + RECORD_SIZE]
        text_ptr = struct.unpack_from('<H', original_data, off + TEXT_PTR_OFF)[0]
        entry = {"raw_hex": raw.hex()}
        if text_ptr in ptr_to_idx:
            entry["text_idx"] = ptr_to_idx[text_ptr]
        records.append(entry)

    stats_hex = original_data[stats_offset:text_section].hex()

    print(f"  Dish descriptions: {len(translations)}")

    result = {
        "format": "cook",
        "file_info": {
            "original_size": len(original_data),
            "encoding": ENCODING,
            "records_count": records_count,
            "record_size": RECORD_SIZE,
        },
        "records": records,
        "stats_hex": stats_hex,
        "translations": translations,
    }

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nDecompiled to {json_path}")
    print(f"Translate by filling 'translation' fields. Empty 'translation' falls back to 'original'.")
    if mode == 'halfwidth':
        print("Letters will be encoded as single SJIS halfwidth bytes on compile.")
    else:
        print("Letters will be encoded as standard 2-byte SJIS on compile (no halfwidth remap).")

    if test_compilation:
        test_compilation_process(dt_path, json_path, original_data, mode)


def compile_cook(json_path, dt_path, cli_mode=None, interactive=False):
    print(f"=== COMPILING {json_path} ===")

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    info = data['file_info']
    encoding = info.get('encoding', ENCODING)
    records = data['records']
    stats_hex = data['stats_hex']
    translations = data['translations']
    mode = resolve_mode(cli_mode, interactive=interactive)
    print(f"Encoding mode: {mode}")
    print(f"Original size: {info['original_size']} bytes")
    print(f"Records: {len(records)}, dish descriptions: {len(translations)}")

    stats_bytes = bytearray.fromhex(stats_hex)
    if len(stats_bytes) != STATS_REGION_BYTES:
        raise ValueError(
            f"stats_hex must decode to {STATS_REGION_BYTES} bytes (got {len(stats_bytes)})."
        )

    # Compute new text positions so we can patch the records' text pointers.
    stats_offset = HEADER_SIZE + len(records) * RECORD_SIZE
    text_section = stats_offset + STATS_REGION_BYTES

    # Pick the effective text per translation entry: the user's translation
    # if non-empty, otherwise the original.
    effective_texts = []
    active = 0
    for entry in translations:
        original = entry.get('original', '')
        translation = entry.get('translation', '')
        text = translation if translation else original
        effective_texts.append(text)
        if translation:
            active += 1
    if active:
        print(f"Translations: {active} of {len(translations)} entries translated.")

    text_positions = []
    cursor = text_section
    for t in effective_texts:
        text_positions.append(cursor)
        cursor += len(encode_str(t, encoding, mode)) + 1

    # Header.
    out = bytearray()
    out.extend(struct.pack('<HH', HEADER_SIZE, stats_offset))

    # Records: copy raw bytes, then overwrite the u16 text pointer where set.
    for i, rec in enumerate(records):
        raw = bytearray.fromhex(rec['raw_hex'])
        if len(raw) != RECORD_SIZE:
            raise ValueError(
                f"Record {i}: raw_hex must decode to {RECORD_SIZE} bytes (got {len(raw)})."
            )
        text_idx = rec.get('text_idx')
        if text_idx is not None:
            if not (0 <= text_idx < len(text_positions)):
                raise ValueError(
                    f"Record {i}: text_idx {text_idx} out of range "
                    f"(have {len(translations)} translations)."
                )
            struct.pack_into('<H', raw, TEXT_PTR_OFF, text_positions[text_idx])
        out.extend(raw)

    # Stats blob, then the encoded texts.
    out.extend(stats_bytes)
    for t in effective_texts:
        out.extend(encode_str(t, encoding, mode))
        out.append(0x00)

    with open(dt_path, 'wb') as f:
        f.write(out)

    print(f"\nCompiled to {dt_path}")
    print(f"New size: {len(out)} bytes")
    print(f"Size difference: {len(out) - info['original_size']:+d} bytes")


def test_compilation_process(dt_path, json_path, original_data, mode='halfwidth'):
    print("\n=== COMPILATION TEST ===")
    test_dt_path = dt_path.parent / f"{dt_path.stem}_test{dt_path.suffix}"

    try:
        compile_cook(json_path, test_dt_path, cli_mode=mode)

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
    parser = argparse.ArgumentParser(description="t_cook._dt decompiler/compiler")
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
        compile_cook(input_path, out, cli_mode=args.mode, interactive=is_interactive())
    elif ftype == 'dt':
        out = Path(args.output) if args.output else input_path.with_suffix(JSON_EXTENSION)
        if args.mode is not None:
            print("Note: encoding mode is ignored on decompile "
                  "(the decoder reads halfwidth and 2-byte SJIS transparently).")
        decompile_cook(input_path, out, test_compilation=args.test, mode='halfwidth')
    else:
        print(f"Unsupported file: {input_path}")
        sys.exit(1)


if __name__ == "__main__":
    run_main(main)
