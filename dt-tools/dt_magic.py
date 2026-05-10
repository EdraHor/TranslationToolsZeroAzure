#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# t_magic._dt decompiler / compiler (spell / magic entries).
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

# t_magic._dt format
# ──────────────────
# Header: u16 array of N absolute offsets, where N = (first_u16) / 2.
#         The very first u16 of the file IS both the table size in bytes AND
#         the offset of the first record (records start right after the table).
#         Multiple slots may point to the same record offset (skill levels
#         that share data) or to the strings boundary (unused tail slots).
#
# Records section (variable, all records concatenated):
#   "magic" record — 32 bytes:
#     bytes  0..27 : raw stat block (id-ish word, costs, ranges, etc.)
#     bytes 28..29 : u16 absolute offset of name string
#     bytes 30..31 : u16 absolute offset of description string
#   "stub" record  — 4 bytes of 0x00, used as a placeholder.
#
# Strings section (immediately after the last record):
#   For every magic record, in physical order:
#     <name>\0<description>\0
#   No deduplication; a record's desc starts right after its name's null.
#
# Some trailing slots in the offset table point to the very first string's
# address (= records-end). Those are unused/sentinel slots — represented as
# null in slot_assignment so the compiler can re-emit them at the right spot.
#
# Two encoding modes (CLI flag --halfwidth / --passthrough):
#   "halfwidth"   : letters become 1-byte halfwidth codes via byte_codec
#                   (needs patched zero.exe + font.itf). Saves ~50% space.
#   "passthrough" : letters become standard 2-byte SJIS pairs (stock font).

ENCODING = 'shift_jis'
DT_EXTENSION = '._dt'
JSON_EXTENSION = '.json'

MAGIC_RECORD_SIZE = 32
STUB_RECORD_SIZE = 4
MAGIC_DATA_HEX_BYTES = 28  # bytes 0..27, the part we don't recompute


def extract_string(data, offset, mode='halfwidth'):
    if offset >= len(data):
        return ""
    end = data.find(b'\x00', offset)
    if end == -1:
        end = len(data)
    return decode_str(bytes(data[offset:end]), ENCODING, mode)


def decompile_magic(dt_path, json_path, test_compilation=False, mode='halfwidth'):
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

    # Sort unique offsets to discover record sizes (each record's size is the
    # gap to the next-larger offset; the largest one is the strings boundary).
    sorted_unique = sorted(set(offsets))
    if sorted_unique[0] != header_size:
        raise ValueError(f"First record offset {sorted_unique[0]:#06x} doesn't match header end {header_size:#06x}")

    strings_boundary = sorted_unique[-1]  # also where the first string begins

    # Build records in physical (offset) order. The boundary itself is NOT a record.
    records = []
    offset_to_index = {}
    for i, off in enumerate(sorted_unique[:-1]):
        nxt = sorted_unique[i + 1]
        size = nxt - off
        body = original_data[off:nxt]

        if size == STUB_RECORD_SIZE:
            if body != b'\x00' * STUB_RECORD_SIZE:
                print(f"  WARN: 4-byte record at 0x{off:04X} is not all zero: {body.hex()}")
            records.append({"kind": "stub"})
        elif size == MAGIC_RECORD_SIZE:
            name_off = struct.unpack('<H', body[28:30])[0]
            desc_off = struct.unpack('<H', body[30:32])[0]
            records.append({
                "kind": "magic",
                "data_hex": body[:MAGIC_DATA_HEX_BYTES].hex(),
                "name": extract_string(original_data, name_off, mode),
                "desc": extract_string(original_data, desc_off, mode),
            })
        else:
            raise ValueError(f"Unexpected record size {size} at 0x{off:04X}")

        offset_to_index[off] = len(records) - 1

    # Map every slot to its record index, or null for boundary-pointers.
    slot_assignment = []
    for slot, off in enumerate(offsets):
        if off == strings_boundary:
            slot_assignment.append(None)
        else:
            slot_assignment.append(offset_to_index[off])

    magic_count = sum(1 for r in records if r["kind"] == "magic")
    stub_count = sum(1 for r in records if r["kind"] == "stub")
    null_slots = sum(1 for s in slot_assignment if s is None)
    print(f"Records: {magic_count} magic, {stub_count} stub")
    print(f"Slots: {slot_count} total, {null_slots} sentinel (point past last record)")

    # Build the translation table: one entry per unique (name, desc) pair,
    # in the order they first appear. Name and description live together so
    # the translator can see both halves of a spell side-by-side.
    seen_pairs = set()
    translations = []
    for r in records:
        if r['kind'] != 'magic':
            continue
        key = (r['name'], r['desc'])
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        translations.append({
            "name_en": r['name'],
            "name_ru": "",
            "desc_en": r['desc'],
            "desc_ru": "",
        })

    result = {
        "file_info": {
            "original_size": len(original_data),
            "encoding": ENCODING,
            "header_size": header_size,
            "slot_count": slot_count,
        },
        "translations": translations,
        "records": records,
        "slot_assignment": slot_assignment,
    }

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nDecompiled to {json_path}")
    print(f"Translate by filling 'name_ru' / 'desc_ru' fields in 'translations'.")
    print(f"Each entry pairs a spell's name with its description. Empty *_ru falls back to *_en.")
    if mode == 'halfwidth':
        print(f"Letters will be encoded as single SJIS halfwidth bytes on compile.")
    else:
        print(f"Letters will be encoded as standard 2-byte SJIS on compile (no halfwidth remap).")

    if test_compilation:
        test_compilation_process(dt_path, json_path, original_data, mode)


def compile_magic(json_path, dt_path, cli_mode=None, interactive=False):
    print(f"=== COMPILING {json_path} ===")

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    info = data['file_info']
    encoding = info.get('encoding', ENCODING)
    header_size = info['header_size']
    slot_count = info['slot_count']
    records = data['records']
    slot_assignment = data['slot_assignment']
    mode = resolve_mode(cli_mode, interactive=interactive)
    print(f"Encoding mode: {mode}")

    if len(slot_assignment) != slot_count:
        raise ValueError(f"slot_assignment length {len(slot_assignment)} != slot_count {slot_count}")

    print(f"Original size: {info['original_size']} bytes")
    print(f"Records: {len(records)}, slots: {slot_count}")

    # Build a (name_en, desc_en) -> (name_ru, desc_ru) lookup. The pair is the
    # key so two spells that happen to share a name but differ in description
    # don't bleed into each other.
    pair_map = {}
    active_names = active_descs = 0
    for entry in data.get('translations', []):
        ne, nr = entry.get('name_en', ''), entry.get('name_ru', '')
        de, dr = entry.get('desc_en', ''), entry.get('desc_ru', '')
        key = (ne, de)
        if key in pair_map and pair_map[key] != (nr, dr):
            print(f"  WARN: duplicate translation for {key!r}")
        pair_map[key] = (nr, dr)
        if nr: active_names += 1
        if dr: active_descs += 1
    if pair_map:
        print(f"Translations: {len(pair_map)} pair(s) loaded, "
              f"{active_names} name(s) and {active_descs} desc(s) active.")

    # Lay out records sequentially right after the header to compute their offsets.
    record_offsets = []
    cursor = header_size
    for rec in records:
        record_offsets.append(cursor)
        if rec['kind'] == 'magic':
            cursor += MAGIC_RECORD_SIZE
        elif rec['kind'] == 'stub':
            cursor += STUB_RECORD_SIZE
        else:
            raise ValueError(f"Unknown record kind: {rec['kind']!r}")

    strings_start = cursor  # also the address slots with null assignment will receive

    # Encode every name+desc into the strings section, recording the absolute
    # offset of each name and desc so we can patch the magic records.
    # For each record, look up its (name, desc) pair in the translation map.
    # A non-empty *_ru overrides the *_en half. Mode applies uniformly to both
    # original and translated text.
    strings_blob = bytearray()
    name_offsets = [None] * len(records)
    desc_offsets = [None] * len(records)
    for i, rec in enumerate(records):
        if rec['kind'] != 'magic':
            continue
        nr, dr = pair_map.get((rec['name'], rec['desc']), ('', ''))
        name_text = nr if nr else rec['name']
        desc_text = dr if dr else rec['desc']
        name_offsets[i] = strings_start + len(strings_blob)
        strings_blob.extend(encode_str(name_text, encoding, mode) + b'\x00')
        desc_offsets[i] = strings_start + len(strings_blob)
        strings_blob.extend(encode_str(desc_text, encoding, mode) + b'\x00')

    # Build the records blob using the freshly computed name/desc offsets.
    records_blob = bytearray()
    for i, rec in enumerate(records):
        if rec['kind'] == 'magic':
            stat_bytes = bytes.fromhex(rec['data_hex'])
            if len(stat_bytes) != MAGIC_DATA_HEX_BYTES:
                raise ValueError(
                    f"Record {i}: data_hex must be {MAGIC_DATA_HEX_BYTES} bytes (got {len(stat_bytes)})"
                )
            records_blob.extend(stat_bytes)
            records_blob.extend(struct.pack('<HH', name_offsets[i], desc_offsets[i]))
        else:  # stub
            records_blob.extend(b'\x00' * STUB_RECORD_SIZE)

    # Build the offset table: each slot points to its record or to strings_start.
    table = bytearray()
    for s in slot_assignment:
        if s is None:
            off = strings_start
        else:
            if not (0 <= s < len(records)):
                raise ValueError(f"slot_assignment value {s} out of range")
            off = record_offsets[s]
        if off > 0xFFFF:
            raise ValueError(f"Offset 0x{off:X} doesn't fit in u16. File too large.")
        table.extend(struct.pack('<H', off))

    # Pad the table to header_size if anything extra was supposed to go there.
    while len(table) < header_size:
        table.append(0)

    result = bytearray()
    result.extend(table)
    result.extend(records_blob)
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
        compile_magic(json_path, test_dt_path, cli_mode=mode)

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
    parser = argparse.ArgumentParser(description="t_magic._dt decompiler/compiler")
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
        compile_magic(input_path, out, cli_mode=args.mode, interactive=is_interactive())
    elif ftype == 'dt':
        out = Path(args.output) if args.output else input_path.with_suffix(JSON_EXTENSION)
        if args.mode is not None:
            print("Note: encoding mode is ignored on decompile "
                  "(the decoder reads halfwidth and 2-byte SJIS transparently).")
        decompile_magic(input_path, out, test_compilation=args.test, mode='halfwidth')
    else:
        print(f"Unsupported file: {input_path}")
        sys.exit(1)


if __name__ == "__main__":
    run_main(main)
