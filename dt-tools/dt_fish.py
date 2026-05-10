#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# t_fish._dt decompiler / compiler.
# Supports both Trails to Azure (full layout: notebook descriptions + NPC
# names + service data + quest texts) and Trails from Zero (notebook
# descriptions only). Format is auto-detected from the binary's header_size
# on decompile, and stored in the JSON's "format" field for compile.
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

# byte_codec lives one level up (dt-tools/), this script lives in dt-tools/fish/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from byte_codec import (encode_str, decode_str, resolve_mode, add_mode_args,
                        ENCODING_MODES, run_main, is_interactive)

# t_fish._dt format
# ─────────────────
# Two layouts share the same extension; we tell them apart by the first u16
# (header_size).
#
# AZURE  (header_size = 0x000C, 12 bytes)
#   0x00..0x0B : header  (header_size, unknown1, unknown2,
#                         npc_names_offset, service_data_offset, quest_data_offset)
#   0x0C..0x0F : 4 bytes belonging to record 0 of metadata, but historically
#                read as the "tail" of the header (unknown3 = record 0's idx,
#                notebook_offset = record 0's text pointer).
#   0x10..notebook_offset : metadata records (48 × 58 bytes).
#   notebook   : 31 fish description strings (null-terminated).
#   npc_names  : 10-byte pointer table + 5 NPC names.
#   service    : opaque blob with 5 internal pointers (rebased on compile).
#   quest      : 120-entry u16 pointer table + quest text strings.
#
# ZERO   (header_size = 0x0006, 6 bytes)
#   0x00..0x05 : header  (header_size, unknown1, unknown2)
#   0x06..N    : metadata records (42 × 60 bytes). The first 24 records have
#                a u16 text pointer at record_offset+2 pointing into the
#                notebook section; the rest are stub records (ptr = 0 or
#                0xFFFF) preserved verbatim.
#   N..notebook: 8 bytes of 0xFF padding.
#   notebook   : 24 fish description strings (null-terminated, to EOF).
#   No npc_names / service / quest sections.
#
# Two encoding modes (CLI flag --halfwidth / --passthrough), applied
# uniformly to every translatable string:
#   "halfwidth"   : letters become 1-byte halfwidth codes via byte_codec.
#                   Saves ~50% space; needs patched font.itf + zero.exe.
#   "passthrough" : letters become standard 2-byte SJIS pairs (stock font).

ENCODING = 'shift_jis'
DT_EXTENSION = '._dt'
JSON_EXTENSION = '.json'

AZURE_HEADER_SIZE = 0x000C
ZERO_HEADER_SIZE = 0x0006


# ─── Format detection ──────────────────────────────────────────────────────

def detect_format_from_binary(data):
    if len(data) < 2:
        raise ValueError("File too small to read header.")
    header_size = struct.unpack_from('<H', data, 0)[0]
    if header_size == AZURE_HEADER_SIZE:
        return 'azure'
    if header_size == ZERO_HEADER_SIZE:
        return 'zero'
    raise ValueError(
        f"Unrecognized fish format: header_size = 0x{header_size:04X}. "
        f"Expected 0x{AZURE_HEADER_SIZE:04X} (Azure) or 0x{ZERO_HEADER_SIZE:04X} (Zero)."
    )


def detect_format_from_json(data_dict):
    fmt = data_dict.get('format')
    if fmt in ('azure', 'zero'):
        return fmt
    # Backward compat: pre-format-tag Azure JSONs have these top-level keys.
    if 'metadata' in data_dict and 'quest_texts' in data_dict:
        return 'azure'
    if 'records' in data_dict and 'texts' in data_dict:
        return 'zero'
    raise ValueError("Cannot determine fish format from JSON; missing 'format' key.")


# ─── AZURE ─────────────────────────────────────────────────────────────────
# Layout: header + metadata + notebook + npc_names + service + quest.
# Original parser by the Trails to Azure community; the binary layout below
# is theirs verbatim — only encoding goes through byte_codec now so Russian
# translations can use the halfwidth single-byte alphabet.

AZURE_METADATA_START = 0x10
AZURE_METADATA_ENTRY_SIZE = 58
AZURE_NPC_PTR_TABLE_SIZE = 10
AZURE_SERVICE_PTR_COUNT = 5
AZURE_SERVICE_RECORD_STRIDE = 48
AZURE_QUEST_POINTER_COUNT = 120


def _split_cstrings(blob, mode):
    return [decode_str(bytes(p), ENCODING, mode) for p in blob.split(b'\x00')]


def decompile_azure(data, mode):
    h = struct.unpack_from('<HHHHHHHH', data, 0)
    header = {
        'header_size': h[0],
        'unknown1': h[1],
        'unknown2': h[2],
        'npc_names_offset': h[3],
        'service_data_offset': h[4],
        'quest_data_offset': h[5],
        'unknown3': h[6],
        'notebook_offset': h[7],
    }
    npc_names_offset = header['npc_names_offset']
    service_data_offset = header['service_data_offset']
    quest_data_offset = header['quest_data_offset']
    notebook_offset = header['notebook_offset']

    print(f'  header_size: 0x{header["header_size"]:04X}')
    print(f'  notebook_offset: 0x{notebook_offset:04X}')
    print(f'  npc_names_offset: 0x{npc_names_offset:04X}')
    print(f'  service_data_offset: 0x{service_data_offset:04X}')
    print(f'  quest_data_offset: 0x{quest_data_offset:04X}')

    # Metadata: 48 records × 58 bytes, stored as raw hex.
    num_entries = (notebook_offset - AZURE_METADATA_START) // AZURE_METADATA_ENTRY_SIZE
    metadata = []
    for i in range(num_entries):
        off = AZURE_METADATA_START + i * AZURE_METADATA_ENTRY_SIZE
        metadata.append(data[off:off + AZURE_METADATA_ENTRY_SIZE].hex())
    print(f'  Metadata records: {num_entries}')

    notebook_texts = [s for s in _split_cstrings(data[notebook_offset:npc_names_offset], mode) if s]
    print(f'  Notebook texts: {len(notebook_texts)}')

    # NPC names: 10-byte pointer table + null-terminated names.
    npc_blob = data[npc_names_offset + AZURE_NPC_PTR_TABLE_SIZE:service_data_offset]
    npc_names = [s for s in _split_cstrings(npc_blob, mode) if s]
    print(f'  NPC names: {len(npc_names)}')

    # Service data: opaque blob, kept as hex; only the first 5 u16 are
    # internal pointers that get rebased on compile.
    service_data = data[service_data_offset:quest_data_offset].hex()

    # Quest: 120 u16 pointers + null-terminated quest strings.
    pointers = list(struct.unpack_from(f'<{AZURE_QUEST_POINTER_COUNT}H', data, quest_data_offset))
    text_start = quest_data_offset + AZURE_QUEST_POINTER_COUNT * 2
    quest_strs = _split_cstrings(data[text_start:], mode)
    if quest_strs and not quest_strs[-1]:
        quest_strs = quest_strs[:-1]
    print(f'  Quest pointers: {AZURE_QUEST_POINTER_COUNT}, texts: {len(quest_strs)}')

    return {
        'format': 'azure',
        'header': header,
        'metadata': metadata,
        'notebook_texts': notebook_texts,
        'npc_names': npc_names,
        'service_data': service_data,
        'quest_texts': {'pointers': pointers, 'texts': quest_strs},
    }


def compile_azure(data_dict, mode):
    enc = lambda s: encode_str(s, ENCODING, mode)

    # 16 bytes reserved for header + the 4-byte "tail" that overlaps with
    # record 0's first fields; both get patched at the end.
    out = bytearray(16)

    # Metadata + recompute notebook string offsets so we can patch the
    # records' text pointers.
    metadata = data_dict['metadata']
    notebook_texts = data_dict['notebook_texts']
    text_abs_offsets = []
    cursor = AZURE_METADATA_START + len(metadata) * AZURE_METADATA_ENTRY_SIZE
    for text in notebook_texts:
        text_abs_offsets.append(cursor)
        cursor += len(enc(text)) + 1

    # Patch text pointers inside each metadata record. The (entry_idx,
    # byte_pos, text_idx) mapping is the original Azure-specific convention:
    # records 1..29 carry their text pointer at byte (N-1)*2; record 31
    # carries it at byte 0.
    for entry_idx, meta_hex in enumerate(metadata):
        meta_bytes = bytearray.fromhex(meta_hex)
        if 1 <= entry_idx <= 29:
            text_idx = entry_idx
            byte_pos = (entry_idx - 1) * 2
            if text_idx < len(text_abs_offsets):
                struct.pack_into('<H', meta_bytes, byte_pos, text_abs_offsets[text_idx])
        elif entry_idx == 31:
            text_idx = 30
            if text_idx < len(text_abs_offsets):
                struct.pack_into('<H', meta_bytes, 0, text_abs_offsets[text_idx])
        out.extend(meta_bytes)

    # Notebook strings.
    notebook_offset = len(out)
    for text in notebook_texts:
        out.extend(enc(text))
        out.append(0x00)

    # NPC names: reserve 10-byte pointer table, then append names and
    # back-fill the table.
    npc_names = data_dict['npc_names']
    npc_names_offset = len(out)
    npc_positions = []
    pos = npc_names_offset + AZURE_NPC_PTR_TABLE_SIZE
    for name in npc_names:
        npc_positions.append(pos)
        pos += len(enc(name)) + 1
    out.extend(b'\x00' * AZURE_NPC_PTR_TABLE_SIZE)
    for i, p in enumerate(npc_positions):
        struct.pack_into('<H', out, npc_names_offset + i * 2, p)
    for name in npc_names:
        out.extend(enc(name))
        out.append(0x00)

    # Service blob: 5 internal pointers rebased to the new section start.
    service_data_offset = len(out)
    service_bytes = bytearray.fromhex(data_dict['service_data'])
    for i in range(AZURE_SERVICE_PTR_COUNT):
        new_ptr = service_data_offset + 10 + (i * AZURE_SERVICE_RECORD_STRIDE)
        struct.pack_into('<H', service_bytes, i * 2, new_ptr)
    out.extend(service_bytes)

    # Quest: 240-byte (120 × u16) pointer table, then quest text strings.
    quest_data_offset = len(out)
    quest_texts = data_dict['quest_texts']['texts']
    orig_pointers = data_dict['quest_texts']['pointers']
    pointers_start = len(out)
    out.extend(b'\x00' * (AZURE_QUEST_POINTER_COUNT * 2))

    text_positions = []
    for text in quest_texts:
        text_positions.append(len(out))
        out.extend(enc(text))
        out.append(0x00)

    # Map original pointers to text indexes (sorted unique → in-order). If
    # there are more unique original pointers than texts, the extra one
    # pointed past-the-end and is dropped before mapping.
    unique_orig_ptrs = sorted(set(orig_pointers))
    if len(unique_orig_ptrs) > len(quest_texts):
        unique_orig_ptrs = unique_orig_ptrs[:-1]
    orig_ptr_to_text_idx = {p: i for i, p in enumerate(unique_orig_ptrs) if i < len(quest_texts)}

    for idx, orig_ptr in enumerate(orig_pointers):
        if orig_ptr in orig_ptr_to_text_idx:
            new_ptr = text_positions[orig_ptr_to_text_idx[orig_ptr]]
        else:
            new_ptr = len(out)  # sentinel pointing past the end
        struct.pack_into('<H', out, pointers_start + idx * 2, new_ptr)

    # Header (the 16-byte prefix we reserved up front).
    h = data_dict['header']
    struct.pack_into('<H', out, 0x00, h['header_size'])
    struct.pack_into('<H', out, 0x02, h['unknown1'])
    struct.pack_into('<H', out, 0x04, h['unknown2'])
    struct.pack_into('<H', out, 0x06, npc_names_offset)
    struct.pack_into('<H', out, 0x08, service_data_offset)
    struct.pack_into('<H', out, 0x0A, quest_data_offset)
    struct.pack_into('<H', out, 0x0C, h['unknown3'])
    struct.pack_into('<H', out, 0x0E, notebook_offset)

    return bytes(out)


# ─── ZERO ──────────────────────────────────────────────────────────────────

ZERO_RECORD_SIZE = 60


def decompile_zero(data, mode):
    h = struct.unpack_from('<3H', data, 0)
    header = {
        'header_size': h[0],
        'unknown1': h[1],
        'unknown2': h[2],
    }
    notebook_offset = struct.unpack_from('<H', data, ZERO_HEADER_SIZE + 2)[0]
    print(f'  header_size: 0x{header["header_size"]:04X}')
    print(f'  notebook_offset: 0x{notebook_offset:04X}')

    # Records run from end-of-header up to the byte just before notebook,
    # 60 bytes each. Any leftover bytes between the last record and the
    # notebook are 0xFF padding (typically 8 bytes), preserved verbatim.
    records_count = (notebook_offset - ZERO_HEADER_SIZE) // ZERO_RECORD_SIZE
    records_end = ZERO_HEADER_SIZE + records_count * ZERO_RECORD_SIZE
    padding = bytes(data[records_end:notebook_offset])
    print(f'  Records: {records_count} × {ZERO_RECORD_SIZE} bytes')
    print(f'  Padding: {len(padding)} bytes')

    # First pass: collect unique text pointers in record order. A record
    # only counts if its u16-at-offset-2 lands inside the notebook section
    # (the rest are stubs with ptr = 0 or 0xFFFF).
    seen_ptrs = []
    for i in range(records_count):
        off = ZERO_HEADER_SIZE + i * ZERO_RECORD_SIZE
        text_ptr = struct.unpack_from('<H', data, off + 2)[0]
        if notebook_offset <= text_ptr < len(data) and text_ptr not in seen_ptrs:
            seen_ptrs.append(text_ptr)

    # Texts: read each pointed-to string in the order pointers first appeared.
    texts = []
    for ptr in seen_ptrs:
        end = data.find(b'\x00', ptr)
        if end == -1:
            end = len(data)
        texts.append(decode_str(bytes(data[ptr:end]), ENCODING, mode))
    print(f'  Texts: {len(texts)}')

    # Second pass: build the records list. Each record carries its raw
    # 60-byte hex (so non-pointer fields round-trip exactly) plus an
    # optional text_idx tagging which entry of `texts` it points to.
    ptr_to_idx = {p: i for i, p in enumerate(seen_ptrs)}
    records = []
    for i in range(records_count):
        off = ZERO_HEADER_SIZE + i * ZERO_RECORD_SIZE
        raw = data[off:off + ZERO_RECORD_SIZE]
        text_ptr = struct.unpack_from('<H', data, off + 2)[0]
        entry = {'raw_hex': raw.hex()}
        if text_ptr in ptr_to_idx:
            entry['text_idx'] = ptr_to_idx[text_ptr]
        records.append(entry)

    return {
        'format': 'zero',
        'header': header,
        'header_hex': bytes(data[:ZERO_HEADER_SIZE]).hex(),
        'records': records,
        'padding_hex': padding.hex(),
        'texts': texts,
    }


def compile_zero(data_dict, mode):
    enc = lambda s: encode_str(s, ENCODING, mode)

    header_bytes = bytearray.fromhex(data_dict['header_hex'])
    if len(header_bytes) != ZERO_HEADER_SIZE:
        raise ValueError(
            f"Zero header_hex must decode to {ZERO_HEADER_SIZE} bytes "
            f"(got {len(header_bytes)})."
        )
    records = data_dict['records']
    padding = bytearray.fromhex(data_dict.get('padding_hex', ''))
    texts = data_dict['texts']

    # Compute where each text will land so we can patch the records' text
    # pointers before writing the records out.
    notebook_offset = ZERO_HEADER_SIZE + len(records) * ZERO_RECORD_SIZE + len(padding)
    text_positions = []
    cursor = notebook_offset
    for t in texts:
        text_positions.append(cursor)
        cursor += len(enc(t)) + 1

    out = bytearray()
    out.extend(header_bytes)

    for rec in records:
        raw = bytearray.fromhex(rec['raw_hex'])
        if len(raw) != ZERO_RECORD_SIZE:
            raise ValueError(
                f"Record raw_hex must decode to {ZERO_RECORD_SIZE} bytes "
                f"(got {len(raw)})."
            )
        text_idx = rec.get('text_idx')
        if text_idx is not None:
            if not (0 <= text_idx < len(text_positions)):
                raise ValueError(f"text_idx {text_idx} out of range (have {len(texts)} texts).")
            struct.pack_into('<H', raw, 2, text_positions[text_idx])
        out.extend(raw)

    out.extend(padding)

    for t in texts:
        out.extend(enc(t))
        out.append(0x00)

    return bytes(out)


# ─── Round-trip test ──────────────────────────────────────────────────────

def test_compilation_process(dt_path, json_path, original_data, mode):
    print("\n=== COMPILATION TEST ===")
    test_dt_path = dt_path.parent / f"{dt_path.stem}_test{dt_path.suffix}"

    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data_dict = json.load(f)
        fmt = detect_format_from_json(data_dict)
        compiled = compile_azure(data_dict, mode) if fmt == 'azure' else compile_zero(data_dict, mode)

        with open(test_dt_path, 'wb') as f:
            f.write(compiled)

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


# ─── CLI ───────────────────────────────────────────────────────────────────

def determine_file_type(input_path):
    if input_path.suffix.lower() == JSON_EXTENSION:
        return 'json'
    elif input_path.name.endswith(DT_EXTENSION):
        return 'dt'
    return 'unknown'


def do_decompile(dt_path, json_path, mode, test):
    print(f"=== DECOMPILING {dt_path} ===")
    with open(dt_path, 'rb') as f:
        original_data = f.read()
    print(f"File size: {len(original_data)} bytes")

    fmt = detect_format_from_binary(original_data)
    print(f"Detected format: {fmt}")
    print(f"Encoding mode (decode): {mode}")

    if fmt == 'azure':
        result = decompile_azure(original_data, mode)
    else:
        result = decompile_zero(original_data, mode)

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nDecompiled to {json_path}")
    if mode == 'halfwidth':
        print("Letters will be encoded as single SJIS halfwidth bytes on compile.")
    else:
        print("Letters will be encoded as standard 2-byte SJIS on compile (no halfwidth remap).")

    if test:
        test_compilation_process(dt_path, json_path, original_data, mode)


def do_compile(json_path, dt_path, cli_mode, interactive):
    print(f"=== COMPILING {json_path} ===")
    with open(json_path, 'r', encoding='utf-8') as f:
        data_dict = json.load(f)

    fmt = detect_format_from_json(data_dict)
    mode = resolve_mode(cli_mode, interactive=interactive)
    print(f"Format: {fmt}")
    print(f"Encoding mode: {mode}")

    if fmt == 'azure':
        compiled = compile_azure(data_dict, mode)
    else:
        compiled = compile_zero(data_dict, mode)

    with open(dt_path, 'wb') as f:
        f.write(compiled)
    print(f"\nCompiled to {dt_path}")
    print(f"New size: {len(compiled)} bytes")


def main():
    parser = argparse.ArgumentParser(description="t_fish._dt decompiler/compiler (Azure + Zero)")
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
        do_compile(input_path, out, cli_mode=args.mode, interactive=is_interactive())
    elif ftype == 'dt':
        out = Path(args.output) if args.output else input_path.with_suffix(JSON_EXTENSION)
        if args.mode is not None:
            print("Note: encoding mode is ignored on decompile "
                  "(the decoder reads halfwidth and 2-byte SJIS transparently).")
        do_decompile(input_path, out, mode='halfwidth', test=args.test)
    else:
        print(f"Unsupported file: {input_path}")
        sys.exit(1)


if __name__ == "__main__":
    run_main(main)
