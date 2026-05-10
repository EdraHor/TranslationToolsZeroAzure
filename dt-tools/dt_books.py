#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# t_book*._dt decompiler / compiler.
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
                        encode_text_safe, ENCODING_MODES, ENCODING,
                        run_main, is_interactive)

# After the P1+P2 binary patches in zero.exe, both render paths (direct font
# and SJIS->UTF-8 tooltip-style) accept 1-byte halfwidth letters, so book
# content too can be halfwidth-encoded.
#
# Mode applies uniformly:
#   halfwidth   -> letters become 1-byte halfwidth (saves ~50% space).
#   passthrough -> letters become standard 2-byte SJIS pairs.
# Headers other than text (header_hex) are stored verbatim and not re-encoded.

DT_EXTENSION = '._dt'
JSON_EXTENSION = '.json'

CONTROL_CHARS = {
    '\u0001': '\\x01',
    '\u0002': '\\x02',
    '\u0003': '\\x03',
    '\u0007': '\\x07',
    '\u0009': '\\x09',
    '\u0010': '\\x10',
    '\u0000': '\\x00',
}

CONTROL_CHARS_REVERSE = {v: k for k, v in CONTROL_CHARS.items()}

def hex_dump(data, offset=0, length=64):
    """Create hex dump of data for debugging purposes"""
    end = min(offset + length, len(data))
    hex_str = " ".join(f"{b:02x}" for b in data[offset:end])
    try:
        text_str = decode_str(bytes(data[offset:end]), ENCODING, 'halfwidth')
        text_str = repr(text_str)
    except:
        text_str = "decode_error"
    return f"[{offset:04x}] {hex_str}\n      Text: {text_str}"

def read_file_header(file_data):
    """Read and validate file header"""
    if len(file_data) < 4:
        raise ValueError("File too small")

    header_size = struct.unpack('<H', file_data[0:2])[0]

    if header_size < 2 or header_size >= len(file_data):
        raise ValueError(f"Invalid header size: {header_size}")

    return header_size

def read_offsets(file_data, header_size):
    """Read all offsets from file header"""
    offset_count = (header_size - 2) // 2
    offsets = []

    for i in range(offset_count):
        pos = 2 + i * 2
        if pos + 2 > header_size:
            break
        offset = struct.unpack('<H', file_data[pos:pos+2])[0]
        offsets.append(offset)

    return offsets

def analyze_file_structure(file_data):
    """Universal analysis of DT file structure"""
    print("\n=== FILE STRUCTURE ANALYSIS ===")

    header_size = read_file_header(file_data)
    print(f"Header size: {header_size} bytes")

    offsets = read_offsets(file_data, header_size)
    print(f"Number of offsets: {len(offsets)}")
    print(f"Offsets: {offsets}")

    first_offset = offsets[0] if offsets else header_size
    between_header = file_data[header_size:first_offset]

    print(f"\nBetween header ({header_size}) and first offset ({first_offset}): {len(between_header)} bytes")
    if len(between_header) > 0:
        print(f"Data: {hex_dump(between_header, 0, min(60, len(between_header)))}")

    return {
        'header_size': header_size,
        'offsets': offsets,
        'first_block_data': between_header,
        'file_size': len(file_data)
    }

def extract_text_from_block(data, expected_encoding=ENCODING, mode='halfwidth'):
    """Extract text from data block"""
    if len(data) == 0:
        return "", b""

    null_pos = data.find(b'\x00')
    if null_pos == -1:
        try:
            text = decode_str(bytes(data), expected_encoding, mode)
            return text, data
        except:
            return "", data

    text_data = data[:null_pos + 1]
    try:
        text = decode_str(bytes(data[:null_pos]), expected_encoding, mode)
        return text, text_data
    except:
        return "", text_data

def detect_data_structure(file_data, structure_info, mode='halfwidth'):
    """Automatically detect data block structure"""
    print("\n=== DATA STRUCTURE DETECTION ===")

    offsets = structure_info['offsets']
    entries = []

    # First entry is special - may have separate initial data
    first_block_data = structure_info['first_block_data']
    first_text = ""
    if len(first_block_data) > 0:
        first_text, _ = extract_text_from_block(first_block_data, mode=mode)

    print(f"First block text: '{first_text}'")

    # Analyze all offsets to determine structure
    print("\nOffset analysis:")

    current_pair = []

    for i, offset in enumerate(offsets):
        if i == 0:
            start = offset
            end = offsets[i + 1] if i + 1 < len(offsets) else len(file_data)

            content_data = file_data[start:end]
            entries.append({
                'header_text': first_text,
                'header_data': first_block_data,
                'content_data': content_data,
                'header_offset': None,
                'content_offset': start
            })
            print(f"  Entry 1: header separate, content {start}-{end} ({end-start} bytes)")

        elif i % 2 == 1:
            header_start = offset
            header_end = offsets[i + 1] if i + 1 < len(offsets) else len(file_data)

            header_block = file_data[header_start:header_end]
            text, header_data = extract_text_from_block(header_block, mode=mode)

            current_pair = [header_start, header_end, text, header_data]
            print(f"  Header {i//2 + 2}: {header_start}-{header_end} ({header_end-header_start} bytes) '{text}'")

        else:
            if current_pair:
                content_start = offset
                content_end = offsets[i + 1] if i + 1 < len(offsets) else len(file_data)

                content_data = file_data[content_start:content_end]

                entries.append({
                    'header_text': current_pair[2],
                    'header_data': current_pair[3],
                    'content_data': content_data,
                    'header_offset': current_pair[0],
                    'content_offset': content_start
                })

                print(f"  Entry {i//2 + 1}: header {current_pair[0]}-{current_pair[1]}, content {content_start}-{content_end}")
                current_pair = []

    print(f"\nFound entries: {len(entries)}")
    return entries

def format_content_text(content_text):
    """Format content for better readability"""
    formatted_text = content_text
    for unicode_char, hex_escape in CONTROL_CHARS.items():
        formatted_text = formatted_text.replace(unicode_char, hex_escape)

    lines = formatted_text.split('\\x01')

    while lines and lines[-1].strip() == '':
        lines.pop()

    return lines

def parse_content_lines(content_lines):
    """Convert array of lines back to text with proper characters"""
    content_text = '\\x01'.join(content_lines)

    for hex_escape, unicode_char in CONTROL_CHARS_REVERSE.items():
        content_text = content_text.replace(hex_escape, unicode_char)

    return content_text

def build_json_structure(dt_path, original_data, structure_info, entries, mode='halfwidth'):
    """Build JSON structure from parsed data"""
    result = {
        "file_info": {
            "filename": dt_path.name,
            "size": len(original_data),
            "encoding": ENCODING,
        },
        "structure": {
            "header_size": structure_info['header_size'],
            "offsets": structure_info['offsets'],
            "first_block_separate": len(structure_info['first_block_data']) > 0,
            "first_block_hex": structure_info['first_block_data'].hex()
        },
        "entries": []
    }

    for entry in entries:
        try:
            content_text = decode_str(bytes(entry['content_data']), ENCODING, mode)
        except:
            content_text = entry['content_data'].decode('utf-8', errors='replace')

        content_lines = format_content_text(content_text)

        result["entries"].append({
            "header_text": entry['header_text'],
            "header_hex": entry['header_data'].hex(),
            "content_lines": content_lines,
            "header_offset": entry['header_offset'],
            "content_offset": entry['content_offset']
        })

    return result

def decompile_dt(dt_path, json_path, test_compilation=False, mode='halfwidth'):
    """Universal decompilation of DT file"""
    print(f"=== DECOMPILING {dt_path} ===")
    print(f"Encoding mode: {mode}")

    with open(dt_path, 'rb') as f:
        original_data = f.read()

    print(f"File size: {len(original_data)} bytes")

    structure_info = analyze_file_structure(original_data)
    entries = detect_data_structure(original_data, structure_info, mode=mode)
    result = build_json_structure(dt_path, original_data, structure_info, entries, mode=mode)

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nDecompiled to {json_path}")
    print(f"Content split into readable lines with \\x01-\\x10 notations")

    if test_compilation:
        test_compilation_process(dt_path, json_path, original_data, mode)

def test_compilation_process(dt_path, json_path, original_data, mode='halfwidth'):
    """Test compilation process"""
    print("\n=== COMPILATION TEST ===")
    test_dt_path = dt_path.parent / f"{dt_path.stem}_test{dt_path.suffix}"

    try:
        compile_dt(json_path, test_dt_path, cli_mode=mode)

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

            for i, (orig, comp) in enumerate(zip(original_data, compiled_data)):
                if orig != comp:
                    print(f"  First difference at position {i}: {orig:02x} -> {comp:02x}")
                    break

            print(f"  Test file saved: {test_dt_path}")

    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        traceback.print_exc()

def build_file_data(data, mode='halfwidth'):
    """Build file data from JSON structure"""
    structure = data["structure"]
    entries = data["entries"]

    print(f"Encoding mode: {mode}")
    print(f"Original size: {data['file_info']['size']} bytes")
    print(f"Number of entries: {len(entries)}")

    result_data = bytearray()

    header_size = structure["header_size"]
    result_data.extend(b'\x00' * header_size)

    if structure["first_block_separate"]:
        first_block_data = bytes.fromhex(structure["first_block_hex"])
        result_data.extend(first_block_data)

    new_offsets = []

    for i, entry in enumerate(entries):
        print(f"\nBuilding entry {i+1}: '{entry['header_text']}'")

        if 'content_lines' in entry:
            content_text = parse_content_lines(entry['content_lines'])
        elif 'content_text' in entry:
            content_text = entry['content_text']
        else:
            raise ValueError(f"Entry {i+1} contains neither content_lines nor content_text")

        if i == 0:
            current_offset = len(result_data)
            new_offsets.append(current_offset)

            content_bytes = encode_str(content_text, data["file_info"]["encoding"], mode)
            result_data.extend(content_bytes)

            print(f"  Content offset: {current_offset}")
            print(f"  Content size: {len(content_bytes)} bytes")
        else:
            header_offset = len(result_data)
            new_offsets.append(header_offset)

            header_bytes = bytes.fromhex(entry["header_hex"])
            result_data.extend(header_bytes)

            content_offset = len(result_data)
            new_offsets.append(content_offset)

            content_bytes = encode_str(content_text, data["file_info"]["encoding"], mode)
            result_data.extend(content_bytes)

            print(f"  Header offset: {header_offset}")
            print(f"  Content offset: {content_offset}")
            print(f"  Header size: {len(header_bytes)} bytes")
            print(f"  Content size: {len(content_bytes)} bytes")

    return result_data, new_offsets, structure

def compile_dt(json_path, dt_path, cli_mode=None, interactive=False):
    """Compile JSON back to DT file"""
    print(f"=== COMPILING {json_path} ===")

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    mode = resolve_mode(cli_mode, interactive=interactive)
    result_data, new_offsets, structure = build_file_data(data, mode=mode)

    original_count = len(structure["offsets"])
    while len(new_offsets) < original_count:
        new_offsets.append(len(result_data))

    new_offsets = new_offsets[:original_count]

    print(f"\nFinal offsets ({len(new_offsets)}): {new_offsets}")
    print(f"Original offsets: {structure['offsets']}")

    header = bytearray()
    header.extend(struct.pack('<H', structure["header_size"]))
    for offset in new_offsets:
        header.extend(struct.pack('<H', offset))

    while len(header) < structure["header_size"]:
        header.append(0)

    result_data[:len(header)] = header

    with open(dt_path, 'wb') as f:
        f.write(result_data)

    print(f"\nCompiled to {dt_path}")
    print(f"New size: {len(result_data)} bytes")
    print(f"Difference: {len(result_data) - data['file_info']['size']:+d} bytes")

def determine_file_type(input_path):
    """Determine if input file is DT or JSON"""
    if input_path.suffix.lower() == JSON_EXTENSION:
        return 'json'
    elif input_path.name.endswith(DT_EXTENSION):
        return 'dt'
    else:
        return 'unknown'

def main():
    parser = argparse.ArgumentParser(description="_DT file decompiler/compiler")
    parser.add_argument("input_file", help="Input file (._dt or .json)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--test", action="store_true", help="Test compilation after decompilation")
    add_mode_args(parser)

    args = parser.parse_args()
    input_path = Path(args.input_file)

    if not input_path.exists():
        print(f"File not found: {input_path}")
        sys.exit(1)

    file_type = determine_file_type(input_path)

    if file_type == 'json':
        output_path = Path(args.output) if args.output else input_path.with_suffix(DT_EXTENSION)
        compile_dt(input_path, output_path, cli_mode=args.mode, interactive=is_interactive())
    elif file_type == 'dt':
        output_path = Path(args.output) if args.output else input_path.with_suffix(JSON_EXTENSION)
        if args.mode is not None:
            print("Note: encoding mode is ignored on decompile "
                  "(the decoder reads halfwidth and 2-byte SJIS transparently).")
        decompile_dt(input_path, output_path, test_compilation=args.test, mode='halfwidth')
    else:
        print(f"Unsupported file: {input_path}")
        print(f"Supported: {JSON_EXTENSION} (for compilation) and {DT_EXTENSION} (for decompilation)")
        sys.exit(1)

if __name__ == "__main__":
    run_main(main)