#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# t_ittxt._dt decompiler / compiler (item names + descriptions).
# Part of the Trails From Zero Toolkit. Author: Edrahor.

import sys
import json
from pathlib import Path
import argparse
import struct

# Console output may include non-ASCII text -- force stdout to UTF-8 so
# prints don't crash on Windows cp1251.
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).resolve().parent))
from byte_codec import (LETTER_TO_BYTE, BYTE_TO_LETTER, resolve_mode, add_mode_args,
                        ENCODING_MODES, run_main, is_interactive)

# Fixed encoding for the game
GAME_ENCODING = 'shift-jis'
ITEM_EXTENSION = '._dt'
JSON_EXTENSION = '.json'

def safe_decode_with_fallback(data_bytes, mode='halfwidth'):
    """Safely decode bytes with fallback to escape sequences for problematic bytes.

    Decoding order at each position:
      1. (mode=halfwidth only) Single-byte letter code (BYTE_TO_LETTER) — wins
         over the 2-byte SJIS interpretation, since 0xA1..0xDF are reserved
         for the alphabet in our remapped font and 0x60/0x5E/0x5F (`/^/_)
         are ASCII passthrough.
      2. 2-byte SJIS pair (real Japanese / standard SJIS).
      3. 1-byte SJIS / ASCII.
      4. Hex escape `\\xNN` for raw bytes that decode none of the above.
    """
    result = ""
    i = 0
    n = len(data_bytes)
    while i < n:
        b = data_bytes[i]

        # 1) Letter single-byte first (halfwidth mode only)
        if mode == 'halfwidth':
            letter = BYTE_TO_LETTER.get(b)
            if letter is not None:
                result += letter
                i += 1
                continue

        decoded = False
        # 2) 2-byte SJIS pair (only for proper SJIS lead bytes)
        if (0x81 <= b <= 0x9F or 0xE0 <= b <= 0xFC) and i + 1 < n:
            try:
                char = data_bytes[i:i+2].decode(GAME_ENCODING)
                result += char
                i += 2
                decoded = True
            except UnicodeDecodeError:
                pass

        # 3) 1-byte fallback
        if not decoded:
            try:
                char = data_bytes[i:i+1].decode(GAME_ENCODING)
                result += char
                i += 1
                decoded = True
            except UnicodeDecodeError:
                pass

        # 4) Raw byte escape
        if not decoded:
            result += f"\\x{data_bytes[i]:02x}"
            i += 1
    return result

def safe_encode_with_fallback(text, use_letter_table=True, mode='halfwidth'):
    """Safely encode text back to bytes, handling escape sequences.

    Effective single-byte path = use_letter_table AND mode == 'halfwidth'.

    Mode controls letter encoding for the WHOLE field (name AND
    description). After the P1+P2 binary patches in zero.exe, both render
    paths (direct font and SJIS->UTF-8 description path) accept halfwidth
    bytes, so descriptions can also use 1-byte halfwidth in halfwidth mode.

      halfwidth   : letters -> 1-byte halfwidth via LETTER_TO_BYTE.
      passthrough : letters -> standard 2-byte SJIS pairs.

    `use_letter_table` is kept as an explicit override (set False to force
    2-byte SJIS even in halfwidth mode), but is no longer used anywhere by
    the compiler itself.

    Encoding order at each character:
      1. Hex escape `\\xNN` -> raw byte NN (preserves control bytes verbatim).
      2. Letter -> 1-byte (halfwidth mode) or 2-byte SJIS (otherwise).
      3. Anything else -> standard SJIS encode (2 bytes for Japanese, 1 for ASCII).
    """
    use_halfwidth = use_letter_table and (mode == 'halfwidth')
    result = bytearray()
    i = 0
    n = len(text)
    while i < n:
        # 1) Hex escape
        if i + 3 < n and text[i:i+2] == "\\x":
            hex_str = text[i+2:i+4]
            if len(hex_str) == 2 and all(c in '0123456789abcdefABCDEF' for c in hex_str):
                result.append(int(hex_str, 16))
                i += 4
                continue

        # 2) Letter -> single byte (halfwidth mode only)
        if use_halfwidth:
            b = LETTER_TO_BYTE.get(text[i])
            if b is not None:
                result.append(b)
                i += 1
                continue

        # 3) Standard SJIS
        try:
            result.extend(text[i].encode(GAME_ENCODING))
        except UnicodeEncodeError:
            result.append(ord('?'))
        i += 1
    return bytes(result)

def analyze_file_structure(file_data):
    """Analyze item database file structure"""
    print("Analyzing file structure...")

    if len(file_data) < 4:
        raise ValueError("File too small for header")

    header_size = struct.unpack('<H', file_data[0:2])[0]
    print(f"  Detected header size: {header_size} bytes")

    # Check that header size is reasonable
    if header_size < 4 or header_size > len(file_data):
        raise ValueError(f"Invalid header size: {header_size}")

    if len(file_data) < header_size:
        raise ValueError(f"File too small for declared header size {header_size}")

    # Calculate number of offsets in header
    # First 2 bytes - header size, rest are offsets (2 bytes each)
    num_offsets = (header_size - 2) // 2
    print(f"  Number of metadata offsets: {num_offsets}")

    # Read metadata offsets
    metadata_offsets = []
    for i in range(num_offsets):
        pos = 2 + i * 2
        if pos + 2 > header_size:
            break
        offset = struct.unpack('<H', file_data[pos:pos+2])[0]
        metadata_offsets.append(offset)

    print(f"  Metadata offsets: {[hex(x) for x in metadata_offsets]}")

    # Find data start - look for data beginning pattern
    data_start = None

    # Try to find pattern 01 00 00 00 (first item ID)
    search_start = max(header_size, 0x400)  # start search after header
    search_end = min(search_start + 0x200, len(file_data) - 8)

    for i in range(search_start, search_end):
        if file_data[i:i+4] == b'\x01\x00\x00\x00':
            data_start = i
            print(f"  Found data start pattern at: 0x{i:x}")
            break

    # If standard pattern not found, try alternative approach
    if data_start is None:
        # Try using last offset as data start
        if metadata_offsets:
            # Find maximum unique offset
            unique_offsets = sorted(list(set(metadata_offsets)))
            if len(unique_offsets) >= 2:
                # Take second-to-last unique offset as potential data start
                potential_start = unique_offsets[-2]
                # Check if there's reasonable data there
                if potential_start + 8 < len(file_data):
                    # Check if it looks like item ID (reasonable number)
                    potential_id = struct.unpack('<I', file_data[potential_start:potential_start+4])[0]
                    if 1 <= potential_id <= 10000:
                        data_start = potential_start
                        print(f"  Estimated data start from offsets: 0x{potential_start:x}")

    if data_start is None:
        # Last attempt - search at end of metadata
        if metadata_offsets:
            max_offset = max(metadata_offsets)
            # Search after maximum offset
            for i in range(max_offset, min(max_offset + 100, len(file_data) - 8)):
                if i + 4 <= len(file_data):
                    potential_id = struct.unpack('<I', file_data[i:i+4])[0]
                    if 1 <= potential_id <= 10000:
                        data_start = i
                        print(f"  Found data start by scanning: 0x{i:x}")
                        break

    if data_start is None:
        raise ValueError("Could not find data start")

    # Analyze metadata sections
    sections = []
    prev_offset = header_size

    # Create sections from unique offsets
    unique_offsets = sorted(list(set(metadata_offsets)))

    for i, offset in enumerate(unique_offsets):
        if offset > prev_offset:  # Only if offset is greater than previous
            section_size = offset - prev_offset
            sections.append({
                'index': len(sections) + 1,
                'start': prev_offset,
                'end': offset,
                'size': section_size
            })
            prev_offset = offset

    # Final metadata section (until data start)
    if prev_offset < data_start:
        final_section = {
            'index': len(sections) + 1,
            'start': prev_offset,
            'end': data_start,
            'size': data_start - prev_offset
        }
        sections.append(final_section)

    print(f"  Header: {header_size} bytes")
    print(f"  Data starts at: 0x{data_start:x}")
    print(f"  Metadata sections: {len(sections)}")
    for section in sections:
        print(f"    Section {section['index']}: 0x{section['start']:x}-0x{section['end']:x} ({section['size']} bytes)")

    return {
        'header_size': header_size,
        'metadata_offsets': metadata_offsets,
        'metadata_sections': sections,
        'data_start': data_start,
        'file_size': len(file_data)
    }

def extract_item_entry(data, start_pos, mode='halfwidth'):
    """Extract single item entry from data"""
    if start_pos + 8 > len(data):
        return None, start_pos

    item_id = struct.unpack('<I', data[start_pos:start_pos+4])[0]
    name_offset = struct.unpack('<H', data[start_pos+4:start_pos+6])[0]
    desc_offset = struct.unpack('<H', data[start_pos+6:start_pos+8])[0]

    if name_offset >= len(data) or desc_offset >= len(data):
        return None, start_pos

    # Extract name
    name_end = data.find(b'\x00', name_offset)
    if name_end == -1:
        name_end = len(data)
    item_name = safe_decode_with_fallback(data[name_offset:name_end], mode=mode)

    # Extract description
    desc_end = data.find(b'\x00', desc_offset)
    if desc_end == -1:
        desc_end = len(data)
    item_desc = safe_decode_with_fallback(data[desc_offset:desc_end], mode=mode)

    # Find next entry start
    next_pos = desc_end + 1
    while next_pos < len(data) and data[next_pos] == 0:
        next_pos += 1

    # Handle problematic items around 510+
    if item_id >= 509:
        for test_pos in range(next_pos-5, min(next_pos+10, len(data)-8)):
            if test_pos + 8 <= len(data):
                test_id = struct.unpack('<I', data[test_pos:test_pos+4])[0]
                test_name_off = struct.unpack('<H', data[test_pos+4:test_pos+6])[0]
                test_desc_off = struct.unpack('<H', data[test_pos+6:test_pos+8])[0]
                if 1 <= test_id <= 10000 and test_name_off > test_pos and test_desc_off > test_name_off:
                    if test_pos != next_pos:
                        next_pos = test_pos
                    break

    if next_pos + 8 > len(data):
        next_pos = len(data)

    return {
        'id': item_id,
        'name': item_name,
        'description': item_desc,
        'position': start_pos
    }, next_pos

def extract_all_items(file_data, data_start, mode='halfwidth'):
    """Extract all item entries from file"""
    print(f"Extracting items starting from 0x{data_start:x} using {GAME_ENCODING} encoding (mode={mode})...")

    items = []
    current_pos = data_start
    item_count = 0

    while current_pos < len(file_data):
        item, next_pos = extract_item_entry(file_data, current_pos, mode=mode)

        if item is None:
            print(f"Failed to extract item at position 0x{current_pos:x}")
            break

        items.append(item)

        if item_count < 5 or item_count >= len(items) - 5 or item_count % 50 == 0:
            print(f"  Item {item['id']:3d}: {item['name']}")

        if next_pos <= current_pos:
            break

        current_pos = next_pos
        item_count += 1

        if item_count > 1000:
            break

    print(f"Extracted {len(items)} items")
    return items

def analyze_metadata_sections(original_data, structure_info, items):
    """Analyze which metadata sections contain item pointers"""
    print("Analyzing metadata sections for item pointers...")

    # Create position mapping
    item_positions = {item['id']: item['position'] for item in items}
    data_start = structure_info['data_start']

    pointer_sections = {}

    for section in structure_info['metadata_sections']:
        section_key = f"section_{section['index']}"
        section_data = original_data[section['start']:section['end']]

        # Analyze this section for item pointers
        pointers_found = 0
        total_slots = len(section_data) // 2

        for i in range(0, len(section_data) - 1, 2):
            value = struct.unpack('<H', section_data[i:i+2])[0]
            if value in item_positions.values():
                pointers_found += 1

        pointer_sections[section_key] = {
            'contains_pointers': pointers_found > 0,
            'total_slots': total_slots,
            'pointers_found': pointers_found,
            'data': section_data.hex()
        }

        print(f"  {section_key}: {pointers_found}/{total_slots} item pointers found")

    return pointer_sections

def build_json_structure(item_path, original_data, structure_info, items, mode='halfwidth'):
    """Build simplified JSON structure"""
    # Analyze metadata sections
    pointer_sections = analyze_metadata_sections(original_data, structure_info, items)

    result = {
        "file_info": {
            "filename": item_path.name,
            "size": len(original_data),
            "encoding": GAME_ENCODING,
        },
        "structure": structure_info,
        "metadata_sections": pointer_sections,
        "original_item_sizes": {},  # Save original sizes instead of positions
        "items": []
    }

    # Save original item sizes for change detection
    for item in items:
        name_bytes = safe_encode_with_fallback(item['name'], mode=mode) + b'\x00'
        desc_bytes = safe_encode_with_fallback(item['description'], mode=mode) + b'\x00'
        result["original_item_sizes"][str(item['id'])] = {
            "name_size": len(name_bytes),
            "desc_size": len(desc_bytes),
            "total_size": 8 + len(name_bytes) + len(desc_bytes),
            "original_position": item['position']
        }

    # Add items with minimal structure
    for item in items:
        result["items"].append({
            "id": item['id'],
            "name": item['name'],
            "description": item['description']
        })

    return result

def update_metadata_pointers(original_data, structure_info, metadata_sections, items, original_sizes, mode='halfwidth'):
    """Update item pointers in metadata when item sizes change"""
    print("Updating item pointers in metadata...")

    # Calculate new item positions
    data_start = structure_info['data_start']
    current_pos = data_start
    new_positions = {}

    sorted_items = items #sorted(items, key=lambda x: x['id'])

    # Detect if any item sizes changed
    sizes_changed = False
    total_size_diff = 0

    for item in sorted_items:
        item_id = str(item['id'])

        # Calculate new sizes
        name_bytes = safe_encode_with_fallback(item['name'], mode=mode) + b'\x00'
        desc_bytes = safe_encode_with_fallback(item['description'], mode=mode) + b'\x00'
        new_total_size = 8 + len(name_bytes) + len(desc_bytes)

        new_positions[item['id']] = current_pos
        current_pos += new_total_size

        # Compare with original sizes
        if item_id in original_sizes:
            original_total_size = original_sizes[item_id]['total_size']
            size_diff = new_total_size - original_total_size

            if size_diff != 0:
                sizes_changed = True
                total_size_diff += size_diff
                if not sizes_changed:  # Log first few changes
                    print(f"  Item {item['id']}: size changed by {size_diff:+d} bytes")
        else:
            # New item - sizes definitely changed
            sizes_changed = True

    print(f"  Calculated new positions for {len(new_positions)} items")

    if not sizes_changed:
        print("  No size changes detected - preserving all metadata")
        # Return original metadata unchanged
        updated_metadata = b''
        for section in structure_info['metadata_sections']:
            section_key = f"section_{section['index']}"
            if section_key in metadata_sections:
                section_info = metadata_sections[section_key]
                updated_metadata += bytes.fromhex(section_info['data'])
            else:
                # If section not found, create empty section of needed size
                section_size = section['end'] - section['start']
                updated_metadata += b'\x00' * section_size
                print(f"  Warning: Section {section_key} not found, filled with zeros")
        return updated_metadata

    print(f"  Size changes detected: total difference {total_size_diff:+d} bytes")
    print("  Rebuilding all item pointers...")

    # Build precise old->new position mapping
    position_mapping = {}

    for item in sorted_items:
        item_id = str(item['id'])
        if item_id in original_sizes:
            old_pos = original_sizes[item_id]['original_position']
            new_pos = new_positions[item['id']]
            position_mapping[old_pos] = new_pos

    print(f"  Built position mapping for {len(position_mapping)} items")

    # Update metadata sections
    updated_metadata = b''

    for section in structure_info['metadata_sections']:
        section_key = f"section_{section['index']}"

        if section_key not in metadata_sections:
            # If section not found, create empty section of needed size
            section_size = section['end'] - section['start']
            updated_metadata += b'\x00' * section_size
            print(f"  {section_key}: not found, filled with zeros ({section_size} bytes)")
            continue

        section_info = metadata_sections[section_key]
        original_bytes = bytes.fromhex(section_info['data'])
        updated_bytes = bytearray(original_bytes)

        if section_info['contains_pointers']:
            updates_count = 0

            # Update all item pointers in this section
            for i in range(0, len(updated_bytes) - 1, 2):
                old_value = struct.unpack('<H', original_bytes[i:i+2])[0]

                # Check if this is an item pointer we need to update
                if old_value in position_mapping:
                    new_value = position_mapping[old_value]
                    # Check that new value fits in 2 bytes
                    if new_value <= 0xFFFF:
                        struct.pack_into('<H', updated_bytes, i, new_value)
                        updates_count += 1

                        if updates_count <= 3:  # Show first few updates
                            print(f"    Slot {i//2}: 0x{old_value:x} -> 0x{new_value:x}")
                    else:
                        print(f"    Warning: New position 0x{new_value:x} too large for 2-byte field")

            print(f"  {section_key}: updated {updates_count} pointers")
        else:
            print(f"  {section_key}: preserved (no item pointers)")

        updated_metadata += updated_bytes

    return updated_metadata

def build_items_data(items, data_start, mode='halfwidth'):
    """Build item entries binary data"""
    print(f"Building items data starting at 0x{data_start:x}")

    sorted_items = items #sorted(items, key=lambda x: x['id'])

    # Calculate positions for all items
    encoded_items = []
    current_pos = data_start

    for item in sorted_items:
        name_bytes = safe_encode_with_fallback(item['name'], mode=mode) + b'\x00'
        desc_bytes = safe_encode_with_fallback(item['description'], mode=mode) + b'\x00'

        header_pos = current_pos
        name_pos = current_pos + 8
        desc_pos = name_pos + len(name_bytes)
        total_size = 8 + len(name_bytes) + len(desc_bytes)

        encoded_items.append({
            'id': item['id'],
            'header_pos': header_pos,
            'name_pos': name_pos,
            'desc_pos': desc_pos,
            'name_bytes': name_bytes,
            'desc_bytes': desc_bytes,
            'total_size': total_size
        })

        current_pos += total_size

    # Build final data
    items_data = b''
    for i, item_data in enumerate(encoded_items):
        # Build entry header
        entry_header = struct.pack('<I', item_data['id'])
        entry_header += struct.pack('<H', item_data['name_pos'])
        entry_header += struct.pack('<H', item_data['desc_pos'])

        # Combine entry data
        entry_data = entry_header + item_data['name_bytes'] + item_data['desc_bytes']
        items_data += entry_data

        if i < 3 or i >= len(encoded_items) - 3:
            print(f"  Item {item_data['id']:3d}: header@0x{item_data['header_pos']:x}")

    print(f"Built {len(encoded_items)} items, total size: {len(items_data)} bytes")
    return items_data

def decompile_item_db(item_path, json_path, test_compilation=False, mode='halfwidth'):
    """Decompile item database file to JSON"""
    print(f"=== DECOMPILING {item_path} ===")
    print(f"Encoding mode: {mode}")

    with open(item_path, 'rb') as f:
        original_data = f.read()

    print(f"File size: {len(original_data)} bytes")
    print(f"Using encoding: {GAME_ENCODING}")

    structure_info = analyze_file_structure(original_data)
    items = extract_all_items(original_data, structure_info['data_start'], mode=mode)
    result = build_json_structure(item_path, original_data, structure_info, items, mode=mode)

    # Save JSON
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nDecompiled to {json_path}")
    print(f"Extracted {len(items)} items using {GAME_ENCODING} encoding")
    print(f"Ready for translation - edit 'name' and 'description' fields in JSON")

    if test_compilation:
        test_compilation_process(item_path, json_path, original_data, mode)

def compile_item_db(json_path, item_path, cli_mode=None, interactive=False):
    """Compile JSON back to item database file"""
    print(f"=== COMPILING {json_path} ===")

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    mode = resolve_mode(cli_mode, interactive=interactive)
    print(f"Encoding mode: {mode}")
    print(f"Using encoding: {GAME_ENCODING}")

    # Rebuild header exactly as original with dynamic size
    header_size = data["structure"]["header_size"]
    metadata_offsets = data["structure"]["metadata_offsets"]

    print(f"Rebuilding header: {header_size} bytes with {len(metadata_offsets)} offsets")

    # Check that header size matches number of offsets
    expected_header_size = 2 + len(metadata_offsets) * 2
    if header_size != expected_header_size:
        print(f"Warning: Header size mismatch. Expected {expected_header_size}, got {header_size}")
        print(f"Using calculated size: {expected_header_size}")
        header_size = expected_header_size

    # Build header
    header = struct.pack('<H', header_size)
    for offset in metadata_offsets:
        header += struct.pack('<H', offset)

    # Pad header to needed size if necessary
    while len(header) < header_size:
        header += b'\x00'

    # Trim header if it became larger than needed
    header = header[:header_size]

    print(f"Built header: {len(header)} bytes")

    # Get original sizes for change detection
    original_sizes = data.get("original_item_sizes", {})

    # Update metadata with correct item pointers (based on size changes)
    metadata = update_metadata_pointers(
        None,
        data["structure"],
        data["metadata_sections"],
        data["items"],
        original_sizes,
        mode=mode,
    )

    # Build items data
    items_data = build_items_data(data["items"], data["structure"]["data_start"], mode=mode)

    # Combine all parts
    result_data = header + metadata + items_data

    with open(item_path, 'wb') as f:
        f.write(result_data)

    print(f"Compiled to {item_path}")
    print(f"New size: {len(result_data)} bytes")
    print(f"Original size: {data['file_info']['size']} bytes")
    print(f"Difference: {len(result_data) - data['file_info']['size']:+d} bytes")

def clean_json_for_user(json_path):
    """Remove internal fields from JSON for cleaner user experience"""
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Remove internal _original_position fields from items
    for item in data['items']:
        if '_original_position' in item:
            del item['_original_position']

    # Save cleaned version
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def test_compilation_process(item_path, json_path, original_data, mode='halfwidth'):
    """Test compilation process"""
    print("\n=== COMPILATION TEST ===")
    test_item_path = item_path.parent / f"{item_path.stem}_test{item_path.suffix}"

    try:
        # Test compilation
        compile_item_db(json_path, test_item_path, cli_mode=mode)

        with open(test_item_path, 'rb') as f:
            compiled_data = f.read()

        print(f"\n=== COMPILATION RESULTS ===")
        print(f"Original file: {len(original_data)} bytes")
        print(f"Compiled file: {len(compiled_data)} bytes")
        print(f"Size difference: {len(compiled_data) - len(original_data):+d} bytes")

        if compiled_data == original_data:
            print("TEST PASSED: byte-identical round-trip!")
            test_item_path.unlink()
        else:
            print("TEST FAILED:")
            # Find first difference
            min_len = min(len(original_data), len(compiled_data))
            for i in range(min_len):
                if original_data[i] != compiled_data[i]:
                    print(f"  First difference at position {i} (0x{i:x}): {original_data[i]:02x} -> {compiled_data[i]:02x}")
                    start = max(0, i - 10)
                    end = min(len(original_data), i + 10)
                    print(f"  Context - Original: {original_data[start:end].hex()}")
                    print(f"  Context - Compiled: {compiled_data[start:end].hex()}")
                    break
            print(f"  Test file saved: {test_item_path}")

    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        traceback.print_exc()

def determine_file_type(input_path):
    """Determine if input file is ITEM or JSON"""
    if input_path.suffix.lower() == JSON_EXTENSION:
        return 'json'
    elif input_path.suffix.lower() == ITEM_EXTENSION or input_path.name.endswith('.item'):
        return 'item'
    else:
        return 'unknown'

def main():
    parser = argparse.ArgumentParser(description="Universal Item Database file decompiler/compiler")
    parser.add_argument("input_file", help="Input file (.item or .json)")
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
        output_path = Path(args.output) if args.output else input_path.with_suffix(ITEM_EXTENSION)
        compile_item_db(input_path, output_path, cli_mode=args.mode, interactive=is_interactive())
    elif file_type == 'item':
        output_path = Path(args.output) if args.output else input_path.with_suffix(JSON_EXTENSION)
        if args.mode is not None:
            print("Note: encoding mode is ignored on decompile "
                  "(the decoder reads halfwidth and 2-byte SJIS transparently).")
        decompile_item_db(input_path, output_path, test_compilation=args.test, mode='halfwidth')
    else:
        print(f"Unsupported file: {input_path}")
        print(f"Supported: {JSON_EXTENSION} (for compilation) and {ITEM_EXTENSION} (for decompilation)")
        sys.exit(1)

if __name__ == "__main__":
    run_main(main)