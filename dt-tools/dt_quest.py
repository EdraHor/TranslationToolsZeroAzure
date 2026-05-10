#!/usr/bin/env python3
"""
Trails from Zero Quest DT Decompiler
Converts ._dt files to JSON format for easier translation work.

Original tool by Ivdos. Adapted for the Trails From Zero Toolkit by Edrahor
(unified CLI, halfwidth/passthrough modes, drag-and-drop interactive mode,
file_info-style JSON metadata).
"""

import struct
import json
import sys
import argparse
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).resolve().parent))
from byte_codec import (encode_str, decode_str, resolve_mode, add_mode_args,
                        encode_text_safe, ENCODING_MODES, run_main, is_interactive)


class QuestDTDecompiler:
    ENTRY_COUNT = 80
    ENTRY_SIZE = 28  # 1(counter) + 11(reserved) + 4 + 4 + 4 + 4
    ENCODING = 'shift_jis'

    # Encoding mode (set per instance; defaults to halfwidth — see add_mode_args).
    # halfwidth   : letters -> 1-byte halfwidth (needs patched zero.exe + font.itf)
    # passthrough : letters -> standard 2-byte SJIS pairs (stock font)
    # After P1+P2 patches in zero.exe, ALL fields including description/progress
    # accept halfwidth bytes, so mode applies uniformly to every text field.
    encoding_mode = 'halfwidth'
    
    # Словарь замен для символов, несовместимых с SJIS
    INCOMPATIBLE_CHARS_REPLACEMENTS = {
        '\u00AD': '',       # Soft Hyphen (SHY) -> удаляем
        '\u2011': '-',      # - -> обычный дефис
        '\u2014': '-',      # Em dash (—) -> обычный дефис
        '\u2013': '-',      # En dash (–) -> обычный дефис
        '\u2015': '-',      # Horizontal bar (―) -> обычный дефис
        '\u2018': "'",      # Left single quote (') -> обычный апостроф
        '\u2019': "'",      # Right single quote (') -> обычный апостроф
        '\u201C': '"',      # Left double quote (") -> обычные кавычки
        '\u201D': '"',      # Right double quote (") -> обычные кавычки
        '\u2026': '...',    # Ellipsis (…) -> три точки
        '\u2022': '*',      # Bullet (•) -> звездочка
        '\u2032': "'",      # Prime (′) -> апостроф
        '\u2033': '"',      # Double prime (″) -> кавычки
        '\u00A0': ' ',      # Non-breaking space -> обычный пробел
        '\u00AB': '"',      # Left-pointing double angle quotation mark («) -> кавычки
        '\u00BB': '"',      # Right-pointing double angle quotation mark (») -> кавычки
        '\u00A9': '(c)',    # Copyright symbol (©) -> (c)
        '\u00AE': '(r)',    # Registered trademark (®) -> (r)
        '\u2122': '(tm)',   # Trademark symbol (™) -> (tm)
        '\u20AC': 'EUR',    # Euro symbol (€) -> EUR
        '\u00A3': 'GBP',    # Pound symbol (£) -> GBP
        '\u00A5': 'JPY',    # Yen symbol (¥) -> JPY
        '\u2212': '-',      # Minus sign (−) -> обычный дефис
        '\u0306': '',       # Combining breve (̆) -> удаляем
        '\u0308': '',       # Combining diaeresis (̈) -> удаляем
        '\u0301': '',       # Combining acute accent (́) -> удаляем
        '\u0300': '',       # Combining grave accent (̀) -> удаляем
        '\u0302': '',       # Combining circumflex accent (̂) -> удаляем
        '\u0303': '',       # Combining tilde (̃) -> удаляем
        '\u0304': '',       # Combining macron (̄) -> удаляем
        '\u0307': '',       # Combining dot above (̇) -> удаляем
        '\u030A': '',       # Combining ring above (̊) -> удаляем
        '\u030B': '',       # Combining double acute accent (̋) -> удаляем
        '\u030C': '',       # Combining caron (̌) -> удаляем
        '\u0327': '',       # Combining cedilla (̧) -> удаляем
        '\u0328': '',       # Combining ogonek (̨) -> удаляем
        '\u0323': '',       # Combining dot below (̣) -> удаляем
        '\u2116': '#',      # № -> #
        '\u04af': 'у',      # ү -> у (это кириллическая у)
        '\u200C': '',       # Zero Width Non-Joiner (ZWNJ) -> удаляем
        '\u200D': '',       # Zero Width Joiner (ZWJ) -> удаляем
        '\uFEFF': '',       # Zero Width No-Break Space (BOM) -> удаляем
        '\u2215': '/',      # Division Slash (∕) -> обычный слэш
        '\u2044': '/',      # Fraction Slash (⁄) -> обычный слэш
        '\u00B7': '.',      # Middle Dot (·) -> точка
        '\u02D9': '.',      # Dot Above (˙) -> точка
        '\u201A': ',',      # Single Low-9 Quotation Mark (‚) -> запятая
        '\u201E': '"',      # Double Low-9 Quotation Mark („) -> кавычки
        '\u2039': '<',      # Single Left-Pointing Angle Quotation Mark (‹) -> <
        '\u203A': '>',      # Single Right-Pointing Angle Quotation Mark (›) -> >
        '\u00B0': '°',      # Degree Sign (°) -> градус
        '\u00F7': '/',      # Division Sign (÷) -> слэш
        '\u00D7': 'x',      # Multiplication Sign (×) -> латинская x
        '\u03BC': 'μ',      # Micro Sign (µ) -> греческая μ
    }

    def __init__(self):
        self.entries = []
        self.file_size = 0

    def get_replacement_for_extended_char(self, c):
        """Получение замены для расширенных символов"""
        char_code = ord(c)

        # Проверка для кириллических символов с диакритическими знаками
        if c == '\u04AF' or c == '\u04af':
            return 'у'  # ү -> у

        # Кириллические символы
        # Ё/ё НЕ нормализуем — byte_codec кодирует их в свои 1-байтные коды
        # if c == '\u0401': return 'Е'   # disabled
        # if c == '\u0451': return 'е'   # disabled

        # Расширенные кириллические символы
        if c == '\u0406': return 'И'  # І -> И
        if c == '\u0456': return 'и'  # і -> и
        if c == '\u0407': return 'И'  # Ї -> И
        if c == '\u0457': return 'и'  # ї -> и
        if c == '\u0404': return 'Э'  # Є -> Э
        if c == '\u0454': return 'э'  # є -> э
        if c == '\u0490': return 'Г'  # Ґ -> Г
        if c == '\u0491': return 'г'  # ґ -> г

        # Белорусские символы
        if c == '\u040E': return 'У'  # Ў -> У
        if c == '\u045E': return 'у'  # ў -> у

        # Другие кириллические
        if c == '\u04D8': return 'Е'  # Ә -> Е
        if c == '\u04D9': return 'е'  # ә -> е
        if c == '\u04A2': return 'Н'  # Ң -> Н
        if c == '\u04A3': return 'н'  # ң -> н
        if c == '\u0492': return 'Г'  # Ғ -> Г
        if c == '\u0493': return 'г'  # ғ -> г
        if c == '\u04B0': return 'У'  # Ұ -> У
        if c == '\u04B1': return 'у'  # ұ -> у
        if c == '\u04AE': return 'У'  # Ү -> У
        if c == '\u049A': return 'К'  # Қ -> К
        if c == '\u049B': return 'к'  # қ -> к
        if c == '\u04E8': return 'О'  # Ө -> О
        if c == '\u04E9': return 'о'  # ө -> о
        if c == '\u04BA': return 'Х'  # Һ -> Х
        if c == '\u04BB': return 'х'  # һ -> х

        # Латинские символы с диакритикой
        if 0x00C0 <= char_code <= 0x00C5: return 'A'  # À-Å -> A
        if 0x00E0 <= char_code <= 0x00E5: return 'a'  # à-å -> a
        if c == '\u00C6': return 'AE'  # Æ -> AE
        if c == '\u00E6': return 'ae'  # æ -> ae
        if c == '\u00C7': return 'C'   # Ç -> C
        if c == '\u00E7': return 'c'   # ç -> c
        if 0x00C8 <= char_code <= 0x00CB: return 'E'  # È-Ë -> E
        if 0x00E8 <= char_code <= 0x00EB: return 'e'  # è-ë -> e
        if 0x00CC <= char_code <= 0x00CF: return 'I'  # Ì-Ï -> I
        if 0x00EC <= char_code <= 0x00EF: return 'i'  # ì-ï -> i
        if c == '\u00D0': return 'D'   # Ð -> D
        if c == '\u00F0': return 'd'   # ð -> d
        if c == '\u00D1': return 'N'   # Ñ -> N
        if c == '\u00F1': return 'n'   # ñ -> n
        if (0x00D2 <= char_code <= 0x00D6) or c == '\u00D8': return 'O'  # Ò-Ö, Ø -> O
        if (0x00F2 <= char_code <= 0x00F6) or c == '\u00F8': return 'o'  # ò-ö, ø -> o
        if 0x00D9 <= char_code <= 0x00DC: return 'U'  # Ù-Ü -> U
        if 0x00F9 <= char_code <= 0x00FC: return 'u'  # ù-ü -> u
        if c == '\u00DD': return 'Y'   # Ý -> Y
        if c == '\u00FD': return 'y'   # ý -> y
        if c == '\u00DE': return 'Th'  # Þ -> Th
        if c == '\u00FE': return 'th'  # þ -> th
        if c == '\u00DF': return 'ss'  # ß -> ss

        # Если не нашли замену, возвращаем None
        return None

    def replace_incompatible_chars(self, text):
        """Замена несовместимых с SJIS символов на поддерживаемые аналоги"""
        if not text:
            return text

        result = []
        for char in text:
            # Сначала проверяем основной словарь
            if char in self.INCOMPATIBLE_CHARS_REPLACEMENTS:
                replacement = self.INCOMPATIBLE_CHARS_REPLACEMENTS[char]
                result.append(replacement)
            else:
                # Затем проверяем расширенные символы
                replacement = self.get_replacement_for_extended_char(char)
                if replacement is not None:
                    result.append(replacement)
                else:
                    result.append(char)

        return ''.join(result)

    def read_cstring_sjis(self, data, ptr):
        """Read null-terminated SJIS string at given pointer"""
        if not ptr or ptr < 0 or ptr >= len(data):
            return ""

        # Find null terminator
        end = ptr
        while end < len(data) and data[end] != 0:
            end += 1

        # Decode SJIS string (1-byte letter codes win over 2-byte SJIS pairs)
        try:
            text = decode_str(bytes(data[ptr:end]), self.ENCODING, self.encoding_mode)
            return text.replace('\u0001', '<LINE>')
        except Exception as e:
            print(f"Warning: SJIS decode error at 0x{ptr:X}: {e}")
            return ""

    def parse_dt_file(self, file_path):
        """Parse ._dt file according to the structure"""
        with open(file_path, 'rb') as f:
            data = f.read()

        self.file_size = len(data)

        if len(data) < self.ENTRY_COUNT * self.ENTRY_SIZE:
            raise ValueError(f"File too small for header table. Need at least {self.ENTRY_COUNT * self.ENTRY_SIZE} bytes")

        # Step 1: Read header entries
        headers = []
        for idx in range(self.ENTRY_COUNT):
            offset = idx * self.ENTRY_SIZE

            # Read header structure
            counter = data[offset]
            reserved = data[offset + 1:offset + 12]  # 11 bytes
            name_ptr = struct.unpack('<I', data[offset + 12:offset + 16])[0]
            client_ptr = struct.unpack('<I', data[offset + 16:offset + 20])[0]
            description_ptr = struct.unpack('<I', data[offset + 20:offset + 24])[0]
            progress_ptr = struct.unpack('<I', data[offset + 24:offset + 28])[0]

            headers.append({
                'idx': idx,
                'counter': counter,
                'reserved': list(reserved),
                'name_ptr': name_ptr,
                'client_ptr': client_ptr,
                'description_ptr': description_ptr,
                'progress_ptr': progress_ptr
            })

        # Step 2: Decode strings and create entries
        entries = []
        for h in headers:
            entry = {
                'index': h['idx'],
                'counter': h['counter'],
                'reserved': h['reserved'],
                'reserved_hex': ' '.join(f'{b:02x}' for b in h['reserved']),
                'name': self.read_cstring_sjis(data, h['name_ptr']),
                'client': self.read_cstring_sjis(data, h['client_ptr']),
                'description': self.read_cstring_sjis(data, h['description_ptr']),
                'progress': [],
                'pointers': {
                    'name_ptr': f"0x{h['name_ptr']:08X}",
                    'client_ptr': f"0x{h['client_ptr']:08X}",
                    'description_ptr': f"0x{h['description_ptr']:08X}",
                    'progress_ptr': f"0x{h['progress_ptr']:08X}"
                }
            }
            entries.append(entry)

        # Step 3: Read progress arrays.
        #
        # Layout note: the original file interleaves per-quest progress STRINGS
        # with per-quest progress ARRAY (4-byte pointers each). There is no
        # explicit length field, so we stop reading when the next u32 stops
        # looking like a valid string pointer.
        #
        # Validity rule: a real progress entry pointer must point inside the
        # file's string area, i.e. [header_size, file_size). Anything outside
        # (huge values, zero, or pointers into the header range) means we've
        # walked past the end of THIS quest's array.
        header_size = self.ENTRY_COUNT * self.ENTRY_SIZE

        for i in range(self.ENTRY_COUNT):
            this_ptr = headers[i]['progress_ptr']
            if not this_ptr:
                entries[i]['progress'] = []
                continue

            progress_list = []
            j = 0
            # Hard cap to avoid pathological loops on a corrupted file.
            HARD_CAP = (len(data) - this_ptr) // 4
            while j < HARD_CAP:
                ptr_offset = this_ptr + j * 4
                if ptr_offset + 4 > len(data):
                    break
                text_ptr = struct.unpack('<I', data[ptr_offset:ptr_offset + 4])[0]

                # Stop on the first u32 that doesn't look like a valid string ptr.
                if not (header_size <= text_ptr < len(data)):
                    break

                text = self.read_cstring_sjis(data, text_ptr)
                progress_list.append(text)
                j += 1

            entries[i]['progress'] = progress_list

        self.entries = entries
        return entries

    def to_json(self, output_path=None, indent=2):
        """Export parsed data to JSON"""
        output = {
            'file_info': {
                'format': 'Trails from Zero Quest DT',
                'encoding': self.ENCODING,
                'endianness': 'little',
                'entry_count': self.ENTRY_COUNT,
                'entry_size': self.ENTRY_SIZE,
                'file_size': self.file_size
            },
            'quests': self.entries
        }

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(output, f, ensure_ascii=False, indent=indent)
            print(f"JSON exported to: {output_path}")
        else:
            return json.dumps(output, ensure_ascii=False, indent=indent)

    def from_json(self, json_path, cli_mode=None, interactive=False):
        """Load data from JSON for recompilation.

        Encoding mode is taken from the CLI flag, or from the interactive
        prompt when the script was launched without arguments. JSON does not
        carry the mode -- it must be specified explicitly each compile run.
        """
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.encoding_mode = resolve_mode(cli_mode, interactive=interactive)
        self.entries = data['quests']
        return self.entries

    def encode_sjis_with_null(self, text, use_letter_table=True):
        """Encode string with null terminator.

        After the P1+P2 binary patches in zero.exe, ALL fields (name, client,
        description, progress) accept 1-byte halfwidth letters, so the
        encoding is driven entirely by self.encoding_mode:
            halfwidth   -> letters become 1-byte halfwidth codes.
            passthrough -> letters become 2-byte SJIS pairs.

        `use_letter_table` is kept as an explicit override (set False to
        force 2-byte SJIS even in halfwidth mode), but the compiler itself
        doesn't use it anywhere -- mode controls everything.
        """
        if not text:
            return b'\x00'

        try:
            # Замена <LINE> обратно на управляющий символ
            text = text.replace('<LINE>', '\u0001')

            # ВАЖНО: Замена несовместимых символов перед кодированием в SJIS
            text = self.replace_incompatible_chars(text)

            if use_letter_table and self.encoding_mode == 'halfwidth':
                encoded = encode_str(text, self.ENCODING, 'halfwidth')
            else:
                encoded = encode_text_safe(text, encoding=self.ENCODING)

            # Проверка на наличие знаков вопроса (могут появиться при неудачной замене)
            decoded_check = encoded.decode(self.ENCODING, errors='replace')
            if '?' in decoded_check and '?' not in text:
                print(f"Warning: Some characters may not encode properly to SJIS: '{text}'")
                print(f"Encoded result: '{decoded_check}'")

            return encoded + b'\x00'

        except Exception as e:
            print(f"Warning: SJIS encode error for '{text}': {e}")
            return b'\x00'

    def compile_to_dt(self, output_path):
        """Compile JSON data back to ._dt format"""
        if not self.entries:
            raise ValueError("No entries loaded. Load JSON data first.")

        # Calculate header size
        header_size = self.ENTRY_COUNT * self.ENTRY_SIZE
        header = bytearray(header_size)

        # Body parts and cursor for allocation
        body_parts = []
        cursor = header_size

        def allocate(data):
            nonlocal cursor
            start = cursor
            body_parts.append(data)
            cursor += len(data)
            return start

        # Allocate strings. All fields (name, client, description) follow the
        # encoding_mode -- halfwidth in halfwidth mode, 2-byte SJIS in passthrough.
        # P1+P2 patches make the SJIS->UTF-8 description path halfwidth-safe.
        for entry in self.entries:
            entry['_name_ptr'] = allocate(self.encode_sjis_with_null(entry.get('name', '')))
            entry['_client_ptr'] = allocate(self.encode_sjis_with_null(entry.get('client', '')))
            entry['_desc_ptr'] = allocate(self.encode_sjis_with_null(entry.get('description', '')))

        # Allocate progress strings and arrays
        for entry in self.entries:
            progress = entry.get('progress', [])
            if not progress:
                entry['_progress_ptr'] = 0
                continue

            # Allocate progress text strings
            progress_ptrs = []
            for text in progress:
                ptr = allocate(self.encode_sjis_with_null(text))
                progress_ptrs.append(ptr)

            # Allocate progress pointer array
            progress_array = b''.join(struct.pack('<I', ptr) for ptr in progress_ptrs)
            entry['_progress_ptr'] = allocate(progress_array)

        # Write header
        for entry in self.entries:
            offset = entry['index'] * self.ENTRY_SIZE

            # Counter (1 byte)
            header[offset] = entry.get('counter', 0) & 0xFF

            # Reserved (11 bytes)
            reserved = entry.get('reserved', [0] * 11)
            for i in range(11):
                header[offset + 1 + i] = reserved[i] if i < len(reserved) else 0

            # Pointers (4 bytes each, little endian)
            struct.pack_into('<I', header, offset + 12, entry['_name_ptr'])
            struct.pack_into('<I', header, offset + 16, entry['_client_ptr'])
            struct.pack_into('<I', header, offset + 20, entry['_desc_ptr'])
            struct.pack_into('<I', header, offset + 24, entry['_progress_ptr'])

        # Combine header and body
        body = b''.join(body_parts)
        final_data = bytes(header) + body

        # Write to file
        with open(output_path, 'wb') as f:
            f.write(final_data)

        print(f"Compiled DT file saved to: {output_path}")
        print(f"File size: {len(final_data)} bytes")


def main():
    parser = argparse.ArgumentParser(description='Trails from Zero Quest DT Decompiler/Compiler')
    parser.add_argument('input', help='Input file path')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-c', '--compile', action='store_true',
                       help='Compile JSON back to DT format (default: decompile DT to JSON)')
    parser.add_argument('--indent', type=int, default=2,
                       help='JSON indentation (default: 2)')
    add_mode_args(parser)

    args = parser.parse_args()

    decompiler = QuestDTDecompiler()
    input_path = Path(args.input)

    # Auto-detect mode based on file extension
    is_json = input_path.suffix.lower() == '.json'
    if is_json and not args.compile:
        args.compile = True  # Auto-compile JSON to DT

    try:
        if args.compile:
            # Compile JSON to DT
            output_path = args.output
            if not output_path:
                output_path = input_path.with_suffix('._dt')

            print(f"Compiling JSON to DT: {input_path} -> {output_path}")
            decompiler.from_json(input_path, cli_mode=args.mode, interactive=is_interactive())
            print(f"Encoding mode: {decompiler.encoding_mode}")
            decompiler.compile_to_dt(output_path)

        else:
            # Decompile DT to JSON
            output_path = args.output
            if not output_path:
                output_path = input_path.with_suffix('.json')

            if args.mode is not None:
                print("Note: encoding mode is ignored on decompile "
                      "(the decoder reads halfwidth and 2-byte SJIS transparently).")
            decompiler.encoding_mode = 'halfwidth'
            print(f"Decompiling DT to JSON: {input_path} -> {output_path}")
            decompiler.parse_dt_file(input_path)
            decompiler.to_json(output_path, indent=args.indent)

            # Print summary
            print(f"\nSummary:")
            print(f"- Total quests: {len(decompiler.entries)}")
            print(f"- File size: {decompiler.file_size} bytes")

            non_empty = sum(1 for e in decompiler.entries if e['name'] or e['client'] or e['description'])
            print(f"- Non-empty entries: {non_empty}")

    except SystemExit:
        raise
    except Exception as e:
        print(f"Error: {e}")
        raise


if __name__ == '__main__':
    run_main(main)