#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# font.itf builder -- turns a TTF + a [Replacements] mapping into a font.itf
# that the engine can load. Language-neutral: the substitution table lives
# entirely in config_font.ini.
#
# Original tool https://github.com/TwnKey/FalcomFontCreator
# rewritten in Python by Ivdos. Adapted for the Trails From Zero Toolkit by Edrahor.

import sys
import struct
import configparser
from pathlib import Path
from typing import Dict, List, Tuple, Optional
try:
    import freetype
except ImportError:
    print("pip install freetype-py")
    sys.exit(1)


def u16le(x: int) -> bytes:
    return struct.pack("<H", x & 0xFFFF)


def u32le(x: int) -> bytes:
    return struct.pack("<I", x & 0xFFFFFFFF)


def r_u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def r_u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def load_ini(path: Path) -> dict:
    cp = configparser.ConfigParser()
    cp.read(path, encoding="utf-8")
    g = cp["general"]
    conf = {
        "resolution": g.getint("Resolution"),
        "size": g.getint("FontSize"),
        "base": g.getint("Base"),
        "NbChar": g.getint("NbChar"),
        "SpaceWidth": g.getint("SpaceWidth"),
        "SpaceBetweenCharacters": g.getint("SpaceBetweenCharacters"),
        "font": g.get("Font"),
        "itf_ref": g.get("ITFReferenceFile", fallback="none"),
    }
    replacements: Dict[int, int] = {}
    if "Replacements" in cp:
        for k, v in cp["Replacements"].items():
            # Берем первый кодпоинт
            if len(k) == 0 or len(v) == 0:
                continue
            k_cp = ord(next(iter(k)))
            v_cp = ord(next(iter(v)))
            # Соответствует логике: replacement_chars[src2.char32At(0)] = src.char32At(0);
            replacements[k_cp] = v_cp
    conf["replacements"] = replacements
    return conf


def create_node(characters: List[Tuple[int, int]],
                pile: List[int],
                code: int,
                idx: int,
                up: int,
                low: int,
                seen_codes: set):
    low_idx = (low + code) // 2
    high_idx = (up + code) // 2

    if code not in seen_codes:
        characters.append((idx, pile[code]))
        seen_codes.add(code)
    else:
        characters.append((idx, -1))

    if low_idx == high_idx:
        if pile[low_idx] > pile[code]:
            characters.append((2 * idx + 1, pile[low_idx]))
        else:
            characters.append((2 * idx, pile[low_idx]))
        return

    if pile[low_idx] < pile[code]:
        create_node(characters, pile, low_idx, 2 * idx, code, low, seen_codes)
    if pile[high_idx] > pile[code]:
        create_node(characters, pile, high_idx, 2 * idx + 1, up, code, seen_codes)


def build_character_order(nb_char: int) -> List[Tuple[int, int]]:
    pile = list(range(nb_char))
    pile.sort()
    first_code = len(pile) // 2
    it_max = len(pile) - 1
    it_min = 0
    characters: List[Tuple[int, int]] = []
    seen_codes: set = set()
    create_node(characters, pile, first_code, 1, it_max, it_min, seen_codes)
    # Отсортировать по "addr" (первый элемент кортежа)
    characters.sort(key=lambda x: x[0])
    return characters


def pack_glyph_header(width: int,
                      height: int,
                      offset_y: int,
                      space_between: int,
                      space_width: int) -> bytes:
    # C++: 12 байт: [w,0,h,0,offy_lo,offy_hi,0,0,b_lo,b_hi,0x01,0x00]
    # width/height ограничивают uint8
    w = max(0, min(255, width))
    h = max(0, min(255, height))
    if offset_y < 0:
        offset_y = 0
    offset_y &= 0xFFFF

    if w == 0:
        b = space_width
    else:
        b = w + space_between
    b &= 0xFFFF

    return bytes([
        w, 0,
        h, 0,
        offset_y & 0xFF,
        (offset_y >> 8) & 0xFF,
        0, 0,
        b & 0xFF,
        (b >> 8) & 0xFF,
        0x01, 0x00
    ])


def pack_bitmap_4bpp(bitmap):
    w, h = bitmap.width, bitmap.rows
    pitch = bitmap.pitch
    buf = bitmap.buffer
    out = bytearray()
    half = None

    if pitch >= 0:
        def row_start(y): return y * pitch
    else:
        # инвертированный по вертикали битмап
        def row_start(y): return (h - 1 - y) * (-pitch)

    for y in range(h):
        base = row_start(y)
        for x in range(w):
            v = buf[base + x]
            nib = v >> 4
            if half is None:
                half = nib
            else:
                out.append((nib << 4) | (half & 0x0F))
                half = None
    if half is not None:
        out.append(half & 0x0F)
    return bytes(out)


def draw_glyph(face: freetype.Face,
               glyph_index: int,
               baseline: int,
               space_between: int,
               space_width: int) -> bytes:
    face.load_glyph(glyph_index, freetype.FT_LOAD_RENDER)
    slot = face.glyph
    bm = slot.bitmap
    # offset_y = baseline - bitmap_top (как в C++)
    offset_y = baseline - slot.bitmap_top
    header = pack_glyph_header(bm.width, bm.rows, offset_y, space_between, space_width)
    body = pack_bitmap_4bpp(bm)
    return header + body


def read_reference_itf(path: Path) -> Dict[int, bytes]:
    # Читаем пары (code, addr) и выдираем срезы до следующего addr
    data = path.read_bytes()
    if len(data) < 0x10:
        return {}

    nb_char = r_u32(data, 8)
    nb_int = 13  # offset table starts after a fixed 13-entry header in this ITF format
    addr_table_off = 0x10 + (nb_int - 1) * 4
    entries: List[Tuple[int, int]] = []
    for i in range(nb_char):
        code = r_u32(data, addr_table_off + i * 8)
        addr = r_u32(data, addr_table_off + i * 8 + 4)
        entries.append((code, addr))
    # Отсортируем по адресу, чтобы знать границы
    entries_by_addr = sorted(entries, key=lambda x: x[1])
    code_to_bytes: Dict[int, bytes] = {}
    for idx, (code, start) in enumerate(entries_by_addr):
        end = len(data) if idx == len(entries_by_addr) - 1 else entries_by_addr[idx + 1][1]
        if 0 <= start < end <= len(data):
            code_to_bytes[code] = data[start:end]
    return code_to_bytes

def make_blank_glyph(baseline: int, space_between: int, space_width: int) -> bytes:
    # Ширина=0, высота=0 задействует SpaceWidth в поле b
    header = pack_glyph_header(0, 0, baseline, space_between, space_width)
    return header  # без тела


def main():
    ini_path = Path("config_font.ini")
    if not ini_path.exists():
        print("config_font.ini not found in the current directory")
        sys.exit(1)

    conf = load_ini(ini_path)

    resolution = conf["resolution"]
    font_size = conf["size"]
    base = conf["base"]
    nb_char = conf["NbChar"]
    space_w = conf["SpaceWidth"]
    space_between = conf["SpaceBetweenCharacters"]
    font_path = Path(conf["font"])
    itf_ref = conf["itf_ref"]
    replacements: Dict[int, int] = conf["replacements"]

    print("Resolution:", resolution)
    print("Font:", font_path)
    print("Base:", base)
    print("NbChar:", nb_char)
    print("FontSize:", font_size)
    print("ITFReferenceFile:", itf_ref)

    ref_map: Dict[int, bytes] = {}
    if itf_ref and itf_ref.lower() != "none" and Path(itf_ref).exists():
        print("Reading reference ITF:", itf_ref)
        ref_map = read_reference_itf(Path(itf_ref))
        print(f"Reference ITF: {len(ref_map)} glyphs found")

    # Инициализация FreeType
    face = freetype.Face(str(font_path))
    baseline = (resolution * base) // 0x20
    actual_resolution = (resolution * 530) // 0x40 
    face.set_char_size(font_size, 0, actual_resolution, 0)

    # Заголовок файла
    # 0x01, 0x01, resolution(u16), nbChar(u32), nbChar(u32),
    # 0x0D(u32), затем (0x0D-1) раз u32 0
    header = bytearray()
    header.extend(bytes([0x01, 0x01]))
    header.extend(u16le(resolution))
    header.extend(u32le(nb_char))
    header.extend(u32le(nb_char))
    idk_what_that_is = 0x0D
    header.extend(u32le(idk_what_that_is))
    for _ in range(idk_what_that_is - 1):
        header.extend(u32le(0))

    
    characters = build_character_order(nb_char)  # список кортежей (addr_idx, code)

    addr_section = bytearray()
    drawing_section = bytearray()
    current_position = len(header) + len(characters) * 8

    for _, code in characters:
        replaced_char = False
        original_code = code
        if code in replacements:
            code = replacements[code]
            replaced_char = True

        glyph_index = face.get_char_index(code)
        letter_bytes: Optional[bytes] = None
        code_for_table = original_code if replaced_char else code
        if glyph_index != 0:
            letter_bytes = draw_glyph(face, glyph_index, baseline, space_between, space_w)
        else:
            # Пробуем взять из reference ITF по коду «code»
            if code in ref_map:
                lb = ref_map[code]
                letter_bytes = lb#adjust_ref_glyph_for_baseline(lb, baseline)
            else:
                # Нет в TTF и нет в reference — делаем пустой глиф
                letter_bytes = make_blank_glyph(baseline, space_between, space_w)
                pass

        # Таблица адресов: (code_for_table, current_position)
        addr_section.extend(u32le(code_for_table & 0xFFFFFFFF))
        addr_section.extend(u32le(current_position))
        drawing_section.extend(letter_bytes)
        current_position += len(letter_bytes)

    # Сборка файла
    out = bytearray()
    out.extend(header)
    out.extend(addr_section)
    out.extend(drawing_section)

    out_path = Path("font.itf")
    out_path.write_bytes(out)
    print(f"SUCCESS! -> {out_path.resolve()}")


if __name__ == "__main__":
    main()