#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_zero_exe.py - apply / revert all known surgical fixes for the
1-byte halfwidth Russian text path in zero.exe.

Part of the Trails From Zero Toolkit. Author: Edrahor.

Patches managed here:

  P1: FUN_140078850 (encoding detector)
      Disable a wrong "early-exit UTF-8" detection that misclassifies
      strings containing pairs like [lowercase 0xC2..0xDF][uppercase
      0xA1..0xC1] as UTF-8. Affects FUN_140077420/ec0 wrapper-style
      text rendering.

  P2: FUN_1401ce2b0 (item info-screen text renderer)
      Fix infinite loop on halfwidth bytes: when a byte ends up in the
      ASCII gate at 0x1401ce6c9, JNC sends bytes >= 0x80 past INC RDI,
      so the pointer never advances. Replacing JNC with NOP/NOP makes
      halfwidth bytes pass through INC RDI / MOV [R14], CL like ASCII;
      FUN_140077580 then renders them via the remapped font.itf.

  P3: FUN_14028b700 (text formatter / preview-truncator with line wrap)
      The "ASCII printable" range check at 0x14028caa4 is `LEA EAX,
      [RCX-0x20]; CMP AL, 0x5F; JA skip` - i.e. byte must be in 0x20..0x7F
      to be written into the local output buffer. Halfwidth bytes
      (0xA0..0xDF) survive the outer ASCII/halfwidth gate, but then this
      inner range check rejects them: pointer and char-counter advance,
      but the byte is silently dropped. This is what produces "Расс.."
      previews in quest-log list (and similar truncate paths).
      Patch widens the range to 0x20..0xDF by changing CMP AL, 0x5F to
      CMP AL, 0xBF (single-byte change at 0x14028caa5). Control bytes
      0x00..0x1F still skip (AL becomes 0xE0..0xFF, > 0xBF).

  P4: FUN_14028aac0 (multi-line text formatter, simple variant)
      Identical P3-style narrow gate at 0x14028b2b2 (`LEA EAX, [RCX-0x20];
      CMP AL, 0x5F; JA 0x14028b2d1`). This formatter handles newline
      (0x0A), `\\n` escape, and `#` numeric markers. Used for memo / book
      / squeeze-aware text blocks. Same byte fix: 0x5F → 0xBF at
      0x14028b2b3.

  P5: FUN_140289a30 (multi-line text formatter with #C/#I/#R markup)
      Identical P3-style narrow gate at 0x14028a442 (`LEA EAX, [RCX-0x20];
      CMP AL, 0x5F; JA 0x14028a467`). This is the rich formatter
      supporting #C color, #I icons, #R ruby markup. Same byte fix:
      0x5F → 0xBF at 0x14028a443.

CLI:
    python patch_zero_exe.py <zero.exe>            # apply ALL patches
    python patch_zero_exe.py <zero.exe> --revert   # revert ALL patches
    python patch_zero_exe.py <zero.exe> --dry-run  # report only
    python patch_zero_exe.py <zero.exe> --only P1  # apply only P1 (or P2/P3)
"""

import argparse
import shutil
import sys
from pathlib import Path

IMAGE_BASE = 0x140000000

# Each patch is (name, virtual_address, original_bytes, patched_bytes, doc).
PATCHES = [
    (
        "P1",
        0x140078936,
        bytes([0x80, 0xF9, 0xC0]),   # CMP CL, 0xC0
        bytes([0x80, 0xF9, 0xFF]),   # CMP CL, 0xFF (never matches after AND CL,0xE0)
        "FUN_140078850 - kill early-exit UTF-8 misdetection of halfwidth pairs",
    ),
    (
        "P2",
        0x1401ce6c9,
        bytes([0x73, 0x09]),         # JNC 0x1401ce6d4
        bytes([0x90, 0x90]),         # NOP NOP
        "FUN_1401ce2b0 - allow halfwidth bytes through ASCII gate (item descriptions)",
    ),
    (
        "P3",
        0x14028caa5,
        bytes([0x5F]),               # CMP AL, 0x5F  (range 0x20..0x7F = ASCII printable)
        bytes([0xBF]),               # CMP AL, 0xBF  (range 0x20..0xDF = ASCII + halfwidth)
        "FUN_14028b700 - widen 'printable' check so halfwidth bytes get written (quest preview truncate)",
    ),
    (
        "P4",
        0x14028b2b3,
        bytes([0x5F]),               # CMP AL, 0x5F
        bytes([0xBF]),               # CMP AL, 0xBF
        "FUN_14028aac0 - widen 'printable' check (multi-line formatter, simple variant)",
    ),
    (
        "P5",
        0x14028a443,
        bytes([0x5F]),               # CMP AL, 0x5F
        bytes([0xBF]),               # CMP AL, 0xBF
        "FUN_140289a30 - widen 'printable' check (rich multi-line formatter #C/#I/#R)",
    ),
]


def read_pe_sections(buf):
    if buf[0:2] != b'MZ':
        raise ValueError("not a PE file (no MZ signature)")
    pe_off = int.from_bytes(buf[0x3C:0x40], 'little')
    if buf[pe_off:pe_off+4] != b'PE\0\0':
        raise ValueError("PE signature not found at e_lfanew")
    coff = pe_off + 4
    n_sections = int.from_bytes(buf[coff+2:coff+4], 'little')
    size_opt   = int.from_bytes(buf[coff+16:coff+18], 'little')
    sec_off    = coff + 20 + size_opt
    sections = []
    for i in range(n_sections):
        s = sec_off + i * 40
        virt_size = int.from_bytes(buf[s+8:s+12], 'little')
        virt_addr = int.from_bytes(buf[s+12:s+16], 'little')
        raw_size  = int.from_bytes(buf[s+16:s+20], 'little')
        raw_off   = int.from_bytes(buf[s+20:s+24], 'little')
        sections.append((virt_addr, virt_addr + max(virt_size, raw_size), raw_off, raw_size))
    return sections


def va_to_file_offset(buf, va):
    rva = va - IMAGE_BASE
    for v_start, v_end, raw_off, raw_size in read_pe_sections(buf):
        if v_start <= rva < v_end:
            return raw_off + (rva - v_start)
    raise ValueError(f"VA {va:#x} not in any PE section")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('exe', type=Path, help='path to zero.exe')
    ap.add_argument('--revert', action='store_true',
                    help='revert patches instead of applying')
    ap.add_argument('--dry-run', action='store_true',
                    help='print what would happen, but do not write')
    ap.add_argument('--only', metavar='ID', default=None,
                    help='operate on only one patch by ID (P1, P2, ...)')
    args = ap.parse_args()

    if not args.exe.exists():
        sys.exit(f"ERROR: {args.exe} does not exist")

    selected = PATCHES
    if args.only:
        selected = [p for p in PATCHES if p[0] == args.only]
        if not selected:
            sys.exit(f"ERROR: no patch with id '{args.only}'. Known: {[p[0] for p in PATCHES]}")

    buf = bytearray(args.exe.read_bytes())
    needs_write = False

    for (pid, va, orig, new, doc) in selected:
        file_off = va_to_file_offset(buf, va)
        cur = bytes(buf[file_off:file_off+len(orig)])
        print(f"--- {pid}  VA={va:#x}  file_offset={file_off:#x}  ({doc})")
        print(f"    current : {cur.hex(' ').upper()}")
        if args.revert:
            target = orig
            label = "revert"
        else:
            target = new
            label = "apply"

        if cur == target:
            print(f"    {label}: already in target state - nothing to do.")
            continue
        elif cur == orig and not args.revert:
            print(f"    apply  : {orig.hex(' ').upper()}  ->  {new.hex(' ').upper()}")
            buf[file_off:file_off+len(orig)] = new
            needs_write = True
        elif cur == new and args.revert:
            print(f"    revert : {new.hex(' ').upper()}  ->  {orig.hex(' ').upper()}")
            buf[file_off:file_off+len(orig)] = orig
            needs_write = True
        else:
            print(f"    ERROR  : bytes don't match either original "
                  f"({orig.hex(' ').upper()}) or patched ({new.hex(' ').upper()}). "
                  f"Skipping this patch.")

    if not needs_write:
        print()
        print("Nothing to write.")
        return

    if args.dry_run:
        print()
        print("(--dry-run: skipping file write)")
        return

    backup = args.exe.with_suffix(args.exe.suffix + '.utf8patch-backup')
    if not backup.exists():
        # shutil.copy2 to preserve mtime as a "first-time backup before any patch"
        original = args.exe.read_bytes()  # already in memory but be safe
        backup.write_bytes(original)
        print()
        print(f"Backup created  : {backup}")
    else:
        print()
        print(f"Backup exists   : {backup}  (kept as-is)")

    args.exe.write_bytes(buf)
    print("DONE.")


if __name__ == '__main__':
    main()
