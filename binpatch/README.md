# binpatch — `zero.exe` patches for halfwidth mode

Five tiny binary patches (1–3 bytes each) for the Steam PC port of
*Trails from Zero*. Tested against build **1.4.13**. Byte offsets may
shift on other builds — see [`PATCHING_NOTES.md`](PATCHING_NOTES.md)
for how to find them.

## When you need this

Only when running [`../dt-tools/`](../dt-tools/README.md) in
**halfwidth mode**.

The game itself works fine without these patches — the stock build
runs, 2-byte `passthrough` mode runs, you can play the game. But the
moment you switch `._dt` files to 1-byte halfwidth encoding, you'll
notice that some letters disappear in specific places (quest log
preview, item descriptions, memo entries, town list, etc.). That's
not a font problem — those are 5 separate ASCII gates inside the
engine's text formatters that silently drop bytes outside the
`0x20..0x7F` printable range, even after the outer halfwidth gate
has already accepted them. These patches widen each of those 5
gates by 1–3 bytes apiece.

If you stay in `passthrough` (2-byte SJIS) mode, you don't need
these patches.

## The five patches

| ID | Address (VA) | Bytes | Function | What it fixes |
|----|--------------|-------|----------|---------------|
| **P1** | `0x140078936` | `80 F9 C0` → `80 F9 FF` | `FUN_140078850` (encoding detector) | Kills false UTF-8 detection of halfwidth byte pairs. |
| **P2** | `0x1401ce6c9` | `73 09` → `90 90` | `FUN_1401ce2b0` (item desc renderer) | Lets halfwidth bytes through ASCII gate (no more infinite loop on item descriptions). |
| **P3** | `0x14028caa5` | `5F` → `BF` | `FUN_14028b700` (single-line truncate, `..` marker) | Widens "printable" range so halfwidth bytes survive truncate (quest log preview). |
| **P4** | `0x14028b2b3` | `5F` → `BF` | `FUN_14028aac0` (multi-line formatter) | Same fix as P3, applied to memo / book formatter. |
| **P5** | `0x14028a443` | `5F` → `BF` | `FUN_140289a30` (rich multi-line formatter `#C`/`#I`/`#R`) | Same fix as P3, applied to town list / battle-notebook widgets / font-scale squeeze paths. |

P3, P4, P5 are the **same byte fix at three different sites**. A
signature scan (`research/ghidra_scripts/find_all_p3_gates.java`)
confirms those are the only three occurrences in `zero.exe`.

## Usage

Edit `apply_patch.bat` and set `EXE` to your `zero.exe`. Then:

```cmd
apply_patch.bat              :: apply all (P1..P5)
apply_patch.bat dry          :: dry-run, no writes
apply_patch.bat revert       :: revert all
apply_patch.bat P3           :: apply only P3 (or P1/P2/P4/P5)
apply_patch.bat revert-P3    :: revert only P3
```

A backup `zero.exe.utf8patch-backup` is created on first apply and
kept.

Direct CLI:

```bash
python patch_zero_exe.py path/to/zero.exe              # apply ALL
python patch_zero_exe.py path/to/zero.exe --revert     # revert ALL
python patch_zero_exe.py path/to/zero.exe --dry-run    # report only
python patch_zero_exe.py path/to/zero.exe --only P3    # one patch
```

## Files

- `patch_zero_exe.py` — Python patcher (P1..P5).
- `apply_patch.bat` — Windows wrapper.
- `PATCHING_NOTES.md` — full technical notes (Russian): function map,
  hypotheses ruled out, Ghidra-script index.
- `research/ghidra_scripts/*.java` — Ghidra Java scripts that found
  each patch site. Useful only if you want to redo the analysis on a
  different binary. **Not required** to apply the patches.

## Platform

PC (Steam, x86-64) only. Switch / Vita builds use different
binaries; these byte offsets won't apply there.
