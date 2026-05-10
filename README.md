# Trails From Zero Toolkit

> 🇷🇺 На русском: [README_RU.md](README_RU.md)

Tools that came out of translating *The Legend of Heroes: Trails from
Zero* (PC port) into Russian. Everything here is what you need to put
your own alphabet into the game and ship a working build — the same
toolchain the Russian translation uses end-to-end.

## Tested versions

- **Trails from Zero — Steam, build 1.4.13.** Every tool here was
  developed and round-tripped against this build.
- **Trails to Azure** — same engine, same data formats. The
  [`dt-tools/`](dt-tools/README.md) decompilers and the [`font/`](font/README.md)
  builder apply directly. The five binary patches in
  [`binpatch/`](binpatch/README.md) target `zero.exe` specifically and are not
  yet ported to Azure's executable.

On other PC revisions of *Zero* the patch byte offsets may differ. The
Ghidra scripts in [`binpatch/research/`](binpatch/research/) reproduce
the analysis if you need to find the equivalents on a different
binary.

## What we went through

The PC port already supports Japanese, English and a baked-in Russian,
so the obvious starting point is to swap strings in the existing data
files. That works for English (proper font, 1-byte ASCII). It doesn't
work for Russian as shipped: the built-in glyphs render packed
together like kana, layouts overflow, and a handful of fields hit
hard length caps. Replacing the font with a real TTF fixes the look
but not the lengths. The fix for the lengths is to encode every
letter as **1 byte** (in the SJIS halfwidth zone the engine already
understands as 1-byte slots) — and that works almost everywhere,
except in five text formatters that silently drop bytes above `0x7F`.
We patched those five spots in `zero.exe`. That's the toolkit: the
font builder, the data-table re-encoder, and the five binary patches.

## Which path is yours

Pick one. The choice is determined by the language you're translating
into, not by preference:

- **Path A — `passthrough`.** For languages the game already supports
  natively (Japanese, English) or for tweaking strings in the stock
  Russian build. Letters encode as standard 2-byte SJIS or 1-byte
  ASCII, exactly like the original files. You only need
  [`dt-tools/`](dt-tools/README.md) in `--passthrough` mode. **This path will
  not work** for any language without a proper font in the game,
  including Russian as shipped — you'll hit the layout / length /
  readability problems that path B was built to solve.

- **Path B — `halfwidth`.** For any language with no proper font in
  the game (Russian, Ukrainian, Greek, Hebrew, …). The full pipeline
  is mandatory; nothing here is optional. You need all three
  components:
  1. [`font/`](font/README.md) — build a custom `font.itf` for your alphabet.
  2. [`dt-tools/`](dt-tools/README.md) in `--halfwidth` mode — re-encode every
     translated `._dt` to 1 byte per letter.
  3. [`binpatch/`](binpatch/README.md) — apply the five surgical patches to
     `zero.exe` so the engine stops dropping halfwidth bytes.

  Skip any one of the three and the build will look broken in
  non-obvious ways: missing letters, random truncation, infinite
  loops on item descriptions.

## What's in the box

| Folder | Path A | Path B | What it does |
|--------|:---:|:---:|--------------|
| [`dt-tools/`](dt-tools/README.md) | yes | yes | Decompilers / compilers for the game's `._dt` data tables. Step-by-step usage, the two encoding modes, drag-and-drop interactive flow, and the substitution-table reference are in its README. |
| [`font/`](font/README.md) | optional | **required** | Builder for `font.itf`. How to build, how to retarget it for a different alphabet, and the required game-side input file are all in its README. |
| [`binpatch/`](binpatch/README.md) | no | **required** | Five tiny patches to `zero.exe` for halfwidth mode. Apply / revert flow and the patch table are in its README; ASM-level deep-dive in [`PATCHING_NOTES.md`](binpatch/PATCHING_NOTES.md). |

Game paths to know:

- `._dt` data tables → `<game>\data\text_us\`
- Font → `<game>\system_us\fontdat\font.itf`
- Scenarios (separate module, not in this repo yet) →
  `<game>\data\scena_us\`

Common prereqs: Python 3.6+, `pip install freetype-py` (only for the
font builder), a copy of the game, and a TTF that contains your
alphabet's glyphs. Always make backups of `zero.exe`,
`system_us\fontdat\font.itf` and any `._dt` you plan to edit before
you start.

## Credits

- **Edrahor** — toolkit, packaging, `byte_codec`, `._dt` compilers
  (books, items, memo, shop, town), binary-patch reverse engineering,
  docs.
- **Ivdos** — original `font.itf` builder
  ([`font/glyph.py`](font/glyph.py)) and original quest decompiler
  ([`dt-tools/dt_quest.py`](dt-tools/dt_quest.py)). Both adapted for
  this toolkit.

## TODO

See [TODO.md](TODO.md). Highlights: a standalone "text ↔ halfwidth"
CLI for non-`._dt` text streams; the upcoming `scena/` module for
translating scenario files in `data\scena_us\`; an English version of
the technical notes in `binpatch/PATCHING_NOTES.md`.

## Community

[Geofront / Trails Discord](https://discord.com/invite/sGzmvFaFAe).
