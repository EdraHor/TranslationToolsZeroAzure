# font — building a custom `font.itf`

Builds `font.itf` for *Trails from Zero* / *Trails to Azure* with
glyphs of your alphabet drawn into the engine's 1-byte halfwidth zone.

Game path: `<game>\system_us\fontdat\font.itf`.

## What it does

`glyph.py` reads `config_font.ini` and produces `font.itf`. The
interesting part is the `[Replacements]` section:

```
<source-character> = <replacement-character>
```

When the engine asks the font for the glyph at codepoint `<source>`,
the bitmap that comes back is the glyph for `<replacement>` rendered
from your TTF.

In practice this is used to overlay your alphabet onto unused 1-byte
slots in the existing font.

## The slots used by the bundled config

The PC build is a multi-region font; the cleanest 1-byte region with
free space is the **halfwidth-katakana** block, SJIS `0xA1..0xDF` /
Unicode `U+FF61..U+FF9F` (63 codepoints).

The bundled `config_font.ini` uses this block plus three rare ASCII
slots — 66 slots total, matching the 66-letter Cyrillic alphabet
(33 uppercase + 30 lowercase a..ь + 3 overflow э/ю/я → `` ` `` / `^` /
`_`).

Why these three ASCII slots specifically? `0x60` `0x5E` `0x5F` are
practically unused by normal game text. We deliberately **avoid**
`{` (`0x7B`) and `}` (`0x7D`) — those are CLM scenario block
delimiters, and remapping a letter onto `}` would silently mis-close
a `TextTalk` block.

## For a different alphabet

Edit `config_font.ini` (the `[Replacements]` table). Replacement
targets must exist in the TTF, and source characters should be ones
the game doesn't otherwise emit.

`config_font.ini` is the **single source of truth** for the alphabet
substitution. [`../dt-tools/byte_codec.py`](../dt-tools/byte_codec.py)
parses the same file at import time, so when you change the table
here, the encoder in dt-tools picks up the change automatically — no
duplicate edit needed.

## Build

```cmd
cd font
build_font.bat
:: or:
python glyph.py
```

`build_font.bat` keeps a `font.itf.bak` backup on first run. Drop the
resulting `font.itf` into `<game>\system_us\fontdat\`.

Requires `freetype-py` (`pip install freetype-py`) and Python 3.6+.

## Required input: the game's original font

`config_font.ini` references `font_default.itf`. This is the
**original** `font.itf` from the game and supplies glyphs for
codepoints you don't override. **It is not bundled** (game asset).
Copy `<game>\system_us\fontdat\font.itf` next to `glyph.py` as
`font_default.itf` before building.

## Files

- `config_font.ini` — example config (Cuprum + 66 Cyrillic mappings).
- `cuprum.ttf` — example free font (SIL OFL).
- `glyph.py` — the builder.
- `build_font.bat` — Windows wrapper.

## Pairing with the codec

`font.itf` only fixes **rendering** — when the engine draws byte
`0xA1`, it draws your glyph. To make `._dt` files actually emit byte
`0xA1` instead of a 2-byte SJIS pair, you also need
[`../dt-tools/`](../dt-tools/README.md) in halfwidth mode, plus the
patches in [`../binpatch/`](../binpatch/README.md) so the engine
doesn't drop those bytes in 5 specific text formatters.
