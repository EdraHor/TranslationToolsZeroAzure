# dt-tools — `._dt` decompilers / compilers

Six Python scripts that round-trip the game's `._dt` data tables
between binary and JSON. Decompile → edit JSON → compile back.

The game keeps these files at `<game>\data\text_us\`.

## Per-file scripts

| Script | Game file | Contents |
|--------|-----------|----------|
| `dt_books.py` | `t_book*._dt` | Book / story files (detective book, etc.) |
| `dt_ittxt.py` | `t_ittxt._dt` | Item names + descriptions |
| `dt_memo.py`  | `t_memo._dt`  | Memo / detective book entries |
| `dt_quest.py` | `t_quest._dt` | Quest names, client, descriptions, progress |
| `dt_shop.py`  | `t_shop._dt`  | Shop names + records |
| `dt_town.py`  | `t_town._dt`  | Town and place names |

## Two ways to use them

### CLI (batch / scripted)

```bash
# Decompile -> JSON. No mode flags here, ever.
python dt_books.py t_book01._dt -o t_book01.json

# Compile -> binary. Mode flag is REQUIRED on the CLI.
python dt_books.py t_book01.json --halfwidth   -o t_book01._dt
python dt_books.py t_book01.json --passthrough -o t_book01._dt

# Round-trip self-test
python dt_books.py t_book01._dt --test
```

### Interactive (drag-and-drop / double-click)

Run a script with **no arguments** (drop a file on it, or
double-click and paste a path) and it will:

- ask for the input path if you didn't pass one;
- decompile when you give it `._dt`, compile when you give it `.json`
  (output path is auto-generated next to the input);
- on **compile**, prompt `1) halfwidth / 2) passthrough` because no
  CLI flag was given;
- on **decompile**, never ask anything;
- keep the console open on errors so the window doesn't vanish before
  you can read the message.

## Encoding modes

Two modes, chosen **at compile time only**:

| Mode | What it does | When to use |
|------|--------------|-------------|
| `halfwidth` | Each letter encodes as **1 byte** in the SJIS halfwidth zone (`0xA1..0xDF`) or one of three rare ASCII slots. Saves ~50% bytes; fixes all length / pointer issues. | Requires the patched `font.itf` (from [`../font/`](../font/README.md)) and the binary patches from [`../binpatch/`](../binpatch/README.md) to render correctly. |
| `passthrough` | Plain `cp932` SJIS encode. Letters become 2-byte SJIS pairs. | If you don't want to touch `zero.exe`. Works with stock or custom `font.itf`. Larger files; some text may overflow boxes / pointer limits. |

### How the mode is chosen — there is no automatic mode

Decompile takes **no mode at all** — the decoder reads halfwidth and
2-byte SJIS transparently in the same pass, so it doesn't need to be
told. The output JSON contains no `encoding_mode` field, and any
`encoding_mode` in older JSONs is ignored.

Compile **must** be told the mode explicitly:

1. **CLI flag** — `--halfwidth` or `--passthrough`. Always wins.
2. **Interactive prompt** — when the script was launched without any
   CLI arguments (drag-and-drop / double-click), it prompts you with
   `1) halfwidth / 2) passthrough` instead.
3. **No mode + no prompt** (e.g. running from a batch script that
   forgot the flag) → the script aborts with a clear error. There is
   no silent default at compile time.

The reasoning: shipping a translation built in the wrong mode is a
bigger problem than typing one extra flag. Making the choice mandatory
keeps it visible.

## The substitution table

The codec ([`byte_codec.py`](byte_codec.py)) reads its `letter -> byte`
table from [`../font/config_font.ini`](../font/config_font.ini) at
import time — the same file `glyph.py` reads to draw glyphs. Edit one
file and both the rendered glyph and the byte encoding follow. There
is no built-in fallback: if `config_font.ini` is missing or
unreadable, importing `byte_codec` fails with a clear error instead of
silently picking a default.

Worked example — the bundled config maps Russian into 66 single-byte
slots:

```
А..Я (33)  ->  0xA1..0xC1     (halfwidth katakana zone)
а..ь (30)  ->  0xC2..0xDF     (halfwidth katakana zone)
э ю я ( 3) ->  0x60 0x5E 0x5F (rare ASCII: ` ^ _)
```

The first two ranges fill the 1-byte halfwidth-katakana block. The
Russian alphabet has 66 letters with the full Ё/ё set — three
overflow into rare ASCII slots. **Don't** use `{` (`0x7B`) or `}`
(`0x7D`); those are CLM scenario block delimiters and will break
scenario files later.

## How the codec gets imported

Each `dt_*.py` does `sys.path.insert(0, parent_dir)` and then
`from byte_codec import ...`, so `byte_codec.py` must sit next to the
script. In this repo it's already there in `dt-tools/`, so things
work as-is. If you move scripts around, keep `byte_codec.py` with
them, or set `PYTHONPATH`. `byte_codec` itself reads
`../font/config_font.ini` relative to its own location, so the
sibling `font/` folder must also still be reachable.
