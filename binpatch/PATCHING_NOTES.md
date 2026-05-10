# Trails from Zero — технические заметки по патчам `zero.exe`

Технический deep-dive: что мы выяснили про текстовый pipeline в exe, как
нашли пять мест, требующих патча, и что именно правит каждый из них.
Документ для тех, кто захочет повторить анализ или перенести подход на
другую сборку игры.

Для применения патчей — см. [`README.md`](README.md). Здесь — research
material.

Тестовая сборка: **Trails from Zero Steam, версия 1.4.13** (Geofront
build). На других PC-ревизиях офсеты могут отличаться — пользуйтесь
сигнатурным поиском (см. `research/ghidra_scripts/`).

---

## Структура text-pipeline в `zero.exe`

### Адресные модули

| Адресный диапазон | Класс / роль |
|---|---|
| `0x140077000..0x14008000` | In-house text codec module: SJIS↔UTF-8 converters, encoding detector, UTF-8 byte parser |
| `0x1400c3000..0x1400c5000` | CRT/STL helpers (`std::codecvt`-стиль UTF-8 validators) — **не используется напрямую** игрой |
| `0x1401cd000..0x1401d0000` | Item info-screen module (item description handler) |
| `0x1401e0000..0x1401f0000` | CBookWindow module (book / notebook / quest preview) |
| `0x140210000..0x140220000` | CMessageWindow module (general dialog / message rendering) |
| `0x140280000..0x14028c000` | Terminal / UI text formatters (line wrap, truncate, squeeze → P3 / P4 / P5) |
| `0x140310000..0x140340000` | Quest UI region (CTerminalQuestWindow) |

### Ключевые функции

#### In-house codec module
- **`FUN_140078850`** — encoding detector, возвращает `0=empty`, `1=ASCII`,
  `2=SJIS`, `3=UTF-8`. Содержит early-exit детект UTF-8 для пары
  `[0xC0..0xDF][0x80..0xBF]` — ошибочно срабатывает на наши halfwidth
  пары. **P1** глушит этот детект.
- **`FUN_140078d00`** — `CSaveData::UTF8toSJIS` (для save-данных).
- **`FUN_140078fb0`** — SJIS→UTF-8 converter, использует таблицу из
  `sjisutf8.dat` через глобал `DAT_1404b1d08`. Halfwidth обрабатывает
  корректно.
- **`FUN_1400794a0`** — UTF-8 byte parser. Для byte `0xC0..0xDF` идёт в
  2-byte UTF-8 path.
- **`FUN_140079360`** — UTF-8 → wchar buffer decoder (вызывает
  `FUN_1400794a0` в цикле).
- **`FUN_140077580`** + **`FUN_140078090`** — основные SJIS render
  paths. Рисуют byte stream через `font.itf`; halfwidth работает
  корректно.

#### Text wrappers с encoding detector
- **`FUN_140077420`** / **`FUN_140077ec0`** — обёртки:
  ```
  detector → if 3 (UTF-8) → FUN_140079360 → render
           → else (SJIS)  → FUN_140077580 / FUN_140078090
  ```
  P1 заставляет detector никогда не возвращать `3` для наших строк, и
  они идут в SJIS path.

#### Item info-screen
- **`FUN_1401ce2b0`** — item description renderer. ASCII gate
  `CMP CL, 0x80; JNC` на адресе `0x1401ce6c9`: halfwidth bytes
  пролетают мимо `INC RDI` и попадают в бесконечный цикл. **P2**
  превращает `JNC` в `NOP NOP` — halfwidth идут как single-byte.
  Зовётся из `FUN_1401cd4e0`.

#### CMessageWindow / CBookWindow (рендеры с корректной halfwidth-логикой)
Эти функции halfwidth-aware из коробки — патчить не требуется, но
полезно знать что они есть:

- **`FUN_140215400`** — `CMessageWindow::ConvertMessage`.
- **`FUN_140212f40`** — `CMessageWindow` render. halfwidth-проверка
  `(byte+0x60) < 0x40`.
- **`FUN_1401e5270`** — `CBookWindow::ConvertMessage`. Те же
  `(byte+0x60) < 0x40` + `(byte+0x5F) < 0x3D`. Пишет в buffer at
  `(param_1 + 0xA0BC)`.
- **`FUN_1401e60d0`** — `CBookWindow::SetMessage`. Очищает буфер,
  вызывает `ConvertMessage`, ставит указатели в
  `param_1[0x12]/[0x13]`.

#### Семейство P3 (одинаковый баг в трёх местах)
Три родственные функции в notebook/UI-модуле имеют **идентичный**
outer halfwidth-gate `(byte<0x80) || ((byte+0x60)<0x40)`, но внутри —
один и тот же `(byte-0x20) < 0x60` filter, пропускающий только ASCII
printable (`0x20..0x7F`). Halfwidth-байты (`0xA0..0xDF`) проходят
outer-gate, но silently drop'аются на inner-check. Один байт-фикс
(`CMP AL, 0x5F` → `CMP AL, 0xBF`) применён в каждой из трёх:

- **`FUN_14028b700`** — single-line truncate с маркером `..` (quest
  preview). → **P3** at `0x14028caa5`.
- **`FUN_14028aac0`** — multi-line formatter (`\n`, escape `\\n`,
  numeric markers `#`). Memo-стиль списки.
  → **P4** at `0x14028b2b3`.
- **`FUN_140289a30`** — rich multi-line formatter с разметкой `#C`
  (color) / `#I` (icon) / `#R` (ruby). Town list, battle notebook,
  любые widget'ы с font-scale squeeze.
  → **P5** at `0x14028a443`.

Сигнатурный поиск (`research/ghidra_scripts/find_all_p3_gates.java`)
подтвердил: в exe ровно три места с этим паттерном, все три
пропатчены.

#### CRT/STL UTF-8 validators (НЕ используются)
- **`FUN_1400c3c70`** / **`FUN_1400c4540`** — `std::codecvt::do_in`
  стиль. Ноль вызывающих в game text path.

#### Прочие halfwidth-aware text loops (не патчим, для справки)
- `FUN_14020e6b0` — CLM dialog parser.
- `FUN_140216720` — width calculator.
- `FUN_1402873c0` — text formatter (notebook lines).
- `FUN_140332ba0` — message text formatter.
- `FUN_140215190` — copy-loop с halfwidth handling.

---

## Применённые патчи на ASM-уровне

### P1 — отключение early-UTF-8 detection в `FUN_140078850`
- **VA**: `0x140078936`
- **Было**: `80 F9 C0` (`CMP CL, 0xC0`)
- **Стало**: `80 F9 FF` (`CMP CL, 0xFF`)
- **Эффект**: detector никогда не возвращает `3` (UTF-8) на основании
  пары `[0xC0..0xDF][cont]`. Наши строки идут в SJIS path. Реальный
  UTF-8 через BOM (`EF BB BF`) — отдельная ветка, патч её не трогает.

### P2 — JNC→NOP в `FUN_1401ce2b0` (item description renderer)
- **VA**: `0x1401ce6c9`
- **Было**: `73 09` (`JNC short +9`)
- **Стало**: `90 90` (NOP NOP)
- **Эффект**: halfwidth bytes (`≥0x80`, не пойманные SJIS-pair branch
  выше) падают в `INC RDI; MOV [R14], CL; INC R14` — пишутся в output
  как single-byte glyph.

### P3 — расширение printable-range в `FUN_14028b700` (quest preview truncate)
- **VA**: `0x14028caa5`
- **Было**: `5F` (`CMP AL, 0x5F` → диапазон `0x20..0x7F` = ASCII
  printable)
- **Стало**: `BF` (`CMP AL, 0xBF` → диапазон `0x20..0xDF` = ASCII +
  halfwidth zone)
- **Эффект**: halfwidth bytes (после `LEA -0x20` дают `AL=0x80..0xBF`)
  проходят range check и пишутся в output buffer. Control bytes
  (`0..0x1F` → `AL=0xE0..0xFF`) по-прежнему скипаются.

### P4 — то же расширение в `FUN_14028aac0` (multi-line formatter)
- **VA**: `0x14028b2b3`
- **Было**: `5F` → **Стало**: `BF` (идентично P3)
- **Контекст**: `0x14028b2af: LEA EAX,[RCX-0x20]; CMP AL,0x5F; JA 0x14028b2d1`.
- **Эффект**: halfwidth-байты больше не теряются в memo-стиле списках
  и multi-line блоках с управляющими `\n`, `\\n`, `#`.

### P5 — то же расширение в `FUN_140289a30` (rich multi-line formatter)
- **VA**: `0x14028a443`
- **Было**: `5F` → **Стало**: `BF` (идентично P3)
- **Контекст**: `0x14028a43f: LEA EAX,[RCX-0x20]; CMP AL,0x5F; JA 0x14028a467`.
- **Эффект**: halfwidth-байты больше не теряются в разметке
  `#C`/`#I`/`#R` (town list, battle-notebook, font-scale squeeze).

---

## Наблюдения, найденные по дороге

- **`MultiByteToWideChar`** в exe есть только из STL/CRT, и game text
  через него не идёт (игра кроссплатформенная — PSP/Vita/Switch/PC,
  WinAPI там не используется).
- **`sjisutf8.dat`** загружается один раз при старте; дальше handler
  работает по таблице в памяти через глобал `DAT_1404b1d08`. ProcMon
  не видит обращений к файлу при показе описаний — патчить файл
  бесполезно.
- **`jis2ucs.bin`** / **`ucs2jis.bin`** — ноль операций по ProcMon, не
  используются рантаймом.
- Шаблон виновников halfwidth-багов: outer gate `byte < 0x80` ||
  `(byte+0x60) < 0x40` ловит ASCII *и* halfwidth, но внутри идёт
  более узкий inner-check, который halfwidth не пропускает. Три
  обнаруженных типа: ASCII range too narrow (P3-семейство), JNC→skip
  пишущей ветки (P2), wrong UTF-8 detection (P1).

---

## Платформы

Этот набор патчей применим только к **PC** (Steam / Geofront, x86-64).
Switch- и Vita-сборки используют другую архитектуру и закрыты для
прямого патча. На Switch halfwidth-баги тоже есть, но они
косметические — играть можно.
