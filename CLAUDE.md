# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-page marketing site (landing / сайт-визитка) for **«Ракурс»**, a fictional online photography school. Plain static site — vanilla HTML/CSS/JS, **no build step, no dependencies, no tests, no package.json**. All text is in Russian.

## Running

Open `index.html` directly in a browser, or serve statically:

```bash
python -m http.server 5500   # then open http://localhost:5500
```

A preview config exists at `.claude/launch.json` (server name `rakurs`, port 5500) for use with the preview tooling.

## Architecture

Two pages sharing the header/footer and `style.css`:

**Theming (light/dark)** — driven entirely by CSS variables. `:root` holds the light palette; `:root[data-theme="dark"]` overrides only the color tokens. All components must read colors from variables (no hardcoded hex/rgb in component rules) so both themes work — e.g. `--header-bg`, `--choose-bg/-fg` exist specifically to keep the header and the dark «Выбрать курс» button themeable. `theme.js` (loaded on both pages) wires the header toggle and saves the choice to `localStorage` key `rakurs-theme`. An inline script in each page's `<head>` sets `data-theme` before first paint (system preference as default) to avoid a flash — keep it in `<head>`, not deferred.

**Landing (`index.html` + `app.js`)** — sections: header → hero → `#courses` → `#prices` → `#contacts` → footer.
- `style.css` — all shared styling. Design tokens live in `:root` CSS variables (`--accent`, `--ink`, `--bg`, etc.); change the palette there. Layout is CSS grid with `auto-fit`/`minmax` (naturally responsive); `@media (max-width: 640px)` breakpoint.
- `app.js` — **the data layer.** The `courses` and `tariffs` arrays are the single source of truth for course names, durations, levels, descriptions, and all prices. Course cards, tariff cards, and the price table are rendered from these into `#courses-grid`, `#tariffs-grid`, `#price-table`. To change course/price content, edit the arrays — there is no hand-written markup for them in the HTML. Also handles: scroll-spy nav highlight (IntersectionObserver over `.nav a[href^="#"]`), and the **favorites** feature (per-course «В избранное» toggles, count badge on the dark header button, persisted in `localStorage` key `rakurs-fav`).

**Gallery (`gallery.html` + `gallery.js` + `gallery.css`)** — a camera-viewfinder photo viewer. `gallery.js` holds the `shots` array (photo src, technique tag, EXIF string, tip) as its source of truth; renders one photo at a time with a fake HUD (REC, thirds grid, AF box, EXIF) plus thumbnails, arrow/keyboard navigation with wrap-around. `gallery.css` is scoped to this page only. Photos live in `pics/` (`1.jpg`…`5.jpg`); referenced by relative path.
- **Interactive controls**: «Свет» and «Фокус» range sliders drive `applyFx()`, which sets `photo.style.filter` — light → `brightness`/`contrast` (shown as ±EV in the HUD), focus → `blur` (locks at ≥90%, turning the AF box green with a «● РЕЗКО» status). Clicking the AF box simulates autofocus (short hunt → lock). Current light/focus persist across photo changes (`applyFx()` is called at the end of `show()`).

Note: `app.js` targets landing-only element IDs and must NOT be loaded on `gallery.html` (and vice-versa).

## Content source of truth (important)

Site copy is **derived from the `.docx` knowledge-base files in the repo root**, not invented:

- `База-знаний_1_О-школе-и-курсах.docx` — school description, course list, tariffs, prices, contacts. This is the authoritative source for everything in the `courses`/`tariffs` arrays in `app.js`.
- `База-знаний_2_Tone-of-Voice.docx` — voice rules for any new copy. Key constraints: address the reader as «ты»; short sentences (one idea per sentence); no снобизм / канцелярит / пафос / кликбейт; light irony, not clownery. Avoid the listed stop-words («уникальный», «успейте», «гуру», «магия», «потенциал», etc.).
- `База-знаний_3_FAQ.docx` — Q&A source, not yet used on the site (available if adding an FAQ section).

When editing text or prices, reconcile against these documents. The `.docx` files are UTF-8 internally but the Windows console garbles their output — extract with Python (`zipfile` + parse `word/document.xml`) and write to a UTF-8 file to read reliably, rather than catting to the terminal.
