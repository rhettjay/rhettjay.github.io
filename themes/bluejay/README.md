# bluejay

Original theme for [rhettjay.github.io](https://rhettjay.github.io) — written from
scratch, not derived from another blog's theme.

The design merges two instincts:

- **Terminal chrome** — a shell-prompt header with a blinking cursor, monospace
  for everything that *signals* (nav, meta, tags, code), dark by default
- **Card-list reading layout** — post cards on the home page, tag pages, a
  light mode, comfortable sans prose at reading measure

The signaling color is light blue, throughout.

## Editing it yourself

Everything visual lives in two plain CSS files — no SCSS, no framework:

- `assets/css/main.css` — **the palette block at the top is the whole color
  system.** Every color in the theme comes from those custom properties;
  change them and the theme follows.
- `assets/css/syntax.css` — code highlighting (Chroma, class-based). Syntax
  colors are also custom properties (`--syn-*`).

Layouts are minimal Hugo templates in `layouts/`. The theme toggle is ~20
lines of vanilla JS in `assets/js/theme.js`.

## License

MIT — it's ours.
