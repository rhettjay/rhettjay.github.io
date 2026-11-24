# rhettjay.github.io

Personal site — a Hugo blog published to GitHub Pages.

## Structure

- `content/posts/` — write-ups and posts (Markdown)
- `themes/bluejay/` — **our own theme**, written from scratch: terminal chrome (prompt header, blinking cursor, mono signals) + card-list reading layout, light-blue signaling. Plain CSS — the palette block at the top of `themes/bluejay/assets/css/main.css` is the whole color system
- `.github/workflows/hugo.yaml` — builds and deploys to Pages on push to `main`

## Writing a post

Drop a Markdown file in `content/posts/` with front matter:

```yaml
---
title: "Post title"
date: 2026-11-13T09:00:00-07:00
tags: ["security"]
toc: true
---
```

Push to `main`; the Pages workflow builds and deploys.

**Voice conventions:** write in our own voice and structure — our facts, commands, and outputs are ours to publish, but borrowed framing, signature phrasings, and post skeletons from other people's write-ups are not. When a post builds on someone else's analysis patterns, say so in a Sources section and link them.

## Building locally

```shell
hugo server -D
```

## License

Content is copyright the author. The bluejay theme is original and MIT-licensed
(`themes/bluejay/LICENSE`).
