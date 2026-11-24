# rhettjay.github.io

Personal site — a Hugo blog published to GitHub Pages.

## Structure

- `content/posts/` — write-ups and posts (Markdown)
- `themes/hello-friend/` — vendored theme ([hello-friend](https://github.com/panr/hugo-theme-hello-friend), MIT)
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

Content is copyright the author. The vendored theme carries its own MIT license
(`themes/hello-friend/LICENSE.md`).
