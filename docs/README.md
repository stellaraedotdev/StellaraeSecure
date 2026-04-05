# StellaraeSecure Documentation Site

This directory contains the static documentation site published via GitHub Pages.

## Pages

- `index.html`: Landing page and product overview
- `getting-started.html`: Local and staged startup flow
- `self-hosting.html`: Deployment guidance and architecture targeting
- `api.html`: Complete API reference (headers, request/response schemas, status behavior)
- `security-model.html`: Security boundaries and enforcement model

## Styling

- Shared visual style: `styles.css`
- Design standard and governance: `../INTERNAL/DOCS_STYLE_GUIDE.md`

## Deployment

GitHub Pages workflow:

- `.github/workflows/docs-pages.yml`

Deploy triggers on pushes to `main` when files under `docs/` change.
