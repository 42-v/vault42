# vault42 · ROOT OF TRUST

Static marketing landing page for `vault.42-v.com`.

## Files
- `index.html` — self-contained landing (plain HTML)
- `styles.css` — design tokens + components + CRT atmosphere (derived verbatim from /allow/branding)
- `app.js` — vanilla JS for live trust chain demo, hash-chained audit, copy buttons, reduced-motion guards

## Preview (local)
Open `index.html` directly in a browser:

```bash
# simplest
open site/index.html
# or
python3 -m http.server 8080 --directory site
# then visit http://localhost:8080
```

Works offline. No build step.

## Production serve
This tree is intended to be served statically at `https://vault.42-v.com` (or equivalent origin).
- Use any static host (nginx, Caddy, object storage + CDN, GitHub Pages, etc.).
- Ensure correct `Content-Type` for `.js`/`.css` and `index.html` as entry.
- Add security headers matching the product (CSP, HSTS, etc.) in the serving layer.
- Versioning: update the `v0.8.0` marker and any copy on release.

## Scope
Purely additive under `site/`. Does not touch `web/`, Go sources, or any other directories.
All branding tokens, copy, and behavior are derived strictly from the canonical design language and actual repository facts.

## Keyboard / a11y
- All interactive targets >= 44px effective.
- Full keyboard navigation + visible focus rings.
- `prefers-reduced-motion` disables loops, scans, flicker; static final states shown.
- WCAG AAA contrast on AMOLED void.

MIT License. See root LICENSE.
