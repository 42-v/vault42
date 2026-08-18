# vault42 · ROOT OF TRUST

Static marketing landing page for `vault.42-v.com`.

## Files

- `index.html` — self-contained landing (plain HTML)
- `styles.css` — design tokens + components + CRT atmosphere
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
- Versioning is not a manual step. `index.html` carries two version strings, the footer marker
  and the `--set image.tag=` line in the quickstart, and `scripts/version-bump.sh` rewrites both
  from `VERSION`. The `Version consistency` CI job runs that script with `--check`, so a stale
  marker here fails the build rather than shipping.

## Scope

Nothing under `site/` writes anywhere else, but the page is not invisible to the rest of the
repository, and a change here can turn CI red:

- `pnpm lint` runs `eslint .` from the root at `--max-warnings 0`, and `eslint.config.mjs` does
  not ignore `site/`, so `app.js` is linted on every pull request.
- `scripts/version-bump.sh` owns the two version strings in `index.html`, and its rules are
  required: a location that stops matching is treated as having dropped out of the propagation
  set.
- `scripts/release-check.sh` scans `site` along with `docs` for chart paths that do not exist,
  and fails the release on one.

Nothing builds, bundles, deploys or tests `site/`. There is no `package.json` under it and it is
not in the pnpm workspace.

## Keyboard / a11y

- Every interactive element is a native `<a>` or `<button>`, so tab order and activation come
  from the browser, and `styles.css` gives all three of them a visible `:focus-visible` outline.
- `prefers-reduced-motion` is honoured in both layers: CSS stops the CRT, grain, scanline and
  badge animations, and `app.js` paints the trust-chain demo's resolved end state instead of
  running the sequence.
- Most targets are at least 44px, set explicitly on the nav links, buttons, footer links and the
  ledger and quickstart controls. The two deploy tabs are not: they have padding and no
  `min-height`, so they render around 22px tall.
- The deploy tabs declare `role="tablist"` and `role="tab"` but bind click only. The WAI-ARIA
  tabs pattern expects arrow keys and a roving `tabindex`, and neither exists, so a screen
  reader is promised a widget the keyboard does not deliver.
- Contrast is AAA for body text (`--text` and `--accent` are both about 15:1 on black) and is
  not AAA everywhere. `--text-dim` is 4.3:1, below AA for normal text, and it colours the nav
  links, the deploy tabs, the footer links and the metadata rows. `--text-ghost` is 2.0:1 and is
  used at 9px for the `.small` paragraphs.

MIT License. See root LICENSE.
