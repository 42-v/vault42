/**
 * Vault42 palette.
 *
 * Every value here is fixed by a contrast requirement rather than by taste, and
 * `src/__tests__/palette.test.ts` re-derives the ratios from this file, so a
 * "just a shade" edit fails the suite instead of quietly failing WCAG.
 *
 * The old palette failed AA in three places at once: `muted #64748b` carried
 * body copy across every screen at 4.15:1, `primary #6366f1` was used as link
 * and active-nav text at 4.42:1, and `border #1e1e2e` drew form-field
 * boundaries at 1.20:1 against a 3:1 requirement. A fourth was hiding
 * underneath: `.vault42-btn` put white on `primary` at 4.47:1 and *lightened*
 * to `accent` on hover, which is 2.98:1.
 *
 * `primary` and `accent` were doing each other's jobs. They are split now:
 *
 *   primary        the interactive *surface*. Dark enough that white sits on it
 *                  at 6.29:1. Never used as text.
 *   primary-hover  the hover surface. Darker, so white still passes at 5.43:1.
 *                  Lightening on hover is what broke the base pairing.
 *   accent         the interactive *ink*: links, active nav, focus borders,
 *                  progress fill. 6.62:1 on bg, 6.25:1 on surface.
 *   border         decorative container outlines only — cards, dividers, tinted
 *                  fills. WCAG 1.4.11 exempts non-interactive containers, so
 *                  this stays deliberately subtle.
 *   control        the boundary of an interactive control: inputs, checkboxes,
 *                  outline buttons. 3.24:1 on bg, 3.05:1 on surface.
 *
 * `error` moved from `#ef4444` to red-400 because it is almost always rendered
 * on its own 10-20% tint, where the old value fell to 4.00-4.53:1.
 *
 * @type {import('tailwindcss').Config}
 */
export default {
  content: ['./index.html', './src/**/*.{vue,ts}'],
  theme: {
    extend: {
      colors: {
        vault42: {
          bg: '#0a0a0f',
          surface: '#12121a',
          border: '#1e1e2e',
          control: '#606078',
          primary: '#4f46e5',
          'primary-hover': '#5b53ea',
          accent: '#818cf8',
          text: '#e2e8f0',
          muted: '#94a3b8',
          success: '#22c55e',
          error: '#f87171',
        },
      },
    },
  },
  plugins: [],
}
