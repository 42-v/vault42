import { describe, it, expect } from 'vitest'
import { qrDataUrl, type QROptions } from '../qr'

/**
 * The QR code on the TOTP enrolment screen.
 *
 * The assertions that matter here are structural, not cosmetic. A renderer that
 * produced well-formed SVG of the right size and colour, containing a grid that
 * is not a QR code, would pass every obvious test and fail every scanner -- and
 * this is the one screen where that failure is expensive: it lands on a user
 * mid-enrolment, and the fallback is typing a 32-character secret.
 *
 * So the finder patterns are checked. Three 7x7 squares in three corners, each
 * a dark ring around a light ring around a dark 3x3 core, is the structure a
 * scanner locates the symbol by; drawing them correctly is not something a
 * plausible-looking bug does by accident.
 */

const OPTIONS: QROptions = {
  width: 200,
  margin: 2,
  dark: '#0a0a0f',
  light: '#ffffff',
}

const OTP_URL = 'otpauth://totp/Vault42:rider@example.test?secret=JBSWY3DPEHPK3PXP&issuer=Vault42'

function svgOf(url: string): string {
  expect(url.startsWith('data:image/svg+xml,')).toBe(true)
  return decodeURIComponent(url.slice('data:image/svg+xml,'.length))
}

/** The side of the viewBox, in modules, quiet zone included. */
function sideOf(svg: string): number {
  const box = /viewBox="0 0 (\d+) \1"/.exec(svg)
  if (!box) throw new Error(`no square viewBox in ${svg.slice(0, 120)}`)
  return Number(box[1])
}

/** Every dark module, as "x,y", read back out of the path data. */
function darkModules(svg: string): Set<string> {
  const path = /<path d="([^"]*)"/.exec(svg)
  if (!path) throw new Error('no path element')
  const out = new Set<string>()
  for (const [, x, y] of path[1].matchAll(/M(\d+) (\d+)h1v1h-1z/g)) {
    out.add(`${x},${y}`)
  }
  return out
}

describe('qrDataUrl', () => {
  it('is a data URL an <img> can render under the frontend CSP', () => {
    const url = qrDataUrl(OTP_URL, OPTIONS)
    // `img-src 'self' data:` is what web/nginx.conf and
    // internal/middleware/security_headers.go both publish, so `data:` is the
    // scheme this has to use.
    expect(url.startsWith('data:image/svg+xml,')).toBe(true)
  })

  it('escapes the # in the colours instead of truncating the image', () => {
    // A bare `#` starts a fragment. Left unescaped, the browser drops
    // everything from the first colour onward and the image is a blank square
    // -- which looks like a rendering failure rather than an encoding one.
    const url = qrDataUrl(OTP_URL, OPTIONS)
    expect(url).not.toContain('#')
    expect(svgOf(url)).toContain('#0a0a0f')
  })

  it('paints the modules dark on an opaque light quiet zone', () => {
    const svg = svgOf(qrDataUrl(OTP_URL, OPTIONS))
    // Opaque, deliberately. Light modules on transparency read correctly on the
    // dark card and are undecodable the moment the code is screenshotted onto
    // white, which is the defect the call site's comment records.
    expect(svg).toContain(`<rect width="${sideOf(svg)}" height="${sideOf(svg)}" fill="#ffffff"/>`)
    expect(svg).toContain('fill="#0a0a0f"')
  })

  it('renders at the requested pixel size with a square viewBox', () => {
    const svg = svgOf(qrDataUrl(OTP_URL, OPTIONS))
    expect(svg).toContain('width="200" height="200"')
    expect(svg).toContain('shape-rendering="crispEdges"')
  })

  it('surrounds the symbol with the quiet zone it was asked for', () => {
    const svg = svgOf(qrDataUrl(OTP_URL, OPTIONS))
    const side = sideOf(svg)
    const dark = darkModules(svg)
    expect(dark.size).toBeGreaterThan(0)

    for (const key of dark) {
      const [x, y] = key.split(',').map(Number)
      expect(x).toBeGreaterThanOrEqual(OPTIONS.margin)
      expect(y).toBeGreaterThanOrEqual(OPTIONS.margin)
      expect(x).toBeLessThan(side - OPTIONS.margin)
      expect(y).toBeLessThan(side - OPTIONS.margin)
    }
  })

  it('draws the three finder patterns a scanner locates the symbol by', () => {
    const svg = svgOf(qrDataUrl(OTP_URL, OPTIONS))
    const side = sideOf(svg)
    const modules = side - OPTIONS.margin * 2
    const dark = darkModules(svg)
    const isDark = (col: number, row: number) =>
      dark.has(`${col + OPTIONS.margin},${row + OPTIONS.margin}`)

    // Top-left, top-right, bottom-left. There is deliberately none in the
    // fourth corner: that asymmetry is how a scanner resolves orientation, so
    // it is asserted too.
    for (const [originCol, originRow] of [
      [0, 0],
      [modules - 7, 0],
      [0, modules - 7],
    ]) {
      for (let r = 0; r < 7; r++) {
        for (let c = 0; c < 7; c++) {
          const ring = r === 0 || r === 6 || c === 0 || c === 6
          const core = r >= 2 && r <= 4 && c >= 2 && c <= 4
          expect(
            isDark(originCol + c, originRow + r),
            `finder at ${originCol},${originRow} module ${c},${r}`,
          ).toBe(ring || core)
        }
      }
    }

    // The fourth corner carries an alignment pattern at most, never a finder:
    // its outer ring is not closed.
    const bottomRightRingClosed = [0, 1, 2, 3, 4, 5, 6].every((c) =>
      isDark(modules - 7 + c, modules - 7),
    )
    expect(bottomRightRingClosed).toBe(false)
  })

  it('grows the symbol rather than truncating a longer payload', () => {
    const short = svgOf(qrDataUrl('otpauth://totp/a?secret=JBSWY3DP', OPTIONS))
    const long = svgOf(qrDataUrl(OTP_URL + '&image=' + 'x'.repeat(300), OPTIONS))
    expect(sideOf(long)).toBeGreaterThan(sideOf(short))
  })

  it('honours a different quiet zone and pixel size', () => {
    const svg = svgOf(qrDataUrl(OTP_URL, { ...OPTIONS, margin: 4, width: 320 }))
    const base = svgOf(qrDataUrl(OTP_URL, OPTIONS))
    expect(sideOf(svg)).toBe(sideOf(base) + 4)
    expect(svg).toContain('width="320" height="320"')
  })

  it('throws when the payload fits no QR version, rather than emitting a broken code', () => {
    // The call site catches this and falls back to the manual secret. A
    // renderer that returned a malformed image here would put an unscannable
    // code on the screen with nothing saying so.
    expect(() => qrDataUrl('x'.repeat(10000), OPTIONS)).toThrow()
  })
})
