/**
 * A QR code as an SVG data URL, for the TOTP enrolment screen.
 *
 * The encoder is `qrcode-generator`: pure JavaScript, no dependencies, and it
 * exposes the module matrix rather than only a rendered image. That matters,
 * because the rendering is the part with a requirement on it -- see the comment
 * at the call site in TwoFactorView -- and this file is where that requirement
 * is met, in code that can be read, rather than inside a library's options bag.
 *
 * It replaced `qrcode`, which brought twenty-seven packages into a browser
 * bundle for one call, including a yargs v13 command-line stack that nothing in
 * a browser can reach. `errorCorrectionLevel: 'M'` is what that library
 * defaulted to, so the code produced here carries the same redundancy as the one
 * it replaces.
 *
 * SVG rather than a raster data URL: it is smaller, it scales to whatever the
 * card gives it without resampling a grid of squares, and `shape-rendering:
 * crispEdges` keeps the module boundaries exact at any size. An `<img>` renders
 * SVG in a sandbox with no script execution, and the frontend CSP already
 * carries `img-src 'self' data:`.
 */
import qrcodeGenerator from 'qrcode-generator'

export interface QROptions {
  /** Rendered width and height in CSS pixels. */
  width: number
  /** Quiet-zone width, in modules. Four is the spec minimum; two is what the
   *  previous library was asked for and what the surrounding card allows. */
  margin: number
  /** Module colour. */
  dark: string
  /** Quiet-zone and light-module colour. Opaque on purpose: a transparent
   *  light colour makes the code undecodable everywhere except the dark card
   *  it was drawn on. */
  light: string
}

/**
 * Renders `text` as an SVG data URL.
 *
 * Throws if the text does not fit any QR version, which is what the encoder
 * does; the caller treats that the same way it treated the previous library
 * rejecting an input.
 */
export function qrDataUrl(text: string, options: QROptions): string {
  // 0 selects the smallest version that fits; 'M' is the redundancy level.
  const qr = qrcodeGenerator(0, 'M')
  qr.addData(text)
  qr.make()

  const modules = qr.getModuleCount()
  const side = modules + options.margin * 2

  // One path for every dark module. Drawn as `M x y h1 v1 h-1 z` rather than
  // one <rect> each: same result, a fraction of the markup, and no per-element
  // attribute parsing for a grid that can run to a couple of thousand squares.
  let path = ''
  for (let row = 0; row < modules; row++) {
    for (let col = 0; col < modules; col++) {
      if (qr.isDark(row, col)) {
        path += `M${col + options.margin} ${row + options.margin}h1v1h-1z`
      }
    }
  }

  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${side} ${side}" ` +
    `width="${options.width}" height="${options.width}" shape-rendering="crispEdges">` +
    `<rect width="${side}" height="${side}" fill="${options.light}"/>` +
    `<path d="${path}" fill="${options.dark}"/>` +
    `</svg>`

  // encodeURIComponent rather than base64: the payload is ASCII markup, so this
  // is both shorter and legible in devtools, and it escapes the `#` in the
  // colours, which would otherwise start a fragment and truncate the image.
  return `data:image/svg+xml,${encodeURIComponent(svg)}`
}
