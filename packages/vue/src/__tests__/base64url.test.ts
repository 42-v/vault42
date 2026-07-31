import { describe, it, expect } from 'vitest'
import { base64urlToBuffer, bufferToBase64url } from '../base64url'

/**
 * base64url decodes WebAuthn challenge material, user handles and credential
 * IDs straight off the wire (useWebAuthn feeds the result to
 * navigator.credentials.create/get). Every input here is therefore attacker
 * influenced: what must never happen is a malformed string quietly producing a
 * buffer of the wrong bytes.
 */

function bytes(...values: number[]): ArrayBuffer {
  return new Uint8Array(values).buffer
}

function toArray(buf: ArrayBuffer): number[] {
  return Array.from(new Uint8Array(buf))
}

describe('bufferToBase64url', () => {
  it('encodes with the base64url alphabet, not standard base64', () => {
    // 0xFB 0xEF 0xBE is the bit pattern that produces "++++" in standard
    // base64; 0xFF 0xFF 0xFF produces "////". Both must be substituted.
    expect(bufferToBase64url(bytes(0xfb, 0xef, 0xbe))).toBe('----')
    expect(bufferToBase64url(bytes(0xff, 0xff, 0xff))).toBe('____')
  })

  it('emits no padding for any input length', () => {
    for (let n = 0; n <= 12; n++) {
      const buf = new Uint8Array(n).map((_, i) => i * 7 + 1).buffer
      const encoded = bufferToBase64url(buf)
      expect(encoded, `length ${n}`).not.toContain('=')
      expect(encoded, `length ${n}`).toMatch(/^[A-Za-z0-9_-]*$/)
    }
  })

  it('encodes the empty buffer as the empty string', () => {
    expect(bufferToBase64url(new ArrayBuffer(0))).toBe('')
  })

  it('preserves bytes above 0x7f rather than mangling them as text', () => {
    // A naive TextDecoder-based implementation turns these into U+FFFD.
    const high = bytes(0x80, 0x9f, 0xc3, 0xa9, 0xfe, 0xff)
    expect(toArray(base64urlToBuffer(bufferToBase64url(high)))).toEqual([
      0x80, 0x9f, 0xc3, 0xa9, 0xfe, 0xff,
    ])
  })
})

describe('base64urlToBuffer', () => {
  it('decodes a known vector to exact bytes', () => {
    expect(toArray(base64urlToBuffer('AQIDBAU'))).toEqual([1, 2, 3, 4, 5])
  })

  it('decodes the empty string to an empty ArrayBuffer', () => {
    const buf = base64urlToBuffer('')
    expect(buf).toBeInstanceOf(ArrayBuffer)
    expect(buf.byteLength).toBe(0)
  })

  it('accepts unpadded input of every length class mod 4', () => {
    // 2 chars -> 1 byte, 3 chars -> 2 bytes, 4 chars -> 3 bytes.
    expect(toArray(base64urlToBuffer('QQ'))).toEqual([0x41])
    expect(toArray(base64urlToBuffer('QUI'))).toEqual([0x41, 0x42])
    expect(toArray(base64urlToBuffer('QUJD'))).toEqual([0x41, 0x42, 0x43])
  })
})

describe('base64url round trip', () => {
  it('preserves length and content for every byte count 0..16', () => {
    for (let n = 0; n <= 16; n++) {
      const source = new Uint8Array(n)
      for (let i = 0; i < n; i++) source[i] = (i * 37 + 11) & 0xff
      const decoded = base64urlToBuffer(bufferToBase64url(source.buffer))
      expect(decoded.byteLength, `length ${n}`).toBe(n)
      expect(toArray(decoded), `length ${n}`).toEqual(Array.from(source))
    }
  })

  it('preserves every possible byte value 0x00..0xff', () => {
    const all = new Uint8Array(256)
    for (let i = 0; i < 256; i++) all[i] = i
    expect(toArray(base64urlToBuffer(bufferToBase64url(all.buffer)))).toEqual(Array.from(all))
  })

  it('handles a buffer far larger than the call-argument limit', () => {
    // Guards against a String.fromCharCode(...bytes) "optimisation", which
    // blows the stack on real attestation objects.
    const big = new Uint8Array(64 * 1024)
    for (let i = 0; i < big.length; i++) big[i] = i & 0xff
    const decoded = base64urlToBuffer(bufferToBase64url(big.buffer))
    expect(decoded.byteLength).toBe(big.length)
    expect(new Uint8Array(decoded)[big.length - 1]).toBe((big.length - 1) & 0xff)
  })
})

/**
 * These only assert rejections that hold under both this host's atob and the
 * WHATWG forgiving-base64 algorithm browsers use. The module adds no alphabet
 * or length check of its own, so anything the two disagree on (embedded
 * whitespace, which browsers strip) is a runtime-defined outcome and is
 * deliberately not pinned here.
 */
describe('base64urlToBuffer rejects malformed input', () => {
  it('rejects a length that cannot encode any byte string (len % 4 === 1)', () => {
    // The decoder pads blindly ("A" -> "A==="), so this only fails because
    // atob rejects it. It must fail, not return a zero-length buffer.
    expect(() => base64urlToBuffer('A')).toThrow()
    expect(() => base64urlToBuffer('QUJDR')).toThrow()
  })

  it('rejects characters outside the alphabet', () => {
    expect(() => base64urlToBuffer('QQ!!')).toThrow()
    expect(() => base64urlToBuffer('QQé')).toThrow()
  })

  it('rejects excess padding', () => {
    expect(() => base64urlToBuffer('QQ===')).toThrow()
  })

  it('throws rather than returning a buffer for a non-string input', () => {
    // DEFECT: this surfaces as a bare TypeError from String.prototype.replace,
    // not a typed SDK error. It still fails closed (no buffer is produced).
    expect(() => base64urlToBuffer(null as unknown as string)).toThrow(TypeError)
    expect(() => base64urlToBuffer(undefined as unknown as string)).toThrow(TypeError)
  })
})

describe('base64urlToBuffer laxness (documented, not endorsed)', () => {
  it('DEFECT: accepts the standard base64 alphabet, so two strings alias to one buffer', () => {
    // "+" and "/" are never produced by bufferToBase64url and are not part of
    // base64url, yet they decode. A challenge echoed back in a different
    // alphabet therefore compares unequal as a string but equal as bytes.
    expect(toArray(base64urlToBuffer('-_8'))).toEqual(toArray(base64urlToBuffer('+/8')))
    expect(toArray(base64urlToBuffer('++++'))).toEqual([251, 239, 190])
  })

  it('DEFECT: accepts non-canonical trailing bits, so distinct strings decode alike', () => {
    // "QQ" and "QR" differ in the discarded low bits of the final sextet.
    expect(toArray(base64urlToBuffer('QQ'))).toEqual([0x41])
    expect(toArray(base64urlToBuffer('QR'))).toEqual([0x41])
    expect(bufferToBase64url(base64urlToBuffer('QR'))).toBe('QQ')
  })

  it('accepts already-padded input, which the encoder never emits', () => {
    expect(toArray(base64urlToBuffer('QQ=='))).toEqual([0x41])
  })
})
