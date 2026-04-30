/**
 * TOTP code generation for admin gateway E2E tests.
 * Uses Node.js crypto module — no external dependencies.
 * Standard RFC 6238: HMAC-SHA1, 30-second period, 6 digits.
 */

import { createHmac } from 'crypto';

/**
 * Decode a base32-encoded string (RFC 4648, no padding).
 */
function base32Decode(input: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = input.toUpperCase().replace(/=+$/, '');
  let bits = '';
  for (const ch of cleaned) {
    const val = alphabet.indexOf(ch);
    if (val === -1) throw new Error(`Invalid base32 character: ${ch}`);
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

/**
 * Generate a 6-digit TOTP code for the given secret and time.
 */
export function generateTOTP(secret: string, time?: Date): string {
  const key = base32Decode(secret);
  const counter = Math.floor((time || new Date()).getTime() / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));

  const hmac = createHmac('sha1', key);
  hmac.update(buf);
  const hash = hmac.digest();

  const offset = hash[hash.length - 1] & 0x0f;
  const code = hash.readUInt32BE(offset) & 0x7fffffff;
  return (code % 1000000).toString().padStart(6, '0');
}

/**
 * Generate a TOTP code for 31 seconds in the future (avoids replay rejection).
 */
export function generateFutureTOTP(secret: string): string {
  return generateTOTP(secret, new Date(Date.now() + 31_000));
}
