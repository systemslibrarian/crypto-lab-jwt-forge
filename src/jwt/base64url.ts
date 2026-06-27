/**
 * Strict base64url (RFC 4648 §5, no padding) encode/decode.
 *
 * Security invariant #4: decoding is STRICT. We reject standard-base64 characters
 * (`+`, `/`, `=`), reject characters outside the base64url alphabet, reject
 * non-canonical lengths, and reject non-zero trailing bits. Lenient base64 decoding
 * is its own vulnerability class (it lets an attacker smuggle alternate encodings of
 * the same logical token past naive equality checks), so we never tolerate it.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// Reverse lookup: char code -> 6-bit value, or -1 if not in the base64url alphabet.
const LOOKUP: Int8Array = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) {
    table[ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

export class Base64UrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Base64UrlError';
  }
}

/** Encode raw bytes as base64url with no padding. */
export function base64urlEncodeBytes(bytes: Uint8Array): string {
  let out = '';
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < len ? bytes[i + 1] : 0;
    const b2 = i + 2 < len ? bytes[i + 2] : 0;

    out += ALPHABET[b0 >> 2];
    out += ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)];
    if (i + 1 < len) out += ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)];
    if (i + 2 < len) out += ALPHABET[b2 & 0x3f];
  }
  return out;
}

const TEXT_ENCODER = new TextEncoder();

/**
 * UTF-8 encode a string to ArrayBuffer-backed bytes. We copy into a fresh
 * `Uint8Array` so the result is typed `Uint8Array<ArrayBuffer>` — the concrete buffer
 * type WebCrypto's `BufferSource` parameters require (TextEncoder.encode is typed as
 * the more general `ArrayBufferLike`).
 */
export function utf8(text: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(TEXT_ENCODER.encode(text));
}

/** Encode a JS string as UTF-8 then base64url. */
export function base64urlEncodeString(text: string): string {
  return base64urlEncodeBytes(utf8(text));
}

/**
 * Decode base64url to raw bytes. Throws Base64UrlError on any non-strict input.
 */
export function base64urlDecodeToBytes(input: string): Uint8Array<ArrayBuffer> {
  // Reject standard-base64 characters explicitly so the error is pedagogically clear.
  if (/[+/=]/.test(input)) {
    throw new Base64UrlError(
      'contains standard-base64 characters (+, /, or =); base64url uses - and _ and no padding',
    );
  }

  const len = input.length;
  // A base64url segment length of (mod 4 === 1) is impossible to produce from any
  // byte string — it is a structurally non-canonical length.
  if (len % 4 === 1) {
    throw new Base64UrlError('non-canonical length (length % 4 === 1 is impossible)');
  }

  // Validate alphabet and gather 6-bit values.
  const sextets = new Int8Array(len);
  for (let i = 0; i < len; i++) {
    const code = input.charCodeAt(i);
    const val = code < 128 ? LOOKUP[code] : -1;
    if (val < 0) {
      throw new Base64UrlError(`invalid base64url character at index ${i}: ${JSON.stringify(input[i])}`);
    }
    sextets[i] = val;
  }

  // Reject non-zero trailing bits (otherwise two distinct strings could decode to the
  // same bytes — a malleability / non-canonical encoding).
  const rem = len % 4;
  if (rem === 2 && (sextets[len - 1] & 0x0f) !== 0) {
    throw new Base64UrlError('non-canonical encoding: non-zero trailing bits');
  }
  if (rem === 3 && (sextets[len - 1] & 0x03) !== 0) {
    throw new Base64UrlError('non-canonical encoding: non-zero trailing bits');
  }

  const outLen = Math.floor((len * 6) / 8);
  const out = new Uint8Array(outLen);
  let oi = 0;
  for (let i = 0; i < len; i += 4) {
    const s0 = sextets[i];
    const s1 = i + 1 < len ? sextets[i + 1] : 0;
    const s2 = i + 2 < len ? sextets[i + 2] : 0;
    const s3 = i + 3 < len ? sextets[i + 3] : 0;

    if (oi < outLen) out[oi++] = (s0 << 2) | (s1 >> 4);
    if (oi < outLen) out[oi++] = ((s1 & 0x0f) << 4) | (s2 >> 2);
    if (oi < outLen) out[oi++] = ((s2 & 0x03) << 6) | s3;
  }
  return out;
}

/** Decode base64url to a UTF-8 string. */
export function base64urlDecodeToString(input: string): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(base64urlDecodeToBytes(input));
}
