import { describe, it, expect } from 'vitest';
import {
  base64urlEncodeBytes,
  base64urlEncodeString,
  base64urlDecodeToBytes,
  base64urlDecodeToString,
  Base64UrlError,
} from './base64url.ts';

describe('base64url round-trip', () => {
  it('round-trips arbitrary byte values', () => {
    const bytes = new Uint8Array(256);
    for (let i = 0; i < 256; i++) bytes[i] = i;
    const encoded = base64urlEncodeBytes(bytes);
    expect(/[+/=]/.test(encoded)).toBe(false);
    expect([...base64urlDecodeToBytes(encoded)]).toEqual([...bytes]);
  });

  it('round-trips unicode strings', () => {
    const s = 'héllo · 世界 · 🔐';
    expect(base64urlDecodeToString(base64urlEncodeString(s))).toBe(s);
  });

  it('encodes a known JWT header vector', () => {
    // {"alg":"HS256","typ":"JWT"} -> RFC 7515 well-known vector
    expect(base64urlEncodeString('{"alg":"HS256","typ":"JWT"}')).toBe(
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    );
  });
});

describe('base64url strict rejection', () => {
  it('rejects standard-base64 padding', () => {
    expect(() => base64urlDecodeToBytes('aGk=')).toThrow(Base64UrlError);
  });

  it('rejects + and / characters', () => {
    expect(() => base64urlDecodeToBytes('ab+c')).toThrow(Base64UrlError);
    expect(() => base64urlDecodeToBytes('ab/c')).toThrow(Base64UrlError);
  });

  it('rejects non-canonical length (len % 4 === 1)', () => {
    expect(() => base64urlDecodeToBytes('abcde')).toThrow(/non-canonical length/);
  });

  it('rejects characters outside the alphabet', () => {
    expect(() => base64urlDecodeToBytes('ab.c')).toThrow(Base64UrlError);
    expect(() => base64urlDecodeToBytes('ab c')).toThrow(Base64UrlError);
  });

  it('rejects non-zero trailing bits (non-canonical encoding)', () => {
    // 'QY' decodes 1 byte but the final sextet has non-zero low bits; 'QQ' is canonical.
    expect(() => base64urlDecodeToBytes('QY')).toThrow(/trailing bits/);
    expect([...base64urlDecodeToBytes('QQ')]).toEqual([0x41]);
  });

  it('accepts the canonical no-pad forms', () => {
    expect(base64urlDecodeToString('aGk')).toBe('hi'); // 2-char tail
    expect(base64urlDecodeToString('YWJj')).toBe('abc'); // full group
  });
});
