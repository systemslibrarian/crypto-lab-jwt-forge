/**
 * JWS signing for HS256 / RS256 / ES256, plus the degenerate `none`.
 *
 * The signature is always computed over the ASCII bytes of
 *   base64url(header) + "." + base64url(payload)
 * exactly as required by RFC 7515 §5.1.
 */

import { base64urlEncodeBytes, base64urlEncodeString, utf8 } from './base64url.ts';
import type { JwtHeader, JwtClaims, SigningKey } from './types.ts';

const subtle = globalThis.crypto.subtle;

/** Build the `header.payload` signing input string (ASCII). */
export function signingInput(header: JwtHeader, claims: JwtClaims): string {
  return `${base64urlEncodeString(JSON.stringify(header))}.${base64urlEncodeString(JSON.stringify(claims))}`;
}

async function rawSign(key: SigningKey, data: Uint8Array<ArrayBuffer>): Promise<Uint8Array> {
  switch (key.kind) {
    case 'HmacKey':
      return new Uint8Array(await subtle.sign('HMAC', key.key, data));
    case 'RsaPrivateKey':
      return new Uint8Array(await subtle.sign('RSASSA-PKCS1-v1_5', key.key, data));
    case 'EcPrivateKey':
      // JWS ES256 uses the raw R||S concatenation (64 bytes), which WebCrypto's
      // ECDSA produces directly with the 'raw' encoding (the default for subtle).
      return new Uint8Array(
        await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.key, data),
      );
    // PQ extension point (3 of 3): a new signing key `kind` adds one `case` here and
    // one matching verify routine — the trust model and token format are unchanged.
  }
}

/**
 * Sign a token with a real signing key. The header's `alg` is set to match the key
 * so the produced token is internally consistent.
 */
export async function sign(
  header: Omit<JwtHeader, 'alg'> & { alg?: JwtHeader['alg'] },
  claims: JwtClaims,
  key: SigningKey,
): Promise<string> {
  const fullHeader: JwtHeader = { ...header, alg: key.alg };
  const input = signingInput(fullHeader, claims);
  const sig = await rawSign(key, utf8(input));
  return `${input}.${base64urlEncodeBytes(sig)}`;
}

/**
 * Produce an `alg:none` (unsecured) JWS per RFC 7515 Appendix A.5: the signature is
 * the empty string. This is only ever a legitimate construction inside the attack
 * demo — the Correct verifier rejects it unless `none` is explicitly allowlisted.
 */
export function signNone(header: Omit<JwtHeader, 'alg'>, claims: JwtClaims): string {
  const fullHeader: JwtHeader = { ...header, alg: 'none' };
  return `${signingInput(fullHeader, claims)}.`;
}

/**
 * Sign using arbitrary raw secret bytes as an HMAC key. This is NOT a normal API —
 * it exists so the key-confusion attack can MAC a token using the RSA public key's
 * bytes as the secret. Deliberately bypasses the typed-key system.
 */
export async function hmacSignWithRawSecret(
  secret: Uint8Array<ArrayBuffer>,
  header: JwtHeader,
  claims: JwtClaims,
): Promise<string> {
  const input = signingInput(header, claims);
  const key = await subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = new Uint8Array(await subtle.sign('HMAC', key, utf8(input)));
  return `${input}.${base64urlEncodeBytes(sig)}`;
}
