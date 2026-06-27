/**
 * Per-session key generation. All key material lives in memory only and is never
 * persisted (no localStorage, no network, no export to disk).
 */

import type {
  HmacKey,
  RsaPublicKey,
  RsaPrivateKey,
  EcPublicKey,
  EcPrivateKey,
} from './types.ts';

const subtle = globalThis.crypto.subtle;

export interface SessionKeys {
  hmac: HmacKey;
  rsaPublic: RsaPublicKey;
  rsaPrivate: RsaPrivateKey;
  ecPublic: EcPublicKey;
  ecPrivate: EcPrivateKey;
  /**
   * The RSA public key serialised as a PEM string. This is the byte-for-byte object
   * the key-confusion attack feeds into an HMAC as if it were a shared secret — the
   * whole point of that attack is that a public value gets treated as secret.
   */
  rsaPublicKeyPem: string;
}

function derToPem(der: ArrayBuffer, label: string): string {
  const bytes = new Uint8Array(der);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const b64 = btoa(binary);
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

export async function generateSessionKeys(): Promise<SessionKeys> {
  const hmacCryptoKey = await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  );

  const rsaPair = await subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );

  const ecPair = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );

  const rsaSpki = await subtle.exportKey('spki', rsaPair.publicKey);

  return {
    hmac: { kind: 'HmacKey', alg: 'HS256', key: hmacCryptoKey, kid: 'hmac-1' },
    rsaPublic: { kind: 'RsaPublicKey', alg: 'RS256', key: rsaPair.publicKey, kid: 'rsa-1' },
    rsaPrivate: { kind: 'RsaPrivateKey', alg: 'RS256', key: rsaPair.privateKey, kid: 'rsa-1' },
    ecPublic: { kind: 'EcPublicKey', alg: 'ES256', key: ecPair.publicKey, kid: 'ec-1' },
    ecPrivate: { kind: 'EcPrivateKey', alg: 'ES256', key: ecPair.privateKey, kid: 'ec-1' },
    rsaPublicKeyPem: derToPem(rsaSpki, 'PUBLIC KEY'),
  };
}
