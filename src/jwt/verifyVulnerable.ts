/**
 * The VULNERABLE verifier — DELIBERATELY BROKEN. This module exists only to be
 * contrasted with the Correct verifier. It must never be the default trust path and
 * is labelled as broken everywhere it surfaces in the UI (invariant #7).
 *
 * It reproduces the two classic structural bugs:
 *   1. It selects the verification routine from the TOKEN's `alg` (attacker input),
 *      so a forged `alg:none` token "verifies" with no signature at all.
 *   2. When the token claims HS256 but the verifier holds an RSA/EC PUBLIC key, it
 *      treats the public key's bytes as an HMAC shared secret — the RS/HS confusion.
 *
 * It also ignores the application's allowlist, trusting whatever the token claims.
 */

import { base64urlDecodeToBytes, utf8 } from './base64url.ts';
import { parseToken } from './parse.ts';
import { validateClaims } from './claims.ts';
import type { VerifyResult, VerifierPolicy, VerifierKey } from './types.ts';

const subtle = globalThis.crypto.subtle;

/** Re-serialise an exported SPKI public key to PEM — the exact bytes the attacker MACs with. */
function spkiToPem(der: ArrayBuffer): string {
  const bytes = new Uint8Array(der);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const b64 = btoa(binary);
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----\n`;
}

export async function verifyVulnerable(
  token: string,
  policy: VerifierPolicy,
): Promise<VerifyResult> {
  const parsed = parseToken(token);
  if (!parsed.ok) {
    // Even the broken verifier can't get past a structurally invalid token here,
    // because it reuses the strict parser. A rejection is the system NOT being fooled.
    return {
      systemIntegrity: 'ok',
      decision: 'reject',
      reason: parsed.reason,
      invariantTriggered: parsed.invariantTriggered,
      signature: 'not-checked',
      claims: 'not-checked',
    };
  }

  const { header, claims, raw, signingInput } = parsed;
  const claimedAlg = header.alg;
  const data = utf8(signingInput);

  // BUG #1: honour alg:none — no signature required. (Note: the allowlist is ignored.)
  if (claimedAlg === 'none') {
    return {
      systemIntegrity: 'fooled',
      decision: 'accept',
      reason:
        "BUG: the token says alg:none, so this verifier skipped signature checking entirely and accepted it",
      invariantTriggered: 'none (this path should not exist)',
      signature: 'not-checked',
      claims: validateClaims(claims, policy.nowSeconds).status,
      claimedAlg,
    };
  }

  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    signatureBytes = base64urlDecodeToBytes(raw.signatureB64);
  } catch (e) {
    return {
      systemIntegrity: 'ok',
      decision: 'reject',
      reason: `signature is not strict base64url: ${(e as Error).message}`,
      signature: 'not-checked',
      claims: 'not-checked',
      claimedAlg,
    };
  }

  // BUG #2: routine is chosen from the TOKEN's alg, and HS256 will gladly consume a
  // public key as an HMAC secret if that's what the verifier happens to hold.
  if (claimedAlg === 'HS256') {
    const hmacKey = policy.keys.find((k) => k.kind === 'HmacKey');
    if (hmacKey) {
      const ok = await subtle.verify('HMAC', hmacKey.key, signatureBytes, data);
      return finishSig(ok, false, claims, policy, claimedAlg, 'HMAC with the genuine shared secret');
    }
    // No HMAC key held — grab whatever public key is around and use its bytes as the secret.
    const pub = policy.keys.find((k): k is Extract<VerifierKey, { kind: 'RsaPublicKey' | 'EcPublicKey' }> =>
      k.kind === 'RsaPublicKey' || k.kind === 'EcPublicKey',
    );
    if (!pub) {
      return rejectNoKey(claimedAlg);
    }
    const spki = await subtle.exportKey('spki', pub.key);
    const pem = spkiToPem(spki);
    const confusedKey = await subtle.importKey(
      'raw',
      utf8(pem),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    const ok = await subtle.verify('HMAC', confusedKey, signatureBytes, data);
    return finishSig(
      ok,
      true,
      claims,
      policy,
      claimedAlg,
      `HMAC using the ${pub.kind} PEM bytes as the secret (RS/HS confusion)`,
    );
  }

  if (claimedAlg === 'RS256') {
    const rsa = policy.keys.find((k) => k.kind === 'RsaPublicKey');
    if (!rsa) return rejectNoKey(claimedAlg);
    const ok = await subtle.verify('RSASSA-PKCS1-v1_5', rsa.key, signatureBytes, data);
    return finishSig(ok, false, claims, policy, claimedAlg, 'RSASSA-PKCS1-v1_5 with the RSA public key');
  }

  if (claimedAlg === 'ES256') {
    const ec = policy.keys.find((k) => k.kind === 'EcPublicKey');
    if (!ec) return rejectNoKey(claimedAlg);
    const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, ec.key, signatureBytes, data);
    return finishSig(ok, false, claims, policy, claimedAlg, 'ECDSA P-256 with the EC public key');
  }

  return rejectNoKey(claimedAlg);
}

function rejectNoKey(claimedAlg: VerifyResult['claimedAlg']): VerifyResult {
  return {
    systemIntegrity: 'ok',
    decision: 'reject',
    reason: `no key available for alg ${JSON.stringify(claimedAlg)}`,
    signature: 'not-checked',
    claims: 'not-checked',
    claimedAlg,
  };
}

function finishSig(
  sigOk: boolean,
  viaConfusion: boolean,
  claims: import('./types.ts').JwtClaims,
  policy: VerifierPolicy,
  claimedAlg: VerifyResult['claimedAlg'],
  routineDescription: string,
): VerifyResult {
  if (!sigOk) {
    return {
      systemIntegrity: 'ok',
      decision: 'reject',
      reason: `signature did not verify (${routineDescription})`,
      signature: 'invalid',
      claims: 'not-checked',
      claimedAlg,
    };
  }
  const claimCheck = validateClaims(claims, policy.nowSeconds);
  const accepted = claimCheck.status === 'valid';
  return {
    // It was fooled only if it actually accepted a token via the confusion path.
    systemIntegrity: viaConfusion && accepted ? 'fooled' : 'ok',
    decision: accepted ? 'accept' : 'reject',
    reason: accepted
      ? viaConfusion
        ? `BUG: signature "verified" via ${routineDescription} — a public value was used as a secret`
        : `valid signature (${routineDescription}); claims passed`
      : `signature valid (${routineDescription}) but ${claimCheck.detail}`,
    signature: 'valid',
    claims: claimCheck.status,
    claimDetail: claimCheck.detail,
    claimedAlg,
  };
}
