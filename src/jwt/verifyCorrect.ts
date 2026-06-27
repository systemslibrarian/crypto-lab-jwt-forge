/**
 * The CORRECT verifier. It is the default trust path and embodies invariants 1–6.
 *
 * The single load-bearing rule (invariant #2): the APPLICATION's policy decides which
 * algorithm(s) and key(s) are acceptable. The verifier compares the token's `alg`
 * against the policy and then dispatches the verification routine on the TYPE of the
 * key it holds — NEVER on the `alg` value carried inside the (attacker-controlled)
 * token. That one rule defeats both alg:none and key confusion.
 */

import { base64urlDecodeToBytes, utf8 } from './base64url.ts';
import { parseToken } from './parse.ts';
import { validateClaims } from './claims.ts';
import type { VerifyResult, VerifierPolicy, VerifierKey, AlgName } from './types.ts';

const subtle = globalThis.crypto.subtle;

function reject(reason: string, invariantTriggered: string, claimedAlg?: AlgName): VerifyResult {
  return {
    systemIntegrity: 'ok', // the Correct verifier rejecting a forgery is the system working
    decision: 'reject',
    reason,
    invariantTriggered,
    signature: 'not-checked',
    claims: 'not-checked',
    claimedAlg,
  };
}

/**
 * Dispatch the signature check on the KEY TYPE. The token's claimed alg never selects
 * the routine; it is only used to choose which held key to attempt (and must match it).
 */
async function verifySignatureWithKey(
  key: VerifierKey,
  signingInput: string,
  signatureBytes: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
  const data = utf8(signingInput);
  switch (key.kind) {
    case 'HmacKey':
      return subtle.verify('HMAC', key.key, signatureBytes, data);
    case 'RsaPublicKey':
      return subtle.verify('RSASSA-PKCS1-v1_5', key.key, signatureBytes, data);
    case 'EcPublicKey':
      return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key.key, signatureBytes, data);
    // PQ extension point: a new key `kind` adds one case here. No other path changes.
  }
}

export async function verifyCorrect(
  token: string,
  policy: VerifierPolicy,
): Promise<VerifyResult> {
  // Invariant #1: the allowlist is required and an empty policy accepts nothing.
  if (policy.acceptedAlgs.size === 0) {
    return reject(
      'policy accepts no algorithms — an empty/missing allowlist means accept NOTHING',
      'required allowlist (invariant #1)',
    );
  }

  const parsed = parseToken(token);
  if (!parsed.ok) {
    return reject(parsed.reason, parsed.invariantTriggered);
  }

  const { header, claims, raw, signingInput } = parsed;
  const claimedAlg = header.alg;

  // Invariant #1/#2: the token's alg must be explicitly allowlisted by the application.
  if (!policy.acceptedAlgs.has(claimedAlg)) {
    return reject(
      `alg ${JSON.stringify(claimedAlg)} is not in the verifier's accepted-algorithms allowlist`,
      'alg not in allowlist (invariant #1)',
      claimedAlg,
    );
  }

  // `none` is only reachable if the application explicitly allowlisted it (which only
  // the attack demo does). Even then we require a genuinely empty signature.
  if (claimedAlg === 'none') {
    if (raw.signatureB64 !== '') {
      return reject(
        "alg 'none' must carry an empty signature",
        "alg:none requires empty signature",
        claimedAlg,
      );
    }
    // Signature step is vacuously satisfied; still run claim checks independently.
    const claimCheck = validateClaims(claims, policy.nowSeconds);
    return {
      systemIntegrity: 'ok',
      decision: claimCheck.status === 'valid' ? 'accept' : 'reject',
      reason:
        claimCheck.status === 'valid'
          ? "alg:none explicitly allowlisted by the application — accepted as an UNSECURED token"
          : `unsecured token but ${claimCheck.detail}`,
      signature: 'valid',
      claims: claimCheck.status,
      claimDetail: claimCheck.detail,
      claimedAlg,
    };
  }

  // A real (non-none) alg must carry a non-empty signature.
  if (raw.signatureB64 === '') {
    return reject(
      `alg ${JSON.stringify(claimedAlg)} requires a signature, but the signature segment is empty`,
      'empty signature on a signing alg',
      claimedAlg,
    );
  }

  // Select the held key by matching the token's alg to a key we ACTUALLY HOLD for that
  // alg. The routine is then chosen by the key's TYPE, not by the token's alg string.
  const candidates = policy.keys.filter((k) => k.alg === claimedAlg);
  if (candidates.length === 0) {
    return reject(
      `the verifier holds no key for alg ${JSON.stringify(claimedAlg)}`,
      'no held key for alg (type binding, invariant #3)',
      claimedAlg,
    );
  }

  // Multiple candidate keys → require a kid to select one (no key guessing).
  let key: VerifierKey;
  if (candidates.length > 1) {
    if (typeof header.kid !== 'string') {
      return reject(
        'multiple keys are available but the token has no kid — refusing to guess a key',
        'no key guessing without kid',
        claimedAlg,
      );
    }
    const matched = candidates.find((k) => k.kid === header.kid);
    if (!matched) {
      return reject(
        `no held key matches kid ${JSON.stringify(header.kid)}`,
        'no key guessing without kid',
        claimedAlg,
      );
    }
    key = matched;
  } else {
    key = candidates[0];
  }

  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    signatureBytes = base64urlDecodeToBytes(raw.signatureB64);
  } catch (e) {
    return reject(
      `signature is not strict base64url: ${(e as Error).message}`,
      'strict base64url decode (invariant #4)',
      claimedAlg,
    );
  }

  const sigValid = await verifySignatureWithKey(key, signingInput, signatureBytes);
  if (!sigValid) {
    return {
      systemIntegrity: 'ok',
      decision: 'reject',
      reason: `signature does not verify under the held ${key.kind} (${key.alg})`,
      signature: 'invalid',
      claims: 'not-checked',
      claimedAlg,
    };
  }

  // Signature is valid. Now — and only now, and reported SEPARATELY — check claims.
  const claimCheck = validateClaims(claims, policy.nowSeconds);
  return {
    systemIntegrity: 'ok',
    decision: claimCheck.status === 'valid' ? 'accept' : 'reject',
    reason:
      claimCheck.status === 'valid'
        ? `valid ${claimedAlg} signature; all claim checks passed`
        : `signature is valid but ${claimCheck.detail}`,
    signature: 'valid',
    claims: claimCheck.status,
    claimDetail: claimCheck.detail,
    claimedAlg,
  };
}
