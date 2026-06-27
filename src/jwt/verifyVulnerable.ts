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
import type {
  VerifyResult,
  VerifierPolicy,
  VerifierKey,
  JwtClaims,
  AlgName,
  TraceStep,
  TraceStatus,
} from './types.ts';

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
  const trace: TraceStep[] = [];
  const step = (label: string, status: TraceStatus, detail: string, decisive = false): void => {
    trace.push({ label, status, detail, decisive });
  };

  const parsed = parseToken(token);
  if (!parsed.ok) {
    step('Token structurally valid?', 'fail', parsed.reason, true);
    // Even the broken verifier can't get past a structurally invalid token here,
    // because it reuses the strict parser. A rejection is the system NOT being fooled.
    return {
      systemIntegrity: 'ok',
      decision: 'reject',
      reason: parsed.reason,
      invariantTriggered: parsed.invariantTriggered,
      signature: 'not-checked',
      claims: 'not-checked',
      trace,
    };
  }
  step('Token structurally valid?', 'pass', 'parsed header + claims');

  const { header, claims, raw, signingInput } = parsed;
  const claimedAlg = header.alg;
  const data = utf8(signingInput);

  // The defining bug: routine is chosen from the TOKEN's alg (attacker-controlled).
  step('Allowlist enforced?', 'fail', 'BUG: no allowlist check — the token is trusted to name its own alg', false);
  step('Routine chosen from token alg?', 'fail', `BUG: dispatching on token alg "${claimedAlg}" instead of the held key type`, false);

  // BUG #1: honour alg:none — no signature required.
  if (claimedAlg === 'none') {
    step('alg:none → skip signature check', 'fail', 'BUG: no signature is verified; the token is accepted as-is', true);
    return {
      systemIntegrity: 'fooled',
      decision: 'accept',
      reason: 'BUG: the token says alg:none, so this verifier skipped signature checking entirely and accepted it',
      invariantTriggered: 'none (this path should not exist)',
      signature: 'not-checked',
      claims: validateClaims(claims, policy.nowSeconds).status,
      claimedAlg,
      trace,
    };
  }

  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    signatureBytes = base64urlDecodeToBytes(raw.signatureB64);
  } catch (e) {
    step('Signature is strict base64url?', 'fail', (e as Error).message, true);
    return {
      systemIntegrity: 'ok',
      decision: 'reject',
      reason: `signature is not strict base64url: ${(e as Error).message}`,
      signature: 'not-checked',
      claims: 'not-checked',
      claimedAlg,
      trace,
    };
  }

  // BUG #2: HS256 will gladly consume a public key as an HMAC secret if that's what
  // the verifier happens to hold.
  if (claimedAlg === 'HS256') {
    const hmacKey = policy.keys.find((k) => k.kind === 'HmacKey');
    if (hmacKey) {
      step('HS256 → HMAC with held secret', 'info', 'genuine shared secret available', false);
      const ok = await subtle.verify('HMAC', hmacKey.key, signatureBytes, data);
      return finishSig(trace, step, ok, false, claims, policy, claimedAlg, 'HMAC with the genuine shared secret');
    }
    const pub = policy.keys.find(
      (k): k is Extract<VerifierKey, { kind: 'RsaPublicKey' | 'EcPublicKey' }> =>
        k.kind === 'RsaPublicKey' || k.kind === 'EcPublicKey',
    );
    if (!pub) return rejectNoKey(trace, step, claimedAlg);
    step(
      'HS256 → HMAC with public-key bytes',
      'fail',
      `BUG: exporting the ${pub.kind} to PEM and using those PUBLIC bytes as the HMAC secret`,
      false,
    );
    const spki = await subtle.exportKey('spki', pub.key);
    const pem = spkiToPem(spki);
    const confusedKey = await subtle.importKey('raw', utf8(pem), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const ok = await subtle.verify('HMAC', confusedKey, signatureBytes, data);
    return finishSig(
      trace,
      step,
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
    if (!rsa) return rejectNoKey(trace, step, claimedAlg);
    const ok = await subtle.verify('RSASSA-PKCS1-v1_5', rsa.key, signatureBytes, data);
    return finishSig(trace, step, ok, false, claims, policy, claimedAlg, 'RSASSA-PKCS1-v1_5 with the RSA public key');
  }

  if (claimedAlg === 'ES256') {
    const ec = policy.keys.find((k) => k.kind === 'EcPublicKey');
    if (!ec) return rejectNoKey(trace, step, claimedAlg);
    const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, ec.key, signatureBytes, data);
    return finishSig(trace, step, ok, false, claims, policy, claimedAlg, 'ECDSA P-256 with the EC public key');
  }

  return rejectNoKey(trace, step, claimedAlg);
}

type StepFn = (label: string, status: TraceStatus, detail: string, decisive?: boolean) => void;

function rejectNoKey(trace: TraceStep[], step: StepFn, claimedAlg: AlgName): VerifyResult {
  step('Key available for this alg?', 'fail', `no key for alg "${claimedAlg}"`, true);
  return {
    systemIntegrity: 'ok',
    decision: 'reject',
    reason: `no key available for alg ${JSON.stringify(claimedAlg)}`,
    signature: 'not-checked',
    claims: 'not-checked',
    claimedAlg,
    trace,
  };
}

function finishSig(
  trace: TraceStep[],
  step: StepFn,
  sigOk: boolean,
  viaConfusion: boolean,
  claims: JwtClaims,
  policy: VerifierPolicy,
  claimedAlg: AlgName,
  routineDescription: string,
): VerifyResult {
  if (!sigOk) {
    step('Signature valid?', 'fail', routineDescription, true);
    return {
      systemIntegrity: 'ok',
      decision: 'reject',
      reason: `signature did not verify (${routineDescription})`,
      signature: 'invalid',
      claims: 'not-checked',
      claimedAlg,
      trace,
    };
  }
  step('Signature valid?', viaConfusion ? 'fail' : 'pass', routineDescription, viaConfusion);
  const claimCheck = validateClaims(claims, policy.nowSeconds);
  const accepted = claimCheck.status === 'valid';
  step('Claims (exp/nbf) valid?', accepted ? 'pass' : 'fail', claimCheck.detail, !accepted);
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
    trace,
  };
}
