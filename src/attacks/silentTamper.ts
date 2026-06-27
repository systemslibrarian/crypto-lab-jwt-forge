/**
 * Control attack: silent tamper. Edit a claim but leave the original signature in
 * place. This is the "naive" forgery that any correctly-implemented signature check —
 * even the Vulnerable one's real routines — must catch.
 *
 * Expected: REJECTED everywhere. It demonstrates that the other two attacks succeed
 * NOT because tampering is undetectable, but because of the specific structural bugs.
 */

import { base64urlEncodeString } from '../jwt/base64url.ts';
import { decodeUnsafe } from './types.ts';
import type { AttackResult } from './types.ts';

export function attackSilentTamper(baseToken: string): AttackResult {
  const [, , originalSig] = baseToken.split('.');
  const { header, claims } = decodeUnsafe(baseToken);

  const forgedClaims = { ...claims, admin: true, role: 'admin' };
  const headerB64 = base64urlEncodeString(JSON.stringify(header));
  const payloadB64 = base64urlEncodeString(JSON.stringify(forgedClaims));

  // Keep the ORIGINAL signature — it was computed over the old payload, so it no
  // longer matches.
  const forgedToken = `${headerB64}.${payloadB64}.${originalSig}`;

  return {
    forgedToken,
    explanation: {
      title: 'silent tamper (control)',
      claimedAlg: header.alg,
      verifierMistake:
        'None — this attack relies on no verifier bug. It just edits the payload and reuses the old signature.',
      whyItPassed:
        'It does NOT pass. The signature was computed over the original payload; changing admin to true breaks the signature-over-content binding.',
      correctDefense:
        'Both verifiers recompute the signature over header.payload and find it no longer matches. This is the baseline: tampering without a structural flaw fails.',
      detail: [
        'Payload changed to admin:true but the signature was left untouched.',
        'Expect REJECTED by both the Correct and the Vulnerable verifier.',
      ],
    },
  };
}
