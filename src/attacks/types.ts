import type { AlgName, JwtHeader, JwtClaims } from '../jwt/types.ts';
import { base64urlDecodeToString } from '../jwt/base64url.ts';

export interface AttackExplanation {
  /** Short attack name. */
  title: string;
  /** What the forged token claims its alg is. */
  claimedAlg: AlgName;
  /** The verifier mistake the attack relies on (plain language). */
  verifierMistake: string;
  /** The causal chain: why a broken verifier passes it. */
  whyItPassed: string;
  /** What the Correct verifier does instead, and which invariant catches it. */
  correctDefense: string;
  /** Optional byte-level / extra evidence rows. */
  detail?: string[];
}

export interface AttackResult {
  forgedToken: string;
  explanation: AttackExplanation;
}

/** Decode the header+claims of a (well-formed) token without verifying it. */
export function decodeUnsafe(token: string): { header: JwtHeader; claims: JwtClaims } {
  const [h, p] = token.split('.');
  return {
    header: JSON.parse(base64urlDecodeToString(h)) as JwtHeader,
    claims: JSON.parse(base64urlDecodeToString(p)) as JwtClaims,
  };
}
