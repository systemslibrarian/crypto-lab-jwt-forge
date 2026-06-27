/**
 * Claim (exp / nbf) validation, kept strictly separate from signature validation
 * (invariant #5). A valid signature on an expired token is reported as
 * signature='valid', claims='invalid' — the two are never collapsed.
 */

import type { JwtClaims, ClaimStatus } from './types.ts';

export interface ClaimCheck {
  status: ClaimStatus;
  detail: string;
}

const LEEWAY_SECONDS = 0;

export function validateClaims(claims: JwtClaims, nowSeconds: number): ClaimCheck {
  if (typeof claims.exp === 'number' && nowSeconds > claims.exp + LEEWAY_SECONDS) {
    return {
      status: 'invalid',
      detail: `token expired: exp=${claims.exp} < now=${nowSeconds}`,
    };
  }
  if (typeof claims.nbf === 'number' && nowSeconds < claims.nbf - LEEWAY_SECONDS) {
    return {
      status: 'invalid',
      detail: `token not yet valid: nbf=${claims.nbf} > now=${nowSeconds}`,
    };
  }
  return { status: 'valid', detail: 'exp/nbf within range (or absent)' };
}
