/**
 * NumericDate type and exp / nbf range validation, separate from signatures
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
  if (!Number.isFinite(nowSeconds)) {
    return { status: 'invalid', detail: 'validation clock must be finite' };
  }
  // Presence is distinct from absence: null, strings, undefined and numeric
  // overflow must not silently remove a registered NumericDate constraint.
  // RFC 7519 permits fractional seconds; iat has no age policy in this demo.
  for (const name of ['exp', 'nbf', 'iat'] as const) {
    if (Object.prototype.hasOwnProperty.call(claims, name) &&
      (typeof claims[name] !== 'number' || !Number.isFinite(claims[name]))) {
      return { status: 'invalid', detail: `${name} must be a finite NumericDate number when present` };
    }
  }
  if (typeof claims.exp === 'number' && nowSeconds >= claims.exp + LEEWAY_SECONDS) {
    return {
      status: 'invalid',
      detail: `token expired: exp=${claims.exp} <= now=${nowSeconds}`,
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
