import { describe, expect, it } from 'vitest';
import { validateClaims } from './claims.ts';
import type { JwtClaims } from './types.ts';

describe('RFC 7519 NumericDate types and boundaries', () => {
  it.each([
    [{ exp: 1000 }, 999.999, 'valid'],
    [{ exp: 1000 }, 1000, 'invalid'],
    [{ exp: 1000 }, 1000.001, 'invalid'],
    [{ exp: 0 }, 0, 'invalid'],
    [{ exp: -0.5 }, -1, 'valid'],
    [{ exp: 1000.5 }, 1000.25, 'valid'],
    [{ nbf: 1000 }, 999.999, 'invalid'],
    [{ nbf: 1000 }, 1000, 'valid'],
    [{ nbf: 1000 }, 1000.001, 'valid'],
    [{ nbf: -0.5 }, -0.5, 'valid'],
    [{ nbf: 1000, exp: 1000 }, 1000, 'invalid'],
    [{ iat: 2000.5 }, 1000, 'valid'], // type only; no extra token-age policy
    [{}, 1000, 'valid'],
  ])('evaluates %j at %s as %s', (claims, now, status) => {
    expect(validateClaims(claims as JwtClaims, now as number).status).toBe(status);
  });

  for (const name of ['exp', 'nbf', 'iat']) {
    it.each([null, '1000', undefined, true, {}, [], NaN, Infinity, -Infinity])(
      `rejects present malformed ${name}=%j rather than treating it as absent`, value => {
        const result = validateClaims({ [name]: value } as JwtClaims, 1000);
        expect(result.status).toBe('invalid');
        expect(result.detail).toContain(name);
      },
    );
  }

  it.each([NaN, Infinity, -Infinity])('rejects an unreadable clock %s', now => {
    expect(validateClaims({}, now).status).toBe('invalid');
  });

  it('rejects a syntactically valid JSON number that overflows to Infinity', () => {
    expect(validateClaims(JSON.parse('{"exp":1e309}'), 1000).status).toBe('invalid');
  });
});
