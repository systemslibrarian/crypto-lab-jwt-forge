import { describe, it, expect, beforeAll } from 'vitest';
import { generateSessionKeys, type SessionKeys } from './keys.ts';
import { sign } from './sign.ts';
import { verifyCorrect } from './verifyCorrect.ts';
import { verifyVulnerable } from './verifyVulnerable.ts';
import type { VerifierPolicy, JwtClaims } from './types.ts';
import { attackAlgNone } from '../attacks/algNone.ts';
import { attackKeyConfusion } from '../attacks/keyConfusion.ts';
import { attackSilentTamper } from '../attacks/silentTamper.ts';

let keys: SessionKeys;
const NOW = 1_750_000_000; // fixed clock (seconds)

const baseClaims = (): JwtClaims => ({
  sub: 'user-123',
  name: 'Ada',
  admin: false,
  iat: NOW - 60,
  exp: NOW + 3600,
});

beforeAll(async () => {
  keys = await generateSessionKeys();
});

function policy(partial: Partial<VerifierPolicy>): VerifierPolicy {
  return {
    acceptedAlgs: new Set(['RS256']),
    keys: [keys.rsaPublic],
    nowSeconds: NOW,
    ...partial,
  };
}

describe('Correct verifier accepts genuine tokens', () => {
  it('accepts a genuine HS256 token', async () => {
    const t = await sign({}, baseClaims(), keys.hmac);
    const r = await verifyCorrect(t, policy({ acceptedAlgs: new Set(['HS256']), keys: [keys.hmac] }));
    expect(r).toMatchObject({ decision: 'accept', signature: 'valid', claims: 'valid', systemIntegrity: 'ok' });
  });

  it('accepts a genuine RS256 token', async () => {
    const t = await sign({}, baseClaims(), keys.rsaPrivate);
    const r = await verifyCorrect(t, policy({}));
    expect(r).toMatchObject({ decision: 'accept', signature: 'valid', claims: 'valid' });
  });

  it('accepts a genuine ES256 token', async () => {
    const t = await sign({}, baseClaims(), keys.ecPrivate);
    const r = await verifyCorrect(t, policy({ acceptedAlgs: new Set(['ES256']), keys: [keys.ecPublic] }));
    expect(r).toMatchObject({ decision: 'accept', signature: 'valid', claims: 'valid' });
  });
});

describe('Correct verifier rejects the three forgeries', () => {
  it('rejects alg:none (not in allowlist)', async () => {
    const base = await sign({}, baseClaims(), keys.rsaPrivate);
    const { forgedToken } = attackAlgNone(base);
    const r = await verifyCorrect(forgedToken, policy({})); // RS256 only
    expect(r.decision).toBe('reject');
    expect(r.systemIntegrity).toBe('ok');
    expect(r.invariantTriggered).toMatch(/allowlist/i);
  });

  it('rejects key confusion (RsaPublicKey cannot enter the HMAC path)', async () => {
    const base = await sign({}, baseClaims(), keys.rsaPrivate);
    const { forgedToken } = await attackKeyConfusion(base, keys.rsaPublicKeyPem);
    const r = await verifyCorrect(forgedToken, policy({})); // expects RS256, holds RSA public
    expect(r.decision).toBe('reject');
    expect(r.systemIntegrity).toBe('ok');
  });

  it('rejects silent tamper (broken signature binding)', async () => {
    const base = await sign({}, baseClaims(), keys.rsaPrivate);
    const { forgedToken } = attackSilentTamper(base);
    const r = await verifyCorrect(forgedToken, policy({}));
    expect(r.decision).toBe('reject');
    expect(r.signature).toBe('invalid');
  });
});

// These pin the DELIBERATE vulnerabilities. If a future change "fixes" the Vulnerable
// verifier, these tests fail on purpose — the teaching contrast must be preserved.
describe('Vulnerable verifier is demonstrably fooled (DELIBERATE — do not "fix")', () => {
  it('accepts alg:none', async () => {
    const base = await sign({}, baseClaims(), keys.rsaPrivate);
    const { forgedToken } = attackAlgNone(base);
    const r = await verifyVulnerable(forgedToken, policy({})); // allowlist ignored anyway
    expect(r.decision).toBe('accept');
    expect(r.systemIntegrity).toBe('fooled');
  });

  it('accepts key confusion (public key used as HMAC secret)', async () => {
    const base = await sign({}, baseClaims(), keys.rsaPrivate);
    const { forgedToken } = await attackKeyConfusion(base, keys.rsaPublicKeyPem);
    const r = await verifyVulnerable(forgedToken, policy({})); // holds RSA public key only
    expect(r.decision).toBe('accept');
    expect(r.systemIntegrity).toBe('fooled');
  });

  it('still rejects silent tamper (no structural bug to exploit)', async () => {
    const base = await sign({}, baseClaims(), keys.rsaPrivate);
    const { forgedToken } = attackSilentTamper(base);
    const r = await verifyVulnerable(forgedToken, policy({}));
    expect(r.decision).toBe('reject');
  });
});

describe('signature and claim validity are reported independently (invariant #5)', () => {
  it('valid signature on an expired token => signature valid, claims invalid', async () => {
    const t = await sign({}, { ...baseClaims(), exp: NOW - 10 }, keys.rsaPrivate);
    const r = await verifyCorrect(t, policy({}));
    expect(r.signature).toBe('valid');
    expect(r.claims).toBe('invalid');
    expect(r.decision).toBe('reject');
    expect(r.claimDetail).toMatch(/expired/);
  });

  it('valid signature on a not-yet-valid (nbf) token => signature valid, claims invalid', async () => {
    const t = await sign({}, { ...baseClaims(), nbf: NOW + 1000 }, keys.rsaPrivate);
    const r = await verifyCorrect(t, policy({}));
    expect(r.signature).toBe('valid');
    expect(r.claims).toBe('invalid');
    expect(r.claimDetail).toMatch(/not yet valid/);
  });
});

describe('edge cases fail closed', () => {
  it('missing alg => reject', async () => {
    // header {"typ":"JWT"} with no alg
    const r = await verifyCorrect('eyJ0eXAiOiJKV1QifQ.eyJhIjoxfQ.x', policy({}));
    expect(r.decision).toBe('reject');
    expect(r.invariantTriggered).toMatch(/default alg/);
  });

  it('wrong segment count => structural reject', async () => {
    const r = await verifyCorrect('a.b', policy({}));
    expect(r.decision).toBe('reject');
    expect(r.invariantTriggered).toMatch(/structure/);
  });

  it('empty allowlist accepts nothing', async () => {
    const t = await sign({}, baseClaims(), keys.rsaPrivate);
    const r = await verifyCorrect(t, policy({ acceptedAlgs: new Set() }));
    expect(r.decision).toBe('reject');
  });

  // header/payload that decode to non-objects (array, number, string) must all reject.
  it.each([
    ['array payload', 'eyJhbGciOiJSUzI1NiJ9', 'WzEsMiwzXQ'], // [1,2,3]
    ['number payload', 'eyJhbGciOiJSUzI1NiJ9', 'NDI'], // 42
    ['string payload', 'eyJhbGciOiJSUzI1NiJ9', 'ImhpIg'], // "hi"
  ])('non-object %s => structural reject, no crash', async (_name, h, p) => {
    const r = await verifyCorrect(`${h}.${p}.x`, policy({}));
    expect(r.decision).toBe('reject');
    expect(r.invariantTriggered).toMatch(/structure/);
  });

  it('array header => structural reject', async () => {
    // header [1] base64url = "WzFd"
    const r = await verifyCorrect('WzFd.eyJhIjoxfQ.x', policy({}));
    expect(r.decision).toBe('reject');
  });

  it('invalid base64url in header => reject at parse, never verified', async () => {
    const r = await verifyCorrect('not+valid.eyJhIjoxfQ.x', policy({}));
    expect(r.decision).toBe('reject');
    expect(r.signature).toBe('not-checked');
    expect(r.invariantTriggered).toMatch(/base64url/);
  });

  it('emits a decision trace with a single decisive step', async () => {
    const base = await sign({}, baseClaims(), keys.rsaPrivate);
    const { forgedToken } = attackAlgNone(base);
    const r = await verifyCorrect(forgedToken, policy({})); // RS256 only → allowlist rejects
    expect(r.trace.length).toBeGreaterThan(0);
    expect(r.trace.filter((s) => s.decisive)).toHaveLength(1);
    expect(r.trace.find((s) => s.decisive)?.status).toBe('fail');
  });

  it('unrecognised crit => reject', async () => {
    const t = await sign({ crit: ['exp'] } as never, baseClaims(), keys.rsaPrivate);
    const r = await verifyCorrect(t, policy({}));
    expect(r.decision).toBe('reject');
    expect(r.invariantTriggered).toMatch(/crit/);
  });

  it('non-object payload (JSON null) => reject, no crash', async () => {
    // header {"alg":"none"} . payload null . empty sig — a crafted fail-closed probe.
    const t = 'eyJhbGciOiJub25lIn0.bnVsbA.';
    const correct = await verifyCorrect(t, policy({ acceptedAlgs: new Set(['none']) }));
    expect(correct.decision).toBe('reject');
    expect(correct.invariantTriggered).toMatch(/structure/);
    const vuln = await verifyVulnerable(t, policy({}));
    expect(vuln.decision).toBe('reject');
  });

  it('empty signature on a non-none alg => reject', async () => {
    const t = await sign({}, baseClaims(), keys.rsaPrivate);
    const [h, p] = t.split('.');
    const r = await verifyCorrect(`${h}.${p}.`, policy({}));
    expect(r.decision).toBe('reject');
    expect(r.invariantTriggered).toMatch(/empty signature/);
  });

  it('multiple keys without kid => reject (no guessing)', async () => {
    const t = await sign({}, baseClaims(), keys.rsaPrivate);
    // Two RS256 keys held; strip kid from header by re-signing without kid then forcing 2 keys.
    const second = { ...keys.rsaPublic, kid: 'rsa-2' };
    const r = await verifyCorrect(t, policy({ keys: [keys.rsaPublic, second] }));
    // The genuine token has no kid header, so selection must refuse.
    expect(r.decision).toBe('reject');
    expect(r.invariantTriggered).toMatch(/kid/);
  });
});
