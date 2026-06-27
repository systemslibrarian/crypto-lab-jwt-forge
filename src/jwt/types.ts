/**
 * JWT / JWS type definitions.
 *
 * Security invariant #3: key types are non-interchangeable at the TypeScript type
 * level. Each key wrapper carries a distinct `kind` discriminant, so an RSA public
 * key can never be passed where an HMAC key is expected. Key confusion is therefore
 * only reachable inside the explicitly-labelled Vulnerable verifier, which must
 * deliberately throw the type away (via `unknown`/`any`) to do its damage.
 */

export type AlgName = 'HS256' | 'RS256' | 'ES256' | 'none';

/** Algorithms that involve a real signature (everything except `none`). */
export const SIGNING_ALGS: readonly AlgName[] = ['HS256', 'RS256', 'ES256'];

// PQ extension point (1 of 3): adding ML-DSA-65 or an Ed25519+ML-DSA-65 composite
// means extending this union with one new alg name — no other type change.
export const ALL_ALGS: readonly AlgName[] = ['HS256', 'RS256', 'ES256', 'none'];

export function isAlgName(value: unknown): value is AlgName {
  return typeof value === 'string' && (ALL_ALGS as readonly string[]).includes(value);
}

// --- Branded, non-interchangeable key wrappers -----------------------------------

export interface HmacKey {
  readonly kind: 'HmacKey';
  readonly alg: 'HS256';
  readonly key: CryptoKey;
  readonly kid?: string;
}

export interface RsaPublicKey {
  readonly kind: 'RsaPublicKey';
  readonly alg: 'RS256';
  readonly key: CryptoKey;
  readonly kid?: string;
}

export interface RsaPrivateKey {
  readonly kind: 'RsaPrivateKey';
  readonly alg: 'RS256';
  readonly key: CryptoKey;
  readonly kid?: string;
}

export interface EcPublicKey {
  readonly kind: 'EcPublicKey';
  readonly alg: 'ES256';
  readonly key: CryptoKey;
  readonly kid?: string;
}

export interface EcPrivateKey {
  readonly kind: 'EcPrivateKey';
  readonly alg: 'ES256';
  readonly key: CryptoKey;
  readonly kid?: string;
}

// PQ extension point (2 of 3): a new algorithm adds exactly one new public-key
// wrapper type here (e.g. `MlDsaPublicKey`) and its private counterpart. The
// verifier dispatches on `kind`, so no existing key path changes.

/** Public verification keys the Correct verifier is allowed to hold. */
export type VerifierKey = HmacKey | RsaPublicKey | EcPublicKey;

/** Signing keys. */
export type SigningKey = HmacKey | RsaPrivateKey | EcPrivateKey;

// --- Token structure --------------------------------------------------------------

export interface JwtHeader {
  alg: AlgName;
  typ?: string;
  kid?: string;
  crit?: string[];
  [key: string]: unknown;
}

export interface JwtClaims {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number; // seconds since epoch
  nbf?: number; // seconds since epoch
  iat?: number; // seconds since epoch
  [key: string]: unknown;
}

/** The three structural pieces of a compact JWS, pre-decode. */
export interface RawToken {
  headerB64: string;
  payloadB64: string;
  signatureB64: string;
}

// --- Verification result ----------------------------------------------------------

export type SignatureStatus = 'valid' | 'invalid' | 'not-checked';
export type ClaimStatus = 'valid' | 'invalid' | 'not-checked';

/**
 * `systemIntegrity` tracks whether the verifier was FOOLED, not whether it returned
 * accept/reject. The Correct verifier can never be fooled, so it always reports `ok`.
 * The Vulnerable verifier reports `fooled` whenever it accepts a token through one of
 * its broken paths (honouring `alg:none`, or treating a public key as an HMAC secret).
 *
 * Invariant #5: signature validity and claim validity are reported separately and
 * never collapsed. A valid signature on an expired token is signature='valid',
 * claims='invalid'.
 */
export interface VerifyResult {
  systemIntegrity: 'ok' | 'fooled';
  decision: 'accept' | 'reject';
  reason: string;
  invariantTriggered?: string;
  signature: SignatureStatus;
  claims: ClaimStatus;
  claimDetail?: string;
  /** The `alg` the token claimed (for the UI's causal chain), if it parsed. */
  claimedAlg?: AlgName;
}

export interface VerifierPolicy {
  /** REQUIRED allowlist. An empty set accepts nothing (invariant #1). */
  acceptedAlgs: ReadonlySet<AlgName>;
  /** The verification keys this verifier holds. */
  keys: readonly VerifierKey[];
  /** Clock for exp/nbf evaluation, in seconds since epoch. Injected for testing. */
  nowSeconds: number;
}
