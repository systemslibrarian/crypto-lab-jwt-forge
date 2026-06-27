/**
 * Structural parsing of a compact JWS, shared by both verifiers.
 *
 * Parsing is fail-closed: any structural or encoding problem is reported as a typed
 * error and NO verification is attempted on a malformed token.
 */

import { base64urlDecodeToString, Base64UrlError } from './base64url.ts';
import { isAlgName } from './types.ts';
import type { RawToken, JwtHeader, JwtClaims } from './types.ts';

export interface ParseError {
  ok: false;
  reason: string;
  invariantTriggered: string;
}

export interface ParseSuccess {
  ok: true;
  raw: RawToken;
  header: JwtHeader;
  claims: JwtClaims;
  /** ASCII signing input: `headerB64.payloadB64`. */
  signingInput: string;
}

export type ParseOutcome = ParseError | ParseSuccess;

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function parseToken(token: string): ParseOutcome {
  const segments = token.split('.');

  // Exactly three segments. Two dots. A `none` token has an empty third segment but
  // still has both dots.
  if (segments.length !== 3) {
    return {
      ok: false,
      reason: `expected 3 segments separated by '.', found ${segments.length}`,
      invariantTriggered: 'structure: a compact JWS is header.payload.signature',
    };
  }

  const [headerB64, payloadB64, signatureB64] = segments;

  let headerJson: string;
  let payloadJson: string;
  try {
    headerJson = base64urlDecodeToString(headerB64);
  } catch (e) {
    return {
      ok: false,
      reason: `header is not strict base64url: ${(e as Base64UrlError).message}`,
      invariantTriggered: 'strict base64url decode (invariant #4)',
    };
  }
  try {
    payloadJson = base64urlDecodeToString(payloadB64);
  } catch (e) {
    return {
      ok: false,
      reason: `payload is not strict base64url: ${(e as Base64UrlError).message}`,
      invariantTriggered: 'strict base64url decode (invariant #4)',
    };
  }

  let header: JwtHeader;
  let claims: JwtClaims;
  try {
    header = JSON.parse(headerJson) as JwtHeader;
  } catch {
    return { ok: false, reason: 'header is not valid JSON', invariantTriggered: 'structure' };
  }
  try {
    claims = JSON.parse(payloadJson) as JwtClaims;
  } catch {
    return { ok: false, reason: 'payload is not valid JSON', invariantTriggered: 'structure' };
  }

  if (!isJsonObject(header)) {
    return { ok: false, reason: 'header is not a JSON object', invariantTriggered: 'structure' };
  }
  // The JWT Claims Set MUST be a JSON object (RFC 7519 §7.2). A payload of `null`, a
  // number, or an array is rejected here so claim validation never dereferences it.
  if (!isJsonObject(claims)) {
    return { ok: false, reason: 'payload is not a JSON object', invariantTriggered: 'structure' };
  }

  // `alg` MUST be present — there is no implicit default (invariant: missing alg → reject).
  if (!('alg' in header)) {
    return {
      ok: false,
      reason: "header has no 'alg' — no implicit default is permitted",
      invariantTriggered: 'no implicit default alg',
    };
  }
  if (!isAlgName(header.alg)) {
    return {
      ok: false,
      reason: `unrecognised alg ${JSON.stringify(header.alg)} — never treated as 'none'`,
      invariantTriggered: 'unknown alg → reject',
    };
  }

  // crit (RFC 7515 §4.1.11): every listed parameter MUST be understood by the verifier.
  // This implementation supports NO critical extensions, so any crit entry is by
  // definition unrecognised → reject. A malformed/empty crit is also a reject.
  if ('crit' in header) {
    const crit = header.crit;
    if (!Array.isArray(crit) || crit.length === 0) {
      return {
        ok: false,
        reason: "'crit' header is present but not a non-empty array",
        invariantTriggered: 'crit must be understood (RFC 7515 §4.1.11)',
      };
    }
    return {
      ok: false,
      reason: `unrecognised 'crit' header parameter(s): ${crit.join(', ')} — this verifier implements no critical extensions`,
      invariantTriggered: 'crit must be understood (RFC 7515 §4.1.11)',
    };
  }

  return {
    ok: true,
    raw: { headerB64, payloadB64, signatureB64 },
    header,
    claims,
    signingInput: `${headerB64}.${payloadB64}`,
  };
}
