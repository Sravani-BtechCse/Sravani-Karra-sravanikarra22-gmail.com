// JWT and password hashing, hand-rolled on node:crypto.
//
// Verification enforces all AUTH-DATA-MODEL.md §10 safety guards:
// 3-part format, strict header algorithm pinning, constant-time HMAC check,
// half-open expiration interval (exp <= now), issuer/audience verification, and jti.

import { createHmac, timingSafeEqual, randomBytes, scryptSync, randomUUID } from 'node:crypto';
import { unauthenticated, tokenStale } from './http.js';

const ALG = 'HS256';
const ISS = 'remoteops';
const AUD = 'remoteops-api';

export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

const base64UrlEncode = (data) => Buffer.from(data).toString('base64url');
const base64UrlDecode = (str) => Buffer.from(str, 'base64url');

export function signToken(claims, secret) {
  const headerSegment = base64UrlEncode(JSON.stringify({ alg: ALG, typ: 'JWT' }));
  const payloadSegment = base64UrlEncode(JSON.stringify(claims));
  const signatureBytes = createHmac('sha256', secret)
    .update(`${headerSegment}.${payloadSegment}`)
    .digest();
  return `${headerSegment}.${payloadSegment}.${base64UrlEncode(signatureBytes)}`;
}

export function issueAccessToken({ userId, orgId, role, permVersion }, secret) {
  const currentTime = Math.floor(Date.now() / 1000);
  return signToken(
    {
      iss: ISS,
      aud: AUD,
      sub: userId,
      org: orgId,
      role,
      pv: permVersion,
      jti: randomUUID(),
      iat: currentTime,
      exp: currentTime + ACCESS_TTL_SECONDS,
    },
    secret
  );
}

export function verifyAccessToken(tokenString, secretKey) {
  const rawToken = String(tokenString ?? '').trim();
  const segments = rawToken.split('.');
  if (segments.length !== 3) {
    throw unauthenticated('malformed access token structure');
  }

  const [headerB64, payloadB64, signatureB64] = segments;

  let parsedHeader;
  try {
    const headerJson = base64UrlDecode(headerB64).toString('utf8');
    parsedHeader = JSON.parse(headerJson);
  } catch {
    throw unauthenticated('invalid token header encoding');
  }

  if (!parsedHeader || typeof parsedHeader !== 'object' || Array.isArray(parsedHeader)) {
    throw unauthenticated('token header must be an object');
  }

  if (parsedHeader.alg !== ALG || parsedHeader.typ !== 'JWT') {
    throw unauthenticated('algorithm or token type not supported');
  }

  const computedSig = createHmac('sha256', secretKey)
    .update(`${headerB64}.${payloadB64}`)
    .digest();
  const providedSig = base64UrlDecode(signatureB64);

  if (
    providedSig.length !== computedSig.length ||
    !timingSafeEqual(providedSig, computedSig)
  ) {
    throw unauthenticated('token signature mismatch');
  }

  let tokenClaims;
  try {
    const payloadJson = base64UrlDecode(payloadB64).toString('utf8');
    tokenClaims = JSON.parse(payloadJson);
  } catch {
    throw unauthenticated('invalid token payload encoding');
  }

  if (!tokenClaims || typeof tokenClaims !== 'object' || Array.isArray(tokenClaims)) {
    throw unauthenticated('token payload must be an object');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (typeof tokenClaims.exp !== 'number' || tokenClaims.exp <= nowSeconds) {
    throw unauthenticated('token has expired');
  }

  if (tokenClaims.iss !== ISS || tokenClaims.aud !== AUD) {
    throw unauthenticated('invalid token issuer or audience');
  }

  if (!tokenClaims.jti || typeof tokenClaims.jti !== 'string') {
    throw unauthenticated('token missing unique jti identifier');
  }

  return tokenClaims;
}

export function assertFresh(claims, membershipRow) {
  if (!membershipRow) throw unauthenticated('not a member of this org');
  if (membershipRow.perm_version !== claims.pv) throw tokenStale();
}

export const newRefreshToken = () => randomBytes(32).toString('base64url');
export const newInviteToken  = () => randomBytes(32).toString('base64url');

const APP_HASH_KEY = process.env.APP_HASH_KEY ?? 'dev-only-app-hash-key-change-me';

export const hashRefreshToken = (rawToken) =>
  createHmac('sha256', `${APP_HASH_KEY}:refresh`).update(rawToken).digest('hex');

export const hashInviteToken = (rawToken) =>
  createHmac('sha256', `${APP_HASH_KEY}:invite`).update(rawToken).digest('hex');

export function hashPassword(password) {
  const saltHex = randomBytes(16).toString('hex');
  const keyDerived = scryptSync(password, saltHex, 64).toString('hex');
  return `scrypt$${saltHex}$${keyDerived}`;
}

export function verifyPassword(plainPassword, storedHash) {
  const parts = String(storedHash ?? '').split('$');
  if (parts.length !== 3) return false;
  const [scheme, saltHex, expectedHex] = parts;
  if (scheme !== 'scrypt' || !saltHex || !expectedHex) return false;

  const actualHex = scryptSync(plainPassword, saltHex, 64).toString('hex');
  const bufActual = Buffer.from(actualHex, 'hex');
  const bufExpected = Buffer.from(expectedHex, 'hex');
  return bufActual.length === bufExpected.length && timingSafeEqual(bufActual, bufExpected);
}
