// Per-request context builder: converts bearer tokens into authenticated caller contexts.
// Enforces structural organization isolation (cross-org parameter mismatches return 404),
// membership state verification (removed -> 401, org_deleted -> 404), and token freshness checks.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

export function authenticate(database, tokenSecret) {
  return function processContext(req, routeParams) {
    const authHeader = req.headers.authorization ?? '';
    if (!authHeader.startsWith('Bearer ')) {
      throw unauthenticated('missing bearer token');
    }

    const bearerToken = authHeader.slice(7).trim();
    if (!bearerToken) {
      throw unauthenticated('empty bearer token');
    }

    const tokenClaims = verifyAccessToken(bearerToken, tokenSecret);

    const callerMembership = database
      .prepare(
        `SELECT m.*, o.deleted_at AS org_deleted_at
           FROM memberships m
           JOIN organizations o ON o.id = m.org_id
          WHERE m.org_id = ? AND m.user_id = ?`
      )
      .get(tokenClaims.org, tokenClaims.sub);

    if (!callerMembership) {
      throw unauthenticated('not a member of this org');
    }

    if (callerMembership.org_deleted_at) {
      throw notFound();
    }

    if (callerMembership.status === 'removed') {
      throw unauthenticated('membership removed');
    }

    if (callerMembership.status !== 'suspended') {
      assertFresh(tokenClaims, callerMembership);
    }

    if (routeParams.org && routeParams.org !== tokenClaims.org) {
      throw notFound();
    }

    return {
      userId: tokenClaims.sub,
      orgId: tokenClaims.org,
      role: callerMembership.role,
      membership: callerMembership,
      claims: tokenClaims,
    };
  };
}
