// Custom auth routes implementation: login, org token switching, refresh token rotation, and caller identity endpoints.
import { newId, nowIso } from '../db.js';
import { send, badRequest, unauthenticated, forbidden, notFound } from '../http.js';
import {
  issueAccessToken, verifyPassword, newRefreshToken, hashRefreshToken,
  REFRESH_TTL_SECONDS, ACCESS_TTL_SECONDS,
} from '../auth.js';
import { resolve } from '../permissions.js';
import { audit } from '../audit.js';

const COOKIE_NAME = 'rt';

function attachRefreshCookie(res, tokenValue) {
  const cookieString = `${COOKIE_NAME}=${tokenValue}; HttpOnly; SameSite=Strict; Path=/v1/auth; Max-Age=${REFRESH_TTL_SECONDS}`;
  res.setHeader('set-cookie', cookieString);
}

function extractRefreshCookieFromHeader(req) {
  const cookieHeader = req.headers.cookie ?? '';
  const cookiePairs = cookieHeader.split(';');
  for (const pair of cookiePairs) {
    const [key, ...valParts] = pair.trim().split('=');
    if (key === COOKIE_NAME) return valParts.join('=');
  }
  return null;
}

function fetchActiveUserMemberships(db, userId) {
  return db
    .prepare(
      `SELECT m.org_id AS orgId, o.name AS orgName, o.theme, m.role, m.status, m.perm_version
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
        ORDER BY o.name`
    )
    .all(userId);
}

export function register(router, { db, secret }) {
  // POST /v1/auth/login
  router.post('/v1/auth/login', (ctx, _params, res) => {
    const { email, password, orgId } = ctx.body;
    if (typeof email !== 'string' || typeof password !== 'string') {
      throw badRequest('email and password are required');
    }

    const normalizedEmail = email.trim().toLowerCase();
    const userRecord = db
      .prepare('SELECT * FROM users WHERE email = ?')
      .get(normalizedEmail);

    if (!userRecord || !verifyPassword(password, userRecord.password_hash)) {
      if (userRecord) {
        const primaryMembership = db
          .prepare("SELECT org_id FROM memberships WHERE user_id = ? AND status = 'active' LIMIT 1")
          .get(userRecord.id);

        if (primaryMembership) {
          audit(db, {
            orgId: primaryMembership.org_id,
            actorId: userRecord.id,
            action: 'auth.login',
            result: 'deny',
            reasonCode: 'bad_credentials',
            requestId: ctx.requestId,
          });
        }
      }
      throw unauthenticated('invalid email or password');
    }

    const availableOrgList = fetchActiveUserMemberships(db, userRecord.id);
    if (availableOrgList.length === 0) {
      throw forbidden('you are not an active member of any organization');
    }

    const targetOrg = orgId
      ? availableOrgList.find((org) => org.orgId === orgId)
      : availableOrgList[0];

    if (!targetOrg) throw notFound();

    const accessToken = issueAccessToken(
      {
        userId: userRecord.id,
        orgId: targetOrg.orgId,
        role: targetOrg.role,
        permVersion: targetOrg.perm_version,
      },
      secret
    );

    const rawRefresh = newRefreshToken();
    db.prepare(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
       VALUES (?, ?, ?, ?, ?)`
    ).run(
      newId('rft'),
      userRecord.id,
      hashRefreshToken(rawRefresh),
      newId('fam'),
      new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString()
    );

    attachRefreshCookie(res, rawRefresh);

    audit(db, {
      orgId: targetOrg.orgId,
      actorId: userRecord.id,
      action: 'auth.login',
      result: 'allow',
      requestId: ctx.requestId,
    });

    send(res, 200, {
      token: accessToken,
      expiresIn: ACCESS_TTL_SECONDS,
      user: { id: userRecord.id, email: userRecord.email, name: userRecord.name },
      orgId: targetOrg.orgId,
      role: targetOrg.role,
      orgs: availableOrgList.map(({ orgId: id, orgName: name, theme, role }) => ({
        id,
        name,
        theme,
        role,
      })),
    });
  });

  // POST /v1/auth/token
  router.post('/v1/auth/token', (ctx, _params, res) => {
    const { orgId } = ctx.body;
    if (typeof orgId !== 'string') throw badRequest('orgId is required');

    const availableOrgList = fetchActiveUserMemberships(db, ctx.userId);
    const targetOrg = availableOrgList.find((org) => org.orgId === orgId);
    if (!targetOrg) throw notFound();

    const accessToken = issueAccessToken(
      {
        userId: ctx.userId,
        orgId: targetOrg.orgId,
        role: targetOrg.role,
        permVersion: targetOrg.perm_version,
      },
      secret
    );

    send(res, 200, {
      token: accessToken,
      expiresIn: ACCESS_TTL_SECONDS,
      orgId: targetOrg.orgId,
      role: targetOrg.role,
      orgs: availableOrgList.map(({ orgId: id, orgName: name, theme, role }) => ({
        id,
        name,
        theme,
        role,
      })),
    });
  });

  // POST /v1/auth/refresh
  router.post('/v1/auth/refresh', (ctx, _params, res) => {
    const rawRefresh = extractRefreshCookieFromHeader(ctx.req);
    if (!rawRefresh) throw unauthenticated('no refresh token');

    const refreshRecord = db
      .prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?')
      .get(hashRefreshToken(rawRefresh));

    if (!refreshRecord) throw unauthenticated('unknown refresh token');

    if (refreshRecord.revoked_at) {
      db.prepare(
        'UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL'
      ).run(nowIso(), refreshRecord.family_id);
      throw unauthenticated('refresh token reuse detected; session family revoked');
    }

    if (refreshRecord.expires_at <= nowIso()) {
      throw unauthenticated('refresh token expired');
    }

    const availableOrgList = fetchActiveUserMemberships(db, refreshRecord.user_id);
    if (availableOrgList.length === 0) {
      throw forbidden('you are not an active member of any organization');
    }

    db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?').run(
      nowIso(),
      refreshRecord.id
    );

    const nextRawRefresh = newRefreshToken();
    db.prepare(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
       VALUES (?, ?, ?, ?, ?)`
    ).run(
      newId('rft'),
      refreshRecord.user_id,
      hashRefreshToken(nextRawRefresh),
      refreshRecord.family_id,
      new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString()
    );

    attachRefreshCookie(res, nextRawRefresh);
    const activeOrg = availableOrgList[0];

    send(res, 200, {
      token: issueAccessToken(
        {
          userId: refreshRecord.user_id,
          orgId: activeOrg.orgId,
          role: activeOrg.role,
          permVersion: activeOrg.perm_version,
        },
        secret
      ),
      expiresIn: ACCESS_TTL_SECONDS,
      orgId: activeOrg.orgId,
      role: activeOrg.role,
      orgs: availableOrgList.map(({ orgId: id, orgName: name, theme, role }) => ({
        id,
        name,
        theme,
        role,
      })),
    });
  });

  // GET /v1/auth/me
  router.get('/v1/auth/me', (ctx, _params, res) => {
    const userProfile = db
      .prepare('SELECT id, email, name FROM users WHERE id = ?')
      .get(ctx.userId);

    const orgDetails = db
      .prepare('SELECT id, name, theme, max_session_minutes FROM organizations WHERE id = ?')
      .get(ctx.orgId);

    send(res, 200, {
      user: userProfile,
      org: orgDetails,
      role: ctx.role,
      orgs: fetchActiveUserMemberships(db, ctx.userId).map(
        ({ orgId: id, orgName: name, theme, role }) => ({ id, name, theme, role })
      ),
      permissions: resolve(db, { userId: ctx.userId, orgId: ctx.orgId }).permissions,
    });
  });
}
