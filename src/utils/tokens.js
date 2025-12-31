// utils/tokens.js
const ms = require('ms');
const prisma = require('../database/prisma/client');
const config = require('../config/env');
const { generateToken, hashToken } = require('./crypto');

const refreshTtlMs = ms(config.tokens.refreshTokenTtl);
if (!refreshTtlMs) throw new Error('Invalid REFRESH_TOKEN_TTL configuration');

const now = () => new Date();

/**
 * Create a new refresh token record (used as our “session”).
 * Returns { token, session } where token is the plaintext refresh token.
 */
async function createSession(userId) {
  const token = generateToken(48); // 384-bit random
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + refreshTtlMs);

  const refresh = await prisma.refreshToken.create({
    data: {
      userId,
      tokenHash,
      expiresAt,
      revoked: false,
    },
  });

  return {
    token,
    session: { id: refresh.id, userId: refresh.userId, expiresAt: refresh.expiresAt },
  };
}

/**
 * Verify a presented refresh token and rotate it (old is revoked, new is issued).
 * Returns { token, session } for the new token.
 * Throws Error codes: 'invalid_refresh', 'expired', 'revoked'
 */
async function verifyAndRotateSession(presentedToken) {
  const presentedHash = hashToken(presentedToken);

  const tokenRecord = await prisma.refreshToken.findUnique({
    where: { tokenHash: presentedHash },
  });

  if (!tokenRecord) throw new Error('invalid_refresh');
  if (tokenRecord.revoked) throw new Error('revoked');
  if (tokenRecord.expiresAt <= now()) throw new Error('expired');

  const newToken = generateToken(48);
  const newHash = hashToken(newToken);
  const newExpiresAt = new Date(Date.now() + refreshTtlMs);

  const newRecord = await prisma.$transaction(async (tx) => {
    await tx.refreshToken.update({
      where: { id: tokenRecord.id },
      data: { revoked: true },
    });

    return tx.refreshToken.create({
      data: {
        userId: tokenRecord.userId,
        tokenHash: newHash,
        expiresAt: newExpiresAt,
        revoked: false,
      },
    });
  });

  return {
    token: newToken,
    session: { id: newRecord.id, userId: newRecord.userId, expiresAt: newRecord.expiresAt },
  };
}

/** Revoke a single refresh token by id */
function revokeSessionById(id) {
  return prisma.refreshToken.update({
    where: { id },
    data: { revoked: true },
  });
}

/** Revoke all refresh tokens for a user (global sign-out) */
function revokeAllSessionsForUser(userId) {
  return prisma.refreshToken.updateMany({
    where: { userId, revoked: false },
    data: { revoked: true },
  });
}

/** Revoke all refresh tokens for a user (compat helper) */
function revokeFamily(userId) {
  return revokeAllSessionsForUser(userId);
}

/** Cleanup expired refresh tokens */
function purgeExpiredSessions() {
  return prisma.refreshToken.deleteMany({
    where: { expiresAt: { lt: now() } },
  });
}

module.exports = {
  createSession,
  verifyAndRotateSession,
  revokeSessionById,
  revokeAllSessionsForUser,
  revokeFamily,
  purgeExpiredSessions,
};
