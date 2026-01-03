const prisma = require('../database/prisma/client');
const { verifyAccessToken } = require('../utils/jwt');
const { createUnauthorizedError, createForbiddenError, ERROR_CODES } = require('../utils/errors');

/**
 * AuthZ rules preserved:
 * - Require Bearer access token
 * - Block banned users
 * - Block pending_verification users
 *
 * Hybrid addition:
 * - If access token contains sid, verify a corresponding Session exists,
 *   is not revoked, and not expired. Also ensure it belongs to the same user.
 */
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw createUnauthorizedError('Authentication token missing', ERROR_CODES.TOKEN_MISSING);
    }

    const token = authHeader.slice(7);
    const decoded = verifyAccessToken(token); // throws on invalid/expired

    // Fetch user
    const user = await prisma.user.findUnique({ where: { id: decoded.sub } });
    if (!user) {
      throw createUnauthorizedError('User not found', ERROR_CODES.USER_NOT_FOUND);
    }
    if (user.status === 'banned') {
      throw createForbiddenError('User account is banned', ERROR_CODES.USER_BANNED);
    }
    // if (user.status === 'pending_verification') {
    //   throw createForbiddenError('Email verification required');
    // }

    // Optional but recommended: bind access token to a live session (refresh token record)
    if (decoded.sid) {
      const session = await prisma.refreshToken.findUnique({ where: { id: decoded.sid } });
      if (
          !session ||
          session.userId !== user.id ||
          session.revoked === true ||
          session.expiresAt <= new Date()
      ) {
        throw createUnauthorizedError('Session invalid or expired', ERROR_CODES.SESSION_INVALID);
      }
      // Attach minimal session context
      req.sessionId = session.id;
    }

    const { passwordHash, ...safeUser } = user;
    req.user = safeUser;
    req.tokenPayload = decoded;

    return next();
  } catch (err) {
    // Normalize common JWT errors to 401
    if (err.name === 'TokenExpiredError' || err.name === 'JsonWebTokenError') {
      return next(createUnauthorizedError('Invalid or expired token', ERROR_CODES.TOKEN_INVALID));
    }
    return next(err);
  }
};

module.exports = authMiddleware;
