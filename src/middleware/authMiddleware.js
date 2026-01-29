const prisma = require('../database/prisma/client');
const { verifyAccessToken } = require('../utils/jwt');
const { createUnauthorizedError, createForbiddenError, ERROR_CODES } = require('../utils/errors');

const ACCESS_TOKEN_COOKIE = 'access_token'; // adjust if needed

const authMiddleware = async (req, res, next) => {
  try {
    let token;

    // 1) Bearer token
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7);
    }

    // 2) Cookie fallback
    if (!token && req.cookies && req.cookies[ACCESS_TOKEN_COOKIE]) {
      token = req.cookies[ACCESS_TOKEN_COOKIE];
    }

    if (!token) {
      throw createUnauthorizedError('Authentication token missing', ERROR_CODES.TOKEN_MISSING);
    }

    const decoded = verifyAccessToken(token); // throws on invalid/expired

    const user = await prisma.user.findUnique({ where: { id: decoded.sub } });
    if (!user) {
      throw createUnauthorizedError('User not found', ERROR_CODES.USER_NOT_FOUND);
    }
    if (user.status === 'banned') {
      throw createForbiddenError('User account is banned', ERROR_CODES.USER_BANNED);
    }

    // Optional session binding
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
      req.sessionId = session.id;
    }

    const { passwordHash, ...safeUser } = user;
    req.user = safeUser;
    req.tokenPayload = decoded;

    return next();
  } catch (err) {
    if (err.name === 'TokenExpiredError' || err.name === 'JsonWebTokenError') {
      return next(createUnauthorizedError('Invalid or expired token', ERROR_CODES.TOKEN_INVALID));
    }
    return next(err);
  }
};

module.exports = authMiddleware;
