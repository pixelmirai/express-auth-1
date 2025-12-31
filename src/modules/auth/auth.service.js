const ms = require('ms');
const prisma = require('../../database/prisma/client');
const logger = require('../../utils/logger');
const { hashPassword, comparePassword } = require('../../utils/password');
const { signAccessToken } = require('../../utils/jwt');
const {
  createSession,
  verifyAndRotateSession,
  revokeSessionById,
  revokeAllSessionsForUser,
} = require('../../utils/tokens');
const { generateToken, hashToken } = require('../../utils/crypto');
const emailService = require('../email/email.service');
const { verifyGoogleIdToken } = require('./oauth/google');
const {
  AppError,
  createUnauthorizedError,
  createForbiddenError,
  createConflictError,
} = require('../../utils/errors');

const EMAIL_VERIFICATION_TTL = ms('24h');
const PASSWORD_RESET_TTL = ms('1h');

const sanitizeUser = (user) => {
  const { passwordHash, ...safeUser } = user;
  return safeUser;
};

const createLoginLog = async ({ userId, success, provider, ip, userAgent }) => {
  await prisma.loginLog.create({
    data: {
      userId,
      success,
      provider,
      ip,
      userAgent,
    },
  });
};

// Helper: sign short-lived access token
const signAccess = (user, sid) =>
    signAccessToken({ sub: user.id, role: user.role, sid });

// REGISTER
const register = async ({ email, password, name }) => {
  const normalizedEmail = email.toLowerCase();
  const normalizedName = name.trim();
  const existingUser = await prisma.user.findUnique({ where: { email: normalizedEmail } });
  if (existingUser) {
    if (existingUser.passwordHash) {
      throw createConflictError('An account with this email already exists');
    }
    throw createConflictError('Email already associated with a social login account');
  }

  const passwordHash = await hashPassword(password);

  const user = await prisma.user.create({
    data: {
      email: normalizedEmail,
      passwordHash,
      name: normalizedName,
      status: 'pending_verification',
    },
  });

  const verificationToken = generateToken(48);
  await prisma.emailVerificationToken.create({
    data: {
      tokenHash: hashToken(verificationToken),
      expiresAt: new Date(Date.now() + EMAIL_VERIFICATION_TTL),
      userId: user.id,
    },
  });

  try {
    await emailService.sendVerificationEmail(user, verificationToken);
  } catch (error) {
    logger.error({ err: error }, 'Failed to send verification email');
  }

  return sanitizeUser(user);
};

// LOGIN (email/password) -> create Session + issue tokens
const login = async ({ email, password, ip, userAgent }) => {
  const normalizedEmail = email.toLowerCase();
  const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });

  if (!user || !user.passwordHash) {
    
    await createLoginLog({ userId: user?.id, success: false, provider: 'password', ip, userAgent });
    throw createUnauthorizedError('Invalid credentials');

  }

  if (user.status === 'banned') {
        console.log("user is banned")
    await createLoginLog({ userId: user.id, success: false, provider: 'password', ip, userAgent });
    throw createForbiddenError('User account is banned');

  }

  // if (user.status === 'pending_verification' ) {
  //       console.log("email not verified")
  //   await createLoginLog({ userId: user.id, success: false, provider: 'password', ip, userAgent });
  //   throw createForbiddenError('Email verification required');
  // }

  const passwordValid = await comparePassword(password, user.passwordHash);
  if (!passwordValid) {
    await createLoginLog({ userId: user.id, success: false, provider: 'password', ip, userAgent });
    throw createUnauthorizedError('Invalid credentials');
  }

  const { token: refreshToken, session } = await createSession(user.id, { ip, userAgent });
  const accessToken = signAccess(user, session.id);

  await createLoginLog({ userId: user.id, success: true, provider: 'password', ip, userAgent });

  return { user: sanitizeUser(user), accessToken, refreshToken };
};

// LOGIN WITH GOOGLE -> same issuance as above
const loginWithGoogleOld = async ({ idToken, ip, userAgent }) => {
  const profile = await verifyGoogleIdToken(idToken);

  if (!profile.email) {
    throw new AppError('Google account does not have an email address', 400);
  }
  if (!profile.emailVerified) {
    throw new AppError('Google email is not verified', 400);
  }

  const normalizedEmail = profile.email.toLowerCase();
  let user = await prisma.user.findUnique({ where: { googleId: profile.googleId } });

  if (!user && normalizedEmail) {
    user = await prisma.user.findUnique({ where: { email: normalizedEmail } });
  }

  if (user) {
    if (user.status === 'banned') {
      await createLoginLog({ userId: user.id, success: false, provider: 'google', ip, userAgent });
      throw createForbiddenError('User account is banned');
    }



    if (!user.googleId) {
      user = await prisma.user.update({
        where: { id: user.id },
        data: {
          googleId: profile.googleId,
          status: 'active',
          name: user.name || profile.name,
          avatarUrl: user.avatarUrl || profile.avatarUrl,
        },
      });
    }




  } else {
    user = await prisma.user.create({
      data: {
        email: normalizedEmail,
        googleId: profile.googleId,
        name: profile.name,
        avatarUrl: profile.avatarUrl,
        status: 'active',
      },
    });
  }

  const { token: refreshToken, session } = await createSession(user.id, { ip, userAgent });
  const accessToken = signAccess(user, session.id);

  await createLoginLog({ userId: user.id, success: true, provider: 'google', ip, userAgent });

  return { user: sanitizeUser(user), accessToken, refreshToken };
};


// updated


//updated login with google, do not allow to merge accounts
const loginWithGoogle = async ({ idToken, ip, userAgent }) => {
  const profile = await verifyGoogleIdToken(idToken);

  if (!profile.email) {
    throw new AppError("Google account does not have an email address", 400);
  }
  if (!profile.emailVerified) {
    throw new AppError("Google email is not verified", 400);
  }

  const normalizedEmail = profile.email.toLowerCase();

  // 1) Find by email (your chosen policy)
  let user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
  });

  // 2) If email exists but is NOT a google-linked account -> block (no implicit linking)
  if (user && !user.googleId) {
    throw createConflictError(
      "An account with this email already exists. Please sign in with email/password."
    );
  }

  // 3) If email exists AND is google-linked, enforce that the googleId matches this token
  if (user && user.googleId && user.googleId !== profile.googleId) {
    throw createConflictError(
      "This email is linked to a different Google account."
    );
  }

  // 4) If no user exists, create a new google user
  if (!user) {
    user = await prisma.user.create({
      data: {
        email: normalizedEmail,
        googleId: profile.googleId,
        name: profile.name,
        avatarUrl: profile.avatarUrl,
        status: "active",
      },
    });
  }

  // 5) Block banned
  if (user.status === "banned") {
    await createLoginLog({
      userId: user.id,
      success: false,
      provider: "google",
      ip,
      userAgent,
    });
    throw createForbiddenError("User account is banned");
  }

  // 6) Session + tokens
  const { token: refreshToken, session } = await createSession(user.id, {
    ip,
    userAgent,
  });

  const accessToken = signAccess(user, session.id);

  await createLoginLog({
    userId: user.id,
    success: true,
    provider: "google",
    ip,
    userAgent,
  });

  return { user: sanitizeUser(user), accessToken, refreshToken };
};

//




// REFRESH TOKENS -> rotation + reuse detection
const refreshTokens = async ({ refreshToken, ip, userAgent }) => {
  if (!refreshToken) {
    throw createUnauthorizedError('Missing refresh token');
  }

  try {
    const { token: newRefresh, session } = await verifyAndRotateSession(refreshToken, { ip, userAgent });
    const user = await prisma.user.findUnique({ where: { id: session.userId } });
    if (!user) throw createUnauthorizedError('Invalid refresh token');

    if (user.status === 'banned') {
      // revoke newly created session just in case
      await revokeSessionById(session.id).catch(() => {});
      throw createForbiddenError('User account is banned');
    }

    const accessToken = signAccess(user, session.id);
    return { accessToken, refreshToken: newRefresh };
  } catch (e) {
    const msg = e && e.message;
    if (msg === 'reuse_detected') {
      // Entire family is revoked in utils already; caller should force re-login
      throw createUnauthorizedError('Refresh token reuse detected');
    }
    if (msg === 'expired') throw createUnauthorizedError('Refresh token expired');
    if (msg === 'revoked' || msg === 'invalid_refresh') throw createUnauthorizedError('Invalid refresh token');
    throw e;
  }
};

// LOGOUT (single session)
const logout = async ({ refreshToken }) => {
  if (!refreshToken) return; // cookie-only logout handled in controller
  const th = hashToken(refreshToken);
  const tokenRecord = await prisma.refreshToken.findUnique({ where: { tokenHash: th } });
  if (tokenRecord && !tokenRecord.revoked) {
    await revokeSessionById(tokenRecord.id);
  }
};

// EMAIL VERIFY
const verifyEmail = async ({ token }) => {
  const tokenHash = hashToken(token);
  const record = await prisma.emailVerificationToken.findUnique({ where: { tokenHash } });
  if (!record) {
    throw createUnauthorizedError('Invalid verification token');
  }

  if (record.expiresAt < new Date()) {
    await prisma.emailVerificationToken.delete({ where: { id: record.id } });
    throw createUnauthorizedError('Verification token expired');
  }

  const user = await prisma.user.findUnique({ where: { id: record.userId } });
  if (!user) {
    throw createUnauthorizedError('Invalid verification token');
  }

  let updatedUser = user;
  if (user.status !== 'banned') {
    updatedUser = await prisma.user.update({
      where: { id: record.userId },
      data: {
        status: 'active',
      },
    });
  }

  await prisma.emailVerificationToken.delete({ where: { id: record.id } });
  return sanitizeUser(updatedUser);
};

// RESEND EMAIL VERIFICATION
const resendVerificationEmail = async ({ email }) => {
  const normalizedEmail = email.toLowerCase();
  const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });

  // Do nothing if user doesn't need verification or shouldn't receive emails
  if (!user || user.status !== 'pending_verification' || user.status === 'banned') {
    return;
  }

  const verificationToken = generateToken(48);

  await prisma.$transaction([
    prisma.emailVerificationToken.deleteMany({ where: { userId: user.id } }),
    prisma.emailVerificationToken.create({
      data: {
        tokenHash: hashToken(verificationToken),
        expiresAt: new Date(Date.now() + EMAIL_VERIFICATION_TTL),
        userId: user.id,
      },
    }),
  ]);

  try {
    await emailService.sendVerificationEmail(user, verificationToken);
  } catch (error) {
    logger.error({ err: error }, 'Failed to send verification email');
  }
};

// PASSWORD RESET
const requestPasswordReset = async ({ email }) => {
  const normalizedEmail = email.toLowerCase();
  const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });
  if (!user || !user.passwordHash || user.status === 'banned') {
    // Do not reveal whether the user exists
    return;
  }

  const tokenValue = generateToken(48);
  await prisma.passwordResetToken.deleteMany({ where: { userId: user.id, used: false } });
  await prisma.passwordResetToken.create({
    data: {
      tokenHash: hashToken(tokenValue),
      expiresAt: new Date(Date.now() + PASSWORD_RESET_TTL),
      userId: user.id,
    },
  });

  try {
    await emailService.sendPasswordResetEmail(user, tokenValue);
  } catch (error) {
    logger.error({ err: error }, 'Failed to send password reset email');
  }
};

const resetPassword = async ({ token, password }) => {
  const tokenHash = hashToken(token);
  const record = await prisma.passwordResetToken.findUnique({ where: { tokenHash } });
  if (!record) {
    throw createUnauthorizedError('Invalid reset token');
  }

  if (record.used) {
    throw createUnauthorizedError('Reset token has already been used');
  }

  if (record.expiresAt < new Date()) {
    await prisma.passwordResetToken.delete({ where: { id: record.id } });
    throw createUnauthorizedError('Reset token expired');
  }

  const passwordHash = await hashPassword(password);

  await prisma.$transaction([
    prisma.user.update({
      where: { id: record.userId },
      data: {
        passwordHash,
        status: 'active',
      },
    }),
    prisma.passwordResetToken.update({
      where: { id: record.id },
      data: { used: true },
    }),
  ]);

  // Global sign-out after password reset
  await revokeAllSessionsForUser(record.userId);
};

module.exports = {
  register,
  login,
  loginWithGoogle,
  refreshTokens,
  logout,
  verifyEmail,
  resendVerificationEmail,
  requestPasswordReset,
  resetPassword,
};
