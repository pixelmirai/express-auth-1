const ms = require('ms');
const authService = require('./auth.service');
const config = require('../../config/env');

function getRefreshTokenFromRequest(req) {
  const cookieName = config.tokens.cookie.name;
  const cookieToken = req.cookies && req.cookies[cookieName];
  const header = req.get('authorization') || '';
  const headerToken = header.startsWith('Bearer ') ? header.slice(7) : undefined;
  const bodyToken = req.validated?.body?.refreshToken;

  return cookieToken || headerToken || bodyToken;
}

function setRefreshCookie(res, token) {
  const c = config.tokens.cookie;
  res.cookie(c.name, token, {
    httpOnly: true,
    secure: c.secure,
    sameSite: c.sameSite,
    path: c.path,
    maxAge: ms(config.tokens.refreshTokenTtl),
  });
}

function clearRefreshCookie(res) {
  const c = config.tokens.cookie;
  res.clearCookie(c.name, {
    httpOnly: true,
    secure: c.secure,
    sameSite: c.sameSite,
    path: c.path,
  });
}

const register = async (req, res, next) => {
  try {
    const { email, password, name } = req.validated.body;
    const user = await authService.register({ email, password, name });
    res.status(201).json({ status: 'success', data: { user } });
  } catch (error) {
    next(error);
  }
};

const login = async (req, res, next) => {
  try {
    const { email, password } = req.validated.body;
    const ip = req.ip;
    const userAgent = req.get('user-agent') || '';
    const result = await authService.login({ email, password, ip, userAgent });

    // result should be { user, accessToken, refreshToken }
    if (result.refreshToken) setRefreshCookie(res, result.refreshToken);

    res.json({
      status: 'success',
      data: {
        user: result.user,
        accessToken: result.accessToken,
        // keep legacy clients happy; browsers will ignore this
        refreshToken: result.refreshToken,
      },
    });
  } catch (error) {
    next(error);
  }
};

const loginWithGoogle = async (req, res, next) => {
  try {
    const { idToken } = req.validated.body;
    const ip = req.ip;
    const userAgent = req.get('user-agent') || '';
    const result = await authService.loginWithGoogle({ idToken, ip, userAgent });

    if (result.refreshToken) setRefreshCookie(res, result.refreshToken);

    res.json({
      status: 'success',
      data: {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      },
    });
  } catch (error) {
    next(error);
  }
};

const refresh = async (req, res, next) => {
  try {
    const provided = getRefreshTokenFromRequest(req);
    if (!provided) {
      return res.status(401).json({ status: 'error', message: 'Missing refresh token' });
    }

    const ip = req.ip;
    const userAgent = req.get('user-agent') || '';

    // result should be { accessToken, refreshToken }
    const result = await authService.refreshTokens({ refreshToken: provided, ip, userAgent });

    if (result.refreshToken) setRefreshCookie(res, result.refreshToken);

    res.json({
      status: 'success',
      data: {
        accessToken: result.accessToken,
        // included for non-browser clients
        refreshToken: result.refreshToken,
      },
    });
  } catch (error) {
    // Map common auth errors to clearer statuses
    const msg = (error && error.message) || '';
    if (msg === 'reuse_detected') {
      clearRefreshCookie(res);
      return res.status(401).json({ status: 'error', message: 'Refresh token reuse detected. Please log in again.' });
    }
    if (msg === 'expired') {
      clearRefreshCookie(res);
      return res.status(401).json({ status: 'error', message: 'Refresh token expired. Please log in again.' });
    }
    if (msg === 'invalid_refresh' || msg === 'revoked') {
      clearRefreshCookie(res);
      return res.status(401).json({ status: 'error', message: 'Invalid refresh token.' });
    }
    next(error);
  }
};

const logout = async (req, res, next) => {
  try {
    // Prefer cookie/header; fall back to body for legacy
    const token = getRefreshTokenFromRequest(req) || req.validated.body.refreshToken;
    await authService.logout({ refreshToken: token });
    clearRefreshCookie(res);
    res.json({ status: 'success', message: 'Logged out successfully' });
  } catch (error) {
    next(error);
  }
};

const logoutAll = async (req, res, next) => {
  try {
    await authService.logoutAllSessions({ userId: req.user.id });
    res.json({ status: 'success', message: 'Logged out from all sessions successfully' });
  } catch (error) {
    next(error);
  }
};

const verifyEmail = async (req, res, next) => {
  console.log("in verify controler")
  try {
    const { token } = req.validated.body;
    const user = await authService.verifyEmail({ token });
    res.json({ status: 'success', data: { user } });
  } catch (error) {
    next(error);
  }
};

const requestPasswordReset = async (req, res, next) => {
  try {
    const { email } = req.validated.body;
    await authService.requestPasswordReset({ email });
    res.json({ status: 'success', message: 'If the email exists, a reset link has been sent' });
  } catch (error) {
    next(error);
  }
};

const resendVerificationEmail = async (req, res, next) => {
  try {
    const { email } = req.validated.body;
    await authService.resendVerificationEmail({ email });
    res.json({
      status: 'success',
      message: 'If the account exists and needs verification, an email has been sent',
    });
  } catch (error) {
    next(error);
  }
};

const resetPassword = async (req, res, next) => {
  try {
    const { token, password } = req.validated.body;
    await authService.resetPassword({ token, password });
    res.json({ status: 'success', message: 'Password updated successfully' });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  register,
  login,
  loginWithGoogle,
  refresh,
  logout,
  logoutAll,
  verifyEmail,
  resendVerificationEmail,
  requestPasswordReset,
  resetPassword,
};
