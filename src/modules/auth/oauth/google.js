// modules/auth/oauth/google.js
const { OAuth2Client } = require('google-auth-library');
const config = require('../../../config/env');

// Reuse client across calls
const idTokenClient = new OAuth2Client({
  clientId: config.google.clientId,
  // timeout helps avoid hanging requests in bad networks
  // Note: google-auth-library uses fetch under the hood; timeout is respected.
  timeout: 5000,
});

const authCodeClient = new OAuth2Client({
  clientId: config.google.clientId,
  clientSecret: config.google.clientSecret,
  timeout: 5000,
});

/**
 * Verifies a Google ID token and returns normalized profile fields:
 * { googleId, email, emailVerified, name, avatarUrl }
 *
 * Throws Error('invalid_google_token') on any verification problem.
 */
const verifyGoogleIdToken = async (idToken) => {
  try {
    const ticket = await idTokenClient.verifyIdToken({
      idToken,
      audience: config.google.clientId, // enforces aud
    });

    const payload = ticket.getPayload();
    if (!payload || !payload.sub) throw new Error('invalid_google_token');

    // Normalize fields
    return {
      googleId: payload.sub,
      email: typeof payload.email === 'string' ? payload.email.toLowerCase() : null,
      emailVerified: Boolean(payload.email_verified),
      name: payload.name || null,
      avatarUrl: payload.picture || null,
    };
  } catch (err) {
    // Unify error so upstream doesn’t leak internals
    const e = new Error('invalid_google_token');
    e.cause = err;
    throw e;
  }
};

/**
 * Exchanges an OAuth authorization code for a Google ID token and verifies it.
 * Accepts optional redirectUri and codeVerifier (PKCE).
 */
const verifyGoogleAuthCodeOLD = async ({ code, redirectUri, codeVerifier }) => {
  try {
    const options = { code };
    if (redirectUri) options.redirect_uri = redirectUri;
    if (codeVerifier) options.codeVerifier = codeVerifier;

    const { tokens } = await authCodeClient.getToken(options);
    if (!tokens || !tokens.id_token) throw new Error('invalid_google_token');

    return await verifyGoogleIdToken(tokens.id_token);
  } catch (err) {
    const e = new Error('invalid_google_token');
    e.cause = err;
    throw e;
  }
};

const verifyGoogleAuthCode = async ({ code, redirectUri, codeVerifier }) => {
  if (!redirectUri) throw new Error("missing_redirect_uri");

  const options = { code, redirect_uri: redirectUri };
  if (codeVerifier) options.codeVerifier = codeVerifier;

  const { tokens } = await authCodeClient.getToken(options);
  if (!tokens?.id_token) throw new Error("invalid_google_token");

  return await verifyGoogleIdToken(tokens.id_token);
};

module.exports = {
  verifyGoogleIdToken,
  verifyGoogleAuthCode,
};
