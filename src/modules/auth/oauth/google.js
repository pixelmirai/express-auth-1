// modules/auth/oauth/google.js
const { OAuth2Client } = require('google-auth-library');
const config = require('../../../config/env');

// Reuse client across calls
const client = new OAuth2Client({
  clientId: config.google.clientId,
  // timeout helps avoid hanging requests in bad networks
  // Note: google-auth-library uses fetch under the hood; timeout is respected.
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
    const ticket = await client.verifyIdToken({
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

module.exports = {
  verifyGoogleIdToken,
};
