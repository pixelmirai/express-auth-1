const jwt = require('jsonwebtoken');
const config = require('../config/env');

const signAccessToken = (payload, options = {}) => {
  return jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.accessTokenTtl,
    ...options,
  });
};

const verifyAccessToken = (token) => {
  return jwt.verify(token, config.jwt.secret);
};

module.exports = {
  signAccessToken,
  verifyAccessToken,
};
