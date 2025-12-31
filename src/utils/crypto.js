const crypto = require('crypto');

const generateToken = (byteLength = 32) => {
  return crypto.randomBytes(byteLength).toString('hex');
};

const hashToken = (token) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

module.exports = {
  generateToken,
  hashToken,
};
