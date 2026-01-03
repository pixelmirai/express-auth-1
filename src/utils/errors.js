const ERROR_CODES = {
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',

  // AuthN/AuthZ specifics
  TOKEN_MISSING: 'TOKEN_MISSING',
  TOKEN_INVALID: 'TOKEN_INVALID',
  USER_NOT_FOUND: 'USER_NOT_FOUND',
  USER_BANNED: 'USER_BANNED',
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  INSUFFICIENT_PERMISSIONS: 'INSUFFICIENT_PERMISSIONS',
  SESSION_INVALID: 'SESSION_INVALID',
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',

  // Account / identity conflicts
  EMAIL_IN_USE_PASSWORD: 'EMAIL_IN_USE_PASSWORD',
  EMAIL_IN_USE_SOCIAL: 'EMAIL_IN_USE_SOCIAL',
  GOOGLE_ACCOUNT_MISMATCH: 'GOOGLE_ACCOUNT_MISMATCH',
  GOOGLE_EMAIL_MISSING: 'GOOGLE_EMAIL_MISSING',
  GOOGLE_EMAIL_NOT_VERIFIED: 'GOOGLE_EMAIL_NOT_VERIFIED',

  // Refresh token + session rotation
  REFRESH_TOKEN_MISSING: 'REFRESH_TOKEN_MISSING',
  INVALID_REFRESH_TOKEN: 'INVALID_REFRESH_TOKEN',
  REFRESH_TOKEN_REUSE: 'REFRESH_TOKEN_REUSE',
  REFRESH_TOKEN_EXPIRED: 'REFRESH_TOKEN_EXPIRED',

  // Email verification
  INVALID_VERIFICATION_TOKEN: 'INVALID_VERIFICATION_TOKEN',
  VERIFICATION_TOKEN_EXPIRED: 'VERIFICATION_TOKEN_EXPIRED',

  // Password reset
  INVALID_RESET_TOKEN: 'INVALID_RESET_TOKEN',
  RESET_TOKEN_USED: 'RESET_TOKEN_USED',
  RESET_TOKEN_EXPIRED: 'RESET_TOKEN_EXPIRED',
};

class AppError extends Error {
  constructor(message, statusCode = 500, details = {}, code = ERROR_CODES.INTERNAL_ERROR) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.details = details;
    this.code = code;
    Error.captureStackTrace?.(this, this.constructor);
  }
}

const createNotFoundError = (message = 'Resource not found', code = ERROR_CODES.NOT_FOUND) =>
  new AppError(message, 404, {}, code);
const createValidationError = (message = 'Validation failed', details = {}, code = ERROR_CODES.VALIDATION_FAILED) =>
  new AppError(message, 400, details, code);
const createUnauthorizedError = (message = 'Unauthorized', code = ERROR_CODES.UNAUTHORIZED) =>
  new AppError(message, 401, {}, code);
const createForbiddenError = (message = 'Forbidden', code = ERROR_CODES.FORBIDDEN) =>
  new AppError(message, 403, {}, code);
const createConflictError = (message = 'Conflict', code = ERROR_CODES.CONFLICT) =>
  new AppError(message, 409, {}, code);

module.exports = {
  AppError,
  ERROR_CODES,
  createNotFoundError,
  createValidationError,
  createUnauthorizedError,
  createForbiddenError,
  createConflictError,
};
