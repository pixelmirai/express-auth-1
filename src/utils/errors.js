class AppError extends Error {
  constructor(message, statusCode = 500, details = {}) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.details = details;
    Error.captureStackTrace?.(this, this.constructor);
  }
}

const createNotFoundError = (message = 'Resource not found') => new AppError(message, 404);
const createValidationError = (message = 'Validation failed', details = {}) => new AppError(message, 400, details);
const createUnauthorizedError = (message = 'Unauthorized') => new AppError(message, 401);
const createForbiddenError = (message = 'Forbidden') => new AppError(message, 403);
const createConflictError = (message = 'Conflict') => new AppError(message, 409);

module.exports = {
  AppError,
  createNotFoundError,
  createValidationError,
  createUnauthorizedError,
  createForbiddenError,
  createConflictError,
};
