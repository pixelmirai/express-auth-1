const { AppError } = require('../utils/errors');
const logger = require('../utils/logger');

const errorHandler = (err, req, res, next) => {
  // JWT errors -> 401
  if (err.name === 'TokenExpiredError' || err.name === 'JsonWebTokenError') {
    return res.status(401).json({ status: 'error', message: 'Invalid or expired token' });
  }

  // Zod validation errors (if your validate middleware ever forwards them)
  if (err.name === 'ZodError') {
    return res.status(400).json({
      status: 'error',
      message: 'Validation failed',
      details: err.errors?.map(e => ({ path: e.path.join('.'), message: e.message })) || [],
    });
  }

  const isAppError = err instanceof AppError;
  const statusCode = isAppError ? err.statusCode : 500;

  const response = {
    status: 'error',
    message: err.message || 'Internal server error',
  };

  if (isAppError && err.details && Object.keys(err.details).length > 0) {
    response.details = err.details;
  }

  if (!isAppError && statusCode >= 500) {
    logger.error({ err }, 'Unhandled error occurred');
  }

  res.status(statusCode).json(response);
};

module.exports = errorHandler;
