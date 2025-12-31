const { createValidationError } = require('../utils/errors');

const validate = (schema) => async (req, res, next) => {
  try {
    const result = await schema.parseAsync({
      body: req.body,
      params: req.params,
      query: req.query,
    });
    req.validated = result;
    return next();
  } catch (error) {
    const formatted = error.issues?.map((issue) => ({
      path: issue.path.join('.'),
      message: issue.message,
    }));
    return next(createValidationError('Invalid request data', formatted));
  }
};

module.exports = validate;
