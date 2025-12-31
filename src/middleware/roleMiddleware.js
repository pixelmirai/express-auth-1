// middleware/roleMiddleware.js
const { createForbiddenError } = require('../utils/errors');

/**
 * Role/permission guard.
 *
 * Usage:
 *   roleMiddleware('admin')
 *   roleMiddleware(['admin', 'moderator'])
 *   roleMiddleware(['admin'], (req) => req.user.orgId === req.params.orgId)
 *
 * @param {string|string[]} roles - allowed roles
 * @param {(req: Request) => boolean|Promise<boolean>} [predicate] - optional extra check
 */
const roleMiddleware = (roles = [], predicate) => {
  const allowed = Array.isArray(roles) ? roles : [roles];

  return async (req, res, next) => {
    try {
      // authMiddleware should set req.user; if it didn't, this is a hard stop
      if (!req.user) {
        return next(createForbiddenError('Insufficient permissions'));
      }

      // role match
      const roleOk =
          allowed.length === 0 || // no roles specified means "any authenticated user"
          allowed.includes(req.user.role);

      if (!roleOk) {
        return next(createForbiddenError('Insufficient permissions'));
      }

      // optional predicate for fine-grained checks (ownership, org, etc.)
      if (typeof predicate === 'function') {
        const extraOk = await Promise.resolve(predicate(req));
        if (!extraOk) {
          return next(createForbiddenError('Insufficient permissions'));
        }
      }

      return next();
    } catch (err) {
      return next(err);
    }
  };
};

module.exports = roleMiddleware;
