const express = require('express');
const rateLimit = require('express-rate-limit');
const controller = require('./auth.controller');
const validate = require('../../middleware/validate');
const authMiddleware = require('../../middleware/authMiddleware');
const {
  registerSchema,
  loginSchema,
  googleLoginSchema,
  refreshSchema,
  logoutSchema,
  logoutAllSchema,
  verifyEmailSchema,
  requestPasswordResetSchema,
  resetPasswordSchema,
  resendVerificationSchema,
} = require('./auth.validators');

const router = express.Router();

const resendVerificationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Too many verification requests. Please try again later.',
  },
});

router.post('/register', validate(registerSchema), controller.register);
router.post('/login', validate(loginSchema), controller.login);
router.post('/login/google', validate(googleLoginSchema), controller.loginWithGoogle);
router.post('/refresh', validate(refreshSchema), controller.refresh);
router.post('/logout', validate(logoutSchema), controller.logout);
router.post('/logout-all', authMiddleware, validate(logoutAllSchema), controller.logoutAll);
router.post('/verify-email', validate(verifyEmailSchema), controller.verifyEmail);
router.post('/resend-verification', resendVerificationLimiter,validate(resendVerificationSchema),controller.resendVerificationEmail);
router.post('/request-password-reset', validate(requestPasswordResetSchema), controller.requestPasswordReset);
router.post('/reset-password', validate(resetPasswordSchema), controller.resetPassword);

module.exports = router;
