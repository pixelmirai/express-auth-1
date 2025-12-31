const { z } = require('zod');

const passwordSchema = z
    .string()
    .min(8, 'Password must be at least 8 characters long')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number');

const registerSchema = z.object({
  body: z.object({
    email: z.string().email(),
    password: passwordSchema,
    name: z.string().min(1).max(120),
  }),
});

const loginSchema = z.object({
  body: z.object({
    email: z.string().email(),
    password: z.string().min(1),
  }),
});

const googleLoginSchema = z.object({
  body: z.object({
    idToken: z.string().min(10),
  }),
});

// Optional so browsers can use HttpOnly cookie and mobile can use header/body
const refreshSchema = z.object({
  body: z.object({
    refreshToken: z.string().min(10).optional(),
  }),
});

const logoutSchema = z.object({
  body: z.object({
    refreshToken: z.string().min(10).optional(),
  }),
});

const logoutAllSchema = z.object({
  body: z.object({}).strict(),
});

const verifyEmailSchema = z.object({
  body: z.object({
    token: z.string().min(10),
  }),
});

const requestPasswordResetSchema = z.object({
  body: z.object({
    email: z.string().email(),
  }),
});

const resendVerificationSchema = z.object({
  body: z.object({
    email: z.string().email(),
  }),
});

const resetPasswordSchema = z.object({
  body: z.object({
    token: z.string().min(10),
    password: passwordSchema,
  }),
});

module.exports = {
  registerSchema,
  loginSchema,
  googleLoginSchema,
  refreshSchema,
  logoutSchema,
  logoutAllSchema,
  verifyEmailSchema,
  requestPasswordResetSchema,
  resendVerificationSchema,
  resetPasswordSchema,
};
