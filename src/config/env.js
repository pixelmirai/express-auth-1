// config/env.js
const path = require('path');
const dotenv = require('dotenv');
const { z } = require('zod');

// Only load .env locally
if (process.env.NODE_ENV !== 'production') {
  const envFile = process.env.NODE_ENV === 'test' ? '.env.test' : '.env';
  dotenv.config({ path: path.resolve(process.cwd(), envFile) });
}

// Read ONLY your existing vars
const rawEnv = {
  NODE_ENV: process.env.NODE_ENV,
  PORT: process.env.PORT,
  APP_URL: process.env.APP_URL,
  DATABASE_URL: process.env.DATABASE_URL,
  JWT_SECRET: process.env.JWT_SECRET,
  ACCESS_TOKEN_TTL: process.env.ACCESS_TOKEN_TTL,
  REFRESH_TOKEN_TTL: process.env.REFRESH_TOKEN_TTL,
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
  EMAIL_SMTP_HOST: process.env.EMAIL_SMTP_HOST,
  EMAIL_SMTP_PORT: process.env.EMAIL_SMTP_PORT,
  EMAIL_SMTP_USER: process.env.EMAIL_SMTP_USER,
  EMAIL_SMTP_PASS: process.env.EMAIL_SMTP_PASS,
  RESEND_API_KEY: process.env.RESEND_API_KEY,
};

// Validation (keeps your original semantics)
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().default('3000').transform((val) => {
    const port = Number(val);
    if (!Number.isInteger(port) || port <= 0) {
      throw new Error('PORT must be a positive integer');
    }
    return port;
  }),
  APP_URL: z.string().url(),
  DATABASE_URL: z.string().min(1),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  ACCESS_TOKEN_TTL: z.string().min(2),
  REFRESH_TOKEN_TTL: z.string().min(2),
  GOOGLE_CLIENT_ID: z.string().min(1),
  GOOGLE_CLIENT_SECRET: z.string().min(1),
  EMAIL_SMTP_HOST: z.string().min(1),
  EMAIL_SMTP_PORT: z.string().transform((val) => {
    const port = Number(val);
    if (!Number.isInteger(port) || port <= 0) {
      throw new Error('EMAIL_SMTP_PORT must be a positive integer');
    }
    return port;
  }),
  EMAIL_SMTP_USER: z.string().min(1),
  EMAIL_SMTP_PASS: z.string().min(1),
  RESEND_API_KEY: z.string().min(1),
});

const parsed = envSchema.safeParse(rawEnv);
if (!parsed.success) {
  const formattedError = parsed.error.errors
      .map((err) => `${err.path.join('.')}: ${err.message}`)
      .join('\n');
  throw new Error(`Invalid environment configuration:\n${formattedError}`);
}

const env = parsed.data;

// Exported config used everywhere else
const config = {
  env: env.NODE_ENV,
  app: {
    port: env.PORT,
    url: env.APP_URL,
  },
  database: {
    url: env.DATABASE_URL,
  },
  // Access JWT stays stateless, HS256 using your single secret
  jwt: {
    alg: 'HS256',
    secret: env.JWT_SECRET,
    accessTokenTtl: env.ACCESS_TOKEN_TTL, // e.g. "15m"
    issuer: env.APP_URL,
  },
  // Refresh is opaque + DB-backed in our new flow
  tokens: {
    refreshTokenTtl: env.REFRESH_TOKEN_TTL, // e.g. "30d"
    // Hard cap for sliding sessions: use same value as refresh TTL by default
    maxSessionLifetime: env.REFRESH_TOKEN_TTL,
    // Cookie defaults for browsers (no new envs required)
    cookie: {
      name: 'rtid',
      secure: env.NODE_ENV === 'production',
      sameSite: 'Lax',
      httpOnly: true,
      path: '/auth/refresh',
    },
  },
  google: {
    clientId: env.GOOGLE_CLIENT_ID,
    clientSecret: env.GOOGLE_CLIENT_SECRET,
  },
  email: {
    smtpHost: env.EMAIL_SMTP_HOST,
    smtpPort: env.EMAIL_SMTP_PORT,
    smtpUser: env.EMAIL_SMTP_USER,
    smtpPass: env.EMAIL_SMTP_PASS,
    resendApiKey: env.RESEND_API_KEY,
  },
};

module.exports = config;

