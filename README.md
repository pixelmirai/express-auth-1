# Express Auth Backend Template

A production-ready, white-label authentication backend for mobile applications built with Node.js, Express, PostgreSQL, and Prisma. Features email and Google authentication, email verification, password resets, refresh token rotation, user banning, and admin tooling.

## Features

- Email + password registration with bcrypt hashing and email verification
- Google OAuth login with backend token verification
- JWT access tokens and database-backed, rotatable refresh tokens
- Password reset flow with expiring tokens
- User banning and admin management endpoints
- Centralized environment configuration with strict validation
- Nodemailer SMTP integration for transactional emails
- Prisma ORM with PostgreSQL

## Prerequisites

- Node.js >= 18
- PostgreSQL database

## Getting Started

1. **Install dependencies**

   ```bash
   cd backend
   npm install
   ```

2. **Configure environment variables**

   Copy `.env.example` to `.env` and provide real values.

   ```bash
   cp .env .env
   ```

   Update the following keys:

   - `DATABASE_URL` – PostgreSQL connection string
   - `JWT_SECRET` – at least 32 characters
   - `ACCESS_TOKEN_TTL` – e.g. `15m`
   - `REFRESH_TOKEN_TTL` – e.g. `30d`
   - `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`
   - `EMAIL_SMTP_*` – SMTP credentials used by Nodemailer

3. **Apply database schema**

   ```bash
   npx prisma migrate deploy
   ```

   Generate Prisma Client (optional during development):

   ```bash
   npx prisma generate
   ```

4. **Start the server**

   ```bash
   npm start
   ```

   The API is available at `http://localhost:3000` by default.

## API Overview

### Authentication

- `POST /auth/register` – Register with email, password, and name.
- `POST /auth/login` – Email/password login.
- `POST /auth/login/google` – Login using a Google ID token.
- `POST /auth/refresh` – Exchange a refresh token for new tokens.
- `POST /auth/logout` – Revoke a refresh token.
- `POST /auth/verify-email` – Verify email using the emailed token.
- `POST /auth/request-password-reset` – Request a reset token.
- `POST /auth/reset-password` – Reset password with the provided token.

### Users

- `GET /users/me` – Fetch the authenticated user's profile.

### Admin

Requires an authenticated admin user (`role = "admin"`).

- `GET /admin/users` – List all users.
- `GET /admin/users/:id` – Fetch details for a specific user.
- `PATCH /admin/users/:id/ban` – Ban a user.
- `PATCH /admin/users/:id/unban` – Unban a user.
- `DELETE /admin/users/:id/delete` – Permanently delete a user and related tokens.

## Mobile App Integration

For mobile clients, include the access token in the `Authorization` header (`Bearer <token>`) for authenticated requests. Store the refresh token securely (e.g., Keychain/Keystore) and call `POST /auth/refresh` before the access token expires. Use the verification and reset endpoints to manage email flows from deep links in your app.

## Development Tips

- Use `npm run dev` for automatic restarts with Nodemon.
- Prisma Studio can inspect your database: `npx prisma studio`.
- Logs are emitted via Pino; in development they are human-readable.

## License

MIT
