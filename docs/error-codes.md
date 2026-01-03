# Error Codes

API errors now include a machine-friendly `code` alongside the HTTP status and `message`. These are the current enum-style codes the backend emits.

## General
- `INTERNAL_ERROR` — Unhandled server error.
- `VALIDATION_FAILED` — Request failed validation.
- `UNAUTHORIZED` — Authentication required/failed (generic).
- `FORBIDDEN` — Authorization failed (generic).
- `NOT_FOUND` — Resource not found.
- `CONFLICT` — Conflict with current state.

## AuthN/AuthZ
- `TOKEN_MISSING` — Access token header missing.
- `TOKEN_INVALID` — Access token invalid or expired.
- `USER_NOT_FOUND` — Authenticated user id not found.
- `USER_BANNED` — Account banned.
- `EMAIL_NOT_VERIFIED` — Email pending verification.
- `INSUFFICIENT_PERMISSIONS` — Role/permission check failed.
- `SESSION_INVALID` — Bound session missing, revoked, or expired.
- `INVALID_CREDENTIALS` — Wrong email/password.

## Account/Identity Conflicts
- `EMAIL_IN_USE_PASSWORD` — Email already registered with email/password.
- `EMAIL_IN_USE_SOCIAL` — Email already associated to a social login account.
- `GOOGLE_ACCOUNT_MISMATCH` — Google sign-in email linked to another Google account.
- `GOOGLE_EMAIL_MISSING` — Google profile missing an email.
- `GOOGLE_EMAIL_NOT_VERIFIED` — Google email not verified.

## Refresh Tokens / Sessions
- `REFRESH_TOKEN_MISSING` — Refresh token not provided.
- `INVALID_REFRESH_TOKEN` — Refresh token unknown or revoked.
- `REFRESH_TOKEN_REUSE` — Refresh token reuse detected.
- `REFRESH_TOKEN_EXPIRED` — Refresh token expired.

## Email Verification
- `INVALID_VERIFICATION_TOKEN` — Verification token invalid.
- `VERIFICATION_TOKEN_EXPIRED` — Verification token expired.

## Password Reset
- `INVALID_RESET_TOKEN` — Reset token invalid.
- `RESET_TOKEN_USED` — Reset token already used.
- `RESET_TOKEN_EXPIRED` — Reset token expired.
