const config = require('../../config/env');
const logger = require('../../utils/logger');
const { Resend } = require('resend');

const frontendURL = 'http://localhost:3000';

const resend = new Resend(config.email.resendApiKey);

const formatFrom = (from) => {
  if (!from) return from;
  if (typeof from === 'string') return from;
  const name = (from.name || '').trim();
  const address = from.address || '';
  return name ? `${name} <${address}>` : address;
};

const sendMail = async (options) => {
  try {
    const payload = {
      to: options.to,
      from: formatFrom(options.from),
      subject: options.subject,
      html: options.html,
      text: options.text,
    };

    const { data, error } = await resend.emails.send(payload);
    if (error) {
      throw error;
    }

    logger.info({ messageId: data && data.id }, 'Email sent');
    return data;
  } catch (error) {
    logger.error({ err: error }, 'Failed to send email');
    throw error;
  }
};

const sendVerificationEmail = async (user, token) => {
  const verificationUrl = `${frontendURL}/auth/verify-email?token=${token}`;



  return sendMail({
    to: user.email,
    from: {
      name: 'Auth Service',
      address: config.email.smtpUser,
    },
    subject: 'Verify your email address',
    html: `
      <h1>Verify your email</h1>
      <p>Hello ${user.name || 'there'},</p>
      <p>Thank you for registering. Please verify your email address by clicking the link below:</p>
      <p><a href="${verificationUrl}">Verify Email</a></p>
      <p>If you did not request this, you can safely ignore this email.</p>
    `,
  });
};

const sendPasswordResetEmail = async (user, token) => {
  const resetUrl = `${frontendURL}/auth/reset-password?token=${token}`;
  return sendMail({
    to: user.email,
    from: {
      name: 'Auth Service',
      address: config.email.smtpUser,
    },
    subject: 'Reset your password',
    html: `
      <h1>Password Reset Request</h1>
      <p>Hello ${user.name || 'there'},</p>
      <p>We received a request to reset your password. Use the token below or click the link to reset it.</p>
      <p><strong>Token:</strong> ${token}</p>
      <p><a href="${resetUrl}">Reset Password</a></p>
      <p>If you did not request this, please ignore this email.</p>
    `,
  });
};

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
};
