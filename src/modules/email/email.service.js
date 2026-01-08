const nodemailer = require('nodemailer');
const config = require('../../config/env');
const logger = require('../../utils/logger');

const frontendURL = `http://localhost:3000`

const transporter = nodemailer.createTransport({
  host: config.email.smtpHost,
  port: config.email.smtpPort,
  secure: config.email.smtpPort === 465,
  auth: {
    user: config.email.smtpUser,
    pass: config.email.smtpPass,
  },
});

const sendMail = async (options) => {
  try {
    const info = await transporter.sendMail(options);
    logger.info({ messageId: info.messageId }, 'Email sent');
    return info;
  } catch (error) {
    logger.error({ err: error }, 'Failed to send email');
    throw error;
  }
};

const sendVerificationEmail = async (user, token) => {

  const apiUrl = `${config.app.url}/auth/verify-email?token=${token}`;
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
  const apiUrl = `${config.app.url}/auth/reset-password?token=${token}`;
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
