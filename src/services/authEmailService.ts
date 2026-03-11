import resend from './resendClient';

const APP_NAME = process.env.APP_NAME || 'Commune';
const EMAIL_FROM = process.env.AUTH_EMAIL_FROM || process.env.DEFAULT_FROM_EMAIL || 'no-reply@commune.email';
const FRONTEND_BASE_URL = process.env.FRONTEND_BASE_URL || 'http://localhost:3000';

export const sendVerificationEmail = async ({ to, token }: { to: string; token: string }) => {
  const verifyUrl = `${FRONTEND_BASE_URL.replace(/\/$/, '')}/verify?token=${token}`;
  const html = `
    <div style="font-family: Arial, sans-serif; color:#0b1224; line-height:1.5;">
      <h2>Verify your email</h2>
      <p>Welcome to ${APP_NAME}. Please verify your email to finish setup.</p>
      <p><a href="${verifyUrl}">Verify email</a></p>
      <p>If the button doesn't work, copy this link:</p>
      <p>${verifyUrl}</p>
    </div>
  `;

  return resend.emails.send({
    from: EMAIL_FROM,
    to,
    subject: `Verify your ${APP_NAME} email`,
    html,
  } as any);
};
