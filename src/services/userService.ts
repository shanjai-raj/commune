import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import type { User, EmailVerificationToken } from '../types';
import { getCollection } from '../db';
import logger from '../utils/logger';

const JWT_SECRET = process.env.JWT_SECRET || '';

type LoginError = { error: 'invalid_credentials' | 'email_not_verified' | 'account_inactive' | 'no_password'; email?: string };
const TOKEN_EXPIRY = '7d';

const getJwtSecret = (): string => {
  if (!JWT_SECRET) {
    throw new Error('JWT_SECRET is not configured');
  }
  return JWT_SECRET;
};

const sendEmail = async (payload: {
  to: string;
  subject: string;
  html: string;
  text: string;
}) => {
  const resend = await import('./resendClient');
  const { data, error } = await resend.default.emails.send({
    from: process.env.DEFAULT_FROM_EMAIL || 'noreply@commune.email',
    to: payload.to,
    subject: payload.subject,
    html: payload.html,
    text: payload.text,
  });

  if (error) {
    logger.error('Failed to send email:', { error });
    throw error;
  }

  return data;
};

export class UserService {
  /**
   * Creates a user record for an agent (no password, no email verification email).
   * Verification is handled via the agent OTP flow, not the standard email link.
   */
  static async registerAgentUser(data: {
    orgId: string;
    email: string;
    name: string;
  }): Promise<{ user: User }> {
    const collection = await getCollection<User>('users');
    if (!collection) throw new Error('Database not available');

    const existingUser = await collection.findOne({ email: data.email });
    if (existingUser) throw new Error('User already exists');

    const user: User = {
      id: randomBytes(16).toString('hex'),
      orgId: data.orgId,
      email: data.email,
      name: data.name,
      role: 'admin',
      status: 'pending',
      emailVerified: false,
      passwordHash: '',       // agents authenticate via Ed25519 signature, not password
      provider: 'email',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    await collection.insertOne(user);
    return { user };
  }

  static async registerUser(data: {
    orgId: string;
    email: string;
    name: string;
    password: string;
    role?: User['role'];
  }): Promise<{ user: User; requiresVerification: boolean }> {
    const collection = await getCollection<User>('users');
    if (!collection) throw new Error('Database not available');

    const existingUser = await collection.findOne({ email: data.email });
    if (existingUser) {
      throw new Error('User already exists');
    }

    const passwordHash = await bcrypt.hash(data.password, 12);

    const user: User = {
      id: randomBytes(16).toString('hex'),
      orgId: data.orgId,
      email: data.email,
      name: data.name,
      role: data.role || 'member',
      status: 'pending',
      emailVerified: false,
      passwordHash,
      provider: 'email',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    await collection.insertOne(user);

    const verificationToken = await this.createEmailVerificationToken(user.id, user.email, 'verification');
    await this.sendVerificationEmail(user.email, verificationToken.token);

    return { user, requiresVerification: true };
  }

  static async verifyEmail(token: string): Promise<{ success: boolean; user?: User }> {
    const tokenCollection = await getCollection<EmailVerificationToken>('email_verification_tokens');
    const userCollection = await getCollection<User>('users');

    if (!tokenCollection || !userCollection) {
      throw new Error('Database not available');
    }

    const verificationToken = await tokenCollection.findOne({
      token,
      purpose: 'verification',
      expiresAt: { $gt: new Date().toISOString() },
      usedAt: { $exists: false }
    });

    if (!verificationToken) {
      return { success: false };
    }

    const result = await userCollection.findOneAndUpdate(
      { id: verificationToken.userId },
      {
        $set: {
          emailVerified: true,
          status: 'active',
          updatedAt: new Date().toISOString()
        },
        $unset: {
          emailVerificationToken: '',
          emailVerificationExpires: ''
        }
      },
      { returnDocument: 'after' }
    );

    await tokenCollection.updateOne(
      { id: verificationToken.id },
      { $set: { usedAt: new Date().toISOString() } }
    );

    return { success: true, user: result || undefined };
  }

  static async loginUser(email: string, password: string): Promise<{ user: User; token: string } | LoginError> {
    const collection = await getCollection<User>('users');
    if (!collection) return { error: 'invalid_credentials' };

    const user = await collection.findOne({ email });

    if (!user) {
      return { error: 'invalid_credentials' };
    }

    // Google-only account trying to use password login
    if (user.provider === 'google' && !user.passwordHash) {
      return { error: 'no_password', email: user.email };
    }

    if (user.status === 'inactive' || user.status === 'pending') {
      if (!user.emailVerified) {
        return { error: 'email_not_verified', email: user.email };
      }
      return { error: 'account_inactive' };
    }

    if (!user.emailVerified) {
      return { error: 'email_not_verified', email: user.email };
    }

    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      return { error: 'invalid_credentials' };
    }

    await collection.updateOne(
      { id: user.id },
      { $set: { lastLoginAt: new Date().toISOString() } }
    );

    const token = jwt.sign(
      { userId: user.id, orgId: user.orgId, role: user.role },
      getJwtSecret(),
      { expiresIn: TOKEN_EXPIRY }
    );

    return { user, token };
  }

  static async createEmailVerificationToken(
    userId: string,
    email: string,
    purpose: 'verification' | 'password_reset' | 'login'
  ): Promise<EmailVerificationToken> {
    const collection = await getCollection<EmailVerificationToken>('email_verification_tokens');
    if (!collection) throw new Error('Database not available');

    const token = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    const verificationToken: EmailVerificationToken = {
      id: randomBytes(16).toString('hex'),
      userId,
      token,
      email,
      purpose,
      expiresAt: expiresAt.toISOString(),
      createdAt: new Date().toISOString()
    };

    await collection.insertOne(verificationToken);
    return verificationToken;
  }

  static async sendVerificationEmail(email: string, token: string): Promise<void> {
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const verificationUrl = `${frontendUrl}/auth/verify?token=${token}`;

    await sendEmail({
      to: email,
      subject: 'Verify your Commune account',
      html: this.getVerificationEmailTemplate(verificationUrl),
      text: `Please verify your email by visiting: ${verificationUrl}`
    });
  }

  static getVerificationEmailTemplate(verificationUrl: string): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Verify your Commune account</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { text-align: center; margin-bottom: 30px; }
          .logo { font-size: 24px; font-weight: bold; color: #2563eb; }
          .button { display: inline-block; background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 30px; font-size: 14px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">Commune</div>
            <h1>Verify your account</h1>
          </div>
          <p>Thank you for signing up for Commune! Please click the button below to verify your email address and activate your account.</p>
          <div style="text-align: center;">
            <a href="${verificationUrl}" class="button">Verify Email</a>
          </div>
          <p>If the button doesn't work, you can also copy and paste this link into your browser:</p>
          <p style="word-break: break-all; background: #f5f5f5; padding: 10px; border-radius: 4px;">${verificationUrl}</p>
          <p>This link will expire in 24 hours.</p>
          <div class="footer">
            <p>If you didn't create this account, you can safely ignore this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  static async getUserById(id: string): Promise<User | null> {
    const collection = await getCollection<User>('users');
    if (!collection) return null;
    return collection.findOne({ id });
  }

  static async getUserByEmail(email: string): Promise<User | null> {
    const collection = await getCollection<User>('users');
    if (!collection) return null;
    return collection.findOne({ email });
  }

  /**
   * Find or create a user from Google OAuth profile.
   * If an email-based account exists, link the Google account to it.
   */
  static async findOrCreateGoogleUser(profile: {
    googleId: string;
    email: string;
    name: string;
    avatarUrl?: string;
    emailVerified: boolean;
  }, orgId?: string): Promise<{ user: User; token: string; isNewUser: boolean }> {
    const collection = await getCollection<User>('users');
    if (!collection) throw new Error('Database not available');

    // Check if user already exists by email
    let user = await collection.findOne({ email: profile.email });
    let isNewUser = false;

    if (user) {
      // Link Google account to existing user if not already linked
      const updates: Record<string, any> = {
        googleId: profile.googleId,
        lastLoginAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      if (profile.avatarUrl) {
        updates.avatarUrl = profile.avatarUrl;
      }

      // If user was pending and Google says email is verified, activate them
      if (!user.emailVerified && profile.emailVerified) {
        updates.emailVerified = true;
        updates.status = 'active';
      }

      await collection.updateOne({ id: user.id }, { $set: updates });
      user = await collection.findOne({ id: user.id });
    } else {
      // Create new user + org
      isNewUser = true;
      const { OrganizationService } = await import('./organizationService');
      const { randomBytes: rb } = await import('crypto');

      let newOrgId = orgId;
      if (!newOrgId) {
        const org = await OrganizationService.createOrganization({
          name: `${profile.name}'s Organization`,
          slug: `org-${rb(4).toString('hex')}`
        });
        newOrgId = org.id;
      }

      const newUser: User = {
        id: randomBytes(16).toString('hex'),
        orgId: newOrgId!,
        email: profile.email,
        name: profile.name,
        role: 'admin',
        status: 'active',
        emailVerified: profile.emailVerified,
        passwordHash: '',
        provider: 'google',
        googleId: profile.googleId,
        avatarUrl: profile.avatarUrl,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      await collection.insertOne(newUser as any);
      user = await collection.findOne({ id: newUser.id });
    }

    const token = jwt.sign(
      { userId: user!.id, orgId: user!.orgId, role: user!.role },
      getJwtSecret(),
      { expiresIn: TOKEN_EXPIRY }
    );

    return { user: user!, token, isNewUser };
  }

  /**
   * Resend verification email for a user who hasn't verified yet.
   */
  static async resendVerificationEmail(email: string): Promise<void> {
    const user = await this.getUserByEmail(email);
    if (!user) {
      // Don't reveal if email exists
      return;
    }

    if (user.emailVerified) {
      return;
    }

    const token = await this.createEmailVerificationToken(user.id, email, 'verification');
    await this.sendVerificationEmail(email, token.token);
  }

  static async getUsersByOrg(orgId: string): Promise<User[]> {
    const collection = await getCollection<User>('users');
    if (!collection) return [];
    return collection.find({ orgId }).sort({ createdAt: -1 }).toArray();
  }

  static async updateUser(id: string, updates: Partial<User>): Promise<User | null> {
    const collection = await getCollection<User>('users');
    if (!collection) return null;

    const result = await collection.findOneAndUpdate(
      { id },
      { $set: { ...updates, updatedAt: new Date().toISOString() } },
      { returnDocument: 'after' }
    );

    return result;
  }

  static async changePassword(userId: string, newPasswordHash: string): Promise<boolean> {
    const collection = await getCollection<User>('users');
    if (!collection) return false;

    const result = await collection.updateOne(
      { id: userId },
      { $set: { passwordHash: newPasswordHash, updatedAt: new Date().toISOString() } }
    );

    return result.modifiedCount > 0;
  }

  static async createPasswordResetToken(email: string): Promise<void> {
    const user = await this.getUserByEmail(email);
    if (!user) {
      // Don't reveal if email exists
      return;
    }

    const token = await this.createEmailVerificationToken(user.id, email, 'password_reset');
    await this.sendPasswordResetEmail(email, token.token);
  }

  static async resetPasswordWithToken(token: string, newPassword: string): Promise<boolean> {
    const collection = await getCollection<EmailVerificationToken>('email_verification_tokens');
    if (!collection) return false;

    const tokenDoc = await collection.findOne({
      token,
      purpose: 'password_reset',
      expiresAt: { $gt: new Date().toISOString() },
      used: { $ne: true }
    });

    if (!tokenDoc) return false;

    const passwordHash = await bcrypt.hash(newPassword, 12);
    const updated = await this.changePassword(tokenDoc.userId, passwordHash);

    if (updated) {
      await collection.updateOne({ id: tokenDoc.id }, { $set: { used: true } });
    }

    return updated;
  }

  static async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const resetUrl = `${frontendUrl}/auth/reset-password?token=${token}`;

    await sendEmail({
      to: email,
      subject: 'Reset your Commune password',
      html: this.getPasswordResetEmailTemplate(resetUrl),
      text: `Reset your password by visiting: ${resetUrl}`
    });
  }

  static getPasswordResetEmailTemplate(resetUrl: string): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Reset your Commune password</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { text-align: center; margin-bottom: 30px; }
          .logo { font-size: 24px; font-weight: bold; color: #2563eb; }
          .button { display: inline-block; background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 30px; font-size: 14px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">Commune</div>
            <h1>Reset your password</h1>
          </div>
          <p>We received a request to reset your password for your Commune account. Click the button below to set a new password.</p>
          <div style="text-align: center;">
            <a href="${resetUrl}" class="button">Reset Password</a>
          </div>
          <p>If the button doesn't work, you can also copy and paste this link into your browser:</p>
          <p style="word-break: break-all; background: #f5f5f5; padding: 10px; border-radius: 4px;">${resetUrl}</p>
          <p>This link will expire in 24 hours.</p>
          <div class="footer">
            <p>If you didn't request this reset, you can safely ignore this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }
}
