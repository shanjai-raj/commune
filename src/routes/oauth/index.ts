/**
 * Commune OAuth Provider Routes — "Continue with Commune"
 *
 * Commune acts as the identity provider (like Google for "Sign in with Google").
 * Agents authenticate using their Commune email inbox via OTP (magic-link style).
 *
 * Integrator API surface:
 *   POST /oauth/clients              Register your app with Commune (dashboard auth)
 *   GET  /oauth/clients              List your registered OAuth clients
 *   DELETE /oauth/clients/:clientId  Revoke a client registration
 *
 *   POST /oauth/send-code            Send OTP to agent's Commune inbox
 *   POST /oauth/verify-code          Verify OTP, receive access_token + id_token + refresh_token
 *   POST /oauth/token                Refresh access token (grant_type=refresh_token)
 *   GET  /oauth/agentinfo            Fetch agent claims with an existing access token
 *   POST /oauth/revoke               Revoke an access or refresh token
 *
 * Auth for integrator-facing endpoints (send-code, verify-code, token, revoke):
 *   Authorization: Basic base64(clientId:clientSecret)
 *
 * Auth for agentinfo:
 *   Authorization: Bearer <access_token>
 */

import { Router, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { OAuthClientStore } from '../../stores/oauthClientStore';
import { OAuthService } from '../../services/oauthService';
import { combinedAuth } from '../../middleware/combinedAuth';
import { jwtAuth } from '../../middleware/jwtAuth';
import logger from '../../utils/logger';

const router = Router();

// ─── Rate limiters ────────────────────────────────────────────────────────────

// Integrator registration: 10 per IP per hour
const registerClientLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'rate_limited', message: 'Too many client registrations. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Send-code: 20 requests per IP per 15 minutes (integrator-level; per-email rate is in OAuthCodeStore)
const sendCodeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'rate_limited', message: 'Too many send-code requests from this IP.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Verify-code: 10 attempts per IP per 15 minutes (prevent brute-force)
const verifyCodeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'rate_limited', message: 'Too many verification attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── Auth helpers ─────────────────────────────────────────────────────────────

/**
 * Parse and validate HTTP Basic Auth credentials.
 * Returns { clientId, clientSecret } or null if header is missing/malformed.
 */
function parseBasicAuth(authHeader: string | undefined): { clientId: string; clientSecret: string } | null {
  if (!authHeader || !authHeader.startsWith('Basic ')) return null;
  try {
    const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
    const colonIdx = decoded.indexOf(':');
    if (colonIdx === -1) return null;
    const clientId = decoded.slice(0, colonIdx);
    const clientSecret = decoded.slice(colonIdx + 1);
    if (!clientId || !clientSecret) return null;
    return { clientId, clientSecret };
  } catch {
    return null;
  }
}

/**
 * Middleware: validate Basic Auth credentials and attach client to req.
 */
async function requireClientAuth(req: any, res: Response, next: () => void): Promise<void> {
  const creds = parseBasicAuth(req.headers.authorization);
  if (!creds) {
    res.status(401).json({
      error: 'unauthorized',
      message: 'Missing or invalid Authorization header. Use: Authorization: Basic base64(clientId:clientSecret)',
    });
    return;
  }

  const client = await OAuthClientStore.validateCredentials(creds.clientId, creds.clientSecret);
  if (!client) {
    res.status(401).json({
      error: 'invalid_client',
      message: 'Invalid client credentials',
    });
    return;
  }

  req.oauthClient = client;
  next();
}

// ─── Integrator Registration ─────────────────────────────────────────────────

/**
 * POST /oauth/clients
 *
 * Register a new OAuth application with Commune.
 * Requires the integrator to be logged into Commune (dashboard JWT auth).
 *
 * Body:
 *   name        string  — Your application name (required)
 *   description string  — What your app does (optional)
 *   websiteUrl  string  — Your app's website (optional)
 *   logoUrl     string  — URL to your app logo (optional)
 *
 * Returns:
 *   client_id     — Public identifier (share with agents)
 *   client_secret — Secret key (store securely, shown ONCE, never retrievable)
 *   ...client metadata
 */
router.post('/clients', combinedAuth, registerClientLimiter, async (req: any, res: Response) => {
  const { name, description, websiteUrl, logoUrl } = req.body;

  if (!name || typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 100) {
    return res.status(400).json({
      error: 'invalid_name',
      message: 'name is required (2–100 characters)',
    });
  }

  if (websiteUrl && typeof websiteUrl === 'string') {
    try { new URL(websiteUrl); } catch {
      return res.status(400).json({ error: 'invalid_website_url', message: 'websiteUrl must be a valid URL' });
    }
  }

  if (logoUrl && typeof logoUrl === 'string') {
    try { new URL(logoUrl); } catch {
      return res.status(400).json({ error: 'invalid_logo_url', message: 'logoUrl must be a valid URL' });
    }
  }

  // Accept orgId from API key auth (req.orgId) or JWT session (req.user.orgId)
  const orgId = req.orgId || req.user?.orgId;
  if (!orgId) {
    return res.status(401).json({ error: 'unauthorized', message: 'Could not resolve organization from session' });
  }

  try {
    const { client, clientSecret } = await OAuthClientStore.create({
      name: name.trim(),
      description: description?.trim(),
      websiteUrl: websiteUrl?.trim(),
      logoUrl: logoUrl?.trim(),
      orgId,
    });

    return res.status(201).json({
      client_id: client.clientId,
      client_secret: clientSecret,        // Shown ONCE — integrator must store immediately
      name: client.name,
      description: client.description,
      website_url: client.websiteUrl,
      logo_url: client.logoUrl,
      status: client.status,
      verified: client.verified,
      created_at: client.createdAt,
      _instructions: {
        warning: 'Store client_secret immediately — it cannot be retrieved again.',
        auth_format: 'Authorization: Basic base64(client_id + ":" + client_secret)',
        endpoints: {
          send_code: 'POST /oauth/send-code',
          verify_code: 'POST /oauth/verify-code',
          token_refresh: 'POST /oauth/token  (grant_type=refresh_token)',
          agentinfo: 'GET /oauth/agentinfo',
          revoke: 'POST /oauth/revoke',
        },
      },
    });
  } catch (err: any) {
    logger.error('OAuth client registration error', { err });
    return res.status(500).json({ error: 'registration_failed', message: 'Failed to register OAuth client' });
  }
});

/**
 * GET /oauth/clients
 *
 * List all OAuth clients registered by the authenticated integrator's org.
 */
router.get('/clients', combinedAuth, async (req: any, res: Response) => {
  const orgId = req.orgId || req.user?.orgId;
  if (!orgId) {
    return res.status(401).json({ error: 'unauthorized', message: 'Not authenticated' });
  }

  try {
    const clients = await OAuthClientStore.findByOrgId(orgId);
    return res.json({
      data: clients.map(c => ({
        client_id: c.clientId,
        name: c.name,
        description: c.description,
        website_url: c.websiteUrl,
        logo_url: c.logoUrl,
        status: c.status,
        verified: c.verified,
        created_at: c.createdAt,
        updated_at: c.updatedAt,
      })),
    });
  } catch (err: any) {
    logger.error('OAuth list clients error', { err });
    return res.status(500).json({ error: 'server_error', message: 'Failed to list clients' });
  }
});

/**
 * DELETE /oauth/clients/:clientId
 *
 * Revoke an OAuth client registration.
 */
router.delete('/clients/:clientId', combinedAuth, async (req: any, res: Response) => {
  const orgId = req.orgId || req.user?.orgId;
  if (!orgId) {
    return res.status(401).json({ error: 'unauthorized', message: 'Not authenticated' });
  }

  const { clientId } = req.params;
  try {
    const revoked = await OAuthClientStore.revoke(clientId, orgId);
    if (!revoked) {
      return res.status(404).json({ error: 'not_found', message: 'Client not found or already revoked' });
    }
    return res.json({ message: 'Client revoked successfully' });
  } catch (err: any) {
    logger.error('OAuth revoke client error', { err });
    return res.status(500).json({ error: 'server_error', message: 'Failed to revoke client' });
  }
});

// ─── Agent OAuth Flow ─────────────────────────────────────────────────────────

/**
 * POST /oauth/send-code
 *
 * Step 1 of the agent auth flow. Integrator calls this when an agent submits
 * their Commune email on the integrator's product.
 *
 * Auth: Authorization: Basic base64(clientId:clientSecret)
 *
 * Body:
 *   email  string  — The agent's Commune inbox email (e.g. ava@commune.dev)
 *
 * Returns:
 *   request_id   string  — Used in the verify-code step
 *   expires_in   number  — Seconds until the code expires (600 = 10 min)
 *   email_hint   string  — Masked email for display (e.g. "a***@commune.dev")
 *
 * Errors:
 *   agent_not_found   — The email is not a registered Commune agent inbox
 *   rate_limited      — Too many codes sent to this email recently
 */
router.post('/send-code', sendCodeLimiter, requireClientAuth, async (req: any, res: Response) => {
  const { email } = req.body;

  if (!email || typeof email !== 'string') {
    return res.status(400).json({
      error: 'missing_email',
      message: 'email is required',
    });
  }

  // Normalize email
  const normalizedEmail = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
    return res.status(400).json({
      error: 'invalid_email',
      message: 'email must be a valid email address',
    });
  }

  const ipAddress = req.ip || req.headers['x-forwarded-for']?.toString();

  try {
    const result = await OAuthService.sendCode({
      email: normalizedEmail,
      clientId: req.oauthClient.clientId,
      integratorName: req.oauthClient.name,
      originHeader: req.headers.origin,
      refererHeader: req.headers.referer,
      registeredWebsiteUrl: req.oauthClient.websiteUrl,
      ipAddress,
    });

    return res.status(200).json(result);
  } catch (err: any) {
    if (err.code === 'ORIGIN_NOT_ALLOWED') {
      return res.status(403).json({
        error: 'origin_not_allowed',
        message: err.message,
      });
    }
    if (err.code === 'AGENT_NOT_FOUND') {
      // Return 404 but with a message that doesn't confirm non-existence (slight ambiguity by design)
      return res.status(404).json({
        error: 'agent_not_found',
        message: 'No active Commune agent found with this email. Ensure the agent has a Commune inbox.',
      });
    }
    if (err.code === 'RATE_LIMITED') {
      return res.status(429).json({
        error: 'rate_limited',
        message: err.message,
        retry_after: 900, // seconds
      });
    }
    if (err.code === 'EMAIL_SEND_FAILED') {
      return res.status(503).json({
        error: 'email_send_failed',
        message: 'Failed to send verification code. Please try again.',
      });
    }
    logger.error('OAuth send-code error', { err, clientId: req.oauthClient.clientId });
    return res.status(500).json({ error: 'server_error', message: 'Internal server error' });
  }
});

/**
 * POST /oauth/verify-code
 *
 * Step 2 of the agent auth flow. Integrator calls this after the agent reads
 * the OTP from their Commune inbox and submits it.
 *
 * Auth: Authorization: Basic base64(clientId:clientSecret)
 *
 * Body:
 *   request_id  string  — From the send-code response
 *   code        string  — The 6-digit OTP the agent read from their inbox
 *
 * Returns on success:
 *   agent        object  — Full agent identity claims (see below)
 *   access_token string  — Bearer token for subsequent /oauth/userinfo calls
 *   token_type   string  — "Bearer"
 *   expires_in   number  — Token lifetime in seconds (3600 = 1 hour)
 *   scope        string  — "identity"
 *
 * Agent claims include:
 *   sub                   Stable agent ID (never changes)
 *   entity_type           Always "agent"
 *   verified_agent        True — passed Commune's registration challenge
 *   identity.email        Agent's Commune inbox address
 *   identity.name         Agent display name
 *   identity.purpose      Agent's stated purpose
 *   identity.account_age_days
 *   operator.org_name     Company behind the agent
 *   operator.org_tier     Commune plan (free / agent_pro / business / enterprise)
 *   email_reputation      Score, grade, spam_agent flag, send volume
 *   trust.level           new | provisional | established | trusted
 *   trust.score           0–100
 *   trust.signals         Array of evidence markers
 *   moltbook.connected    Whether agent has a Moltbook account linked
 *
 * Errors:
 *   invalid_code   — Wrong code, expired, already used, or mismatched request_id
 *   agent_inactive — Agent account has been suspended
 */
router.post('/verify-code', verifyCodeLimiter, requireClientAuth, async (req: any, res: Response) => {
  const { request_id, code } = req.body;

  if (!request_id || typeof request_id !== 'string') {
    return res.status(400).json({
      error: 'missing_request_id',
      message: 'request_id is required (from the send-code response)',
    });
  }

  if (!code || typeof code !== 'string') {
    return res.status(400).json({
      error: 'missing_code',
      message: 'code is required (the 6-digit OTP from the agent\'s inbox)',
    });
  }

  // Accept both "482931" and " 482931 " (trim whitespace the agent might include)
  const normalizedCode = code.trim();
  if (!/^\d{6}$/.test(normalizedCode)) {
    return res.status(400).json({
      error: 'invalid_code_format',
      message: 'code must be exactly 6 digits',
    });
  }

  try {
    const result = await OAuthService.verifyCode({
      requestId: request_id,
      code: normalizedCode,
      clientId: req.oauthClient.clientId,
      originHeader: req.headers.origin,
      refererHeader: req.headers.referer,
      registeredWebsiteUrl: req.oauthClient.websiteUrl,
    });

    return res.status(200).json(result);
  } catch (err: any) {
    if (err.code === 'ORIGIN_NOT_ALLOWED') {
      return res.status(403).json({
        error: 'origin_not_allowed',
        message: err.message,
      });
    }
    if (err.code === 'INVALID_CODE') {
      return res.status(401).json({
        error: 'invalid_code',
        message: 'The verification code is incorrect, expired, or has already been used.',
      });
    }
    if (err.code === 'AGENT_INACTIVE') {
      return res.status(403).json({
        error: 'agent_inactive',
        message: 'This agent account has been suspended.',
      });
    }
    logger.error('OAuth verify-code error', { err, clientId: req.oauthClient.clientId });
    return res.status(500).json({ error: 'server_error', message: 'Internal server error' });
  }
});

/**
 * POST /oauth/token
 *
 * Token refresh — exchange a refresh_token for a new access_token + id_token.
 * The old refresh_token is rotated (revoked and replaced with a new one).
 *
 * Auth: Authorization: Basic base64(clientId:clientSecret)
 *
 * Body:
 *   grant_type     string  — Must be "refresh_token"
 *   refresh_token  string  — The refresh_token from verify-code or a prior token refresh
 *
 * Returns: same shape as verify-code (access_token, id_token, refresh_token, agent_id, expires_in, scope)
 */
router.post('/token', requireClientAuth, async (req: any, res: Response) => {
  const { grant_type, refresh_token } = req.body;

  if (grant_type !== 'refresh_token') {
    return res.status(400).json({
      error: 'unsupported_grant_type',
      message: 'Only grant_type=refresh_token is supported',
    });
  }

  if (!refresh_token || typeof refresh_token !== 'string') {
    return res.status(400).json({
      error: 'missing_refresh_token',
      message: 'refresh_token is required',
    });
  }

  try {
    const result = await OAuthService.refreshAccessToken({
      refreshToken: refresh_token,
      clientId: req.oauthClient.clientId,
    });
    return res.status(200).json(result);
  } catch (err: any) {
    if (err.code === 'INVALID_REFRESH_TOKEN') {
      return res.status(401).json({
        error: 'invalid_grant',
        message: 'The refresh token is invalid, expired, or has been revoked.',
      });
    }
    if (err.code === 'AGENT_INACTIVE') {
      return res.status(403).json({
        error: 'agent_inactive',
        message: 'This agent account has been suspended.',
      });
    }
    logger.error('OAuth token refresh error', { err, clientId: req.oauthClient.clientId });
    return res.status(500).json({ error: 'server_error', message: 'Internal server error' });
  }
});

/**
 * GET /oauth/agentinfo
 *
 * Fetch fresh agent identity claims using an existing access token.
 * Like Google's /oauth2/v2/userinfo, but for agents.
 *
 * Auth: Authorization: Bearer <access_token>
 *
 * Returns: full agent claims object (same as verify-code, without token fields)
 */
router.get('/agentinfo', async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Authorization: Bearer <access_token> required',
    });
  }

  const token = authHeader.slice(7);
  if (!token) {
    return res.status(401).json({ error: 'unauthorized', message: 'Missing access token' });
  }

  try {
    const claims = await OAuthService.getAgentInfo(token);
    return res.json(claims);
  } catch (err: any) {
    if (err.code === 'INVALID_TOKEN') {
      return res.status(401).json({ error: 'invalid_token', message: 'Access token is invalid or expired' });
    }
    if (err.code === 'AGENT_INACTIVE') {
      return res.status(403).json({ error: 'agent_inactive', message: 'This agent account has been suspended' });
    }
    logger.error('OAuth agentinfo error', { err });
    return res.status(500).json({ error: 'server_error', message: 'Internal server error' });
  }
});

/**
 * POST /oauth/revoke
 *
 * Revoke an access token. Can be called by the integrator (Basic Auth)
 * or by presenting the token itself (Bearer).
 *
 * Body:
 *   token  string  — The access token to revoke
 */
router.post('/revoke', async (req: Request, res: Response) => {
  // Accept both Basic Auth (integrator-initiated) and Bearer (agent-initiated)
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Authorization header required (Basic or Bearer)',
    });
  }

  // Validate client credentials if Basic Auth is provided
  if (authHeader.startsWith('Basic ')) {
    const creds = parseBasicAuth(authHeader);
    if (creds) {
      const client = await OAuthClientStore.validateCredentials(creds.clientId, creds.clientSecret);
      if (!client) {
        return res.status(401).json({ error: 'invalid_client', message: 'Invalid client credentials' });
      }
    }
  }

  const { token } = req.body;
  if (!token || typeof token !== 'string') {
    return res.status(400).json({ error: 'missing_token', message: 'token is required' });
  }

  try {
    await OAuthService.revokeToken(token);
    // Always return 200 even if token didn't exist — per RFC 7009
    return res.status(200).json({ message: 'Token revoked' });
  } catch (err: any) {
    logger.error('OAuth revoke error', { err });
    return res.status(500).json({ error: 'server_error', message: 'Internal server error' });
  }
});

export default router;
