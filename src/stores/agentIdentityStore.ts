import { randomBytes } from 'crypto';
import { getCollection } from '../db';
import { getRedisClient } from '../lib/redis';
import type { AgentIdentity, AgentSignatureNonce } from '../types/auth';

const NONCE_TTL_MS = 2 * 60 * 1000; // 2 minutes — same as original MongoDB TTL

// ─── ARCH-07: Agent identity in-memory cache (5-minute TTL) ─────────────────
const AGENT_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const agentCache = new Map<string, { identity: AgentIdentity; expiresAt: number }>();

export class AgentIdentityStore {
  static async create(data: Omit<AgentIdentity, 'id' | 'createdAt' | 'status' | 'lastUsedAt' | 'revokedAt'>): Promise<AgentIdentity> {
    const collection = await getCollection<AgentIdentity>('agent_identities');
    if (!collection) throw new Error('Database not available');

    const identity: AgentIdentity = {
      id: 'agt_' + randomBytes(16).toString('hex'),
      ...data,
      status: 'active',
      createdAt: new Date().toISOString(),
    };

    await collection.insertOne(identity);
    return identity;
  }

  static async findById(id: string): Promise<AgentIdentity | null> {
    // Check cache first
    const cached = agentCache.get(id);
    if (cached && cached.expiresAt > Date.now()) return cached.identity;

    // DB lookup
    const collection = await getCollection<AgentIdentity>('agent_identities');
    if (!collection) return null;
    const identity = await collection.findOne(
      { id, status: 'active' },
      { projection: { id: 1, publicKey: 1, orgId: 1, status: 1, agentEmail: 1, inboxEmail: 1, agentName: 1, agentPurpose: 1, createdAt: 1, lastUsedAt: 1 } }
    );

    if (identity) {
      agentCache.set(id, { identity, expiresAt: Date.now() + AGENT_CACHE_TTL_MS });
    }
    return identity;
  }

  static invalidateAgentCache(id: string): void {
    agentCache.delete(id);
  }

  static async findByOrgId(orgId: string): Promise<AgentIdentity[]> {
    const collection = await getCollection<AgentIdentity>('agent_identities');
    if (!collection) return [];
    return collection.find({ orgId }).toArray();
  }

  static async updateLastUsed(id: string): Promise<void> {
    const collection = await getCollection<AgentIdentity>('agent_identities');
    if (!collection) return;
    await collection.updateOne({ id }, { $set: { lastUsedAt: new Date().toISOString() } });
  }

  static async revoke(id: string): Promise<boolean> {
    const collection = await getCollection<AgentIdentity>('agent_identities');
    if (!collection) return false;
    const result = await collection.updateOne(
      { id, status: 'active' },
      { $set: { status: 'revoked', revokedAt: new Date().toISOString() } }
    );
    if (result.modifiedCount > 0) {
      AgentIdentityStore.invalidateAgentCache(id);
    }
    return result.modifiedCount > 0;
  }

  // ─── ARCH-06: Redis nonce for replay protection ────────────────────────────
  // Returns false if this (agentId, timestampMs) pair was already used (replay)

  static async claimNonce(agentId: string, timestampMs: number): Promise<boolean> {
    const redis = getRedisClient();

    if (redis) {
      const key = `nonce:${agentId}:${timestampMs}`;
      const result = await redis.set(key, '1', 'PX', NONCE_TTL_MS, 'NX');
      return result === 'OK'; // null means key already existed (replay attack)
    }

    // Fallback to MongoDB when Redis unavailable
    return AgentIdentityStore.claimNonceDb(agentId, timestampMs);
  }

  // MongoDB fallback implementation — used when Redis is unavailable
  static async claimNonceDb(agentId: string, timestampMs: number): Promise<boolean> {
    const collection = await getCollection<AgentSignatureNonce>('agent_signature_nonces');
    if (!collection) throw new Error('Database not available');

    try {
      await collection.insertOne({
        _id: `${agentId}:${timestampMs}` as any,
        expiresAt: new Date(Date.now() + NONCE_TTL_MS),
      });
      return true; // nonce is fresh, proceed
    } catch (err: any) {
      if (err.code === 11000) return false; // duplicate key = replay
      throw err;
    }
  }

  // Call once on startup to ensure indexes exist
  static async ensureIndexes(): Promise<void> {
    const identityCol = await getCollection<AgentIdentity>('agent_identities');
    const nonceCol = await getCollection<AgentSignatureNonce>('agent_signature_nonces');

    if (identityCol) {
      await identityCol.createIndex({ id: 1 }, { unique: true });
      await identityCol.createIndex({ orgId: 1 });
      await identityCol.createIndex({ id: 1, status: 1 });
    }

    if (nonceCol) {
      await nonceCol.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    }
  }
}
