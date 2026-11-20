const KEY_TABLE = "aston_device_trust_keys";
const CHALLENGE_TABLE = "aston_device_trust_challenges";

function isD1Database(db) {
  return db && typeof db.prepare === "function";
}

/**
 * Cloudflare D1 adapter for createDeviceTrustRegistry().
 * Requires the accompanying migration to be applied by an authorized operator.
 * This module never creates or migrates tables automatically.
 */
export function createD1DeviceTrustStore(db) {
  if (!isD1Database(db)) throw new TypeError("d1_database_required");

  return Object.freeze({
    async createKeyIfAbsent(record) {
      const result = await db.prepare(
        `INSERT OR IGNORE INTO ${KEY_TABLE}
        (tenant_id, issuer_id, key_id, device_id, public_key_json, status,
         revoked, device_status, not_before, not_after, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        record.tenantId, record.issuerId, record.keyId, record.deviceId,
        JSON.stringify(record.publicKey), record.status, record.revoked ? 1 : 0,
        record.deviceStatus, record.notBefore, record.notAfter, record.createdAt
      ).run();
      return result?.success === true && result?.meta?.changes === 1;
    },

    async getKey({ tenantId, issuerId, keyId }) {
      const row = await db.prepare(
        `SELECT tenant_id, issuer_id, key_id, device_id, public_key_json,
         status, revoked, device_status, not_before, not_after, created_at,
         revoked_at, revocation_reason
         FROM ${KEY_TABLE}
         WHERE tenant_id = ? AND issuer_id = ? AND key_id = ?
         LIMIT 1`
      ).bind(tenantId, issuerId, keyId).first();
      if (!row) return null;
      let publicKey;
      try { publicKey = JSON.parse(row.public_key_json); }
      catch { throw new Error("stored_public_key_corrupt"); }
      return {
        tenantId: row.tenant_id,
        issuerId: row.issuer_id,
        keyId: row.key_id,
        deviceId: row.device_id,
        publicKey,
        status: row.status,
        revoked: row.revoked === 1 || row.revoked === true,
        deviceStatus: row.device_status,
        notBefore: row.not_before,
        notAfter: row.not_after,
        createdAt: row.created_at,
        ...(row.revoked_at ? { revokedAt: row.revoked_at } : {}),
        ...(row.revocation_reason ? { revocationReason: row.revocation_reason } : {})
      };
    },

    async revokeKey({ tenantId, issuerId, keyId, revokedAt, reason }) {
      const result = await db.prepare(
        `UPDATE ${KEY_TABLE}
         SET status = 'revoked', revoked = 1, revoked_at = ?, revocation_reason = ?
         WHERE tenant_id = ? AND issuer_id = ? AND key_id = ? AND status = 'active'`
      ).bind(revokedAt, reason, tenantId, issuerId, keyId).run();
      return result?.success === true && result?.meta?.changes === 1;
    },

    async consumeChallengeIfAbsent(record) {
      const result = await db.prepare(
        `INSERT OR IGNORE INTO ${CHALLENGE_TABLE}
         (tenant_id, device_id, challenge_id, attestation_id, consumed_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      ).bind(
        record.tenantId, record.deviceId, record.challengeId,
        record.attestationId, record.consumedAt, record.expiresAt
      ).run();
      return result?.success === true && result?.meta?.changes === 1;
    }
  });
}

export const DEVICE_TRUST_D1_TABLES = Object.freeze({
  keys: KEY_TABLE,
  challenges: CHALLENGE_TABLE
});
