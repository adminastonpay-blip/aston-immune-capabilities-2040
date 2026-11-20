const ID = /^[A-Za-z0-9._:-]{1,128}$/;

function validId(value) { return typeof value === "string" && ID.test(value); }
function validTime(value) { return typeof value === "string" && Number.isFinite(Date.parse(value)); }

/**
 * Creates a host-side facade over a durable, tenant-scoped device/key store.
 *
 * Required store contract:
 * - createKeyIfAbsent(record): atomic insert; returns true only on first insert.
 * - getKey({tenantId, issuerId, keyId}): exact tenant-scoped lookup.
 * - revokeKey({tenantId, issuerId, keyId, revokedAt, reason}): atomic status update.
 * - consumeChallengeIfAbsent(record): atomic unique insert keyed by tenant/device/challenge.
 *
 * authorize is privileged host code. It must derive the actor and tenant from
 * authenticated host context, never from device/request/queue payloads.
 */
export function createDeviceTrustRegistry({ store, authorize, now = () => Date.now() } = {}) {
  const unavailable = () => ({ ok: false, decision: "review", reason: "trusted_store_unavailable", executable: false });
  if (!store || typeof store.createKeyIfAbsent !== "function" ||
      typeof store.getKey !== "function" || typeof store.revokeKey !== "function" ||
      typeof store.consumeChallengeIfAbsent !== "function" ||
      typeof authorize !== "function" || typeof now !== "function") {
    return Object.freeze({
      enrollDeviceKey: async () => unavailable(),
      resolveTrustedKey: async () => null,
      revokeDeviceKey: async () => unavailable(),
      consumeChallenge: async () => unavailable()
    });
  }

  async function permitted(action, context) {
    try { return await authorize(action, context) === true; }
    catch { return false; }
  }

  return Object.freeze({
    async enrollDeviceKey(input, authContext) {
      if (!input || !validId(input.tenantId) || !validId(input.issuerId) ||
          !validId(input.keyId) || !validId(input.deviceId) ||
          !input.publicKey || !validTime(input.notBefore) || !validTime(input.notAfter) ||
          Date.parse(input.notAfter) <= Date.parse(input.notBefore)) {
        return { ok: false, decision: "deny", reason: "invalid_key_record", executable: false };
      }
      const scope = { tenantId: input.tenantId, deviceId: input.deviceId, issuerId: input.issuerId, keyId: input.keyId };
      if (!await permitted("device_key:enroll", { ...scope, authContext })) {
        return { ok: false, decision: "deny", reason: "enrollment_not_authorized", executable: false };
      }
      const record = {
        tenantId: input.tenantId, issuerId: input.issuerId, keyId: input.keyId,
        deviceId: input.deviceId, publicKey: input.publicKey,
        status: "active", revoked: false, deviceStatus: "active",
        notBefore: input.notBefore, notAfter: input.notAfter,
        createdAt: new Date(now()).toISOString()
      };
      try {
        const inserted = await store.createKeyIfAbsent(record);
        return inserted
          ? { ok: true, decision: "registered", reason: "device_key_registered", record: { ...record, publicKey: undefined }, executable: false }
          : { ok: false, decision: "deny", reason: "key_id_already_exists", executable: false };
      } catch { return unavailable(); }
    },

    async resolveTrustedKey({ tenantId, issuerId, keyId }) {
      if (!validId(tenantId) || !validId(issuerId) || !validId(keyId)) return null;
      try {
        const record = await store.getKey({ tenantId, issuerId, keyId });
        if (!record || record.tenantId !== tenantId || record.issuerId !== issuerId || record.keyId !== keyId) return null;
        return record;
      } catch { return null; }
    },

    async revokeDeviceKey(input, authContext) {
      if (!input || !validId(input.tenantId) || !validId(input.issuerId) ||
          !validId(input.keyId) || typeof input.reason !== "string" ||
          input.reason.length < 1 || input.reason.length > 256) {
        return { ok: false, decision: "deny", reason: "invalid_revocation_request", executable: false };
      }
      const scope = { tenantId: input.tenantId, issuerId: input.issuerId, keyId: input.keyId };
      if (!await permitted("device_key:revoke", { ...scope, authContext })) {
        return { ok: false, decision: "deny", reason: "revocation_not_authorized", executable: false };
      }
      try {
        const revoked = await store.revokeKey({ ...scope, revokedAt: new Date(now()).toISOString(), reason: input.reason });
        return revoked
          ? { ok: true, decision: "revoked", reason: "device_key_revoked", executable: false }
          : { ok: false, decision: "deny", reason: "trusted_key_not_found", executable: false };
      } catch { return unavailable(); }
    },

    async consumeChallenge(input, authContext) {
      if (!input || !validId(input.tenantId) || !validId(input.deviceId) ||
          !validId(input.challengeId) || !validId(input.attestationId) ||
          !validTime(input.expiresAt) || Date.parse(input.expiresAt) <= now()) {
        return { ok: false, decision: "deny", reason: "invalid_challenge_record", executable: false };
      }
      const scope = { tenantId: input.tenantId, deviceId: input.deviceId, challengeId: input.challengeId };
      if (!await permitted("device_challenge:consume", { ...scope, authContext })) {
        return { ok: false, decision: "deny", reason: "challenge_consumption_not_authorized", executable: false };
      }
      const record = { ...scope, attestationId: input.attestationId, consumedAt: new Date(now()).toISOString(), expiresAt: input.expiresAt };
      try {
        const consumed = await store.consumeChallengeIfAbsent(record);
        return consumed
          ? { ok: true, decision: "consumed", reason: "challenge_consumed_once", executable: false }
          : { ok: false, decision: "deny", reason: "challenge_replay_detected", executable: false };
      } catch { return unavailable(); }
    }
  });
}
