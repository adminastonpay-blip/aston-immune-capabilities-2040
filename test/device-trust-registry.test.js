import test from "node:test";
import assert from "node:assert/strict";
import { createDeviceTrustRegistry } from "../src/device-trust-registry.js";

function fixture({ allow = true, failStore = false } = {}) {
  const keys = new Map();
  const challenges = new Map();
  const keyId = (x) => [x.tenantId, x.issuerId, x.keyId].join("|");
  const challengeId = (x) => [x.tenantId, x.deviceId, x.challengeId].join("|");
  const store = {
    async createKeyIfAbsent(record) {
      if (failStore) throw new Error("store offline");
      const id = keyId(record);
      if (keys.has(id)) return false;
      keys.set(id, structuredClone(record));
      return true;
    },
    async getKey(scope) {
      if (failStore) throw new Error("store offline");
      const value = keys.get(keyId(scope));
      return value ? structuredClone(value) : null;
    },
    async revokeKey(input) {
      if (failStore) throw new Error("store offline");
      const record = keys.get(keyId(input));
      if (!record) return false;
      keys.set(keyId(input), { ...record, status: "revoked", revoked: true, revokedAt: input.revokedAt, revocationReason: input.reason });
      return true;
    },
    async consumeChallengeIfAbsent(record) {
      if (failStore) throw new Error("store offline");
      const id = challengeId(record);
      if (challenges.has(id)) return false;
      challenges.set(id, structuredClone(record));
      return true;
    }
  };
  const registry = createDeviceTrustRegistry({
    store,
    authorize: async () => allow,
    now: () => Date.parse("2026-11-20T12:00:00.000Z")
  });
  return { registry, keys, challenges };
}

const key = {
  tenantId: "tenant-a", issuerId: "factory-1", keyId: "key-1",
  deviceId: "device-1", publicKey: { kty: "OKP", crv: "Ed25519", x: "public" },
  notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2027-01-01T00:00:00.000Z"
};

test("registers a tenant-scoped device key and resolves exact binding", async () => {
  const { registry } = fixture();
  const enrolled = await registry.enrollDeviceKey(key, { actor: "admin" });
  assert.equal(enrolled.decision, "registered");
  assert.equal((await registry.resolveTrustedKey({ tenantId: "tenant-a", issuerId: "factory-1", keyId: "key-1" })).deviceId, "device-1");
  assert.equal(await registry.resolveTrustedKey({ tenantId: "tenant-b", issuerId: "factory-1", keyId: "key-1" }), null);
});

test("rejects duplicate key IDs without overwriting the original key", async () => {
  const { registry } = fixture();
  assert.equal((await registry.enrollDeviceKey(key, {})).ok, true);
  const duplicate = await registry.enrollDeviceKey({ ...key, deviceId: "attacker-device" }, {});
  assert.equal(duplicate.reason, "key_id_already_exists");
  assert.equal((await registry.resolveTrustedKey({ tenantId: "tenant-a", issuerId: "factory-1", keyId: "key-1" })).deviceId, "device-1");
});

test("requires host authorization for enrollment and revocation", async () => {
  const { registry } = fixture({ allow: false });
  assert.equal((await registry.enrollDeviceKey(key, {})).reason, "enrollment_not_authorized");
  assert.equal((await registry.revokeDeviceKey({ tenantId: "tenant-a", issuerId: "factory-1", keyId: "key-1", reason: "compromised" }, {})).reason, "revocation_not_authorized");
});

test("revokes a key and makes the stored record inactive", async () => {
  const { registry } = fixture();
  await registry.enrollDeviceKey(key, {});
  const result = await registry.revokeDeviceKey({ tenantId: "tenant-a", issuerId: "factory-1", keyId: "key-1", reason: "key compromise" }, {});
  assert.equal(result.decision, "revoked");
  const record = await registry.resolveTrustedKey({ tenantId: "tenant-a", issuerId: "factory-1", keyId: "key-1" });
  assert.equal(record.status, "revoked");
  assert.equal(record.revoked, true);
});

test("consumes a challenge once and rejects a replay", async () => {
  const { registry } = fixture();
  const challenge = { tenantId: "tenant-a", deviceId: "device-1", challengeId: "challenge-1", attestationId: "att-1", expiresAt: "2026-11-20T12:02:00.000Z" };
  assert.equal((await registry.consumeChallenge(challenge, {})).decision, "consumed");
  assert.equal((await registry.consumeChallenge({ ...challenge, attestationId: "att-2" }, {})).reason, "challenge_replay_detected");
});

test("isolates replay keys across tenants and devices", async () => {
  const { registry } = fixture();
  const base = { tenantId: "tenant-a", deviceId: "device-1", challengeId: "challenge-1", attestationId: "att-1", expiresAt: "2026-11-20T12:02:00.000Z" };
  assert.equal((await registry.consumeChallenge(base, {})).ok, true);
  assert.equal((await registry.consumeChallenge({ ...base, tenantId: "tenant-b" }, {})).ok, true);
  assert.equal((await registry.consumeChallenge({ ...base, deviceId: "device-2" }, {})).ok, true);
});

test("fails closed for malformed and expired challenge records", async () => {
  const { registry } = fixture();
  const base = { tenantId: "tenant-a", deviceId: "device-1", challengeId: "challenge-1", attestationId: "att-1", expiresAt: "2026-11-20T11:59:00.000Z" };
  assert.equal((await registry.consumeChallenge(base, {})).reason, "invalid_challenge_record");
  assert.equal((await registry.enrollDeviceKey({ ...key, notAfter: key.notBefore }, {})).reason, "invalid_key_record");
});

test("store failures return review and never claim successful persistence", async () => {
  const { registry } = fixture({ failStore: true });
  assert.equal((await registry.enrollDeviceKey(key, {})).decision, "review");
  assert.equal((await registry.consumeChallenge({ tenantId: "tenant-a", deviceId: "device-1", challengeId: "challenge-1", attestationId: "att-1", expiresAt: "2026-11-20T12:02:00.000Z" }, {})).decision, "review");
});

test("missing store or authorization dependencies produce an inert fail-safe facade", async () => {
  const registry = createDeviceTrustRegistry({});
  assert.equal((await registry.enrollDeviceKey(key, {})).reason, "trusted_store_unavailable");
  assert.equal(await registry.resolveTrustedKey({ tenantId: "tenant-a", issuerId: "factory-1", keyId: "key-1" }), null);
});
