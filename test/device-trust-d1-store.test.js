import test from "node:test";
import assert from "node:assert/strict";
import { createD1DeviceTrustStore, DEVICE_TRUST_D1_TABLES } from "../src/device-trust-d1-store.js";

function fakeD1() {
  const keys = new Map();
  const challenges = new Map();
  const keyId = (tenant, issuer, key) => [tenant, issuer, key].join("|");
  const challengeId = (tenant, device, challenge) => [tenant, device, challenge].join("|");
  const db = {
    prepare(sql) {
      return {
        values: [],
        bind(...values) { this.values = values; return this; },
        async run() {
          const v = this.values;
          if (sql.includes("INSERT OR IGNORE INTO aston_device_trust_keys")) {
            const id = keyId(v[0], v[1], v[2]);
            if (keys.has(id)) return { success: true, meta: { changes: 0 } };
            keys.set(id, {
              tenant_id: v[0], issuer_id: v[1], key_id: v[2], device_id: v[3],
              public_key_json: v[4], status: v[5], revoked: v[6], device_status: v[7],
              not_before: v[8], not_after: v[9], created_at: v[10],
              revoked_at: null, revocation_reason: null
            });
            return { success: true, meta: { changes: 1 } };
          }
          if (sql.includes("UPDATE aston_device_trust_keys")) {
            const row = keys.get(keyId(v[2], v[3], v[4]));
            if (!row || row.status !== "active") return { success: true, meta: { changes: 0 } };
            Object.assign(row, { status: "revoked", revoked: 1, revoked_at: v[0], revocation_reason: v[1] });
            return { success: true, meta: { changes: 1 } };
          }
          if (sql.includes("INSERT OR IGNORE INTO aston_device_trust_challenges")) {
            const id = challengeId(v[0], v[1], v[2]);
            if (challenges.has(id)) return { success: true, meta: { changes: 0 } };
            challenges.set(id, { tenant_id: v[0], device_id: v[1], challenge_id: v[2], attestation_id: v[3], consumed_at: v[4], expires_at: v[5] });
            return { success: true, meta: { changes: 1 } };
          }
          throw new Error("unexpected_sql");
        },
        async first() {
          if (!sql.includes("FROM aston_device_trust_keys")) throw new Error("unexpected_sql");
          const row = keys.get(keyId(...this.values));
          return row ? structuredClone(row) : null;
        }
      };
    }
  };
  return { db, keys, challenges };
}

const key = {
  tenantId: "tenant-1", issuerId: "issuer-1", keyId: "key-1",
  deviceId: "device-1", publicKey: { kty: "OKP", crv: "Ed25519", x: "abc" },
  status: "active", revoked: false, deviceStatus: "active",
  notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2027-01-01T00:00:00.000Z",
  createdAt: "2026-11-20T12:00:00.000Z"
};

test("requires a D1-compatible database binding", () => {
  assert.throws(() => createD1DeviceTrustStore(null), /d1_database_required/);
});

test("exports fixed table names for the migration contract", () => {
  assert.equal(DEVICE_TRUST_D1_TABLES.keys, "aston_device_trust_keys");
  assert.equal(DEVICE_TRUST_D1_TABLES.challenges, "aston_device_trust_challenges");
});

test("inserts a key once and preserves public key JSON on exact lookup", async () => {
  const { db } = fakeD1();
  const store = createD1DeviceTrustStore(db);
  assert.equal(await store.createKeyIfAbsent(key), true);
  assert.equal(await store.createKeyIfAbsent(key), false);
  const found = await store.getKey({ tenantId: key.tenantId, issuerId: key.issuerId, keyId: key.keyId });
  assert.deepEqual(found.publicKey, key.publicKey);
  assert.equal(found.deviceId, key.deviceId);
});

test("tenant-scoped lookup cannot return another tenant's key", async () => {
  const { db } = fakeD1();
  const store = createD1DeviceTrustStore(db);
  await store.createKeyIfAbsent(key);
  assert.equal(await store.getKey({ tenantId: "tenant-other", issuerId: key.issuerId, keyId: key.keyId }), null);
});

test("revocation changes active key state and cannot be repeated as a new transition", async () => {
  const { db } = fakeD1();
  const store = createD1DeviceTrustStore(db);
  await store.createKeyIfAbsent(key);
  const scope = { tenantId: key.tenantId, issuerId: key.issuerId, keyId: key.keyId };
  assert.equal(await store.revokeKey({ ...scope, revokedAt: "2026-11-20T12:01:00.000Z", reason: "compromised" }), true);
  assert.equal(await store.revokeKey({ ...scope, revokedAt: "2026-11-20T12:02:00.000Z", reason: "again" }), false);
  const found = await store.getKey(scope);
  assert.equal(found.status, "revoked");
  assert.equal(found.revoked, true);
});

test("challenge consumption uses tenant-device-challenge uniqueness", async () => {
  const { db } = fakeD1();
  const store = createD1DeviceTrustStore(db);
  const challenge = {
    tenantId: "tenant-1", deviceId: "device-1", challengeId: "nonce-1",
    attestationId: "att-1", consumedAt: "2026-11-20T12:00:00.000Z",
    expiresAt: "2026-11-20T12:05:00.000Z"
  };
  assert.equal(await store.consumeChallengeIfAbsent(challenge), true);
  assert.equal(await store.consumeChallengeIfAbsent({ ...challenge, attestationId: "att-2" }), false);
  assert.equal(await store.consumeChallengeIfAbsent({ ...challenge, tenantId: "tenant-2" }), true);
  assert.equal(await store.consumeChallengeIfAbsent({ ...challenge, deviceId: "device-2" }), true);
});

test("concurrent duplicate challenge inserts have exactly one winner in the adapter contract", async () => {
  const { db } = fakeD1();
  const store = createD1DeviceTrustStore(db);
  const challenge = {
    tenantId: "tenant-1", deviceId: "device-1", challengeId: "race-1",
    attestationId: "att-race", consumedAt: "2026-11-20T12:00:00.000Z",
    expiresAt: "2026-11-20T12:05:00.000Z"
  };
  const results = await Promise.all(Array.from({ length: 20 }, () => store.consumeChallengeIfAbsent(challenge)));
  assert.equal(results.filter(Boolean).length, 1);
});

test("storage errors propagate to the registry facade for fail-closed handling", async () => {
  const store = createD1DeviceTrustStore({
    prepare() { return { bind() { return this; }, async run() { throw new Error("d1 offline"); } }; }
  });
  await assert.rejects(() => store.createKeyIfAbsent(key), /d1 offline/);
});
