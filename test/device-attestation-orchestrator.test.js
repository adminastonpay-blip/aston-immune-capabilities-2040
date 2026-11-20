import test from "node:test";
import assert from "node:assert/strict";
import { createDeviceAttestationOrchestrator } from "../src/device-attestation-orchestrator.js";
import { canonicalizeAttestationPayload } from "../src/device-attestation-crypto-verifier.js";

const NOW = Date.parse("2026-11-20T12:00:00.000Z");
const hostContext = Object.freeze({ tenantId: "tenant-1", audience: "aston-edge-v1", principalId: "host-service-1" });

function fakeD1({ fail = false, failOnChallenge = false } = {}) {
  const keys = new Map();
  const challenges = new Set();
  const keyId = (t, i, k) => [t, i, k].join("|");
  const challengeId = (t, d, c) => [t, d, c].join("|");
  return {
    keys, challenges,
    db: {
      prepare(sql) {
        return {
          values: [],
          bind(...values) { this.values = values; return this; },
          async run() {
            if (fail || (failOnChallenge && sql.includes("aston_device_trust_challenges"))) throw new Error("simulated_d1_failure");
            const v = this.values;
            if (sql.includes("INSERT OR IGNORE INTO aston_device_trust_keys")) {
              const id = keyId(v[0], v[1], v[2]);
              if (keys.has(id)) return { success: true, meta: { changes: 0 } };
              keys.set(id, {
                tenant_id:v[0], issuer_id:v[1], key_id:v[2], device_id:v[3],
                public_key_json:v[4], status:v[5], revoked:v[6], device_status:v[7],
                not_before:v[8], not_after:v[9], created_at:v[10],
                revoked_at:null, revocation_reason:null
              });
              return { success:true, meta:{changes:1} };
            }
            if (sql.includes("INSERT OR IGNORE INTO aston_device_trust_challenges")) {
              const id = challengeId(v[0],v[1],v[2]);
              if (challenges.has(id)) return { success:true, meta:{changes:0} };
              challenges.add(id);
              return { success:true, meta:{changes:1} };
            }
            throw new Error("unexpected_sql");
          },
          async first() {
            if (fail) throw new Error("simulated_d1_failure");
            const row = keys.get(keyId(...this.values));
            return row ? structuredClone(row) : null;
          }
        };
      }
    }
  };
}

function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

async function fixture({ fail = false, failOnChallenge = false, authorize = async () => true } = {}) {
  const { db, keys, challenges } = fakeD1({ fail, failOnChallenge });
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const key = {
    tenantId:"tenant-1", issuerId:"issuer-1", keyId:"key-1", deviceId:"device-1",
    publicKey, status:"active", revoked:false, deviceStatus:"active",
    notBefore:"2026-01-01T00:00:00.000Z", notAfter:"2027-01-01T00:00:00.000Z",
    createdAt:"2026-11-20T11:00:00.000Z"
  };
  keys.set("tenant-1|issuer-1|key-1", {
    tenant_id:key.tenantId, issuer_id:key.issuerId, key_id:key.keyId,
    device_id:key.deviceId, public_key_json:JSON.stringify(publicKey),
    status:"active", revoked:0, device_status:"active",
    not_before:key.notBefore, not_after:key.notAfter, created_at:key.createdAt,
    revoked_at:null, revocation_reason:null
  });
  const payload = {
    attestationId:"att-1", tenantId:"tenant-1", deviceId:"device-1",
    agentId:"agent-1", missionId:"mission-1", challengeId:"challenge-1",
    nonce:"nonce-1", audience:"aston-edge-v1", issuerId:"issuer-1", keyId:"key-1",
    issuedAt:new Date(NOW - 1000).toISOString(),
    expiresAt:new Date(NOW + 60000).toISOString(),
    claims:["device_present","mission_bound"]
  };
  const signature = b64url(await crypto.subtle.sign(
    { name:"Ed25519" }, pair.privateKey,
    new TextEncoder().encode(canonicalizeAttestationPayload(payload))
  ));
  const orchestrator = createDeviceAttestationOrchestrator({
    db, hostContext, authorize, now:() => NOW
  });
  return { orchestrator, payload:{...payload,signature}, pair, keys, challenges };
}

test("verifies Ed25519 trust bindings then atomically consumes the challenge", async () => {
  const { orchestrator, payload, challenges } = await fixture();
  const result = await orchestrator.verifyAndConsume(payload);
  assert.equal(result.ok, true);
  assert.equal(result.decision, "verified_and_consumed");
  assert.equal(result.executable, false);
  assert.equal(challenges.size, 1);
});

test("rejects replay without a second successful consumption", async () => {
  const { orchestrator, payload, challenges } = await fixture();
  assert.equal((await orchestrator.verifyAndConsume(payload)).ok, true);
  const replay = await orchestrator.verifyAndConsume(payload);
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, "challenge_replay_detected");
  assert.equal(challenges.size, 1);
});

test("invalid signature is rejected before consuming the challenge", async () => {
  const { orchestrator, payload, challenges } = await fixture();
  const result = await orchestrator.verifyAndConsume({...payload, signature:b64url(new Uint8Array(64))});
  assert.equal(result.reason, "invalid_signature");
  assert.equal(challenges.size, 0);
});

test("rejects tenant or audience values not matching trusted host context", async () => {
  const { orchestrator, payload, challenges } = await fixture();
  const result = await orchestrator.verifyAndConsume({...payload, tenantId:"tenant-2"});
  assert.equal(result.reason, "tenant_or_audience_mismatch");
  assert.equal(challenges.size, 0);
});

test("requires D1 and authenticated host authorization configuration", async () => {
  const missingDb = createDeviceAttestationOrchestrator({ hostContext, authorize:async()=>true });
  assert.equal((await missingDb.verifyAndConsume({})).reason, "d1_database_required");
  const missingAuth = createDeviceAttestationOrchestrator({ db:{prepare(){}}, hostContext });
  assert.equal((await missingAuth.verifyAndConsume({})).reason, "trusted_host_context_required");
});

test("fails closed when host authorization denies challenge consumption", async () => {
  const { orchestrator, payload, challenges } = await fixture({ authorize:async()=>false });
  const result = await orchestrator.verifyAndConsume(payload);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "challenge_consumption_not_authorized");
  assert.equal(challenges.size, 0);
});

test("fails closed on D1 storage errors after cryptographic verification", async () => {
  const { orchestrator, payload } = await fixture({ failOnChallenge:true });
  const result = await orchestrator.verifyAndConsume(payload);
  assert.equal(result.ok, false);
  assert.equal(result.decision, "review");
  assert.equal(result.reason, "trusted_store_unavailable");
});

test("expired attestation is rejected before challenge consumption", async () => {
  const { orchestrator, payload, challenges } = await fixture();
  const expired = {...payload, issuedAt:new Date(NOW - 120000).toISOString(), expiresAt:new Date(NOW - 1).toISOString()};
  const result = await orchestrator.verifyAndConsume(expired);
  assert.equal(result.reason, "attestation_time_invalid");
  assert.equal(challenges.size, 0);
});

test("key belonging to a different device cannot verify this device envelope", async () => {
  const { orchestrator, payload, keys, challenges } = await fixture();
  const row = keys.get("tenant-1|issuer-1|key-1");
  row.device_id = "device-other";
  const result = await orchestrator.verifyAndConsume(payload);
  assert.equal(result.reason, "trusted_key_not_found");
  assert.equal(challenges.size, 0);
});

test("never treats caller-provided verified flags as evidence", async () => {
  const { orchestrator, payload, challenges } = await fixture();
  const result = await orchestrator.verifyAndConsume({...payload, verified:true, evidence:{verified:true}});
  assert.equal(result.ok, true);
  assert.equal(result.executable, false);
  assert.equal(challenges.size, 1);
});
