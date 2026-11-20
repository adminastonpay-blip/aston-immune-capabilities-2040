import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import {
  verifyDeviceAttestation,
  canonicalizeAttestationPayload
} from "../src/device-attestation-crypto-verifier.js";

const now = Date.parse("2026-11-20T12:00:00.000Z");
const base = {
  attestationId: "att-001", tenantId: "tenant-a", deviceId: "device-7",
  agentId: "agent-2", missionId: "mission-9", challengeId: "challenge-3",
  nonce: "nonce-abc", audience: "aston-edge", issuerId: "issuer-factory",
  keyId: "key-2026-01", issuedAt: "2026-11-20T11:59:00.000Z",
  expiresAt: "2026-11-20T12:03:00.000Z",
  claims: ["secure-boot", "firmware-v4"]
};

async function fixture() {
  const pair = await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const jwk = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
  const payload = new TextEncoder().encode(canonicalizeAttestationPayload(base));
  const signature = new Uint8Array(await webcrypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, payload));
  let binary = "";
  for (const byte of signature) binary += String.fromCharCode(byte);
  const envelope = { ...base, signature: btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_") };
  const keyRecord = {
    tenantId: "tenant-a", issuerId: "issuer-factory", keyId: "key-2026-01",
    status: "active", revoked: false, deviceStatus: "active",
    notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2027-01-01T00:00:00.000Z",
    publicKey: jwk
  };
  return { envelope, keyRecord };
}

function options(keyRecord, overrides = {}) {
  return { now, expectedTenantId: "tenant-a", expectedAudience: "aston-edge",
    resolveTrustedKey: async () => keyRecord, ...overrides };
}

test("verifies valid Ed25519 attestation and emits bound evidence", async () => {
  const { envelope, keyRecord } = await fixture();
  const result = await verifyDeviceAttestation(envelope, options(keyRecord));
  assert.equal(result.decision, "verified");
  assert.equal(result.verified, true);
  assert.equal(result.tenantId, envelope.tenantId);
  assert.equal(result.deviceId, envelope.deviceId);
  assert.match(result.evidenceDigest, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(result.executable, false);
});

test("rejects a tampered signed field", async () => {
  const { envelope, keyRecord } = await fixture();
  const result = await verifyDeviceAttestation({ ...envelope, deviceId: "device-attacker" }, options(keyRecord));
  assert.equal(result.reason, "invalid_signature");
});

test("rejects tenant and audience substitution", async () => {
  const { envelope, keyRecord } = await fixture();
  assert.equal((await verifyDeviceAttestation(envelope, options(keyRecord, { expectedTenantId: "tenant-b" }))).reason, "tenant_or_audience_mismatch");
  assert.equal((await verifyDeviceAttestation(envelope, options(keyRecord, { expectedAudience: "other-service" }))).reason, "tenant_or_audience_mismatch");
});

test("rejects unknown, mismatched, revoked and expired keys", async () => {
  const { envelope, keyRecord } = await fixture();
  assert.equal((await verifyDeviceAttestation(envelope, options(null))).reason, "trusted_key_not_found");
  assert.equal((await verifyDeviceAttestation(envelope, options({ ...keyRecord, tenantId: "tenant-b" }))).reason, "trusted_key_binding_mismatch");
  assert.equal((await verifyDeviceAttestation(envelope, options({ ...keyRecord, status: "revoked", revoked: true }))).reason, "trusted_key_not_active");
  assert.equal((await verifyDeviceAttestation(envelope, options({ ...keyRecord, notAfter: "2026-11-01T00:00:00.000Z" }))).reason, "trusted_key_outside_validity");
});

test("fails closed on malformed, stale and expired attestations", async () => {
  const { envelope, keyRecord } = await fixture();
  assert.equal((await verifyDeviceAttestation({ ...envelope, claims: ["duplicate", "duplicate"] }, options(keyRecord))).reason, "invalid_attestation_claims");
  assert.equal((await verifyDeviceAttestation(envelope, options(keyRecord, { now: Date.parse("2026-11-20T12:04:00.000Z") }))).reason, "attestation_time_invalid");
});

test("requires a trusted registry and treats lookup failure as review", async () => {
  const { envelope, keyRecord } = await fixture();
  assert.equal((await verifyDeviceAttestation(envelope, { now, expectedTenantId: "tenant-a", expectedAudience: "aston-edge" })).decision, "review");
  assert.equal((await verifyDeviceAttestation(envelope, options(keyRecord, { resolveTrustedKey: async () => { throw new Error("offline"); } }))).decision, "review");
});

test("canonicalization is independent of object insertion order", () => {
  assert.equal(canonicalizeAttestationPayload({ z: 1, a: { y: true, x: 2 } }), canonicalizeAttestationPayload({ a: { x: 2, y: true }, z: 1 }));
});
