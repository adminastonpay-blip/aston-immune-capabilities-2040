import test from "node:test";
import assert from "node:assert/strict";
import { evaluatePhysicalEdgeAttestation } from "../src/physical-edge-attestation.js";

const now = Date.parse("2026-11-20T12:00:00.000Z");
const envelope = {
  attestationId: "att-001", tenantId: "tenant-a", deviceId: "device-7",
  agentId: "edge-agent-2", missionId: "mission-9", challengeId: "challenge-3",
  nonce: "nonce-abc", audience: "aston-edge-gateway", issuerId: "issuer-factory",
  keyId: "device-key-4", issuedAt: "2026-11-20T11:59:00.000Z",
  expiresAt: "2026-11-20T12:02:00.000Z",
  claims: ["secure_boot:verified", "firmware:approved"]
};
const verifier = (value) => ({
  verified: true, attestationId: value.attestationId, tenantId: value.tenantId,
  deviceId: value.deviceId, agentId: value.agentId, missionId: value.missionId,
  challengeId: value.challengeId, nonce: value.nonce, audience: value.audience,
  issuerId: value.issuerId, keyId: value.keyId, issuedAt: value.issuedAt,
  expiresAt: value.expiresAt, claims: JSON.stringify(value.claims),
  deviceStatus: "active", verifierId: "trusted-edge-verifier",
  evidenceDigest: "sha256:0123456789abcdef"
});
const evaluate = (value = envelope, policy = {}) =>
  evaluatePhysicalEdgeAttestation(value, { now, verifyAttestation: verifier, policy });

test("allows a fully bound active-device attestation as non-executable", () => {
  const result = evaluate();
  assert.equal(result.decision, "allow");
  assert.equal(result.executable, false);
  assert.equal(result.scope.deviceId, "device-7");
});

test("requires a trusted host verifier", () => {
  const result = evaluatePhysicalEdgeAttestation(envelope, { now });
  assert.equal(result.decision, "review");
  assert.equal(result.reason, "trusted_attestation_verifier_required");
});

test("verifier exceptions fail to review", () => {
  const result = evaluatePhysicalEdgeAttestation(envelope, {
    now, verifyAttestation: () => { throw new Error("verification unavailable"); }
  });
  assert.equal(result.decision, "review");
});

test("rejects missing tenant or device identity", () => {
  assert.equal(evaluate({ ...envelope, tenantId: "" }).decision, "deny");
  assert.equal(evaluate({ ...envelope, deviceId: null }).decision, "deny");
});

test("rejects duplicate or malformed claims", () => {
  assert.equal(evaluate({ ...envelope, claims: ["x", "x"] }).decision, "deny");
  assert.equal(evaluate({ ...envelope, claims: [] }).decision, "deny");
});

test("rejects expired, future-issued and overlong attestations", () => {
  assert.equal(evaluate({ ...envelope, expiresAt: "2026-11-20T11:59:30.000Z" }).reason, "attestation_time_invalid");
  assert.equal(evaluate({ ...envelope, issuedAt: "2026-11-20T12:01:00.000Z" }).reason, "attestation_time_invalid");
  assert.equal(evaluate({ ...envelope, expiresAt: "2026-11-20T12:10:00.000Z" }).reason, "attestation_time_invalid");
});

test("requires exact challenge and nonce binding", () => {
  assert.equal(evaluate(envelope, {}).decision, "allow");
  const result = evaluatePhysicalEdgeAttestation(envelope, {
    now, verifyAttestation: (value) => ({ ...verifier(value), nonce: "different-nonce" })
  });
  assert.equal(result.decision, "review");
});

test("requires exact tenant and device binding from verifier", () => {
  const result = evaluatePhysicalEdgeAttestation(envelope, {
    now, verifyAttestation: (value) => ({ ...verifier(value), tenantId: "tenant-b" })
  });
  assert.equal(result.reason, "attestation_verification_failed");
});

test("requires exact issuer and key binding", () => {
  const result = evaluatePhysicalEdgeAttestation(envelope, {
    now, verifyAttestation: (value) => ({ ...verifier(value), keyId: "untrusted-key" })
  });
  assert.equal(result.decision, "review");
});

test("inactive devices never pass verification", () => {
  const result = evaluatePhysicalEdgeAttestation(envelope, {
    now, verifyAttestation: (value) => ({ ...verifier(value), deviceStatus: "revoked" })
  });
  assert.equal(result.decision, "review");
});

test("requires an evidence digest and verifier identity", () => {
  const result = evaluatePhysicalEdgeAttestation(envelope, {
    now, verifyAttestation: (value) => ({ ...verifier(value), evidenceDigest: "", verifierId: "" })
  });
  assert.equal(result.decision, "review");
});

test("required claims are enforced", () => {
  const result = evaluate(envelope, { requiredClaims: ["secure_boot:verified", "hardware_root:present"] });
  assert.equal(result.decision, "deny");
  assert.equal(result.reason, "required_claim_missing");
});

test("denied devices fail closed", () => {
  const result = evaluate(envelope, { deniedDevices: ["device-7"] });
  assert.equal(result.decision, "deny");
});

test("sensitive claims require human approval", () => {
  const result = evaluate(envelope, { approvalRequiredClaims: ["physical_actuation:requested"] });
  assert.equal(result.decision, "allow");
  const gated = evaluate({ ...envelope, claims: [...envelope.claims, "physical_actuation:requested"] },
    { approvalRequiredClaims: ["physical_actuation:requested"] });
  assert.equal(gated.decision, "review");
  assert.equal(gated.approvalRequired, true);
  assert.equal(gated.executable, false);
});

test("invalid verifier output never returns allow", () => {
  const result = evaluatePhysicalEdgeAttestation(envelope, {
    now, verifyAttestation: () => ({ verified: true, verifierId: "v1" })
  });
  assert.equal(result.decision, "review");
});
