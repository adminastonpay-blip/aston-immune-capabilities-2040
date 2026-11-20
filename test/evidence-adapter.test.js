import test from "node:test";
import assert from "node:assert/strict";
import { evaluateThreatWithVerifier } from "../src/evidence-adapter.js";

const NOW = Date.parse("2026-11-19T12:00:00.000Z");
const event = {
  eventId: "evt-001",
  tenantId: "tenant-a",
  agentId: "agent-7",
  observedAt: new Date(NOW).toISOString(),
  signalType: "integrity_failure",
  severity: "critical",
  evidence: { verified: true, reference: "caller-forged", verifier: "caller" },
};
const validVerifier = async () => ({
  verified: true,
  eventId: event.eventId,
  tenantId: event.tenantId,
  agentId: event.agentId,
  observedAt: event.observedAt,
  reference: "sha256:verified-proof",
  verifierId: "host-attestation-verifier",
});

test("ignores caller-supplied verified=true when no host verifier is provided", async () => {
  const result = await evaluateThreatWithVerifier(event, { now: NOW });
  assert.equal(result.action, "review");
  assert.equal(result.evidenceVerified, false);
});

test("accepts a verifier result bound to the exact tenant, agent, event and timestamp", async () => {
  const result = await evaluateThreatWithVerifier(event, { now: NOW, verifyEvidence: validVerifier });
  assert.equal(result.action, "propose_isolation");
  assert.equal(result.evidenceVerified, true);
  assert.equal(result.executable, false);
});

test("rejects a verifier result bound to another tenant", async () => {
  const result = await evaluateThreatWithVerifier(event, {
    now: NOW,
    verifyEvidence: async () => ({ ...(await validVerifier()), tenantId: "tenant-b" }),
  });
  assert.equal(result.action, "review");
  assert.equal(result.evidenceVerified, false);
});

test("rejects a verifier result bound to another agent", async () => {
  const result = await evaluateThreatWithVerifier(event, {
    now: NOW,
    verifyEvidence: async () => ({ ...(await validVerifier()), agentId: "agent-other" }),
  });
  assert.equal(result.action, "review");
  assert.equal(result.evidenceVerified, false);
});

test("rejects a verifier result bound to another event", async () => {
  const result = await evaluateThreatWithVerifier(event, {
    now: NOW,
    verifyEvidence: async () => ({ ...(await validVerifier()), eventId: "evt-other" }),
  });
  assert.equal(result.action, "review");
  assert.equal(result.evidenceVerified, false);
});

test("verifier exceptions fail closed", async () => {
  const result = await evaluateThreatWithVerifier(event, {
    now: NOW,
    verifyEvidence: async () => { throw new Error("verification unavailable"); },
  });
  assert.equal(result.action, "review");
  assert.equal(result.evidenceVerified, false);
});

test("missing verifier fails closed even if caller claims verification", async () => {
  const result = await evaluateThreatWithVerifier(event, { now: NOW, verifyEvidence: null });
  assert.equal(result.action, "review");
  assert.equal(result.executable, false);
});
