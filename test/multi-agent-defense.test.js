import test from "node:test";
import assert from "node:assert/strict";
import { evaluateThreat } from "../src/multi-agent-defense.js";

const NOW = Date.parse("2026-11-19T12:00:00.000Z");

function observation(overrides = {}) {
  return {
    eventId: "evt-001",
    tenantId: "tenant-a",
    agentId: "agent-7",
    observedAt: new Date(NOW).toISOString(),
    signalType: "integrity_failure",
    severity: "critical",
    evidence: {
      verified: true,
      reference: "sha256:abc123",
      verifier: "trusted-attestation-adapter",
    },
    ...overrides,
  };
}

test("verified critical signal proposes isolation for only the named agent", () => {
  const result = evaluateThreat(observation(), { now: NOW });
  assert.equal(result.action, "propose_isolation");
  assert.deepEqual(result.scope, { tenantId: "tenant-a", agentId: "agent-7" });
  assert.equal(result.executable, false);
});

test("verified high signal proposes restriction, not isolation", () => {
  const result = evaluateThreat(observation({ severity: "high" }), { now: NOW });
  assert.equal(result.action, "propose_restriction");
});

test("unverified critical signal is review-only", () => {
  const result = evaluateThreat(
    observation({ evidence: { verified: false, reference: "", verifier: "" } }),
    { now: NOW },
  );
  assert.equal(result.action, "review");
  assert.equal(result.reason, "evidence_not_verified");
});

test("medium signal requests review", () => {
  const result = evaluateThreat(observation({ severity: "medium" }), { now: NOW });
  assert.equal(result.action, "review");
});

test("low signal does not propose containment", () => {
  const result = evaluateThreat(observation({ severity: "low" }), { now: NOW });
  assert.equal(result.action, "none");
});

test("stale observations are rejected", () => {
  const old = new Date(NOW - 120_001).toISOString();
  const result = evaluateThreat(observation({ observedAt: old }), { now: NOW });
  assert.equal(result.decision, "reject");
  assert.equal(result.reason, "stale_observation");
});

test("future observations outside clock skew are rejected", () => {
  const future = new Date(NOW + 30_001).toISOString();
  const result = evaluateThreat(observation({ observedAt: future }), { now: NOW });
  assert.equal(result.reason, "timestamp_in_future");
});

test("malformed or incomplete observations fail closed", () => {
  const result = evaluateThreat(observation({ tenantId: "" }), { now: NOW });
  assert.equal(result.decision, "reject");
  assert.equal(result.action, "none");
  assert.equal(result.scope, null);
});

test("invalid timestamp is rejected", () => {
  const result = evaluateThreat(observation({ observedAt: "not-a-date" }), { now: NOW });
  assert.equal(result.reason, "invalid_timestamp");
});

test("decision never claims to execute a containment action", () => {
  const result = evaluateThreat(observation(), { now: NOW });
  assert.equal(result.executable, false);
});
