import test from "node:test";
import assert from "node:assert/strict";
import { evaluateInterAgentRequest } from "../src/inter-agent-governance.js";

const now = Date.parse("2026-11-20T12:00:00.000Z");
const request = {
  requestId: "req-001", tenantId: "tenant-a",
  sourceAgentId: "agent-alpha", targetAgentId: "agent-beta",
  action: "read_inventory", resource: "inventory:item-7",
  requestedScopes: ["inventory:read"], audience: "aston-inventory",
  issuedAt: "2026-11-20T11:59:00.000Z",
  expiresAt: "2026-11-20T12:05:00.000Z",
  delegation: {
    grantId: "grant-001", tenantId: "tenant-a",
    issuerAgentId: "agent-alpha", subjectAgentId: "agent-beta",
    audience: "aston-inventory", scopes: ["inventory:read", "inventory:list"],
    expiresAt: "2026-11-20T12:10:00.000Z", depth: 0, maxDepth: 1
  }
};
const verifier = (value) => ({
  verified: true, requestId: value.requestId, tenantId: value.tenantId,
  sourceAgentId: value.sourceAgentId, targetAgentId: value.targetAgentId,
  action: value.action, resource: value.resource,
  requestedScopes: JSON.stringify(value.requestedScopes),
  issuedAt: value.issuedAt, expiresAt: value.expiresAt,
  grantId: value.delegation.grantId,
  issuerAgentId: value.delegation.issuerAgentId,
  subjectAgentId: value.delegation.subjectAgentId,
  delegationScopes: JSON.stringify(value.delegation.scopes),
  delegationExpiresAt: value.delegation.expiresAt,
  delegationDepth: value.delegation.depth,
  delegationMaxDepth: value.delegation.maxDepth,
  audience: value.audience, verifierId: "trusted-host-verifier"
});
const evaluate = (value = request, options = {}) => evaluateInterAgentRequest(value, {
  now, verifyRequest: verifier, policy: { allowedActions: ["read_inventory", "write_inventory"], ...options }
});

test("allows a verified request within delegated scopes and local policy", () => {
  const result = evaluate();
  assert.equal(result.decision, "allow");
  assert.equal(result.executable, false);
});

test("rejects cross-tenant delegation", () => {
  const result = evaluate({ ...request, delegation: { ...request.delegation, tenantId: "tenant-b" } });
  assert.equal(result.reason, "tenant_scope_mismatch");
});

test("rejects a request outside delegated scopes", () => {
  const result = evaluate({ ...request, requestedScopes: ["inventory:write"] });
  assert.equal(result.reason, "requested_scope_exceeds_grant");
});

test("rejects delegation to a different target agent", () => {
  const result = evaluate({ ...request, delegation: { ...request.delegation, subjectAgentId: "agent-gamma" } });
  assert.equal(result.reason, "delegation_party_mismatch");
});

test("rejects audience confusion", () => {
  const result = evaluate({ ...request, audience: "other-service" });
  assert.equal(result.reason, "audience_mismatch");
});

test("rejects expired or insufficient grant lifetime", () => {
  const result = evaluate({ ...request, delegation: { ...request.delegation, expiresAt: "2026-11-20T12:01:00.000Z" } });
  assert.equal(result.reason, "delegation_expired_or_shorter_than_request");
});

test("rejects delegation depth escalation", () => {
  const result = evaluate({ ...request, delegation: { ...request.delegation, depth: 2, maxDepth: 1 } });
  assert.equal(result.reason, "delegation_depth_exceeded");
});

test("requires trusted verifier and returns review-only", () => {
  const result = evaluateInterAgentRequest(request, { now, policy: { allowedActions: ["read_inventory"] } });
  assert.equal(result.decision, "review");
  assert.equal(result.reason, "trusted_verifier_required");
});

test("verifier must bind exact action and resource", () => {
  const result = evaluateInterAgentRequest(request, {
    now, verifyRequest: (value) => ({ ...verifier(value), action: "delete_inventory" })
  });
  assert.equal(result.reason, "request_verification_failed");
});

test("verifier must bind the complete delegation scope and lifetime", () => {
  const result = evaluateInterAgentRequest(request, {
    now, verifyRequest: (value) => ({ ...verifier(value), delegationScopes: JSON.stringify(["inventory:read", "admin:*"]) })
  });
  assert.equal(result.decision, "review");
  assert.equal(result.reason, "request_verification_failed");
});

test("denied actions fail closed", () => {
  const result = evaluate(request, { deniedActions: ["read_inventory"] });
  assert.equal(result.decision, "deny");
  assert.equal(result.reason, "action_denied_by_policy");
});

test("sensitive actions require human approval", () => {
  const result = evaluate(request, { approvalRequiredActions: ["read_inventory"] });
  assert.equal(result.decision, "review");
  assert.equal(result.approvalRequired, true);
  assert.equal(result.executable, false);
});

test("self delegation is rejected", () => {
  const result = evaluate({ ...request, targetAgentId: request.sourceAgentId });
  assert.equal(result.reason, "self_delegation_not_allowed");
});

test("future-issued and expired requests are rejected", () => {
  const future = evaluate({ ...request, issuedAt: "2026-11-20T12:01:00.000Z" });
  assert.equal(future.reason, "request_expired_or_invalid_time");
  const expired = evaluate({ ...request, expiresAt: "2026-11-20T11:59:30.000Z" });
  assert.equal(expired.reason, "request_expired_or_invalid_time");
});

test("invalid verifier output fails to review rather than allow", () => {
  const result = evaluateInterAgentRequest(request, {
    now, verifyRequest: () => ({ verified: true, requestId: request.requestId, verifierId: "v1" })
  });
  assert.equal(result.decision, "review");
  assert.equal(result.reason, "request_verification_failed");
});
