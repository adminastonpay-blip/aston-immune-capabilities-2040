import test from "node:test";
import assert from "node:assert/strict";
import { createAston155HostExecutionBridge } from "../src/aston-155-host-execution-bridge.js";
const baseIdentity = { actor: "operator@example.test", method: "access", tenant: "tenant-a", roles: ["operator"], clearance: "confidential" };
const activeTenant = { tenantId: "tenant-a", status: "active", lifecycleVersion: 4 };
function makeBridge({ verified, binding, tenant = activeTenant, safety = { ok: true, status: "allowed" } } = {}) {
 const calls = { binding: 0, tenant: 0, safety: 0, policy: 0 };
 const bridge = createAston155HostExecutionBridge({
  resolveVerifiedPrincipal: async () => verified,
  resolvePrincipalBinding: async input => { calls.binding++; return binding(input); },
  loadTenantLifecycle: async () => { calls.tenant++; return tenant; },
  safetyGate: { evaluate: async () => { calls.safety++; return safety; } }
 });
 return { bridge, calls };
}
test("current Access Identity without issuer and subject fails closed", async () => {
 const { bridge, calls } = makeBridge({ verified: { actor: baseIdentity.actor, method: "access" }, binding: async () => ({}) });
 const result = await bridge.evaluateAction({ request: {}, identity: baseIdentity, action: { tool: "mission.dispatch" }, evaluatePolicy: async () => ({ ok: true, decision: "allow", executable: false }) });
 assert.equal(result.ok, false); assert.equal(result.reason, "ASTON_155_ACCESS_ISSUER_SUBJECT_UNAVAILABLE");
 assert.equal(calls.binding, 0); assert.equal(calls.safety, 0);
});
test("verified Access principal passes authority and SafetyInterlock decision-only", async () => {
 const issuer = "https://example.cloudflareaccess.com";
 const { bridge, calls } = makeBridge({
  verified: { actor: baseIdentity.actor, method: "access", issuer, subject: "cf-subject-77" },
  binding: async () => ({ status: "active", method: "access", tenantId: "tenant-a", issuer, subject: "cf-subject-77", roles: ["operator"], clearance: "confidential" })
 });
 const result = await bridge.evaluateAction({ request: {}, identity: baseIdentity, action: { tool: "mission.dispatch" }, evaluatePolicy: async () => { calls.policy++; return { ok: true, decision: "allow", reason: "policy-ok", executable: false }; } });
 assert.equal(result.ok, true); assert.equal(result.executable, false);
 assert.equal(calls.binding, 1); assert.equal(calls.tenant, 2); assert.equal(calls.safety, 1); assert.equal(calls.policy, 1);
});
test("legacy API-key tenant default cannot pass authoritative binding", async () => {
 const identity = { actor: "apikey:0123456789abcdef", method: "apikey", tenant: "default", roles: ["admin", "executor"], clearance: "confidential" };
 const { bridge, calls } = makeBridge({ verified: { actor: identity.actor, method: "apikey" }, binding: async () => ({ status: "active", method: "apikey", tenantId: "default", actor: identity.actor, roles: ["admin"], clearance: "confidential" }) });
 const result = await bridge.evaluateAction({ request: {}, identity, action: { tool: "d1.write" }, evaluatePolicy: async () => ({ ok: true, decision: "allow", executable: false }) });
 assert.equal(result.ok, false); assert.equal(result.reason, "PRINCIPAL_BINDING_NOT_ACTIVE_OR_INVALID"); assert.equal(calls.safety, 0);
});
test("static sensor actor without stable credential ID cannot pass", async () => {
 const identity = { actor: "lb-sensor", method: "sensor", tenant: "ops", roles: ["sensor"], clearance: "secret" };
 const { bridge, calls } = makeBridge({ verified: { actor: identity.actor, method: "sensor" }, binding: async () => ({}) });
 const result = await bridge.evaluateAction({ request: {}, identity, action: { tool: "mission.dispatch" }, evaluatePolicy: async () => ({ ok: true, decision: "allow", executable: false }) });
 assert.equal(result.ok, false); assert.equal(result.reason, "ASTON_155_SENSOR_CREDENTIAL_ID_UNAVAILABLE"); assert.equal(calls.binding, 0); assert.equal(calls.safety, 0);
});
test("SafetyInterlock pending approval never becomes allow", async () => {
 const issuer = "https://example.cloudflareaccess.com";
 const { bridge } = makeBridge({ verified: { actor: baseIdentity.actor, method: "access", issuer, subject: "cf-subject-77" },
  binding: async () => ({ status: "active", method: "access", tenantId: "tenant-a", issuer, subject: "cf-subject-77", roles: ["operator"], clearance: "confidential" }),
  safety: { ok: false, status: "pending_approval", approvalId: "approval-1" } });
 const result = await bridge.evaluateAction({ request: {}, identity: baseIdentity, action: { tool: "mission.dispatch" }, evaluatePolicy: async () => ({ ok: true, decision: "allow", executable: false }) });
 assert.equal(result.ok, false); assert.equal(result.executable, false); assert.equal(result.decision, "review"); assert.equal(result.approvalId, "approval-1");
});