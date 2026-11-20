import test from "node:test";
import assert from "node:assert/strict";
import { createAstonCapabilityRuntimeGateway } from "../src/aston-capability-runtime-gateway.js";

const identity = {
  actor: "operator@example.test", method: "access", tenant: "tenant-a",
  issuer: "https://example.cloudflareaccess.com", subject: "subject-1",
  roles: ["viewer"], clearance: "internal"
};
const action = { tool: "aston.capability.evaluate", args: { input: "safe" } };
const resolvePrincipalBinding = async () => ({
  status: "active", method: "access", tenantId: "tenant-a",
  issuer: identity.issuer, subject: identity.subject,
  roles: ["operator"], clearance: "confidential"
});
const loadTenantLifecycle = async () => ({
  tenantId: "tenant-a", status: "active", lifecycleVersion: 2
});

test("does not invoke a capability when tenant authority is unavailable", async () => {
  let invoked = false;
  const gateway = createAstonCapabilityRuntimeGateway({
    resolvePrincipalBinding: async () => { throw new Error("offline"); },
    loadTenantLifecycle,
    safetyGate: { evaluate: async () => ({ ok: true, status: "allowed" }) }
  });
  const result = await gateway.evaluate({
    identity, action, evaluateCapability: async () => { invoked = true; return { executable: false }; }
  });
  assert.equal(result.ok, false);
  assert.equal(invoked, false);
});

test("does not invoke a capability when SafetyInterlock denies or requests approval", async () => {
  for (const safety of [
    { ok: false, status: "denied", reason: "policy denied" },
    { ok: false, status: "pending_approval", approvalId: "approval-1" }
  ]) {
    let invoked = false;
    const gateway = createAstonCapabilityRuntimeGateway({
      resolvePrincipalBinding, loadTenantLifecycle,
      safetyGate: { evaluate: async () => safety }
    });
    const result = await gateway.evaluate({
      identity, action, evaluateCapability: async () => { invoked = true; return { executable: false }; }
    });
    assert.equal(result.ok, false);
    assert.equal(invoked, false);
  }
});

test("invokes a decision-only capability only after active tenant and SafetyInterlock allow", async () => {
  const order = [];
  const gateway = createAstonCapabilityRuntimeGateway({
    resolvePrincipalBinding: async input => { order.push("binding"); return resolvePrincipalBinding(input); },
    loadTenantLifecycle: async id => { order.push("tenant"); return loadTenantLifecycle(id); },
    safetyGate: { evaluate: async ({ hostContext }) => {
      order.push("safety");
      assert.equal(hostContext.tenantId, "tenant-a");
      return { ok: true, status: "allowed" };
    }}
  });
  const result = await gateway.evaluate({
    identity, action,
    evaluateCapability: async ({ hostContext }) => {
      order.push("capability");
      assert.equal(hostContext.authorityVerified, true);
      return { ok: true, decision: "allow", reason: "policy passed", executable: false };
    }
  });
  assert.deepEqual(order, ["binding", "tenant", "safety", "tenant", "capability"]);
  assert.equal(result.ok, true);
  assert.equal(result.safetyStatus, "allowed");
  assert.equal(result.executable, false);
});

test("rejects a capability evaluator that claims execution capability", async () => {
  const gateway = createAstonCapabilityRuntimeGateway({
    resolvePrincipalBinding, loadTenantLifecycle,
    safetyGate: { evaluate: async () => ({ ok: true, status: "allowed" }) }
  });
  const result = await gateway.evaluate({
    identity, action,
    evaluateCapability: async () => ({ ok: true, decision: "allow", executable: true })
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "CAPABILITY_RESULT_NOT_DECISION_ONLY");
});

test("does not evaluate a capability when tenant lifecycle changes after SafetyInterlock", async () => {
  let reads = 0, invoked = false;
  const gateway = createAstonCapabilityRuntimeGateway({
    resolvePrincipalBinding, 
    loadTenantLifecycle: async () => {
      reads++;
      return reads === 1
        ? { tenantId: "tenant-a", status: "active", lifecycleVersion: 2 }
        : { tenantId: "tenant-a", status: "suspended", lifecycleVersion: 3 };
    },
    safetyGate: { evaluate: async () => ({ ok: true, status: "allowed" }) }
  });
  const result = await gateway.evaluate({
    identity, action,
    evaluateCapability: async () => { invoked = true; return { executable: false }; }
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "TENANT_LIFECYCLE_CHANGED_DURING_GATE");
  assert.equal(invoked, false);
  assert.equal(reads, 2);
});
