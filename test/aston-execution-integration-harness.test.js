import test from "node:test";
import assert from "node:assert/strict";
import { createAstonCapabilityRuntimeGateway } from "../src/aston-capability-runtime-gateway.js";
import { createAstonExecutionPerimeter } from "../src/aston-execution-perimeter.js";

const identity = {
  actor: "operator@example.test",
  method: "access",
  tenant: "tenant-a",
  issuer: "https://example.cloudflareaccess.com",
  subject: "subject-1"
};
const binding = async () => ({
  status: "active", method: "access", tenantId: "tenant-a",
  issuer: identity.issuer, subject: identity.subject,
  roles: ["operator"], clearance: "confidential"
});
const tenant = version => ({
  tenantId: "tenant-a", status: "active", lifecycleVersion: version
});

function harness({ safetyResponse, safetyThrows = false, tenantVersions = [7, 7] } = {}) {
  const effects = { d1Writes: 0, queueSends: 0, missionDispatches: 0, capabilityCalls: 0, safetyCalls: 0 };
  let tenantReads = 0;
  const gateway = createAstonCapabilityRuntimeGateway({
    resolvePrincipalBinding: binding,
    loadTenantLifecycle: async () => tenant(tenantVersions[Math.min(tenantReads++, tenantVersions.length - 1)]),
    safetyGate: {
      async evaluate() {
        effects.safetyCalls++;
        if (safetyThrows) throw new Error("SafetyInterlock unavailable");
        return safetyResponse ?? { ok: true, status: "allowed" };
      }
    }
  });
  const perimeter = createAstonExecutionPerimeter({ gateway });
  // Mirrors the host rule: no downstream adapter is invoked unless the
  // decision-only perimeter returns an affirmative, non-executable decision.
  async function guardedOperation(action, adapter) {
    const decision = await perimeter.evaluateAction({
      identity, action,
      evaluatePolicy: async () => {
        effects.capabilityCalls++;
        return { ok: true, decision: "allow", reason: "policy-approved", executable: false };
      }
    });
    if (decision.ok === true && decision.decision === "allow" && decision.executable === false) {
      await adapter();
    }
    return decision;
  }
  return { effects, perimeter, guardedOperation };
}

test("SafetyInterlock exception fails closed and causes zero downstream writes or dispatches", async () => {
  const h = harness({ safetyThrows: true });
  const results = await Promise.all([
    h.guardedOperation({ tool: "d1.insert" }, async () => h.effects.d1Writes++),
    h.guardedOperation({ tool: "queue.send" }, async () => h.effects.queueSends++),
    h.guardedOperation({ tool: "mission.dispatch" }, async () => h.effects.missionDispatches++)
  ]);
  assert.ok(results.every(result => result.ok === false && result.executable === false));
  assert.ok(results.every(result => result.reason === "SAFETY_INTERLOCK_EVALUATION_FAILED"));
  assert.deepEqual(h.effects, {
    d1Writes: 0, queueSends: 0, missionDispatches: 0,
    capabilityCalls: 0, safetyCalls: 3
  });
});

test("SafetyInterlock denied and pending approval both prevent all side effects", async () => {
  for (const safetyResponse of [
    { ok: false, status: "denied", reason: "policy-denied" },
    { ok: false, status: "pending_approval", approvalId: "approval-77" }
  ]) {
    const h = harness({ safetyResponse });
    const result = await h.guardedOperation(
      { tool: "mission.dispatch" },
      async () => { h.effects.missionDispatches++; }
    );
    assert.equal(result.ok, false);
    assert.equal(result.executable, false);
    assert.equal(h.effects.missionDispatches, 0);
    assert.equal(h.effects.capabilityCalls, 0);
  }
});

test("tenant lifecycle version change after SafetyInterlock prevents capability and side effects", async () => {
  const h = harness({ tenantVersions: [7, 8] });
  const result = await h.guardedOperation(
    { tool: "d1.insert" },
    async () => { h.effects.d1Writes++; }
  );
  assert.equal(result.ok, false);
  assert.equal(result.reason, "TENANT_LIFECYCLE_CHANGED_DURING_GATE");
  assert.equal(h.effects.capabilityCalls, 0);
  assert.equal(h.effects.d1Writes, 0);
  assert.equal(h.effects.safetyCalls, 1);
});

test("action policy denial prevents side effects after tenant and SafetyInterlock pass", async () => {
  const h = harness();
  const result = await h.perimeter.evaluateAction({
    identity,
    action: { tool: "queue.send" },
    evaluatePolicy: async () => ({
      ok: false, decision: "deny", reason: "scope-not-granted", executable: false
    })
  });
  assert.equal(result.ok, false);
  assert.equal(result.decision, "deny");
  assert.equal(h.effects.safetyCalls, 1);
  assert.equal(h.effects.capabilityCalls, 0);
  assert.equal(h.effects.queueSends, 0);
});

test("multi-action plan rechecks tenant and SafetyInterlock for each step and stops at first block", async () => {
  const effects = { safetyCalls: 0, policyCalls: 0, dispatches: 0 };
  const gateway = createAstonCapabilityRuntimeGateway({
    resolvePrincipalBinding: binding,
    loadTenantLifecycle: async () => tenant(11),
    safetyGate: {
      async evaluate() {
        effects.safetyCalls++;
        return effects.safetyCalls === 2
          ? { ok: false, status: "pending_approval", approvalId: "approval-step-2" }
          : { ok: true, status: "allowed" };
      }
    }
  });
  const perimeter = createAstonExecutionPerimeter({ gateway });
  const result = await perimeter.evaluatePlan({
    identity, planId: "plan-isolated-1",
    actions: [{ tool: "mission.prepare" }, { tool: "mission.dispatch" }, { tool: "queue.send" }],
    evaluatePolicy: async () => {
      effects.policyCalls++;
      return { ok: true, decision: "allow", reason: "policy-approved", executable: false };
    }
  });
  assert.equal(result.ok, false);
  assert.equal(result.failedStep, 1);
  assert.equal(result.decisions.length, 2);
  assert.equal(effects.safetyCalls, 2);
  assert.equal(effects.policyCalls, 1);
  assert.equal(effects.dispatches, 0);
});

test("malformed decision-only capability result is rejected before host adapter", async () => {
  const gateway = createAstonCapabilityRuntimeGateway({
    resolvePrincipalBinding: binding,
    loadTenantLifecycle: async () => tenant(12),
    safetyGate: { evaluate: async () => ({ ok: true, status: "allowed" }) }
  });
  const perimeter = createAstonExecutionPerimeter({ gateway });
  let adapterCalls = 0;
  const result = await perimeter.evaluateAction({
    identity, action: { tool: "d1.insert" },
    evaluatePolicy: async () => ({ ok: true, decision: "allow", executable: true })
  });
  if (result.ok && result.executable === false) adapterCalls++;
  assert.equal(result.ok, false);
  assert.equal(result.reason, "CAPABILITY_RESULT_NOT_DECISION_ONLY");
  assert.equal(adapterCalls, 0);
});
