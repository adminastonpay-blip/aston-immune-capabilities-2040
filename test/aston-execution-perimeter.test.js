import test from "node:test";
import assert from "node:assert/strict";
import {
  ASTON_155_EXECUTION_SURFACE,
  EXECUTION_PERIMETER_REQUIRED_ORDER,
  createAstonExecutionPerimeter,
  inspectExecutionSurface
} from "../src/aston-execution-perimeter.js";

test("inventory includes every identified high-impact ASTON 15.5 route", () => {
  const keys = new Set(ASTON_155_EXECUTION_SURFACE.map(x => x.method + " " + x.path));
  for (const key of [
    "POST /v1/agents/plans/:id/execute",
    "POST /v1/factory/run",
    "POST /v1/sandbox/exec",
    "POST /v1/mission",
    "POST /v1/simulation/commit",
    "POST /v1/recovery/diagnose",
    "POST /v1/etl/enqueue",
    "POST /v1/rag/ingest",
    "POST /v1/ontology/objects",
    "POST /v1/constitution",
    "POST /v1/defense/approve"
  ]) assert.equal(keys.has(key), true, key);
  assert.deepEqual(EXECUTION_PERIMETER_REQUIRED_ORDER, [
    "authenticated_identity", "authoritative_tenant", "safety_interlock",
    "tenant_lifecycle_recheck", "action_specific_policy", "decision_only_result"
  ]);
});

test("route inventory never claims a host route is already integrated", () => {
  for (const route of ASTON_155_EXECUTION_SURFACE) {
    const result = inspectExecutionSurface(route.method, route.path);
    assert.equal(result.known, true);
    assert.equal(result.hostIntegrated, false);
    assert.equal(result.status, "HOST_INTEGRATION_NOT_PROVEN");
  }
});

test("unknown route is not silently marked safe", () => {
  assert.deepEqual(inspectExecutionSurface("POST", "/v1/unknown/execute"), {
    known: false, safetyRequired: null, hostIntegrated: false
  });
});

test("execution perimeter requires the tenant and SafetyInterlock gateway", async () => {
  const perimeter = createAstonExecutionPerimeter();
  const result = await perimeter.evaluateAction({
    identity: {}, action: { tool: "write" }, evaluatePolicy: async () => ({ executable: false })
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "EXECUTION_PERIMETER_GATEWAY_REQUIRED");
});

test("each plan action receives its own authority and SafetyInterlock evaluation", async () => {
  const calls = [];
  const perimeter = createAstonExecutionPerimeter({
    gateway: {
      async evaluate(input) {
        calls.push(input);
        return {
          ok: true, decision: "allow", reason: "allowed",
          tenantId: "tenant-a", lifecycleVersion: 3,
          safetyStatus: "allowed", executable: false,
          capability: await input.evaluateCapability({ hostContext: { tenantId: "tenant-a" }, action: input.action })
        };
      }
    }
  });
  const result = await perimeter.evaluatePlan({
    identity: { actor: "operator", method: "access" },
    planId: "plan-123",
    actions: [{ tool: "create_object" }, { tool: "update_object" }, { tool: "delete_object" }],
    evaluatePolicy: async ({ stepIndex, action }) => ({
      ok: true, decision: "allow", reason: action.tool + "_approved_" + stepIndex, executable: false
    })
  });
  assert.equal(result.ok, true);
  assert.equal(result.decisions.length, 3);
  assert.equal(calls.length, 3);
  assert.deepEqual(calls.map(x => x.action.context.stepIndex), [0, 1, 2]);
  assert.deepEqual(calls.map(x => x.action.context.planId), ["plan-123", "plan-123", "plan-123"]);
  assert.equal(result.executable, false);
});

test("plan stops immediately when any action is denied or pending review", async () => {
  let policyCalls = 0;
  const perimeter = createAstonExecutionPerimeter({
    gateway: {
      async evaluate({ action }) {
        if (action.context.stepIndex === 1) {
          return { ok: false, decision: "review", reason: "approval_pending", executable: false };
        }
        return {
          ok: true, decision: "allow", reason: "allowed",
          tenantId: "tenant-a", safetyStatus: "allowed", executable: false,
          capability: await evaluateCapability({ hostContext: { tenantId: "tenant-a" }, action })
        };
      }
    }
  });
  const result = await perimeter.evaluatePlan({
    identity: {}, planId: "plan-456",
    actions: [{ tool: "step-1" }, { tool: "step-2" }, { tool: "step-3" }],
    evaluatePolicy: async () => { policyCalls++; return { executable: false }; }
  });
  assert.equal(result.ok, false);
  assert.equal(result.failedStep, 1);
  assert.equal(result.decisions.length, 2);
  assert.equal(policyCalls, 1);
  assert.equal(result.executable, false);
});

test("action-specific policy must return decision-only output", async () => {
  const perimeter = createAstonExecutionPerimeter({
    gateway: {
      async evaluate({ evaluateCapability }) {
        const result = await evaluateCapability({});
        if (!result || result.executable !== false) {
          return { ok: false, decision: "deny", reason: "EXECUTION_CLAIM_REJECTED", executable: false };
        }
        return { ok: true, decision: "allow", reason: "allowed", executable: false };
      }
    }
  });
  const result = await perimeter.evaluateAction({
    identity: {}, action: { tool: "transfer" },
    evaluatePolicy: async () => ({ ok: true, executable: true })
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "EXECUTION_CLAIM_REJECTED");
});
