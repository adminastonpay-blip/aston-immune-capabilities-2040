/**
 * ASTON OS 15.5 execution perimeter contract.
 *
 * This module is a decision-only integration adapter. It does not dispatch
 * tools, mutate host state, or claim that ASTON host routes are wired to it.
 */
export const ASTON_155_EXECUTION_SURFACE = Object.freeze([
  { method: "POST", path: "/v1/agents/plans", class: "plan_mutation", currentGate: "risk_and_access", safetyRequired: true },
  { method: "POST", path: "/v1/agents/plans/:id/approve", class: "human_approval", currentGate: "access_and_verified_approver", safetyRequired: true },
  { method: "POST", path: "/v1/agents/plans/:id/execute", class: "agent_execution", currentGate: "access_digest_single_use_approval_and_risk", safetyRequired: true },
  { method: "POST", path: "/v1/factory/run", class: "tool_execution", currentGate: "optional_payment_only", safetyRequired: true },
  { method: "POST", path: "/v1/sandbox/exec", class: "sandbox_execution", currentGate: "safety_do_proxy_contract_unverified", safetyRequired: true },
  { method: "POST", path: "/v1/mission", class: "mission_dispatch", currentGate: "direct_mission_do_dispatch", safetyRequired: true },
  { method: "POST", path: "/v1/simulation/commit", class: "simulation_commit", currentGate: "direct_simulation_do_dispatch", safetyRequired: true },
  { method: "POST", path: "/v1/recovery/diagnose", class: "recovery_dispatch", currentGate: "signed_mission_token_identity_and_payload_binding", safetyRequired: true },
  { method: "POST", path: "/v1/etl/enqueue", class: "queue_mutation", currentGate: "tenant_actor_presence", safetyRequired: true },
  { method: "POST", path: "/v1/rag/ingest", class: "data_mutation", currentGate: "tenant_namespace_and_binding_checks", safetyRequired: true },
  { method: "POST", path: "/v1/ontology/types", class: "data_mutation", currentGate: "binding_presence", safetyRequired: true },
  { method: "POST", path: "/v1/ontology/objects", class: "data_mutation", currentGate: "binding_presence_and_identity_scope", safetyRequired: true },
  { method: "POST", path: "/v1/ontology/links", class: "data_mutation", currentGate: "binding_presence_and_identity_scope", safetyRequired: true },
  { method: "POST", path: "/v1/constitution", class: "policy_mutation", currentGate: "tenant_scoped_persistence", safetyRequired: true },
  { method: "POST", path: "/v1/defense/approve", class: "human_approval", currentGate: "safety_do_decide", safetyRequired: true }
]);

export const EXECUTION_PERIMETER_REQUIRED_ORDER = Object.freeze([
  "authenticated_identity",
  "authoritative_tenant",
  "safety_interlock",
  "tenant_lifecycle_recheck",
  "action_specific_policy",
  "decision_only_result"
]);

function blocked(reason, decision = "deny") {
  return { ok: false, decision, reason, executable: false };
}

/**
 * The host must call this for EACH protected action, not once per multi-step
 * plan. The supplied gateway is the tenant-authority + SafetyInterlock bridge.
 */
export function createAstonExecutionPerimeter({ gateway } = {}) {
  if (!gateway || typeof gateway.evaluate !== "function") {
    return Object.freeze({
      async evaluateAction() { return blocked("EXECUTION_PERIMETER_GATEWAY_REQUIRED"); },
      async evaluatePlan() { return blocked("EXECUTION_PERIMETER_GATEWAY_REQUIRED"); }
    });
  }

  return Object.freeze({
    async evaluateAction({ identity, action, evaluatePolicy } = {}) {
      if (!action || typeof action.tool !== "string" || !action.tool ||
          typeof evaluatePolicy !== "function") {
        return blocked("ACTION_AND_POLICY_EVALUATOR_REQUIRED");
      }
      return gateway.evaluate({ identity, action, evaluateCapability: evaluatePolicy });
    },

    async evaluatePlan({ identity, planId, actions, evaluatePolicy } = {}) {
      if (typeof planId !== "string" || !planId ||
          !Array.isArray(actions) || actions.length === 0 ||
          actions.length > 100 || typeof evaluatePolicy !== "function") {
        return blocked("VALID_PLAN_ACTIONS_REQUIRED");
      }
      const decisions = [];
      for (let index = 0; index < actions.length; index++) {
        const action = actions[index];
        const result = await gateway.evaluate({
          identity,
          action: {
            ...action,
            context: {
              ...(action?.context && typeof action.context === "object" ? action.context : {}),
              planId,
              stepIndex: index
            }
          },
          evaluateCapability: async context => evaluatePolicy({
            ...context,
            planId,
            stepIndex: index,
            action
          })
        });
        decisions.push({
          stepIndex: index,
          action: action?.tool ?? null,
          ok: result.ok === true,
          decision: result.decision ?? "deny",
          reason: result.reason ?? "NO_DECISION",
          tenantId: result.tenantId
        });
        if (result.ok !== true || result.executable !== false) {
          return {
            ok: false,
            decision: result.decision === "review" ? "review" : "deny",
            reason: "PLAN_STOPPED_AT_PROTECTED_ACTION",
            failedStep: index,
            decisions,
            executable: false
          };
        }
      }
      return { ok: true, decision: "allow", reason: "ALL_ACTIONS_GATED", decisions, executable: false };
    }
  });
}

/**
 * Audit-only lookup. "covered_by_contract" means a host route could use the
 * perimeter contract; it does NOT mean the deployed route currently does.
 */
export function inspectExecutionSurface(method, path) {
  const route = ASTON_155_EXECUTION_SURFACE.find(item =>
    item.method === method && item.path === path
  );
  if (!route) return { known: false, safetyRequired: null, hostIntegrated: false };
  return {
    known: true,
    ...route,
    hostIntegrated: false,
    status: "HOST_INTEGRATION_NOT_PROVEN"
  };
}
