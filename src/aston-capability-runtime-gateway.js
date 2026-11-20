import { resolveAstonTenantRuntimeAuthority } from "./aston-tenant-runtime-authority.js";

/**
 * Common entry point for isolated capability evaluators.
 * Every request must pass authoritative identity/tenant resolution and the
 * existing ASTON SafetyInterlock before a capability evaluator is invoked.
 * Evaluators must remain decision-only and return executable:false.
 */
export function createAstonCapabilityRuntimeGateway({
  resolvePrincipalBinding,
  loadTenantLifecycle,
  safetyGate
} = {}) {
  return Object.freeze({
    async evaluate({ identity, action, evaluateCapability } = {}) {
      const authority = await resolveAstonTenantRuntimeAuthority({
        identity, resolvePrincipalBinding, loadTenantLifecycle
      });
      if (!authority.ok || authority.authorityVerified !== true) {
        return { ok: false, decision: authority.decision, reason: authority.reason, executable: false };
      }
      if (!safetyGate || typeof safetyGate.evaluate !== "function") {
        return { ok: false, decision: "deny", reason: "SAFETY_INTERLOCK_GATE_REQUIRED", executable: false };
      }
      const safety = await safetyGate.evaluate({ hostContext: authority, action });
      if (!safety || safety.ok !== true || safety.status !== "allowed") {
        return {
          ok: false,
          decision: safety?.status === "pending_approval" ? "review" : "deny",
          reason: safety?.reason || "SAFETY_INTERLOCK_BLOCKED",
          ...(safety?.approvalId ? { approvalId: safety.approvalId } : {}),
          executable: false
        };
      }
      if (typeof evaluateCapability !== "function") {
        return { ok: false, decision: "deny", reason: "CAPABILITY_EVALUATOR_REQUIRED", executable: false };
      }

      let capability;
      try {
        capability = await evaluateCapability({ hostContext: authority, action });
      } catch {
        return { ok: false, decision: "review", reason: "CAPABILITY_EVALUATION_FAILED", executable: false };
      }
      if (!capability || typeof capability !== "object" ||
          Array.isArray(capability) || capability.executable !== false) {
        return { ok: false, decision: "deny", reason: "CAPABILITY_RESULT_NOT_DECISION_ONLY", executable: false };
      }
      return {
        ok: capability.ok === true,
        decision: capability.decision || "review",
        reason: capability.reason || "CAPABILITY_EVALUATED",
        tenantId: authority.tenantId,
        lifecycleVersion: authority.lifecycleVersion,
        safetyStatus: safety.status,
        capability,
        executable: false
      };
    }
  });
}
