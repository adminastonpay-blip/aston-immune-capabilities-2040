import { createAstonCapabilityRuntimeGateway } from "./aston-capability-runtime-gateway.js";
import { createAstonExecutionPerimeter } from "./aston-execution-perimeter.js";

const ACCESS_ISSUER = /^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/;
const PRINCIPAL = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/;

function blocked(reason, decision = "review") {
  return { ok: false, decision, reason, executable: false };
}

/**
 * Compatibility boundary for the current ASTON OS 15.5 Identity interface.
 * resolveVerifiedPrincipal is privileged host code. For Access it MUST
 * recover issuer+subject from verified JWT context; for sensors it MUST
 * return a stable credentialId from the authenticated credential record.
 * Never implement it by copying request headers/body.
 * This bridge is decision-only and never dispatches host operations.
 */
export function createAston155HostExecutionBridge({
  resolveVerifiedPrincipal, resolvePrincipalBinding, loadTenantLifecycle, safetyGate
} = {}) {
  const gateway = createAstonCapabilityRuntimeGateway({ resolvePrincipalBinding, loadTenantLifecycle, safetyGate });
  const perimeter = createAstonExecutionPerimeter({ gateway });
  return Object.freeze({
    async evaluateAction({ request, identity, action, evaluatePolicy } = {}) {
      if (!identity || typeof identity !== "object" ||
          !["access", "apikey", "sensor"].includes(identity.method) ||
          typeof identity.actor !== "string" || !PRINCIPAL.test(identity.actor) ||
          typeof identity.tenant !== "string" || !Array.isArray(identity.roles) ||
          !identity.roles.every(role => typeof role === "string")) {
        return blocked("ASTON_155_AUTHENTICATED_IDENTITY_REQUIRED", "deny");
      }
      if (typeof resolveVerifiedPrincipal !== "function") return blocked("ASTON_155_VERIFIED_PRINCIPAL_PROVIDER_REQUIRED");
      let verified;
      try { verified = await resolveVerifiedPrincipal({ request, identity }); }
      catch { return blocked("ASTON_155_VERIFIED_PRINCIPAL_UNAVAILABLE"); }
      if (!verified || typeof verified !== "object" || verified.actor !== identity.actor || verified.method !== identity.method) {
        return blocked("ASTON_155_VERIFIED_PRINCIPAL_MISMATCH", "deny");
      }
      const enriched = { actor: identity.actor, method: identity.method, tenant: identity.tenant, roles: [...identity.roles], clearance: identity.clearance };
      if (identity.method === "access") {
        if (typeof verified.issuer !== "string" || !ACCESS_ISSUER.test(verified.issuer) ||
            typeof verified.subject !== "string" || !PRINCIPAL.test(verified.subject)) {
          return blocked("ASTON_155_ACCESS_ISSUER_SUBJECT_UNAVAILABLE");
        }
        enriched.issuer = verified.issuer;
        enriched.subject = verified.subject;
      } else if (identity.method === "apikey") {
        if (!identity.actor.startsWith("apikey:")) return blocked("ASTON_155_API_KEY_FINGERPRINT_REQUIRED");
      } else if (identity.method === "sensor") {
        if (typeof verified.credentialId !== "string" || !PRINCIPAL.test(verified.credentialId)) {
          return blocked("ASTON_155_SENSOR_CREDENTIAL_ID_UNAVAILABLE");
        }
        enriched.credentialId = verified.credentialId;
      }
      return perimeter.evaluateAction({ identity: enriched, action, evaluatePolicy });
    }
  });
}