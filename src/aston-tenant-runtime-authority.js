const TENANT_ID = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const METHODS = new Set(["access", "apikey", "sensor"]);
const CLEARANCES = new Set(["public", "internal", "confidential", "secret"]);

function deny(reason, decision = "deny") {
  return { ok: false, decision, reason, executable: false };
}

/**
 * D1 read-only adapter for the authoritative tenant lifecycle table.
 * It does not create tenants, mutate status, or apply migrations.
 */
export function createD1TenantLifecycleReader(db) {
  if (!db || typeof db.prepare !== "function") {
    throw new TypeError("D1 database binding is required");
  }
  return async function loadTenantLifecycle(tenantId) {
    if (typeof tenantId !== "string" || !TENANT_ID.test(tenantId)) return null;
    const row = await db.prepare(
      "SELECT tenant_id, status, version, created_at, updated_at FROM aston_tenants WHERE tenant_id = ?"
    ).bind(tenantId).first();
    if (!row) return null;
    return {
      tenantId: row.tenant_id,
      status: row.status,
      lifecycleVersion: Number(row.version),
      createdAt: Number(row.created_at),
      updatedAt: Number(row.updated_at)
    };
  };
}

/**
 * Resolves the existing ASTON Identity only after a privileged credential
 * binding lookup and an authoritative tenant lifecycle read.
 *
 * resolvePrincipalBinding must query a trusted credential/issuer-subject
 * registry. It must never echo identity.tenant or caller input as authority.
 * Cloudflare Access requires issuer+subject; API keys require their existing
 * stable fingerprint actor; sensors require a credentialId added by trusted
 * authentication code (the current static "lb-sensor" actor is insufficient).
 */
export async function resolveAstonTenantRuntimeAuthority({
  identity,
  resolvePrincipalBinding,
  loadTenantLifecycle
} = {}) {
  if (!identity || typeof identity !== "object" ||
      !METHODS.has(identity.method) ||
      typeof identity.actor !== "string" || !identity.actor ||
      identity.actor.length > 200) {
    return deny("AUTHENTICATED_HOST_IDENTITY_REQUIRED");
  }
  if (typeof resolvePrincipalBinding !== "function" ||
      typeof loadTenantLifecycle !== "function") {
    return deny("AUTHORITATIVE_TENANT_PROVIDERS_REQUIRED", "review");
  }

  if (identity.method === "access" &&
      (typeof identity.issuer !== "string" || !identity.issuer ||
       typeof identity.subject !== "string" || !identity.subject)) {
    return deny("ACCESS_ISSUER_SUBJECT_REQUIRED", "review");
  }
  if (identity.method === "apikey" && !identity.actor.startsWith("apikey:")) {
    return deny("STABLE_API_KEY_FINGERPRINT_REQUIRED", "review");
  }
  if (identity.method === "sensor" &&
      (typeof identity.credentialId !== "string" || !identity.credentialId)) {
    return deny("SENSOR_CREDENTIAL_BINDING_REQUIRED", "review");
  }

  let binding;
  try {
    binding = await resolvePrincipalBinding({
      method: identity.method,
      actor: identity.actor,
      issuer: identity.method === "access" ? identity.issuer : undefined,
      subject: identity.method === "access" ? identity.subject : undefined,
      credentialId: identity.method === "sensor" ? identity.credentialId : undefined
    });
  } catch {
    return deny("PRINCIPAL_BINDING_UNAVAILABLE", "review");
  }

  if (!binding || binding.status !== "active" ||
      binding.method !== identity.method ||
      typeof binding.tenantId !== "string" || !TENANT_ID.test(binding.tenantId) ||
      ["default", "ops"].includes(binding.tenantId) ||
      binding.tenantId.startsWith("unassigned-") ||
      !Array.isArray(binding.roles) ||
      !binding.roles.every(role => typeof role === "string" && role.length > 0 && role.length <= 40) ||
      !CLEARANCES.has(binding.clearance)) {
    return deny("PRINCIPAL_BINDING_NOT_ACTIVE_OR_INVALID");
  }

  if (identity.method === "access" &&
      (binding.issuer !== identity.issuer || binding.subject !== identity.subject ||
       binding.tenantId !== identity.tenant)) {
    return deny("ACCESS_ISSUER_SUBJECT_TENANT_MISMATCH");
  }
  if (identity.method === "apikey" && binding.actor !== identity.actor) {
    return deny("API_KEY_PRINCIPAL_MISMATCH");
  }
  if (identity.method === "sensor" && binding.credentialId !== identity.credentialId) {
    return deny("SENSOR_CREDENTIAL_MISMATCH");
  }

  let tenant;
  try {
    tenant = await loadTenantLifecycle(binding.tenantId);
  } catch {
    return deny("TENANT_LIFECYCLE_UNAVAILABLE", "review");
  }

  if (!tenant || tenant.tenantId !== binding.tenantId ||
      !Number.isSafeInteger(tenant.lifecycleVersion) || tenant.lifecycleVersion < 1) {
    return deny("TENANT_LIFECYCLE_RECORD_INVALID", "review");
  }
  if (tenant.status !== "active") {
    return deny(tenant.status === "revoked" || tenant.status === "offboarded"
      ? "TENANT_REVOKED" : "TENANT_NOT_ACTIVE");
  }

  const authorizedIdentity = Object.freeze({
    actor: identity.actor,
    method: identity.method,
    tenant: tenant.tenantId,
    roles: Object.freeze([...binding.roles]),
    clearance: binding.clearance,
    ...(binding.plan ? { plan: binding.plan } : {})
  });

  return {
    ok: true,
    decision: "authorized",
    reason: "ACTIVE_PRINCIPAL_AND_TENANT_VERIFIED",
    tenantId: tenant.tenantId,
    lifecycleVersion: tenant.lifecycleVersion,
    principalId: identity.actor,
    authMethod: identity.method,
    identity: authorizedIdentity,
    authorityVerified: true,
    executable: false
  };
}

/**
 * Adapter for the existing ASTON SafetyInterlock Durable Object contract.
 * It accepts only a host context produced by the authority adapter above.
 * No action is executed here; callers must treat anything except status
 * "allowed" as a hard stop. Missing DO, timeout, malformed response, or
 * unknown contract/status fails closed.
 */
export function createAstonSafetyInterlockGate({ SAFETY, timeoutMs = 2000 } = {}) {
  const blocked = reason => ({ ok: false, status: "denied", reason, executable: false });
  if (!SAFETY || typeof SAFETY.idFromName !== "function" ||
      typeof SAFETY.get !== "function" ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) {
    return Object.freeze({ evaluate: async () => blocked("SAFETY_INTERLOCK_UNAVAILABLE") });
  }

  return Object.freeze({
    async evaluate({ hostContext, action } = {}) {
      if (!hostContext || hostContext.authorityVerified !== true ||
          hostContext.decision !== "authorized" ||
          hostContext.identity?.tenant !== hostContext.tenantId ||
          !TENANT_ID.test(hostContext.tenantId ?? "") ||
          !Number.isSafeInteger(hostContext.lifecycleVersion) ||
          hostContext.lifecycleVersion < 1 ||
          !action || typeof action !== "object" ||
          typeof action.tool !== "string" || !action.tool ||
          action.tool.length > 128) {
        return blocked("TRUSTED_TENANT_CONTEXT_AND_ACTION_REQUIRED");
      }

      let stub;
      try {
        stub = SAFETY.get(SAFETY.idFromName(hostContext.tenantId));
      } catch {
        return blocked("SAFETY_INTERLOCK_UNAVAILABLE");
      }

      const controller = new AbortController();
      let timeout;
      try {
        const request = stub.fetch("https://do/evaluate", {
          method: "POST",
          headers: { "content-type": "application/json" },
          signal: controller.signal,
          body: JSON.stringify({ action, identity: hostContext.identity })
        }).then(async response => {
          if (!response?.ok) return blocked("SAFETY_INTERLOCK_REQUEST_FAILED");
          const payload = await response.json();
          if (!payload || typeof payload !== "object" || Array.isArray(payload) ||
              payload.contract_version !== "1" ||
              !["allowed", "denied", "pending_approval"].includes(payload.status) ||
              (payload.status === "pending_approval" &&
               (typeof payload.approval_id !== "string" || !payload.approval_id))) {
            return blocked("SAFETY_INTERLOCK_RESPONSE_INVALID");
          }
          return {
            ok: payload.status === "allowed",
            status: payload.status,
            ...(payload.approval_id ? { approvalId: payload.approval_id } : {}),
            ...(payload.policy ? { policy: payload.policy } : {}),
            reason: payload.status === "allowed" ? "SAFETY_INTERLOCK_ALLOWED" : "SAFETY_INTERLOCK_BLOCKED",
            executable: false
          };
        });
        const deadline = new Promise(resolve => {
          timeout = setTimeout(() => {
            controller.abort();
            resolve(blocked("SAFETY_INTERLOCK_TIMEOUT"));
          }, timeoutMs);
        });
        return await Promise.race([request, deadline]);
      } catch {
        return blocked("SAFETY_INTERLOCK_UNAVAILABLE");
      } finally {
        if (timeout !== undefined) clearTimeout(timeout);
      }
    }
  });
}
