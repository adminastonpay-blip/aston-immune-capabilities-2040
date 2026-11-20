const TENANT_ID = /^[A-Za-z0-9_-]{1,64}$/;
const AUDIENCE_ID = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * Adapt an ASTON OS authenticated Identity into the host context expected by
 * the device-attestation orchestrator.
 *
 * IMPORTANT: Identity.tenant is not, by itself, an authoritative tenant
 * lifecycle decision. The privileged authorizeIdentity callback must verify
 * the identity against the host's authoritative credential/tenant binding
 * and require tenant status exactly "active". Do not implement this callback
 * by echoing values from identity or request input.
 *
 * attestationAudience is a dedicated trusted host configuration value. It is
 * deliberately separate from Cloudflare Access JWT audience (ACCESS_AUD).
 */
export async function resolveAstonDeviceHostContext({
  identity,
  attestationAudience,
  authorizeIdentity
} = {}) {
  const deny = (reason) => ({ ok: false, decision: "deny", reason, executable: false });

  if (!identity || typeof identity !== "object" ||
      identity.method === "public" ||
      !["access", "apikey", "sensor"].includes(identity.method) ||
      typeof identity.actor !== "string" || identity.actor.length < 1 ||
      identity.actor.length > 200 ||
      typeof identity.tenant !== "string" || !TENANT_ID.test(identity.tenant) ||
      identity.tenant.startsWith("unassigned-") ||
      !Array.isArray(identity.roles) ||
      !identity.roles.every((role) => typeof role === "string")) {
    return deny("authenticated_aston_identity_required");
  }
  if (typeof attestationAudience !== "string" || !AUDIENCE_ID.test(attestationAudience)) {
    return deny("dedicated_attestation_audience_required");
  }
  if (typeof authorizeIdentity !== "function") {
    return deny("authoritative_identity_authorizer_required");
  }

  let authority;
  try {
    authority = await authorizeIdentity({
      actor: identity.actor,
      method: identity.method,
      tenant: identity.tenant,
      roles: [...identity.roles]
    });
  } catch {
    return { ok: false, decision: "review", reason: "authoritative_identity_check_failed", executable: false };
  }

  if (!authority || authority.status !== "active" ||
      authority.tenantId !== identity.tenant ||
      authority.principalId !== identity.actor) {
    return deny("identity_or_tenant_not_authoritatively_active");
  }

  return {
    ok: true,
    decision: "host_context_resolved",
    context: Object.freeze({
      tenantId: authority.tenantId,
      audience: attestationAudience,
      principalId: authority.principalId,
      authMethod: identity.method,
      roles: Object.freeze([...identity.roles]),
      tenantLifecycleStatus: "active"
    }),
    executable: false
  };
}
