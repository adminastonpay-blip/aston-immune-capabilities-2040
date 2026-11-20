const CANONICAL_TENANT_ID = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const PRINCIPAL_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/;
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
export const TENANT_AUTHORITY_CLOCK_SKEW_MS = 30_000;

const LEGACY_TENANTS = new Set(["default", "ops"]);

function safeCorrelationId(value) {
  return typeof value === "string" && TOKEN.test(value) ? value : undefined;
}

function deny(reason, correlationId, decision = "deny") {
  return {
    ok: false,
    decision,
    reason,
    ...(correlationId ? { correlationId } : {}),
    executable: false
  };
}

function validTimeWindow(record, now, skewMs) {
  const hasStart = record.notBefore === undefined || Number.isFinite(record.notBefore);
  const hasEnd = record.expiresAt === undefined || Number.isFinite(record.expiresAt);
  if (!hasStart || !hasEnd) return "AUTHORITY_DATA_INCOMPLETE";
  if (record.notBefore !== undefined && now + skewMs < record.notBefore) return "ASSIGNMENT_NOT_YET_VALID";
  if (record.expiresAt !== undefined && now - skewMs > record.expiresAt) return "ASSIGNMENT_EXPIRED";
  return null;
}

/**
 * Evaluate a critical host identity request against an authoritative tenant
 * and membership provider. The provider is a privileged host dependency:
 * it must resolve records from the host's trusted source of truth and must
 * never echo caller-supplied values as proof.
 *
 * Tenant IDs are validated, not silently normalized. Canonical format:
 * lowercase ASCII letters/digits with internal hyphens, 1-64 characters.
 */
export async function evaluateTenantAuthorization({
  identity,
  request,
  resolveAuthority,
  now = Date.now(),
  clockSkewMs = TENANT_AUTHORITY_CLOCK_SKEW_MS,
  correlationId
} = {}) {
  const trace = safeCorrelationId(correlationId);

  if (!Number.isFinite(now) || !Number.isInteger(now) ||
      !Number.isFinite(clockSkewMs) || clockSkewMs < 0 ||
      clockSkewMs > TENANT_AUTHORITY_CLOCK_SKEW_MS) {
    return deny("INVALID_HOST_POLICY", trace);
  }

  if (!identity || typeof identity !== "object" ||
      !["access", "apikey", "sensor", "agent"].includes(identity.method) ||
      typeof identity.actor !== "string" || !PRINCIPAL_ID.test(identity.actor)) {
    return deny("UNTRUSTED_HOST_CONTEXT", trace);
  }

  const tenantId = identity.tenant;
  if (typeof tenantId !== "string" ||
      !CANONICAL_TENANT_ID.test(tenantId) ||
      LEGACY_TENANTS.has(tenantId) ||
      tenantId.startsWith("unassigned-")) {
    return deny("UNRESOLVED_TENANT_IDENTITY", trace);
  }

  if (!request || typeof request !== "object" ||
      request.tenantId !== tenantId ||
      request.resourceTenantId !== tenantId) {
    return deny("TENANT_MISMATCH", trace);
  }
  if (typeof request.audience !== "string" || !TOKEN.test(request.audience)) {
    return deny("AUDIENCE_MISMATCH", trace);
  }
  if (typeof request.capability !== "string" || !TOKEN.test(request.capability)) {
    return deny("CAPABILITY_NOT_AUTHORIZED", trace);
  }
  if (typeof resolveAuthority !== "function") {
    return deny("MISSING_TENANT_AUTHORITY", trace, "review");
  }

  let record;
  try {
    record = await resolveAuthority({
      principalId: identity.actor,
      authMethod: identity.method,
      tenantId
    });
  } catch {
    return deny("AUTHORITY_UNAVAILABLE", trace, "review");
  }

  if (!record || typeof record !== "object" ||
      !record.tenant || !record.membership ||
      typeof record.tenant.tenantId !== "string" ||
      typeof record.tenant.status !== "string" ||
      typeof record.membership.tenantId !== "string" ||
      typeof record.membership.principalId !== "string" ||
      typeof record.membership.status !== "string" ||
      !Array.isArray(record.membership.capabilities) ||
      !Array.isArray(record.membership.audiences)) {
    return deny("AUTHORITY_DATA_INCOMPLETE", trace, "review");
  }

  if (record.tenant.tenantId !== tenantId ||
      record.membership.tenantId !== tenantId ||
      record.membership.principalId !== identity.actor) {
    return deny("TENANT_MISMATCH", trace);
  }

  if (record.tenant.status !== "active") {
    const reason = ["revoked", "offboarded"].includes(record.tenant.status)
      ? "TENANT_REVOKED"
      : "TENANT_NOT_ACTIVE";
    return deny(reason, trace);
  }
  if (record.membership.status !== "active") {
    return deny("ACTOR_NOT_AUTHORIZED", trace);
  }

  const tenantWindow = validTimeWindow(record.tenant, now, clockSkewMs);
  if (tenantWindow) return deny(tenantWindow, trace);
  const membershipWindow = validTimeWindow(record.membership, now, clockSkewMs);
  if (membershipWindow) return deny(membershipWindow, trace);

  if (!record.membership.audiences.includes(request.audience)) {
    return deny("AUDIENCE_MISMATCH", trace);
  }
  if (!record.membership.capabilities.includes(request.capability)) {
    return deny("CAPABILITY_NOT_AUTHORIZED", trace);
  }

  return {
    ok: true,
    decision: "allow",
    reason: "AUTHORIZED",
    tenantId,
    principalId: identity.actor,
    authMethod: identity.method,
    audience: request.audience,
    capability: request.capability,
    ...(trace ? { correlationId: trace } : {}),
    executable: false
  };
}
