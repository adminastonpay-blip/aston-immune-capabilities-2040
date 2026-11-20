const TENANT_ID = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const PRINCIPAL_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/;
const SAFE_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const OPERATIONS = new Set(["create", "activate", "suspend", "revoke"]);
const REQUIRED_CAPABILITY = {
  create: "tenant.create",
  activate: "tenant.activate",
  suspend: "tenant.suspend",
  revoke: "tenant.revoke"
};
const LEGACY_IDS = new Set(["default", "ops"]);

function failure(reason, correlationId, decision = "deny") {
  return { ok: false, decision, reason, ...(correlationId ? { correlationId } : {}), executable: false };
}

function validTenantId(value) {
  return typeof value === "string" && TENANT_ID.test(value) &&
    !LEGACY_IDS.has(value) && !value.startsWith("unassigned-");
}

function safeToken(value) {
  return typeof value === "string" && SAFE_TOKEN.test(value);
}

function normalizeCommand(input) {
  if (!input || typeof input !== "object" || !OPERATIONS.has(input.operation)) return null;
  if (!validTenantId(input.tenantId)) return null;
  if (typeof input.reason !== "string" || input.reason.trim().length < 8 || input.reason.length > 500) return null;
  if (!safeToken(input.idempotencyKey)) return null;
  return {
    operation: input.operation,
    tenantId: input.tenantId,
    reason: input.reason.trim(),
    idempotencyKey: input.idempotencyKey
  };
}

function targetStatus(operation) {
  return { create: "pending", activate: "active", suspend: "suspended", revoke: "revoked" }[operation];
}

/**
 * Execute an administrative tenant lifecycle command.
 *
 * authorizeAdmin is a privileged host callback. It must derive the administrator
 * from authenticated host context and enforce platform/tenant administration policy.
 * store.applyTenantLifecycleCommand must atomically enforce idempotency, apply the
 * state transition and append its audit event in one transaction.
 *
 * This module never performs persistence itself and never executes tenant workloads.
 */
export async function executeTenantLifecycleCommand({
  adminIdentity,
  command: input,
  authorizeAdmin,
  store,
  now = Date.now(),
  correlationId
} = {}) {
  const trace = safeToken(correlationId) ? correlationId : undefined;
  if (!Number.isSafeInteger(now) || now < 0) return failure("INVALID_HOST_TIME", trace);

  const command = normalizeCommand(input);
  if (!command) return failure("INVALID_LIFECYCLE_COMMAND", trace);
  if (!adminIdentity || typeof adminIdentity !== "object" ||
      typeof adminIdentity.actor !== "string" || !PRINCIPAL_ID.test(adminIdentity.actor)) {
    return failure("UNTRUSTED_ADMIN_CONTEXT", trace);
  }
  if (typeof authorizeAdmin !== "function") return failure("MISSING_ADMIN_AUTHORITY", trace, "review");
  if (!store || typeof store.applyTenantLifecycleCommand !== "function") {
    return failure("MISSING_LIFECYCLE_STORE", trace, "review");
  }

  let authorization;
  try {
    authorization = await authorizeAdmin({
      principalId: adminIdentity.actor,
      operation: command.operation,
      capability: REQUIRED_CAPABILITY[command.operation],
      tenantId: command.tenantId
    });
  } catch {
    return failure("ADMIN_AUTHORITY_UNAVAILABLE", trace, "review");
  }

  if (!authorization || authorization.authorized !== true ||
      authorization.status !== "active" ||
      authorization.principalId !== adminIdentity.actor ||
      !["platform", "tenant"].includes(authorization.scope)) {
    return failure("ADMIN_NOT_AUTHORIZED", trace);
  }
  if (authorization.scope === "tenant" &&
      (!validTenantId(authorization.tenantId) ||
       authorization.tenantId !== command.tenantId ||
       adminIdentity.tenantId !== command.tenantId)) {
    return failure("ADMIN_SCOPE_MISMATCH", trace);
  }
  if (authorization.scope === "tenant" && adminIdentity.tenantId === command.tenantId) {
    return failure("SELF_TENANT_ADMIN_FORBIDDEN", trace);
  }

  const mutation = {
    operation: command.operation,
    tenantId: command.tenantId,
    targetStatus: targetStatus(command.operation),
    reason: command.reason,
    idempotencyKey: command.idempotencyKey,
    actorPrincipalId: adminIdentity.actor,
    actorScope: authorization.scope,
    correlationId: trace,
    occurredAt: now
  };

  let result;
  try {
    result = await store.applyTenantLifecycleCommand(mutation);
  } catch {
    return failure("LIFECYCLE_STORE_UNAVAILABLE", trace, "review");
  }

  if (!result || typeof result !== "object") {
    return failure("LIFECYCLE_STORE_INVALID_RESPONSE", trace, "review");
  }
  if (result.status === "idempotency_conflict") {
    return failure("IDEMPOTENCY_CONFLICT", trace);
  }
  if (result.status === "transition_rejected") {
    return failure("LIFECYCLE_TRANSITION_REJECTED", trace);
  }
  if (result.status === "applied" || result.status === "replayed") {
    if (typeof result.auditEventId !== "string" || !SAFE_TOKEN.test(result.auditEventId)) {
      return failure("LIFECYCLE_STORE_INVALID_RESPONSE", trace, "review");
    }
    return {
      ok: true,
      decision: "recorded",
      reason: result.status === "replayed" ? "IDEMPOTENT_REPLAY" : "LIFECYCLE_MUTATION_RECORDED",
      operation: command.operation,
      tenantId: command.tenantId,
      status: targetStatus(command.operation),
      auditEventId: result.auditEventId,
      ...(trace ? { correlationId: trace } : {}),
      executable: false
    };
  }
  return failure("LIFECYCLE_STORE_INVALID_RESPONSE", trace, "review");
}

export const TENANT_LIFECYCLE_OPERATIONS = Object.freeze({
  create: "tenant.create",
  activate: "tenant.activate",
  suspend: "tenant.suspend",
  revoke: "tenant.revoke"
});
