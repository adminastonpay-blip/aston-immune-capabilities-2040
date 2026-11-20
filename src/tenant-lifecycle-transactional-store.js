const TENANT_ID = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const PRINCIPAL_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/;
const SAFE_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const STATUSES = new Set(["pending", "active", "suspended", "revoked", "offboarded"]);
const TRANSITIONS = Object.freeze({
  create: { from: [null], to: "pending" },
  activate: { from: ["pending", "suspended"], to: "active" },
  suspend: { from: ["active"], to: "suspended" },
  revoke: { from: ["pending", "active", "suspended"], to: "revoked" }
});

function validMutation(value) {
  return value && typeof value === "object" &&
    Object.hasOwn(TRANSITIONS, value.operation) &&
    typeof value.tenantId === "string" && TENANT_ID.test(value.tenantId) &&
    typeof value.reason === "string" && value.reason.length >= 8 && value.reason.length <= 500 &&
    typeof value.idempotencyKey === "string" && SAFE_TOKEN.test(value.idempotencyKey) &&
    typeof value.actorPrincipalId === "string" && PRINCIPAL_ID.test(value.actorPrincipalId) &&
    ["platform", "delegated"].includes(value.actorScope) &&
    Number.isSafeInteger(value.occurredAt) && value.occurredAt >= 0 &&
    (value.correlationId === undefined || SAFE_TOKEN.test(value.correlationId));
}

function fingerprint(m) {
  return JSON.stringify([
    m.operation, m.tenantId, m.targetStatus, m.reason,
    m.actorPrincipalId, m.actorScope, m.correlationId ?? null
  ]);
}

function validTransaction(tx) {
  return tx && typeof tx.getTenant === "function" &&
    typeof tx.insertTenant === "function" && typeof tx.updateTenant === "function" &&
    typeof tx.getIdempotency === "function" && typeof tx.insertIdempotency === "function" &&
    typeof tx.appendAuditEvent === "function";
}

/**
 * Creates the persistence adapter consumed by executeTenantLifecycleCommand.
 *
 * The injected transaction provider MUST provide serializable isolation (or an
 * equivalent per-key lock/unique-constraint strategy), rollback on any thrown
 * error, and atomic commit of every operation in the callback. The adapter
 * deliberately does not pretend that sequential D1 statements are a transaction.
 *
 * Transaction API:
 * - getTenant(tenantId) -> { tenantId, status, version } | null
 * - insertTenant(record) -> void
 * - updateTenant(tenantId, expectedVersion, patch) -> boolean
 * - getIdempotency(scopeKey) -> { fingerprint, auditEventId } | null
 * - insertIdempotency(scopeKey, record) -> void
 * - appendAuditEvent(event) -> safe event ID string
 */
export function createTransactionalTenantLifecycleStore({ transaction } = {}) {
  if (typeof transaction !== "function") throw new TypeError("transaction provider is required");

  return Object.freeze({
    async applyTenantLifecycleCommand(mutation) {
      if (!validMutation(mutation) ||
          mutation.targetStatus !== TRANSITIONS[mutation.operation].to) {
        throw new TypeError("invalid lifecycle mutation");
      }

      return transaction(async tx => {
        if (!validTransaction(tx)) throw new TypeError("invalid transaction interface");

        const scopeKey = mutation.actorPrincipalId + ":" + mutation.idempotencyKey;
        const digest = fingerprint(mutation);
        const prior = await tx.getIdempotency(scopeKey);
        if (prior) {
          if (prior.fingerprint !== digest) return { status: "idempotency_conflict" };
          if (typeof prior.auditEventId !== "string" || !SAFE_TOKEN.test(prior.auditEventId)) {
            throw new Error("corrupt idempotency record");
          }
          return { status: "replayed", auditEventId: prior.auditEventId };
        }

        const current = await tx.getTenant(mutation.tenantId);
        const transition = TRANSITIONS[mutation.operation];
        const currentStatus = current ? current.status : null;
        if (!transition.from.includes(currentStatus)) {
          return { status: "transition_rejected" };
        }

        if (currentStatus === null) {
          await tx.insertTenant({
            tenantId: mutation.tenantId,
            status: transition.to,
            version: 1,
            createdAt: mutation.occurredAt,
            updatedAt: mutation.occurredAt
          });
        } else {
          if (!STATUSES.has(current.status) || !Number.isSafeInteger(current.version) ||
              current.version < 1) throw new Error("corrupt tenant record");
          const updated = await tx.updateTenant(mutation.tenantId, current.version, {
            status: transition.to,
            version: current.version + 1,
            updatedAt: mutation.occurredAt
          });
          if (updated !== true) throw new Error("tenant version conflict");
        }

        const auditEventId = await tx.appendAuditEvent({
          eventType: "tenant.lifecycle." + mutation.operation,
          tenantId: mutation.tenantId,
          fromStatus: currentStatus,
          toStatus: transition.to,
          actorPrincipalId: mutation.actorPrincipalId,
          actorScope: mutation.actorScope,
          reason: mutation.reason,
          occurredAt: mutation.occurredAt,
          ...(mutation.correlationId ? { correlationId: mutation.correlationId } : {})
        });
        if (typeof auditEventId !== "string" || !SAFE_TOKEN.test(auditEventId)) {
          throw new Error("invalid audit event identifier");
        }

        await tx.insertIdempotency(scopeKey, {
          fingerprint: digest,
          auditEventId,
          tenantId: mutation.tenantId,
          createdAt: mutation.occurredAt
        });
        return { status: "applied", auditEventId };
      });
    }
  });
}
