const TENANT_ID = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const LEGACY_TENANT_IDS = new Set(["default", "ops"]);
const PRINCIPAL_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/;
const SAFE_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const OPERATIONS = Object.freeze({
  create: "pending",
  activate: "active",
  suspend: "suspended",
  revoke: "revoked"
});

function validTenantId(value) {
  return typeof value === "string" && TENANT_ID.test(value) &&
    !LEGACY_TENANT_IDS.has(value) && !value.startsWith("unassigned-");
}

function validMutation(m) {
  return m && typeof m === "object" &&
    Object.hasOwn(OPERATIONS, m.operation) &&
    validTenantId(m.tenantId) &&
    typeof m.reason === "string" && m.reason.length >= 8 && m.reason.length <= 500 &&
    typeof m.idempotencyKey === "string" && SAFE_TOKEN.test(m.idempotencyKey) &&
    typeof m.actorPrincipalId === "string" && PRINCIPAL_ID.test(m.actorPrincipalId) &&
    ["platform", "delegated"].includes(m.actorScope) &&
    Number.isSafeInteger(m.occurredAt) && m.occurredAt >= 0 &&
    (m.correlationId === undefined || SAFE_TOKEN.test(m.correlationId)) &&
    m.targetStatus === OPERATIONS[m.operation];
}

function safeRow(row) {
  return row && typeof row.fingerprint === "string" &&
    typeof row.audit_event_id === "string" && SAFE_TOKEN.test(row.audit_event_id) &&
    validTenantId(row.tenant_id);
}

async function fingerprint(m) {
  const canonical = JSON.stringify([
    m.operation, m.tenantId, m.targetStatus, m.reason,
    m.actorPrincipalId, m.actorScope, m.correlationId ?? null
  ]);
  const bytes = new TextEncoder().encode(canonical);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map(x => x.toString(16).padStart(2, "0")).join("");
}

/**
 * Cloudflare D1 lifecycle store.
 *
 * Atomicity is provided by one D1 batch containing an INSERT and its readback.
 * SQLite triggers in migration 0002 apply tenant mutation, idempotency and audit
 * as consequences of that INSERT, inside D1's atomic batch transaction.
 * No BEGIN/COMMIT statements or multi-request pseudo-transactions are used.
 *
 * Required D1 binding methods: prepare(sql).bind(...), batch(statements).
 * createId must return a unique, safe audit event identifier.
 */
export function createD1TenantLifecycleStore({ db, createId } = {}) {
  if (!db || typeof db.prepare !== "function" || typeof db.batch !== "function") {
    throw new TypeError("Cloudflare D1 binding with prepare() and batch() is required");
  }
  if (typeof createId !== "function") {
    throw new TypeError("trusted audit event ID factory is required");
  }

  return Object.freeze({
    async applyTenantLifecycleCommand(m) {
      if (!validMutation(m)) throw new TypeError("invalid lifecycle mutation");
      const digest = await fingerprint(m);
      const auditEventId = createId();
      if (typeof auditEventId !== "string" || !SAFE_TOKEN.test(auditEventId)) {
        throw new TypeError("invalid generated audit event identifier");
      }

      const insert = db.prepare(`
        INSERT INTO aston_tenant_lifecycle_idempotency (
          actor_principal_id, idempotency_key, fingerprint, audit_event_id,
          tenant_id, operation, target_status, actor_scope, reason,
          correlation_id, occurred_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(actor_principal_id, idempotency_key) DO NOTHING
      `).bind(
        m.actorPrincipalId, m.idempotencyKey, digest, auditEventId,
        m.tenantId, m.operation, m.targetStatus, m.actorScope, m.reason,
        m.correlationId ?? null, m.occurredAt
      );

      const readback = db.prepare(`
        SELECT fingerprint, audit_event_id, tenant_id
        FROM aston_tenant_lifecycle_idempotency
        WHERE actor_principal_id = ? AND idempotency_key = ?
      `).bind(m.actorPrincipalId, m.idempotencyKey);

      const results = await db.batch([insert, readback]);
      if (!Array.isArray(results) || results.length !== 2) {
        throw new Error("invalid D1 batch response");
      }
      const rows = results[1]?.results;
      if (!Array.isArray(rows) || rows.length !== 1 || !safeRow(rows[0])) {
        throw new Error("missing or corrupt D1 idempotency readback");
      }
      const row = rows[0];
      if (row.fingerprint !== digest || row.tenant_id !== m.tenantId) {
        return { status: "idempotency_conflict" };
      }

      const inserted = Number(results[0]?.meta?.changes);
      if (inserted === 1) {
        if (row.audit_event_id !== auditEventId) {
          throw new Error("D1 audit identifier mismatch");
        }
        return { status: "applied", auditEventId: row.audit_event_id };
      }
      if (inserted === 0) {
        return { status: "replayed", auditEventId: row.audit_event_id };
      }
      throw new Error("invalid D1 insert result");
    }
  });
}
