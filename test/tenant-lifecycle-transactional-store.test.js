import test from "node:test";
import assert from "node:assert/strict";
import { createTransactionalTenantLifecycleStore } from "../src/tenant-lifecycle-transactional-store.js";

function fixture() {
  const tenants = new Map();
  const idempotency = new Map();
  const audit = [];
  let sequence = 0;
  const transaction = async callback => {
    // Test-only transactional fixture: snapshot and rollback on error.
    const before = structuredClone({ tenants: [...tenants], idempotency: [...idempotency], audit });
    const tx = {
      getTenant: async id => tenants.get(id) ?? null,
      insertTenant: async record => {
        if (tenants.has(record.tenantId)) throw new Error("tenant uniqueness conflict");
        tenants.set(record.tenantId, structuredClone(record));
      },
      updateTenant: async (id, version, patch) => {
        const current = tenants.get(id);
        if (!current || current.version !== version) return false;
        tenants.set(id, { ...current, ...patch });
        return true;
      },
      getIdempotency: async key => idempotency.get(key) ?? null,
      insertIdempotency: async (key, record) => {
        if (idempotency.has(key)) throw new Error("idempotency uniqueness conflict");
        idempotency.set(key, structuredClone(record));
      },
      appendAuditEvent: async event => {
        const id = "audit-" + (++sequence);
        audit.push({ id, ...structuredClone(event) });
        return id;
      }
    };
    try { return await callback(tx); }
    catch (error) {
      tenants.clear(); for (const [k,v] of before.tenants) tenants.set(k,v);
      idempotency.clear(); for (const [k,v] of before.idempotency) idempotency.set(k,v);
      audit.splice(0, audit.length, ...before.audit);
      throw error;
    }
  };
  return { store: createTransactionalTenantLifecycleStore({ transaction }), tenants, idempotency, audit };
}

const base = {
  operation: "create", tenantId: "tenant-alpha", targetStatus: "pending",
  reason: "Approved tenant onboarding", idempotencyKey: "idem-001",
  actorPrincipalId: "platform-admin:1", actorScope: "platform",
  correlationId: "trace-001", occurredAt: 1_800_000_000_000
};

test("creates pending tenant, idempotency record and audit in one transaction", async () => {
  const f = fixture();
  const result = await f.store.applyTenantLifecycleCommand(base);
  assert.deepEqual(result, { status: "applied", auditEventId: "audit-1" });
  assert.equal(f.tenants.get("tenant-alpha").status, "pending");
  assert.equal(f.tenants.get("tenant-alpha").version, 1);
  assert.equal(f.idempotency.size, 1);
  assert.equal(f.audit.length, 1);
  assert.equal(f.audit[0].eventType, "tenant.lifecycle.create");
});

test("replays the same command without a second state change or audit event", async () => {
  const f = fixture();
  const first = await f.store.applyTenantLifecycleCommand(base);
  const second = await f.store.applyTenantLifecycleCommand(base);
  assert.deepEqual(second, { status: "replayed", auditEventId: first.auditEventId });
  assert.equal(f.tenants.get("tenant-alpha").version, 1);
  assert.equal(f.audit.length, 1);
});

test("rejects reuse of the same actor idempotency key for a different payload", async () => {
  const f = fixture();
  await f.store.applyTenantLifecycleCommand(base);
  const result = await f.store.applyTenantLifecycleCommand({ ...base, reason: "Different approved reason" });
  assert.deepEqual(result, { status: "idempotency_conflict" });
  assert.equal(f.audit.length, 1);
});

test("idempotency scope is isolated by administrator principal", async () => {
  const f = fixture();
  await f.store.applyTenantLifecycleCommand(base);
  const other = await f.store.applyTenantLifecycleCommand({
    ...base, actorPrincipalId: "platform-admin:2"
  });
  assert.equal(other.status, "transition_rejected");
});

test("enforces lifecycle transitions and immutable terminal states", async () => {
  const f = fixture();
  await f.store.applyTenantLifecycleCommand(base);
  assert.equal((await f.store.applyTenantLifecycleCommand({
    ...base, operation: "suspend", targetStatus: "suspended", idempotencyKey: "idem-002"
  })).status, "transition_rejected");
  assert.equal((await f.store.applyTenantLifecycleCommand({
    ...base, operation: "activate", targetStatus: "active", idempotencyKey: "idem-003"
  })).status, "applied");
  assert.equal((await f.store.applyTenantLifecycleCommand({
    ...base, operation: "suspend", targetStatus: "suspended", idempotencyKey: "idem-004"
  })).status, "applied");
  assert.equal((await f.store.applyTenantLifecycleCommand({
    ...base, operation: "revoke", targetStatus: "revoked", idempotencyKey: "idem-005"
  })).status, "applied");
  assert.equal((await f.store.applyTenantLifecycleCommand({
    ...base, operation: "activate", targetStatus: "active", idempotencyKey: "idem-006"
  })).status, "transition_rejected");
  assert.equal(f.tenants.get("tenant-alpha").status, "revoked");
  assert.equal(f.audit.length, 4);
});

test("records version increments on each successful transition", async () => {
  const f = fixture();
  await f.store.applyTenantLifecycleCommand(base);
  await f.store.applyTenantLifecycleCommand({
    ...base, operation: "activate", targetStatus: "active", idempotencyKey: "idem-002"
  });
  assert.equal(f.tenants.get("tenant-alpha").version, 2);
});

test("rolls back tenant and audit writes when idempotency persistence fails", async () => {
  const f = fixture();
  const transaction = async callback => callback({
    getTenant: async () => null,
    insertTenant: async () => {},
    updateTenant: async () => true,
    getIdempotency: async () => null,
    appendAuditEvent: async () => "audit-valid",
    insertIdempotency: async () => { throw new Error("storage failure"); }
  });
  const store = createTransactionalTenantLifecycleStore({ transaction });
  await assert.rejects(store.applyTenantLifecycleCommand(base), /storage failure/);
  assert.equal(f.tenants.size, 0);
  assert.equal(f.audit.length, 0);
});

test("fails closed on malformed transaction providers and mutations", async () => {
  assert.throws(() => createTransactionalTenantLifecycleStore({}), /transaction provider/);
  const store = createTransactionalTenantLifecycleStore({ transaction: async fn => fn({}) });
  await assert.rejects(store.applyTenantLifecycleCommand(base), /transaction interface/);
  await assert.rejects(store.applyTenantLifecycleCommand({ ...base, targetStatus: "active" }), /invalid lifecycle mutation/);
});

test("does not accept malformed persisted records or unsafe audit identifiers", async () => {
  const badTenantStore = createTransactionalTenantLifecycleStore({
    transaction: async fn => fn({
      getTenant: async () => ({ status: "unknown", version: 1 }),
      insertTenant: async () => {}, updateTenant: async () => true,
      getIdempotency: async () => null, insertIdempotency: async () => {},
      appendAuditEvent: async () => "audit-1"
    })
  });
  await assert.rejects(badTenantStore.applyTenantLifecycleCommand({
    ...base, operation: "activate", targetStatus: "active"
  }), /corrupt tenant record/);

  const badAuditStore = createTransactionalTenantLifecycleStore({
    transaction: async fn => fn({
      getTenant: async () => null, insertTenant: async () => {}, updateTenant: async () => true,
      getIdempotency: async () => null, insertIdempotency: async () => {},
      appendAuditEvent: async () => "secret=leak"
    })
  });
  await assert.rejects(badAuditStore.applyTenantLifecycleCommand(base), /audit event identifier/);
});

test("audit event contains lifecycle facts but not idempotency keys", async () => {
  const f = fixture();
  await f.store.applyTenantLifecycleCommand(base);
  assert.equal(f.audit[0].tenantId, "tenant-alpha");
  assert.equal(f.audit[0].actorPrincipalId, "platform-admin:1");
  assert.equal(JSON.stringify(f.audit).includes("idem-001"), false);
});

test("rejects invalid input without opening a transaction", async () => {
  let calls = 0;
  const store = createTransactionalTenantLifecycleStore({
    transaction: async fn => { calls++; return fn({}); }
  });
  await assert.rejects(store.applyTenantLifecycleCommand({ ...base, tenantId: "Default" }), /invalid lifecycle mutation/);
  assert.equal(calls, 0);
});
