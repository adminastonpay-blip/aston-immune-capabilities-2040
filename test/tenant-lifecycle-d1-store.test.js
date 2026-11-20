import test from "node:test";
import assert from "node:assert/strict";
import { createD1TenantLifecycleStore } from "../src/tenant-lifecycle-d1-store.js";

const mutation = (overrides = {}) => ({
  operation: "create", tenantId: "tenant-one", targetStatus: "pending",
  reason: "approved customer onboarding", idempotencyKey: "request-001",
  actorPrincipalId: "admin:root", actorScope: "platform",
  occurredAt: 1000, correlationId: "trace-001", ...overrides
});

async function testFingerprint(m) {
  const canonical = JSON.stringify([
    m.operation, m.tenantId, m.targetStatus, m.reason,
    m.actorPrincipalId, m.actorScope, m.correlationId ?? null
  ]);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return [...new Uint8Array(digest)].map(x => x.toString(16).padStart(2, "0")).join("");
}

function fakeD1({ changes = 1, row, error } = {}) {
  const calls = [];
  const db = {
    prepare(sql) {
      return {
        bind(...values) {
          return { sql, values };
        }
      };
    },
    async batch(statements) {
      calls.push(statements);
      if (error) throw error;
      return [
        { success: true, meta: { changes } },
        { success: true, results: [row ?? {
          fingerprint: "0".repeat(64), audit_event_id: "audit-001", tenant_id: "tenant-one"
        }] }
      ];
    }
  };
  return { db, calls };
}

test("requires a D1 binding and trusted audit ID factory", () => {
  assert.throws(() => createD1TenantLifecycleStore(), /D1 binding/);
  assert.throws(() => createD1TenantLifecycleStore({ db: { prepare() {}, batch() {} } }), /ID factory/);
});

test("submits exactly one atomic D1 batch with bound parameters and readback", async () => {
  const { db, calls } = fakeD1();
  const store = createD1TenantLifecycleStore({ db, createId: () => "audit-001" });
  const result = await store.applyTenantLifecycleCommand(mutation());
  assert.equal(result.status, "applied");
  assert.equal(result.auditEventId, "audit-001");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].length, 2);
  assert.match(calls[0][0].sql, /INSERT INTO aston_tenant_lifecycle_idempotency/);
  assert.match(calls[0][1].sql, /SELECT fingerprint, audit_event_id, tenant_id/);
  assert.deepEqual(calls[0][0].values.slice(0, 2), ["admin:root", "request-001"]);
});

test("returns replay for an existing matching idempotency record", async () => {
  const m = mutation();
  const { db } = fakeD1({
    changes: 0,
    row: { fingerprint: await testFingerprint(m), audit_event_id: "audit-prior", tenant_id: "tenant-one" }
  });
  const store = createD1TenantLifecycleStore({ db, createId: () => "audit-new" });
  const result = await store.applyTenantLifecycleCommand(m);
  assert.deepEqual(result, { status: "replayed", auditEventId: "audit-prior" });
});

test("rejects an idempotency key reused with a different fingerprint", async () => {
  const { db } = fakeD1({
    changes: 0,
    row: { fingerprint: "f".repeat(64), audit_event_id: "audit-prior", tenant_id: "tenant-one" }
  });
  const store = createD1TenantLifecycleStore({ db, createId: () => "audit-new" });
  const result = await store.applyTenantLifecycleCommand(mutation());
  assert.deepEqual(result, { status: "idempotency_conflict" });
});

test("rejects corrupt readback and malformed D1 results", async () => {
  const bad = fakeD1({ row: { fingerprint: "x", audit_event_id: "bad id", tenant_id: "tenant-one" } });
  const store = createD1TenantLifecycleStore({ db: bad.db, createId: () => "audit-001" });
  await assert.rejects(store.applyTenantLifecycleCommand(mutation()), /corrupt/);
  const malformed = createD1TenantLifecycleStore({
    db: { prepare: () => ({ bind: () => ({}) }), batch: async () => [] },
    createId: () => "audit-001"
  });
  await assert.rejects(malformed.applyTenantLifecycleCommand(mutation()), /batch response/);
});

test("fails closed when D1 batch throws", async () => {
  const { db } = fakeD1({ error: new Error("database unavailable") });
  const store = createD1TenantLifecycleStore({ db, createId: () => "audit-001" });
  await assert.rejects(store.applyTenantLifecycleCommand(mutation()), /database unavailable/);
});

test("rejects invalid mutation before database access", async () => {
  let calls = 0;
  const db = { prepare() { calls++; }, batch() { calls++; } };
  const store = createD1TenantLifecycleStore({ db, createId: () => "audit-001" });
  await assert.rejects(store.applyTenantLifecycleCommand(mutation({ tenantId: "Default" })), /invalid lifecycle/);
  assert.equal(calls, 0);
});

test("rejects invalid audit event IDs", async () => {
  const { db } = fakeD1();
  const store = createD1TenantLifecycleStore({ db, createId: () => "not safe!" });
  await assert.rejects(store.applyTenantLifecycleCommand(mutation()), /audit event identifier/);
});

test("schema declares atomic triggers and immutable audit/idempotency records", async () => {
  const { readFile } = await import("node:fs/promises");
  const sql = await readFile(new URL("../migrations/0002_tenant_lifecycle_d1.sql", import.meta.url), "utf8");
  assert.match(sql, /trg_aston_tenant_lifecycle_validate/);
  assert.match(sql, /trg_aston_tenant_lifecycle_apply/);
  assert.match(sql, /RAISE\(ABORT, 'TEN02_AUDIT_IMMUTABLE'\)/);
  assert.match(sql, /RAISE\(ABORT, 'TEN02_IDEMPOTENCY_IMMUTABLE'\)/);
  assert.match(sql, /PRIMARY KEY \(actor_principal_id, idempotency_key\)/);
});
