import test from "node:test";
import assert from "node:assert/strict";
import { executeTenantLifecycleCommand } from "../src/tenant-lifecycle-control-plane.js";

const now = 1_800_000_000_000;
const adminIdentity = { actor: "platform-admin:001", method: "access", tenantId: null };
const command = (overrides = {}) => ({
  operation: "create", tenantId: "tenant-new-01",
  reason: "Approved tenant onboarding", idempotencyKey: "idem-0001", ...overrides
});
const adminAuthority = async ({ principalId, capability }) => ({
  authorized: true, status: "active", principalId, scope: "platform", capability
});
const store = async mutation => ({
  status: "applied", auditEventId: "audit-event-001", received: mutation
});
const execute = (overrides = {}) => executeTenantLifecycleCommand({
  adminIdentity, command: command(), authorizeAdmin: adminAuthority,
  store: { applyTenantLifecycleCommand: store }, now, correlationId: "trace-001", ...overrides
});

test("records an authorized tenant creation as pending with an audit reference", async () => {
  const result = await execute();
  assert.equal(result.ok, true);
  assert.equal(result.status, "pending");
  assert.equal(result.reason, "LIFECYCLE_MUTATION_RECORDED");
  assert.equal(result.auditEventId, "audit-event-001");
  assert.equal(result.executable, false);
});

test("maps every lifecycle operation to its intended state", async () => {
  for (const [operation, status] of [
    ["create", "pending"], ["activate", "active"], ["suspend", "suspended"], ["revoke", "revoked"]
  ]) {
    const result = await execute({ command: command({ operation }) });
    assert.equal(result.ok, true, operation);
    assert.equal(result.status, status, operation);
  }
});

test("requires a canonical tenant ID and rejects legacy shortcuts", async () => {
  for (const tenantId of ["Tenant-A", "tenant_a", "tenant.a", " default", "default", "ops", "unassigned-01", ""]) {
    const result = await execute({ command: command({ tenantId }) });
    assert.equal(result.reason, "INVALID_LIFECYCLE_COMMAND", tenantId);
  }
});

test("requires an operation, meaningful reason and idempotency key", async () => {
  const cases = [
    { operation: "delete" },
    { reason: " " },
    { reason: "short" },
    { idempotencyKey: "" },
    { idempotencyKey: "key with spaces" }
  ];
  for (const change of cases) {
    const result = await execute({ command: command(change) });
    assert.equal(result.reason, "INVALID_LIFECYCLE_COMMAND");
  }
});

test("requires a trusted administrator principal", async () => {
  const result = await execute({ adminIdentity: { actor: "" } });
  assert.equal(result.reason, "UNTRUSTED_ADMIN_CONTEXT");
});

test("requires an administrative authority and lifecycle store", async () => {
  assert.equal((await execute({ authorizeAdmin: undefined })).reason, "MISSING_ADMIN_AUTHORITY");
  assert.equal((await execute({ store: undefined })).reason, "MISSING_LIFECYCLE_STORE");
});

test("fails closed when admin authorization throws", async () => {
  const result = await execute({ authorizeAdmin: async () => { throw new Error("private"); } });
  assert.equal(result.reason, "ADMIN_AUTHORITY_UNAVAILABLE");
  assert.equal(result.decision, "review");
  assert.equal(JSON.stringify(result).includes("private"), false);
});

test("rejects inactive, denied, mismatched or malformed admin authorization", async () => {
  const cases = [
    null,
    { authorized: false, status: "active", principalId: adminIdentity.actor, scope: "platform" },
    { authorized: true, status: "suspended", principalId: adminIdentity.actor, scope: "platform" },
    { authorized: true, status: "active", principalId: "other-admin", scope: "platform" },
    { authorized: true, status: "active", principalId: adminIdentity.actor, scope: "unknown" }
  ];
  for (const auth of cases) {
    const result = await execute({ authorizeAdmin: async () => auth });
    assert.equal(result.reason, "ADMIN_NOT_AUTHORIZED");
  }
});

test("requires tenant-scoped administrators to match exact target scope", async () => {
  const result = await execute({
    adminIdentity: { actor: "tenant-admin:1", tenantId: "tenant-home" },
    authorizeAdmin: async ({ principalId }) => ({
      authorized: true, status: "active", principalId, scope: "delegated", tenantId: "tenant-other"
    })
  });
  assert.equal(result.reason, "ADMIN_SCOPE_MISMATCH");
});

test("prevents tenant-scoped administrators from administering their own tenant", async () => {
  const result = await execute({
    adminIdentity: { actor: "tenant-admin:1", tenantId: "tenant-new-01" },
    authorizeAdmin: async ({ principalId }) => ({
      authorized: true, status: "active", principalId, scope: "delegated", tenantId: "tenant-new-01"
    })
  });
  assert.equal(result.reason, "SELF_TENANT_ADMIN_FORBIDDEN");
});

test("allows a delegated administrator only for a different explicitly granted tenant", async () => {
  const result = await execute({
    adminIdentity: { actor: "tenant-admin:1", tenantId: "tenant-home" },
    authorizeAdmin: async ({ principalId }) => ({
      authorized: true, status: "active", principalId, scope: "delegated", tenantId: "tenant-new-01"
    })
  });
  assert.equal(result.ok, true);
});

test("allows a separately authorized platform administrator", async () => {
  const result = await execute();
  assert.equal(result.ok, true);
});

test("passes actor, reason, idempotency, target status and trace to the atomic store boundary", async () => {
  let captured;
  await execute({ store: { applyTenantLifecycleCommand: async value => {
    captured = value; return { status: "applied", auditEventId: "audit-1" };
  }}});
  assert.deepEqual({
    operation: captured.operation, tenantId: captured.tenantId,
    targetStatus: captured.targetStatus, reason: captured.reason,
    idempotencyKey: captured.idempotencyKey, actorPrincipalId: captured.actorPrincipalId,
    actorScope: captured.actorScope, correlationId: captured.correlationId,
    occurredAt: captured.occurredAt
  }, {
    operation: "create", tenantId: "tenant-new-01", targetStatus: "pending",
    reason: "Approved tenant onboarding", idempotencyKey: "idem-0001",
    actorPrincipalId: adminIdentity.actor, actorScope: "platform",
    correlationId: "trace-001", occurredAt: now
  });
});

test("treats an identical idempotent replay as recorded without duplicating the mutation", async () => {
  const result = await execute({ store: { applyTenantLifecycleCommand: async () => ({
    status: "replayed", auditEventId: "audit-original"
  })}});
  assert.equal(result.ok, true);
  assert.equal(result.reason, "IDEMPOTENT_REPLAY");
  assert.equal(result.auditEventId, "audit-original");
});

test("rejects idempotency-key reuse with a different command", async () => {
  const result = await execute({ store: { applyTenantLifecycleCommand: async () => ({
    status: "idempotency_conflict"
  })}});
  assert.equal(result.reason, "IDEMPOTENCY_CONFLICT");
});

test("rejects invalid lifecycle transitions reported by the atomic store", async () => {
  const result = await execute({ store: { applyTenantLifecycleCommand: async () => ({
    status: "transition_rejected"
  })}});
  assert.equal(result.reason, "LIFECYCLE_TRANSITION_REJECTED");
});

test("fails closed when persistence throws or returns malformed data", async () => {
  const unavailable = await execute({ store: { applyTenantLifecycleCommand: async () => {
    throw new Error("database secret");
  }}});
  assert.equal(unavailable.reason, "LIFECYCLE_STORE_UNAVAILABLE");
  assert.equal(unavailable.decision, "review");
  assert.equal(JSON.stringify(unavailable).includes("database secret"), false);

  const malformed = await execute({ store: { applyTenantLifecycleCommand: async () => ({ status: "applied" }) } });
  assert.equal(malformed.reason, "LIFECYCLE_STORE_INVALID_RESPONSE");
});

test("does not report success without a safe audit event identifier", async () => {
  for (const auditEventId of [undefined, "", "contains spaces", "token=secret"]) {
    const result = await execute({ store: { applyTenantLifecycleCommand: async () => ({
      status: "applied", auditEventId
    })}});
    assert.equal(result.ok, false);
    assert.equal(result.reason, "LIFECYCLE_STORE_INVALID_RESPONSE");
  }
});

test("rejects invalid host time", async () => {
  const result = await execute({ now: NaN });
  assert.equal(result.reason, "INVALID_HOST_TIME");
});

test("does not leak unsafe correlation IDs or mutate caller input", async () => {
  const input = command();
  const before = structuredClone(input);
  const result = await execute({ command: input, correlationId: "token=private" });
  assert.equal(result.correlationId, undefined);
  assert.deepEqual(input, before);
  assert.equal(result.executable, false);
});

test("every returned decision is non-executable", async () => {
  const results = await Promise.all([
    execute(),
    execute({ authorizeAdmin: undefined }),
    execute({ store: { applyTenantLifecycleCommand: async () => { throw new Error("x"); } } }),
    execute({ command: command({ tenantId: "default" }) })
  ]);
  for (const result of results) assert.equal(result.executable, false);
});
