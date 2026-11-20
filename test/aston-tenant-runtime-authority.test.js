import test from "node:test";
import assert from "node:assert/strict";
import {
  createD1TenantLifecycleReader,
  resolveAstonTenantRuntimeAuthority,
  createAstonSafetyInterlockGate
} from "../src/aston-tenant-runtime-authority.js";

const accessIdentity = () => ({
  actor: "operator@example.test", method: "access", tenant: "tenant-a",
  issuer: "https://example.cloudflareaccess.com", subject: "access-subject-1",
  roles: ["viewer"], clearance: "internal"
});
const activeBinding = (overrides = {}) => ({
  status: "active", method: "access", tenantId: "tenant-a",
  issuer: "https://example.cloudflareaccess.com", subject: "access-subject-1",
  roles: ["operator"], clearance: "confidential", ...overrides
});
const activeTenant = (overrides = {}) => ({
  tenantId: "tenant-a", status: "active", lifecycleVersion: 3,
  createdAt: 1, updatedAt: 2, ...overrides
});

test("D1 reader performs a parameterized authoritative lifecycle lookup", async () => {
  let sql, values;
  const reader = createD1TenantLifecycleReader({
    prepare(query) {
      sql = query;
      return { bind(...args) {
        values = args;
        return { first: async () => ({ tenant_id: "tenant-a", status: "active", version: 4, created_at: 1, updated_at: 2 }) };
      }};
    }
  });
  assert.deepEqual(await reader("tenant-a"), {
    tenantId: "tenant-a", status: "active", lifecycleVersion: 4, createdAt: 1, updatedAt: 2
  });
  assert.match(sql, /WHERE tenant_id = \?/);
  assert.deepEqual(values, ["tenant-a"]);
  assert.equal(await reader("Default"), null);
});

test("requires authenticated identity and both privileged authority providers", async () => {
  assert.equal((await resolveAstonTenantRuntimeAuthority()).reason, "AUTHENTICATED_HOST_IDENTITY_REQUIRED");
  assert.equal((await resolveAstonTenantRuntimeAuthority({
    identity: accessIdentity()
  })).decision, "review");
});

test("rejects Access identity without verified issuer and subject fields", async () => {
  const identity = accessIdentity();
  delete identity.subject;
  const result = await resolveAstonTenantRuntimeAuthority({
    identity, resolvePrincipalBinding: async () => activeBinding(),
    loadTenantLifecycle: async () => activeTenant()
  });
  assert.equal(result.reason, "ACCESS_ISSUER_SUBJECT_REQUIRED");
});

test("authorizes Access only when issuer, subject, tenant binding and lifecycle are exact", async () => {
  let bindingInput;
  const result = await resolveAstonTenantRuntimeAuthority({
    identity: accessIdentity(),
    resolvePrincipalBinding: async input => { bindingInput = input; return activeBinding(); },
    loadTenantLifecycle: async tenantId => tenantId === "tenant-a" ? activeTenant() : null
  });
  assert.equal(result.ok, true);
  assert.equal(result.identity.tenant, "tenant-a");
  assert.deepEqual(result.identity.roles, ["operator"]);
  assert.equal(result.lifecycleVersion, 3);
  assert.equal(result.executable, false);
  assert.deepEqual(bindingInput, {
    method: "access", actor: "operator@example.test",
    issuer: "https://example.cloudflareaccess.com",
    subject: "access-subject-1", credentialId: undefined
  });
});

test("rejects issuer, subject or tenant claim mismatch", async () => {
  for (const binding of [
    activeBinding({ issuer: "https://wrong.example" }),
    activeBinding({ subject: "different-subject" }),
    activeBinding({ tenantId: "tenant-b" })
  ]) {
    const result = await resolveAstonTenantRuntimeAuthority({
      identity: accessIdentity(),
      resolvePrincipalBinding: async () => binding,
      loadTenantLifecycle: async () => activeTenant()
    });
    assert.equal(result.ok, false);
  }
});

test("rejects missing, legacy, synthetic, suspended and revoked tenant records", async () => {
  for (const tenant of [
    null,
    activeTenant({ tenantId: "tenant-b" }),
    activeTenant({ status: "suspended" }),
    activeTenant({ status: "revoked" }),
    activeTenant({ status: "offboarded" }),
    activeTenant({ lifecycleVersion: 0 })
  ]) {
    const result = await resolveAstonTenantRuntimeAuthority({
      identity: accessIdentity(),
      resolvePrincipalBinding: async () => activeBinding(),
      loadTenantLifecycle: async () => tenant
    });
    assert.equal(result.ok, false);
  }
});

test("fails closed on unavailable binding or lifecycle provider", async () => {
  const identity = accessIdentity();
  const unavailableBinding = await resolveAstonTenantRuntimeAuthority({
    identity, resolvePrincipalBinding: async () => { throw new Error("offline"); },
    loadTenantLifecycle: async () => activeTenant()
  });
  assert.equal(unavailableBinding.decision, "review");
  const unavailableTenant = await resolveAstonTenantRuntimeAuthority({
    identity, resolvePrincipalBinding: async () => activeBinding(),
    loadTenantLifecycle: async () => { throw new Error("offline"); }
  });
  assert.equal(unavailableTenant.decision, "review");
});

test("maps API key fingerprint through an explicit binding, never the default tenant", async () => {
  const result = await resolveAstonTenantRuntimeAuthority({
    identity: { actor: "apikey:0123456789abcdef", method: "apikey", tenant: "default", roles: ["admin"], clearance: "secret" },
    resolvePrincipalBinding: async input => ({
      status: "active", method: "apikey", actor: input.actor, tenantId: "tenant-a",
      roles: ["billing:read"], clearance: "internal"
    }),
    loadTenantLifecycle: async () => activeTenant()
  });
  assert.equal(result.ok, true);
  assert.equal(result.identity.tenant, "tenant-a");
  assert.deepEqual(result.identity.roles, ["billing:read"]);
});

test("rejects sensor identity until a unique credential ID is available", async () => {
  const result = await resolveAstonTenantRuntimeAuthority({
    identity: { actor: "lb-sensor", method: "sensor", tenant: "ops", roles: ["sensor"], clearance: "secret" },
    resolvePrincipalBinding: async () => activeBinding(),
    loadTenantLifecycle: async () => activeTenant()
  });
  assert.equal(result.reason, "SENSOR_CREDENTIAL_BINDING_REQUIRED");
});

const authorizedHostContext = () => ({
  ok: true, decision: "authorized", authorityVerified: true,
  tenantId: "tenant-a", lifecycleVersion: 3,
  identity: { actor: "operator@example.test", method: "access", tenant: "tenant-a", roles: ["operator"], clearance: "confidential" }
});

test("SafetyInterlock gate routes to tenant-partitioned DO and accepts only contract-v1 allow", async () => {
  let name, request;
  const gate = createAstonSafetyInterlockGate({
    SAFETY: {
      idFromName(value) { name = value; return "do-id"; },
      get(id) {
        assert.equal(id, "do-id");
        return { async fetch(url, init) {
          request = { url, init, body: JSON.parse(init.body) };
          return { ok: true, json: async () => ({ contract_version: "1", status: "allowed", policy: { decision: "allow" } }) };
        }};
      }
    }
  });
  const result = await gate.evaluate({
    hostContext: authorizedHostContext(),
    action: { tool: "agent.action", args: { safe: true }, context: { objective: "test" } }
  });
  assert.equal(name, "tenant-a");
  assert.equal(request.url, "https://do/evaluate");
  assert.equal(request.body.identity.tenant, "tenant-a");
  assert.equal(result.ok, true);
  assert.equal(result.executable, false);
});

test("SafetyInterlock gate blocks pending approval, denied, malformed and unsupported contracts", async () => {
  for (const payload of [
    { contract_version: "1", status: "pending_approval", approval_id: "approval-1" },
    { contract_version: "1", status: "denied" },
    { contract_version: "2", status: "allowed" },
    { contract_version: "1", status: "unknown" },
    { contract_version: "1", status: "pending_approval" }
  ]) {
    const gate = createAstonSafetyInterlockGate({
      SAFETY: {
        idFromName: () => "id",
        get: () => ({ fetch: async () => ({ ok: true, json: async () => payload }) })
      }
    });
    const result = await gate.evaluate({ hostContext: authorizedHostContext(), action: { tool: "write" } });
    assert.equal(result.ok, false);
  }
});

test("SafetyInterlock gate denies absent authority, missing DO and DO failures", async () => {
  const missing = createAstonSafetyInterlockGate();
  assert.equal((await missing.evaluate({ hostContext: authorizedHostContext(), action: { tool: "write" } })).ok, false);
  const gate = createAstonSafetyInterlockGate({
    SAFETY: { idFromName: () => "id", get: () => ({ fetch: async () => { throw new Error("offline"); } }) }
  });
  assert.equal((await gate.evaluate({ hostContext: { ...authorizedHostContext(), authorityVerified: false }, action: { tool: "write" } })).ok, false);
  assert.equal((await gate.evaluate({ hostContext: authorizedHostContext(), action: { tool: "write" } })).ok, false);
});
