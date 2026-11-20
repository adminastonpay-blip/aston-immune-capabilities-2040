import test from "node:test";
import assert from "node:assert/strict";
import {
  evaluateTenantAuthorization,
  TENANT_AUTHORITY_CLOCK_SKEW_MS
} from "../src/tenant-authority-contract.js";

const now = 1_800_000_000_000;
const identity = { actor: "service:edge-01", method: "apikey", tenant: "tenant-acme-01" };
const request = {
  tenantId: "tenant-acme-01",
  resourceTenantId: "tenant-acme-01",
  audience: "aston-device-edge-v1",
  capability: "attestation.evaluate"
};
const activeRecord = () => ({
  tenant: { tenantId: "tenant-acme-01", status: "active", notBefore: now - 60_000, expiresAt: now + 60_000 },
  membership: {
    tenantId: "tenant-acme-01", principalId: "service:edge-01", status: "active",
    notBefore: now - 60_000, expiresAt: now + 60_000,
    capabilities: ["attestation.evaluate", "device.enroll"],
    audiences: ["aston-device-edge-v1"]
  }
});
const resolver = async () => activeRecord();
const evaluate = (overrides = {}) => evaluateTenantAuthorization({
  identity, request, now, correlationId: "trace-001", resolveAuthority: resolver, ...overrides
});

test("allows an active tenant with exact principal, tenant, audience and capability bindings", async () => {
  const result = await evaluate();
  assert.equal(result.ok, true);
  assert.equal(result.decision, "allow");
  assert.equal(result.tenantId, identity.tenant);
  assert.equal(result.principalId, identity.actor);
  assert.equal(result.executable, false);
  assert.equal(result.correlationId, "trace-001");
});

test("rejects non-canonical tenant identifiers without normalizing them", async () => {
  for (const tenant of ["Tenant-Acme", " tenant-acme", "tenant_acme", "tenant--", "tenant.acme", ""]) {
    const result = await evaluate({ identity: { ...identity, tenant } });
    assert.equal(result.ok, false, tenant);
    assert.equal(result.reason, "UNRESOLVED_TENANT_IDENTITY", tenant);
  }
});

test("rejects legacy default, ops and unassigned tenant shortcuts", async () => {
  for (const tenant of ["default", "ops", "unassigned-abc123"]) {
    const result = await evaluate({ identity: { ...identity, tenant } });
    assert.equal(result.ok, false);
    assert.equal(result.reason, "UNRESOLVED_TENANT_IDENTITY");
  }
});

test("rejects suspended, pending and unknown tenants", async () => {
  for (const status of ["suspended", "pending", "unknown"]) {
    const result = await evaluate({ resolveAuthority: async () => {
      const record = activeRecord(); record.tenant.status = status; return record;
    }});
    assert.equal(result.ok, false);
    assert.equal(result.reason, "TENANT_NOT_ACTIVE");
  }
});

test("rejects revoked and offboarded tenants", async () => {
  for (const status of ["revoked", "offboarded"]) {
    const result = await evaluate({ resolveAuthority: async () => {
      const record = activeRecord(); record.tenant.status = status; return record;
    }});
    assert.equal(result.ok, false);
    assert.equal(result.reason, "TENANT_REVOKED");
  }
});

test("rejects inactive actor membership", async () => {
  const result = await evaluate({ resolveAuthority: async () => {
    const record = activeRecord(); record.membership.status = "suspended"; return record;
  }});
  assert.equal(result.reason, "ACTOR_NOT_AUTHORIZED");
});

test("rejects identity/request/resource tenant mismatch", async () => {
  for (const changed of [
    { ...request, tenantId: "tenant-other" },
    { ...request, resourceTenantId: "tenant-other" }
  ]) {
    const result = await evaluate({ request: changed });
    assert.equal(result.reason, "TENANT_MISMATCH");
  }
});

test("rejects authoritative principal or tenant binding mismatch", async () => {
  for (const mutate of [
    record => { record.tenant.tenantId = "tenant-other"; },
    record => { record.membership.tenantId = "tenant-other"; },
    record => { record.membership.principalId = "service:other"; }
  ]) {
    const result = await evaluate({ resolveAuthority: async () => {
      const record = activeRecord(); mutate(record); return record;
    }});
    assert.equal(result.reason, "TENANT_MISMATCH");
  }
});

test("rejects an audience not granted by the authoritative membership", async () => {
  const result = await evaluate({ request: { ...request, audience: "other-audience" } });
  assert.equal(result.reason, "AUDIENCE_MISMATCH");
});

test("rejects a capability not granted by the authoritative membership", async () => {
  const result = await evaluate({ request: { ...request, capability: "device.revoke" } });
  assert.equal(result.reason, "CAPABILITY_NOT_AUTHORIZED");
});

test("fails closed when authority is missing, unavailable or incomplete", async () => {
  const missing = await evaluate({ resolveAuthority: undefined });
  assert.equal(missing.reason, "MISSING_TENANT_AUTHORITY");
  assert.equal(missing.decision, "review");

  const unavailable = await evaluate({ resolveAuthority: async () => { throw new Error("private provider detail"); } });
  assert.equal(unavailable.reason, "AUTHORITY_UNAVAILABLE");
  assert.equal(unavailable.decision, "review");
  assert.equal(JSON.stringify(unavailable).includes("private provider detail"), false);

  const incomplete = await evaluate({ resolveAuthority: async () => ({ tenant: { tenantId: identity.tenant, status: "active" } }) });
  assert.equal(incomplete.reason, "AUTHORITY_DATA_INCOMPLETE");
  assert.equal(incomplete.decision, "review");
});

test("enforces membership and tenant start and expiry timestamps", async () => {
  const notYetValid = await evaluate({ resolveAuthority: async () => {
    const record = activeRecord(); record.membership.notBefore = now + 60_000; return record;
  }});
  assert.equal(notYetValid.reason, "ASSIGNMENT_NOT_YET_VALID");

  const expired = await evaluate({ resolveAuthority: async () => {
    const record = activeRecord(); record.tenant.expiresAt = now - 60_000; return record;
  }});
  assert.equal(expired.reason, "ASSIGNMENT_EXPIRED");
});

test("allows only the explicitly bounded clock-skew policy", async () => {
  const tooLarge = await evaluate({ clockSkewMs: TENANT_AUTHORITY_CLOCK_SKEW_MS + 1 });
  assert.equal(tooLarge.reason, "INVALID_HOST_POLICY");
  const negative = await evaluate({ clockSkewMs: -1 });
  assert.equal(negative.reason, "INVALID_HOST_POLICY");
});

test("rejects malformed host identity and invalid request contracts", async () => {
  const noActor = await evaluate({ identity: { ...identity, actor: "" } });
  assert.equal(noActor.reason, "UNTRUSTED_HOST_CONTEXT");
  const noAudience = await evaluate({ request: { ...request, audience: "" } });
  assert.equal(noAudience.reason, "AUDIENCE_MISMATCH");
  const noCapability = await evaluate({ request: { ...request, capability: "" } });
  assert.equal(noCapability.reason, "CAPABILITY_NOT_AUTHORIZED");
});

test("does not echo unsafe correlation identifiers or expose provider details", async () => {
  const result = await evaluate({
    correlationId: "token=secret-value",
    resolveAuthority: async () => { throw new Error("database password"); }
  });
  assert.equal(result.correlationId, undefined);
  assert.equal(JSON.stringify(result).includes("secret-value"), false);
  assert.equal(JSON.stringify(result).includes("database password"), false);
});

test("returns a non-executable decision and never mutates identity or request", async () => {
  const identityCopy = structuredClone(identity);
  const requestCopy = structuredClone(request);
  const result = await evaluate();
  assert.equal(result.executable, false);
  assert.deepEqual(identity, identityCopy);
  assert.deepEqual(request, requestCopy);
});
