import test from "node:test";
import assert from "node:assert/strict";
import { resolveAstonDeviceHostContext } from "../src/aston-host-identity-adapter.js";

const identity = {
  actor:"operator@example.test",
  method:"access",
  tenant:"tenant_acme-01",
  roles:["admin","executor"],
  clearance:"confidential"
};
const authority = async (input) => ({
  status:"active",
  tenantId:input.tenant,
  principalId:input.actor
});

test("maps an authenticated and authoritatively active ASTON identity", async () => {
  const result = await resolveAstonDeviceHostContext({
    identity, attestationAudience:"aston-device-edge-v1",
    authorizeIdentity:authority
  });
  assert.equal(result.ok,true);
  assert.equal(result.context.tenantId,identity.tenant);
  assert.equal(result.context.principalId,identity.actor);
  assert.equal(result.context.audience,"aston-device-edge-v1");
  assert.equal(result.context.authMethod,"access");
  assert.deepEqual(result.context.roles,identity.roles);
  assert.equal(result.context.tenantLifecycleStatus,"active");
  assert.equal(result.executable,false);
});

test("rejects public, unknown and synthetic unassigned identities", async () => {
  for (const candidate of [
    {...identity,method:"public"},
    {...identity,method:"unknown"},
    {...identity,tenant:"unassigned-actor-fingerprint"}
  ]) {
    const result = await resolveAstonDeviceHostContext({
      identity:candidate,attestationAudience:"aston-device-edge-v1",
      authorizeIdentity:authority
    });
    assert.equal(result.ok,false);
    assert.equal(result.reason,"authenticated_aston_identity_required");
  }
});

test("requires a dedicated attestation audience, not an implicit Access audience", async () => {
  const result = await resolveAstonDeviceHostContext({
    identity,attestationAudience:"",authorizeIdentity:authority
  });
  assert.equal(result.reason,"dedicated_attestation_audience_required");
});

test("requires an authoritative identity and tenant authorizer", async () => {
  const result = await resolveAstonDeviceHostContext({
    identity,attestationAudience:"aston-device-edge-v1"
  });
  assert.equal(result.reason,"authoritative_identity_authorizer_required");
});

test("rejects tenant mismatch, principal mismatch and inactive tenant", async () => {
  const cases = [
    async () => ({status:"active",tenantId:"tenant-other",principalId:identity.actor}),
    async () => ({status:"active",tenantId:identity.tenant,principalId:"other-actor"}),
    async () => ({status:"suspended",tenantId:identity.tenant,principalId:identity.actor}),
    async () => ({status:"unknown",tenantId:identity.tenant,principalId:identity.actor})
  ];
  for (const authorizeIdentity of cases) {
    const result = await resolveAstonDeviceHostContext({
      identity,attestationAudience:"aston-device-edge-v1",authorizeIdentity
    });
    assert.equal(result.ok,false);
    assert.equal(result.reason,"identity_or_tenant_not_authoritatively_active");
  }
});

test("fails to review when authoritative identity lookup throws", async () => {
  const result = await resolveAstonDeviceHostContext({
    identity,attestationAudience:"aston-device-edge-v1",
    authorizeIdentity:async()=>{throw new Error("registry unavailable");}
  });
  assert.equal(result.ok,false);
  assert.equal(result.decision,"review");
  assert.equal(result.reason,"authoritative_identity_check_failed");
});

test("does not mutate the input identity or roles", async () => {
  const roles = [...identity.roles];
  await resolveAstonDeviceHostContext({
    identity,attestationAudience:"aston-device-edge-v1",
    authorizeIdentity:authority
  });
  assert.deepEqual(identity.roles,roles);
});
