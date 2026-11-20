# ASTON Runtime Authority and SafetyInterlock Bridge v1

**Status:** IMPLEMENTED + AUTOMATED TESTED in the isolated capability repository. Not connected to the production ASTON Worker and not production validated.

## Purpose

Provide a single fail-closed host adapter for the existing ASTON OS identity model, TEN-02 tenant lifecycle authority, and SafetyInterlock Durable Object contract.

## Runtime sequence

1. Receive an authenticated host Identity from ASTON's authentication layer.
2. Resolve its credential binding through a privileged host callback:
   - Cloudflare Access: exact issuer + subject + tenant claim binding.
   - API key: stable key fingerprint principal binding.
   - Sensor: unique credential ID binding; the current static `lb-sensor` actor is deliberately insufficient.
3. Read `aston_tenants` from the authoritative lifecycle store and require status exactly `active` plus a positive lifecycle version.
4. Construct an authority-verified identity with roles and clearance from the trusted credential binding, not caller-supplied role claims.
5. Resolve the existing tenant-partitioned SafetyInterlock Durable Object and call its `POST /evaluate` endpoint.
6. Accept only contract version `1` and status `allowed`. Denied, pending approval, timeout, malformed responses, and missing bindings stop capability evaluation.
7. Re-read tenant lifecycle after SafetyInterlock and immediately before evaluation; reject if status or lifecycle version changed.
8. Invoke a capability evaluator only after both authority and SafetyInterlock allow. Evaluators must return `executable:false`.

## ASTON interface mapping

The bridge matches the inspected ASTON OS 15.5 interfaces:
- `Identity`: `actor`, `method`, `tenant`, `roles`, `clearance`.
- `SAFETY` Durable Object namespace: `idFromName(tenantId)`, `get(id)`.
- SafetyInterlock request: `POST https://do/evaluate` with `{ action, identity }`.
- SafetyInterlock response: `contract_version: "1"`, status `allowed | denied | pending_approval`.

## Mandatory host changes before runtime activation

The current ASTON OS 15.5 `Identity` type does not expose Access JWT `issuer` and `subject`, nor a unique sensor `credentialId`. The current API-key path uses the shared legacy tenant `default`, and the sensor path uses `ops`. The bridge intentionally does not treat these placeholders as authoritative tenant IDs.

Before activation, the host authentication layer must:
- preserve verified Access JWT issuer and subject in the trusted Identity context;
- attach a stable credential ID for sensor credentials;
- provide a trusted credential-binding resolver (not an echo of JWT/request tenant claims);
- bind API-key fingerprints to one canonical tenant and scoped roles;
- supply the approved D1 binding with migration 0002 applied through a separately authorized migration process.

The authoritative tenant provisioning owner and credential enrollment process must be approved. Until then, the bridge returns deny/review. No speculative tenant mappings are created.

## Safety boundary

- No ASTON OS 15.5 source, main branch, Worker, Durable Object, D1 database, binding, secret, or Cloudflare resource was changed.
- No D1 migration was applied.
- The bridge does not execute tools, transfer funds, dispatch missions, or mutate device state.
- A passing unit test is not proof of a live SafetyInterlock DO or D1 deployment.

## Verification

CI runs the Node test suite plus the SQLite migration integration suite. The authority bridge tests cover Access issuer/subject matching, API-key fingerprint mapping, sensor fail-closed behavior, active/suspended/revoked tenant states, provider failure, tenant-partitioned SafetyInterlock requests, malformed/unknown SafetyInterlock responses, and the requirement that capability evaluators run only after both gates allow.
