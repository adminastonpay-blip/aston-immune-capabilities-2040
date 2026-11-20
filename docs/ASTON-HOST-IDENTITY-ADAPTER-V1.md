# ASTON Host Identity Adapter v1

Status: IMPLEMENTED. CI result for final commit pending. Not runtime integrated or production validated.

## Source contract inspected

The ASTON OS 15.5 `main` branch currently exposes:
- `authenticate(req, env): Promise<Identity | null>` in `src/auth.ts`.
- `resolveIdentity(req, env): Promise<Identity>` in `src/lib/identity.ts`.
- `Identity` fields: `actor`, `method`, `tenant`, `roles`, `clearance`, optional `plan`, in `src/types.ts`.

The adapter is designed for the resulting Identity object. It does not import from or modify the ASTON OS repository.

## Security boundary

`resolveAstonDeviceHostContext({ identity, attestationAudience, authorizeIdentity })`:
- Rejects public, unknown, malformed, and synthetic `unassigned-*` identities.
- Requires a dedicated attestation audience supplied by trusted host configuration. It intentionally does not reuse Cloudflare Access JWT `ACCESS_AUD`.
- Requires a privileged `authorizeIdentity` callback.
- Requires the callback to establish an exact actor and tenant binding and return tenant status exactly `active`.
- Fails closed on mismatch, inactive tenant, missing authorizer, or authorizer error.
- Returns the `hostContext` shape expected by the device-attestation orchestrator.
- Does not itself authenticate HTTP requests, verify JWTs, or establish tenant lifecycle authority.

## Mandatory integration requirements

The current ASTON OS TEN-02 tenant lifecycle design is explicitly marked DESIGN PROPOSED / NOT IMPLEMENTED. Current auth code derives the tenant from a signed Access claim, assigns a synthetic `unassigned-*` tenant when missing, and uses fixed `default` / `ops` tenants for API-key / sensor credentials. These are not an authoritative tenant lifecycle registry.

Therefore:
- Do not implement `authorizeIdentity` by echoing the supplied Identity.
- Do not assume the signed JWT tenant claim alone proves the tenant is provisioned and active.
- Do not allow API-key or sensor identities until an approved credential-to-tenant authority can prove their exact binding.
- Do not wire this adapter into production until the authoritative identity/tenant callback exists and is independently tested.
- Use a dedicated trusted configuration value for the physical-device attestation audience; do not silently substitute `ACCESS_AUD`.

## Scope boundary

This is an isolated adapter contract and tests only. No ASTON OS source, branch, schema, Cloudflare binding, D1 database, secret, migration, or deployment was changed. The existing device-attestation orchestrator remains non-executable and is not connected to physical actuation.

## Acceptance tests

- Active exact actor/tenant mapping produces a host context.
- Public, unknown, and synthetic unassigned identities are rejected.
- Dedicated audience and authoritative callback are mandatory.
- Tenant/principal mismatch and inactive/unknown tenant states are rejected.
- Authoritative lookup errors fail to review.
- Input identity is not mutated.

## Status vocabulary

- IMPLEMENTED: adapter, tests, and this contract are committed on an isolated branch.
- TESTED: only after GitHub Actions passes on the final documentation commit.
- VALIDATED: not claimed; TEN-02 authority is still not implemented in the host repository.
- PRODUCTION: not claimed; no runtime wiring or deployment was performed.
