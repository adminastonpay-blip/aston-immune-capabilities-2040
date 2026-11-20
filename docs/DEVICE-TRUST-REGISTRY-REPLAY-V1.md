# Device Trust Registry + Replay Protection v1

**Status:** IMPLEMENTED + TESTED only after the branch CI run succeeds. Not production validated.

## Scope

This capability adds a host-side facade for tenant-scoped device key enrollment, lookup, revocation, and one-time challenge consumption. It is intentionally independent of ASTON OS 15.5 and does not modify Cloudflare or production resources.

## API

`createDeviceTrustRegistry({ store, authorize, now })` returns:

- `enrollDeviceKey(record, authContext)`: validates and inserts an active tenant/issuer/key/device binding. Duplicate key IDs are rejected; existing records are never overwritten.
- `resolveTrustedKey({ tenantId, issuerId, keyId })`: exact tenant-scoped lookup suitable for injection as the crypto verifier's `resolveTrustedKey` callback.
- `revokeDeviceKey({ tenantId, issuerId, keyId, reason }, authContext)`: host-authorized revocation.
- `consumeChallenge({ tenantId, deviceId, challengeId, attestationId, expiresAt }, authContext)`: one-time challenge consumption.

Every decision is non-executable. Missing dependencies or storage failures return review/fail-safe results.

## Durable adapter contract

The injected store must provide durable, atomic operations:

1. `createKeyIfAbsent(record)` — unique constraint on (tenant_id, issuer_id, key_id).
2. `getKey(scope)` — exact tenant + issuer + key lookup.
3. `revokeKey(scope)` — atomic state transition to revoked; revocation is permanent absent a separately governed re-enrollment process.
4. `consumeChallengeIfAbsent(record)` — atomic unique insert on (tenant_id, device_id, challenge_id), with expiry retention at least through the challenge's expiration and the configured replay window.

The facade deliberately does not pretend an in-memory test store is durable. A production adapter must implement database uniqueness/transaction semantics; a read-then-write check is not sufficient. Concurrent duplicate consumes must have exactly one winner.

## Trust boundary

- `authorize` is privileged host code and must derive actor/tenant from authenticated host context. Never pass caller-supplied tenant identity as proof of authorization.
- The store is privileged infrastructure. Its results must be integrity-protected and tenant-scoped.
- The Ed25519 verifier's `resolveTrustedKey` may be wired to this facade, but the host must also consume the challenge as part of the same trusted request workflow before accepting the attestation.
- Key revocation and challenge consumption are separate operations. The host integration must fail closed if either operation fails.
- The in-memory adapter used by unit tests validates API behavior only; it does not demonstrate cross-process atomicity or persistence.

## Explicitly not implemented

No Cloudflare D1/KV/DO binding, migration, deployment, secrets, hardware root-of-trust, device enrollment ceremony, authenticated tenant middleware, distributed transaction, automatic key rotation, device actuation, SafetyInterlock/MissionBrain wiring, or production activation.

## Acceptance criteria

- Tenant-scoped key registration and lookup.
- Duplicate key registration cannot overwrite an existing key.
- Host authorization required for enrollment, revocation, and challenge consumption.
- Revoked keys remain visibly inactive.
- One-time challenge semantics and tenant/device replay isolation.
- Storage errors never report successful persistence.
- Automated tests and CI pass on this isolated branch.
