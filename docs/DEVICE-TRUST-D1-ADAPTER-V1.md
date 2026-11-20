# Device Trust D1 Adapter v1

**Status:** IMPLEMENTED + TESTED only after branch CI succeeds. Not production validated.

## Included

- `src/device-trust-d1-store.js`: Cloudflare D1-compatible implementation of the device trust store contract.
- `migrations/0001_device_trust_registry.sql`: proposed schema for tenant-scoped public keys and consumed challenges.
- `test/device-trust-d1-store.test.js`: adapter contract tests using a deterministic D1 test double.

## Wiring

```js
import { createD1DeviceTrustStore } from "./device-trust-d1-store.js";
import { createDeviceTrustRegistry } from "./device-trust-registry.js";

const store = createD1DeviceTrustStore(env.DB);
const registry = createDeviceTrustRegistry({
  store,
  authorize: trustedHostAuthorization
});
```

The host must supply `env.DB` only after an authorized deployment/configuration process, and `trustedHostAuthorization` must derive tenant and actor from authenticated host context. Never pass untrusted request claims as proof of authorization.

## Atomicity and isolation

- Key uniqueness: primary key `(tenant_id, issuer_id, key_id)`; insertion uses `INSERT OR IGNORE`.
- Replay uniqueness: primary key `(tenant_id, device_id, challenge_id)`; consumption uses `INSERT OR IGNORE`.
- Revocation is a conditional state transition from active to revoked.
- All lookup statements constrain the full tenant/issuer/key tuple.
- The adapter checks D1's `success` and `meta.changes`; it does not report a write as successful unless exactly one row was changed.
- SQLite uniqueness constraints provide the cross-request race boundary; a prior SELECT followed by INSERT is deliberately not used.

## Deployment boundary

The migration is a source artifact only. It has NOT been applied to D1. No database, Worker, binding, secret, production setting, or Cloudflare resource was created or modified. The unit tests use a test double and do not prove behavior against a live D1 instance.

Before production use, an authorized operator must review/apply the migration in a non-production D1 database, run an integration test against that actual D1 binding, configure authenticated host authorization, set challenge retention/cleanup policy, and only then plan any production rollout.

## Limitations

This adapter does not authenticate tenant identity, perform device enrollment ceremonies, verify signatures itself, manage hardware roots of trust, clean expired challenge rows, rotate keys, or call SafetyInterlock/MissionBrain. The existing Ed25519 verifier can use the registry's `resolveTrustedKey` method; the host must also consume the challenge and fail closed if consumption fails.
