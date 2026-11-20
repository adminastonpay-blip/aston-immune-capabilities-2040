# TEN-02 Tenant Lifecycle Transactional Store Adapter v1

Status: IMPLEMENTED / TESTED IN ISOLATED TEST FIXTURE  
Not validated against a production database. Not deployed. No D1 migration has been applied.

## Purpose

Implements the persistence boundary required by `executeTenantLifecycleCommand`:
`applyTenantLifecycleCommand(mutation)`. It composes lifecycle state mutation,
idempotency, and audit append inside one injected transaction callback.

## Transaction provider contract

The host must inject `transaction(callback)`. The provider MUST guarantee:
- serializable isolation or an equivalent concurrency-safe locking/uniqueness strategy;
- atomic commit and rollback for every operation performed in the callback;
- unique tenant IDs and unique idempotency scope keys;
- durable storage for tenant records, idempotency records, and append-only audit events;
- no success response before the transaction commits.

The transaction object must implement:
- `getTenant(tenantId)`
- `insertTenant(record)`
- `updateTenant(tenantId, expectedVersion, patch)`
- `getIdempotency(scopeKey)`
- `insertIdempotency(scopeKey, record)`
- `appendAuditEvent(event)`

The adapter is database-agnostic. It does not claim that Cloudflare D1 provides this transaction contract through a sequence of ordinary statements. A concrete D1 provider requires a separately reviewed implementation and verified transaction semantics.

## Idempotency

The idempotency scope is administrator principal plus caller key. The fingerprint binds
operation, target tenant, target status, reason, administrator principal, authorization
scope, and correlation ID. Reuse with the same fingerprint returns the original audit
event reference. Reuse with a different fingerprint returns `idempotency_conflict`.

The provider must enforce uniqueness and serialization for concurrent requests. A
uniqueness race that cannot be resolved to a replay must abort/fail closed; it must not
produce a partial mutation.

## Lifecycle transitions

| Operation | Allowed prior state | New state |
| --- | --- | --- |
| create | absent | pending |
| activate | pending, suspended | active |
| suspend | active | suspended |
| revoke | pending, active, suspended | revoked |

Revoked and offboarded are terminal. Every successful transition increments the tenant
record version. Version conflicts abort the transaction.

## Audit

A successful transition appends a lifecycle event and stores its safe event ID in the
idempotency record in the same transaction. The audit event excludes the idempotency key.
The provider must make audit events append-only and must not allow mutation success when
audit append fails.

## Security boundary

This adapter is not an authentication or authorization provider. The upstream control
plane must continue to authorize the administrator before calling the store. All results
remain non-executable: this module records tenant lifecycle state only.

## Verification

Node test fixture exercises create, replay, fingerprint conflict, principal scoping,
transition enforcement, version increments, rollback behavior, malformed records, and
audit content. The fixture is not a substitute for a real database concurrency or
durability test.
