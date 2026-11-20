# TEN-02 Control Plane Contract v1

Status: IMPLEMENTED + TESTED IN ISOLATED LABORATORY. NOT HOST-VALIDATED. NOT RUNTIME-INTEGRATED. NOT PRODUCTION.

## Purpose and trust boundary

This module defines the administrative write-side contract for tenant lifecycle changes. It is deliberately separate from the read/evaluation contract in `tenant-authority-contract.js`.

- Evaluation plane: reads authoritative tenant and membership state to decide whether a workload may proceed.
- Control plane: accepts authenticated administrative lifecycle commands and records approved state changes.
- The capability modules do not access D1 or lifecycle tables directly.

The host must supply a privileged `authorizeAdmin` callback. It must derive the principal from authenticated host context and enforce the approved administrator policy. Request bodies cannot supply proof of administrator authority.

## Supported operations

| Operation | Resulting state | Required capability |
|---|---|---|
| create | pending | tenant.create |
| activate | active | tenant.activate |
| suspend | suspended | tenant.suspend |
| revoke | revoked | tenant.revoke |

Creation starts in `pending`; it never creates an immediately active tenant. The storage implementation must enforce the allowed transition graph and must not reactivate revoked/offboarded tenants. This contract does not prescribe an unapproved transition policy beyond the requested operation; the store must reject invalid transitions.

## Command requirements

Every command requires:
- Canonical tenant ID (same strict ASCII lowercase rule as TEN-02 evaluation; legacy `default`, `ops`, and `unassigned-*` are rejected).
- Supported lifecycle operation.
- Human-readable reason of 8-500 characters.
- Bounded idempotency key.
- Authenticated administrator principal from host context.
- Authorization for the exact operation and target tenant.
- Correlation ID where available.

A platform-scoped administrator may administer tenants globally only when the host explicitly grants the operation capability. A delegated administrator may administer only the exact target tenant named in the host authorization result, and only when that target differs from the administrator's own home tenant. Tenant-scoped self-administration is forbidden. The host authorization provider remains responsible for authenticating platform administrators and issuing narrow, auditable cross-tenant delegations.

## Atomic store boundary

The only write method is:

`store.applyTenantLifecycleCommand(mutation)`

The store implementation MUST atomically:
1. Check the idempotency key in its correct administrative scope.
2. Compare the canonical command fingerprint if the key already exists.
3. Return `replayed` for the same command, or `idempotency_conflict` for different command content.
4. Validate the current-to-target lifecycle transition.
5. Apply the lifecycle state mutation.
6. Append an immutable audit event with actor, operation, target tenant, reason, timestamp and correlation reference.
7. Commit mutation, idempotency record and audit event together, or commit none.

The adapter treats `applied` and `replayed` as recorded only when a safe audit event ID is returned. Storage errors, malformed responses and transition conflicts never produce success. A database implementation must use a real transaction or an equivalent atomic primitive; a sequence of independent writes is insufficient.

## Audit and privacy

Audit records should include event ID, tenant ID, previous and new state, operation, actor principal, authorization scope, reason, idempotency reference, timestamp and correlation ID. They must not contain raw JWTs, API keys, private keys, session cookies or unnecessary PII. Audit history must be append-only to ordinary administrators; corrections should be represented by new events.

## Laboratory implementation

The module implements the authorization/validation boundary and calls an injected atomic store interface. Tests use a deterministic fake store to exercise authorized lifecycle operations, capability/identity checks, delegated target scope, self-tenant restriction, missing/failed authorization, idempotent replay, idempotency conflict, transition rejection, persistence failures, malformed responses, audit reference requirements and non-executable outcomes.

The fake store is test-only. It does not provide durable idempotency, database transactions, append-only audit guarantees, concurrency safety or production lifecycle enforcement.

## Explicit non-goals and blockers

- No production administrator or tenant provisioning owner has been identified.
- No admin API, authentication endpoint, UI, D1 schema, migration or database write is created.
- No actual D1 transaction implementation, durable idempotency ledger or audit table is included.
- No runtime wiring, Cloudflare change, deployment, PR merge or production activation occurs.
- The host must approve who may create, activate, suspend and revoke tenants, the tenant transition graph, emergency/break-glass policy, and the authenticated platform-admin source.

Until those governance decisions and a real transactional store are validated, this is a laboratory contract only.
