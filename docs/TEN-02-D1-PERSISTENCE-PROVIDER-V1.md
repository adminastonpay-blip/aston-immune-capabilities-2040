# TEN-02 D1 Persistence Provider v1

Status: IMPLEMENTED + UNIT TESTED (isolated fake D1 binding). Not validated against a live Cloudflare D1 database. Migration is proposed and unapplied.

## Design

The provider implements the existing `applyTenantLifecycleCommand(mutation)` store contract using Cloudflare D1's `prepare().bind()` and `batch()` APIs.

One D1 batch contains:
1. An idempotency INSERT with a unique key on (actor principal, idempotency key).
2. A readback SELECT for the resulting idempotency row.

SQLite triggers run inside that same D1 batch transaction. The insert trigger validates the requested lifecycle transition, mutates the tenant row, and appends the audit event. If a trigger or constraint aborts, D1 rolls back the batch. The provider does not issue BEGIN/COMMIT or pretend separate D1 requests form a transaction.

## Idempotency

- Scope: authenticated administrator principal + idempotency key.
- Fingerprint: SHA-256 over canonical operation, tenant, target state, reason, actor, scope and correlation ID.
- Same fingerprint returns replay and the original audit event ID.
- Different fingerprint returns idempotency_conflict.
- The unique primary key serializes competing submissions for the same actor/key.

## Lifecycle transitions

- create: absent -> pending
- activate: pending/suspended -> active
- suspend: active -> suspended
- revoke: pending/active/suspended -> revoked
- revoked and offboarded are terminal in this v1 schema.

A database trigger rejects invalid transitions before committing the idempotency record. Tenant version increments on each successful non-create transition.

## Audit

The trigger appends one event in the same atomic batch. Audit and idempotency rows reject UPDATE and DELETE. The audit event ID is supplied by a trusted host factory; no secret values are stored.

## Required host integration

- Supply the authenticated D1 binding.
- Supply a collision-resistant, trusted audit ID factory.
- Apply migration 0002 through the approved migration process.
- Map D1 constraint/trigger failures to stable control-plane reason codes without exposing raw SQL errors.
- Ensure only the trusted control-plane service can write these tables; tenant-facing agents must not receive this binding.

## Explicit limits

- No migration has been applied to any D1 database.
- Tests use a fake D1 binding and inspect SQL/batch behavior; they do not execute SQLite triggers or prove Cloudflare runtime behavior.
- No live concurrency, rollback, latency, or durability test has been performed.
- No Cloudflare binding, Worker, secret, production database, ASTON OS 15.5 repository, or main branch was changed.
- This module returns persistence outcomes only; it does not authorize administrators or execute tenant workloads.
