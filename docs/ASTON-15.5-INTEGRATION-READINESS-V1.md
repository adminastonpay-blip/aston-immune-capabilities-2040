# ASTON OS 15.5 Integration Readiness — v1

**Review date:** 2026-11-20  
**Scope:** Read-only source inspection of ASTON OS 15.5 plus isolated bridge implementation.  
**Production changes:** None.  
**Verdict:** Bridge contract implemented and CI-tested; host runtime integration is not yet safe to activate.

## Confirmed host interfaces

### Authentication and Identity

The inspected ASTON host code currently:
- Verifies Cloudflare Access JWTs for RS256 signature, issuer, audience, expiry, and not-before.
- Uses the Access custom tenant claim as `Identity.tenant`; missing/malformed claims become synthetic `unassigned-...`.
- Assigns API-key authentication to shared tenant `default` with roles `admin, executor`.
- Assigns sensor authentication to tenant `ops` with static actor `lb-sensor`.
- Exposes Identity fields `actor, method, tenant, roles, clearance, plan`.

The Identity type currently omits verified Access JWT issuer/subject and a unique sensor credential ID. It has no authoritative tenant lifecycle version. The API-key and sensor paths do not have per-credential tenant bindings in the inspected code.

The existing TEN-02 design note in the host repository explicitly records that no authoritative tenant registry or approved provisioning source was identified. A signed JWT claim is not itself a lifecycle authority.

### SafetyInterlock

The inspected host uses the existing Durable Object namespace `SAFETY`:
- `SAFETY.idFromName(tenantId)` and `SAFETY.get(id)`.
- `POST https://do/evaluate` with `{ action, identity }`.
- Contract version `1` and statuses `allowed`, `denied`, `pending_approval`.

AgentNode calls SafetyInterlock before model planning, before each tool, and before synthesis. It executes a tool only after an exact `allowed` response. Missing binding, timeout, malformed contract, or unknown status fail closed.

The sovereign sandbox route also forwards requests to the SafetyInterlock Durable Object. Its status document reports Containers are not enabled; therefore the route is not evidence of a functioning Linux sandbox.

### Other governed execution paths

The inspected governed-agent plan path uses access policy, risk-envelope checks, and persisted human approval before simulated plan execution. The source audit does not establish that this path calls the same SafetyInterlock decision point.

The existing constitution check endpoint is documented in the host audit as an advisory calculation over caller-supplied input, not a server-authoritative execution permit.

## Integration gaps that must be closed before activation

1. Host authentication must preserve verified Access `iss` and `sub` and a unique sensor credential identifier in trusted context.
2. The tenant provisioning owner and credential-to-tenant enrollment source must be approved. No tenant mappings may be guessed.
3. The approved D1 database must receive migration 0002 through a separately authorized migration process.
4. The host must run tenant lifecycle authorization before protected reads, AI calls, queue writes, Durable Object actions, or other side effects.
5. The SafetyInterlock gate must be enforced at every execution entry point, including governed plans and any future capability dispatch—not merely AgentNode.
6. Human approval routes must bind the approval to authenticated approver, tenant, action digest, expiry, and single-use consumption.
7. Real-route adversarial tests must assert zero side effects for unknown/suspended/revoked tenants, identity mismatch, SafetyInterlock denial, timeout, and missing bindings.

## Isolated bridge delivered

The capability repository now contains:
- `src/aston-tenant-runtime-authority.js`: D1 read-only lifecycle reader, trusted credential-binding adapter, and SafetyInterlock contract-v1 adapter.
- `src/aston-capability-runtime-gateway.js`: orders tenant authority -> SafetyInterlock -> decision-only capability evaluator.
- Tests cover Access issuer/subject matching, API-key fingerprint mapping, sensor fail-closed behavior, active/suspended/revoked tenants, provider failures, tenant-partitioned SafetyInterlock requests, malformed responses, and no evaluator invocation before both gates allow.

## Status

| Area | Status |
|---|---|
| SQLite migration and trigger semantics | TESTED — 9 real SQLite integration tests |
| D1 provider behavior | UNIT TESTED — fake D1 binding; no live D1 |
| Host identity adapter | IMPLEMENTED + TESTED; waiting on missing host identity fields and approved credential authority |
| SafetyInterlock adapter | IMPLEMENTED + TESTED against the documented DO contract; no live DO test |
| Capability gateway ordering | IMPLEMENTED + TESTED; isolated evaluators only |
| Full ASTON route integration | NOT IMPLEMENTED |
| Production / Cloudflare | NOT VALIDATED; untouched |

## Deployment boundary

No host source, main branch, Cloudflare binding, D1 database, Durable Object, secret, Worker, or deployment configuration was changed. The bridge is intentionally fail-closed until the authoritative credential source and host integration are approved.
