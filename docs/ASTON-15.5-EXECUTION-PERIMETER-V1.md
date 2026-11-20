# ASTON OS 15.5 Execution Perimeter — v1

**Status:** Isolated contract + tests implemented. Host routes NOT modified. Host integration NOT proven.  
**Reviewed:** 2026-11-20  
**Host source:** `adminastonpay-blip/agente-OS-15.5-hector-zapata` (read-only inspection)

## Objective

Ensure every high-impact route obtains authenticated identity, authoritative active tenant, SafetyInterlock approval, a tenant lifecycle recheck, and action-specific policy approval before a protected side effect.

## Required order

1. Authenticated host identity.
2. Authoritative credential-to-tenant binding and active tenant lifecycle.
3. Tenant-partitioned SafetyInterlock evaluation for the exact action.
4. Re-read tenant lifecycle/version after SafetyInterlock.
5. Action-specific policy and approval checks.
6. Decision-only result; host performs the side effect only after the entire gate passes.

For multi-step plans, repeat this sequence for EVERY action. A plan-level check cannot authorize every future action.

## Host route findings

The following route implementations were inspected. Their current controls are recorded as observed, not as claims of sufficient protection.

| Route | Existing control observed | Required close-out |
|---|---|---|
| `POST /v1/agents/plans/:id/execute` | Access decision, persisted single-use human approval, plan digest, risk envelope, per-action access | Add SafetyInterlock per action and tenant lifecycle checks before each side effect |
| `POST /v1/factory/run` | Optional payment check, recipe execution | Require tenant authority, SafetyInterlock per recipe step, and action-specific authorization |
| `POST /v1/sandbox/exec` | Proxies directly to Safety DO sandbox endpoint | Verify exact DO sandbox contract, tenant authority, timeout, approval and actual runtime availability |
| `POST /v1/mission` | Direct MissionBrain DO dispatch | Require authoritative tenant, SafetyInterlock and mission-specific policy before dispatch |
| `POST /v1/simulation/commit` | Direct Simulation DO dispatch | Require authority and SafetyInterlock for commit; distinguish simulation from real side effects |
| `POST /v1/recovery/diagnose` | Signed mission token, actor/tenant/action/payload binding | Add lifecycle authority and SafetyInterlock before workflow creation |
| `POST /v1/etl/enqueue` | Tenant and actor presence check | Require authoritative tenant and scoped queue-write policy before send |
| `POST /v1/rag/ingest` | Tenant namespace, binding checks, D1 and Vectorize writes | Require lifecycle authority and data-write policy before first write |
| `POST /v1/ontology/types` | D1 binding presence | Require tenant authority and action-specific authorization |
| `POST /v1/ontology/objects`, `/links` | D1/Graph binding and identity scoping | Require lifecycle authority and action-specific authorization |
| `POST /v1/constitution` | Tenant-scoped persistence | Require policy issuer authorization and immutable/versioned policy updates |
| `POST /v1/defense/approve` | Authenticated actor forwarded to Safety DO `/decide` | Verify approval is bound to tenant, action digest, approver role, expiry and single use |

Additional concern: `/v1/risk/score` and `/v1/risk/assess` accept a caller-provided `human_approved` boolean as an input to scoring. It must never be treated as a real approval. The durable approval in the governed-plan flow is stronger, but it still does not replace SafetyInterlock.

The `/v1/constitution/check` endpoint explicitly reports caller-supplied, advisory, non-authoritative input; it must not be used as an execution permit.

## Isolated implementation in this repository

- `src/aston-execution-perimeter.js` provides a route inventory and a per-action gate wrapper.
- Each plan step calls the existing tenant-authority + SafetyInterlock gateway independently.
- The plan stops at the first denied, pending, malformed, or non-decision-only result.
- No method dispatches a tool or mutates host state.
- The inventory deliberately reports `hostIntegrated:false` for every route until source-level integration and real-route tests prove otherwise.

## Validation limits

Unit tests prove the isolated wrapper's sequencing and fail-closed behavior only. They do not prove ASTON 15.5 currently invokes the wrapper, nor that every production route is covered.

## Required host integration and close-out evidence

1. Wire authoritative tenant resolver before protected side effects.
2. Wire this perimeter (or equivalent) into governed-plan execution, factory recipe steps, mission dispatch, simulation commit, sandbox execution, recovery workflow creation, queue writes and data mutation routes.
3. Do not accept request-body booleans as human approval.
4. Add route-level tests that instrument D1, Vectorize, R2, Queues, DO and Workflow mocks and assert zero writes/dispatches for inactive tenant, SafetyInterlock denied/pending/timeout, tenant version change, malformed contract, and replayed approval.
5. Run staging integration against actual configured D1/DO bindings. Only after those pass can the integration be marked VALIDATED.

## Safety boundary

No ASTON OS 15.5 source file, main branch, Cloudflare Worker, D1 database, binding, secret, Durable Object, Queue, Vectorize index, or production deployment was changed. No route is described as fully protected or production-ready by this isolated deliverable.


## Integration harness close-out — v1.1

The isolated integration harness now composes the real tenant-authority gateway and execution perimeter with instrumented test doubles. It verifies:

- SafetyInterlock exceptions become a fail-closed `review` result; they do not escape as unhandled errors.
- Denied and pending-approval responses do not invoke the capability evaluator or downstream host adapters.
- A tenant lifecycle version/status change after SafetyInterlock blocks capability evaluation.
- Action-specific policy denial blocks the host adapter.
- Multi-action plans re-run the full gateway for each step and stop at the first blocked step.
- A capability result claiming `executable:true` is rejected.

The harness counts simulated D1 writes, Queue sends, Mission dispatches, capability evaluations, and SafetyInterlock calls. These are test doubles only: this is not a live D1, Durable Object, Queue, R2, Vectorize, Workflow, or production test.

A successful CI run establishes **IMPLEMENTED + TESTED in the isolated repository**. It does not establish host route integration or production readiness. The host must still enforce the same gate before each real side effect.
