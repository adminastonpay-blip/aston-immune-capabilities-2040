# ASTON OS 15.5 Host Execution Bridge — v1

**Status:** Compatibility bridge implemented in isolated capabilities repository. Not installed in ASTON OS 15.5. Not production validated.

## Source compatibility facts

The inspected host Identity interface contains actor, method, tenant, roles, clearance and optional plan. The current Access authentication path verifies a Cloudflare Access JWT but returns only the email-derived actor and custom tenant/roles/clearance/plan; it discards the verified JWT issuer and subject. The API-key path uses the shared legacy tenant default; the sensor path uses the static actor lb-sensor and legacy tenant ops.

The tenant authority bridge requires a stable verified principal and an active non-legacy tenant binding. It correctly rejects default, ops, synthetic unassigned-* tenants, missing Access issuer/subject, and sensors without a stable credential ID.

## Implemented isolated bridge

- src/aston-155-host-execution-bridge.js accepts the existing ASTON Identity shape.
- A privileged resolveVerifiedPrincipal host callback must recover issuer/subject from verified Access authentication context and stable sensor credential IDs. It must never copy request-body/header values.
- It forwards only enriched authenticated context to the existing tenant authority + SafetyInterlock + per-action decision perimeter.
- All outcomes remain decision-only; the bridge never invokes D1, Queue, Mission, Workflow, R2, or Vectorize adapters.

## Required host-side prerequisite

The current host code does not expose the necessary verified claims to route handlers. A future host change must preserve issuer and subject from the already-verified JWT in a trusted internal context (not a caller-controlled header), and must provide a stable sensor credential ID. API keys must be provisioned into an authoritative per-tenant credential registry; the shared default tenant cannot be grandfathered.

Until these prerequisites and the authoritative tenant records exist, protected requests must remain blocked/review. Do not deploy this bridge or claim host integration from this repository change.

## Safety boundary

This branch changes only the independent capabilities repository. No ASTON OS 15.5 file, main branch, Cloudflare Worker, D1 database, binding, secret, Durable Object, Queue, Vectorize index, or deployment was modified.