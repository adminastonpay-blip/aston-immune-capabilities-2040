# ASTON OS 15.5 — Production Release Closure v1

**Status:** EXECUTION PLAN OPEN — NOT A PRODUCTION APPROVAL  
**Created:** 2026-11-20  
**Repository:** `aston-immune-capabilities-2040`  
**Branch:** `feat/production-release-closure-v1`  
**Host repository:** `agente-OS-15.5-hector-zapata`  
**Production changes authorized:** None by this plan

## Objective

Close the remaining integration work in one bounded release program so ASTON OS 15.5 can receive a single evidence-backed integration PR. Preserve existing runtime behavior. Do not merge capability work into the host `main` until every mandatory gate below passes.

This is not a rebuild of ASTON OS and does not authorize production deployment, live D1 migrations, secret changes, Worker changes, Durable Object changes, or Cloudflare binding changes.

## Confirmed facts from the current host `main`

1. `src/auth.ts` verifies Cloudflare Access JWT signature, issuer, audience, expiry and not-before, but returns only the current public `Identity` fields. Verified JWT `iss` and `sub` are discarded.
2. API-key authentication maps the shared configured secret to tenant `default`; this is not a tenant-specific credential enrollment.
3. Sensor authentication reuses the same configured API secret and maps to static actor `lb-sensor` and tenant `ops`; there is no stable per-device credential identifier.
4. `src/types.ts` has no trusted internal principal context or authoritative tenant lifecycle version.
5. `wrangler.toml` defines production D1 binding `DB` -> `sos-db` and a separate Preview D1 binding -> `aston-rag-staging-db`. The existence of a Preview binding is not proof that the new TEN-02/device-trust schemas have been applied or validated there.
6. The current host SafetyInterlock binding exists in configuration, but isolated contract tests are not live Durable Object integration evidence.

## Work packages — bounded and ordered

### W1 — Trusted host identity (mandatory)

- Introduce an internal authenticated-principal context created only after successful host verification.
- Preserve verified Access issuer and subject from the already-verified JWT; never re-read them from request headers or body.
- Replace shared API-key tenant assignment with a credential registry lookup that binds a stable credential fingerprint to one active tenant and explicit capabilities.
- Replace shared sensor secret/static actor with unique sensor credential IDs bound to tenant, device, issuer, status, and allowed capabilities.
- Keep internal proof material out of public API responses and logs.
- Unknown, suspended, revoked, ambiguous, or mismatched credentials must fail closed.
- Add regression tests for existing authentication behavior and all negative cases.

**Acceptance:** no protected action can obtain an authoritative tenant from a caller-controlled field, shared legacy tenant, or unverified claim.

### W2 — Authoritative tenant and credential persistence (mandatory)

- Review TEN-02 and device-trust migrations as one schema set; detect naming collisions and migration ordering before applying anything.
- Use the isolated Preview D1 database only after confirming it is disposable/staging and its current schema/version.
- Apply migrations to Preview through the repository's documented migration workflow only after explicit staging authorization.
- Verify real D1 reads, writes, uniqueness, idempotency, revocation, lifecycle transitions, audit append-only behavior, and failure rollback.
- Keep production `sos-db` untouched until a separate production change window and explicit authorization.

**Acceptance:** integration tests run against actual Cloudflare Preview D1, not a fake binding or local SQLite alone; tenant lifecycle and credential state are read from authoritative persisted records.

### W3 — Runtime enforcement (mandatory)

- Connect the trusted principal and authoritative tenant reader to the actual host request boundary.
- Enforce tenant lifecycle before protected reads and before any side effect.
- Enforce SafetyInterlock at each real execution entry point, not only the isolated gateway or AgentNode happy path.
- Re-check tenant lifecycle immediately before each side effect.
- Ensure pending approval, denial, timeout, missing binding, malformed response, and thrown exceptions stop execution.
- Do not route capability modules into production dispatch until their own explicit adapters and route tests exist.

**Acceptance:** route-level tests demonstrate the exact order: authenticated principal -> active tenant -> SafetyInterlock allow -> lifecycle recheck -> action policy -> existing operation. All other outcomes produce zero side effects.

### W4 — Capability integration (bounded)

Integrate only capabilities whose host adapter, authority source, SafetyInterlock gate, replay/idempotency behavior, and route-level tests are complete:
- Multi-Agent Defense
- Agentic Escrow
- Inter-Agent Governance
- Physical Edge Attestation

A module remaining decision-only is not a production integration. Escrow must not move money; edge attestation must not actuate equipment; governance must not dispatch agents until separately authorized and validated end-to-end.

**Acceptance:** each enabled capability has a documented route, authority contract, negative-path test, and explicit disabled-by-default state until its gate passes.

### W5 — Release verification

- Run all repository CI suites from the final candidate commit.
- Run typecheck, lint, unit tests, SQLite migration tests, and Cloudflare Wrangler dry-run using the exact candidate configuration.
- Run Preview D1 and Preview Durable Object integration tests.
- Run adversarial route tests for unknown/suspended/revoked tenant, wrong issuer/subject, wrong device, replay, expired evidence, duplicate idempotency key, SafetyInterlock deny/pending/timeout/error, and partial storage failure.
- Compare the candidate against host `main`; require zero unrelated deletions and no unreviewed production configuration changes.
- Prepare one final PR with a rollback plan and an implementation/validation/production evidence matrix.

**Acceptance:** all required CI and Preview integration checks pass on the exact PR head; no unexplained failures or waived mandatory gates.

## Non-negotiable safety boundary

- Do not edit host `main`.
- Do not merge any capability PR to host `main` during this work.
- Do not apply migrations to production D1.
- Do not change Cloudflare production bindings, secrets, Durable Objects, queues, Vectorize, R2, Workers, or deploy.
- Do not weaken fail-closed checks to make legacy identities pass.
- Do not describe local/fake/SQLite tests as live Cloudflare validation.
- Do not mark a capability PRODUCTION until its real host route and production controls have been validated.

## Current release decision

**NO-GO for host `main` today.** The verified identity context, authoritative credential/tenant registry, real Preview D1 validation, and real route/SafetyInterlock integration are not yet demonstrated.

The work is considered complete when W1–W5 pass and the final PR is ready for the user's explicit merge decision. No additional audit cycle is opened unless a concrete failed acceptance test reveals a defect.


## Additional host findings from the integration branch inspection

- The host repository currently uses date-prefixed D1 migration filenames (for example `20261117_tenant_scoped_links.sql` and `20261119_lineage_tenant_isolation.sql`). The proposed capability migrations use `0001_...` and `0002_...`; before host adoption, they must be reconciled with the host migration convention and the actual D1 migration history. Do not copy them into the host unchanged or apply them based on local ordering assumptions.
- Legacy tenant fallbacks are not isolated to authentication. Search results show several routes and data access paths still use `identity.tenant || "default"`. The final route inventory must remove shared-tenant fallback from protected operations, not just enrich the JWT identity.
- SafetyInterlock persists the supplied `Identity` JSON for pending approvals. Therefore verified issuer/subject proof must not be added casually to the public `Identity` object; keep trusted principal metadata in a separate internal context and explicitly bind approvals to that principal.
- The host `main` branch currently reports branch protection disabled. This is a repository governance gap; enable required CI/review protection before final merge if repository permissions allow. No settings were changed.

## Work started

- Created host feature branch `feat/aston-production-integration-v1` from host `main` commit `be8c92c017fd2586098b33bed1b16fdeb9214729`. The branch is isolated; no host source files have been changed yet.
- Created this bounded release-closure branch from the isolated capability integration work. No PR was opened and no merge was performed.
