# TEN-02 Tenant Authority Contract v1

Status: IMPLEMENTED + TESTED IN ISOLATED LABORATORY. NOT HOST-VALIDATED. NOT RUNTIME-INTEGRATED. NOT PRODUCTION.

## Architecture decision

The target architecture is hybrid:
- A single host-controlled Tenant Authority service owns authorization decisions and lifecycle policy.
- D1 is the intended durable persistence layer for tenant, principal, membership, credential-binding and audit records.
- Capability modules consume a narrow authorization contract. They do not invent tenant identity, interpret lifecycle independently, or fall back to alternate registries.

This repository implements only the deterministic contract and an injected authority-provider boundary. It does not create a D1 schema, provision tenants, or claim that a production authority exists.

## Canonical tenant identifier

Tenant IDs are validated, never silently normalized:
- 1-64 characters.
- Lowercase ASCII letters and digits, with internal hyphens only.
- Must begin and end with a lowercase letter or digit.
- No whitespace, underscores, dots, Unicode lookalikes, or ambiguous punctuation.
- Reserved legacy values `default`, `ops`, and all `unassigned-*` values are rejected.

The actor/principal is distinct from the tenant. Authentication method identifies how the actor authenticated; the authoritative membership record binds that principal to the tenant and its permissions.

## Authority record contract

The privileged `resolveAuthority({ principalId, authMethod, tenantId })` provider must return trusted records with:
- `tenant: { tenantId, status, notBefore?, expiresAt? }`
- `membership: { tenantId, principalId, status, capabilities[], audiences[], notBefore?, expiresAt? }`

The provider must resolve records from the host's approved source of truth. It must not echo request values as proof, accept authority data from an agent/request body, or silently use a fallback store.

Accepted lifecycle state is exactly `active`. `suspended`, `pending`, `unknown`, and any unrecognized state deny. `revoked` and `offboarded` deny as revoked. Membership must also be exactly active.

## Authorization checks

The evaluator requires:
1. Authenticated host identity with a supported method and non-empty principal.
2. Canonical tenant identity; no legacy aliases.
3. Exact equality between identity tenant, requested tenant and resource tenant.
4. Exact authoritative tenant and principal bindings.
5. Active tenant and active membership.
6. Valid tenant and membership time windows.
7. Exact audience and capability grants.
8. A functioning, complete authority response.

Maximum configurable clock skew is 30 seconds. No ID normalization is performed. Authority absence, exceptions and incomplete records fail closed with a non-allowing review result.

## Structured outcomes

Stable reasons include `UNRESOLVED_TENANT_IDENTITY`, `TENANT_NOT_ACTIVE`, `TENANT_REVOKED`, `TENANT_MISMATCH`, `MISSING_TENANT_AUTHORITY`, `AUTHORITY_UNAVAILABLE`, `AUTHORITY_DATA_INCOMPLETE`, `UNTRUSTED_HOST_CONTEXT`, `ACTOR_NOT_AUTHORIZED`, `ASSIGNMENT_NOT_YET_VALID`, `ASSIGNMENT_EXPIRED`, `AUDIENCE_MISMATCH`, and `CAPABILITY_NOT_AUTHORIZED`.

Correlation IDs are included only when they match a bounded safe token format. Provider exception text, tokens, credentials and arbitrary PII are never returned. Every result has `executable: false`; this contract only decides authorization and does not execute operations.

## Intended D1 model (not implemented)

The future persistence model is separated into:
- `aston_tenants`: canonical tenant ID, lifecycle status and lifecycle timestamps.
- `aston_principals`: actor/principal records and authentication identity.
- `aston_tenant_memberships`: tenant-principal binding, status, roles, capabilities, audiences and validity.
- `aston_credential_bindings`: trusted credential-to-principal/tenant bindings and revocation metadata.
- `aston_tenant_audit`: append-only lifecycle and authorization administration events.

The host authority service remains the sole decision point. D1 is storage, not an independent authorization engine. Schema design and migration require a confirmed provisioning owner, authoritative issuer/credential binding rules, and explicit production authorization.

## Laboratory acceptance coverage

Tests cover active exact match; suspended, revoked, offboarded, pending and unknown tenants; legacy aliases; malformed/noncanonical identifiers; tenant/resource/principal mismatches; inactive memberships; temporal validity and expiry; audience and capability denial; missing, throwing and incomplete providers; bounded clock skew; safe correlation IDs; non-mutation; and non-executable outcomes.

## Explicit limitations / next integration gate

- No authoritative tenant registry or provisioning owner has been identified in ASTON OS 15.5.
- No production D1 schema or migration has been created or applied.
- No cryptographic credential binding, issuer enrollment, tenant onboarding workflow, admin lifecycle API, or audit persistence is implemented here.
- No host adapter/runtime wiring, Cloudflare change, deployment, PR merge, or production activation is performed.

Before runtime integration, the ASTON platform owner must approve the source of truth, provisioning/offboarding authority, issuer-to-principal binding, and the host service interface. Until then, this is an executable laboratory contract only.
