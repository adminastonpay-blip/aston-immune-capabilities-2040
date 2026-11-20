# Multi-Agent Defense — Trusted Evidence Adapter v1

**Status:** IMPLEMENTED in isolated branch; automated tests pending CI; VALIDATED no; PRODUCTION no.

## Purpose

The v1 triage engine accepts a normalized evidence assertion. That assertion must not be trusted when it originates from an agent or arbitrary request. This adapter removes caller-supplied verification fields and requires a host-controlled verifier result before a high/critical recommendation can be produced.

## Contract

`evaluateThreatWithVerifier(observation, { now, verifyEvidence })`

The verifier is injected by the authenticated host composition root. Its result must include:

- `verified: true`
- exact `eventId`, `tenantId`, `agentId`, and `observedAt` matching the observation
- bounded non-empty `reference` and `verifierId`

Missing verifier, verifier exception, false verification, or any binding mismatch becomes unverified evidence and therefore review-only. The underlying triage engine continues to emit `executable: false`.

## Critical trust boundary

This package does **not** implement cryptographic signature verification, trust-anchor management, issuer authorization, tenant authentication, key rotation/revocation, or proof of runtime integrity. The verifier must establish those properties independently before returning `verified: true`.

Never accept `verifyEvidence` from an agent, request body, queue payload, or other untrusted caller. The callback itself is a privileged dependency and must be wired only by the authenticated host composition root. No ASTON runtime integration is included in this change.

## Acceptance checks

- Caller-provided `evidence.verified` is ignored.
- Verification is bound to exact tenant, agent, event, and observation timestamp.
- Missing verifier, thrown verifier, and mismatched bindings fail closed to review.
- No action is executable; no network, storage, Cloudflare, or host side effects.
