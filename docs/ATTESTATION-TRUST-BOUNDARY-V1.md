# Attestation Trust Boundary v1 — Integration Decision Record

**Status:** DESIGN ONLY  
**Date:** 2026-11-20  
**Scope:** Isolated capability repository; no runtime or infrastructure integration.

## Decision

Do not map an ASTON Agent Attestation document directly to `evidence.verified`. The published schema is descriptive; schema validity and a declared verification status are not proof that a signature, issuer identity, or tenant binding has been independently verified.

Multi-Agent Defense may only receive a trusted verification result from a separately specified verifier adapter. Until that adapter contract and its trust policy exist, evidence remains untrusted and the decision engine must not be upgraded to treat it as verified.

## Source facts inspected

Repository: `adminastonpay-blip/aston-attestation-sdk`  
Default branch: `main`  
Release identified by its README: `v1.0.0`

Inspected files:
- `README.md` — explicitly states that schema validation does not generate or verify signatures, prove key ownership, validate timestamps or transparency logs, or guarantee runtime/model integrity.
- `agent-attestation.schema.json` — requires `schema_version`, `attestation_id`, `created_at`, `agent`, `issuer`, `execution`, and `verification`. It describes optional `signatures`, digests, evidence, provenance, and transparency references.
- `SECURITY.md` — states that a valid signature proves only that signed bytes verify under a public key; identity requires an independently established trust policy. A fully verified OpenTimestamps proof supports an existence-time bound, not authorship or truth.

## Compatibility gaps

1. **No tenant binding in schema v1.0.0.** The schema does not define `tenant_id` or an equivalent mandatory tenant-scoping claim. A tenant value must not be inferred from `agent.id`, `issuer.id`, or an untrusted extension.
2. **No verifier implementation contract established by the inspected README/schema.** The `verification.status` field is a document claim unless a consumer independently performs and records verification.
3. **No signature profile selected.** Signature algorithm, signed-byte canonicalization, signature encoding, key resolution, trust anchors, rotation, revocation, and algorithm allowlists must be specified before implementation.
4. **No issuer-to-agent authorization rule.** Cryptographic validity alone does not establish that an issuer is authorized to attest for a particular agent or tenant.
5. **No freshness/replay binding.** The consumer must define how attestation time, execution time, event ID, nonce, and replay protection relate to the Multi-Agent Defense observation window.
6. **No trusted result provenance contract.** The host must authenticate the verifier result and bind it to the exact attestation digest, tenant, agent, policy version, and verification time.

## Required adapter contract before implementation

A future adapter result must be produced only after independent checks and must be cryptographically or transport-authenticated between the verifier and the capability. At minimum it must bind:

- exact attestation digest and schema version;
- tenant ID from an independently authenticated tenant context (not from an untrusted attestation claim);
- agent ID and issuer ID, plus an explicit authorization decision linking issuer → agent → tenant;
- signature algorithm/profile, key ID, trust-policy version, key status and revocation result;
- signature verification result and all required digest checks;
- timestamp/freshness and replay result;
- verifier identity, verification timestamp, and a stable decision/reference ID.

Any missing, unsupported, failed, skipped, or indeterminate mandatory check must yield an untrusted result. No adapter output may enable automatic containment; Multi-Agent Defense remains recommendation-only.

## Required tests

- malformed and unsupported schema versions;
- missing signature, altered signed bytes, altered digest, unknown key, revoked key, wrong algorithm, and key-confusion attempts;
- valid signature from an issuer not authorized for the agent;
- valid issuer/agent pair presented under the wrong authenticated tenant;
- tenant claim mismatch and attempts to override tenant context using extensions;
- stale/future timestamps, replayed event/nonce, and mismatched attestation digest;
- verifier result tampering, wrong policy version, and missing/indeterminate checks;
- fail-closed behavior for every negative case.


## Related ASTON Trust Infrastructure candidate inspected (read-only)

Repository: `adminastonpay-blip/aston-trust-infrastructure`, default branch `main`.

Inspected:
- `src/hmac-passport.ts` at blob `18f5cec63ce4682bcb9a3c7f92279793b2889bb7`.
- `src/poi/proof-of-intention.ts` at blob `2677c47ef1ed77bfc2cfd08e40192a4effd4bc35`.

The HMAC Decision Passport candidate includes `tenant`, `actor`, `replay_key`, `issued_at`, `kid`, and an HMAC-SHA256 signature; it exports `verifyPassport`. This is a potentially reusable existing primitive, but it is **not yet an approved adapter** for Multi-Agent Defense:
- It uses a shared secret, not the public-key signature profile represented by the Attestation SDK schema.
- Its verifier proves MAC integrity under the supplied secret; it does not independently establish that the supplied tenant/actor is the authenticated caller or that the issuer is authorized for that tenant/agent.
- The current source uses a simple derived `kid`; key lifecycle, rotation, revocation, trust-policy versioning, and cross-service secret distribution are not established by this file alone.
- The Proof-of-Intention source contains tenant and nonce fields, but its package hash and status flow are not a substitute for an authenticated signature or issuer authorization.

Therefore, treat this as a candidate to evaluate, not a verified dependency or production-ready trust root. Do not import or modify it in this capability until its owner contract, secret lifecycle, authenticated tenant source, and test evidence are established.

## Explicit non-goals

- No changes to `agente-OS-15.5-hector-zapata` or any other runtime repository.
- No Cloudflare Workers, D1, KV, R2, Vectorize, Durable Objects, secrets, bindings, or production configuration changes.
- No real containment, agent shutdown, credential revocation, or cross-tenant action.
- No claim of VALIDATED or PRODUCTION.

## Exit criterion

Implementation may begin only after the verifier profile, authenticated tenant source, issuer authorization model, key lifecycle/trust policy, and signed-payload canonicalization are specified and testable. Until then this record is the completed output of the contract-discovery step; it is not a production integration.
