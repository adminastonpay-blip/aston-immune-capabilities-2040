# ASTON OS 2040 — Existing Capability Interface Inventory v1

**Date:** 2026-11-20  
**Status:** READ-ONLY INVENTORY / DESIGN INPUT  
**Scope:** Inspect existing repositories and code contracts; no runtime, infrastructure, or production changes.

## Executive decision

Extend ASTON OS 15.5 through isolated capability modules and narrow, versioned adapters. Do not rebuild Workers, D1, Vectorize, Durable Objects, Queues, R2, SafetyInterlock, identity, or Trust Infrastructure where suitable components already exist.

This inventory distinguishes:
- **CODE FOUND:** source code or a contract exists in the inspected repository.
- **DOCUMENTED:** described in repository documentation only.
- **NOT PROVEN DEPLOYED:** source/binding declaration does not prove a live production resource or configuration.
- **GAP:** required behavior or contract was not established by inspected evidence.

The inventory is a source-code inspection, not a production audit or deployment verification.

## Repositories in scope

| Repository | Role in this expansion | Inspection |
|---|---|---|
| `agente-OS-15.5-hector-zapata` | Existing runtime and host services | Read-only source inspection |
| `aston-trust-infrastructure` | Shared trust, policy and decision primitives | Read-only source inspection |
| `aston-attestation-sdk` | Attestation document schema and security guidance | Read-only contract inspection |
| `aston-risk-protocol` | Risk vocabulary / protocol candidate | Listed as related repository; no interface claimed without a verified source contract |
| `aston-ots-verifier` | External timestamp proof verifier | Existing service-binding interface referenced by runtime; its current deployment status is not established here |
| `aston-immune-capabilities-2040` | Independent capability modules | Expansion workspace |

## 1. Existing host interfaces found in ASTON OS 15.5

### Identity and tenant context

**CODE FOUND**
- `src/types.ts` defines `Identity`: `actor`, `method` (`access | apikey | sensor | public`), `tenant`, `roles`, `clearance`, optional `plan`.
- The same file declares optional host bindings: AI, SESSION, GRAPH, SUPERVISOR, AGENT, SIMULATION, MISSION, SAFETY, REPLAY_GUARD, DB, VECTORIZE, JOURNAL, AUDIT_ARCHIVE, OTS_VERIFIER, ETL_QUEUE, MISSIONS and HYPERDRIVE.
- It defines `Mission` and `MissionParams`; the latter carries a signed `mission_token`.

**GAP / integration rule**
- A TypeScript interface is not an authenticated identity provider. Capability adapters must receive identity from the runtime's verified authentication boundary, never trust a tenant supplied in an arbitrary capability payload.
- Optional binding declarations do not prove production bindings are configured.

### SafetyInterlock and human approval

**CODE FOUND**
- `src/do/safety-interlock.ts`: Durable Object exposes `POST /evaluate`, `GET /pending`, `POST /decide`, audit append/verify and sandbox routes.
- `/evaluate` accepts a `ProposedAction` and `Identity`, applies `evaluatePolicy`, records execution/audit/lineage, and returns allow, deny or pending approval.
- Approval records include action, identity, policy, expiry and human decision metadata.
- `src/safety/policy.ts` defines risk scoring, high/critical tool lists and human-approval requirements.
- `src/do/agent-node.ts` calls the SAFETY Durable Object using tenant-scoped object IDs and fails closed when SAFETY is absent, invalid, or times out.
- `src/do/supervisor.ts` also checks the SafetyInterlock before planning and dispatch.

**Reuse candidate**
- Multi-Agent Defense: submit a narrowly scoped proposed action for policy evaluation; do not implement a second global safety gate.
- Agentic Escrow: use it as an approval/policy decision point, not as a payment ledger or settlement engine.
- Inter-Agent Governance: reuse policy vocabulary and approval records where the host contract permits.

**GAP**
- Do not assume every possible runtime execution path is gated merely because AgentNode and Supervisor call SafetyInterlock. No universal call-path coverage claim is made by this inventory.
- A future adapter must use the real authenticated host identity and tenant context; it must not forward a caller-controlled Identity object as authoritative.

### Durable Objects and replay protection

**CODE FOUND**
- `src/do/agent-node.ts`: agent execution entrypoint; safety checks before plan, tools and synthesis; uses tenant-scoped SafetyInterlock and tenant-scoped graph IDs.
- `src/do/supervisor.ts`: plans tasks and dispatches AgentNode instances.
- `src/do/mission-brain.ts`: mission diagnosis/journal and manual-action-only recovery path.
- `src/core/replay-guard.ts`: atomic SQLite single-use JTI consumption with expiry bounds; replay returns HTTP 409.
- `src/types.ts`: declares named Durable Object namespaces as optional bindings.

**Reuse candidate**
- Multi-Agent Defense: future adapter may address a specific tenant/agent object only through an approved host contract; use replay protection for one-time commands/events if the token contract matches.
- Agentic Escrow and Governance: use Durable Objects for per-tenant serialized state only if the required API and state ownership are explicitly approved.
- Physical Edge Attestation: use replay guard for nonce/JTI consumption after device identity and signature verification have been established.

**GAP**
- ReplayGuard's inspected contract accepts `jti` and `exp`; it is not itself a signature verifier or device registry.
- Do not invent a DO namespace or object naming scheme for a capability until the host exposes and approves it.

### D1, Vectorize, Queues and R2

**CODE FOUND**
- `src/etl.ts`: queue consumer requires DB and VECTORIZE; validates tenant and actor fields; stores tenant in Vectorize namespace/metadata and D1 document rows; emits lineage.
- `src/types.ts`: declares D1, Vectorize, ETL_QUEUE, MISSIONS, JOURNAL and AUDIT_ARCHIVE bindings as optional.
- `src/do/safety-interlock.ts` and `src/security/audit-anchor.ts`: tenant-scoped hash-chain audit records, immutable checkpoint writes to R2, and external OpenTimestamps proof verification via OTS_VERIFIER.
- `src/do/mission-brain.ts`: writes a mission journal to R2 when JOURNAL is available; its code explicitly reports whether journal persistence occurred.
- `src/do/agent-node.ts`: Vectorize query and D1 write paths are present.

**Reuse candidate**
- Use existing tenant-aware audit/lineage, D1 records, queue patterns, Vectorize and R2 through host-owned adapters.
- Do not provision new databases, indexes, buckets, queues or bindings for capability modules by default.

**GAP**
- Optional bindings and source-code call sites do not prove production activation.
- The ETL consumer expects trusted tenant/actor values from its producer; a new capability must not treat arbitrary queue message fields as trusted without authenticating the producer boundary.
- Vectorize namespaces and metadata do not replace D1 tenant authorization or query-path access control.

### Autodefense

**DOCUMENTED**
- `docs/AUTODEFENSE.md` describes collect → triage → investigate → mitigate → approve.
- It explicitly states high-impact blocks require human approval through SafetyInterlock; observe/rate-limit are soft actions.
- Documentation lists defense ingest, triage and approve endpoints.

**Reuse candidate**
- Multi-Agent Defense can complement existing detection/triage by adding a deterministic, tenant-scoped decision module and then handing recommendations to the existing host safety process.

**GAP**
- Documentation alone does not establish all endpoints are active in production or that every defense path is wired.

## 2. Existing Trust Infrastructure candidates

### HMAC Decision Passport

**CODE FOUND**
- `aston-trust-infrastructure/src/hmac-passport.ts` exports `issuePassport` and `verifyPassport`.
- Passport fields include tenant, actor, replay_key, issued_at, HMAC-SHA256 signature and kid.
- Verification checks the supplied shared secret, algorithm, kid and MAC.

**Reuse candidate**
- Potential integrity primitive for a shared-secret decision passport where both parties are authorized to hold the secret.

**GAP**
- HMAC is not a public-key signature profile.
- A valid MAC does not independently authenticate the caller's tenant/actor or establish issuer authorization.
- The inspected implementation's derived kid and single-secret verification do not establish a complete key rotation, revocation or trust-root lifecycle.
- Not an approved adapter for Multi-Agent Defense without a separate authenticated identity and key-management contract.

### Proof of Intention (PoI)

**CODE FOUND**
- `aston-trust-infrastructure/src/poi/proof-of-intention.ts` defines AgentCard, IntentionDraft and ProofOfIntention.
- It includes tenant, agent ID, nonce, expiry and package hash, plus propose/accept/expiry logic.

**Reuse candidate**
- A starting point for inter-agent intent/handshake data structures.

**GAP**
- The inspected package hash/status flow is not itself a signed, authenticated inter-organization authorization protocol.
- Acceptance checks the counterparty agent ID and package hash; it does not by itself prove the acceptor's cryptographic identity or tenant authority.

## 3. Attestation and timestamp evidence

### Agent Attestation SDK

**DOCUMENTED / SCHEMA FOUND**
- `aston-attestation-sdk` v1.0.0 publishes an attestation schema with issuer, agent, execution, verification, digests and optional signatures/evidence/provenance.
- Its README and SECURITY guidance state that schema validation does not verify signatures, establish key ownership, validate timestamps, or prove runtime/model integrity.
- The v1.0.0 schema inspected does not define a mandatory tenant ID claim.

**Reuse candidate**
- Use its document format as an input envelope only after an independent verifier and issuer authorization policy are defined.

**GAP**
- Do not map the document's declared `verification.status` to `evidence.verified`.
- Need signature profile/canonicalization, trust anchors, key lifecycle/revocation, issuer→agent authorization, authenticated tenant context, freshness and replay binding.

### OpenTimestamps

**CODE FOUND**
- Runtime `Env` declares OTS_VERIFIER service binding.
- `src/security/audit-anchor.ts` sends the exact checkpoint manifest and OTS proof to the verifier and requires a confirmed result, matching root hash and valid block height.
- This verifies an existence-time anchor for exact evidence bytes; it does not prove the truth of the evidence or the identity of the author/device.

**Reuse candidate**
- Evidence timestamp/provenance support for all capabilities, without claiming device identity or signature verification.

## 4. Capability-to-host reuse map

| New capability | Existing components to reuse | New isolated work actually needed | Current maturity |
|---|---|---|---|
| Multi-Agent Defense | SafetyInterlock, policy engine, Autodefense, tenant identity, ReplayGuard, audit/lineage | Authenticated observation contract; verifier adapter; threat-specific tests; recommendation adapter | Decision engine IMPLEMENTED and TESTED (10/10 CI per PR #1); not VALIDATED or PRODUCTION |
| Agentic Escrow | SafetyInterlock approvals, Identity, HMAC Passport candidate, D1/audit/lineage, PoI candidate | Escrow state machine, conditional evidence contract, idempotency, dispute/expiry semantics, simulation tests | DESIGN only |
| Inter-Agent Governance | Identity, policy/approval, PoI candidate, Passport candidate, attestation envelope | Issuer/tenant trust, scoped delegation, interoperability contract, revocation and arbitration rules | DESIGN only |
| Physical Edge Attestation | Identity method sensor, Mission token type, ReplayGuard, OTS timestamp proof, audit/lineage | Device key enrollment/registry, hardware-rooted identity profile, signed telemetry/command contract, freshness and anti-replay tests | DESIGN only |

## 5. Capability activation model

Each capability must expose a small versioned interface and remain disabled unless explicitly enabled by its host integration. The module must not access Cloudflare bindings directly.

Proposed lifecycle:
1. `DISABLED` — no calls, no side effects.
2. `SHADOW` — evaluate/read-only; no mutation.
3. `ACTIVE_RECOMMENDATION` — emits scoped recommendations only.
4. `ACTIVE_APPROVAL_REQUIRED` — sends permitted proposals to existing SafetyInterlock; irreversible action remains human-approved.
5. `ACTIVE_AUTOMATION` — only for narrowly allowlisted, reversible, tested actions, and only after separate explicit host authorization.

No capability in this repository is authorized to enable a production lifecycle state. This is a contract proposal, not a change to runtime configuration.

## 6. Hard boundaries

- Never modify `agente-OS-15.5-hector-zapata` while developing capabilities.
- Never change Cloudflare resources, bindings, secrets, migrations, routes, or production configuration from this project.
- Never duplicate SafetyInterlock, identity, audit, replay protection, or infrastructure services merely to make a module self-contained.
- Never trust a tenant or actor from an untrusted request, queue message, attestation claim, or agent self-description.
- Never equate schema validity, a MAC, an OTS timestamp, or a CI pass with complete identity/security validation.
- Integrate only through a versioned adapter and only after independent capability tests, compatibility proof and explicit user approval.

## 7. Evidence references inspected

Runtime repository:
- `src/types.ts` blob `2b4aaf8a201cfbdc151c4b02b55497818e0096d2`
- `src/do/safety-interlock.ts` blob `2e37058d15f89b85bb6daf21f4c5ee739a8f1904`
- `src/core/replay-guard.ts` blob `5073456f300c8fced1fada97596860485a7c44a8`
- `src/etl.ts` blob `e4b890c051edd2b830fb010e9636a3c7a41e241b`
- `src/safety/policy.ts` blob `615f9f81f62b8b24258088d47e2eedd62ef03080`
- `src/do/agent-node.ts` blob `c5a7f05ce6836f1ef01d70050cbf638f76114662`
- `src/do/supervisor.ts` blob `a325cb42515ee0a352abef8391d57704a4050fab`
- `src/do/mission-brain.ts` blob `3be0995c498d5390e8cf65225d75cd9f3fb43952`
- `src/security/audit-anchor.ts` blob `5dfe888cb0172b70b28c20b9bafcbbaf10262173`
- `docs/CLOUDFLARE-STACK.md` blob `44439547f650b55c0c7fab91da664fa0bf1dd23f`
- `docs/AUTODEFENSE.md` blob `78157a23b3af9fd64fa360f757649991fd7c59cd`

Trust Infrastructure candidates previously inspected:
- `src/hmac-passport.ts` blob `18f5cec63ce4682bcb9a3c7f92279793b2889bb7`
- `src/poi/proof-of-intention.ts` blob `2677c47ef1ed77bfc2cfd08e40192a4effd4bc35`

**Limitations:** this is a bounded source inspection. It does not establish the current live deployment, complete route/call-path coverage, all PR states, the full contents of every repository, or the deployed status of Cloudflare bindings. No production or runtime mutation was performed.
