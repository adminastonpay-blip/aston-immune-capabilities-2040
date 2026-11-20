# Device Attestation Integration Orchestrator v1

Status: IMPLEMENTED + TESTED (isolated unit/integration tests). NOT production validated.

## Purpose

Composes the existing Ed25519 device-attestation verifier, tenant-scoped device trust registry, and Cloudflare D1 store adapter into one host-side verification flow.

## Flow

1. Host code injects the D1 binding, authenticated host context, and privileged authorization callback.
2. The orchestrator derives the expected tenant and audience exclusively from that host context.
3. The registry resolves the exact tenant/issuer/key record. The orchestrator additionally binds that key record to the envelope's device ID.
4. The Ed25519 verifier validates the signed canonical payload, signature, key status, key validity, tenant, audience, and attestation time bounds.
5. The orchestrator checks the verifier result's tenant/device/agent/mission/challenge/attestation/issuer/key bindings and evidence metadata.
6. Only after successful cryptographic verification does the registry atomically consume the tenant/device/challenge tuple in D1.
7. A duplicate challenge or storage/authorization failure fails closed. Every result has `executable: false`.

## Host integration contract

- `hostContext` must be created by authenticated host middleware, not copied from a request body, device, agent, or queue message. It must include `tenantId` and `audience`.
- `authorize(action, context)` is privileged host code and must independently authorize the authenticated actor for the exact tenant-scoped action.
- `db` is an injected D1 binding. No binding name, account, database, secret, or deployment is configured here.
- Device keys must already exist in the trust registry. This module does not enroll or provision keys.
- The migration `migrations/0001_device_trust_registry.sql` must be applied separately by an authorized operator before a live D1 binding can be used.
- The D1 adapter uses atomic uniqueness constraints for one-time challenge consumption. Tests use a D1-compatible fake; they do not prove live Cloudflare D1 behavior.

## Explicit non-goals

No migration execution, Cloudflare configuration/deployment, production database access, hardware/root-of-trust measurement, device enrollment, key rotation, external identity authentication, SafetyInterlock/MissionBrain wiring, physical actuation, or payment execution.

## Acceptance evidence

- Unit/integration tests generate real Ed25519 keypairs with WebCrypto.
- Covered: successful verification and one-time consumption, replay, invalid signature, tenant/audience mismatch, missing D1/auth configuration, denied host authorization, D1 write failure, expired attestation, wrong-device key binding, and caller-supplied `verified` flags.
- CI status must be checked on the final documentation commit before calling this branch tested.

## Status vocabulary

- IMPLEMENTED: composition module, tests, and documentation are committed on this isolated feature branch.
- TESTED: only when the GitHub Actions run for the final commit succeeds.
- VALIDATED: not claimed; requires review against the real host authentication/authorization context and an authorized live D1 test.
- PRODUCTION: not claimed; no deployment or production binding has been touched.
