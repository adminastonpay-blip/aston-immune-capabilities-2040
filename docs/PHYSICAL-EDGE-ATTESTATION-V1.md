# Physical Edge Attestation v1 — Isolated Capability

Status: IMPLEMENTED (decision-contract prototype) / TESTS PENDING
Branch: `feat/physical-edge-attestation-v1`

## Purpose

Define a deterministic trust boundary for attestations from physical/edge devices before a host considers associating a device with an agent and mission.

## Included

- Tenant, device, agent, mission, challenge, nonce, audience, issuer and key identifiers.
- Bounded attestation lifetime and future-issued checks.
- Exact host-verifier binding to every envelope field and the complete claims list.
- Active-device status and evidence-digest requirements from the trusted verifier.
- Required-claim, denied-device and approval-required policy outcomes.
- All decisions are non-executable.

## Explicitly excluded

- Cryptographic signature verification, hardware-root measurement, secure boot measurement validation or trust-anchor management.
- Device enrollment, ownership proof, key rotation/revocation registry or authenticated tenant resolution.
- Durable challenge/nonce replay storage.
- SafetyInterlock or MissionBrain integration, network transport, dispatch or physical actuation.
- Cloudflare bindings, infrastructure changes or production deployment.

## Trust boundary

`verifyAttestation` is privileged host composition code. It must independently authenticate tenant context, device enrollment/status, issuer and key trust, cryptographic signature and measured claims. It must bind the exact attestation ID, tenant, device, agent, mission, challenge, nonce, audience, issuer, key, timestamps and claims. It must not originate from an agent payload, device-supplied callback or queue message. This module does not prove that the verifier is trustworthy.

The challenge/nonce must be issued by the host and consumed in durable replay protection outside this pure module. A valid result here is not proof that replay protection occurred.

## Acceptance criteria

1. Malformed, expired, future-issued and overlong attestations are denied.
2. Missing, throwing or mismatched verification never returns allow.
3. Tenant/device/challenge/nonce/issuer/key/claims are bound exactly.
4. Required claims and denied-device policy fail closed.
5. Approval-required claims return review.
6. All decisions remain non-executable.
7. Isolated automated tests pass.

No integration into ASTON OS 15.5, no Cloudflare changes and no production activation are included.
