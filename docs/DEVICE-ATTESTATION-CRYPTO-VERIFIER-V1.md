# Device Attestation Crypto Verifier v1

Status: IMPLEMENTED + TESTED only after the isolated CI run for this branch succeeds. NOT VALIDATED for production.

## Purpose
An isolated Ed25519 signature verifier for physical-edge attestation envelopes. It can supply cryptographic evidence to the existing Physical Edge Attestation decision module through trusted host composition.

## Trust contract
- Host code supplies `resolveTrustedKey({ tenantId, issuerId, keyId })`, backed by an authenticated, tenant-scoped trust registry.
- The returned record must bind the exact tenant, issuer and key IDs and include an Ed25519 public key, active/revoked status, device status, and key validity interval.
- The signature is checked over deterministic canonical JSON containing the fixed attestation fields, using Ed25519 and WebCrypto.
- Tenant and audience are compared against host-provided expected values, never trusted from the envelope alone.
- Successful verification returns exact evidence bindings and a SHA-256 digest. It never executes an action.

## Explicit limits
This v1 module does not implement device enrollment, authenticated tenant resolution, hardware root-of-trust or measured boot, durable challenge/nonce replay consumption, registry persistence, key rotation workflows, revocation distribution, SafetyInterlock/MissionBrain wiring, or physical actuation. The host must implement and secure the trust registry and replay store. A valid signature proves possession of the corresponding private key for the signed payload; it does not independently prove genuine hardware or uncompromised firmware.

## Integration rule
Never accept `resolveTrustedKey` from an agent, device, HTTP body, or queue payload. Never treat caller-supplied `verified: true` as proof. Compose this verifier only inside trusted host code, then pass its returned proof to the existing Physical Edge Attestation evaluator. Keep all outputs non-executable until authenticated identity, durable replay protection, policy, and SafetyInterlock approval are applied.

## API
`verifyDeviceAttestation(envelope, { resolveTrustedKey, expectedTenantId, expectedAudience, now, maxLifetimeMs, futureSkewMs })`

Public key inputs: WebCrypto Ed25519 CryptoKey, JWK, or base64url-encoded SPKI. The registry is responsible for pinning the public key to the tenant/issuer/key tuple.

## Test scope
Node built-in test runner; generated Ed25519 keypair; valid signature; tamper detection; tenant/audience binding; unknown/mismatched/revoked/expired key; malformed and expired envelope; unavailable registry; deterministic canonicalization.
