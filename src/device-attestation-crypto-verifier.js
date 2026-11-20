const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const REQUIRED = [
  "attestationId", "tenantId", "deviceId", "agentId", "missionId",
  "challengeId", "nonce", "audience", "issuerId", "keyId",
  "issuedAt", "expiresAt", "claims"
];

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function stableJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(stableJson).join(",") + "]";
  if (!isPlainObject(value)) throw new TypeError("non_json_value");
  return "{" + Object.keys(value).sort().map((key) =>
    JSON.stringify(key) + ":" + stableJson(value[key])
  ).join(",") + "}";
}

function payloadFor(envelope) {
  const payload = {};
  for (const key of REQUIRED) payload[key] = envelope[key];
  return payload;
}

function decodeBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError("invalid_base64url");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function importEd25519PublicKey(publicKey, subtle) {
  if (publicKey && publicKey.type === "public" && publicKey.algorithm?.name === "Ed25519") {
    return publicKey;
  }
  if (isPlainObject(publicKey)) {
    return subtle.importKey("jwk", publicKey, { name: "Ed25519" }, false, ["verify"]);
  }
  if (typeof publicKey === "string") {
    return subtle.importKey(
      "spki", decodeBase64Url(publicKey), { name: "Ed25519" }, false, ["verify"]
    );
  }
  throw new TypeError("unsupported_public_key");
}

/**
 * Cryptographically verifies an Ed25519-signed physical-device attestation.
 *
 * resolveTrustedKey is privileged host code backed by an authenticated,
 * tenant-scoped trust registry. It must return the pinned issuer/key record;
 * never accept it from the device, agent, request body, or queue payload.
 *
 * This module does not enroll devices, authenticate the caller's tenant,
 * persist nonce/challenge consumption, measure hardware, or actuate devices.
 */
export async function verifyDeviceAttestation(envelope, {
  resolveTrustedKey,
  expectedTenantId,
  expectedAudience,
  now = Date.now(),
  maxLifetimeMs = 300000,
  futureSkewMs = 30000
} = {}) {
  const result = (decision, reason, extra = {}) => ({
    ok: decision === "verified",
    decision,
    reason,
    executable: false,
    ...extra
  });

  if (!isPlainObject(envelope) || !REQUIRED.every((key) =>
    Object.prototype.hasOwnProperty.call(envelope, key)
  ) || typeof envelope.signature !== "string") {
    return result("deny", "invalid_attestation_envelope");
  }
  for (const key of REQUIRED.filter((key) => key !== "claims")) {
    if (typeof envelope[key] !== "string" || !ID.test(envelope[key])) {
      return result("deny", "invalid_attestation_field");
    }
  }
  if (!Array.isArray(envelope.claims) || envelope.claims.length === 0 ||
      envelope.claims.length > 64 ||
      envelope.claims.some((claim) => typeof claim !== "string" ||
        claim.length === 0 || claim.length > 128) ||
      new Set(envelope.claims).size !== envelope.claims.length) {
    return result("deny", "invalid_attestation_claims");
  }
  if (!ID.test(expectedTenantId ?? "") || !ID.test(expectedAudience ?? "") ||
      envelope.tenantId !== expectedTenantId || envelope.audience !== expectedAudience) {
    return result("deny", "tenant_or_audience_mismatch");
  }
  if (!Number.isFinite(now) || !Number.isFinite(maxLifetimeMs) ||
      maxLifetimeMs <= 0 || !Number.isFinite(futureSkewMs) || futureSkewMs < 0) {
    return result("deny", "invalid_verification_parameters");
  }

  const issued = Date.parse(envelope.issuedAt);
  const expires = Date.parse(envelope.expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) ||
      issued > now + futureSkewMs || expires <= now || expires <= issued ||
      expires - issued > maxLifetimeMs) {
    return result("deny", "attestation_time_invalid");
  }

  if (typeof resolveTrustedKey !== "function") {
    return result("review", "trusted_key_registry_required");
  }

  let keyRecord;
  try {
    keyRecord = await resolveTrustedKey({
      tenantId: envelope.tenantId,
      issuerId: envelope.issuerId,
      keyId: envelope.keyId
    });
  } catch {
    return result("review", "trusted_key_lookup_failed");
  }
  if (!keyRecord) return result("deny", "trusted_key_not_found");
  if (keyRecord.tenantId !== envelope.tenantId ||
      keyRecord.issuerId !== envelope.issuerId ||
      keyRecord.keyId !== envelope.keyId) {
    return result("deny", "trusted_key_binding_mismatch");
  }
  if (keyRecord.status !== "active" || keyRecord.revoked === true) {
    return result("deny", "trusted_key_not_active");
  }

  const keyNotBefore = Date.parse(keyRecord.notBefore);
  const keyNotAfter = Date.parse(keyRecord.notAfter);
  if (!Number.isFinite(keyNotBefore) || !Number.isFinite(keyNotAfter) ||
      keyNotBefore > issued || keyNotAfter <= issued) {
    return result("deny", "trusted_key_outside_validity");
  }

  let subtle;
  try {
    subtle = globalThis.crypto?.subtle;
    if (!subtle) return result("review", "webcrypto_unavailable");
    const publicKey = await importEd25519PublicKey(keyRecord.publicKey, subtle);
    const payload = new TextEncoder().encode(stableJson(payloadFor(envelope)));
    const signature = decodeBase64Url(envelope.signature);
    const verified = await subtle.verify({ name: "Ed25519" }, publicKey, signature, payload);
    if (!verified) return result("deny", "invalid_signature");

    const digestInput = new Uint8Array(payload.length + signature.length);
    digestInput.set(payload);
    digestInput.set(signature, payload.length);
    const digest = new Uint8Array(await subtle.digest("SHA-256", digestInput));
    return result("verified", "ed25519_signature_and_trust_binding_verified", {
      verified: true,
      tenantId: envelope.tenantId,
      deviceId: envelope.deviceId,
      agentId: envelope.agentId,
      missionId: envelope.missionId,
      challengeId: envelope.challengeId,
      attestationId: envelope.attestationId,
      issuerId: envelope.issuerId,
      keyId: envelope.keyId,
      issuedAt: envelope.issuedAt,
      expiresAt: envelope.expiresAt,
      claims: stableJson(envelope.claims),
      deviceStatus: keyRecord.deviceStatus === "active" ? "active" : "unknown",
      verifierId: "aston-ed25519-device-verifier-v1",
      evidenceDigest: encodeBase64Url(digest)
    });
  } catch {
    return result("deny", "cryptographic_verification_error");
  }
}

export { stableJson as canonicalizeAttestationPayload };
