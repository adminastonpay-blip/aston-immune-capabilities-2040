const ID = /^[A-Za-z0-9._:-]{1,128}$/;

function validId(value) {
  return typeof value === "string" && ID.test(value);
}

function validClaims(value) {
  return Array.isArray(value) && value.length > 0 &&
    value.every((claim) => typeof claim === "string" && claim.length > 0 && claim.length <= 128) &&
    new Set(value).size === value.length;
}

/**
 * Evaluates a physical-edge attestation envelope.
 * verifyAttestation is privileged host code. It must authenticate the tenant,
 * enrolled device, issuer/key trust and signature, and bind every envelope field.
 *
 * Pure decision logic only: no crypto, device enrollment, replay persistence,
 * mission dispatch, SafetyInterlock call or physical actuation.
 */
export function evaluatePhysicalEdgeAttestation(envelope, {
  now = Date.now(),
  verifyAttestation,
  policy = {},
  maxLifetimeMs = 300000,
  futureSkewMs = 30000
} = {}) {
  const result = (decision, reason, extra = {}) => ({
    ok: decision !== "deny",
    decision,
    reason,
    executable: false,
    scope: envelope && validId(envelope.tenantId)
      ? { tenantId: envelope.tenantId }
      : null,
    ...extra
  });

  if (!envelope || typeof envelope !== "object") return result("deny", "invalid_envelope");
  const {
    attestationId, tenantId, deviceId, agentId, missionId, challengeId,
    nonce, audience, issuerId, keyId, issuedAt, expiresAt, claims
  } = envelope;

  if (![attestationId, tenantId, deviceId, agentId, missionId, challengeId,
        nonce, audience, issuerId, keyId].every(validId) || !validClaims(claims)) {
    return result("deny", "invalid_envelope_fields");
  }
  if (!Number.isFinite(now) || !Number.isFinite(maxLifetimeMs) ||
      maxLifetimeMs <= 0 || !Number.isFinite(futureSkewMs) || futureSkewMs < 0) {
    return result("deny", "invalid_evaluation_parameters");
  }

  const issued = Date.parse(issuedAt);
  const expires = Date.parse(expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) ||
      issued > now + futureSkewMs || expires <= now || expires <= issued ||
      expires - issued > maxLifetimeMs) {
    return result("deny", "attestation_time_invalid");
  }

  if (typeof verifyAttestation !== "function") {
    return result("review", "trusted_attestation_verifier_required");
  }

  let proof;
  try { proof = verifyAttestation(envelope); } catch {
    return result("review", "attestation_verification_failed");
  }

  if (!proof || proof.verified !== true ||
      proof.attestationId !== attestationId || proof.tenantId !== tenantId ||
      proof.deviceId !== deviceId || proof.agentId !== agentId ||
      proof.missionId !== missionId || proof.challengeId !== challengeId ||
      proof.nonce !== nonce || proof.audience !== audience ||
      proof.issuerId !== issuerId || proof.keyId !== keyId ||
      proof.issuedAt !== issuedAt || proof.expiresAt !== expiresAt ||
      proof.claims !== JSON.stringify(claims) ||
      proof.deviceStatus !== "active" ||
      !validId(proof.verifierId) ||
      typeof proof.evidenceDigest !== "string" ||
      proof.evidenceDigest.length < 16 || proof.evidenceDigest.length > 256) {
    return result("review", "attestation_verification_failed");
  }

  const requiredClaims = Array.isArray(policy.requiredClaims) ? policy.requiredClaims : [];
  if (!requiredClaims.every((claim) => claims.includes(claim))) {
    return result("deny", "required_claim_missing", { verifierId: proof.verifierId });
  }

  const deniedDevices = Array.isArray(policy.deniedDevices) ? policy.deniedDevices : [];
  if (deniedDevices.includes(deviceId)) {
    return result("deny", "device_denied_by_policy", { verifierId: proof.verifierId });
  }

  const approvalClaims = Array.isArray(policy.approvalRequiredClaims)
    ? policy.approvalRequiredClaims : [];
  if (approvalClaims.some((claim) => claims.includes(claim))) {
    return result("review", "human_approval_required", {
      approvalRequired: true,
      verifierId: proof.verifierId,
      scope: { tenantId, deviceId, agentId, missionId, challengeId }
    });
  }

  return result("allow", "attestation_and_policy_verified", {
    approvalRequired: false,
    verifierId: proof.verifierId,
    evidenceDigest: proof.evidenceDigest,
    scope: { tenantId, deviceId, agentId, missionId, challengeId }
  });
}
