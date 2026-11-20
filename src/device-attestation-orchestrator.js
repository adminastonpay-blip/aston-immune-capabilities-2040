import { verifyDeviceAttestation } from "./device-attestation-crypto-verifier.js";
import { createDeviceTrustRegistry } from "./device-trust-registry.js";
import { createD1DeviceTrustStore } from "./device-trust-d1-store.js";

const ID = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * Compose the Ed25519 verifier, tenant-scoped device registry and D1 replay
 * store. hostContext and authorize MUST be supplied by trusted host code;
 * never construct them from request, device, agent, or queue input.
 *
 * The D1 migration must already have been applied by an authorized operator.
 * This factory does not apply migrations, configure bindings, or deploy.
 */
export function createDeviceAttestationOrchestrator({
  db, hostContext, authorize, now = () => Date.now(),
  maxLifetimeMs = 300000, futureSkewMs = 30000
} = {}) {
  const unavailable = (reason) => ({
    ok: false, decision: "review", reason, executable: false
  });

  if (!db || typeof db.prepare !== "function") {
    return Object.freeze({ verifyAndConsume: async () => unavailable("d1_database_required") });
  }
  if (!hostContext || !ID.test(hostContext.tenantId ?? "") ||
      !ID.test(hostContext.audience ?? "") ||
      typeof authorize !== "function" || typeof now !== "function") {
    return Object.freeze({ verifyAndConsume: async () => unavailable("trusted_host_context_required") });
  }

  let store;
  try { store = createD1DeviceTrustStore(db); }
  catch { return Object.freeze({ verifyAndConsume: async () => unavailable("d1_store_unavailable") }); }

  const registry = createDeviceTrustRegistry({ store, authorize, now });

  return Object.freeze({
    async verifyAndConsume(envelope) {
      const currentTime = now();
      if (!Number.isFinite(currentTime)) return unavailable("invalid_host_clock");
      if (!envelope || envelope.tenantId !== hostContext.tenantId ||
          envelope.audience !== hostContext.audience) {
        return { ok: false, decision: "deny", reason: "tenant_or_audience_mismatch", executable: false };
      }

      const verification = await verifyDeviceAttestation(envelope, {
        expectedTenantId: hostContext.tenantId,
        expectedAudience: hostContext.audience,
        now: currentTime,
        maxLifetimeMs,
        futureSkewMs,
        resolveTrustedKey: async (scope) => {
          const record = await registry.resolveTrustedKey(scope);
          // The crypto verifier binds tenant/issuer/key. Add the device binding
          // here because key records are also device-scoped.
          if (!record || record.deviceId !== envelope.deviceId) return null;
          return record;
        }
      });
      if (!verification.ok || verification.decision !== "verified") {
        return { ...verification, executable: false };
      }

      const exactBindings = [
        ["tenantId", hostContext.tenantId],
        ["deviceId", envelope.deviceId],
        ["agentId", envelope.agentId],
        ["missionId", envelope.missionId],
        ["challengeId", envelope.challengeId],
        ["attestationId", envelope.attestationId],
        ["issuerId", envelope.issuerId],
        ["keyId", envelope.keyId]
      ];
      for (const [field, expected] of exactBindings) {
        if (verification[field] !== expected) {
          return { ok: false, decision: "deny", reason: "verified_evidence_binding_mismatch", field, executable: false };
        }
      }
      if (verification.deviceStatus !== "active" ||
          verification.verifierId !== "aston-ed25519-device-verifier-v1" ||
          typeof verification.evidenceDigest !== "string" ||
          verification.evidenceDigest.length === 0) {
        return { ok: false, decision: "deny", reason: "verified_evidence_incomplete", executable: false };
      }

      const consumed = await registry.consumeChallenge({
        tenantId: hostContext.tenantId,
        deviceId: envelope.deviceId,
        challengeId: envelope.challengeId,
        attestationId: envelope.attestationId,
        expiresAt: envelope.expiresAt
      }, hostContext);

      if (!consumed.ok || consumed.decision !== "consumed") {
        return {
          ok: false,
          decision: consumed.decision === "review" ? "review" : "deny",
          reason: consumed.reason,
          executable: false
        };
      }

      return {
        ok: true,
        decision: "verified_and_consumed",
        reason: "signature_trust_bindings_and_one_time_challenge_verified",
        tenantId: hostContext.tenantId,
        deviceId: envelope.deviceId,
        agentId: envelope.agentId,
        missionId: envelope.missionId,
        challengeId: envelope.challengeId,
        attestationId: envelope.attestationId,
        issuerId: envelope.issuerId,
        keyId: envelope.keyId,
        verifierId: verification.verifierId,
        evidenceDigest: verification.evidenceDigest,
        executable: false
      };
    }
  });
}
