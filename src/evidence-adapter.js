import { evaluateThreat } from "./multi-agent-defense.js";

/**
 * Runs threat triage only after a host-controlled verifier returns a result
 * cryptographically/authoritatively verified by that verifier.
 *
 * SECURITY BOUNDARY:
 * - verifyEvidence MUST be injected by the authenticated host composition
 *   root; never accept a verifier function supplied by an agent/request.
 * - This adapter checks subject binding, not signature mathematics, trust
 *   roots, key ownership, revocation, or tenant authentication.
 * - The verifier must establish those properties before returning verified.
 */
export async function evaluateThreatWithVerifier(
  observation,
  { now = Date.now(), verifyEvidence } = {},
) {
  if (typeof verifyEvidence !== "function") {
    return evaluateThreat(withUnverifiedEvidence(observation), { now });
  }

  let result;
  try {
    result = await verifyEvidence(observation?.evidence, observation);
  } catch {
    result = null;
  }

  const bound =
    result?.verified === true &&
    result.eventId === observation?.eventId &&
    result.tenantId === observation?.tenantId &&
    result.agentId === observation?.agentId &&
    result.observedAt === observation?.observedAt &&
    typeof result.reference === "string" &&
    result.reference.trim().length > 0 &&
    result.reference.length <= 500 &&
    typeof result.verifierId === "string" &&
    result.verifierId.trim().length > 0 &&
    result.verifierId.length <= 120;

  const normalized = bound
    ? {
        ...observation,
        evidence: {
          verified: true,
          reference: result.reference,
          verifier: result.verifierId,
        },
      }
    : withUnverifiedEvidence(observation);

  return evaluateThreat(normalized, { now });
}

function withUnverifiedEvidence(observation) {
  if (!observation || typeof observation !== "object") return observation;
  return {
    ...observation,
    evidence: { verified: false, reference: "", verifier: "" },
  };
}
