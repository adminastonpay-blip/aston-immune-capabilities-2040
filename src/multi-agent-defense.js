const SIGNAL_TYPES = new Set([
  "credential_anomaly",
  "policy_violation",
  "tool_abuse",
  "integrity_failure",
  "replay_detected",
]);

const SEVERITIES = new Set(["low", "medium", "high", "critical"]);
const MAX_AGE_MS = 120_000;
const MAX_FUTURE_SKEW_MS = 30_000;

function isNonEmptyString(value, max = 200) {
  return typeof value === "string" && value.trim().length > 0 && value.length <= max;
}

/**
 * Pure, side-effect-free threat triage.
 *
 * The caller must supply evidence that has already been authenticated and
 * verified by a trusted adapter. This module does not authenticate agents,
 * verify signatures, persist events, or execute containment.
 */
export function evaluateThreat(observation, options = {}) {
  const now = options.now ?? Date.now();

  if (!Number.isFinite(now) || !observation || typeof observation !== "object") {
    return reject("invalid_input");
  }

  const {
    eventId,
    tenantId,
    agentId,
    observedAt,
    signalType,
    severity,
    evidence,
  } = observation;

  if (
    !isNonEmptyString(eventId) ||
    !isNonEmptyString(tenantId) ||
    !isNonEmptyString(agentId) ||
    !isNonEmptyString(observedAt, 64) ||
    !SIGNAL_TYPES.has(signalType) ||
    !SEVERITIES.has(severity) ||
    !evidence ||
    typeof evidence !== "object"
  ) {
    return reject("invalid_observation");
  }

  const timestamp = Date.parse(observedAt);
  if (!Number.isFinite(timestamp)) return reject("invalid_timestamp");
  if (timestamp - now > MAX_FUTURE_SKEW_MS) return reject("timestamp_in_future");
  if (now - timestamp > MAX_AGE_MS) return reject("stale_observation");

  const evidenceVerified =
    evidence.verified === true &&
    isNonEmptyString(evidence.reference, 500) &&
    isNonEmptyString(evidence.verifier, 120);

  let action = "none";
  let reason = "low_risk_signal";

  if (!evidenceVerified) {
    action = "review";
    reason = "evidence_not_verified";
  } else if (severity === "critical") {
    action = "propose_isolation";
    reason = "verified_critical_signal";
  } else if (severity === "high") {
    action = "propose_restriction";
    reason = "verified_high_signal";
  } else if (severity === "medium") {
    action = "review";
    reason = "medium_risk_signal";
  }

  return Object.freeze({
    schemaVersion: "1.0.0",
    decision: "triage",
    action,
    reason,
    scope: Object.freeze({ tenantId, agentId }),
    eventId,
    signalType,
    severity,
    evidenceVerified,
    executable: false,
  });
}

function reject(reason) {
  return Object.freeze({
    schemaVersion: "1.0.0",
    decision: "reject",
    action: "none",
    reason,
    scope: null,
    evidenceVerified: false,
    executable: false,
  });
}
