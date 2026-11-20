const ID = /^[A-Za-z0-9._:-]{1,128}$/;

function validId(value) {
  return typeof value === "string" && ID.test(value);
}

function validStringList(value) {
  return Array.isArray(value) && value.length > 0 &&
    value.every((item) => typeof item === "string" && item.length > 0 && item.length <= 128) &&
    new Set(value).size === value.length;
}

function includesAll(allowed, requested) {
  return requested.every((item) => allowed.includes(item));
}

/**
 * Evaluates a cross-agent request against a delegated grant and local policy.
 * verifyRequest is privileged host code: it must authenticate the request and
 * bind every security-relevant field. Never accept it from request data.
 *
 * This function is pure. It does not authenticate cryptographically, persist
 * replay state, invoke SafetyInterlock, or execute the requested action.
 */
export function evaluateInterAgentRequest(request, {
  now = Date.now(),
  verifyRequest,
  policy = {}
} = {}) {
  const result = (decision, reason, extra = {}) => ({
    ok: decision !== "deny",
    decision,
    reason,
    executable: false,
    scope: request && validId(request.tenantId)
      ? { tenantId: request.tenantId }
      : null,
    ...extra
  });

  if (!request || typeof request !== "object") return result("deny", "invalid_request");
  const {
    requestId, tenantId, sourceAgentId, targetAgentId, action, resource,
    requestedScopes, audience, issuedAt, expiresAt, delegation
  } = request;

  if (![requestId, tenantId, sourceAgentId, targetAgentId, action, audience].every(validId) ||
      typeof resource !== "string" || resource.length < 1 || resource.length > 512 ||
      !validStringList(requestedScopes)) {
    return result("deny", "invalid_request_fields");
  }
  if (sourceAgentId === targetAgentId) return result("deny", "self_delegation_not_allowed");
  if (!Number.isFinite(now)) return result("deny", "invalid_evaluation_time");

  const issued = Date.parse(issuedAt);
  const expires = Date.parse(expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued > now + 30000 ||
      expires <= now || expires <= issued) return result("deny", "request_expired_or_invalid_time");

  if (!delegation || !validId(delegation.grantId) ||
      !validId(delegation.tenantId) || !validId(delegation.issuerAgentId) ||
      !validId(delegation.subjectAgentId) || !validId(delegation.audience) ||
      !validStringList(delegation.scopes)) {
    return result("deny", "invalid_delegation");
  }
  const grantExpiry = Date.parse(delegation.expiresAt);
  if (delegation.tenantId !== tenantId) return result("deny", "tenant_scope_mismatch");
  if (delegation.issuerAgentId !== sourceAgentId ||
      delegation.subjectAgentId !== targetAgentId) return result("deny", "delegation_party_mismatch");
  if (delegation.audience !== audience) return result("deny", "audience_mismatch");
  if (!Number.isFinite(grantExpiry) || grantExpiry <= now || grantExpiry < expires) {
    return result("deny", "delegation_expired_or_shorter_than_request");
  }
  if (!Number.isInteger(delegation.depth) || delegation.depth < 0 ||
      !Number.isInteger(delegation.maxDepth) || delegation.maxDepth < 0 ||
      delegation.depth > delegation.maxDepth) {
    return result("deny", "delegation_depth_exceeded");
  }
  if (!includesAll(delegation.scopes, requestedScopes)) {
    return result("deny", "requested_scope_exceeds_grant");
  }

  if (typeof verifyRequest !== "function") return result("review", "trusted_verifier_required");
  let proof;
  try { proof = verifyRequest(request); } catch {
    return result("review", "request_verification_failed");
  }
  if (!proof || proof.verified !== true ||
      proof.requestId !== requestId || proof.tenantId !== tenantId ||
      proof.sourceAgentId !== sourceAgentId || proof.targetAgentId !== targetAgentId ||
      proof.action !== action || proof.resource !== resource ||
      proof.requestedScopes !== JSON.stringify(requestedScopes) ||
      proof.issuedAt !== issuedAt || proof.expiresAt !== expiresAt ||
      proof.grantId !== delegation.grantId ||
      proof.issuerAgentId !== delegation.issuerAgentId ||
      proof.subjectAgentId !== delegation.subjectAgentId ||
      proof.delegationScopes !== JSON.stringify(delegation.scopes) ||
      proof.delegationExpiresAt !== delegation.expiresAt ||
      proof.delegationDepth !== delegation.depth ||
      proof.delegationMaxDepth !== delegation.maxDepth ||
      proof.audience !== audience ||
      !validId(proof.verifierId)) {
    return result("review", "request_verification_failed");
  }

  const deniedActions = Array.isArray(policy.deniedActions) ? policy.deniedActions : [];
  const allowedActions = Array.isArray(policy.allowedActions) ? policy.allowedActions : [];
  const approvalActions = Array.isArray(policy.approvalRequiredActions) ? policy.approvalRequiredActions : [];

  if (deniedActions.includes(action)) return result("deny", "action_denied_by_policy", { verifierId: proof.verifierId });
  if (allowedActions.length > 0 && !allowedActions.includes(action)) {
    return result("deny", "action_not_allowlisted", { verifierId: proof.verifierId });
  }
  if (approvalActions.includes(action)) {
    return result("review", "human_approval_required", {
      approvalRequired: true, verifierId: proof.verifierId,
      scope: { tenantId, requestId, sourceAgentId, targetAgentId }
    });
  }

  return result("allow", "delegation_and_policy_verified", {
    approvalRequired: false,
    verifierId: proof.verifierId,
    scope: { tenantId, requestId, sourceAgentId, targetAgentId }
  });
}
