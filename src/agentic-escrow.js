const CURRENCIES = /^[A-Z]{3}$/;
const ID = /^[A-Za-z0-9._:-]{1,128}$/;

function validId(value) {
  return typeof value === "string" && ID.test(value);
}

export function createEscrow(input) {
  if (!input || typeof input !== "object") return { ok: false, reason: "invalid_input" };
  const { escrowId, tenantId, payerAgentId, payeeAgentId, amountMinor, currency, releaseCondition, expiresAt } = input;
  if (![escrowId, tenantId, payerAgentId, payeeAgentId].every(validId)) {
    return { ok: false, reason: "invalid_identity_or_scope" };
  }
  if (payerAgentId === payeeAgentId) return { ok: false, reason: "same_payer_and_payee" };
  if (!Number.isSafeInteger(amountMinor) || amountMinor <= 0) return { ok: false, reason: "invalid_amount" };
  if (typeof currency !== "string" || !CURRENCIES.test(currency)) return { ok: false, reason: "invalid_currency" };
  if (!releaseCondition || !["delivery_confirmed", "work_accepted", "human_approval"].includes(releaseCondition.type) ||
      !validId(releaseCondition.reference)) return { ok: false, reason: "invalid_release_condition" };
  const expiry = Date.parse(expiresAt);
  if (!Number.isFinite(expiry)) return { ok: false, reason: "invalid_expiry" };

  return {
    ok: true,
    escrow: {
      escrowId, tenantId, payerAgentId, payeeAgentId, amountMinor, currency,
      releaseCondition: { type: releaseCondition.type, reference: releaseCondition.reference },
      expiresAt: new Date(expiry).toISOString(),
      status: "created",
      processedEventIds: []
    }
  };
}

/**
 * Pure decision function. verifyEvent MUST be injected by a trusted host composition
 * layer; never accept it from an agent request, event payload, or queue message.
 * This module never moves funds or executes a release/refund.
 */
export function evaluateEscrowEvent(escrow, event, { now = Date.now(), verifyEvent } = {}) {
  const reject = (reason) => ({ ok: false, reason, escrow, action: "none", executable: false });
  if (!escrow || !validId(escrow.escrowId) || !validId(escrow.tenantId)) return reject("invalid_escrow");
  if (!event || !validId(event.eventId) || !validId(event.escrowId) || !validId(event.tenantId) ||
      typeof event.type !== "string") return reject("invalid_event");
  if (event.escrowId !== escrow.escrowId || event.tenantId !== escrow.tenantId) return reject("scope_mismatch");
  if (escrow.processedEventIds?.includes(event.eventId)) {
    return { ok: true, reason: "duplicate_event", escrow, action: "none", executable: false };
  }
  if (!Number.isFinite(now) || Date.parse(escrow.expiresAt) <= now) return reject("escrow_expired");
  if (typeof verifyEvent !== "function") return reject("trusted_verifier_required");

  let proof;
  try { proof = verifyEvent(event); } catch { return reject("verification_failed"); }
  if (!proof || proof.verified !== true || proof.eventId !== event.eventId ||
      proof.eventType !== event.type ||
      proof.escrowId !== escrow.escrowId || proof.tenantId !== escrow.tenantId ||
      proof.conditionType !== (event.conditionType ?? null) ||
      proof.conditionReference !== (event.conditionReference ?? null) ||
      !validId(proof.verifierId)) return reject("verification_failed");

  const processedEventIds = [...(escrow.processedEventIds || []), event.eventId];
  let status = escrow.status;
  let action = "none";
  let reason = "event_recorded";

  if (event.type === "funds_secured" && status === "created") {
    status = "funded";
    reason = "funding_confirmed";
  } else if (event.type === "release_condition_met" && status === "funded") {
    if (event.conditionType !== escrow.releaseCondition.type ||
        event.conditionReference !== escrow.releaseCondition.reference) {
      return reject("release_condition_mismatch");
    }
    status = "release_pending_approval";
    action = "propose_release";
    reason = "release_requires_approval";
  } else if (event.type === "refund_requested" && status === "funded") {
    status = "refund_pending_approval";
    action = "propose_refund";
    reason = "refund_requires_approval";
  } else {
    return reject("invalid_transition");
  }

  return {
    ok: true,
    reason,
    escrow: {
      ...escrow,
      status,
      processedEventIds,
      ...(action !== "none" ? {
        pendingApproval: {
          proposalId: "proposal-" + event.eventId,
          decisionType: action === "propose_release" ? "release" : "refund",
          sourceEventId: event.eventId
        }
      } : {})
    },
    action,
    approvalRequired: action !== "none",
    executable: false,
    scope: { tenantId: escrow.tenantId, escrowId: escrow.escrowId },
    verifierId: proof.verifierId
  };
}

/**
 * Records an authenticated approval decision. The verifier is trusted host code
 * and must prove authorization for this exact tenant, escrow, proposal and decision.
 * Approval only authorizes a later settlement integration; this module never moves funds.
 */
export function evaluateEscrowApproval(escrow, approval, { now = Date.now(), verifyApproval } = {}) {
  const reject = (reason) => ({ ok: false, reason, escrow, action: "none", executable: false });
  if (!escrow || !validId(escrow.escrowId) || !validId(escrow.tenantId)) return reject("invalid_escrow");
  if (!approval || !validId(approval.approvalId) || !validId(approval.proposalId) ||
      !validId(approval.tenantId) || !validId(approval.escrowId) ||
      !validId(approval.approverId) || !["approved", "rejected"].includes(approval.decision)) {
    return reject("invalid_approval");
  }
  if (approval.tenantId !== escrow.tenantId || approval.escrowId !== escrow.escrowId) return reject("scope_mismatch");
  const pending = escrow.pendingApproval;
  if (!pending || approval.proposalId !== pending.proposalId) return reject("proposal_mismatch");
  if (escrow.status !== "release_pending_approval" && escrow.status !== "refund_pending_approval") {
    return reject("approval_not_pending");
  }
  if (!Number.isFinite(now) || Date.parse(escrow.expiresAt) <= now) return reject("escrow_expired");
  if (typeof verifyApproval !== "function") return reject("trusted_approval_verifier_required");

  let proof;
  try { proof = verifyApproval(approval); } catch { return reject("approval_verification_failed"); }
  if (!proof || proof.verified !== true ||
      proof.approvalId !== approval.approvalId ||
      proof.proposalId !== pending.proposalId ||
      proof.tenantId !== escrow.tenantId ||
      proof.escrowId !== escrow.escrowId ||
      proof.approverId !== approval.approverId ||
      proof.decision !== approval.decision ||
      !validId(proof.verifierId)) return reject("approval_verification_failed");

  const status = approval.decision === "approved"
    ? (pending.decisionType === "release" ? "approved_for_release" : "approved_for_refund")
    : (pending.decisionType === "release" ? "release_rejected" : "refund_rejected");

  return {
    ok: true,
    reason: approval.decision === "approved" ? "approval_recorded" : "approval_rejected",
    escrow: { ...escrow, status, pendingApproval: null, approvalRecord: {
      approvalId: approval.approvalId,
      proposalId: pending.proposalId,
      approverId: approval.approverId,
      decision: approval.decision,
      verifierId: proof.verifierId
    } },
    action: approval.decision === "approved" ? "authorize_external_settlement" : "none",
    approvalRequired: false,
    executable: false,
    scope: { tenantId: escrow.tenantId, escrowId: escrow.escrowId }
  };
}
