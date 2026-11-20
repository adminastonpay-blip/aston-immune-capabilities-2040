import test from "node:test";
import assert from "node:assert/strict";
import { createEscrow, evaluateEscrowEvent, evaluateEscrowApproval } from "../src/agentic-escrow.js";

const input = {
  escrowId: "escrow-001", tenantId: "tenant-a",
  payerAgentId: "agent-payer", payeeAgentId: "agent-payee",
  amountMinor: 12500, currency: "USD",
  releaseCondition: { type: "delivery_confirmed", reference: "delivery-001" },
  expiresAt: "2030-01-01T00:00:00.000Z"
};
const verifier = (event) => ({
  verified: true, eventId: event.eventId, escrowId: event.escrowId,
  tenantId: event.tenantId, eventType: event.type,
  conditionType: event.conditionType ?? null,
  conditionReference: event.conditionReference ?? null,
  verifierId: "host-verifier-1"
});
const event = (eventId, type, overrides = {}) => ({
  eventId, type, escrowId: "escrow-001", tenantId: "tenant-a", ...overrides
});

test("creates a scoped escrow with validated amount and condition", () => {
  const result = createEscrow(input);
  assert.equal(result.ok, true);
  assert.equal(result.escrow.status, "created");
});

test("rejects invalid amounts and same payer/payee", () => {
  assert.equal(createEscrow({ ...input, amountMinor: 0 }).reason, "invalid_amount");
  assert.equal(createEscrow({ ...input, payerAgentId: input.payeeAgentId }).reason, "same_payer_and_payee");
});

test("ignores caller claims and requires trusted verifier", () => {
  const escrow = createEscrow(input).escrow;
  assert.equal(evaluateEscrowEvent(escrow, event("e1", "funds_secured", { verified: true }), { now: 0 }).reason, "trusted_verifier_required");
});

test("requires exact tenant and escrow scope", () => {
  const escrow = createEscrow(input).escrow;
  const result = evaluateEscrowEvent(escrow, event("e1", "funds_secured", { tenantId: "tenant-b" }), { now: 0, verifyEvent: verifier });
  assert.equal(result.reason, "scope_mismatch");
});

test("event verifier must bind the event type and release-condition payload", () => {
  const escrow = createEscrow(input).escrow;
  const result = evaluateEscrowEvent(escrow, event("e1", "funds_secured"), {
    now: 0,
    verifyEvent: (value) => ({ ...verifier(value), eventType: "release_condition_met" })
  });
  assert.equal(result.reason, "verification_failed");
});

test("funding must be verified before release can be proposed", () => {
  const escrow = createEscrow(input).escrow;
  const result = evaluateEscrowEvent(escrow, event("e1", "release_condition_met"), { now: 0, verifyEvent: verifier });
  assert.equal(result.reason, "invalid_transition");
});

test("verified funding then release condition proposes approval, never executes", () => {
  const created = createEscrow(input).escrow;
  const funded = evaluateEscrowEvent(created, event("e1", "funds_secured"), { now: 0, verifyEvent: verifier });
  assert.equal(funded.escrow.status, "funded");
  const release = evaluateEscrowEvent(funded.escrow, event("e2", "release_condition_met", { conditionType: "delivery_confirmed", conditionReference: "delivery-001" }), { now: 0, verifyEvent: verifier });
  assert.equal(release.action, "propose_release");
  assert.equal(release.escrow.status, "release_pending_approval");
  assert.equal(release.approvalRequired, true);
  assert.equal(release.executable, false);
});

test("release condition must match the escrow's configured condition", () => {
  const created = createEscrow(input).escrow;
  const funded = evaluateEscrowEvent(created, event("e1", "funds_secured"), { now: 0, verifyEvent: verifier });
  const result = evaluateEscrowEvent(funded.escrow, event("e2", "release_condition_met", {
    conditionType: "delivery_confirmed", conditionReference: "other-delivery"
  }), { now: 0, verifyEvent: verifier });
  assert.equal(result.reason, "release_condition_mismatch");
  assert.equal(result.escrow.status, "funded");
});

test("duplicate events are idempotent", () => {
  const created = createEscrow(input).escrow;
  const first = evaluateEscrowEvent(created, event("e1", "funds_secured"), { now: 0, verifyEvent: verifier });
  const duplicate = evaluateEscrowEvent(first.escrow, event("e1", "funds_secured"), { now: 0, verifyEvent: verifier });
  assert.equal(duplicate.reason, "duplicate_event");
  assert.equal(duplicate.escrow.status, "funded");
});

test("expired escrow fails closed", () => {
  const escrow = createEscrow(input).escrow;
  const result = evaluateEscrowEvent(escrow, event("e1", "funds_secured"), { now: Date.parse("2031-01-01T00:00:00Z"), verifyEvent: verifier });
  assert.equal(result.reason, "escrow_expired");
});

test("verifier exception fails closed", () => {
  const escrow = createEscrow(input).escrow;
  const result = evaluateEscrowEvent(escrow, event("e1", "funds_secured"), { now: 0, verifyEvent: () => { throw new Error("no"); } });
  assert.equal(result.reason, "verification_failed");
});

const approvalVerifier = (approval) => ({
  verified: true,
  approvalId: approval.approvalId,
  proposalId: approval.proposalId,
  tenantId: approval.tenantId,
  escrowId: approval.escrowId,
  approverId: approval.approverId,
  decision: approval.decision,
  verifierId: "host-approval-verifier"
});
function pendingRelease() {
  const created = createEscrow(input).escrow;
  const funded = evaluateEscrowEvent(created, event("e1", "funds_secured"), { now: 0, verifyEvent: verifier });
  return evaluateEscrowEvent(funded.escrow, event("e2", "release_condition_met", {
    conditionType: "delivery_confirmed", conditionReference: "delivery-001"
  }), { now: 0, verifyEvent: verifier }).escrow;
}

test("approval requires trusted host verifier", () => {
  const escrow = pendingRelease();
  const approval = { approvalId: "a1", proposalId: escrow.pendingApproval.proposalId,
    tenantId: escrow.tenantId, escrowId: escrow.escrowId, approverId: "human-1", decision: "approved" };
  assert.equal(evaluateEscrowApproval(escrow, approval, { now: 0 }).reason, "trusted_approval_verifier_required");
});

test("verified human approval authorizes external settlement but never executes it", () => {
  const escrow = pendingRelease();
  const approval = { approvalId: "a1", proposalId: escrow.pendingApproval.proposalId,
    tenantId: escrow.tenantId, escrowId: escrow.escrowId, approverId: "human-1", decision: "approved" };
  const result = evaluateEscrowApproval(escrow, approval, { now: 0, verifyApproval: approvalVerifier });
  assert.equal(result.escrow.status, "approved_for_release");
  assert.equal(result.action, "authorize_external_settlement");
  assert.equal(result.executable, false);
  assert.equal(result.escrow.pendingApproval, null);
});

test("approval verifier must bind exact approver and decision", () => {
  const escrow = pendingRelease();
  const approval = { approvalId: "a1", proposalId: escrow.pendingApproval.proposalId,
    tenantId: escrow.tenantId, escrowId: escrow.escrowId, approverId: "human-1", decision: "approved" };
  const result = evaluateEscrowApproval(escrow, approval, { now: 0,
    verifyApproval: () => ({ ...approvalVerifier(approval), approverId: "attacker" }) });
  assert.equal(result.reason, "approval_verification_failed");
});

test("approval from another tenant is rejected", () => {
  const escrow = pendingRelease();
  const approval = { approvalId: "a1", proposalId: escrow.pendingApproval.proposalId,
    tenantId: "tenant-other", escrowId: escrow.escrowId, approverId: "human-1", decision: "approved" };
  assert.equal(evaluateEscrowApproval(escrow, approval, { now: 0, verifyApproval: approvalVerifier }).reason, "scope_mismatch");
});

test("approval for another proposal is rejected", () => {
  const escrow = pendingRelease();
  const approval = { approvalId: "a1", proposalId: "proposal-other",
    tenantId: escrow.tenantId, escrowId: escrow.escrowId, approverId: "human-1", decision: "approved" };
  assert.equal(evaluateEscrowApproval(escrow, approval, { now: 0, verifyApproval: approvalVerifier }).reason, "proposal_mismatch");
});

test("rejected approval closes proposal without authorizing settlement", () => {
  const escrow = pendingRelease();
  const approval = { approvalId: "a1", proposalId: escrow.pendingApproval.proposalId,
    tenantId: escrow.tenantId, escrowId: escrow.escrowId, approverId: "human-1", decision: "rejected" };
  const result = evaluateEscrowApproval(escrow, approval, { now: 0, verifyApproval: approvalVerifier });
  assert.equal(result.escrow.status, "release_rejected");
  assert.equal(result.action, "none");
  assert.equal(result.executable, false);
});

test("expired approval window fails closed", () => {
  const escrow = pendingRelease();
  const approval = { approvalId: "a1", proposalId: escrow.pendingApproval.proposalId,
    tenantId: escrow.tenantId, escrowId: escrow.escrowId, approverId: "human-1", decision: "approved" };
  assert.equal(evaluateEscrowApproval(escrow, approval, {
    now: Date.parse("2031-01-01T00:00:00Z"), verifyApproval: approvalVerifier
  }).reason, "escrow_expired");
});
