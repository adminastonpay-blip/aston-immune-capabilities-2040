# Agentic Escrow v1 — Isolated Capability

Status: IMPLEMENTED (decision core + approval contract) / TESTING IN PROGRESS
Branch: `feat/agentic-escrow-v1`

## Purpose

Provide a deterministic, tenant-scoped decision core for conditional agent-to-agent value transfer workflows. The module records verified lifecycle events and produces non-executable proposals for approval.

## Included

- Escrow creation with validated identifiers, positive integer minor-unit amount, ISO currency code, release condition and expiry.
- Exact tenant and escrow binding for incoming events.
- A trusted-host verifier callback; caller-supplied `verified` flags are ignored.
- Minimal state transitions: `created → funded → release_pending_approval` or `funded → refund_pending_approval`.
- Exact release-condition type/reference matching before proposing release.
- Verified approval/rejection decisions bound to the exact tenant, escrow, proposal, approver and decision.
- Approved decisions become `approved_for_release` / `approved_for_refund` and only authorize a separate settlement integration; they do not execute settlement.
- Duplicate event idempotency within the returned escrow state.
- Explicit `executable: false` for every decision.

## Explicitly excluded

- Custody, payment processing, settlement, transfers, refunds, banking integrations or ledger persistence.
- Authentication of tenant/agent identity.
- Cryptographic signature verification, issuer authorization, key lifecycle or trust-anchor management.
- Durable replay protection across processes; current duplicate tracking is in-memory state supplied by the caller.
- SafetyInterlock or ASTON OS runtime wiring.
- Production deployment or permission to move funds.

## Trust boundary

The `verifyEvent` callback is privileged host code. It must be supplied by a trusted composition layer and must not originate from an agent, request body, queue payload or user-controlled data. A successful callback must bind the exact event ID, event type, escrow ID, tenant ID and (when present) release-condition type/reference, and identify the verifier. Approval verification must additionally bind the approval ID, proposal ID, approver and decision. This library does not prove that the callback itself is trustworthy.

## Approval boundary

A release or refund event only creates a proposal and moves the local decision record to a pending-approval state. A separate host integration must obtain the required human/SafetyInterlock approval and execute settlement through an independently authorized payment provider. This module cannot execute either action.

## Acceptance criteria for v1

1. Invalid escrow inputs are rejected.
2. Events with mismatched tenant/escrow scope are rejected.
3. Missing, throwing or mismatched verifier results fail closed.
4. Release cannot be proposed before funding is verified.
5. Release proposals match the configured release condition exactly.
6. Release/refund proposals are non-executable and approval-required.
7. Approval/rejection requires a trusted verifier bound to the exact proposal and approver.
8. Rejected approvals never authorize settlement; approved decisions remain non-executable.
9. Duplicate events do not repeat transitions.
10. Expired escrows reject new events and approvals.
11. Automated tests pass on the isolated branch.

No integration into `agente-OS-15.5-hector-zapata`, no Cloudflare changes and no production activation are included.
