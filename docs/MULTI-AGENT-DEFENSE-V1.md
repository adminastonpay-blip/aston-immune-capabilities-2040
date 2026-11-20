# Multi-Agent Defense v1

**Status:** IMPLEMENTED (isolated decision engine); TESTED pending CI evidence; VALIDATED no; PRODUCTION no.

## Scope

A deterministic, side-effect-free decision function evaluates a normalized threat observation and returns a scoped recommendation. It does not connect to ASTON OS, authenticate agents, persist data, call Cloudflare, or execute containment.

## Input contract

Required fields:
- `eventId`, `tenantId`, `agentId`: non-empty bounded strings.
- `observedAt`: parseable timestamp.
- `signalType`: credential_anomaly, policy_violation, tool_abuse, integrity_failure, or replay_detected.
- `severity`: low, medium, high, or critical.
- `evidence`: `verified`, `reference`, and `verifier`.

The evidence verification fields are assertions from a trusted upstream adapter, not cryptographic verification performed by this module. An adapter must authenticate the source and verify evidence before setting `verified: true`.

## Decision policy

| Condition | Result |
|---|---|
| Invalid, stale, or implausibly future observation | Reject; no action |
| Evidence not verified | Review only |
| Verified low | No action |
| Verified medium | Review |
| Verified high | Propose restriction |
| Verified critical | Propose isolation |

Observation freshness is limited to 120 seconds, with 30 seconds of future clock skew.

## Safety invariants

- Every recommendation is scoped to the observation's exact tenant and agent.
- No cross-tenant target selection or fan-out is implemented.
- Recommendations are non-executable (`executable: false`).
- No automatic blocking, shutdown, credential revocation, or recovery occurs.
- Missing or malformed input fails closed.
- The module has no runtime dependencies and no network or storage side effects.

## Acceptance still required

1. CI test run passes on GitHub Actions.
2. Add adversarial tests for tenant-boundary misuse and untrusted adapter integration when the adapter contract is designed.
3. Independently review the evidence-verifier trust boundary.
4. Define a versioned host adapter contract before any ASTON integration.

Passing unit tests alone will not establish production readiness.
