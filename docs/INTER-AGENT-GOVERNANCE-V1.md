# Inter-Agent Governance v1 — Isolated Capability

Status: IMPLEMENTED (initial policy decision core) / TESTING IN PROGRESS
Branch: `feat/inter-agent-governance-v1`

## Purpose

Provide a deterministic policy boundary for agent-to-agent requests. The module checks tenant scope, delegation parties, audience, requested scopes, grant lifetime, delegation depth, host verification and local action policy.

## Included

- Exact tenant, issuer/source-agent and subject/target-agent binding.
- Audience binding and scope-subset enforcement.
- Request and grant expiry checks, including future-issued request rejection.
- Delegation depth bounds.
- Trusted host verifier callback with exact request/grant binding.
- Policy outcomes: allow, review, deny.
- Human approval-required action classification.
- All outcomes are non-executable.

## Explicitly excluded

- Cryptographic signature verification, key management, issuer trust anchors or agent identity enrollment.
- Authenticated tenant resolution; the trusted host verifier must bind tenant and agent identities.
- Durable nonce/replay storage.
- Delegation issuance, revocation registry or persistent grant ledger.
- SafetyInterlock runtime integration, message transport, tool invocation or action execution.
- Production deployment or automatic cross-agent authority.

## Trust boundary

`verifyRequest` is privileged host composition code. It must not originate from request payloads, agents or queue messages. It must authenticate the request and bind request ID, tenant, source/target agents, action, resource, grant ID and audience. This library checks the returned bindings but does not prove the verifier itself is trustworthy.

## Policy boundary

The host supplies the local policy. Denied actions are rejected; an optional allowlist restricts accepted actions; approval-required actions return review with `approvalRequired: true`. A plain `allow` is a non-executable policy result, not permission for this module to invoke a tool.

## Acceptance criteria

1. Tenant, agent, audience and scope mismatches are rejected.
2. Expired, future-issued and over-depth delegations fail closed.
3. Missing or mismatched trusted verification never returns allow.
4. Denied actions are rejected and approval-required actions return review.
5. All decisions remain non-executable.
6. Automated tests pass on the isolated branch.

No integration into `agente-OS-15.5-hector-zapata`, no Cloudflare changes and no production activation are included.
