# Architecture and integration boundaries

## 1. Purpose

This repository contains optional capability modules for ASTON OS 2040. It is not a replacement runtime, control plane, or production deployment repository.

## 2. Dependency direction

Capability modules may depend on narrow, versioned host contracts. The ASTON OS runtime must not depend on this repository during its development. Integration is a later, separately approved activity.

```text
ASTON OS runtime (unchanged)
        |
        | approved, versioned host contracts only
        v
Independent capability adapters
        |
        +-- Multi-Agent Defense
        +-- Agentic Escrow
        +-- Inter-Agent Governance
        +-- Physical Edge Attestation
```

The diagram describes the intended boundary, not a currently deployed connection.

## 3. Contract principles

- Explicit identity and tenant scope on every security-sensitive request.
- Least privilege; no ambient authority or implicit trust between agents.
- Authenticated, integrity-protected evidence with timestamps/nonces where replay matters.
- Idempotent operations and explicit timeouts for host calls.
- Fail closed when identity, policy, evidence, or host capability is missing.
- Human approval for irreversible/high-impact actions.
- Audit records must avoid secrets and unnecessary personal data.
- No direct Cloudflare binding names, credentials, or production resource assumptions in capability code.

## 4. Capability boundaries

### Multi-Agent Defense
A pure decision layer evaluates signed observations and proposes scoped containment actions. Execution is delegated to an approved host adapter. It must not disable unrelated tenants, agents, or services.

### Agentic Escrow
A policy engine evaluates release conditions and evidence. The initial implementation is simulation-only: it cannot move money, call payment processors, or release real assets.

### Inter-Agent Governance
Defines interoperable identity claims, scoped delegation, policy decisions, expiry, revocation, and evidence formats. Trust is never inferred solely from an agent's self-asserted identity.

### Physical Edge Attestation
Verifies device credentials, signed telemetry, freshness, and command provenance. Initial implementation is verification-only; it cannot actuate physical equipment.

## 5. Required acceptance criteria

A capability is not complete until:
1. Its contract and threat model are explicit.
2. Positive, negative, malformed, replay, and cross-tenant cases are tested.
3. Missing dependencies and invalid evidence fail closed.
4. Tests run in an isolated environment without production credentials.
5. No writes or dependencies are introduced into the ASTON OS runtime.
6. Evidence, limitations, and exact delivery state are recorded.
7. Any proposed integration is reviewed separately and requires explicit approval.

## 6. Delivery states

- DESIGN: contract and design documented.
- IMPLEMENTED: code exists; not necessarily tested.
- TESTED: automated tests pass in the stated isolated environment.
- VALIDATED: acceptance criteria and integration assumptions have supporting evidence.
- PRODUCTION: deployed and operational with explicit authorization and production evidence.

Never infer a later state from an earlier one.
