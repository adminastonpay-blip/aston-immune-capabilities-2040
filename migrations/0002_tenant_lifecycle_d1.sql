-- TEN-02 Tenant Lifecycle D1 Provider v1
-- PROPOSED ONLY. Do not apply without explicit production authorization.
-- A single INSERT into the idempotency table drives all lifecycle effects through
-- SQLite triggers. Cloudflare D1 batch() executes the INSERT + readback atomically.

CREATE TABLE IF NOT EXISTS aston_tenants (
  tenant_id TEXT PRIMARY KEY NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','active','suspended','revoked','offboarded')),
  version INTEGER NOT NULL CHECK (version >= 1),
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
  CHECK (length(tenant_id) BETWEEN 1 AND 64)
);

CREATE TABLE IF NOT EXISTS aston_tenant_lifecycle_idempotency (
  actor_principal_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
  audit_event_id TEXT NOT NULL UNIQUE,
  tenant_id TEXT NOT NULL,
  operation TEXT NOT NULL CHECK (operation IN ('create','activate','suspend','revoke')),
  target_status TEXT NOT NULL CHECK (target_status IN ('pending','active','suspended','revoked')),
  actor_scope TEXT NOT NULL CHECK (actor_scope IN ('platform','delegated')),
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 8 AND 500),
  correlation_id TEXT,
  occurred_at INTEGER NOT NULL CHECK (occurred_at >= 0),
  PRIMARY KEY (actor_principal_id, idempotency_key),
  CHECK (length(actor_principal_id) BETWEEN 1 AND 200),
  CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  CHECK (length(tenant_id) BETWEEN 1 AND 64)
);

CREATE TABLE IF NOT EXISTS aston_tenant_lifecycle_audit (
  audit_event_id TEXT PRIMARY KEY NOT NULL,
  event_type TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  from_status TEXT,
  to_status TEXT NOT NULL,
  actor_principal_id TEXT NOT NULL,
  actor_scope TEXT NOT NULL,
  reason TEXT NOT NULL,
  correlation_id TEXT,
  occurred_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_aston_tenant_lifecycle_audit_tenant_time
  ON aston_tenant_lifecycle_audit (tenant_id, occurred_at);

-- Validate state before the idempotency INSERT can commit. For an existing
-- actor/key, the insert is a replay candidate and must not revalidate transition.
CREATE TRIGGER IF NOT EXISTS trg_aston_tenant_lifecycle_validate
BEFORE INSERT ON aston_tenant_lifecycle_idempotency
WHEN NOT EXISTS (
  SELECT 1 FROM aston_tenant_lifecycle_idempotency
  WHERE actor_principal_id = NEW.actor_principal_id
    AND idempotency_key = NEW.idempotency_key
)
BEGIN
  SELECT CASE
    WHEN NEW.operation = 'create' AND NEW.target_status != 'pending'
      THEN RAISE(ABORT, 'TEN02_INVALID_TARGET')
    WHEN NEW.operation = 'create' AND EXISTS (
      SELECT 1 FROM aston_tenants WHERE tenant_id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'TEN02_TRANSITION_REJECTED')
    WHEN NEW.operation = 'activate' AND NEW.target_status != 'active'
      THEN RAISE(ABORT, 'TEN02_INVALID_TARGET')
    WHEN NEW.operation = 'activate' AND NOT EXISTS (
      SELECT 1 FROM aston_tenants
      WHERE tenant_id = NEW.tenant_id AND status IN ('pending','suspended')
    ) THEN RAISE(ABORT, 'TEN02_TRANSITION_REJECTED')
    WHEN NEW.operation = 'suspend' AND NEW.target_status != 'suspended'
      THEN RAISE(ABORT, 'TEN02_INVALID_TARGET')
    WHEN NEW.operation = 'suspend' AND NOT EXISTS (
      SELECT 1 FROM aston_tenants
      WHERE tenant_id = NEW.tenant_id AND status = 'active'
    ) THEN RAISE(ABORT, 'TEN02_TRANSITION_REJECTED')
    WHEN NEW.operation = 'revoke' AND NEW.target_status != 'revoked'
      THEN RAISE(ABORT, 'TEN02_INVALID_TARGET')
    WHEN NEW.operation = 'revoke' AND NOT EXISTS (
      SELECT 1 FROM aston_tenants
      WHERE tenant_id = NEW.tenant_id AND status IN ('pending','active','suspended')
    ) THEN RAISE(ABORT, 'TEN02_TRANSITION_REJECTED')
  END;
END;

CREATE TRIGGER IF NOT EXISTS trg_aston_tenant_lifecycle_apply
AFTER INSERT ON aston_tenant_lifecycle_idempotency
BEGIN
  INSERT INTO aston_tenants (tenant_id, status, version, created_at, updated_at)
  SELECT NEW.tenant_id, 'pending', 1, NEW.occurred_at, NEW.occurred_at
  WHERE NEW.operation = 'create';

  UPDATE aston_tenants
  SET status = NEW.target_status, version = version + 1, updated_at = NEW.occurred_at
  WHERE tenant_id = NEW.tenant_id AND NEW.operation != 'create';

  INSERT INTO aston_tenant_lifecycle_audit (
    audit_event_id, event_type, tenant_id, from_status, to_status,
    actor_principal_id, actor_scope, reason, correlation_id, occurred_at
  ) VALUES (
    NEW.audit_event_id, 'tenant.lifecycle.' || NEW.operation, NEW.tenant_id,
    CASE WHEN NEW.operation = 'create' THEN NULL ELSE
      (SELECT status FROM aston_tenants WHERE tenant_id = NEW.tenant_id)
    END,
    NEW.target_status, NEW.actor_principal_id, NEW.actor_scope, NEW.reason,
    NEW.correlation_id, NEW.occurred_at
  );
END;

-- Append-only protections. Application code receives no update/delete API.
CREATE TRIGGER IF NOT EXISTS trg_aston_tenant_lifecycle_audit_no_update
BEFORE UPDATE ON aston_tenant_lifecycle_audit
BEGIN SELECT RAISE(ABORT, 'TEN02_AUDIT_IMMUTABLE'); END;

CREATE TRIGGER IF NOT EXISTS trg_aston_tenant_lifecycle_audit_no_delete
BEFORE DELETE ON aston_tenant_lifecycle_audit
BEGIN SELECT RAISE(ABORT, 'TEN02_AUDIT_IMMUTABLE'); END;

CREATE TRIGGER IF NOT EXISTS trg_aston_tenant_idempotency_no_update
BEFORE UPDATE ON aston_tenant_lifecycle_idempotency
BEGIN SELECT RAISE(ABORT, 'TEN02_IDEMPOTENCY_IMMUTABLE'); END;

CREATE TRIGGER IF NOT EXISTS trg_aston_tenant_idempotency_no_delete
BEFORE DELETE ON aston_tenant_lifecycle_idempotency
BEGIN SELECT RAISE(ABORT, 'TEN02_IDEMPOTENCY_IMMUTABLE'); END;
