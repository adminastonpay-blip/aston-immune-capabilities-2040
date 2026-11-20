-- ASTON Device Trust Registry + Replay Protection v1
-- Apply only through an explicitly authorized Cloudflare D1 migration.
-- This file is a proposed migration; it has NOT been applied to any database.

CREATE TABLE IF NOT EXISTS aston_device_trust_keys (
  tenant_id TEXT NOT NULL,
  issuer_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  public_key_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
  device_status TEXT NOT NULL CHECK (device_status IN ('active', 'inactive', 'revoked')),
  not_before TEXT NOT NULL,
  not_after TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  revocation_reason TEXT,
  PRIMARY KEY (tenant_id, issuer_id, key_id),
  CHECK (length(tenant_id) BETWEEN 1 AND 128),
  CHECK (length(issuer_id) BETWEEN 1 AND 128),
  CHECK (length(key_id) BETWEEN 1 AND 128),
  CHECK (length(device_id) BETWEEN 1 AND 128),
  CHECK (not_after > not_before)
);

CREATE INDEX IF NOT EXISTS idx_aston_device_trust_keys_device
  ON aston_device_trust_keys (tenant_id, device_id, status);

CREATE TABLE IF NOT EXISTS aston_device_trust_challenges (
  tenant_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  attestation_id TEXT NOT NULL,
  consumed_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, device_id, challenge_id),
  CHECK (length(tenant_id) BETWEEN 1 AND 128),
  CHECK (length(device_id) BETWEEN 1 AND 128),
  CHECK (length(challenge_id) BETWEEN 1 AND 128),
  CHECK (length(attestation_id) BETWEEN 1 AND 128),
  CHECK (expires_at > consumed_at)
);

CREATE INDEX IF NOT EXISTS idx_aston_device_trust_challenges_expiry
  ON aston_device_trust_challenges (expires_at);
