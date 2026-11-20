import sqlite3
import unittest
from pathlib import Path

MIGRATION = Path(__file__).resolve().parents[2] / "migrations" / "0002_tenant_lifecycle_d1.sql"


class TenantLifecycleSqliteIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.migration = MIGRATION.read_text(encoding="utf-8")
        self.db.executescript(self.migration)

    def tearDown(self):
        self.db.close()

    def command(self, *, key, event, tenant="tenant-a", operation="create",
                target="pending", fingerprint=None, actor="admin:root",
                reason="approved lifecycle", at=100):
        return (
            """
            INSERT INTO aston_tenant_lifecycle_idempotency (
              actor_principal_id, idempotency_key, fingerprint, audit_event_id,
              tenant_id, operation, target_status, actor_scope, reason,
              correlation_id, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'platform', ?, 'trace-1', ?)
            ON CONFLICT(actor_principal_id, idempotency_key) DO NOTHING
            """,
            (actor, key, fingerprint or (key[0].lower() * 64), event,
             tenant, operation, target, reason, at),
        )

    def apply(self, command):
        statement, values = command
        with self.db:
            cursor = self.db.execute(statement, values)
            row = self.db.execute(
                """SELECT fingerprint, audit_event_id, tenant_id
                   FROM aston_tenant_lifecycle_idempotency
                   WHERE actor_principal_id=? AND idempotency_key=?""",
                (values[0], values[1]),
            ).fetchone()
        return cursor.rowcount, row

    def test_migration_executes_and_is_idempotent(self):
        self.db.executescript(self.migration)
        self.db.executescript(self.migration)
        names = self.db.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall()
        self.assertGreaterEqual(len(names), 5)

    def test_complete_lifecycle_and_audit_pre_state(self):
        transitions = [
            ("create", "pending", None, "pending"),
            ("activate", "active", "pending", "active"),
            ("suspend", "suspended", "active", "suspended"),
            ("activate", "active", "suspended", "active"),
            ("revoke", "revoked", "active", "revoked"),
        ]
        for index, (operation, target, _before, _after) in enumerate(transitions):
            self.apply(self.command(
                key=f"key-{index}", event=f"event-{index}",
                operation=operation, target=target, at=100 + index
            ))
        tenant = self.db.execute(
            "SELECT status, version FROM aston_tenants WHERE tenant_id='tenant-a'"
        ).fetchone()
        self.assertEqual((tenant["status"], tenant["version"]), ("revoked", 5))
        audit = self.db.execute(
            "SELECT from_status, to_status FROM aston_tenant_lifecycle_audit ORDER BY occurred_at"
        ).fetchall()
        self.assertEqual([(r["from_status"], r["to_status"]) for r in audit],
                         [(x[2], x[3]) for x in transitions])

    def test_same_idempotency_key_replays_without_second_effect(self):
        cmd = self.command(key="same-key", event="event-original")
        first_changes, first = self.apply(cmd)
        replay_changes, replay = self.apply(self.command(
            key="same-key", event="event-retry"
        ))
        self.assertEqual(first_changes, 1)
        self.assertEqual(replay_changes, 0)
        self.assertEqual(first["audit_event_id"], replay["audit_event_id"])
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM aston_tenant_lifecycle_audit"
        ).fetchone()[0], 1)

    def test_reused_key_with_different_fingerprint_does_not_overwrite(self):
        self.apply(self.command(key="same-key", event="event-original"))
        changes, row = self.apply(self.command(
            key="same-key", event="event-conflict", fingerprint="f" * 64
        ))
        self.assertEqual(changes, 0)
        self.assertEqual(row["audit_event_id"], "event-original")
        self.assertNotEqual(row["fingerprint"], "f" * 64)

    def test_invalid_transition_aborts_without_partial_writes(self):
        with self.assertRaisesRegex(sqlite3.IntegrityError, "TEN02_TRANSITION_REJECTED"):
            self.apply(self.command(
                key="bad-activate", event="bad-event",
                operation="activate", target="active"
            ))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM aston_tenant_lifecycle_idempotency").fetchone()[0], 0)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM aston_tenant_lifecycle_audit").fetchone()[0], 0)

    def test_audit_and_idempotency_are_append_only(self):
        self.apply(self.command(key="create-key", event="create-event"))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "TEN02_AUDIT_IMMUTABLE"):
            with self.db:
                self.db.execute("DELETE FROM aston_tenant_lifecycle_audit WHERE audit_event_id='create-event'")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "TEN02_IDEMPOTENCY_IMMUTABLE"):
            with self.db:
                self.db.execute("DELETE FROM aston_tenant_lifecycle_idempotency WHERE idempotency_key='create-key'")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM aston_tenant_lifecycle_audit").fetchone()[0], 1)

    def test_trigger_failure_rolls_back_idempotency_audit_and_tenant(self):
        self.apply(self.command(key="seed-key", event="shared-event"))
        before = tuple(self.db.execute(
            "SELECT (SELECT COUNT(*) FROM aston_tenants), "
            "(SELECT COUNT(*) FROM aston_tenant_lifecycle_audit), "
            "(SELECT COUNT(*) FROM aston_tenant_lifecycle_idempotency)"
        ).fetchone())
        with self.assertRaises(sqlite3.IntegrityError):
            self.apply(self.command(
                key="rollback-key", event="shared-event", tenant="tenant-b"
            ))
        after = tuple(self.db.execute(
            "SELECT (SELECT COUNT(*) FROM aston_tenants), "
            "(SELECT COUNT(*) FROM aston_tenant_lifecycle_audit), "
            "(SELECT COUNT(*) FROM aston_tenant_lifecycle_idempotency)"
        ).fetchone())
        self.assertEqual(before, after)
        self.assertIsNone(self.db.execute(
            "SELECT tenant_id FROM aston_tenants WHERE tenant_id='tenant-b'"
        ).fetchone())

    def test_schema_rejects_noncanonical_and_legacy_tenant_ids(self):
        for tenant in ("default", "ops", "unassigned-abc", "Uppercase", "-leading", "trailing-"):
            with self.subTest(tenant=tenant):
                with self.assertRaises(sqlite3.IntegrityError):
                    with self.db:
                        self.db.execute(
                            """INSERT INTO aston_tenants
                               (tenant_id,status,version,created_at,updated_at)
                               VALUES (?, 'pending', 1, 1, 1)""",
                            (tenant,),
                        )

    def test_schema_accepts_canonical_tenant_id(self):
        with self.db:
            self.db.execute(
                """INSERT INTO aston_tenants
                   (tenant_id,status,version,created_at,updated_at)
                   VALUES ('tenant-2040', 'pending', 1, 1, 1)"""
            )
        self.assertEqual(self.db.execute(
            "SELECT tenant_id FROM aston_tenants"
        ).fetchone()[0], "tenant-2040")


if __name__ == "__main__":
    unittest.main(verbosity=2)
