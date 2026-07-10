import sqlite3
from datetime import datetime, timedelta
from orchestrator.sqlite_store import get_db, cleanup_old_incidents


def test_schema_initialization():
    """Verify that tables are correctly initialized and indexes are present."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Verify tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row["name"] for row in cursor.fetchall()]
        assert "incident_history" in tables
        assert "pending_incidents" in tables
        
        # Verify indexes
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = [row["name"] for row in cursor.fetchall()]
        assert "idx_history_fingerprint" in indexes
        assert "idx_pending_status" in indexes


def test_data_insertion_and_querying():
    """Verify that we can insert records and query them."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Insert a pending incident
        cursor.execute(
            """
            INSERT INTO pending_incidents (incident_id, source, namespace, pod_name, proposed_action, manifest_path)
            VALUES ('inc-test-1', 'test', 'default', 'pod-1', 'tweak_limits', '/manifest.yaml')
            """
        )
        conn.commit()

        # Query pending
        cursor.execute("SELECT * FROM pending_incidents WHERE incident_id = 'inc-test-1'")
        row = cursor.fetchone()
        assert row is not None
        assert row["status"] == "pending"
        assert row["source"] == "test"
        assert row["proposed_action"] == "tweak_limits"


def test_database_retention():
    """Verify that records older than 90 days are deleted."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Insert recent record
        cursor.execute(
            """
            INSERT INTO incident_history (fingerprint, action_type, outcome, proof_contract_json, created_at)
            VALUES ('fp-new', 'tweak_limits', 'resolved', '{}', datetime('now'))
            """
        )
        
        # Insert old record (95 days ago)
        old_date = (datetime.utcnow() - timedelta(days=95)).isoformat(timespec="seconds")
        cursor.execute(
            """
            INSERT INTO incident_history (fingerprint, action_type, outcome, proof_contract_json, created_at)
            VALUES ('fp-old', 'tweak_limits', 'reoccurred', '{}', ?)
            """,
            (old_date,)
        )
        conn.commit()

    # Perform cleanup
    deleted = cleanup_old_incidents(days=90)
    assert deleted == 1

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT fingerprint FROM incident_history")
        rows = cursor.fetchall()
        fingerprints = [r["fingerprint"] for r in rows]
        assert "fp-new" in fingerprints
        assert "fp-old" not in fingerprints
