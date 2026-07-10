import os
import json
from fastapi.testclient import TestClient
from orchestrator.api import app
from orchestrator.sqlite_store import get_store, get_db
from orchestrator.worker import process_pending_once
from orchestrator.historian import process_applied_incidents_once

def test_full_loop_integration(monkeypatch, tmp_path):
    """
    Verifies end-to-end integration:
    1. Send webhook alert
    2. Check pending incident queue
    3. Process via worker daemon
    4. Classify via historian
    """
    import orchestrator.api
    monkeypatch.setattr(orchestrator.api, "WEBHOOK_TOKEN", "test-token")
    client = TestClient(app)
    
    # 1. Simulate incoming webhook alert
    payload = {
        "source": "alertmanager",
        "incident_id": "integration-incident-123",
        "fingerprint_inputs": {
            "namespace": "app",
            "pod_name": "app-service-xyz",
            "container_image": "app:v1",
            "error_type": "OOMKilled"
        },
        "proposed_action": "tweak_limits",
        "raw_payload": {
            "version": 2
        }
    }
    
    # Authenticate with configured test token
    headers = {"X-Webhook-Token": "test-token"}
    response = client.post("/webhook", json=payload, headers=headers)
    assert response.status_code == 200
    assert "processed_incidents" in response.json()
    assert "integration-incident-123" in response.json()["processed_incidents"]

    # 2. Check pending queue in database
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_incidents WHERE incident_id = 'integration-incident-123'")
        row = cursor.fetchone()
        assert row is not None
        assert row["status"] == "pending"
        assert row["playbook_id"] == "tweak_limits_v1"
        assert row["incident_version"] == 2

    # 3. Run worker processing once
    # Mock is_playbook_already_applied to return False
    monkeypatch.setenv("EXECUTION_MODE", "offline")
    monkeypatch.setenv("HOSTNAME", "test-worker-1")
    
    processed = process_pending_once()
    assert processed is True

    # Check status changed to applied
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_incidents WHERE incident_id = 'integration-incident-123'")
        row = cursor.fetchone()
        assert row is not None
        assert row["status"] == "applied"
        assert row["ts_applied"] is not None
        print("DEBUG row ts_applied:", row["ts_applied"])

    # 4. Run historian processing once
    monkeypatch.setenv("HISTORIAN_DELAY_SEC", "-10")
    
    # Mock get_pod_status and get_pod_logs
    import orchestrator.historian
    monkeypatch.setattr(orchestrator.historian, "get_pod_status", lambda ns, p: {"status": {"phase": "Running"}})
    monkeypatch.setattr(orchestrator.historian, "get_pod_logs", lambda ns, p: "Standard pod logs, running healthy.")
    
    import datetime as dt
    print("DEBUG threshold:", (dt.datetime.utcnow() - dt.timedelta(seconds=-10)).isoformat(timespec="seconds"))

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_incidents WHERE status = 'applied'")
        print("DEBUG DB applied rows:", [dict(r) for r in cursor.fetchall()])

    classified = process_applied_incidents_once()
    assert classified == 1

    # Verify database final state
    with get_db() as conn:
        cursor = conn.cursor()
        # Incident status should now be 'classified'
        cursor.execute("SELECT * FROM pending_incidents WHERE incident_id = 'integration-incident-123'")
        row = cursor.fetchone()
        assert row is not None
        assert row["status"] == "classified"

        # Check history contains the record
        cursor.execute("SELECT * FROM incident_history WHERE fingerprint = ?", (row["fingerprint"],))
        hist_row = cursor.fetchone()
        assert hist_row is not None
        assert hist_row["outcome"] == "resolved"
        assert hist_row["action_type"] == "tweak_limits"
        assert "OOMKilled" in hist_row["proof_contract_json"]
