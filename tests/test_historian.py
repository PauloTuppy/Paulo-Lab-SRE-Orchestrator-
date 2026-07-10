import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from orchestrator.historian import (
    classify_incident,
    call_local_classifier,
    process_applied_incidents_once,
    get_pod_status,
    get_pod_logs
)
from orchestrator.sqlite_store import get_db


def test_local_rule_classifier_cases():
    """Verify deterministic local classification rules."""
    contract = {"incident_fingerprint": "fp-1"}

    # Case 1: Healthy pod -> resolved
    pod_healthy = {
        "status": {
            "phase": "Running",
            "containerStatuses": [{"restartCount": 0, "ready": True}]
        }
    }
    logs_healthy = "Application started. Listening on port 8080."
    res = call_local_classifier(contract, pod_healthy, logs_healthy)
    assert res["outcome"] == "resolved"

    # Case 2: Pod restarted -> reoccurred
    pod_restarted = {
        "status": {
            "phase": "Running",
            "containerStatuses": [{"restartCount": 3, "ready": True}]
        }
    }
    res = call_local_classifier(contract, pod_restarted, logs_healthy)
    assert res["outcome"] == "reoccurred"

    # Case 3: Node memory pressure log -> caused_side_effect
    logs_side_effect = "Target pod healthy, node memory_pressure=true, sibling latency increased"
    res = call_local_classifier(contract, pod_healthy, logs_side_effect)
    assert res["outcome"] == "caused_side_effect"

    # Case 4: Negated critical log events -> resolved
    logs_negated_oom = "Logs: Container started, health checks passed. No OOMKilled events."
    res = call_local_classifier(contract, pod_healthy, logs_negated_oom)
    assert res["outcome"] == "resolved"

    logs_negated_crash = "Pod started without crash loop."
    res = call_local_classifier(contract, pod_healthy, logs_negated_crash)
    assert res["outcome"] == "resolved"

    # Case 5: Non-negated critical log events -> reoccurred
    logs_critical_oom = "Logs: OOMKilled detected."
    res = call_local_classifier(contract, pod_healthy, logs_critical_oom)
    assert res["outcome"] == "reoccurred"

    logs_critical_crash = "Pod is in CrashLoopBackOff status"
    res = call_local_classifier(contract, pod_healthy, logs_critical_crash)
    assert res["outcome"] == "reoccurred"


def test_fallback_sequence_offline_mode(monkeypatch):
    """Verify that in offline mode, the historian uses local rules directly."""
    monkeypatch.setenv("EXECUTION_MODE", "offline")
    
    contract = {"incident_fingerprint": "fp-1"}
    pod_status = {"status": {"phase": "Running"}}
    post_logs = "Clean logs."

    # Even if internal endpoint is set, offline mode should bypass and use local rules
    monkeypatch.setenv("HISTORIAN_ENDPOINT", "http://test-endpoint/historian")
    
    with patch("requests.post") as mock_post:
        outcome, model = classify_incident(contract, pod_status, post_logs)
        assert model == "local_rules"
        assert outcome["outcome"] == "resolved"
        mock_post.assert_not_called()


@patch("orchestrator.historian.call_internal_endpoint")
@patch("orchestrator.historian.call_gemini_historian")
def test_fallback_chain_failures(mock_gemini, mock_internal, monkeypatch):
    """Verify fallback from internal endpoint to Gemini, and then to local rules on error."""
    monkeypatch.setenv("EXECUTION_MODE", "staging")
    monkeypatch.setenv("HISTORIAN_ENDPOINT", "http://test-endpoint/historian")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    contract = {"incident_fingerprint": "fp-1", "hypothesis": {"proposed_action": "tweak_limits"}}
    pod_status = {"status": {"phase": "Running"}}
    post_logs = "Pressure occurred"

    # Scenario: Internal endpoint fails, Gemini fails, should return local rules (caused_side_effect)
    mock_internal.side_effect = Exception("Internal endpoint down")
    mock_gemini.side_effect = Exception("Gemini API quota exceeded")

    outcome, model_name = classify_incident(contract, pod_status, post_logs)
    assert model_name == "local_rules"
    assert outcome["outcome"] == "caused_side_effect"


def test_process_applied_incidents(monkeypatch, tmp_path):
    """Verify DB workflow: fetching applied incidents, classifying, and saving results."""
    monkeypatch.setenv("HISTORIAN_DELAY_SEC", "0")  # Process instantly without delay
    
    # Insert an applied incident into SQLite with ts_applied offset in the past
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO pending_incidents (
                incident_id, source, namespace, pod_name, proposed_action, manifest_path, status, ts_applied, playbook_id, fingerprint, idempotency_key
            )
            VALUES ('inc-applied-1', 'alertmanager', 'sre-system', 'app-pod-123', 'tweak_limits', 'manifest.yaml', 'applied', datetime('now', '-10 seconds'), 'tweak_limits_v1', 'fp-applied-1', 'key-applied-1')
            """
        )
        conn.commit()

        # Create dummy manifest file to pass local dry-run / contract builder
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text("apiVersion: v1")

    # Run historian processing
    processed = process_applied_incidents_once()
    assert processed == 1

    # Verify state updates in SQLite
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Incident state should now be 'classified'
        cursor.execute("SELECT status FROM pending_incidents WHERE incident_id = 'inc-applied-1'")
        row = cursor.fetchone()
        assert row["status"] == "classified"

        # A new row should exist in incident_history
        cursor.execute("SELECT * FROM incident_history")
        history_row = cursor.fetchone()
        assert history_row is not None
        assert history_row["outcome"] == "resolved"  # default local mock classification
        assert history_row["historian_model"] == "local_rules"


def test_synthetic_incidents_regression():
    """Regression test verifying local classifier outcomes match expected outcomes for SYNTHETIC_INCIDENTS."""
    from orchestrator.wandb_eval import SYNTHETIC_INCIDENTS
    
    # 1. Run on the original 3 synthetic scenarios
    for incident in SYNTHETIC_INCIDENTS:
        contract = incident["proof_contract"]
        pod_status = incident["pod_status"]
        logs = incident["post_apply_logs"]
        expected = incident["expected_outcome"]
        
        res = call_local_classifier(contract, pod_status, logs)
        assert res["outcome"] == expected, f"Incident {incident['incident_id']} expected {expected}, got {res['outcome']}"

    # 2. Additional regression cases for negation checking
    pod_healthy = {
        "status": {
            "phase": "Running",
            "containerStatuses": [{"restartCount": 0, "ready": True}]
        }
    }
    contract = {"incident_fingerprint": "fp-test"}
    
    # Case A: "No CrashLoopBackOff events" -> resolved
    res = call_local_classifier(contract, pod_healthy, "No CrashLoopBackOff events")
    assert res["outcome"] == "resolved", f"Expected resolved for No CrashLoopBackOff events, got {res['outcome']}"
    
    # Case B: "timeout resolved, no new 5xx" -> resolved
    res = call_local_classifier(contract, pod_healthy, "timeout resolved, no new 5xx")
    assert res["outcome"] == "resolved", f"Expected resolved for timeout resolved, no new 5xx, got {res['outcome']}"


def test_v2_regression_cases():
    """Verify three new regression cases for historian-agent-v2."""
    from orchestrator.historian import call_local_classifier
    pod_healthy = {
        "status": {
            "phase": "Running",
            "containerStatuses": [{"restartCount": 0, "ready": True}]
        }
    }
    
    # 1. reoccurred com historical_match alerta de padrão repetido
    contract_repeated = {
        "evidence": {
            "historical_match": {
                "found": True,
                "previous_outcome": "reoccurred"
            }
        }
    }
    res = call_local_classifier(contract_repeated, pod_healthy, "Clean logs.")
    assert res["outcome"] == "reoccurred"
    assert "padrão repetido" in res["observacao"]
    
    # 2. caused_side_effect (PDB violation + DB overload)
    contract_clean = {"evidence": {"historical_match": {"found": False}}}
    res = call_local_classifier(contract_clean, pod_healthy, "PDB violation detected, database overload observed")
    assert res["outcome"] == "caused_side_effect"
    assert "pdb" in res["observacao"] or "overload" in res["observacao"]
    
    # 3. resolved (restart_pod limpo)
    res = call_local_classifier(contract_clean, pod_healthy, "restart_pod limpo, pod started successfully")
    assert res["outcome"] == "resolved"

