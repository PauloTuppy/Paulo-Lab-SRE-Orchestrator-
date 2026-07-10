import os
from orchestrator.gatekeeper import decide_remediation, safe_kubectl_apply, get_confidence_threshold
from orchestrator.sqlite_store import get_db


def test_confidence_threshold_rules():
    """Verify confidence rules and action-specific limits."""
    # Action 'tweak_limits' needs 0.6. Confidence 0.55 should ESCALATE.
    contract_1 = {
        "incident_fingerprint": "fp-1",
        "hypothesis": {"proposed_action": "tweak_limits", "confidence": 0.55},
        "evidence": {}
    }
    decision, reason = decide_remediation(contract_1)
    assert decision == "ESCALATE"
    assert "Confiança baixa" in reason

    # Confidence 0.65 should APPLY.
    contract_2 = {
        "incident_fingerprint": "fp-1",
        "hypothesis": {"proposed_action": "tweak_limits", "confidence": 0.65},
        "evidence": {}
    }
    decision, reason = decide_remediation(contract_2)
    assert decision == "APPLY"

    # Action 'rollback' needs 0.7. Confidence 0.65 should ESCALATE.
    contract_3 = {
        "incident_fingerprint": "fp-1",
        "hypothesis": {"proposed_action": "rollback", "confidence": 0.65},
        "evidence": {}
    }
    decision, reason = decide_remediation(contract_3)
    assert decision == "ESCALATE"


def test_threshold_environment_overrides(monkeypatch):
    """Verify that environment variables can override default action thresholds."""
    monkeypatch.setenv("THRESHOLD_TWEAK_LIMITS", "0.9")
    assert get_confidence_threshold("tweak_limits") == 0.9

    contract = {
        "incident_fingerprint": "fp-1",
        "hypothesis": {"proposed_action": "tweak_limits", "confidence": 0.8},
        "evidence": {}
    }
    decision, _ = decide_remediation(contract)
    assert decision == "ESCALATE"  # 0.8 < 0.9 threshold


def test_recent_failure_veto():
    """Verify that a recent reoccurrence (within 24 hours) trigger a VETO."""
    fingerprint = "fp-failed-remed"
    action = "tweak_limits"
    
    # Check initially - should APPLY
    contract = {
        "incident_fingerprint": fingerprint,
        "hypothesis": {"proposed_action": action, "confidence": 0.8},
        "evidence": {}
    }
    decision, _ = decide_remediation(contract)
    assert decision == "APPLY"

    # Insert a recent reoccurred outcome in SQLite history
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO incident_history (fingerprint, action_type, outcome, proof_contract_json, created_at)
            VALUES (?, ?, 'reoccurred', '{}', datetime('now'))
            """,
            (fingerprint, action)
        )
        conn.commit()

    # Query gatekeeper again - should VETO due to recent failure
    decision, reason = decide_remediation(contract)
    assert decision == "VETO"
    assert "já falhou recentemente" in reason


def test_previous_outcome_veto_in_contract():
    """Verify that previous outcome details in contract evidence trigger a VETO."""
    contract = {
        "incident_fingerprint": "fp-new",
        "hypothesis": {"proposed_action": "tweak_limits", "confidence": 0.8},
        "evidence": {
            "historical_match": {
                "found": True,
                "previous_incident_id": "1",
                "previous_outcome": "caused_side_effect"
            }
        }
    }
    decision, reason = decide_remediation(contract)
    assert decision == "VETO"
    assert "histórico ruim" in reason


def test_safe_kubectl_apply_offline_dry_run(tmp_path):
    """Verify simulated offline kubectl dry-run success and failure cases."""
    manifest = tmp_path / "app-pod.yaml"
    contract = {
        "incident_fingerprint": "fp-offline",
        "hypothesis": {"proposed_action": "tweak_limits", "confidence": 0.85},
        "evidence": {}
    }

    # Manifest file doesn't exist -> VETO
    decision, reason = safe_kubectl_apply(str(manifest), contract)
    assert decision == "VETO"
    assert "não encontrado" in reason

    # Create empty manifest file -> VETO
    manifest.write_text("")
    decision, reason = safe_kubectl_apply(str(manifest), contract)
    assert decision == "VETO"
    assert "Manifesto vazio" in reason

    # Create valid manifest content -> APPLY
    manifest.write_text("apiVersion: v1\nkind: Pod")
    decision, reason = safe_kubectl_apply(str(manifest), contract)
    assert decision == "APPLY"
    assert "[OFFLINE SIMULATION]" in reason
