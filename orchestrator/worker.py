import os
import sys
import time
import threading
from datetime import datetime
from orchestrator.sqlite_store import get_store, initialize_database
from orchestrator.gatekeeper import safe_kubectl_apply
from orchestrator.contracts import ProofContract, Hypothesis, Evidence, HistoricalMatch, generate_fingerprint
from orchestrator.metrics import increment_applies, increment_vetos, increment_escalates
from orchestrator.historian import run_historian_loop

MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
POLL_INTERVAL_SEC = int(os.getenv("POLL_INTERVAL_SEC", "5"))

store = get_store()


def fetch_previous_outcome(fingerprint: str) -> tuple[bool, str | None, str | None]:
    """Queries StoreBackend for the latest history record of the given fingerprint."""
    try:
        return store.fetch_previous_outcome(fingerprint)
    except Exception:
        pass
    return False, None, None


def build_proof_contract(row: dict) -> dict:
    """Builds a ProofContract JSON/dict representation for the given database incident row."""
    # Build fingerprint inputs
    fingerprint_inputs = {
        "namespace": row["namespace"],
        "service_name": row["pod_name"].split("-")[0] if "-" in row["pod_name"] else row["pod_name"],
        "container_image": "app-container:latest",  # Default placeholder
        "error_type": "CrashLoopBackOff" if "limits" in row["proposed_action"] else "ProbeFailure"
    }
    
    fingerprint = generate_fingerprint(fingerprint_inputs)
    
    # Query history
    found, prev_id, prev_outcome = fetch_previous_outcome(fingerprint)
    
    # Build Hypothesis
    # We default confidence to 0.75, unless overridden by config/env
    confidence = float(os.getenv("DEFAULT_PROPOSAL_CONFIDENCE", "0.75"))
    
    contract_data = {
        "incident_fingerprint": fingerprint,
        "hypothesis": {
            "proposed_action": row["proposed_action"],
            "root_cause_analysis": f"Remediação automatizada proposta para {row['pod_name']}.",
            "confidence": confidence
        },
        "evidence": {
            "log_pattern": "Standard system alert logs.",
            "metrics_baseline": {"cpu": "avg", "mem": "avg"},
            "historical_match": {
                "found": found,
                "previous_incident_id": prev_id,
                "previous_outcome": prev_outcome
            }
        }
    }
    return contract_data


def process_pending_once() -> bool:
    """
    Fetches the oldest 'pending' incident, decides on remediation,
    and updates status or increments retry count with backoff.
    Returns True if an incident was processed, False if queue is empty.
    """
    try:
        row = store.get_oldest_pending_incident()
    except Exception as e:
        print(f"[Worker] Erro ao ler fila de incidentes: {e}")
        return False

    if not row:
        return False

    incident_id = row["incident_id"]
    manifest_path = row["manifest_path"]
    retry_count = row["retry_count"]

    try:
        # Build proof contract
        contract_dict = build_proof_contract(dict(row))
        
        # Apply gatekeeper decisions
        decision, reason = safe_kubectl_apply(manifest_path, contract_dict)
        print(f"[Worker] Incidente {incident_id} avaliado. Decisão: {decision} ({reason})")

        if decision == "APPLY":
            store.update_incident_status(incident_id, status='applied', ts_applied_now=True)
            increment_applies()
        elif decision == "VETO":
            store.update_incident_status(incident_id, status='needs_review', error_message=f"Gatekeeper VETO: {reason}")
            increment_vetos()
        else:  # ESCALATE
            store.update_incident_status(incident_id, status='needs_review', error_message=f"Gatekeeper ESCALATE: {reason}")
            increment_escalates()

    except Exception as e:
        # Increment retry count or transition to dead-letter state
        new_retry = retry_count + 1
        print(f"[Worker] Erro ao processar incidente {incident_id}: {e}. Tentativa {new_retry}/{MAX_RETRIES}")
        
        if new_retry >= MAX_RETRIES:
            store.update_incident_status(
                incident_id,
                status='failed',
                error_message=f"Excedeu limite de retries. Último erro: {str(e)}"
            )
        else:
            store.update_incident_status(
                incident_id,
                status='pending',
                error_message=str(e),
                retry_count=new_retry
            )
            
        # Exponential backoff sleep for retries
        time.sleep(2 ** new_retry)

    return True


def run_daemon():
    """Runs the main loop daemon for processing SRE incidents."""
    if os.getenv("ORCHESTRATOR_ENABLED", "true").lower() != "true":
        print("Orquestrador desabilitado via ORCHESTRATOR_ENABLED=false")
        sys.exit(0)

    print("Iniciando Paulo Lab SRE Orchestrator Worker...")
    
    # Initialize DB schemas on startup
    initialize_database()

    # Start the historian loop in a background thread
    historian_thread = threading.Thread(target=run_historian_loop, daemon=True)
    historian_thread.start()

    while True:
        # Check kill-switch
        if os.getenv("ORCHESTRATOR_ENABLED", "true").lower() != "true":
            print("[Worker] Worker pausado via kill-switch (ORCHESTRATOR_ENABLED=false).")
            time.sleep(POLL_INTERVAL_SEC)
            continue

        try:
            processed = process_pending_once()
            if not processed:
                time.sleep(POLL_INTERVAL_SEC)
        except Exception as e:
            print(f"[Worker] Erro crítico no loop: {e}", file=sys.stderr)
            time.sleep(POLL_INTERVAL_SEC)


if __name__ == "__main__":
    run_daemon()
