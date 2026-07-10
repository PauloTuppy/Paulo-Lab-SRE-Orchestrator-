import os
import sys
import time
import threading
import uuid
import json
import subprocess
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from orchestrator.sqlite_store import get_store, initialize_database
from orchestrator.gatekeeper import safe_kubectl_apply
from orchestrator.contracts import ProofContract, Hypothesis, Evidence, HistoricalMatch, generate_fingerprint
from orchestrator.metrics import increment_applies, increment_vetos, increment_escalates
from orchestrator.historian import run_historian_loop, get_pod_status, get_pod_logs

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


def is_playbook_already_applied(namespace: str, pod_name: str, playbook_id: str, parameters: dict) -> bool:
    """Checks the actual cluster state to see if the proposed playbook change is already present."""
    mode = os.getenv("EXECUTION_MODE", "offline").lower()
    if mode == "offline":
        return False
        
    workload = parameters.get("workload", pod_name)
    value = str(parameters.get("value", ""))
    
    cmd = ["kubectl", "get", "deployment", workload, "-n", namespace, "-o", "json"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if res.returncode != 0:
            return False
        doc = json.loads(res.stdout)
        
        containers = doc.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        if not containers:
            return False
            
        if "tweak_limits" in playbook_id:
            mem_limit = containers[0].get("resources", {}).get("limits", {}).get("memory", "")
            if mem_limit == value:
                return True
        elif "liveness" in playbook_id:
            probe = containers[0].get("livenessProbe", {})
            delay = probe.get("initialDelaySeconds", -1)
            if str(delay) == value:
                return True
        elif "rollback" in playbook_id:
            image = containers[0].get("image", "")
            if image == value:
                return True
    except Exception:
        pass
    return False


def build_proof_contract(row: dict) -> dict:
    """Builds a validated ProofContract JSON/dict representation for the given database incident row."""
    namespace = row["namespace"]
    pod_name = row["pod_name"]
    proposed_action = row["proposed_action"]
    
    # Gather actual pod status and logs for diagnostics
    pod_status = get_pod_status(namespace, pod_name)
    pod_logs = get_pod_logs(namespace, pod_name)
    
    container_image = "app-container:latest"
    error_type = "UnknownError"
    restart_count = 0
    
    if "status" in pod_status:
        statuses = pod_status.get("status", {}).get("containerStatuses", [])
        if statuses:
            container_image = statuses[0].get("image", container_image)
            restart_count = statuses[0].get("restartCount", 0)
            
    logs_lower = pod_logs.lower()
    if "oomkilled" in logs_lower or "oom" in logs_lower:
        error_type = "OOMKilled"
    elif "crashloopbackoff" in logs_lower or "crash" in logs_lower:
        error_type = "CrashLoopBackOff"
    elif "liveness" in logs_lower or "probe" in logs_lower:
        error_type = "LivenessProbeFailure"
        
    fingerprint_inputs = {
        "namespace": namespace,
        "service_name": pod_name.split("-")[0] if "-" in pod_name else pod_name,
        "container_image": container_image,
        "error_type": error_type
    }
    
    fingerprint = row.get("fingerprint") or generate_fingerprint(fingerprint_inputs)
    
    # Query history
    found, prev_id, prev_outcome = fetch_previous_outcome(fingerprint)
    
    # Calibrate confidence based on diagnostics and history
    base_confidence = 0.5
    if error_type != "UnknownError":
        base_confidence = 0.85
        
    if found:
        if prev_outcome == "resolved":
            base_confidence = min(1.0, base_confidence + 0.1)
        elif prev_outcome in {"reoccurred", "caused_side_effect"}:
            base_confidence = max(0.0, base_confidence - 0.25)
            
    # Load fallback default from env if specified
    env_default_conf = os.getenv("DEFAULT_PROPOSAL_CONFIDENCE")
    if env_default_conf is not None:
        try:
            base_confidence = float(env_default_conf)
        except ValueError:
            pass

    # Instantiate and validate Pydantic models (ProofContract)
    hypothesis = Hypothesis(
        proposed_action=proposed_action,
        root_cause_analysis=f"SRE Diagnostics: Identified error '{error_type}' with {restart_count} restarts on {pod_name}.",
        confidence=base_confidence
    )
    
    evidence = Evidence(
        log_pattern=f"Critical pattern: {error_type}" if error_type != "UnknownError" else "No critical patterns.",
        metrics_baseline={"cpu_usage_pct": 80 if error_type == "OOMKilled" else 40, "restart_count": restart_count},
        historical_match=HistoricalMatch(
            found=found,
            previous_incident_id=prev_id,
            previous_outcome=prev_outcome
        )
    )
    
    contract = ProofContract(
        incident_id=row["incident_id"],
        incident_fingerprint=fingerprint,
        hypothesis=hypothesis,
        evidence=evidence
    )
    
    return contract.model_dump()


def process_pending_once() -> bool:
    """
    Transactionally leases the oldest pending incident, validates it, and applies changes.
    """
    try:
        worker_id = os.getenv("HOSTNAME", "default-worker")
        row = store.claim_next_incident(worker_id=worker_id)
    except Exception as e:
        print(f"[Worker] Erro ao reivindicar incidente: {e}")
        return False

    if not row:
        return False

    incident_id = row["incident_id"]
    playbook_id = row["playbook_id"]
    retry_count = row["retry_count"]
    
    try:
        playbook_parameters = json.loads(row["playbook_parameters"]) if row["playbook_parameters"] else {}
    except Exception as e:
        store.update_incident_status(
            incident_id,
            status='failed',
            error_message=f"Erro de parsing de parâmetros do playbook: {e}"
        )
        return True

    # 1. At Least Once Check: Check if already applied
    try:
        already_applied = is_playbook_already_applied(
            row["namespace"], row["pod_name"], playbook_id, playbook_parameters
        )
        if already_applied:
            mode = os.getenv("EXECUTION_MODE", "offline").lower()
            status_target = 'dry_run_passed' if mode == 'staging' else 'applied'
            print(f"[Worker] Incidente {incident_id} já aplicado no cluster. Marcando como {status_target}.")
            store.update_incident_status(incident_id, status=status_target, ts_applied_now=True)
            return True
    except Exception as e:
        print(f"[Worker] Erro ao checar aplicação prévia: {e}")

    try:
        # 2. Build ProofContract using Pydantic
        contract_dict = build_proof_contract(dict(row))
        
        # 3. Apply playbook changes
        decision, reason = safe_kubectl_apply(playbook_id, playbook_parameters, contract_dict)
        print(f"[Worker] Incidente {incident_id} processado. Decisão: {decision} ({reason})")

        if decision == "APPLY":
            store.update_incident_status(incident_id, status='applied', ts_applied_now=True)
            increment_applies()
        elif decision == "dry_run_passed":
            store.update_incident_status(incident_id, status='dry_run_passed', ts_applied_now=True)
            increment_applies()
        elif decision == "VETO":
            store.update_incident_status(incident_id, status='needs_review', error_message=f"Gatekeeper VETO: {reason}")
            increment_vetos()
        else:  # ESCALATE
            store.update_incident_status(incident_id, status='needs_review', error_message=f"Gatekeeper ESCALATE: {reason}")
            increment_escalates()

    except Exception as e:
        err_str = str(e)
        # Classify retry: Timeout and connection errors are transient (retry). Schema and values are permanent (fail).
        is_transient = "timeout" in err_str.lower() or "connection" in err_str.lower() or "dial" in err_str.lower()
        
        if not is_transient:
            print(f"[Worker] Falha de validação irreversível ao processar {incident_id}: {e}")
            store.update_incident_status(
                incident_id,
                status='failed',
                error_message=f"Falha de validação/política: {err_str}"
            )
        else:
            new_retry = retry_count + 1
            print(f"[Worker] Falha transitória ao processar {incident_id}: {e}. Tentativa {new_retry}/{MAX_RETRIES}")
            
            if new_retry >= MAX_RETRIES:
                store.update_incident_status(
                    incident_id,
                    status='failed',
                    error_message=f"Excedeu retries. Último erro: {err_str}"
                )
            else:
                store.update_incident_status(
                    incident_id,
                    status='pending',
                    error_message=err_str,
                    retry_count=new_retry
                )
            # Exponential backoff sleep
            time.sleep(2 ** new_retry)

    return True


def run_daemon():
    """Runs the main loop SRE Worker daemon."""
    if os.getenv("ORCHESTRATOR_ENABLED", "true").lower() != "true":
        print("Orquestrador desabilitado via ORCHESTRATOR_ENABLED=false")
        sys.exit(0)

    print("Iniciando SRE Orchestrator Worker...")
    initialize_database()

    # Start the historian loop in a background thread
    historian_thread = threading.Thread(target=run_historian_loop, daemon=True)
    historian_thread.start()

    while True:
        if os.getenv("ORCHESTRATOR_ENABLED", "true").lower() != "true":
            print("[Worker] Worker pausado via kill-switch.")
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
