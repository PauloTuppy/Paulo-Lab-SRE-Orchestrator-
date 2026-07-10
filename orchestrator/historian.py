import json
import os
import subprocess
import time
import requests
import re
from datetime import datetime
from pydantic import ValidationError

from orchestrator.sqlite_store import get_store
from orchestrator.contracts import ProofContract, generate_fingerprint, HistorianResponse
from orchestrator.metrics import increment_outcome

# System prompt version 2
HISTORIAN_SYSTEM_PROMPT = """
Você é o historian-agent-v2, um SRE de Governança de IA rodando sobre um modelo SubQ de longo contexto,
orquestrado por um sistema multi-agente RecursiveMAS em espaço latente.

Sua função é analisar o resultado de correções automáticas no cluster.

Entrada:
- O Contrato de Prova que gerou a ação.
- Trechos de logs e/ou métricas pós-aplicação (t ≈ 15 min).
- Estado atual do Pod/Serviço (incluindo restartCount e condições).

Definições:
- resolved: O incidente cessou e as métricas estão estáveis.
- reoccurred: O pod voltou a entrar em CrashLoopBackOff ou apresentou o mesmo log de erro em menos de 15 minutos.
- caused_side_effect: O pod parou de reiniciar, mas o nó sofreu memory_pressure OU outros serviços apresentaram latência/erros associados.

Regra de Ouro:
Não seja otimista. Se houver qualquer indício de que o problema foi apenas mascarado e não resolvido, classifique como reoccurred.

Saída:
Retorne APENAS um JSON compacto:
{"outcome": "...", "observacao": "..."}
""".strip()

store = get_store()

HISTORIAN_PROMPT_REF = "historian-agent-v2:v1"


def get_historian_prompt() -> str:
    """Gets the historian system prompt. Attempts to retrieve it from Weave first if enabled."""
    if os.getenv("WEAVE_ENABLED", "true").lower() == "true":
        try:
            import weave
            ref = weave.ref(HISTORIAN_PROMPT_REF).get()
            if hasattr(ref, "format"):
                return ref.format()
            elif isinstance(ref, str):
                return ref
        except Exception as e:
            try:
                import weave
                ref = weave.ref("historian-agent-v2").get()
                if hasattr(ref, "format"):
                    return ref.format()
                elif isinstance(ref, str):
                    return ref
            except Exception:
                pass
            print(f"[Weave] Não foi possível carregar o prompt '{HISTORIAN_PROMPT_REF}' via Weave: {e}. Usando fallback local.")
    return HISTORIAN_SYSTEM_PROMPT


def get_pod_status(namespace: str, pod_name: str) -> dict:
    """Gathers Kubernetes pod status in JSON format. Mocks in offline mode."""
    mode = os.getenv("EXECUTION_MODE", "offline").lower()
    if mode == "offline":
        # Simulate a running, stable pod by default
        return {
            "metadata": {"name": pod_name, "namespace": namespace},
            "status": {
                "phase": "Running",
                "containerStatuses": [{"restartCount": 0, "ready": True}]
            }
        }

    cmd = ["kubectl", "get", "pod", pod_name, "-n", namespace, "-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            raise RuntimeError(f"kubectl failed: {result.stderr.strip()}")
        return json.loads(result.stdout)
    except Exception as e:
        # Fallback placeholder if pod cannot be fetched but command executed
        return {"error": f"Failed to retrieve pod status: {str(e)}"}


def get_pod_logs(namespace: str, pod_name: str) -> str:
    """Gathers post-apply pod logs. Mocks in offline mode."""
    mode = os.getenv("EXECUTION_MODE", "offline").lower()
    if mode == "offline":
        return "Logs: Container started, health checks passed. No OOM events."

    cmd = ["kubectl", "logs", pod_name, "-n", namespace, "--tail=50"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return f"Error retrieving logs: {result.stderr.strip()}"
        return result.stdout
    except Exception as e:
        return f"Error executing kubectl logs: {str(e)}"


def is_critical_event_present(logs_lower: str) -> bool:
    """
    Checks if critical SRE events (oomkilled, crash, crashloopbackoff, probe failed)
    are present in the logs, filtering out negated instances (e.g. 'no oomkilled',
    'without crash', 'zero probe failed', 'absent oomkilled').
    """
    critical_patterns = ["oomkilled", "crashloopbackoff", "probe failed", "crash"]
    negation_patterns = [
        r"\bno\b",
        r"\bwithout\b",
        r"\bzero\b",
        r"\babsent\b",
        r"\bnot\b",
        r"\bfree of\b",
        r"\bnone\b"
    ]
    
    for pattern in critical_patterns:
        pattern_regex = re.compile(re.escape(pattern))
        for match in pattern_regex.finditer(logs_lower):
            start_idx = match.start()
            # Inspect the preceding window (up to 30 characters before)
            window_start = max(0, start_idx - 30)
            preceding_window = logs_lower[window_start:start_idx]
            
            # Split by common sentence/line boundaries to keep the negation search local
            parts = re.split(r'[\.\;\n\r]', preceding_window)
            clause_preceding = parts[-1]
            
            is_negated = False
            for neg in negation_patterns:
                if re.search(neg, clause_preceding):
                    is_negated = True
                    break
            
            if not is_negated:
                return True
                
    return False


def call_local_classifier(contract: dict, pod_status: dict, post_logs: str) -> dict:
    """Deterministic local classifier used as final fallback or offline mode."""
    # Check restart count
    restart_count = 0
    phase = "Running"
    try:
        if "status" in pod_status:
            status_part = pod_status.get("status", {})
            phase = status_part.get("phase", "Running")
            container_statuses = status_part.get("containerStatuses", [])
            if container_statuses:
                restart_count = container_statuses[0].get("restartCount", 0)
        else:
            phase = pod_status.get("phase", "Running")
            restart_count = pod_status.get("restartCount", 0)
    except Exception:
        pass

    logs_lower = post_logs.lower()
    
    # Check historical match in contract for recent reoccurred outcome (repeated pattern)
    historical_match = contract.get("evidence", {}).get("historical_match", {}) if contract else {}
    has_repeated_pattern = (
        historical_match.get("found") == True and 
        historical_match.get("previous_outcome") == "reoccurred"
    )
    
    # Anti-optimism checks
    if phase != "Running" or restart_count > 0 or is_critical_event_present(logs_lower) or has_repeated_pattern:
        reason = f"[Local Rule] Pod reiniciou {restart_count} vezes, apresentou erros nos logs ou possui padrão repetido no histórico."
        return {
            "outcome": "reoccurred",
            "observacao": reason
        }
    
    # Side effects checks (including PDB violation and DB overload/exhaustion)
    if (
        "memory_pressure" in logs_lower or 
        "pressure" in logs_lower or 
        "latency" in logs_lower or
        "pdb" in logs_lower or 
        "poddisruptionbudget" in logs_lower or
        "overload" in logs_lower or
        "exhausted" in logs_lower
    ):
        return {
            "outcome": "caused_side_effect",
            "observacao": "[Local Rule] Pod está de pé, mas há indícios de side effects (pressure, latency, pdb, poddisruptionbudget, overload ou exhausted)."
        }

    return {
        "outcome": "resolved",
        "observacao": "[Local Rule] Pod rodando sem reinícios ou erros aparentes nos logs."
    }

def call_gemini_historian(user_payload: str) -> dict:
    """Calls Gemini API using user-provided API key."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("Chave de API do Gemini não configurada.")
        
    import google.generativeai as genai
    genai.configure(api_key=api_key)
    # Use gemini-1.5-flash as the fallback model
    model = genai.GenerativeModel(
        model_name="gemini-1.5-flash",
        system_instruction=get_historian_prompt()
    )
    
    response = model.generate_content(
        user_payload,
        generation_config={"response_mime_type": "application/json", "temperature": 0.0}
    )
    
    text = response.text.strip()
    return json.loads(text)


def call_internal_endpoint(user_payload: str) -> dict:
    """Calls internal SubQ + RecursiveMAS endpoint if configured."""
    endpoint = os.getenv("HISTORIAN_ENDPOINT")
    if not endpoint:
        raise ValueError("HISTORIAN_ENDPOINT não configurado.")

    resp = requests.post(
        endpoint,
        json={
            "system_prompt": get_historian_prompt(),
            "user_payload": user_payload,
            "temperature": 0.0,
        },
        timeout=30,
    )
    resp.raise_for_status()
    content = resp.json()["content"]
    return json.loads(content)


def classify_incident(contract: dict, pod_status: dict, post_logs: str) -> tuple[dict, str]:
    """
    Executes the deterministic LLM/local fallback chain:
    Internal Endpoint -> Gemini API -> Local Rule-based Classifier.
    Returns (outcome_dict, model_used_name).
    """
    user_payload = json.dumps({
        "proof_contract": contract,
        "pod_status": pod_status,
        "post_apply_logs": post_logs
    }, ensure_ascii=False)

    # If running in offline mode, skip remote LLM calls directly to ensure offline compliance
    mode = os.getenv("EXECUTION_MODE", "offline").lower()
    if mode == "offline":
        print("[Historian] Modo offline ativo. Usando classificador de regras locais.")
        return call_local_classifier(contract, pod_status, post_logs), "local_rules"

    # Step 1: Internal Endpoint
    try:
        outcome = call_internal_endpoint(user_payload)
        try:
            HistorianResponse(**outcome)
            return outcome, "internal_endpoint"
        except Exception as ve:
            print(f"[Historian] Schema inválido do Endpoint Interno: {ve}")
            increment_outcome("invalid")
            raise ve
    except Exception as e:
        print(f"[Historian] Erro ao chamar Endpoint Interno: {e}. Tentando Gemini fallback...")

    # Step 2: Gemini API Fallback
    try:
        outcome = call_gemini_historian(user_payload)
        try:
            HistorianResponse(**outcome)
            return outcome, "gemini-1.5-flash"
        except Exception as ve:
            print(f"[Historian] Schema inválido do Gemini API: {ve}")
            increment_outcome("invalid")
            raise ve
    except Exception as e:
        print(f"[Historian] Erro ao chamar Gemini API: {e}. Tentando Classificador Local...")

    # Step 3: Local Classifier Fallback
    outcome = call_local_classifier(contract, pod_status, post_logs)
    return outcome, "local_rules"


def process_applied_incidents_once() -> int:
    """
    Queries applied incidents that are older than evaluation delay window.
    Applies the fallback classifier and writes outcome back to incident_history.
    """
    # Delay window (default 15 minutes = 900 seconds)
    delay_sec = int(os.getenv("HISTORIAN_DELAY_SEC", "900"))
    
    try:
        rows = store.fetch_applied_incidents(delay_sec)
    except Exception as e:
        print(f"[Historian] Erro ao buscar incidentes aplicados: {e}")
        return 0

    processed_count = 0
    max_retries = int(os.getenv("MAX_RETRIES", "3"))

    for row in rows:
        incident_id = row["incident_id"]
        namespace = row["namespace"]
        pod_name = row["pod_name"]
        ts_applied = row["ts_applied"]
        retry_count = row["retry_count"]

        try:
            print(f"[Historian] Classificando incidente {incident_id}...")
            
            # Gathers telemetry
            pod_status = get_pod_status(namespace, pod_name)
            post_logs = get_pod_logs(namespace, pod_name)
            
            # Re-generate ProofContract matching the applied action
            from orchestrator.worker import build_proof_contract
            contract_dict = build_proof_contract(dict(row))
            
            # Run classifier chain
            classification, model_name = classify_incident(contract_dict, pod_status, post_logs)
            
            outcome = classification.get("outcome", "reoccurred")
            observacao = classification.get("observacao", "")

            # Write to history and mark pending incident as classified atomically
            store.classify_and_record_incident(
                incident_id=incident_id,
                fingerprint=contract_dict["incident_fingerprint"],
                action_type=row["proposed_action"],
                outcome=outcome,
                proof_contract_json=json.dumps(contract_dict),
                decision_reason=observacao,
                ts_applied=ts_applied,
                historian_model=model_name
            )
            
            # Increment metrics counters
            increment_outcome(outcome)

            print(f"[Historian] Incidente {incident_id} classificado como: {outcome} via {model_name}")
            processed_count += 1

        except Exception as e:
            # Handle classification retries
            new_retry = retry_count + 1
            print(f"[Historian] Erro ao classificar incidente {incident_id}: {e}. Tentativa {new_retry}/{max_retries}")
            
            if new_retry >= max_retries:
                store.update_incident_status(
                    incident_id,
                    status='failed',
                    error_message=f"Historian falhou: Excedeu limite de retries. Último erro: {str(e)}"
                )
            else:
                store.update_incident_status(
                    incident_id,
                    status='applied',
                    error_message=str(e),
                    retry_count=new_retry
                )
            
            # exponential backoff sleep
            time.sleep(2 ** new_retry)

    return processed_count


def run_historian_loop():
    """Run SRE Historian background evaluator loop."""
    print("Iniciando Paulo Lab SRE Historian loop...")
    poll_interval = int(os.getenv("HISTORIAN_POLL_INTERVAL_SEC", "10"))
    
    while True:
        # Check kill-switch
        if os.getenv("ORCHESTRATOR_ENABLED", "true").lower() != "true":
            print("[Historian] Historian pausado via kill-switch (ORCHESTRATOR_ENABLED=false).")
            time.sleep(poll_interval)
            continue

        try:
            process_applied_incidents_once()
        except Exception as e:
            print(f"[Historian] Erro crítico no loop do Historiador: {e}")
        time.sleep(poll_interval)


if __name__ == "__main__":
    run_historian_loop()
