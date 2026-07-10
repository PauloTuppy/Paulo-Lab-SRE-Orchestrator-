import json
import os
import re
import hashlib
import subprocess
import yaml
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
from orchestrator.sqlite_store import get_store

store = get_store()

# Default confidence thresholds by action type
DEFAULT_THRESHOLDS = {
    "tweak_limits": 0.6,
    "liveness_probe_adjustment": 0.6,
    "rollback": 0.7
}

# Allowlist of namespaces
ALLOWED_NAMESPACES = set(os.getenv("ALLOWED_NAMESPACES", "default,sre-system,app").split(","))


def get_confidence_threshold(action_type: str) -> float:
    """Returns the required confidence threshold for a given action type, configurable via environment."""
    env_var_name = f"THRESHOLD_{action_type.upper()}"
    val = os.getenv(env_var_name)
    if val is not None:
        try:
            return float(val)
        except ValueError:
            pass
    return DEFAULT_THRESHOLDS.get(action_type, 0.6)


def has_recent_failed_strategy(fingerprint: str, action_type: str, window_hours: int = 24) -> bool:
    """Queries history to check if the exact same strategy failed (outcome='reoccurred') in the last N hours."""
    since = datetime.utcnow() - timedelta(hours=window_hours)
    return store.has_recent_failed_strategy(fingerprint, action_type, since.isoformat(timespec="seconds"))


def decide_remediation(contract: dict) -> tuple[str, str]:
    """
    Decides whether to APPLY, VETO, or ESCALATE a remediation based on:
    1. Confidence thresholds (action-specific)
    2. Recent failed strategies in the same fingerprint class
    3. Previous outcome flags in the contract evidence
    """
    fingerprint = contract.get("incident_fingerprint")
    hypothesis = contract.get("hypothesis", {})
    proposed_action = hypothesis.get("proposed_action")
    confidence = float(hypothesis.get("confidence", 0.0))

    # 1. Check confidence threshold
    threshold = get_confidence_threshold(proposed_action)
    if confidence < threshold:
        return "ESCALATE", f"Confiança baixa ({confidence:.2f} < {threshold:.2f} requerida para '{proposed_action}')."

    # 2. Check recent failed strategy (last 24 hours)
    veto_window = int(os.getenv("VETO_WINDOW_HOURS", "24"))
    if has_recent_failed_strategy(fingerprint, proposed_action, veto_window):
        return "VETO", f"Estratégia '{proposed_action}' já falhou recentemente para este fingerprint."

    # 3. Check historical match outcome in proof contract evidence
    hist = contract.get("evidence", {}).get("historical_match", {})
    if hist.get("found") and hist.get("previous_outcome") in {"reoccurred", "caused_side_effect"}:
        return "VETO", f"Memória indica histórico ruim ({hist.get('previous_outcome')}) para estratégia similar."

    return "APPLY", "Sem histórico negativo forte e confiança aceitável."


def is_parameter_safe(val: str) -> bool:
    """Validates parameter values to prevent YAML injection or path traversal."""
    return bool(re.match(r"^[a-zA-Z0-9\.\-_:]+$", str(val)))


def calculate_normalized_hash(content: str) -> str:
    """Computes a stable hash after normalizing line endings and trimming space."""
    normalized = "\n".join(line.strip() for line in content.splitlines() if line.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def render_and_validate_playbook(playbook_id: str, parameters: dict) -> Tuple[str, str]:
    """
    Resolves, validates, hashes, and renders a playbook from the secure catalog.
    """
    playbooks_dir = Path("kubernetes/playbooks").resolve()
    catalog_path = playbooks_dir / "catalog.json"
    
    if not catalog_path.exists():
        return "", "Playbooks catalog.json not found."
        
    try:
        with open(catalog_path, "r", encoding="utf-8") as f:
            catalog = json.load(f)
    except Exception as e:
        return "", f"Failed to load catalog.json: {e}"
        
    if playbook_id not in catalog:
        return "", f"Playbook ID '{playbook_id}' is not in the secure catalog."
        
    playbook_info = catalog[playbook_id]
    playbook_file = playbooks_dir / playbook_info["file"]
    
    # Resolve path, reject symlinks, verify regular file
    try:
        resolved_path = playbook_file.resolve(strict=True)
        if playbook_file.is_symlink():
            return "", "Playbook file is a symbolic link (rejected)."
        if not resolved_path.is_file():
            return "", "Playbook path is not a regular file."
    except Exception as e:
        return "", f"Failed to resolve playbook path: {e}"
        
    # Verify hash
    try:
        content = resolved_path.read_text(encoding="utf-8")
        current_hash = calculate_normalized_hash(content)
        if current_hash != playbook_info["hash"]:
            return "", "Playbook hash mismatch! Potential tampering detected."
    except Exception as e:
        return "", f"Failed to read/hash playbook file: {e}"
        
    # Populate default parameters if missing
    full_params = dict(parameters)
    if "workload" not in full_params:
        pod_name = full_params.get("pod_name", "app-pod")
        # Strip replica suffix if present (e.g. service-a-12345 -> service-a)
        full_params["workload"] = pod_name.rsplit("-", 1)[0] if "-" in pod_name else pod_name
    if "namespace" not in full_params:
        full_params["namespace"] = "default"
    if "value" not in full_params:
        if "limits" in playbook_id:
            full_params["value"] = "2Gi"
        elif "liveness" in playbook_id:
            full_params["value"] = "30"
        elif "rollback" in playbook_id:
            full_params["value"] = "app-container:latest"
        else:
            full_params["value"] = "default"

    # Validate parameters
    for k, v in full_params.items():
        if not is_parameter_safe(v):
            return "", f"Parameter '{k}' has unsafe value: {v}"
            
    # Simple template rendering
    rendered = content
    for k, v in full_params.items():
        rendered = rendered.replace(f"{{{{ {k} }}}}", str(v))
        
    # Parse YAML and validate structure
    try:
        docs = list(yaml.safe_load_all(rendered))
    except Exception as e:
        return "", f"Rendered playbook is not valid YAML: {e}"
        
    for doc in docs:
        if not doc:
            continue
        kind = doc.get("kind", "")
        metadata = doc.get("metadata", {})
        namespace = metadata.get("namespace", "default")
        
        if kind in {"Secret", "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "StorageClass"} or kind.endswith("CRD"):
            return "", f"Resource kind '{kind}' is forbidden."
            
        if namespace not in ALLOWED_NAMESPACES:
            return "", f"Namespace '{namespace}' is not in the allowlist: {ALLOWED_NAMESPACES}"
            
    return rendered, ""


def safe_kubectl_apply(playbook_id_or_path: str, parameters: Any = None, contract: Any = None) -> Tuple[str, str]:
    """
    Validates execution mode and applies playbook using playbooks catalog.
    """
    if contract is None:
        if isinstance(parameters, dict) and ("hypothesis" in parameters or "incident_fingerprint" in parameters):
            contract = parameters
            parameters = {}
        else:
            contract = {}
    if parameters is None:
        parameters = {}

    mode = os.getenv("EXECUTION_MODE", "offline").lower()
    if mode not in {"offline", "staging", "production"}:
        return "VETO", f"Modo de execução '{mode}' não seguro ou desconhecido. Fail-closed."

    # Production safety checks:
    if mode == "production":
        apply_enabled = os.getenv("PRODUCTION_APPLY_ENABLED", "false").lower() == "true"
        if not apply_enabled:
            return "VETO", "Produção ativa mas PRODUCTION_APPLY_ENABLED=false. Aplicação bloqueada."

    # Decide remediation
    decision, reason = decide_remediation(contract)
    if decision != "APPLY":
        return decision, reason

    # Check if a direct file path is passed (supported in offline/staging testing only)
    is_path = (
        playbook_id_or_path.endswith(".yaml") or 
        playbook_id_or_path.endswith(".yml") or 
        "/" in playbook_id_or_path or 
        "\\" in playbook_id_or_path
    )
    
    if is_path:
        if mode == "production":
            return "VETO", "Caminhos de arquivo diretos não são permitidos em modo de produção."
            
        manifest_path = playbook_id_or_path
        path = Path(manifest_path)
        if not path.exists():
            return "VETO", f"Manifesto {manifest_path} não encontrado."
        if path.is_symlink():
            return "VETO", "Links simbólicos são rejeitados."
            
        try:
            content = path.read_text(encoding="utf-8")
            if not content.strip():
                return "VETO", "Manifesto vazio."
        except Exception as e:
            return "VETO", f"Erro ao ler manifesto: {e}"
            
        if mode == "staging":
            dry_run_cmd = ["kubectl", "apply", "-f", manifest_path, "--dry-run=server"]
            try:
                dry_run = subprocess.run(dry_run_cmd, capture_output=True, text=True, timeout=15)
                if dry_run.returncode != 0:
                    return "VETO", f"kubectl dry-run falhou: {dry_run.stderr.strip()}"
                return "dry_run_passed", f"[STAGING DRY-RUN] kubectl apply dry-run bem-sucedido para '{manifest_path}'"
            except Exception as e:
                return "VETO", f"Falha ao executar comando kubectl dry-run: {e}"
                
        return "APPLY", f"[OFFLINE SIMULATION] kubectl apply dry-run & apply bem-sucedidos para '{manifest_path}'"

    else:
        # Resolve playbook ID
        rendered_yaml, err = render_and_validate_playbook(playbook_id_or_path, parameters)
        if err:
            return "VETO", f"Falha de validação do playbook: {err}"
            
        import tempfile
        temp_dir = tempfile.gettempdir()
        temp_file = Path(temp_dir) / f"rendered_{playbook_id_or_path}_{contract['incident_id']}.yaml"
        try:
            temp_file.write_text(rendered_yaml, encoding="utf-8")
        except Exception as e:
            return "VETO", f"Falha ao salvar manifesto temporário: {e}"
            
        manifest_path = str(temp_file)
        
        if mode == "staging":
            dry_run_cmd = ["kubectl", "apply", "-f", manifest_path, "--dry-run=server"]
            try:
                dry_run = subprocess.run(dry_run_cmd, capture_output=True, text=True, timeout=15)
                try: temp_file.unlink() 
                except: pass
                if dry_run.returncode != 0:
                    return "VETO", f"kubectl dry-run falhou: {dry_run.stderr.strip()}"
                return "dry_run_passed", f"[STAGING DRY-RUN] Playbook '{playbook_id_or_path}' validado com sucesso."
            except Exception as e:
                try: temp_file.unlink()
                except: pass
                return "VETO", f"Falha ao executar comando dry-run: {e}"
                
        if mode == "offline":
            try: temp_file.unlink()
            except: pass
            return "APPLY", f"[OFFLINE SIMULATION] Playbook '{playbook_id_or_path}' renderizado e validado."

        # Production real apply
        apply_cmd = ["kubectl", "apply", "-f", manifest_path]
        try:
            result = subprocess.run(apply_cmd, capture_output=True, text=True, timeout=15)
            try: temp_file.unlink()
            except: pass
            if result.returncode != 0:
                return "VETO", f"kubectl apply real falhou: {result.stderr.strip()}"
            return "APPLY", f"Playbook '{playbook_id_or_path}' aplicado com sucesso no cluster."
        except Exception as e:
            try: temp_file.unlink()
            except: pass
            return "VETO", f"Falha ao executar apply real: {e}"
