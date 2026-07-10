import json
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from orchestrator.sqlite_store import get_db

# Default confidence thresholds by action type
DEFAULT_THRESHOLDS = {
    "tweak_limits": 0.6,
    "liveness_probe_adjustment": 0.6,
    "rollback": 0.7,
    "code_fix": 0.8
}


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
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT COUNT(*) as cnt
            FROM incident_history
            WHERE fingerprint = ?
              AND action_type = ?
              AND outcome = 'reoccurred'
              AND datetime(created_at) > ?
            """,
            (fingerprint, action_type, since.isoformat(timespec="seconds"))
        )
        row = cursor.fetchone()
    return row["cnt"] > 0


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


def safe_kubectl_apply(manifest_path: str, contract: dict) -> tuple[str, str]:
    """
    Validates with decide_remediation, checks execution mode:
    - 'offline': Simulates apply checks locally.
    - 'staging': Runs kubectl apply --dry-run=server.
    - 'production': Runs dry-run and then applies manifest to cluster.
    """
    decision, reason = decide_remediation(contract)
    if decision != "APPLY":
        return decision, reason

    mode = os.getenv("EXECUTION_MODE", "offline").lower()

    if mode == "offline":
        # Simulate local dry-run checking file existence and base syntax
        path = Path(manifest_path)
        if not path.exists():
            return "VETO", f"Offline dry-run falhou: Arquivo de manifesto não encontrado no caminho '{manifest_path}'"
        
        # Verify file is not empty
        try:
            content = path.read_text(encoding="utf-8")
            if not content.strip():
                return "VETO", "Offline dry-run falhou: Manifesto vazio."
        except Exception as e:
            return "VETO", f"Offline dry-run falhou ao ler arquivo: {e}"

        return "APPLY", f"[OFFLINE SIMULATION] kubectl apply dry-run & apply bem-sucedidos para '{manifest_path}'"

    # For staging and production, check if manifest path exists
    if not Path(manifest_path).exists():
        return "VETO", f"Manifesto {manifest_path} não encontrado."

    # 1. Run dry-run server validation
    dry_run_cmd = ["kubectl", "apply", "-f", manifest_path, "--dry-run=server"]
    try:
        dry_run = subprocess.run(dry_run_cmd, capture_output=True, text=True, timeout=15)
        if dry_run.returncode != 0:
            return "VETO", f"kubectl dry-run falhou: {dry_run.stderr.strip()}"
    except Exception as e:
        return "VETO", f"Falha ao executar comando kubectl dry-run: {e}"

    # 2. In staging, dry-run is the final step
    if mode == "staging":
        return "APPLY", f"[STAGING DRY-RUN] kubectl apply dry-run bem-sucedido para '{manifest_path}'"

    # 3. Apply changes in production mode
    apply_cmd = ["kubectl", "apply", "-f", manifest_path]
    try:
        result = subprocess.run(apply_cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return "VETO", f"kubectl apply real falhou: {result.stderr.strip()}"
        return "APPLY", "kubectl apply bem-sucedido"
    except Exception as e:
        return "VETO", f"Falha ao executar comando kubectl apply real: {e}"
