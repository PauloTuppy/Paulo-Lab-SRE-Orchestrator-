# orchestrator/wandb_eval.py
# Paulo Lab – SRE Orchestrator | Weave Eval com traces reais
# Executa: python -m orchestrator.wandb_eval
# Pré-requisitos:
#   WANDB_API_KEY       → chave W&B (export ou .env)
#   OPENAI_API_KEY      → ou configure base_url para OpenRouter/Gemini
#   WEAVE_PARALLELISM=1 → recomendado para debug inicial (evita race conditions no SQLite)
# ─────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

import weave
from weave import Dataset, Evaluation

# ──────────────────────────────────────────────────────────────────────────
# CONFIGURAÇÃO — ajuste aqui se mudar de provider
# ──────────────────────────────────────────────────────────────────────────
ENTITY  = "paulotuppyjatoba-tuppyia"
PROJECT = "paulo-lab-sre-orchestrator"

# Modelo usado na avaliação — troque por openrouter/..., google/gemini-*, etc.
LLM_MODEL     = os.getenv("EVAL_LLM_MODEL", "gpt-4o-mini")
LLM_BASE_URL  = os.getenv("EVAL_LLM_BASE_URL", None)   # None = OpenAI padrão
LLM_API_KEY   = os.getenv("OPENAI_API_KEY", "")

# Ref do prompt versionado no Weave (publicado na sessão anterior)
HISTORIAN_PROMPT_REF = os.getenv(
    "HISTORIAN_PROMPT_REF",
    "historian-agent-v2:v1",
)

# ──────────────────────────────────────────────────────────────────────────
# INICIALIZAÇÃO WEAVE — real, sem fallback
# ──────────────────────────────────────────────────────────────────────────
# Weave é inicializado dinamicamente no runner para evitar chamadas de rede no import.


# ──────────────────────────────────────────────────────────────────────────
# CARREGAMENTO DO PROMPT VERSIONADO
# ──────────────────────────────────────────────────────────────────────────
def get_historian_prompt() -> str:
    """
    Resolve o prompt via weave.ref() dinâmico.
    Lança RuntimeError se a ref não existir — sem fallback silencioso,
    para garantir que nunca rodemos com prompt desconhecido em produção.
    Se não for encontrado, tenta carregar 'latest' ou publica o prompt local de historian.py.
    """
    try:
        prompt_obj = weave.ref(HISTORIAN_PROMPT_REF).get()
        return _parse_prompt_obj(prompt_obj, HISTORIAN_PROMPT_REF)
    except Exception as e1:
        print(f"[weave] '{HISTORIAN_PROMPT_REF}' não encontrado. Tentando 'historian-agent-v2:latest'...")
        try:
            prompt_obj = weave.ref("historian-agent-v2:latest").get()
            return _parse_prompt_obj(prompt_obj, "historian-agent-v2:latest")
        except Exception as e2:
            print(f"[weave] Prompt não encontrado no Weave. Publicando prompt local...")
            try:
                from orchestrator.historian import HISTORIAN_SYSTEM_PROMPT as local_prompt
                weave.publish(local_prompt, name="historian-agent-v2")
                print(f"[weave] Prompt local publicado com sucesso sob o nome 'historian-agent-v2'.")
                # Carrega o recém-publicado
                prompt_obj = weave.ref("historian-agent-v2:latest").get()
                return _parse_prompt_obj(prompt_obj, "historian-agent-v2:latest")
            except Exception as exc:
                raise RuntimeError(
                    f"[FATAL] Não foi possível carregar ou publicar o prompt no Weave.\n"
                    f"Erro original: {exc}"
                ) from exc


def _parse_prompt_obj(prompt_obj: Any, ref_name: str) -> str:
    if isinstance(prompt_obj, dict):
        content = prompt_obj.get("system") or prompt_obj.get("content") or prompt_obj.get("prompt")
    elif hasattr(prompt_obj, "system_prompt"):
        content = prompt_obj.system_prompt
    elif isinstance(prompt_obj, str):
        content = prompt_obj
    else:
        content = str(prompt_obj)

    if not content:
        raise ValueError(f"Prompt vazio para ref '{ref_name}'")

    print(f"[weave] Prompt carregado com sucesso da ref: {ref_name}")
    return content


HISTORIAN_SYSTEM_PROMPT: str | None = None


# ──────────────────────────────────────────────────────────────────────────
# DATASET SINTÉTICO — 5 exemplos cobrindo as 3 classes + edge cases
# ──────────────────────────────────────────────────────────────────────────
SYNTHETIC_ROWS: list[dict] = [
    # ── resolved verdadeiro ───────────────────────────────────────────────
    {
        "incident_id": "inc-001",
        "proof_contract": {
            "incident_fingerprint": "oomkilled:svc-a:v1",
            "hypothesis": {
                "proposed_action":     "tweak_limits",
                "root_cause_analysis": "Container memory limit too low",
                "confidence": 0.78,
            },
        },
        "pod_status":      {"phase": "Running", "restartCount": 0},
        "post_apply_logs": "No OOMKilled events in last 15 minutes. Memory usage stable at 68%.",
        "expected_outcome": "resolved",
    },
    # ── reoccurred mascarado como aparente sucesso ────────────────────────
    {
        "incident_id": "inc-002",
        "proof_contract": {
            "incident_fingerprint": "oomkilled:svc-b:v2",
            "hypothesis": {
                "proposed_action":     "tweak_limits",
                "root_cause_analysis": "Suspected memory exhaustion",
                "confidence": 0.82,
            },
        },
        "pod_status":      {"phase": "Running", "restartCount": 3},
        "post_apply_logs": "OOMKilled repeated after 7 minutes. Same fingerprint redetected.",
        "expected_outcome": "reoccurred",
    },
    # ── caused_side_effect (pressão de memória no nó vizinho) ─────────────
    {
        "incident_id": "inc-003",
        "proof_contract": {
            "incident_fingerprint": "probefail:svc-c:v9",
            "hypothesis": {
                "proposed_action":     "liveness_probe_adjustment",
                "root_cause_analysis": "Probe too aggressive",
                "confidence": 0.69,
            },
        },
        "pod_status":      {"phase": "Running", "restartCount": 0},
        "post_apply_logs": "Target pod healthy. Node memory_pressure=true. Sibling svc-d p99 latency +340ms.",
        "expected_outcome": "caused_side_effect",
    },
    # ── reoccurred via historical_match (v2 regression) ──────────────────
    {
        "incident_id": "inc-004",
        "proof_contract": {
            "incident_fingerprint": "crashloop:svc-e:v3",
            "hypothesis": {
                "proposed_action":     "rollback_deployment",
                "root_cause_analysis": "Regression in v3 — historical_match: same fingerprint failed 3x",
                "confidence": 0.77,
            },
        },
        "pod_status":      {"phase": "Running", "restartCount": 1},
        "post_apply_logs": "Rollback applied. Pod stable for 3 min. Same crashloop pattern redetected at minute 4.",
        "expected_outcome": "reoccurred",
    },
    # ── caused_side_effect via PDB violation (v2 regression) ─────────────
    {
        "incident_id": "inc-005",
        "proof_contract": {
            "incident_fingerprint": "probefail:svc-f:v4",
            "hypothesis": {
                "proposed_action":     "liveness_probe_adjustment",
                "root_cause_analysis": "Probe misconfigured after v4 deploy",
                "confidence": 0.71,
            },
        },
        "pod_status":      {"phase": "Running", "restartCount": 0},
        "post_apply_logs": (
            "Target pod recovered. PodDisruptionBudget violated: 2 of 3 replicas unavailable. "
            "svc-g database connection pool exhausted. Error rate +18%."
        ),
        "expected_outcome": "caused_side_effect",
    },
    # ── falso negativo de side effect (adversarial) ──────────────────────
    {
        "incident_id": "inc-006",
        "proof_contract": {
            "incident_fingerprint": "latency:svc-g:v5",
            "hypothesis": {
                "proposed_action":     "tweak_limits",
                "root_cause_analysis": "Resource limits update to stabilize container",
                "confidence": 0.85,
            },
        },
        "pod_status":      {"phase": "Running", "restartCount": 0},
        "post_apply_logs": (
            "Pod limits updated successfully. Svc-g is healthy and stable. "
            "Sibling service svc-h reporting HTTP 504 Gateway Timeout and p99 latency spiked to 2.4s."
        ),
        "expected_outcome": "caused_side_effect",
    },
    # ── reocorrência tardia >30min (adversarial) ──────────────────────────
    {
        "incident_id": "inc-007",
        "proof_contract": {
            "incident_fingerprint": "crashloop:svc-i:v6",
            "hypothesis": {
                "proposed_action":     "rollback_deployment",
                "root_cause_analysis": "Regression in latest deploy, rollback proposed",
                "confidence": 0.90,
            },
        },
        "pod_status":      {"phase": "Running", "restartCount": 2},
        "post_apply_logs": (
            "Rollback complete. Service stable for 35 minutes. "
            "Unexpected panic occurred at minute 37: connection pool reset, entering CrashLoopBackOff."
        ),
        "expected_outcome": "reoccurred",
    },
    # ── cascata multi-alerta (adversarial) ────────────────────────────────
    {
        "incident_id": "inc-008",
        "proof_contract": {
            "incident_fingerprint": "oomkilled:svc-j:v7",
            "hypothesis": {
                "proposed_action":     "tweak_limits",
                "root_cause_analysis": "Overlapping node limits and db starvation",
                "confidence": 0.73,
            },
        },
        "pod_status":      {"phase": "Running", "restartCount": 1},
        "post_apply_logs": (
            "Alert: Node cpu_utilization=98%, database overload, pod restarted 1 time after memory pressure, "
            "latency on all HTTP endpoints > 5000ms."
        ),
        "expected_outcome": "reoccurred",
    },
]

SYNTHETIC_INCIDENTS = SYNTHETIC_ROWS


def publish_dataset() -> Dataset:
    """Publica o dataset como artefato versionado no Weave e retorna o objeto."""
    dataset = Dataset(
        name="historian-synthetic-v1",
        rows=SYNTHETIC_ROWS,
    )
    weave.publish(dataset)
    print(f"[weave] Dataset publicado: historian-synthetic-v1 ({len(SYNTHETIC_ROWS)} exemplos)")
    return dataset


# ──────────────────────────────────────────────────────────────────────────
# CLIENTE LLM — compatível com OpenAI SDK >= 1.0 e OpenRouter e Gemini Nativo
# ──────────────────────────────────────────────────────────────────────────
IS_GEMINI_NATIVE = (
    LLM_API_KEY.startswith("AIzaSy") or 
    (LLM_BASE_URL and "googleapis.com" in LLM_BASE_URL)
)

def _build_llm_client():
    if IS_GEMINI_NATIVE:
        import google.generativeai as genai
        genai.configure(api_key=LLM_API_KEY)
        return genai
    else:
        from openai import OpenAI
        kwargs: dict[str, Any] = {"api_key": LLM_API_KEY}
        if LLM_BASE_URL:
            kwargs["base_url"] = LLM_BASE_URL
        return OpenAI(**kwargs)


_llm_client = _build_llm_client()


# ──────────────────────────────────────────────────────────────────────────
# FUNÇÃO DE CHAMADA AO LLM — decorada com @weave.op para gerar spans
# ──────────────────────────────────────────────────────────────────────────
@weave.op(name="call_llm_historian")
def call_llm_historian(system_prompt: str, payload: str) -> dict:
    """
    Chama o LLM Historiador e retorna o dict parseado.
    O @weave.op cria um Span individual para cada chamada,
    capturando input, output, latência e tokens usados.
    """
    t0 = time.time()
    
    if IS_GEMINI_NATIVE:
        # Use native Gemini SDK
        model = _llm_client.GenerativeModel(
            model_name=LLM_MODEL,
            system_instruction=system_prompt
        )
        response = model.generate_content(
            payload,
            generation_config={"response_mime_type": "application/json", "temperature": 0.0}
        )
        latency_ms = int((time.time() - t0) * 1000)
        raw = response.text.strip()
        
        prompt_tokens = 0
        completion_tokens = 0
        try:
            if hasattr(response, "usage_metadata") and response.usage_metadata:
                prompt_tokens = response.usage_metadata.prompt_token_count
                completion_tokens = response.usage_metadata.candidates_token_count
        except Exception:
            pass
            
    else:
        # Use OpenAI SDK
        response = _llm_client.chat.completions.create(
            model=LLM_MODEL,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": payload},
            ],
            temperature=0.0,
        )
        latency_ms = int((time.time() - t0) * 1000)
        raw = response.choices[0].message.content or "{}"
        
        prompt_tokens = response.usage.prompt_tokens if response.usage else 0
        completion_tokens = response.usage.completion_tokens if response.usage else 0

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        result = {"outcome": "invalid", "observacao": f"JSON parse error: {raw[:120]}", "confidence": 0.0}

    # Injeta metadados de latência e uso de tokens na saída para rastreio no Weave
    result["_meta"] = {
        "latency_ms":     latency_ms,
        "prompt_tokens":  prompt_tokens,
        "completion_tokens": completion_tokens,
        "model":          LLM_MODEL,
        "prompt_ref":     HISTORIAN_PROMPT_REF,
    }
    return result


# ──────────────────────────────────────────────────────────────────────────
# APLICAÇÃO AVALIADA — @weave.op que o Evaluation vai chamar por exemplo
# ──────────────────────────────────────────────────────────────────────────
@weave.op(name="historian_app")
def historian_app(incident_id: str,
                  proof_contract: dict,
                  pod_status: dict,
                  post_apply_logs: str,
                  expected_outcome: str) -> dict:
    """
    Função principal avaliada pelo Weave Evaluation.
    Recebe os campos do dataset como kwargs (Weave injeta por nome).
    Retorna o dict completo do Historiador para o scorer.
    """
    global HISTORIAN_SYSTEM_PROMPT
    if HISTORIAN_SYSTEM_PROMPT is None:
        HISTORIAN_SYSTEM_PROMPT = get_historian_prompt()

    payload = json.dumps(
        {
            "proof_contract":  proof_contract,
            "pod_status":      pod_status,
            "post_apply_logs": post_apply_logs,
        },
        ensure_ascii=False,
        indent=2,
    )
    return call_llm_historian(HISTORIAN_SYSTEM_PROMPT, payload)


# ──────────────────────────────────────────────────────────────────────────
# SCORER — métricas operacionais de classificação
# ──────────────────────────────────────────────────────────────────────────
class HistorianClassificationScorer(weave.Scorer):
    """
    Três métricas por exemplo:
    - accuracy               : 1.0 se pred == gold, senão 0.0
    - false_positive_resolved: 1 se o modelo disse "resolved" mas era outra coisa
                               (erro mais perigoso — otimismo indevido)
    - invalid_output         : 1 se a saída está fora do contrato de labels
    """

    @weave.op(name="historian_scorer")
    def score(self, output: dict, expected_outcome: str) -> dict:  # type: ignore[override]
        valid = {"resolved", "reoccurred", "caused_side_effect"}
        pred  = output.get("outcome", "invalid")
        gold  = expected_outcome

        return {
            "accuracy":                float(pred == gold),
            "false_positive_resolved": int(pred == "resolved" and gold != "resolved"),
            "invalid_output":          int(pred not in valid),
            "predicted_outcome":       pred,
            "expected_outcome":        gold,
            "llm_confidence":          float(output.get("confidence", 0.0)),
            "latency_ms":              int(output.get("_meta", {}).get("latency_ms", 0)),
            "prompt_tokens":           int(output.get("_meta", {}).get("prompt_tokens", 0)),
            "completion_tokens":       int(output.get("_meta", {}).get("completion_tokens", 0)),
        }


# ──────────────────────────────────────────────────────────────────────────
# RUNNER PRINCIPAL
# ──────────────────────────────────────────────────────────────────────────
async def run_evaluation() -> dict:
    """
    1. Publica o dataset no Weave (versionado)
    2. Cria o Evaluation com o scorer customizado
    3. Executa — gera Traces, Spans e resultados na aba Evals
    4. Retorna o sumário de métricas
    """
    # weave.init() deve ser chamado antes de qualquer @weave.op para que todos
    # os traces sejam enviados ao projeto remoto correto.
    weave.init(f"{ENTITY}/{PROJECT}")
    print(f"[weave] Conectado a: {ENTITY}/{PROJECT}")

    global HISTORIAN_SYSTEM_PROMPT
    HISTORIAN_SYSTEM_PROMPT = get_historian_prompt()

    print("\n[eval] Publicando dataset sintético...")
    dataset = publish_dataset()

    scorer  = HistorianClassificationScorer()
    
    # Publish the scorer to Weave for prompt version comparison in Playground
    weave.publish(scorer, name="historian-scorer-v1")
    print("[weave] Scorer publicado: historian-scorer-v1")

    evaluation = Evaluation(
        name="historian-eval-v1",
        dataset=dataset,
        scorers=[scorer],
    )

    print(f"[eval] Iniciando avaliação com modelo '{LLM_MODEL}'...")
    print(f"[eval] Prompt ref: {HISTORIAN_PROMPT_REF}")

    results = await evaluation.evaluate(historian_app)
    print(f"\n[eval] Resultados da Avaliação: {results}")

    # Check thresholds to fail CI if violated
    import sys
    scorer_results = results.get("historian_scorer", results)
    
    # Get accuracy
    accuracy_data = scorer_results.get("accuracy", {})
    accuracy = accuracy_data.get("mean") if isinstance(accuracy_data, dict) else accuracy_data
    if accuracy is None:
        accuracy = results.get("historian_scorer.accuracy.mean")

    # Get false_positive_resolved
    fp_data = scorer_results.get("false_positive_resolved", {})
    fp_resolved = fp_data.get("mean") if isinstance(fp_data, dict) else fp_data
    if fp_resolved is None:
        fp_resolved = results.get("historian_scorer.false_positive_resolved.mean")

    print(f"[eval] Verificando limites de qualidade CI/CD: accuracy={accuracy}, false_positive_resolved={fp_resolved}")

    # Set thresholds
    MIN_ACCURACY = 0.80
    MAX_FP_RESOLVED = 0.05
    
    if accuracy is not None and accuracy < MIN_ACCURACY:
        print(f"[eval] ERRO: Acurácia ({accuracy:.2f}) abaixo do limite mínimo de {MIN_ACCURACY:.2f}!")
        sys.exit(1)
        
    if fp_resolved is not None and fp_resolved > MAX_FP_RESOLVED:
        print(f"[eval] ERRO: Falsos positivos resolved ({fp_resolved:.2f}) acima do limite máximo de {MAX_FP_RESOLVED:.2f}!")
        sys.exit(1)
        
    print("[eval] Avaliação passou nos critérios de qualidade CI/CD!")
    return results


if __name__ == "__main__":
    asyncio.run(run_evaluation())
