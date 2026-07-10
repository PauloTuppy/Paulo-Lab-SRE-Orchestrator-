# Paulo Lab SRE Orchestrator

Sistema de auto-remediação para Kubernetes orientado por **dúvida**, memória histórica e gatekeeping determinístico. O objetivo é automatizar correções seguras sem cair em reward hacking, sucesso aparente ou dívida técnica acumulada. [docs.wandb](https://docs.wandb.ai/weave)

A arquitetura foi evoluída além do MVP original para incluir modos de execução controlados, observabilidade com Prometheus, rastreamento com W&B, avaliações com Weave, retries com dead-letter e um roadmap explícito para PostgreSQL como backend de produção. [github](https://github.com/prometheus/client_python)

## Visão geral

O sistema opera em malha fechada:

1. Um alerta chega por webhook.
2. O payload é autenticado, normalizado e deduplicado.
3. O Gatekeeper decide entre `APPLY`, `VETO` ou `ESCALATE`.
4. O Worker executa a ação aprovada de forma segura.
5. O Historiador reavalia o resultado após a janela de observação.
6. O outcome é gravado na memória histórica e influencia decisões futuras. [render](https://render.com/articles/fastapi-production-deployment-best-practices)

Esse desenho separa claramente **execução**, **avaliação tardia** e **aprendizado operacional**, o que reduz o risco de otimização local cega e melhora a auditabilidade do sistema. [render](https://render.com/articles/fastapi-production-deployment-best-practices)

## Modos de execução

O orquestrador suporta três modos definidos por `EXECUTION_MODE`:

| Modo | Objetivo | Comportamento |
|---|---|---|
| `offline` | Desenvolvimento e testes locais | Simula `kubectl`, usa classificador local no Historiador, desabilita ou roda W&B em modo offline. [docs.wandb](https://docs.wandb.ai/models/ref/python/functions/init) |
| `staging` | Validação conectada, sem ação destrutiva | Usa `kubectl apply --dry-run=server`, Historian em modo `log-only`, W&B/Weave habilitados. [apxml](https://apxml.com/courses/fastapi-ml-deployment/chapter-6-containerization-deployment-prep/production-deployment-gunicorn-uvicorn) |
| `production` | Operação real no cluster | Executa ações reais, usa memória histórica para vetos e mantém instrumentação completa. [render](https://render.com/articles/fastapi-production-deployment-best-practices) |

Além disso, `ORCHESTRATOR_ENABLED=false` atua como kill-switch global. Quando desligado, o Worker e o Historiador devem pausar processamento sem perder estado da fila. [render](https://render.com/articles/fastapi-production-deployment-best-practices)

## Fluxo de decisão

### 1. Entrada e normalização

O endpoint de webhook recebe alertas de fontes como Alertmanager e Datadog. Cada payload é convertido para um contrato interno padronizado para evitar regras específicas por fonte espalhadas no código. [render](https://render.com/articles/fastapi-production-deployment-best-practices)

Campos mínimos do contrato normalizado:

- `source`
- `incident_id`
- `fingerprint_inputs`
- `proposed_action`
- `manifest_ref`
- `raw_payload`

Antes de inserir um novo incidente em fila, o sistema deve verificar se já existe um incidente ativo com o mesmo `incident_fingerprint` em estado `pending` ou `applied`, respeitando também uma janela de cooldown configurável. [render](https://render.com/articles/fastapi-production-deployment-best-practices)

### 2. Gatekeeper determinístico

O Gatekeeper aplica políticas simples, auditáveis e previsíveis. Ele não “imagina”; ele valida se a hipótese proposta é segura o bastante para seguir adiante. [render](https://render.com/articles/fastapi-production-deployment-best-practices)

Regras-base:

- `confidence < CONFIDENCE_THRESHOLD` → `ESCALATE`
- Estratégia com falha recente para mesmo fingerprint → `VETO`
- Match histórico ruim para mesma ação → `VETO`
- Caso contrário → `APPLY`

Toda decisão deve registrar `decision_reason`, `trace_id` e `run_id` para posterior auditoria cruzada com W&B e banco histórico. [docs.wandb](https://docs.wandb.ai/models/ref/python/functions/init)

### 3. Execução controlada

O Worker consome incidentes da fila `pending_incidents`, aplica retries com backoff exponencial e encaminha casos exauridos para estados terminais como `failed` ou `needs_review`. [render](https://render.com/articles/fastapi-production-deployment-best-practices)

Em `offline`, a aplicação é simulada. Em `staging`, a validação principal ocorre com `kubectl apply --dry-run=server`. Em `production`, a ação real só ocorre quando o Gatekeeper aprova explicitamente. [apxml](https://apxml.com/courses/fastapi-ml-deployment/chapter-6-containerization-deployment-prep/production-deployment-gunicorn-uvicorn)

### 4. Historiador tardio

Após a janela de observação, o Historiador coleta sinais operacionais e classifica o resultado em:

- `resolved`
- `reoccurred`
- `caused_side_effect`

Essa classificação é gravada em `incident_history` e retroalimenta o Gatekeeper para bloquear estratégias ruins no futuro. [render](https://render.com/articles/fastapi-production-deployment-best-practices)

## Contratos principais

### Contrato de Prova

Toda proposta de remediação deve ser representada por um JSON estruturado como este:

```json
{
  "incident_fingerprint": "hash_unico_do_evento",
  "hypothesis": {
    "proposed_action": "tweak_limits|rollback|code_fix|liveness_probe_adjustment",
    "root_cause_analysis": "...",
    "confidence": 0.85
  },
  "evidence": {
    "log_pattern": "...",
    "historical_match": {
      "found": false,
      "last_outcome": null
    }
  },
  "source": "alertmanager",
  "manifest_ref": "./manifests/example.yaml"
}
```

### Resposta do Historiador

```json
{
  "outcome": "resolved|reoccurred|caused_side_effect",
  "observacao": "resumo curto da justificativa",
  "model": "historian-agent-v2"
}
```

## Esquema de dados

O projeto usa duas tabelas principais no MVP.

### `pending_incidents`

Responsável pela fila transacional de trabalho.

Campos esperados:

- `incident_id`
- `source`
- `namespace`
- `pod_name`
- `proposed_action`
- `manifest_path`
- `status`
- `retry_count`
- `ts_applied`
- `created_at`
- `error_message`

Estados típicos:

- `pending`
- `applied`
- `classified`
- `vetoed`
- `escalated`
- `failed`
- `needs_review`

### `incident_history`

Responsável pela memória histórica auditável.

Campos esperados:

- `id`
- `fingerprint`
- `action_type`
- `outcome`
- `proof_contract_json`
- `decision_reason`
- `applied_at`
- `classified_at`
- `historian_model`
- `trace_id`
- `run_id`
- `created_at`

Índices mínimos recomendados:

- `idx_history_fingerprint`
- `idx_history_fingerprint_action`
- `idx_history_created`
- `idx_pending_status`
- `idx_pending_created`

## Backend de dados

### Fase 1: SQLite

SQLite atende bem ao MVP local e ao piloto de réplica única com PVC. Para esse estágio, WAL, retries leves e política de retenção de 90 dias já entregam um bom compromisso entre simplicidade e auditabilidade. [render](https://render.com/articles/fastapi-production-deployment-best-practices)

### Fase 2: PostgreSQL

Para produção com múltiplas réplicas e maior concorrência, o backend alvo é PostgreSQL. A recomendação é manter uma interface de storage comum com implementações explícitas por backend, em vez de traduzir SQL genericamente em tempo de execução. [wiki.postgresql](https://wiki.postgresql.org/wiki/Using_psycopg2_with_PostgreSQL)

## Observabilidade

### Prometheus

O endpoint `/metrics` deve expor métricas em formato Prometheus usando o cliente Python oficial, com `Counter` para decisões, outcomes e erros, e `generate_latest()` para serialização scrapeável. [cloudbees](https://www.cloudbees.com/blog/monitoring-your-synchronous-python-web-applications-using-prometheus)

Métricas recomendadas:

- `sre_gatekeeper_decisions_total{decision="APPLY|VETO|ESCALATE"}`
- `sre_historian_outcome_total{outcome="resolved|reoccurred|caused_side_effect"}`
- `sre_webhook_errors_total`
- `sre_pending_incidents_total`
- `sre_dead_letter_total`

Se necessário, o endpoint pode oferecer fallback em JSON para inspeção manual, mas o formato padrão de produção deve ser texto Prometheus. [cloudbees](https://www.cloudbees.com/blog/monitoring-your-synchronous-python-web-applications-using-prometheus)

### W&B Runs

O projeto deve iniciar runs com `wandb.init()` e logar métricas operacionais com `run.log()`, diferenciando pelo menos `job_type="gatekeeper"` e `job_type="historian"`. [docs.wandb](https://docs.wandb.ai/models/track/log)

Exemplos de campos úteis:

- `incident_id`
- `incident_fingerprint`
- `decision`
- `latency_ms`
- `outcome`
- `response_valid`

### Weave

O Weave é usado para três objetivos:

1. Versionar prompts do Historiador. [docs.wandb](https://docs.wandb.ai/weave/guides/core-types/prompts)
2. Manter datasets de incidentes sintéticos para avaliação. [docs.wandb](https://docs.wandb.ai/weave)
3. Definir scorers automáticos como `accuracy`, `false_positive_resolved` e `invalid_label_rate`. [docs.wandb](https://docs.wandb.ai/weave)

O prompt operacional do Historiador deve ser recuperado por ref/version, por exemplo `historian-agent-v2`, com fallback local quando Weave estiver desabilitado ou indisponível. [wandb](https://wandb.ai/paulotuppyjatoba-tuppyia/paulo-lab-sre-orchestrator/weave/playground?model=cw_deepseek-ai_DeepSeek-V4-Flash)

## Historiador e prompts

O Historiador deve seguir uma cadeia de fallback determinística:

1. Endpoint interno (`HISTORIAN_ENDPOINT`)
2. Gemini API
3. Classificador local por regras

Essa ordem deve ser consistente para evitar comportamento diferente entre ambientes equivalentes. [docs.wandb](https://docs.wandb.ai/weave)

O classificador local existe para offline testing e contingência, mas precisa de regressões fixas para negação semântica. Casos como `No OOMKilled events` não podem ser classificados como `reoccurred` apenas por substring ingênua. [render](https://render.com/articles/fastapi-production-deployment-best-practices)

## Segurança e governança

### RBAC

O bot deve operar com princípio de menor privilégio. A documentação e os manifests devem restringir acesso ao namespace alvo e distinguir claramente permissões de leitura, listagem, watch e patch. [render](https://render.com/articles/fastapi-production-deployment-best-practices)

### Kill-switch

`ORCHESTRATOR_ENABLED=false` deve pausar tanto o Worker quanto o Historiador, sem apagar fila, histórico ou observabilidade mínima. [render](https://render.com/articles/fastapi-production-deployment-best-practices)

### Feature flags

Flags mínimas recomendadas:

- `EXECUTION_MODE`
- `ORCHESTRATOR_ENABLED`
- `WANDB_ENABLED`
- `WEAVE_ENABLED`
- `WANDB_MODE`
- `DB_TYPE`
- `CONFIDENCE_THRESHOLD`

## Deploy em Kubernetes

### PVC

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: incident-db-pvc
  namespace: sre-system
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
```

### Stack de API

Para produção, a API FastAPI deve rodar com Gunicorn + Uvicorn workers, em vez de `uvicorn --reload`, que fica restrito ao desenvolvimento local. [apxml](https://apxml.com/courses/fastapi-ml-deployment/chapter-6-containerization-deployment-prep/production-deployment-gunicorn-uvicorn)

### Arquitetura de implantação

No MVP, uma implantação single-replica com sidecar pode ser aceitável para compartilhar o volume SQLite localmente. Isso deve ser documentado como limitação deliberada de fase 1, não como HA final. [seenode](https://seenode.com/blog/deploy-fastapi-docker-and-uvicorn)

## Testes

### Unitários

Cobertura mínima recomendada:

- Banco e retenção de 90 dias
- Regras do Gatekeeper
- Deduplicação do webhook
- Retries e dead-letter
- Kill-switch
- Classificação local do Historiador
- Backend dual (quando PostgreSQL entrar)

### Regressão

Casos obrigatórios:

- `No OOMKilled events` → não deve virar `reoccurred` por substring
- OOM repetido real → `reoccurred`
- `memory_pressure` + aumento de latência → `caused_side_effect`

### Evals com Weave

Antes de promover ambiente, rodar:

```bash
python -m pytest tests/
python -m orchestrator.wandb_eval --eval-only
```

A promoção para `staging` ou `production` deve exigir, no mínimo:

- `false_positive_resolved = 0`
- `invalid_label_rate = 0`
- acurácia mínima definida por política interna

## Operação inicial

### Dias 1 e 2

Rodar em `log-only` por 48 horas. Nesse período, o Historiador apenas registra classificações e métricas, sem disparar bloqueios automáticos baseados em sua própria avaliação. [render](https://render.com/articles/fastapi-production-deployment-best-practices)

### Auditoria manual

Exemplos de auditoria:

```bash
sqlite3 incident_history.sqlite3 "SELECT * FROM incident_history ORDER BY created_at DESC;"
sqlite3 incident_history.sqlite3 "SELECT fingerprint, action_type, outcome, created_at FROM incident_history;"
```

### Ativação gradual

Após validação:

1. Ligar alertas humanos para `reoccurred` e `caused_side_effect`.
2. Habilitar uso mais forte da memória histórica no Gatekeeper.
3. Revisar thresholds por tipo de ação.

## Roadmap

### Curto prazo

- Consolidar Prometheus
- Integrar prompt versionado no Weave
- Fechar regressões do Historiador
- Melhorar documentação operacional

### Médio prazo

- Backend PostgreSQL
- Suporte multi-réplica
- Dashboards operacionais
- Critérios de promoção automáticos baseados em evals

### Longo prazo

- Expansão do Historiador para sinais mais ricos
- Aprendizado supervisionado sobre outcomes históricos
- Políticas diferenciadas por tipo de remediação

## Definition of Done

O que é necessário para considerar pronto:

- O README reflete a arquitetura real do sistema.
- O loop fechado está funcional de ponta a ponta.
- O kill-switch pausa Worker e Historiador.
- O `/metrics` está scrapeável por Prometheus. [github](https://github.com/prometheus/client_python)
- W&B registra runs operacionais. [docs.wandb](https://docs.wandb.ai/models/ref/python/functions/init)
- Weave executa evals com dataset sintético e scorers formais. [docs.wandb](https://docs.wandb.ai/weave/guides/core-types/prompts)
- O Historiador usa prompt versionado com fallback controlado. [wandb](https://wandb.ai/paulotuppyjatoba-tuppyia/paulo-lab-sre-orchestrator/weave/playground?model=cw_deepseek-ai_DeepSeek-V4-Flash)
- O classificador local passou nas regressões de negação semântica. [render](https://render.com/articles/fastapi-production-deployment-best-practices)
- O roadmap para PostgreSQL está documentado e aceito. [wiki.postgresql](https://wiki.postgresql.org/wiki/Using_psycopg2_with_PostgreSQL)
