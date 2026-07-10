import os
from typing import Any, Dict, List
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from orchestrator.contracts import IncidentPayload, generate_fingerprint
from orchestrator.sqlite_store import get_store
from orchestrator.metrics import increment_webhook_errors, get_system_metrics
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response

store = get_store()
app = FastAPI(title="Paulo Lab SRE Orchestrator API")

EXECUTION_MODE = os.getenv("EXECUTION_MODE", "development").lower()
WEBHOOK_TOKEN = os.getenv("WEBHOOK_TOKEN", "dev-secret")

if EXECUTION_MODE == "production" and (
    not WEBHOOK_TOKEN 
    or WEBHOOK_TOKEN == "dev-secret" 
    or WEBHOOK_TOKEN == "prod-secret-token-change-me"
):
    raise RuntimeError("Insecure default WEBHOOK_TOKEN is forbidden in production execution mode.")



def authenticate_token(x_webhook_token: str = Header(None)):
    if not x_webhook_token or x_webhook_token != WEBHOOK_TOKEN:
        increment_webhook_errors()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticação inválido ou ausente."
        )


def normalize_incoming_payload(raw_json: Dict[str, Any]) -> List[IncidentPayload]:
    """
    Adapter function that normalizes Alertmanager, Datadog or direct schema requests
    into a list of IncidentPayload objects.
    """
    normalized_list = []

    # 1. Alertmanager payload check
    # Alertmanager typical fields: 'alerts', 'receiver', 'status', 'commonLabels', 'commonAnnotations'
    if "alerts" in raw_json and isinstance(raw_json["alerts"], list):
        for alert in raw_json["alerts"]:
            labels = alert.get("labels", {})
            annotations = alert.get("annotations", {})
            
            fingerprint_inputs = {
                "namespace": labels.get("namespace", "default"),
                "service_name": labels.get("service", labels.get("job", "unknown-service")),
                "container_image": labels.get("image", "unknown-image"),
                "error_type": labels.get("alertname", "UnknownAlert")
            }
            
            # Map annotations to action and manifest
            proposed_action = annotations.get("proposed_action", "tweak_limits")
            manifest_path = annotations.get("manifest_path", "")
            incident_id = alert.get("fingerprint", f"alert-{hash(str(alert))}")

            try:
                payload = IncidentPayload(
                    source="alertmanager",
                    incident_id=incident_id,
                    fingerprint_inputs=fingerprint_inputs,
                    proposed_action=proposed_action,
                    manifest_path=manifest_path,
                    raw_payload=alert
                )
                normalized_list.append(payload)
            except ValidationError:
                continue

    # 2. Datadog webhook payload check
    # Datadog typical webhook payload includes 'body', 'event_type', 'org', 'id'
    elif "event_type" in raw_json or ("body" in raw_json and "title" in raw_json):
        # Extract metadata from body text or tags
        body_text = raw_json.get("body", "")
        title = raw_json.get("title", "")
        tags = raw_json.get("tags", "").split(",") if isinstance(raw_json.get("tags"), str) else []
        
        tag_dict = {}
        for t in tags:
            if ":" in t:
                k, v = t.split(":", 1)
                tag_dict[k.strip()] = v.strip()

        fingerprint_inputs = {
            "namespace": tag_dict.get("namespace", "default"),
            "service_name": tag_dict.get("service", "unknown-service"),
            "container_image": tag_dict.get("image", "unknown-image"),
            "error_type": title or "DatadogAlert"
        }

        proposed_action = tag_dict.get("proposed_action", "tweak_limits")
        manifest_path = tag_dict.get("manifest_path", "")
        incident_id = str(raw_json.get("id", f"dd-{hash(title)}"))

        try:
            payload = IncidentPayload(
                source="datadog",
                incident_id=incident_id,
                fingerprint_inputs=fingerprint_inputs,
                proposed_action=proposed_action,
                manifest_path=manifest_path,
                raw_payload=raw_json
            )
            normalized_list.append(payload)
        except ValidationError:
            pass

    # 3. Direct internal format fallback
    else:
        try:
            payload = IncidentPayload(**raw_json)
            normalized_list.append(payload)
        except ValidationError as e:
            increment_webhook_errors()
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Payload não pôde ser normalizado: {e.errors()}"
            )

    return normalized_list


def has_active_incident(fingerprint: str) -> bool:
    """Checks if there is an active incident with the same fingerprint."""
    return store.has_active_incident(fingerprint)


@app.post("/webhook")
async def receive_webhook(request: Request, x_webhook_token: str = Header(None)):
    # Authenticate token
    authenticate_token(x_webhook_token)
    
    try:
        raw_json = await request.json()
    except Exception:
        increment_webhook_errors()
        raise HTTPException(status_code=400, detail="Corpo da requisição JSON inválido.")

    # Normalize inputs
    incidents = normalize_incoming_payload(raw_json)
    if not incidents:
        return JSONResponse(
            status_code=200,
            content={"status": "ignored", "message": "Nenhum incidente válido processado do payload."}
        )

    processed_ids = []
    ignored_duplicates = []

    for inc in incidents:
        namespace = inc.fingerprint_inputs.get("namespace", "default")
        pod_name = inc.fingerprint_inputs.get("pod_name", inc.incident_id)
        
        # Calculate fingerprint
        fingerprint = generate_fingerprint(inc.fingerprint_inputs)

        # Idempotency / De-duplication check
        if has_active_incident(fingerprint):
            active_row = store.get_active_incident_by_fingerprint(fingerprint)
            if active_row:
                # Compare incident version
                new_version = inc.raw_payload.get("version", 1)
                # Re-open or update if new version is higher, or if already applied but re-occurred
                if (
                    new_version > active_row["incident_version"] or
                    active_row["status"] == "applied"
                ):
                    import json
                    store.update_active_incident(
                        fingerprint=fingerprint,
                        incident_version=new_version,
                        idempotency_key=inc.incident_id,
                        playbook_parameters_json=json.dumps(inc.fingerprint_inputs)
                    )
                    processed_ids.append(inc.incident_id)
                else:
                    ignored_duplicates.append(inc.incident_id)
            else:
                ignored_duplicates.append(inc.incident_id)
            continue

        # Insert into pending_incidents
        import json
        playbook_id = f"{inc.proposed_action}_v1"
        playbook_parameters_json = json.dumps(inc.fingerprint_inputs)
        incident_version = inc.raw_payload.get("version", 1)
        idempotency_key = inc.incident_id

        store.insert_pending_incident(
            incident_id=inc.incident_id,
            source=inc.source,
            namespace=namespace,
            pod_name=pod_name,
            proposed_action=inc.proposed_action,
            playbook_id=playbook_id,
            playbook_parameters_json=playbook_parameters_json,
            fingerprint=fingerprint,
            incident_version=incident_version,
            idempotency_key=idempotency_key
        )
        processed_ids.append(inc.incident_id)

    return {
        "status": "success",
        "processed_incidents": processed_ids,
        "ignored_duplicates": ignored_duplicates
    }


@app.get("/metrics")
async def get_metrics(request: Request):
    """
    Returns Prometheus metrics in text format or the custom JSON dashboard if Accept header is application/json.
    """
    accept_header = request.headers.get("accept", "")
    if "application/json" in accept_header or request.query_params.get("format") == "json":
        return get_system_metrics()
    
    # Update Prometheus gauges before generating latest metrics scrape
    from orchestrator.metrics import update_dynamic_gauges
    update_dynamic_gauges()
    
    # Return Prometheus metrics format
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
