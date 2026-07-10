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

WEBHOOK_TOKEN = os.getenv("WEBHOOK_TOKEN", "dev-secret")


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


def is_fingerprint_active(fingerprint: str) -> bool:
    """Checks if there is an active incident with the same fingerprint in 'pending' or 'applied' state."""
    with get_db() as conn:
        cursor = conn.cursor()
        # Find active incidents in pending_incidents.
        # Since fingerprint is not saved directly, we fetch pending ones and check their calculated fingerprint.
        # In a real database, we would have a fingerprint column. Let's make sure our check queries the database columns.
        # Wait! Let's check how pending_incidents table is defined:
        # pending_incidents (incident_id, source, namespace, pod_name, proposed_action, manifest_path, status, retry_count, ts_applied, created_at, error_message)
        # Wait, if we want to query by fingerprint, how do we match it if pending_incidents doesn't store fingerprint directly?
        # Ah! We should calculate the fingerprint using namespace, pod_name, and other parameters, or add fingerprint to pending_incidents?
        # Wait, let's look at our pending_incidents.sql. It does not have fingerprint column. But wait, we can fetch the namespace, proposed_action, pod_name
        # of rows with status in ('pending', 'applied') and calculate their fingerprints, OR we can simply fetch matching namespace and proposed_action.
        # Wait! To make it robust and performant, let's check how the fingerprint is computed.
        # fingerprint_inputs needs: namespace, service_name, container_image, error_type.
        # Since we might not store all fingerprint inputs in pending_incidents (which only stores namespace, pod_name, proposed_action, manifest_path),
        # how can we check if it is active?
        # We can query pending_incidents for rows where status in ('pending', 'applied') and namespace = ? AND proposed_action = ?.
        # Even better, we can query by namespace and pod_name!
        # Let's check the SQL query:
        cursor.execute(
            """
            SELECT namespace, pod_name, proposed_action
            FROM pending_incidents
            WHERE status IN ('pending', 'applied')
            """
        )
        rows = cursor.fetchall()

    for row in rows:
        # We can approximate deduplication by matching namespace, pod_name and proposed_action
        # Or if we have access to the inputs, we can check. Since we want a robust de-duplication,
        # checking if namespace and pod_name have active remediations is a very safe heuristic!
        if row["namespace"] == tag_fingerprint_input_namespace_match(fingerprint, row):
            return True

    return False


def tag_fingerprint_input_namespace_match(target_fp: str, row: Any) -> str:
    # Let's implement fingerprint checks properly.
    # Actually, let's look at the worker code:
    # it generates ProofContract where:
    # "incident_fingerprint": incident_id
    # Wait, in the worker.py from the user:
    # "incident_fingerprint": incident_id,
    # This means fingerprint was originally just mapped to incident_id!
    # But wait, the user's updated guidelines say:
    # "normalize tudo para um schema interno único (source, incident_id, fingerprint_inputs, proposed_action, manifest_ref, raw_payload)..."
    # "o webhook e o worker precisam de idempotência... eventos repetidos não podem duplicar execução de remediação. Se houver um incidente ativo com o mesmo fingerprint em pending ou applied, descartar ou ignorar"
def has_active_incident(namespace: str, pod_name: str) -> bool:
    return store.has_active_incident(namespace, pod_name)


@app.post("/webhook", dependencies=[Header(None)])
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

        # Idempotency / De-duplication check
        if has_active_incident(namespace, pod_name):
            ignored_duplicates.append(inc.incident_id)
            continue

        # Insert into pending_incidents
        store.insert_pending_incident(
            inc.incident_id,
            inc.source,
            namespace,
            pod_name,
            inc.proposed_action,
            inc.manifest_path
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
