import hashlib
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator


class IncidentPayload(BaseModel):
    source: str = Field(..., description="Source of the incident alert (e.g. alertmanager, datadog)")
    incident_id: str = Field(..., description="Unique UUID or identifier of the incident")
    fingerprint_inputs: Dict[str, str] = Field(
        ...,
        description="Inputs for fingerprint calculation (namespace, service_name, container_image, error_type)"
    )
    proposed_action: str = Field(..., description="Action proposed: tweak_limits, liveness_probe_adjustment, rollback, code_fix")
    manifest_path: str = Field(..., description="Local path to the Kubernetes manifest proposed for apply")
    raw_payload: Dict[str, Any] = Field(default_factory=dict, description="Raw alert payload")

    @field_validator("proposed_action")
    def validate_action(cls, v):
        allowed = {"tweak_limits", "liveness_probe_adjustment", "rollback", "code_fix"}
        if v not in allowed:
            raise ValueError(f"proposed_action must be one of {allowed}")
        return v


class Hypothesis(BaseModel):
    proposed_action: str
    root_cause_analysis: str
    confidence: float = Field(0.0, ge=0.0, le=1.0)


class HistoricalMatch(BaseModel):
    found: bool = False
    previous_incident_id: Optional[str] = None
    previous_outcome: Optional[str] = None


class Evidence(BaseModel):
    log_pattern: Optional[str] = None
    metrics_baseline: Dict[str, Any] = Field(default_factory=dict)
    historical_match: HistoricalMatch = Field(default_factory=HistoricalMatch)


class ProofContract(BaseModel):
    incident_fingerprint: str
    hypothesis: Hypothesis
    evidence: Evidence = Field(default_factory=Evidence)


class HistorianResponse(BaseModel):
    outcome: str = Field(..., description="resolved, reoccurred, caused_side_effect")
    observacao: str = Field(..., description="Context or notes about the classification decision")

    @field_validator("outcome")
    def validate_outcome(cls, v):
        allowed = {"resolved", "reoccurred", "caused_side_effect"}
        if v not in allowed:
            raise ValueError(f"outcome must be one of {allowed}")
        return v


def generate_fingerprint(inputs: Dict[str, str]) -> str:
    """
    Generates a stable SHA-256 hash from the fingerprint inputs to identify the incident class.
    Required keys: namespace, service_name, container_image, error_type.
    """
    required = ["namespace", "service_name", "container_image", "error_type"]
    parts = []
    for k in required:
        v = inputs.get(k, "").strip().lower()
        parts.append(f"{k}:{v}")
    
    raw_string = "|".join(parts)
    return hashlib.sha256(raw_string.encode("utf-8")).hexdigest()
