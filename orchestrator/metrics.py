import os
import threading
from pathlib import Path
from orchestrator.sqlite_store import DB_PATH, get_store
from prometheus_client import Counter, Gauge

store = get_store()

# Thread-safe counters
_lock = threading.Lock()
_metrics = {
    "webhook_errors": 0,
    "total_vetos": 0,
    "total_applies": 0,
    "total_escalates": 0,
}

# Define Prometheus metrics
SRE_HISTORIAN_OUTCOME_TOTAL = Counter(
    'sre_historian_outcome_total',
    'Total count of SRE incident outcomes classified by the Historian',
    ['outcome']
)

SRE_GATEKEEPER_DECISIONS_TOTAL = Counter(
    'sre_gatekeeper_decisions_total',
    'Total count of SRE Gatekeeper decisions by type (APPLY, VETO, ESCALATE)',
    ['decision']
)

SRE_WEBHOOK_ERRORS_TOTAL = Counter(
    'sre_webhook_errors_total',
    'Total count of incoming webhook processing errors'
)

SRE_PENDING_INCIDENTS = Gauge(
    'sre_pending_incidents_total',
    'Current number of pending incidents in the queue'
)

SRE_DEAD_LETTER = Gauge(
    'sre_dead_letter_total',
    'Current number of failed/dead-letter incidents in the database'
)


def update_dynamic_gauges():
    """Queries current DB stats and updates Prometheus Gauges before scraping."""
    try:
        stats = store.get_metrics_statistics()
        SRE_PENDING_INCIDENTS.set(stats.get("pending_count", 0))
        # Dead letter is status 'failed'
        SRE_DEAD_LETTER.set(stats.get("failed_count", 0))
    except Exception:
        pass


def increment_webhook_errors():
    with _lock:
        _metrics["webhook_errors"] += 1
    SRE_WEBHOOK_ERRORS_TOTAL.inc()


def increment_vetos():
    with _lock:
        _metrics["total_vetos"] += 1
    SRE_GATEKEEPER_DECISIONS_TOTAL.labels(decision="VETO").inc()


def increment_applies():
    with _lock:
        _metrics["total_applies"] += 1
    SRE_GATEKEEPER_DECISIONS_TOTAL.labels(decision="APPLY").inc()


def increment_escalates():
    with _lock:
        _metrics["total_escalates"] += 1
    SRE_GATEKEEPER_DECISIONS_TOTAL.labels(decision="ESCALATE").inc()


def increment_outcome(outcome: str):
    SRE_HISTORIAN_OUTCOME_TOTAL.labels(outcome=outcome).inc()


def get_sqlite_db_size() -> int:
    """Returns database size in bytes."""
    path = Path(DB_PATH)
    if path.exists():
        return path.stat().st_size
    return 0


def get_system_metrics() -> dict:
    """Aggregates memory and database records to expose comprehensive SRE metrics."""
    db_size = get_sqlite_db_size()
    
    # Query database statistics from StoreBackend
    try:
        stats = store.get_metrics_statistics()
    except Exception:
        # Fallback if DB is not yet initialized or locked
        stats = {
            "pending_count": 0,
            "applied_count": 0,
            "classified_count": 0,
            "failed_count": 0,
            "needs_review_count": 0,
            "outcome_resolved": 0,
            "outcome_reoccurred": 0,
            "outcome_caused_side_effect": 0,
            "avg_remediation_time_sec": 0.0
        }

    with _lock:
        return {
            "webhook_errors": _metrics["webhook_errors"],
            "total_vetos": _metrics["total_vetos"],
            "total_applies": _metrics["total_applies"],
            "total_escalates": _metrics["total_escalates"],
            "sqlite_db_size_bytes": db_size,
            "database_records": stats
        }
