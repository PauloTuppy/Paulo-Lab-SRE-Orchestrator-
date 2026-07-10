import os
import pytest
from pathlib import Path


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """
    Automatically overrides DB_PATH and sets up the execution mode
    to offline for all tests.
    """
    test_db = tmp_path / "test_incident_history.sqlite3"
    monkeypatch.setenv("DB_PATH", str(test_db))
    
    import orchestrator.sqlite_store
    monkeypatch.setattr(orchestrator.sqlite_store, "DB_PATH", str(test_db))
    
    # Configure offline and test-friendly settings
    monkeypatch.setenv("EXECUTION_MODE", "offline")
    monkeypatch.setenv("WANDB_ENABLED", "false")
    monkeypatch.setenv("WEAVE_ENABLED", "false")
    monkeypatch.setenv("WEBHOOK_TOKEN", "test-token")
    
    from orchestrator.sqlite_store import initialize_database
    initialize_database()
    
    yield test_db
    
    # Clean up
    if test_db.exists():
        try:
            test_db.unlink()
        except OSError:
            pass
