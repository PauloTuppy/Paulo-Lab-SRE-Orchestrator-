import os
import sqlite3
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

# SQLite Configuration (kept for compatibility)
DEFAULT_DB_PATH = "/var/lib/incident-db/incident_history.sqlite3"
DB_PATH = os.getenv("DB_PATH", DEFAULT_DB_PATH)


class StoreBackend(ABC):
    @abstractmethod
    def initialize_database(self) -> None:
        """Creates schemas and indexes if they do not exist."""
        pass

    @abstractmethod
    def cleanup_old_incidents(self, days: int) -> int:
        """Deletes history records older than the specified days."""
        pass

    @abstractmethod
    def has_active_incident(self, namespace: str, pod_name: str) -> bool:
        """Checks if an incident for the workload is pending or applied."""
        pass

    @abstractmethod
    def insert_pending_incident(self, incident_id: str, source: str, namespace: str, pod_name: str, proposed_action: str, manifest_path: str) -> None:
        """Inserts a new incident with status 'pending'."""
        pass

    @abstractmethod
    def get_oldest_pending_incident(self) -> Optional[Dict[str, Any]]:
        """Returns the oldest pending incident in the queue."""
        pass

    @abstractmethod
    def update_incident_status(self, incident_id: str, status: str, error_message: Optional[str] = None, ts_applied_now: bool = False, retry_count: Optional[int] = None) -> None:
        """Updates the status and telemetry of an incident."""
        pass

    @abstractmethod
    def fetch_previous_outcome(self, fingerprint: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Finds the most recent outcome of an incident class fingerprint."""
        pass

    @abstractmethod
    def fetch_applied_incidents(self, delay_sec: int) -> List[Dict[str, Any]]:
        """Fetches applied incidents that have passed the delay evaluation window."""
        pass

    @abstractmethod
    def insert_incident_history(self, fingerprint: str, action_type: str, outcome: str, proof_contract_json: str, decision_reason: str, ts_applied: Optional[str], historian_model: str) -> None:
        """Inserts an evaluation record into the incident history."""
        pass

    @abstractmethod
    def get_metrics_statistics(self) -> Dict[str, Any]:
        """Calculates incident metrics counts and average remediation time."""
        pass


class SQLiteStore(StoreBackend):
    def __init__(self, db_path: str = None):
        self.db_path = db_path

    @contextmanager
    def _get_connection(self, max_retries: int = 5, initial_delay: float = 0.1):
        # Resolve db_path dynamically to support monkeypatching in unit tests
        db_path = self.db_path or os.getenv("DB_PATH", DEFAULT_DB_PATH)
        db_dir = Path(db_path).parent
        if not db_dir.exists():
            db_dir.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
        except sqlite3.OperationalError:
            pass

        try:
            yield conn
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                delay = initial_delay
                for attempt in range(max_retries):
                    try:
                        time.sleep(delay)
                        yield conn
                        break
                    except sqlite3.OperationalError as err:
                        if attempt == max_retries - 1:
                            raise err
                        delay *= 2
            else:
                raise e
        finally:
            conn.close()

    def initialize_database(self) -> None:
        base_dir = Path(__file__).parent.parent
        history_sql_path = base_dir / "sql" / "incident_history.sql"
        pending_sql_path = base_dir / "sql" / "pending_incidents.sql"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            if history_sql_path.exists():
                with open(history_sql_path, "r", encoding="utf-8") as f:
                    cursor.executescript(f.read())
            else:
                cursor.executescript("""
                CREATE TABLE IF NOT EXISTS incident_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    proof_contract_json TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    decision_reason TEXT,
                    applied_at DATETIME,
                    classified_at DATETIME,
                    historian_model TEXT,
                    trace_id TEXT,
                    run_id TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_history_fingerprint ON incident_history (fingerprint);
                CREATE INDEX IF NOT EXISTS idx_history_fingerprint_action ON incident_history (fingerprint, action_type);
                CREATE INDEX IF NOT EXISTS idx_history_created ON incident_history (created_at);
                """)

            if pending_sql_path.exists():
                with open(pending_sql_path, "r", encoding="utf-8") as f:
                    cursor.executescript(f.read())
            else:
                cursor.executescript("""
                CREATE TABLE IF NOT EXISTS pending_incidents (
                    incident_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    pod_name TEXT NOT NULL,
                    proposed_action TEXT NOT NULL,
                    manifest_path TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    retry_count INTEGER DEFAULT 0,
                    ts_applied DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    error_message TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_incidents (status);
                CREATE INDEX IF NOT EXISTS idx_pending_created ON pending_incidents (created_at);
                """)
            conn.commit()

    def cleanup_old_incidents(self, days: int) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM incident_history WHERE created_at < datetime('now', ?)",
                (f"-{days} days",)
            )
            conn.commit()
            return cursor.rowcount

    def has_active_incident(self, namespace: str, pod_name: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT COUNT(*) as cnt
                FROM pending_incidents
                WHERE namespace = ?
                  AND pod_name = ?
                  AND status IN ('pending', 'applied')
                """,
                (namespace, pod_name)
            )
            row = cursor.fetchone()
            return row["cnt"] > 0

    def insert_pending_incident(self, incident_id: str, source: str, namespace: str, pod_name: str, proposed_action: str, manifest_path: str) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO pending_incidents (incident_id, source, namespace, pod_name, proposed_action, manifest_path, status)
                VALUES (?, ?, ?, ?, ?, ?, 'pending')
                ON CONFLICT(incident_id) DO NOTHING
                """,
                (incident_id, source, namespace, pod_name, proposed_action, manifest_path)
            )
            conn.commit()

    def get_oldest_pending_incident(self) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                """
                SELECT * FROM pending_incidents
                WHERE status = 'pending'
                ORDER BY created_at ASC
                LIMIT 1
                """
            ).fetchone()
            return dict(row) if row else None

    def update_incident_status(self, incident_id: str, status: str, error_message: Optional[str] = None, ts_applied_now: bool = False, retry_count: Optional[int] = None) -> None:
        query = "UPDATE pending_incidents SET status = ?"
        params = [status]
        if error_message is not None:
            query += ", error_message = ?"
            params.append(error_message)
        if ts_applied_now:
            query += ", ts_applied = datetime('now')"
        if retry_count is not None:
            query += ", retry_count = ?"
            params.append(retry_count)
        query += " WHERE incident_id = ?"
        params.append(incident_id)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            conn.commit()

    def fetch_previous_outcome(self, fingerprint: str) -> Tuple[bool, Optional[str], Optional[str]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, outcome
                FROM incident_history
                WHERE fingerprint = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (fingerprint,)
            )
            row = cursor.fetchone()
            if row:
                return True, str(row["id"]), row["outcome"]
        return False, None, None

    def fetch_applied_incidents(self, delay_sec: int) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            rows = cursor.execute(
                """
                SELECT * FROM pending_incidents
                WHERE status = 'applied'
                  AND datetime(ts_applied) < datetime('now', ?)
                ORDER BY ts_applied ASC
                """,
                (f"-{delay_sec} seconds",)
            ).fetchall()
            return [dict(r) for r in rows]

    def insert_incident_history(self, fingerprint: str, action_type: str, outcome: str, proof_contract_json: str, decision_reason: str, ts_applied: Optional[str], historian_model: str) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO incident_history (
                    fingerprint, action_type, outcome, proof_contract_json,
                    decision_reason, applied_at, classified_at, historian_model
                )
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                """,
                (fingerprint, action_type, outcome, proof_contract_json, decision_reason, ts_applied, historian_model)
            )
            conn.commit()

    def get_metrics_statistics(self) -> Dict[str, Any]:
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

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status, COUNT(*) as cnt FROM pending_incidents GROUP BY status")
            for row in cursor.fetchall():
                status_name = row["status"]
                if status_name == "pending":
                    stats["pending_count"] = row["cnt"]
                elif status_name == "applied":
                    stats["applied_count"] = row["cnt"]
                elif status_name == "classified":
                    stats["classified_count"] = row["cnt"]
                elif status_name == "failed":
                    stats["failed_count"] = row["cnt"]
                elif status_name == "needs_review":
                    stats["needs_review_count"] = row["cnt"]

            cursor.execute("SELECT outcome, COUNT(*) as cnt FROM incident_history GROUP BY outcome")
            for row in cursor.fetchall():
                outcome_name = row["outcome"]
                if outcome_name == "resolved":
                    stats["outcome_resolved"] = row["cnt"]
                elif outcome_name == "reoccurred":
                    stats["outcome_reoccurred"] = row["cnt"]
                elif outcome_name == "caused_side_effect":
                    stats["outcome_caused_side_effect"] = row["cnt"]

            cursor.execute(
                """
                SELECT AVG((julianday(ts_applied) - julianday(created_at)) * 86400) as avg_time
                FROM pending_incidents
                WHERE ts_applied IS NOT NULL
                """
            )
            row = cursor.fetchone()
            if row and row["avg_time"] is not None:
                stats["avg_remediation_time_sec"] = round(row["avg_time"], 2)

        return stats


class PostgresStore(StoreBackend):
    def __init__(self):
        self.user = os.getenv("POSTGRES_USER", "postgres")
        self.password = os.getenv("POSTGRES_PASSWORD", "postgres")
        self.host = os.getenv("POSTGRES_HOST", "localhost")
        self.port = os.getenv("POSTGRES_PORT", "5432")
        self.database = os.getenv("POSTGRES_DB", "sre_orchestrator")
        self.database_url = os.getenv("DATABASE_URL")

    @contextmanager
    def _get_connection(self, max_retries: int = 5, initial_delay: float = 0.1):
        import psycopg2
        from psycopg2.extras import RealDictCursor
        conn = None
        for attempt in range(max_retries):
            try:
                if self.database_url:
                    conn = psycopg2.connect(self.database_url, cursor_factory=RealDictCursor)
                else:
                    conn = psycopg2.connect(
                        user=self.user,
                        password=self.password,
                        host=self.host,
                        port=self.port,
                        database=self.database,
                        cursor_factory=RealDictCursor
                    )
                break
            except Exception as e:
                if attempt == max_retries - 1:
                    raise e
                time.sleep(initial_delay * (2 ** attempt))
        try:
            yield conn
        finally:
            if conn:
                conn.close()

    def initialize_database(self) -> None:
        base_dir = Path(__file__).parent.parent
        history_sql_path = base_dir / "sql" / "incident_history.sql"
        pending_sql_path = base_dir / "sql" / "pending_incidents.sql"

        # Load schemas
        if history_sql_path.exists():
            with open(history_sql_path, "r", encoding="utf-8") as f:
                history_sql = f.read()
        else:
            history_sql = """
            CREATE TABLE IF NOT EXISTS incident_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                action_type TEXT NOT NULL,
                outcome TEXT NOT NULL,
                proof_contract_json TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                decision_reason TEXT,
                applied_at DATETIME,
                classified_at DATETIME,
                historian_model TEXT,
                trace_id TEXT,
                run_id TEXT
            );
            """
        # Adapt DDL from SQLite to PostgreSQL
        history_sql = history_sql.replace("AUTOINCREMENT", "")
        history_sql = history_sql.replace("INTEGER PRIMARY KEY", "SERIAL PRIMARY KEY")

        if pending_sql_path.exists():
            with open(pending_sql_path, "r", encoding="utf-8") as f:
                pending_sql = f.read()
        else:
            pending_sql = """
            CREATE TABLE IF NOT EXISTS pending_incidents (
                incident_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                namespace TEXT NOT NULL,
                pod_name TEXT NOT NULL,
                proposed_action TEXT NOT NULL,
                manifest_path TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                retry_count INTEGER DEFAULT 0,
                ts_applied DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                error_message TEXT
            );
            """

        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(history_sql)
                cursor.execute(pending_sql)
                # Create indexes (fully compatible)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_history_fingerprint ON incident_history (fingerprint)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_history_fingerprint_action ON incident_history (fingerprint, action_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_history_created ON incident_history (created_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_incidents (status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_pending_created ON pending_incidents (created_at)")
            conn.commit()

    def cleanup_old_incidents(self, days: int) -> int:
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM incident_history WHERE created_at < NOW() - CAST(%s AS INTERVAL)",
                    (f"{days} days",)
                )
                deleted_count = cursor.rowcount
            conn.commit()
        return deleted_count

    def has_active_incident(self, namespace: str, pod_name: str) -> bool:
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT COUNT(*) as cnt
                    FROM pending_incidents
                    WHERE namespace = %s
                      AND pod_name = %s
                      AND status IN ('pending', 'applied')
                    """,
                    (namespace, pod_name)
                )
                row = cursor.fetchone()
                return row["cnt"] > 0

    def insert_pending_incident(self, incident_id: str, source: str, namespace: str, pod_name: str, proposed_action: str, manifest_path: str) -> None:
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO pending_incidents (incident_id, source, namespace, pod_name, proposed_action, manifest_path, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 'pending')
                    ON CONFLICT(incident_id) DO NOTHING
                    """,
                    (incident_id, source, namespace, pod_name, proposed_action, manifest_path)
                )
            conn.commit()

    def get_oldest_pending_incident(self) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT * FROM pending_incidents
                    WHERE status = 'pending'
                    ORDER BY created_at ASC
                    LIMIT 1
                    """
                )
                row = cursor.fetchone()
                return dict(row) if row else None

    def update_incident_status(self, incident_id: str, status: str, error_message: Optional[str] = None, ts_applied_now: bool = False, retry_count: Optional[int] = None) -> None:
        query = "UPDATE pending_incidents SET status = %s"
        params = [status]
        if error_message is not None:
            query += ", error_message = %s"
            params.append(error_message)
        if ts_applied_now:
            query += ", ts_applied = NOW()"
        if retry_count is not None:
            query += ", retry_count = %s"
            params.append(retry_count)
        query += " WHERE incident_id = %s"
        params.append(incident_id)

        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, tuple(params))
            conn.commit()

    def fetch_previous_outcome(self, fingerprint: str) -> Tuple[bool, Optional[str], Optional[str]]:
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, outcome
                    FROM incident_history
                    WHERE fingerprint = %s
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (fingerprint,)
                )
                row = cursor.fetchone()
                if row:
                    return True, str(row["id"]), row["outcome"]
        return False, None, None

    def fetch_applied_incidents(self, delay_sec: int) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT * FROM pending_incidents
                    WHERE status = 'applied'
                      AND ts_applied < NOW() - CAST(%s AS INTERVAL)
                    ORDER BY ts_applied ASC
                    """,
                    (f"{delay_sec} seconds",)
                )
                rows = cursor.fetchall()
                return [dict(r) for r in rows]

    def insert_incident_history(self, fingerprint: str, action_type: str, outcome: str, proof_contract_json: str, decision_reason: str, ts_applied: Optional[str], historian_model: str) -> None:
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO incident_history (
                        fingerprint, action_type, outcome, proof_contract_json,
                        decision_reason, applied_at, classified_at, historian_model
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s)
                    """,
                    (fingerprint, action_type, outcome, proof_contract_json, decision_reason, ts_applied, historian_model)
                )
            conn.commit()

    def get_metrics_statistics(self) -> Dict[str, Any]:
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

        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT status, COUNT(*) as cnt FROM pending_incidents GROUP BY status")
                for row in cursor.fetchall():
                    status_name = row["status"]
                    if status_name == "pending":
                        stats["pending_count"] = row["cnt"]
                    elif status_name == "applied":
                        stats["applied_count"] = row["cnt"]
                    elif status_name == "classified":
                        stats["classified_count"] = row["cnt"]
                    elif status_name == "failed":
                        stats["failed_count"] = row["cnt"]
                    elif status_name == "needs_review":
                        stats["needs_review_count"] = row["cnt"]

                cursor.execute("SELECT outcome, COUNT(*) as cnt FROM incident_history GROUP BY outcome")
                for row in cursor.fetchall():
                    outcome_name = row["outcome"]
                    if outcome_name == "resolved":
                        stats["outcome_resolved"] = row["cnt"]
                    elif outcome_name == "reoccurred":
                        stats["outcome_reoccurred"] = row["cnt"]
                    elif outcome_name == "caused_side_effect":
                        stats["outcome_caused_side_effect"] = row["cnt"]

                cursor.execute(
                    """
                    SELECT AVG(EXTRACT(EPOCH FROM (ts_applied - created_at))) as avg_time
                    FROM pending_incidents
                    WHERE ts_applied IS NOT NULL
                    """
                )
                row = cursor.fetchone()
                if row and row["avg_time"] is not None:
                    stats["avg_remediation_time_sec"] = round(row["avg_time"], 2)

        return stats


# Global store selector
DB_TYPE = os.getenv("DB_TYPE", "sqlite").lower()


def get_store() -> StoreBackend:
    if DB_TYPE == "postgres":
        return PostgresStore()
    return SQLiteStore()


# Deprecated SQLite direct functions kept for backward compatibility / transition
@contextmanager
def get_db(max_retries: int = 5, initial_delay: float = 0.1):
    store = SQLiteStore()
    with store._get_connection(max_retries, initial_delay) as conn:
        yield conn


def initialize_database():
    store = get_store()
    store.initialize_database()


def cleanup_old_incidents(days: int = 90) -> int:
    store = get_store()
    return store.cleanup_old_incidents(days)
