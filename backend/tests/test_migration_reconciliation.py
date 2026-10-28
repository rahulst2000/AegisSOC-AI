import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path


def test_migration_002_clean_and_reconciliation():
    """
    Validates Alembic 002 migration architecture:
    1. Clean upgrade from 001 to 002 succeeds.
    2. Simulated production state (where detection_rules was pre-created)
       upgrades cleanly without psycopg.errors.DuplicateTable or sqlite3.OperationalError.
    3. Pre-existing rows in detection_rules and incidents are 100% preserved.
    4. Missing extended incident columns are added correctly.
    """
    repo_root = Path(__file__).resolve().parents[2]
    alembic_ini = repo_root / "database" / "alembic.ini"

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_reconcile.db"
        db_url = f"sqlite:///{db_path.as_posix()}"

        # Step 1: Migrate to 001_initial_schema
        res1 = subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                str(alembic_ini),
                "-x",
                f"url={db_url}",
                "upgrade",
                "001_initial_schema",
            ],
            capture_output=True,
            text=True,
            cwd=str(repo_root),
        )
        assert res1.returncode == 0, f"001 failed: {res1.stderr}"

        # Step 2: Seed data and simulate pre-existing detection_rules table (the production condition)
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("INSERT INTO tenants (id, name, status) VALUES ('t-rec-1', 'Reconcile Tenant', 'ACTIVE')")
        cur.execute("""
            INSERT INTO incidents (id, tenant_id, title, description, severity, status, created_at, updated_at)
            VALUES ('inc-rec-1', 't-rec-1', 'Existing Production Incident', 'Testing', 'HIGH', 'OPEN', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """)
        # Pre-create detection_rules table with existing data
        cur.execute("""
            CREATE TABLE detection_rules (
                id TEXT PRIMARY KEY,
                rule_id TEXT UNIQUE,
                tenant_id TEXT,
                name TEXT,
                description TEXT,
                version TEXT DEFAULT '1.0.0',
                enabled BOOLEAN DEFAULT 1,
                severity TEXT DEFAULT 'MEDIUM',
                confidence REAL DEFAULT 0.9,
                event_types JSON DEFAULT '[]',
                conditions JSON DEFAULT '{}',
                mitre_tactics JSON DEFAULT '[]',
                mitre_techniques JSON DEFAULT '[]',
                tags JSON DEFAULT '[]',
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        """)
        cur.execute("""
            INSERT INTO detection_rules (id, rule_id, name, description, severity)
            VALUES ('rule-rec-1', 'AEGIS-SIG-PREEXISTING', 'Pre-existing Detection Rule', 'Preserved', 'CRITICAL')
        """)
        conn.commit()
        conn.close()

        # Step 3: Execute upgrade head (which executes 002_complete_schema)
        res2 = subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                str(alembic_ini),
                "-x",
                f"url={db_url}",
                "upgrade",
                "head",
            ],
            capture_output=True,
            text=True,
            cwd=str(repo_root),
        )
        assert res2.returncode == 0, f"002 upgrade failed on pre-existing table: {res2.stderr}"

        # Step 4: Verify data integrity and column reconciliation
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # Verify pre-existing detection rule row was preserved
        cur.execute("SELECT id, rule_id, name, severity FROM detection_rules WHERE id = 'rule-rec-1'")
        rule_row = cur.fetchone()
        assert rule_row == ("rule-rec-1", "AEGIS-SIG-PREEXISTING", "Pre-existing Detection Rule", "CRITICAL")

        # Verify pre-existing incident row was preserved and new columns are accessible
        cur.execute("SELECT id, title, mitre_techniques, detection_ids FROM incidents WHERE id = 'inc-rec-1'")
        inc_row = cur.fetchone()
        assert inc_row[0] == "inc-rec-1"
        assert inc_row[1] == "Existing Production Incident"

        # Verify all Phase 2-5 tables now exist
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}
        assert "detection_rules" in tables
        assert "detection_results" in tables
        assert "investigations" in tables
        assert "adversary_assessments" in tables
        assert "remediation_actions" in tables
        assert "attack_trajectories" in tables

        conn.close()

        # Step 5: Test idempotence - subsequent upgrade head succeeds with no changes
        res3 = subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                str(alembic_ini),
                "-x",
                f"url={db_url}",
                "upgrade",
                "head",
            ],
            capture_output=True,
            text=True,
            cwd=str(repo_root),
        )
        assert res3.returncode == 0, f"Second upgrade failed: {res3.stderr}"
