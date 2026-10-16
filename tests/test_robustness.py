import json
import sqlite3
import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy.exc import OperationalError
from models import db, SecurityEvent, Incident, IncidentEvent, DetectionAlert
from services.ingestion import IngestionService
from services.correlation import IncidentCorrelationEngine, _is_sqlite_locked_error
from config import TestConfig, BASE_DIR

def test_ip_address_validation_ipv4_and_ipv6(app):
    """Verify that IPv4 and IPv6 addresses are accepted, while invalid IPs are rejected."""
    with app.app_context():
        # Valid IPv4
        v4_data = json.dumps([{
            "event_id": "IP-TEST-001",
            "timestamp": "2026-10-16T12:00:00Z",
            "username": "network_user",
            "event_type": "login_success",
            "outcome": "success",
            "source_ip": "192.168.1.100"
        }])
        res_v4 = IngestionService.ingest_json(v4_data)
        assert res_v4["accepted_count"] == 1
        assert res_v4["rejected_count"] == 0

        # Valid IPv6
        v6_data = json.dumps([{
            "event_id": "IP-TEST-002",
            "timestamp": "2026-10-16T12:01:00Z",
            "username": "network_user",
            "event_type": "login_success",
            "outcome": "success",
            "source_ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        }])
        res_v6 = IngestionService.ingest_json(v6_data)
        assert res_v6["accepted_count"] == 1
        assert res_v6["rejected_count"] == 0

        # Invalid IP (out-of-range octet)
        bad_ip_data = json.dumps([{
            "event_id": "IP-TEST-003",
            "timestamp": "2026-10-16T12:02:00Z",
            "username": "network_user",
            "event_type": "login_success",
            "outcome": "success",
            "source_ip": "999.168.1.1"
        }])
        res_bad = IngestionService.ingest_json(bad_ip_data)
        assert res_bad["accepted_count"] == 0
        assert res_bad["rejected_count"] == 1
        assert "Invalid IP address format" in res_bad["rejected_records"][0]["reason"]


def test_batch_partial_success_and_duplicate_tracking(app):
    """Verify that batches with mixed valid, invalid, and duplicate records process cleanly."""
    with app.app_context():
        batch = json.dumps([
            {
                "event_id": "BATCH-P-1",
                "timestamp": "2026-10-16T12:10:00Z",
                "username": "  user_padded  ",  # Tests username trimming
                "event_type": "login_success",
                "outcome": "success"
            },
            {
                "event_id": "BATCH-P-2",
                "timestamp": "2026-10-16T12:11:00Z",
                "username": "user_two",
                "event_type": "resource_access",
                "outcome": "success"
            },
            {
                "event_id": "BATCH-P-2",  # Duplicate in same batch
                "timestamp": "2026-10-16T12:12:00Z",
                "username": "user_two",
                "event_type": "resource_access",
                "outcome": "success"
            },
            {
                "event_id": "BATCH-P-3",
                "timestamp": "2026-10-16T12:13:00Z",
                "username": "",  # Empty username
                "event_type": "login_failure",
                "outcome": "failure"
            }
        ])
        result = IngestionService.ingest_json(batch)
        assert result["total_records"] == 4
        assert result["accepted_count"] == 2
        assert result["rejected_count"] == 2
        assert result["duplicate_count"] == 1

        # Check that username was stripped
        ev = SecurityEvent.query.filter_by(event_id="BATCH-P-1").first()
        assert ev.username == "user_padded"


def test_incident_id_monotonic_and_collision_proof(app):
    """Verify that generate_incident_id correctly increments and never produces collisions."""
    with app.app_context():
        reserved = set()
        id1 = IncidentCorrelationEngine.generate_incident_id(reserved)
        id2 = IncidentCorrelationEngine.generate_incident_id(reserved)
        id3 = IncidentCorrelationEngine.generate_incident_id(reserved)

        assert id1 != id2
        assert id2 != id3
        assert id1 in reserved
        assert id2 in reserved
        assert id3 in reserved

        # Check sequence numbers
        seq1 = int(id1.split("-")[-1])
        seq2 = int(id2.split("-")[-1])
        seq3 = int(id3.split("-")[-1])
        assert seq2 == seq1 + 1
        assert seq3 == seq2 + 1


def test_sqlite_locked_error_detection():
    """Verify that _is_sqlite_locked_error accurately detects SQLite lock messages."""
    lock_err = OperationalError("statement", {}, Exception("database is locked"))
    busy_err = OperationalError("statement", {}, Exception("database is busy"))
    table_lock = OperationalError("statement", {}, Exception("database table is locked"))
    other_err = OperationalError("statement", {}, Exception("no such table: test"))

    assert _is_sqlite_locked_error(lock_err) is True
    assert _is_sqlite_locked_error(busy_err) is True
    assert _is_sqlite_locked_error(table_lock) is True
    assert _is_sqlite_locked_error(other_err) is False


def test_production_database_integrity_verified():
    """Strict verification that privilegeguard.db historical records remain intact and untouched."""
    prod_db_path = BASE_DIR / "privilegeguard.db"
    assert prod_db_path.exists(), "Production database file privilegeguard.db must exist"

    conn = sqlite3.connect(str(prod_db_path))
    cur = conn.cursor()
    events_count = cur.execute("SELECT count(*) FROM security_events").fetchone()[0]
    incidents_count = cur.execute("SELECT count(*) FROM incidents").fetchone()[0]
    alerts_count = cur.execute("SELECT count(*) FROM detection_alerts").fetchone()[0]
    incident_events_count = cur.execute("SELECT count(*) FROM incident_events").fetchone()[0]
    audit_logs_count = cur.execute("SELECT count(*) FROM audit_logs").fetchone()[0]
    conn.close()

    assert events_count == 12, f"Expected 12 production security events, found {events_count}"
    assert incidents_count == 2, f"Expected 2 production incidents, found {incidents_count}"
    assert alerts_count == 4, f"Expected 4 production detection alerts, found {alerts_count}"
    assert incident_events_count == 6, f"Expected 6 production incident events, found {incident_events_count}"
    assert audit_logs_count == 23, f"Expected 23 production audit logs, found {audit_logs_count}"
