import json
from datetime import datetime, timezone, timedelta
from sqlalchemy import func
from models import db, SecurityEvent, Incident, IncidentEvent, DetectionAlert
from services.ingestion import IngestionService
from services.detection_engine import DetectionEngine
from services.correlation import IncidentCorrelationEngine
from config import TestConfig

def test_database_persistence_and_exact_metrics_sync(app, client):
    """
    Verifies that:
    1. Events and incidents persist properly in SQLite.
    2. Incident timelines preserve chronological event ordering.
    3. Dashboard metrics (/api/stats) match real database counts with 0 hardcoding.
    """
    with app.app_context():
        # Ensure clean state
        IncidentEvent.query.delete()
        DetectionAlert.query.delete()
        Incident.query.delete()
        SecurityEvent.query.delete()
        db.session.commit()

        base_time = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)

        # Create two distinct attack scenarios
        # Scenario A: Brute force for user 'user_alpha'
        events_a = [
            {
                "event_id": f"PERSIST-ALPHA-{i}",
                "timestamp": (base_time + timedelta(minutes=i*2)).isoformat(),
                "username": "user_alpha",
                "event_type": "login_failure",
                "outcome": "failure",
                "source_ip": "198.51.100.1"
            }
            for i in range(4)
        ]
        events_a.append({
            "event_id": "PERSIST-ALPHA-SUCC",
            "timestamp": (base_time + timedelta(minutes=10)).isoformat(),
            "username": "user_alpha",
            "event_type": "login_success",
            "outcome": "success",
            "source_ip": "198.51.100.1"
        })

        # Scenario B: Escalation + sensitive access for user 'user_beta'
        events_b = [
            {
                "event_id": "PERSIST-BETA-ROLE",
                "timestamp": (base_time + timedelta(minutes=20)).isoformat(),
                "username": "user_beta",
                "event_type": "role_change",
                "old_role": "analyst",
                "new_role": "root",
                "actor": "user_beta",
                "outcome": "success"
            },
            {
                "event_id": "PERSIST-BETA-ACCESS",
                "timestamp": (base_time + timedelta(minutes=25)).isoformat(),
                "username": "user_beta",
                "event_type": "resource_access",
                "resource": "/api/v1/vault/keys",
                "outcome": "success"
            }
        ]

        all_events_payload = events_a + events_b
        ingest_res = IngestionService.ingest_json(json.dumps(all_events_payload))
        assert ingest_res["accepted_count"] == 7
        assert ingest_res["rejected_count"] == 0

        # Run detection and correlation
        all_db_events = SecurityEvent.query.order_by(SecurityEvent.timestamp.asc()).all()
        engine = DetectionEngine(TestConfig)
        alerts = engine.run_detection(all_db_events)
        incidents = IncidentCorrelationEngine.correlate_alerts(alerts, TestConfig)

        # Assert two distinct incidents created
        assert len(incidents) == 2

        # Verify real database counts
        db_events_count = SecurityEvent.query.count()
        db_incidents_count = Incident.query.count()
        db_high_crit_count = Incident.query.filter(Incident.severity.in_(["high", "critical"])).count()
        db_distinct_users = db.session.query(func.count(func.distinct(Incident.affected_user))).scalar()

        assert db_events_count == 7
        assert db_incidents_count == 2
        assert db_high_crit_count == 2
        assert db_distinct_users == 2

        # Verify timeline chronological ordering in incident
        beta_inc = Incident.query.filter_by(affected_user="user_beta").first()
        assert beta_inc is not None
        assert len(beta_inc.events) == 2
        assert beta_inc.events[0].event_id == "PERSIST-BETA-ROLE"
        assert beta_inc.events[1].event_id == "PERSIST-BETA-ACCESS"
        assert beta_inc.events[0].timestamp <= beta_inc.events[1].timestamp

    # Query the live stats API endpoint
    res = client.get("/api/stats")
    assert res.status_code == 200
    stats = res.get_json()

    # Verify that API statistics directly and accurately match the database counts (NO HARDCODING)
    assert stats["total_events"] == 7
    assert stats["total_incidents"] == 2
    assert stats["high_critical_count"] == 2
    assert stats["affected_identities_count"] == 2
    assert stats["severity_distribution"]["critical"] >= 1
    assert len(stats["recent_incidents"]) == 2
