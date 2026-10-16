import json
from datetime import datetime, timezone, timedelta
from models import SecurityEvent, Incident, IncidentEvent
from services.ingestion import IngestionService
from services.detection_engine import DetectionEngine
from services.correlation import IncidentCorrelationEngine
from config import TestConfig

def test_incident_correlation_and_deduplication(app):
    with app.app_context():
        base_time = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
        
        # Ingest events for user 'victim_alex'
        events_payload = [
            {
                "event_id": f"CORR-FAIL-{i}",
                "timestamp": (base_time + timedelta(minutes=i*2)).isoformat(),
                "username": "victim_alex",
                "event_type": "login_failure",
                "outcome": "failure",
                "source_ip": "198.51.100.9"
            }
            for i in range(4)
        ]
        events_payload.append({
            "event_id": "CORR-SUCCESS-01",
            "timestamp": (base_time + timedelta(minutes=10)).isoformat(),
            "username": "victim_alex",
            "event_type": "login_success",
            "outcome": "success",
            "source_ip": "198.51.100.9"
        })

        ingest_res = IngestionService.ingest_json(json.dumps(events_payload))
        assert ingest_res["accepted_count"] == 5

        # Run detection
        db_events = SecurityEvent.query.filter_by(username="victim_alex").all()
        engine = DetectionEngine(TestConfig)
        alerts = engine.run_detection(db_events)
        assert len(alerts) >= 1

        # Correlate into incidents
        incidents = IncidentCorrelationEngine.correlate_alerts(alerts, TestConfig)
        assert len(incidents) == 1
        incident = incidents[0]

        assert incident.affected_user == "victim_alex"
        assert incident.risk_score >= 60  # High or critical
        assert incident.status == "New"
        assert len(incident.events) == 5

        # Verify chronology of incident events
        for idx in range(len(incident.events) - 1):
            assert incident.events[idx].timestamp <= incident.events[idx + 1].timestamp

        # Now test DEDUPLICATION: re-run correlation with the same alerts
        incidents_run_2 = IncidentCorrelationEngine.correlate_alerts(alerts, TestConfig)
        assert len(incidents_run_2) == 1
        # Incident count in database should still be 1!
        total_in_db = Incident.query.count()
        assert total_in_db == 1
        assert incidents_run_2[0].id == incident.id
