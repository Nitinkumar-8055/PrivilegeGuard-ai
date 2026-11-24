import json
import os
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest

from models import db, Incident, SecurityEvent, Notification, NotificationSetting, CollectorCheckpoint
from services.ingestion import IngestionService
from services.detection_engine import DetectionEngine
from services.correlation import IncidentCorrelationEngine
from services.email_service import EmailService
from services.notification_service import NotificationDispatcher
from services.collector import WindowsSecurityCollector, SimulatedEventSource
from config import Config


def test_end_to_end_json_ingestion_triggers_notifications(app, db_session):
    """
    Ingests synthetic high-severity attack JSON events, triggers detection & correlation,
    and asserts qualifying security notifications are generated.
    """
    sample_attack_events = [
        {
            "event_id": "EVT-INT-001",
            "timestamp": "2026-11-23T10:00:00Z",
            "username": "compromised_admin",
            "event_type": "login_failure",
            "source_ip": "198.51.100.44",
            "outcome": "failure",
            "action": "auth",
            "resource": "ad://domain_controllers"
        },
        {
            "event_id": "EVT-INT-002",
            "timestamp": "2026-11-23T10:01:00Z",
            "username": "compromised_admin",
            "event_type": "login_failure",
            "source_ip": "198.51.100.44",
            "outcome": "failure",
            "action": "auth",
            "resource": "ad://domain_controllers"
        },
        {
            "event_id": "EVT-INT-003",
            "timestamp": "2026-11-23T10:02:00Z",
            "username": "compromised_admin",
            "event_type": "login_failure",
            "source_ip": "198.51.100.44",
            "outcome": "failure",
            "action": "auth",
            "resource": "ad://domain_controllers"
        },
        {
            "event_id": "EVT-INT-004",
            "timestamp": "2026-11-23T10:03:00Z",
            "username": "compromised_admin",
            "event_type": "login_success",
            "source_ip": "198.51.100.44",
            "outcome": "success",
            "action": "auth",
            "resource": "ad://domain_controllers"
        },
        {
            "event_id": "EVT-INT-005",
            "timestamp": "2026-11-23T10:05:00Z",
            "username": "compromised_admin",
            "event_type": "role_change",
            "source_ip": "198.51.100.44",
            "outcome": "success",
            "actor": "compromised_admin",
            "old_role": "user",
            "new_role": "domain_admin",
            "resource": "/api/v1/vault/keys"
        }
    ]

    # Ingest JSON
    json_payload = json.dumps(sample_attack_events)
    res = IngestionService.ingest_json(json_payload)
    assert res["success"] is True
    assert res["accepted_count"] == 5

    # Run detection
    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.asc()).all()
    engine = DetectionEngine(Config())
    alerts = engine.run_detection(events)
    assert len(alerts) > 0

    # Correlate alerts -> triggers NotificationDispatcher
    incidents = IncidentCorrelationEngine.correlate_alerts(alerts, Config())
    assert len(incidents) >= 1

    first_inc = incidents[0]
    # Check notifications generated for this incident
    notifs = Notification.query.filter_by(incident_id=first_inc.id).all()
    assert len(notifs) >= 1

    inapp_notifs = [n for n in notifs if n.channel == "in_app"]
    assert len(inapp_notifs) == 1
    assert inapp_notifs[0].severity in ("critical", "high")
    assert inapp_notifs[0].delivery_status == "delivered"

    if first_inc.severity in ("critical", "high"):
        email_notifs = [n for n in notifs if n.channel == "email"]
        assert len(email_notifs) == 1
        assert email_notifs[0].recipient == "nk8055444@gmail.com"


def test_collector_cycle_and_notification_deduplication(app, db_session):
    """
    Verifies that simulated collector polling cycles correctly correlate incidents
    and respect notification deduplication rules.
    """
    collector = WindowsSecurityCollector.get_instance()
    sim_source = SimulatedEventSource()
    collector.set_event_source(sim_source, "Simulated Adapter")

    # Cycle 1: Collects initial batch
    poll_res1 = collector.poll_once(app)
    assert poll_res1["success"] is True
    collected_first = poll_res1.get("collected_count", 0)

    # Count initial notifications
    init_notif_count = Notification.query.count()

    # Cycle 2: Poll immediately with simulated source returning no new events
    sim_source.events = []  # Empty new events
    poll_res2 = collector.poll_once(app)
    assert poll_res2["success"] is True
    assert poll_res2.get("collected_count", 0) == 0

    # Assert NO duplicate notifications generated when collector polls with no new events (Scenario 2)
    after_empty_count = Notification.query.count()
    assert after_empty_count == init_notif_count
