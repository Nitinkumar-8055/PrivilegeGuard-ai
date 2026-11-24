import json
import os
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest

from models import db, Incident, SecurityEvent, DetectionAlert, Notification, NotificationSetting, AuditLog
from services.email_service import EmailService, is_valid_email, sanitize_header
from services.notification_service import NotificationDispatcher, NotificationWorker
from services.correlation import IncidentCorrelationEngine
from config import Config


def test_email_helper_validation():
    """Verify email format validation and header sanitization."""
    assert is_valid_email("nk8055444@gmail.com") is True
    assert is_valid_email("admin@domain.corp") is True
    assert is_valid_email("invalid-email") is False
    assert is_valid_email("") is False
    assert is_valid_email(None) is False

    header_input = "Security Alert\r\nBcc: evil@attacker.com\nSubject: Injected"
    sanitized = sanitize_header(header_input)
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert "evil@attacker.com" in sanitized


def test_notification_models_and_settings(app, db_session):
    """Verify Notification and NotificationSetting persistence and dictionary serialization."""
    inc = Incident(
        incident_id="INC-2026-TEST-01",
        title="Test Incident Title",
        affected_user="secops_test",
        severity="critical",
        risk_score=95,
        status="New",
        first_observed_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc)
    )
    db_session.add(inc)
    db_session.commit()

    notif = Notification(
        incident_id=inc.id,
        recipient="nk8055444@gmail.com",
        channel="in_app",
        severity="critical",
        title="[CRITICAL] Test Incident Title",
        message="A critical threat has been detected.",
        is_read=False,
        delivery_status="delivered"
    )
    db_session.add(notif)
    db_session.commit()

    assert notif.id is not None
    data = notif.to_dict()
    assert data["incident_ref"] == "INC-2026-TEST-01"
    assert data["severity"] == "critical"
    assert data["is_read"] is False

    # Test key-value NotificationSetting
    NotificationSetting.set("admin_email", "admin_custom@corp.local")
    NotificationSetting.set("email_severities", ["critical"])
    db_session.commit()

    assert NotificationSetting.get("admin_email") == "admin_custom@corp.local"
    assert NotificationSetting.get("email_severities") == ["critical"]
    assert NotificationSetting.get("non_existent_key", "default_val") == "default_val"


def test_test_email_delivery_mocked(app, db_session):
    """Verify send_test_email functionality with mocked SMTP."""
    with patch("smtplib.SMTP_SSL") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_instance

        # Test with environment password
        with patch.dict(os.environ, {"SMTP_PASSWORD": "dummy-app-password"}):
            res = EmailService.send_test_email("nk8055444@gmail.com")
            assert res["success"] is True
            assert res["recipient"] == "nk8055444@gmail.com"
            assert mock_instance.login.called
            assert mock_instance.send_message.called


def test_missing_credentials_handling(app, db_session):
    """Verify graceful handling when SMTP_PASSWORD is not set."""
    with patch.dict(os.environ, {"SMTP_PASSWORD": ""}):
        res = EmailService.send_test_email("nk8055444@gmail.com")
        assert res["success"] is False
        assert "SMTP_PASSWORD is not set" in res["error"]


def test_qualifying_incident_notifications(app, db_session):
    """
    Scenario 1: CRITICAL and HIGH incidents trigger both In-App and Email notifications.
    MEDIUM and LOW incidents trigger In-App only.
    """
    # 1. Critical Incident
    inc_crit = Incident(
        incident_id="INC-2026-0010",
        title="Security Audit Log Tampering",
        affected_user="attacker_01",
        severity="critical",
        risk_score=95,
        status="New",
        first_observed_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc)
    )
    db_session.add(inc_crit)
    db_session.commit()

    notifs_crit = NotificationDispatcher.dispatch_incident_notification(inc_crit, is_new=True)
    channels_crit = [n.channel for n in notifs_crit]
    assert "in_app" in channels_crit
    assert "email" in channels_crit
    assert len(notifs_crit) == 2

    # 2. High Incident
    inc_high = Incident(
        incident_id="INC-2026-0011",
        title="Unauthorized Privilege Grant and Role Modification",
        affected_user="contractor_joe",
        severity="high",
        risk_score=75,
        status="New",
        first_observed_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc)
    )
    db_session.add(inc_high)
    db_session.commit()

    notifs_high = NotificationDispatcher.dispatch_incident_notification(inc_high, is_new=True)
    channels_high = [n.channel for n in notifs_high]
    assert "in_app" in channels_high
    assert "email" in channels_high
    assert len(notifs_high) == 2

    # 3. Medium Incident (In-App only by default)
    inc_med = Incident(
        incident_id="INC-2026-0012",
        title="Failed Authentication Burst",
        affected_user="user_bob",
        severity="medium",
        risk_score=45,
        status="New",
        first_observed_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc)
    )
    db_session.add(inc_med)
    db_session.commit()

    notifs_med = NotificationDispatcher.dispatch_incident_notification(inc_med, is_new=True)
    channels_med = [n.channel for n in notifs_med]
    assert "in_app" in channels_med
    assert "email" not in channels_med
    assert len(notifs_med) == 1

    # 4. Low Incident (In-App only by default)
    inc_low = Incident(
        incident_id="INC-2026-0013",
        title="Normal Off-Hours Login Activity",
        affected_user="user_alice",
        severity="low",
        risk_score=15,
        status="New",
        first_observed_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc)
    )
    db_session.add(inc_low)
    db_session.commit()

    notifs_low = NotificationDispatcher.dispatch_incident_notification(inc_low, is_new=True)
    channels_low = [n.channel for n in notifs_low]
    assert "in_app" in channels_low
    assert "email" not in channels_low
    assert len(notifs_low) == 1


def test_deduplication_and_escalation_scenarios(app, db_session):
    """
    Scenario 3: Evidence added without severity change -> No duplicate email.
    Scenario 4: Severity escalates (HIGH -> CRITICAL) -> New notification generated.
    """
    inc = Incident(
        incident_id="INC-2026-0020",
        title="Suspicious Role Activity",
        affected_user="admin_target",
        severity="high",
        risk_score=65,
        status="New",
        first_observed_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc)
    )
    db_session.add(inc)
    db_session.commit()

    # Initial dispatch
    first_dispatch = NotificationDispatcher.dispatch_incident_notification(inc, is_new=True)
    assert len(first_dispatch) == 2  # 1 in_app, 1 email

    # Scenario 3: More events arrive, but severity is unchanged (high -> high)
    inc.risk_score = 70
    inc.severity = "high"
    db_session.commit()

    second_dispatch = NotificationDispatcher.dispatch_incident_notification(
        inc,
        is_new=False,
        old_severity="high"
    )
    assert len(second_dispatch) == 0  # Deduplicated! No duplicate notification!

    # Scenario 4: Severity escalates to CRITICAL (high -> critical)
    inc.risk_score = 95
    inc.severity = "critical"
    db_session.commit()

    escalation_dispatch = NotificationDispatcher.dispatch_incident_notification(
        inc,
        is_new=False,
        old_severity="high"
    )
    assert len(escalation_dispatch) == 2  # Escalation generated for both channels!
    for notif in escalation_dispatch:
        assert "[ESCALATION" in notif.title
        assert notif.severity == "critical"

    # Subsequent re-evaluation of same escalated state -> deduplicated
    repeat_escalation = NotificationDispatcher.dispatch_incident_notification(
        inc,
        is_new=False,
        old_severity="critical"
    )
    assert len(repeat_escalation) == 0


def test_api_notification_routes(client, app, db_session):
    """Verify REST API notification listing, filtering, marking read/unread, and dismissing."""
    inc = Incident(
        incident_id="INC-2026-0030",
        title="Credential Harvesting Attempt",
        affected_user="secops_analyst",
        severity="high",
        risk_score=72,
        status="New",
        first_observed_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc)
    )
    db_session.add(inc)
    db_session.commit()

    n1 = Notification(
        incident_id=inc.id,
        recipient="nk8055444@gmail.com",
        channel="in_app",
        severity="high",
        title="[HIGH] Credential Harvesting",
        message="Suspicious login pattern detected.",
        is_read=False,
        delivery_status="delivered"
    )
    n2 = Notification(
        incident_id=inc.id,
        recipient="nk8055444@gmail.com",
        channel="email",
        severity="high",
        title="[HIGH] Credential Harvesting Email",
        message="Email dispatch details.",
        is_read=True,
        delivery_status="sent"
    )
    db_session.add_all([n1, n2])
    db_session.commit()

    # 1. Unread count endpoint
    resp = client.get("/api/notifications/unread-count")
    assert resp.status_code == 200
    assert resp.get_json()["unread_count"] == 1

    # 2. Recent endpoint
    resp_recent = client.get("/api/notifications/recent")
    assert resp_recent.status_code == 200
    assert len(resp_recent.get_json()["notifications"]) == 2

    # 3. Filtering by channel
    resp_email = client.get("/api/notifications?channel=email")
    assert resp_email.status_code == 200
    assert resp_email.get_json()["total"] == 1

    # 4. Mark single as read
    resp_read = client.post(f"/api/notifications/{n1.id}/read")
    assert resp_read.status_code == 200
    assert resp_read.get_json()["unread_count"] == 0

    # 5. Mark single as unread
    resp_unread = client.post(f"/api/notifications/{n1.id}/unread")
    assert resp_unread.status_code == 200
    assert resp_unread.get_json()["unread_count"] == 1

    # 6. Mark all read
    resp_mark_all = client.post("/api/notifications/mark-all-read")
    assert resp_mark_all.status_code == 200
    assert resp_mark_all.get_json()["unread_count"] == 0

    # 7. Dismiss (delete) notification
    resp_del = client.delete(f"/api/notifications/{n1.id}")
    assert resp_del.status_code == 200
    assert db_session.get(Notification, n1.id) is None


def test_api_notification_settings_routes(client, app, db_session):
    """Verify settings retrieval, validation, and update."""
    # 1. Get settings
    resp = client.get("/api/notifications/settings")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "settings" in data
    assert "status" in data
    # Ensure password is NEVER leaked
    assert "smtp_password" not in data["settings"]
    assert "SMTP_PASSWORD" not in str(data)

    # 2. Invalid email format rejection
    resp_bad = client.post(
        "/api/notifications/settings",
        json={"admin_email": "not-an-email"}
    )
    assert resp_bad.status_code == 400
    assert "Invalid recipient email" in resp_bad.get_json()["error"]

    # 3. Valid update
    resp_update = client.post(
        "/api/notifications/settings",
        json={
            "admin_email": "security_officer@privilegeguard.ai",
            "email_enabled": True,
            "inapp_enabled": True,
            "email_severities": ["critical", "high"],
            "inapp_severities": ["critical", "high", "medium", "low"],
            "smtp_port": 465,
            "smtp_security": "SSL"
        }
    )
    assert resp_update.status_code == 200
    assert resp_update.get_json()["success"] is True

    # Verify audit log was recorded
    audit = AuditLog.query.filter_by(action_type="NOTIFICATION_SETTINGS_UPDATED").first()
    assert audit is not None


def test_background_worker_execution(app, db_session):
    """Verify that NotificationWorker processes queued emails."""
    inc = Incident(
        incident_id="INC-2026-WORKER-01",
        title="Threat Emulation For Background Worker",
        affected_user="secops_worker",
        severity="critical",
        risk_score=90,
        status="New",
        first_observed_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc)
    )
    db_session.add(inc)
    db_session.commit()

    notif = Notification(
        incident_id=inc.id,
        recipient="nk8055444@gmail.com",
        channel="email",
        severity="critical",
        title="[CRITICAL] Threat Emulation",
        message="Background worker processing test.",
        delivery_status="pending"
    )
    db_session.add(notif)
    db_session.commit()

    worker = NotificationWorker(app)

    with patch.object(EmailService, "send_smtp_message", return_value={"success": True, "error": None}) as mock_send:
        worker._process_email_notification(notif.id)
        assert mock_send.called

        db_session.expire_all()
        updated_notif = db_session.get(Notification, notif.id)
        assert updated_notif.delivery_status == "sent"
        assert updated_notif.sent_at is not None
