from datetime import datetime, timezone, timedelta
from services.detection_engine import DetectionEngine
from models import SecurityEvent
from config import TestConfig

class MockEvent:
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", 1)
        self.event_id = kwargs.get("event_id", "EVT-MOCK-01")
        self.timestamp = kwargs.get("timestamp", datetime.now(timezone.utc))
        self.username = kwargs.get("username", "test_user")
        self.event_type = kwargs.get("event_type", "login_success")
        self.source_ip = kwargs.get("source_ip", "10.0.0.1")
        self.outcome = kwargs.get("outcome", "success")
        self.actor = kwargs.get("actor", None)
        self.old_role = kwargs.get("old_role", None)
        self.new_role = kwargs.get("new_role", None)
        self.resource = kwargs.get("resource", None)
        self.action = kwargs.get("action", None)
        self.session_id = kwargs.get("session_id", None)


def test_rule_repeated_failed_logins_without_success():
    engine = DetectionEngine(TestConfig)
    base_time = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
    
    events = [
        MockEvent(event_id=f"FAIL-{i}", timestamp=base_time + timedelta(minutes=i*2), username="bob", event_type="login_failure", outcome="failure")
        for i in range(4)
    ]
    alerts = engine.run_detection(events)
    r1_alerts = [a for a in alerts if a["rule_id"] == "RULE-001"]
    
    assert len(r1_alerts) == 1
    assert r1_alerts[0]["affected_user"] == "bob"
    assert r1_alerts[0]["severity"] == "medium"
    assert len(r1_alerts[0]["relevant_event_ids"]) == 4


def test_rule_repeated_failed_logins_with_subsequent_success():
    engine = DetectionEngine(TestConfig)
    base_time = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
    
    events = [
        MockEvent(event_id=f"FAIL-{i}", timestamp=base_time + timedelta(minutes=i*2), username="target_user", event_type="login_failure", outcome="failure")
        for i in range(4)
    ]
    # Followed by success from the same user within 10 minutes
    events.append(
        MockEvent(event_id="SUCCESS-WIN", timestamp=base_time + timedelta(minutes=10), username="target_user", event_type="login_success", outcome="success", source_ip="203.0.113.10")
    )
    
    alerts = engine.run_detection(events)
    r1_alerts = [a for a in alerts if a["rule_id"] == "RULE-001"]
    
    assert len(r1_alerts) == 1
    assert r1_alerts[0]["severity"] == "high"
    assert "SUCCESS-WIN" in r1_alerts[0]["relevant_event_ids"]
    assert "credential stuffing" in r1_alerts[0]["reason"].lower() or "brute-force" in r1_alerts[0]["reason"].lower()


def test_rule_unexpected_privilege_escalation():
    engine = DetectionEngine(TestConfig)
    base_time = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    events = [
        MockEvent(
            event_id="ESCAL-01",
            timestamp=base_time,
            username="clara",
            actor="clara",  # Self-elevation
            event_type="role_change",
            old_role="viewer",
            new_role="administrator",
            outcome="success"
        )
    ]
    alerts = engine.run_detection(events)
    r2_alerts = [a for a in alerts if a["rule_id"] == "RULE-002"]
    
    assert len(r2_alerts) == 1
    assert r2_alerts[0]["affected_user"] == "clara"
    assert r2_alerts[0]["severity"] == "critical"  # self-elevation triggers critical
    assert "self-elevation" in r2_alerts[0]["reason"]


def test_rule_unauthorized_privilege_grant():
    engine = DetectionEngine(TestConfig)
    base_time = datetime(2026, 10, 15, 13, 0, 0, tzinfo=timezone.utc)
    
    events = [
        MockEvent(
            event_id="GRANT-01",
            timestamp=base_time,
            username="intern_sam",
            actor="unauthorized_contractor_jim",
            event_type="role_change",
            old_role="user",
            new_role="secops_admin",
            outcome="success"
        )
    ]
    alerts = engine.run_detection(events)
    r3_alerts = [a for a in alerts if a["rule_id"] == "RULE-003"]
    
    assert len(r3_alerts) == 1
    assert r3_alerts[0]["affected_user"] == "intern_sam"
    assert "unauthorized_contractor_jim" in r3_alerts[0]["reason"]


def test_rule_sensitive_access_following_privilege_change():
    engine = DetectionEngine(TestConfig)
    base_time = datetime(2026, 10, 15, 14, 0, 0, tzinfo=timezone.utc)
    
    events = [
        MockEvent(
            event_id="PRIV-CHANGE-01",
            timestamp=base_time,
            username="marcus",
            event_type="role_change",
            old_role="operator",
            new_role="root",
            outcome="success"
        ),
        MockEvent(
            event_id="ACCESS-SENS-01",
            timestamp=base_time + timedelta(minutes=5),
            username="marcus",
            event_type="resource_access",
            resource="/api/v1/vault/keys",
            outcome="success"
        )
    ]
    alerts = engine.run_detection(events)
    r4_alerts = [a for a in alerts if a["rule_id"] == "RULE-004"]
    
    assert len(r4_alerts) == 1
    assert r4_alerts[0]["severity"] == "critical"
    assert "PRIV-CHANGE-01" in r4_alerts[0]["relevant_event_ids"]
    assert "ACCESS-SENS-01" in r4_alerts[0]["relevant_event_ids"]


def test_legitimate_admin_activity_does_not_trigger_false_criticals():
    engine = DetectionEngine(TestConfig)
    base_time = datetime(2026, 10, 15, 15, 0, 0, tzinfo=timezone.utc)
    
    # Authorized administrator performs authorized service account role maintenance
    events = [
        MockEvent(
            event_id="LEGIT-01",
            timestamp=base_time,
            username="backup_service",
            actor="secops_admin",  # Authorized manager in config
            event_type="role_change",
            old_role="service_account",
            new_role="backup_operator",
            outcome="success"
        ),
        MockEvent(
            event_id="LEGIT-02",
            timestamp=base_time + timedelta(minutes=3),
            username="secops_admin",
            actor="secops_admin",
            event_type="resource_access",
            resource="portal://admin/health_check",
            outcome="success"
        )
    ]
    alerts = engine.run_detection(events)
    # Neither RULE-003 (unauthorized actor) nor RULE-004 (vault keys access) nor RULE-001 (brute force) should trigger
    r3_alerts = [a for a in alerts if a["rule_id"] == "RULE-003"]
    r4_alerts = [a for a in alerts if a["rule_id"] == "RULE-004"]
    assert len(r3_alerts) == 0
    assert len(r4_alerts) == 0


def test_normal_user_routine_activity_triggers_zero_alerts():
    """Verify that routine everyday user logins and document reads produce 0 alerts (0 false positives)."""
    engine = DetectionEngine(TestConfig)
    base_time = datetime(2026, 10, 15, 9, 0, 0, tzinfo=timezone.utc)
    
    events = [
        MockEvent(
            event_id="NORM-01",
            timestamp=base_time,
            username="emily.watson",
            actor="emily.watson",
            event_type="login_success",
            outcome="success",
            source_ip="10.0.4.15"
        ),
        MockEvent(
            event_id="NORM-02",
            timestamp=base_time + timedelta(minutes=5),
            username="emily.watson",
            actor="emily.watson",
            event_type="resource_access",
            resource="git://repos/privilegeguard-core",
            outcome="success"
        ),
        MockEvent(
            event_id="NORM-03",
            timestamp=base_time + timedelta(minutes=10),
            username="emily.watson",
            actor="emily.watson",
            event_type="resource_access",
            resource="wiki://engineering-guidelines",
            outcome="success"
        )
    ]
    alerts = engine.run_detection(events)
    assert len(alerts) == 0, f"Expected 0 alerts for normal user activity, but got: {alerts}"
