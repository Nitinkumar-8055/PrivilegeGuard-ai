import json
from datetime import datetime, timezone, timedelta
import pytest

from services.windows_parser import WindowsEventParser
from services.collector import WindowsSecurityCollector, SimulatedEventSource
from services.detection_engine import DetectionEngine
from services.correlation import IncidentCorrelationEngine
from models import db, SecurityEvent, Incident, DetectionAlert, CollectorCheckpoint
from config import TestConfig

SAMPLE_XML_4624 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4624</EventID>
    <EventRecordID>5001</EventRecordID>
    <TimeCreated SystemTime='2026-10-26T18:00:00.0000000Z'/>
    <Channel>Security</Channel>
    <Computer>WIN-SRV01</Computer>
  </System>
  <EventData>
    <Data Name='TargetUserName'>jdoe</Data>
    <Data Name='TargetDomainName'>CORP</Data>
    <Data Name='IpAddress'>192.168.1.105</Data>
    <Data Name='LogonType'>2</Data>
  </EventData>
</Event>"""

SAMPLE_XML_4625 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4625</EventID>
    <EventRecordID>5002</EventRecordID>
    <TimeCreated SystemTime='2026-10-26T18:01:00.0000000Z'/>
    <Channel>Security</Channel>
    <Computer>WIN-SRV01</Computer>
  </System>
  <EventData>
    <Data Name='TargetUserName'>jdoe</Data>
    <Data Name='TargetDomainName'>CORP</Data>
    <Data Name='IpAddress'>192.168.1.105</Data>
    <Data Name='Status'>0xC000006D</Data>
    <Data Name='SubStatus'>0xC000006A</Data>
  </EventData>
</Event>"""

SAMPLE_XML_4634 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4634</EventID>
    <EventRecordID>5003</EventRecordID>
    <TimeCreated SystemTime='2026-10-26T18:02:00.0000000Z'/>
    <Channel>Security</Channel>
    <Computer>WIN-SRV01</Computer>
  </System>
  <EventData>
    <Data Name='TargetUserName'>jdoe</Data>
    <Data Name='TargetDomainName'>CORP</Data>
  </EventData>
</Event>"""

SAMPLE_XML_4648 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4648</EventID>
    <EventRecordID>5004</EventRecordID>
    <TimeCreated SystemTime='2026-10-26T18:03:00.0000000Z'/>
    <Channel>Security</Channel>
    <Computer>WIN-SRV01</Computer>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>local_user</Data>
    <Data Name='TargetUserName'>admin_user</Data>
    <Data Name='TargetServerName'>DC01.CORP</Data>
    <Data Name='IpAddress'>10.0.0.12</Data>
  </EventData>
</Event>"""

SAMPLE_XML_4672 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4672</EventID>
    <EventRecordID>5005</EventRecordID>
    <TimeCreated SystemTime='2026-10-26T18:04:00.0000000Z'/>
    <Channel>Security</Channel>
    <Computer>WIN-SRV01</Computer>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>admin_user</Data>
    <Data Name='PrivilegeList'>SeDebugPrivilege&#x000D;&#x000A;SeTcbPrivilege</Data>
  </EventData>
</Event>"""

SAMPLE_XML_4720 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4720</EventID>
    <EventRecordID>5006</EventRecordID>
    <TimeCreated SystemTime='2026-10-26T18:05:00.0000000Z'/>
    <Channel>Security</Channel>
    <Computer>WIN-SRV01</Computer>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>secops_admin</Data>
    <Data Name='TargetUserName'>new_contractor</Data>
  </EventData>
</Event>"""

SAMPLE_XML_4722 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4722</EventID>
    <EventRecordID>5007</EventRecordID>
    <TimeCreated SystemTime='2026-10-26T18:06:00.0000000Z'/>
    <Channel>Security</Channel>
    <Computer>WIN-SRV01</Computer>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>secops_admin</Data>
    <Data Name='TargetUserName'>new_contractor</Data>
  </EventData>
</Event>"""

SAMPLE_XML_4732 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4732</EventID>
    <EventRecordID>5008</EventRecordID>
    <TimeCreated SystemTime='2026-10-26T18:07:00.0000000Z'/>
    <Channel>Security</Channel>
    <Computer>WIN-SRV01</Computer>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>rogue_admin</Data>
    <Data Name='MemberName'>CN=evil_backdoor,OU=Users,DC=corp</Data>
    <Data Name='TargetUserName'>Administrators</Data>
  </EventData>
</Event>"""

SAMPLE_XML_4738 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4738</EventID>
    <EventRecordID>5009</EventRecordID>
    <TimeCreated SystemTime='2026-10-26T18:08:00.0000000Z'/>
    <Channel>Security</Channel>
    <Computer>WIN-SRV01</Computer>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>admin_user</Data>
    <Data Name='TargetUserName'>some_user</Data>
  </EventData>
</Event>"""

SAMPLE_XML_4740 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4740</EventID>
    <EventRecordID>5010</EventRecordID>
    <TimeCreated SystemTime='2026-10-26T18:09:00.0000000Z'/>
    <Channel>Security</Channel>
    <Computer>WIN-SRV01</Computer>
  </System>
  <EventData>
    <Data Name='TargetUserName'>locked_user</Data>
  </EventData>
</Event>"""

SAMPLE_XML_1102 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>1102</EventID>
    <EventRecordID>5011</EventRecordID>
    <TimeCreated SystemTime='2026-10-26T18:10:00.0000000Z'/>
    <Channel>Security</Channel>
    <Computer>WIN-SRV01</Computer>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>malicious_user</Data>
    <Data Name='SubjectDomainName'>CORP</Data>
  </EventData>
</Event>"""


def test_windows_parser_all_mapped_event_ids():
    """Verify that every required Windows Security Event ID maps cleanly to the schema."""
    samples = [
        (SAMPLE_XML_4624, "login_success", "success", "WIN-SEC-5001"),
        (SAMPLE_XML_4625, "login_failure", "failure", "WIN-SEC-5002"),
        (SAMPLE_XML_4634, "resource_access", "success", "WIN-SEC-5003"),
        (SAMPLE_XML_4648, "login_success", "success", "WIN-SEC-5004"),
        (SAMPLE_XML_4672, "permission_grant", "success", "WIN-SEC-5005"),
        (SAMPLE_XML_4720, "role_change", "success", "WIN-SEC-5006"),
        (SAMPLE_XML_4722, "role_change", "success", "WIN-SEC-5007"),
        (SAMPLE_XML_4732, "role_change", "success", "WIN-SEC-5008"),
        (SAMPLE_XML_4738, "role_change", "success", "WIN-SEC-5009"),
        (SAMPLE_XML_4740, "access_denied", "failure", "WIN-SEC-5010"),
        (SAMPLE_XML_1102, "access_denied", "success", "WIN-SEC-5011")
    ]

    for xml_text, expected_type, expected_outcome, expected_eid in samples:
        parsed = WindowsEventParser.parse_xml_to_dict(xml_text)
        assert parsed is not None, f"Failed parsing XML for {expected_eid}"
        norm = WindowsEventParser.normalize_event(parsed)
        assert norm is not None, f"Failed normalizing event for {expected_eid}"
        assert norm["event_id"] == expected_eid
        assert norm["event_type"] == expected_type
        assert norm["outcome"] == expected_outcome
        assert norm["username"] is not None
        assert norm["timestamp"] is not None
        assert "raw_data" in norm


def test_collector_duplicate_prevention_across_polling(app):
    """Verify that already-collected events are never duplicated across polls or restarts."""
    with app.app_context():
        collector = WindowsSecurityCollector.get_instance()
        sim_source = SimulatedEventSource()
        collector.set_event_source(sim_source, "Simulated Adapter")
        collector.last_record_id = 0

        # Queue one event
        sim_source.queue_event_xml(SAMPLE_XML_4624)

        # Poll 1
        res1 = collector.poll_once(app)
        assert res1["success"] is True
        assert res1["collected_count"] == 1
        assert collector.last_record_id == 5001

        # Re-queue same event XML (representing replay/restart from previous bookmark)
        sim_source.queue_event_xml(SAMPLE_XML_4624)

        # Poll 2
        res2 = collector.poll_once(app)
        assert res2["success"] is True
        # Accepted count must be 0 because event_id is a duplicate
        assert res2["collected_count"] == 0

        # Check total database count remains 1
        ev_count = SecurityEvent.query.filter_by(event_id="WIN-SEC-5001").count()
        assert ev_count == 1


def test_collector_batch_limit(app):
    """Verify that batch size limits are honored and checkpoint advances correctly."""
    with app.app_context():
        collector = WindowsSecurityCollector.get_instance()
        sim_source = SimulatedEventSource()
        collector.set_event_source(sim_source, "Simulated Adapter")
        collector.last_record_id = 0
        collector.batch_size = 2

        # Queue 3 events
        sim_source.queue_event_xml(SAMPLE_XML_4624)  # 5001
        sim_source.queue_event_xml(SAMPLE_XML_4625)  # 5002
        sim_source.queue_event_xml(SAMPLE_XML_4648)  # 5004

        # Poll 1: processes exactly 2 events
        res1 = collector.poll_once(app)
        assert res1["success"] is True
        assert res1["collected_count"] == 2
        assert collector.last_record_id == 5002

        # Poll 2: processes remaining 1 event
        res2 = collector.poll_once(app)
        assert res2["success"] is True
        assert res2["collected_count"] == 1
        assert collector.last_record_id == 5004


def test_collector_checkpoint_persistence_and_recovery(app):
    """Verify that checkpoint state persists to SQLite and recovers across restarts."""
    with app.app_context():
        collector = WindowsSecurityCollector.get_instance()
        collector.last_record_id = 9999
        collector.total_collected = 42
        collector.polling_interval = 10.0
        collector.save_checkpoint_to_db(app, status="Stopped")

        # Create new collector instance simulation
        new_collector = WindowsSecurityCollector()
        new_collector.load_checkpoint_from_db(app)

        assert new_collector.last_record_id == 9999
        assert new_collector.total_collected == 42
        assert new_collector.polling_interval == 10.0
        assert new_collector.status == "Stopped"


def test_rule_security_log_cleared_critical_alert(app):
    """Verify that RULE-006 detects Event 1102 and raises Critical alert."""
    with app.app_context():
        parsed = WindowsEventParser.parse_xml_to_dict(SAMPLE_XML_1102)
        norm = WindowsEventParser.normalize_event(parsed)

        ev = SecurityEvent(
            event_id=norm["event_id"],
            timestamp=datetime.now(timezone.utc),
            username=norm["username"],
            event_type=norm["event_type"],
            outcome=norm["outcome"],
            actor=norm["actor"],
            resource=norm["resource"],
            action=norm["action"],
            raw_data=json.dumps(norm["raw_data"])
        )

        engine = DetectionEngine(TestConfig)
        alerts = engine.run_detection([ev])

        r6_alerts = [a for a in alerts if a["rule_id"] == "RULE-006"]
        assert len(r6_alerts) == 1
        assert r6_alerts[0]["severity"] == "critical"
        assert "cleared" in r6_alerts[0]["reason"].lower()


def test_rule_privileged_group_addition(app):
    """Verify that RULE-007 detects Event 4732 adding evil_backdoor to Administrators."""
    with app.app_context():
        parsed = WindowsEventParser.parse_xml_to_dict(SAMPLE_XML_4732)
        norm = WindowsEventParser.normalize_event(parsed)

        ev = SecurityEvent(
            event_id=norm["event_id"],
            timestamp=datetime.now(timezone.utc),
            username=norm["username"],
            event_type=norm["event_type"],
            outcome=norm["outcome"],
            actor=norm["actor"],
            new_role=norm["new_role"],
            resource=norm["resource"],
            action=norm["action"],
            raw_data=json.dumps(norm["raw_data"])
        )

        engine = DetectionEngine(TestConfig)
        alerts = engine.run_detection([ev])

        r7_alerts = [a for a in alerts if a["rule_id"] == "RULE-007"]
        assert len(r7_alerts) == 1
        assert r7_alerts[0]["severity"] in ("high", "critical")
        assert "evil_backdoor" in r7_alerts[0]["affected_user"]


def test_collector_api_endpoints(client):
    """Verify collector REST API controls and configurations."""
    # 1. Get status
    res_status = client.get("/api/collector/status")
    assert res_status.status_code == 200
    data = res_status.get_json()
    assert data["success"] is True
    assert "collector" in data

    # 2. Config update
    res_cfg = client.post("/api/collector/config", json={"polling_interval": 6.5, "batch_size": 250})
    assert res_cfg.status_code == 200
    cfg_data = res_cfg.get_json()
    assert cfg_data["config"]["polling_interval"] == 6.5
    assert cfg_data["config"]["batch_size"] == 250

    # 3. Invalid config validation
    res_bad = client.post("/api/collector/config", json={"polling_interval": -1})
    assert res_bad.status_code == 400

    # 4. Stop collector
    res_stop = client.post("/api/collector/stop")
    assert res_stop.status_code == 200
    assert res_stop.get_json()["status"] == "Stopped"
