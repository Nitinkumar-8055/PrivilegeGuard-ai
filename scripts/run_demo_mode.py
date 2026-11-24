import os
import sys
import pathlib
from datetime import datetime, timezone, timedelta

# Ensure project root is on sys.path
BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# Force completely isolated demo database path BEFORE importing app/config
DEMO_DB_PATH = BASE_DIR / "privilegeguard_demo.db"
os.environ["DATABASE_URL"] = f"sqlite:///{DEMO_DB_PATH}"

from app import create_app
from config import Config
from models import db, SecurityEvent, Incident, DetectionAlert, IncidentEvent, AuditLog, CollectorCheckpoint
from services.ingestion import IngestionService
from services.detection_engine import DetectionEngine
from services.correlation import IncidentCorrelationEngine

class DemoConfig(Config):
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DEMO_DB_PATH}"

def setup_demo_environment():
    print("=" * 70)
    print(" PrivilegeGuard AI — ISOLATED DEMONSTRATION MODE")
    print("=" * 70)
    print(f"[*] Target Demo Database: {DEMO_DB_PATH.name} (Completely isolated from production)")
    print(f"[*] Production Database : privilegeguard.db (UNTOUCHED)")

    app = create_app(DemoConfig)
    with app.app_context():
        # Ensure fresh clean demo tables
        db.create_all()
        # Wipe only the demo database if re-running
        IncidentEvent.query.delete()
        DetectionAlert.query.delete()
        Incident.query.delete()
        SecurityEvent.query.delete()
        AuditLog.query.delete()
        CollectorCheckpoint.query.delete()
        db.session.commit()

        base_time = datetime.now(timezone.utc) - timedelta(minutes=45)

        demo_events = [
            # Scenario 1: Credential Stuffing & Penetration (Windows 4625 -> 4624)
            {
                "event_id": "DEMO-WIN-4625-1",
                "timestamp": (base_time + timedelta(minutes=1)).isoformat(),
                "username": "victim.corp",
                "event_type": "login_failure",
                "outcome": "failure",
                "source_ip": "198.51.100.42",
                "action": "failed_logon_substatus_0xC000006A"
            },
            {
                "event_id": "DEMO-WIN-4625-2",
                "timestamp": (base_time + timedelta(minutes=3)).isoformat(),
                "username": "victim.corp",
                "event_type": "login_failure",
                "outcome": "failure",
                "source_ip": "198.51.100.42",
                "action": "failed_logon_substatus_0xC000006A"
            },
            {
                "event_id": "DEMO-WIN-4625-3",
                "timestamp": (base_time + timedelta(minutes=5)).isoformat(),
                "username": "victim.corp",
                "event_type": "login_failure",
                "outcome": "failure",
                "source_ip": "198.51.100.42",
                "action": "failed_logon_substatus_0xC000006A"
            },
            {
                "event_id": "DEMO-WIN-4624-SUCC",
                "timestamp": (base_time + timedelta(minutes=7)).isoformat(),
                "username": "victim.corp",
                "event_type": "login_success",
                "outcome": "success",
                "source_ip": "198.51.100.42",
                "action": "logon_type_10"  # RDP
            },
            # Scenario 2: Privilege Escalation to Administrators (Windows 4732)
            {
                "event_id": "DEMO-WIN-4732-ADMIN",
                "timestamp": (base_time + timedelta(minutes=15)).isoformat(),
                "username": "victim.corp",
                "event_type": "role_change",
                "outcome": "success",
                "actor": "compromised_it_lead",
                "old_role": "user",
                "new_role": "Administrators",
                "resource": "BUILTIN\\Administrators",
                "action": "security_group_member_added"
            },
            # Scenario 3: Sensitive Resource Access Post-Escalation
            {
                "event_id": "DEMO-WIN-VAULT-ACCESS",
                "timestamp": (base_time + timedelta(minutes=20)).isoformat(),
                "username": "victim.corp",
                "event_type": "resource_access",
                "outcome": "success",
                "resource": "/api/v1/vault/keys",
                "action": "read_secret_keys"
            },
            # Scenario 4: Security Log Tampering (Event 1102)
            {
                "event_id": "DEMO-WIN-1102-CLEARED",
                "timestamp": (base_time + timedelta(minutes=25)).isoformat(),
                "username": "victim.corp",
                "event_type": "access_denied",
                "outcome": "success",
                "actor": "victim.corp",
                "resource": "Windows Security Event Log",
                "action": "security_audit_log_cleared"
            }
        ]

        # Ingest demo events
        ingest_res = IngestionService._process_records(demo_events)
        print(f"[+] Ingested {ingest_res['accepted_count']} synthetic demonstration events.")

        # Run rules and correlate
        all_events = SecurityEvent.query.order_by(SecurityEvent.timestamp.asc()).all()
        engine = DetectionEngine(DemoConfig())
        alerts = engine.run_detection(all_events)
        print(f"[+] Generated {len(alerts)} security detection alerts.")

        incidents = IncidentCorrelationEngine.correlate_alerts(alerts, DemoConfig())
        print(f"[+] Correlated {len(incidents)} high-fidelity security incidents:")
        for inc in incidents:
            print(f"    - [{inc.incident_id}] {inc.title} (Score: {inc.risk_score}/100, Severity: {inc.severity})")

        # Set simulated collector status
        cp = CollectorCheckpoint(
            channel="Security",
            last_record_id=104920,
            status="Simulated",
            source_type="Simulated Demonstration Adapter",
            total_events_collected=len(demo_events)
        )
        db.session.add(cp)
        db.session.commit()

    print("\n" + "=" * 70)
    print(" DEMO SERVER READY")
    print("=" * 70)
    print("[*] Starting isolated demo server at http://127.0.0.1:5001")
    print("[*] Note: To clean up demo database afterwards, run:")
    print(f"    Remove-Item '{DEMO_DB_PATH}'")
    print("=" * 70 + "\n")

    app.run(host="127.0.0.1", port=5001, debug=False)

if __name__ == "__main__":
    setup_demo_environment()
