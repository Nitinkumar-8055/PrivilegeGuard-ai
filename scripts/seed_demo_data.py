import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from services.ingestion import IngestionService
from services.detection_engine import DetectionEngine
from services.correlation import IncidentCorrelationEngine
from scripts.generate_dataset import build_synthetic_events
from config import Config
from models import SecurityEvent, Incident, DetectionAlert

def seed_database():
    app = create_app()
    with app.app_context():
        print("[+] Generating synthetic security event dataset...")
        events = build_synthetic_events(include_malformed=True)
        res = IngestionService.ingest_json(json.dumps(events))
        print(f"[+] Ingestion complete: {res['accepted_count']} accepted, {res['rejected_count']} rejected.")
        
        print("[+] Evaluating security detection engine rules...")
        all_evs = SecurityEvent.query.order_by(SecurityEvent.timestamp.asc()).all()
        engine = DetectionEngine(Config())
        alerts = engine.run_detection(all_evs)
        print(f"[+] Generated {len(alerts)} alerts.")

        print("[+] Correlating incidents, computing risk scores, and generating forensic analyses...")
        incidents = IncidentCorrelationEngine.correlate_alerts(alerts, Config())
        print(f"[+] Successfully correlated {len(incidents)} incidents:")
        for inc in incidents:
            print(f"    - [{inc.severity.upper():<8}] Score: {inc.risk_score:>3}/100 | {inc.incident_id} | {inc.title}")

if __name__ == "__main__":
    seed_database()
