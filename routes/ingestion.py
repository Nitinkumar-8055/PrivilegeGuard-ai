from flask import Blueprint, render_template, request, jsonify
from werkzeug.utils import secure_filename
import os

from models import db, SecurityEvent, Incident, IncidentEvent, DetectionAlert, AuditLog
from services.ingestion import IngestionService
from services.detection_engine import DetectionEngine
from services.correlation import IncidentCorrelationEngine
from scripts.generate_dataset import build_synthetic_events
from config import Config

ingestion_bp = Blueprint("ingestion", __name__)

@ingestion_bp.route("/ingestion")
def ingestion_page():
    """Renders the data ingestion and scenario generation dashboard."""
    return render_template("ingestion.html")

@ingestion_bp.route("/api/ingestion/upload", methods=["POST"])
def upload_file():
    """
    Handles file upload of JSON or CSV security events.
    Validates, handles duplicates, stores accepted events, and triggers detection.
    """
    if "file" not in request.files:
        return jsonify({"success": False, "error_message": "No file uploaded in request."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "error_message": "Selected file has an empty filename."}), 400

    filename = secure_filename(file.filename)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext not in ("json", "csv"):
        return jsonify({"success": False, "error_message": f"Unsupported file extension '{ext}'. Only .json and .csv are permitted."}), 400

    content = file.read().decode("utf-8", errors="replace")

    if ext == "json":
        result = IngestionService.ingest_json(content, max_records=Config.MAX_RECORDS_PER_UPLOAD)
    else:
        result = IngestionService.ingest_csv(content, max_records=Config.MAX_RECORDS_PER_UPLOAD)

    # If events were accepted, automatically trigger detection to surface incidents
    incidents_created = 0
    alerts_created = 0
    if result.get("accepted_count", 0) > 0:
        all_events = SecurityEvent.query.order_by(SecurityEvent.timestamp.asc()).all()
        engine = DetectionEngine(Config())
        alerts = engine.run_detection(all_events)
        alerts_created = len(alerts)
        incidents = IncidentCorrelationEngine.correlate_alerts(alerts, Config())
        incidents_created = len(incidents)

    # Return response without serializing large event model arrays
    return jsonify({
        "success": result["success"],
        "error_message": result["error_message"],
        "total_records": result["total_records"],
        "accepted_count": result["accepted_count"],
        "rejected_count": result["rejected_count"],
        "rejected_records": result["rejected_records"],
        "detection_summary": {
            "alerts_generated": alerts_created,
            "incidents_active": incidents_created
        }
    })

@ingestion_bp.route("/api/ingestion/generate_demo", methods=["POST"])
def generate_demo_scenario():
    """
    Generates synthetic security events including normal patterns, attacks, and malformed records.
    Runs detection and correlation, populating the database with realistic demonstration data.
    """
    raw_events = build_synthetic_events(include_malformed=True)

    # Ingest using IngestionService
    import json
    json_str = json.dumps(raw_events)
    result = IngestionService.ingest_json(json_str)

    # Run detection & correlation
    all_events = SecurityEvent.query.order_by(SecurityEvent.timestamp.asc()).all()
    engine = DetectionEngine(Config())
    alerts = engine.run_detection(all_events)
    incidents = IncidentCorrelationEngine.correlate_alerts(alerts, Config())

    audit = AuditLog(
        action_type="DEMO_DATASET_GENERATED",
        details=f"Generated synthetic dataset: {result['accepted_count']} accepted, {result['rejected_count']} rejected records. Resulted in {len(incidents)} correlated incidents."
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Synthetic demonstration dataset loaded and correlated successfully.",
        "total_generated": len(raw_events),
        "accepted_count": result["accepted_count"],
        "rejected_count": result["rejected_count"],
        "rejected_details": result["rejected_records"],
        "alerts_generated": len(alerts),
        "incidents_created": len(incidents)
    })

@ingestion_bp.route("/api/ingestion/clear", methods=["POST"])
def clear_database():
    """Wipes ingested events, alerts, and incidents for a clean state in testing environments."""
    # Safety protection: prevent accidental wipe of historical and production database records
    from flask import current_app
    data = request.get_json(silent=True) or {}
    confirmation = data.get("confirm", "")
    if not current_app.config.get("TESTING") and confirmation != "RESET_TEST_DATA":
        return jsonify({
            "success": False,
            "error_message": "Production safety guard: clearing data requires explicit payload {'confirm': 'RESET_TEST_DATA'}."
        }), 403


    try:
        IncidentEvent.query.delete()
        DetectionAlert.query.delete()
        Incident.query.delete()
        SecurityEvent.query.delete()
        
        audit = AuditLog(
            action_type="DATABASE_RESET",
            details="All security events, detection alerts, and correlated incidents were cleared."
        )
        db.session.add(audit)
        db.session.commit()

        return jsonify({"success": True, "message": "Database cleared successfully."})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error_message": str(e)}), 500

