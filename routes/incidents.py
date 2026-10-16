from flask import Blueprint, render_template, request, jsonify, abort
from datetime import datetime, timezone
from models import db, Incident, SecurityEvent, DetectionAlert, AuditLog
from services.detection_engine import DetectionEngine
from services.correlation import IncidentCorrelationEngine
from services.ai_analysis import AIAnalysisService
from config import Config

incidents_bp = Blueprint("incidents", __name__)

@incidents_bp.route("/incidents")
def incidents_page():
    """Renders the Incident Center list view."""
    return render_template("incidents.html")

@incidents_bp.route("/incidents/<int:incident_id>")
def incident_detail_page(incident_id):
    """Renders the deep-dive Incident Detail view."""
    incident = db.get_or_404(Incident, incident_id)
    return render_template("incident_detail.html", incident=incident)

@incidents_bp.route("/api/incidents")
def get_incidents():
    """
    Returns list of correlated incidents.
    Supports filtering by severity, status, search string, and sorting.
    """
    severity = request.args.get("severity", "").strip().lower()
    status = request.args.get("status", "").strip()
    search = request.args.get("search", "").strip()
    sort_by = request.args.get("sort", "risk_desc")  # risk_desc, risk_asc, date_desc, date_asc

    query = Incident.query

    if severity:
        query = query.filter(Incident.severity == severity)

    if status:
        query = query.filter(Incident.status == status)

    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            db.or_(
                Incident.incident_id.ilike(search_filter),
                Incident.title.ilike(search_filter),
                Incident.affected_user.ilike(search_filter)
            )
        )

    if sort_by == "risk_desc":
        query = query.order_by(Incident.risk_score.desc())
    elif sort_by == "risk_asc":
        query = query.order_by(Incident.risk_score.asc())
    elif sort_by == "date_asc":
        query = query.order_by(Incident.last_observed_at.asc())
    else:  # date_desc
        query = query.order_by(Incident.last_observed_at.desc())

    incidents = query.all()
    return jsonify({
        "total": len(incidents),
        "incidents": [inc.to_dict(include_events=False) for inc in incidents]
    })

@incidents_bp.route("/api/incidents/<int:incident_id>")
def get_incident_detail(incident_id):
    """Returns complete details for a single incident including evidence events and factors."""
    incident = db.get_or_404(Incident, incident_id)
    return jsonify(incident.to_dict(include_events=True))

@incidents_bp.route("/api/incidents/<int:incident_id>/status", methods=["POST"])
def update_incident_status(incident_id):
    """Updates the investigation status of an incident."""
    incident = db.get_or_404(Incident, incident_id)
    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    allowed_statuses = ["New", "Investigating", "Contained", "Closed", "False Positive"]

    if new_status not in allowed_statuses:
        return jsonify({"success": False, "error": f"Invalid status. Must be one of {allowed_statuses}"}), 400

    old_status = incident.status
    incident.status = new_status
    incident.updated_at = datetime.now(timezone.utc)

    # Audit log
    audit = AuditLog(
        action_type="STATUS_CHANGE",
        details=f"Updated status of {incident.incident_id} from '{old_status}' to '{new_status}'."
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({"success": True, "incident": incident.to_dict(include_events=False)})

@incidents_bp.route("/api/incidents/<int:incident_id>/simulate_containment", methods=["POST"])
def simulate_containment(incident_id):
    """
    Simulates security containment actions without modifying actual infrastructure.
    Permitted actions: 'lock_account', 'revoke_sessions', 'quarantine_identity'.
    """
    incident = db.get_or_404(Incident, incident_id)
    data = request.get_json(silent=True) or {}
    action = data.get("action", "lock_account")

    action_descriptions = {
        "lock_account": f"SIMULATED: Placed Active Directory / IdP hold on account '{incident.affected_user}'. Disabled future logins.",
        "revoke_sessions": f"SIMULATED: Invalidated all active OAuth refresh tokens and SSO browser sessions for '{incident.affected_user}'.",
        "quarantine_identity": f"SIMULATED: Enforced emergency conditional access policy. Isolated access to honeypot telemetry for '{incident.affected_user}'."
    }

    desc = action_descriptions.get(action, f"SIMULATED: Generic containment executed for '{incident.affected_user}'.")

    # Update incident status to Contained if currently New or Investigating
    if incident.status in ("New", "Investigating"):
        incident.status = "Contained"

    audit = AuditLog(
        action_type="CONTAINMENT_SIMULATION",
        details=f"[{incident.incident_id}] {desc}"
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        "success": True,
        "action": action,
        "message": desc,
        "new_status": incident.status
    })

@incidents_bp.route("/api/incidents/run_detection", methods=["POST"])
def run_detection_pipeline():
    """Manually run detection rules across all ingested events and correlate incidents."""
    all_events = SecurityEvent.query.order_by(SecurityEvent.timestamp.asc()).all()
    if not all_events:
        return jsonify({
            "success": True,
            "message": "No events in database to analyze.",
            "alerts_count": 0,
            "incidents_count": 0
        })

    engine = DetectionEngine(Config())
    alerts = engine.run_detection(all_events)
    incidents = IncidentCorrelationEngine.correlate_alerts(alerts, Config())

    audit = AuditLog(
        action_type="DETECTION_RUN",
        details=f"Detection run completed: evaluated {len(all_events)} events, generated {len(alerts)} alerts, resulting in {len(incidents)} incidents."
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        "success": True,
        "total_events_evaluated": len(all_events),
        "alerts_generated": len(alerts),
        "incidents_created_or_updated": len(incidents),
        "incidents": [inc.to_dict(include_events=False) for inc in incidents]
    })
