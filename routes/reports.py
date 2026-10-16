from flask import Blueprint, render_template, jsonify, Response, abort
from datetime import datetime, timezone
import json

from models import db, Incident, SecurityEvent, DetectionAlert
from services.reporting import ReportingService

reports_bp = Blueprint("reports", __name__)

@reports_bp.route("/reports")
def reports_page():
    """Renders the Incident Reporting and Export Center."""
    incidents = Incident.query.order_by(Incident.risk_score.desc()).all()
    return render_template("reports.html", incidents=incidents)

@reports_bp.route("/reports/incident/<int:incident_id>/json")
def download_incident_json(incident_id):
    """Download forensic incident data as a JSON file."""
    incident = db.get_or_404(Incident, incident_id)
    report_dict = ReportingService.generate_incident_json(incident)
    
    filename = f"PrivilegeGuard_Report_{incident.incident_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        json.dumps(report_dict, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@reports_bp.route("/reports/incident/<int:incident_id>/html")
def view_incident_html(incident_id):
    """View/Print standalone forensic HTML report."""
    incident = db.get_or_404(Incident, incident_id)
    html_content = ReportingService.generate_incident_html(incident)
    return Response(html_content, mimetype="text/html")

@reports_bp.route("/reports/platform/json")
def download_platform_json():
    """Download complete platform security summary as JSON."""
    incidents = Incident.query.order_by(Incident.risk_score.desc()).all()
    events_count = SecurityEvent.query.count()
    alerts_count = DetectionAlert.query.count()

    summary_data = {
        "platform": "PrivilegeGuard AI",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_events_ingested": events_count,
            "total_alerts_detected": alerts_count,
            "total_incidents_correlated": len(incidents),
            "critical_incidents": sum(1 for i in incidents if i.severity == "critical"),
            "high_incidents": sum(1 for i in incidents if i.severity == "high"),
            "medium_incidents": sum(1 for i in incidents if i.severity == "medium"),
            "low_incidents": sum(1 for i in incidents if i.severity == "low")
        },
        "incidents": [inc.to_dict(include_events=True) for inc in incidents]
    }

    filename = f"PrivilegeGuard_Platform_Executive_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        json.dumps(summary_data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
