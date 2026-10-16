from flask import Blueprint, render_template, jsonify
from sqlalchemy import func
from datetime import datetime, timezone, timedelta
from models import db, SecurityEvent, Incident, DetectionAlert, AuditLog

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/")
def index():
    """Renders the primary cybersecurity operations overview dashboard."""
    return render_template("dashboard.html")

@dashboard_bp.route("/api/stats")
def get_stats():
    """Returns actual aggregated database metrics and chart datasets."""
    total_events = SecurityEvent.query.count()
    total_incidents = Incident.query.count()
    
    high_critical_count = Incident.query.filter(
        Incident.severity.in_(["high", "critical"])
    ).count()

    # Distinct affected identities in incidents
    affected_identities_count = db.session.query(
        func.count(func.distinct(Incident.affected_user))
    ).scalar() or 0

    # Severity distribution
    sev_counts = {
        "critical": Incident.query.filter_by(severity="critical").count(),
        "high": Incident.query.filter_by(severity="high").count(),
        "medium": Incident.query.filter_by(severity="medium").count(),
        "low": Incident.query.filter_by(severity="low").count()
    }

    # Status distribution
    status_counts = {
        "New": Incident.query.filter_by(status="New").count(),
        "Investigating": Incident.query.filter_by(status="Investigating").count(),
        "Contained": Incident.query.filter_by(status="Contained").count(),
        "Closed": Incident.query.filter_by(status="Closed").count(),
        "False Positive": Incident.query.filter_by(status="False Positive").count()
    }

    # Recent incidents (up to 5)
    recent_incidents = Incident.query.order_by(
        Incident.created_at.desc()
    ).limit(6).all()
    recent_incidents_data = [inc.to_dict(include_events=False) for inc in recent_incidents]

    # Event activity over time (aggregate by day or 1-hour slots)
    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.asc()).all()
    activity_buckets: dict = {}
    for ev in events:
        if ev.timestamp:
            bucket_key = ev.timestamp.strftime("%m-%d %H:%M")
            activity_buckets[bucket_key] = activity_buckets.get(bucket_key, 0) + 1

    # Keep latest 15 time buckets for chart clarity
    timeline_labels = list(activity_buckets.keys())[-15:]
    timeline_values = [activity_buckets[k] for k in timeline_labels]

    return jsonify({
        "total_events": total_events,
        "total_incidents": total_incidents,
        "high_critical_count": high_critical_count,
        "affected_identities_count": affected_identities_count,
        "severity_distribution": sev_counts,
        "status_distribution": status_counts,
        "activity_timeline": {
            "labels": timeline_labels,
            "data": timeline_values
        },
        "recent_incidents": recent_incidents_data
    })
