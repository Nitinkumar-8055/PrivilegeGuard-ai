from datetime import datetime, timezone
import json
from models import db

class Incident(db.Model):
    """Represents a correlated security incident composed of alerts and events."""
    __tablename__ = "incidents"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    affected_user = db.Column(db.String(100), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, default="medium")  # low, medium, high, critical
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    risk_factors = db.Column(db.Text, nullable=True)  # JSON-encoded array of factor objects
    status = db.Column(db.String(30), nullable=False, default="New")  # New, Investigating, Contained, Closed, False Positive
    first_observed_at = db.Column(db.DateTime, nullable=False)
    last_observed_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    summary = db.Column(db.Text, nullable=True)
    ai_explanation = db.Column(db.Text, nullable=True)  # JSON-encoded explanation structure
    recommended_actions = db.Column(db.Text, nullable=True)  # JSON-encoded list of actions

    # Relationships
    alerts = db.relationship("DetectionAlert", backref="incident", cascade="all, delete-orphan", lazy=True)
    incident_events = db.relationship("IncidentEvent", backref="incident", cascade="all, delete-orphan", lazy=True)

    @property
    def events(self):
        """Return all linked SecurityEvents ordered by timestamp."""
        return [
            ie.security_event for ie in sorted(
                self.incident_events, 
                key=lambda item: item.security_event.timestamp if item.security_event and item.security_event.timestamp else datetime.min
            ) if ie.security_event is not None
        ]

    def to_dict(self, include_events=True):
        """Serialize incident object to dictionary representation."""
        data = {
            "id": self.id,
            "incident_id": self.incident_id,
            "title": self.title,
            "affected_user": self.affected_user,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "risk_factors": json.loads(self.risk_factors) if self.risk_factors else [],
            "status": self.status,
            "first_observed_at": self.first_observed_at.isoformat() if self.first_observed_at else None,
            "last_observed_at": self.last_observed_at.isoformat() if self.last_observed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "summary": self.summary,
            "ai_explanation": json.loads(self.ai_explanation) if self.ai_explanation else {},
            "recommended_actions": json.loads(self.recommended_actions) if self.recommended_actions else [],
            "alerts": [alert.to_dict() for alert in self.alerts]
        }
        if include_events:
            data["events"] = [e.to_dict() for e in self.events]
        return data


class IncidentEvent(db.Model):
    """Associates an Incident with a SecurityEvent and notes its role."""
    __tablename__ = "incident_events"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False)
    role_in_incident = db.Column(db.String(50), default="supporting_evidence")

    # Direct relation to SecurityEvent
    security_event = db.relationship("SecurityEvent", lazy="joined")


class DetectionAlert(db.Model):
    """Represents a single rule hit triggered by the detection engine."""
    __tablename__ = "detection_alerts"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    rule_id = db.Column(db.String(50), nullable=False, index=True)
    rule_name = db.Column(db.String(150), nullable=False)
    affected_user = db.Column(db.String(100), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    suggested_investigation_steps = db.Column(db.Text, nullable=True)  # JSON-encoded array
    relevant_event_ids = db.Column(db.Text, nullable=False)  # JSON-encoded array of event_id strings
    detected_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "affected_user": self.affected_user,
            "severity": self.severity,
            "reason": self.reason,
            "suggested_investigation_steps": json.loads(self.suggested_investigation_steps) if self.suggested_investigation_steps else [],
            "relevant_event_ids": json.loads(self.relevant_event_ids) if self.relevant_event_ids else [],
            "detected_at": self.detected_at.isoformat() if self.detected_at else None
        }
