from datetime import datetime, timezone
import json
from models import db

class SecurityEvent(db.Model):
    """Represents an ingested authentication, authorization, or access event."""
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    username = db.Column(db.String(100), nullable=False, index=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=True)
    outcome = db.Column(db.String(50), nullable=False)
    actor = db.Column(db.String(100), nullable=True)
    old_role = db.Column(db.String(50), nullable=True)
    new_role = db.Column(db.String(50), nullable=True)
    resource = db.Column(db.String(255), nullable=True)
    action = db.Column(db.String(100), nullable=True)
    session_id = db.Column(db.String(100), nullable=True)
    raw_data = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        """Serialize event to dictionary representation."""
        return {
            "id": self.id,
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "username": self.username,
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "outcome": self.outcome,
            "actor": self.actor,
            "old_role": self.old_role,
            "new_role": self.new_role,
            "resource": self.resource,
            "action": self.action,
            "session_id": self.session_id,
            "raw_data": json.loads(self.raw_data) if self.raw_data else {}
        }
