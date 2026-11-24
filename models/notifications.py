from datetime import datetime, timezone
import json
from models import db

class Notification(db.Model):
    """Represents a dispatched security alert across email or in-app channels."""
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    recipient = db.Column(db.String(255), nullable=True)
    channel = db.Column(db.String(20), nullable=False, default="in_app", index=True)  # in_app, email
    severity = db.Column(db.String(20), nullable=False, default="medium", index=True)  # low, medium, high, critical
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, nullable=False, default=False, index=True)
    delivery_status = db.Column(db.String(30), nullable=False, default="delivered", index=True)  # delivered, pending, sent, failed
    error_message = db.Column(db.Text, nullable=True)
    retry_count = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    sent_at = db.Column(db.DateTime, nullable=True)

    incident = db.relationship("Incident", backref=db.backref("notifications", cascade="all, delete-orphan", lazy=True))

    def to_dict(self):
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "incident_ref": self.incident.incident_id if self.incident else None,
            "incident_title": self.incident.title if self.incident else None,
            "affected_user": self.incident.affected_user if self.incident else None,
            "recipient": self.recipient,
            "channel": self.channel,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "is_read": self.is_read,
            "delivery_status": self.delivery_status,
            "error_message": self.error_message,
            "retry_count": self.retry_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None
        }


class NotificationSetting(db.Model):
    """Persists dynamic administrator notification preferences and runtime status."""
    __tablename__ = "notification_settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    @classmethod
    def get(cls, key: str, default=None):
        record = cls.query.filter_by(key=key).first()
        if record is None or record.value is None:
            return default
        try:
            return json.loads(record.value)
        except (json.JSONDecodeError, TypeError):
            return record.value

    @classmethod
    def set(cls, key: str, value):
        record = cls.query.filter_by(key=key).first()
        val_str = json.dumps(value) if not isinstance(value, str) else value
        if record:
            record.value = val_str
            record.updated_at = datetime.now(timezone.utc)
        else:
            record = cls(key=key, value=val_str)
            db.session.add(record)
        return record
