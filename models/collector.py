from datetime import datetime, timezone
from models import db

class CollectorCheckpoint(db.Model):
    """Tracks persistent bookmarks, status, and health metrics for event log collectors."""
    __tablename__ = "collector_checkpoints"

    id = db.Column(db.Integer, primary_key=True)
    channel = db.Column(db.String(50), unique=True, nullable=False, default="Security", index=True)
    last_record_id = db.Column(db.BigInteger, nullable=False, default=0)
    last_event_timestamp = db.Column(db.DateTime, nullable=True)
    last_poll_timestamp = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), nullable=False, default="Stopped")  # Stopped, Running, Access Denied, Error, Simulated
    error_message = db.Column(db.Text, nullable=True)
    polling_interval_seconds = db.Column(db.Float, nullable=False, default=5.0)
    batch_size_limit = db.Column(db.Integer, nullable=False, default=100)
    total_events_collected = db.Column(db.Integer, nullable=False, default=0)
    source_type = db.Column(db.String(50), nullable=False, default="Native Windows wevtapi")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        """Serialize checkpoint and collector state."""
        return {
            "id": self.id,
            "channel": self.channel,
            "last_record_id": self.last_record_id,
            "last_event_timestamp": self.last_event_timestamp.isoformat() if self.last_event_timestamp else None,
            "last_poll_timestamp": self.last_poll_timestamp.isoformat() if self.last_poll_timestamp else None,
            "status": self.status,
            "error_message": self.error_message,
            "polling_interval_seconds": self.polling_interval_seconds,
            "batch_size_limit": self.batch_size_limit,
            "total_events_collected": self.total_events_collected,
            "source_type": self.source_type,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }
