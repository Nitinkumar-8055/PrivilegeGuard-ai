from datetime import datetime, timezone
from models import db

class AuditLog(db.Model):
    """Tracks analyst actions, ingestion runs, containment simulations, and status updates."""
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    action_type = db.Column(db.String(50), nullable=False, index=True)
    details = db.Column(db.Text, nullable=False)
    user = db.Column(db.String(100), default="security_analyst")

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "action_type": self.action_type,
            "details": self.details,
            "user": self.user
        }
