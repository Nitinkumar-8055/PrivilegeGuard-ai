import os
import queue
import threading
import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from models import db, Notification, NotificationSetting, Incident, AuditLog
from services.email_service import EmailService

logger = logging.getLogger("privilegeguard.notifications")

SEVERITY_LEVELS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}


class NotificationWorker:
    """
    Asynchronous background notification worker.
    Processes outbound email queue without blocking the Windows collector,
    ingestion pipeline, or web requests. Includes bounded retries.
    """
    _instance = None
    _lock = threading.Lock()

    def __init__(self, app=None):
        self.app = app
        self.queue: queue.Queue = queue.Queue()
        self.worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.max_retries = 3

    @classmethod
    def get_instance(cls, app=None):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(app)
            elif app is not None and cls._instance.app is None:
                cls._instance.app = app
            return cls._instance

    def start(self, app=None):
        if app:
            self.app = app
        with self._lock:
            if self.worker_thread and self.worker_thread.is_alive():
                return
            self._stop_event.clear()
            self.worker_thread = threading.Thread(
                target=self._run_loop,
                name="PrivilegeGuard-NotificationWorker",
                daemon=True
            )
            self.worker_thread.start()
            logger.info("PrivilegeGuard AI Notification Background Worker started.")

    def stop(self, timeout=3.0):
        self._stop_event.set()
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=timeout)
            logger.info("PrivilegeGuard AI Notification Background Worker stopped.")

    def enqueue_email(self, notification_id: int):
        """Enqueue notification ID for asynchronous background dispatch."""
        self.queue.put(notification_id)

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                notification_id = self.queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                self._process_email_notification(notification_id)
            except Exception as e:
                logger.error(f"Unexpected error in notification worker for id={notification_id}: {e}")
            finally:
                self.queue.task_done()

    def _process_email_notification(self, notification_id: int):
        """Processes a single email notification record inside the Flask application context."""
        if not self.app:
            logger.error("Notification worker has no active Flask application instance.")
            return

        with self.app.app_context():
            notif = db.session.get(Notification, notification_id)
            if not notif or notif.delivery_status == "sent":
                return

            incident = notif.incident
            if not incident:
                notif.delivery_status = "failed"
                notif.error_message = "Associated incident no longer exists in database."
                db.session.commit()
                return

            is_escalation = "[ESCALATION]" in notif.title
            email_payload = EmailService.build_incident_email(
                incident=incident,
                is_escalation=is_escalation
            )

            res = EmailService.send_smtp_message(
                recipient=notif.recipient,
                subject=email_payload["subject"],
                html_body=email_payload["html_body"],
                text_body=email_payload["text_body"]
            )

            if res.get("success"):
                notif.delivery_status = "sent"
                notif.sent_at = datetime.now(timezone.utc)
                notif.error_message = None
                db.session.commit()
                logger.info(f"Notification id={notification_id} successfully sent to {notif.recipient}")
            else:
                err_msg = res.get("error") or "Unknown SMTP error"
                notif.retry_count += 1
                notif.error_message = err_msg

                if notif.retry_count >= self.max_retries or "credentials unavailable" in err_msg.lower() or "authentication failed" in err_msg.lower():
                    notif.delivery_status = "failed"
                    logger.warning(f"Notification id={notification_id} marked as failed: {err_msg}")
                else:
                    notif.delivery_status = "pending"
                    # Re-enqueue for retry after brief delay
                    time.sleep(1.0 * notif.retry_count)
                    self.queue.put(notification_id)

                db.session.commit()


class NotificationDispatcher:
    """
    Centralized coordinator for incident notification decisions, deduplication,
    in-app record creation, and email queuing.
    """

    @classmethod
    def get_preferences(cls) -> Dict[str, Any]:
        """Resolves active preferences from NotificationSetting or environment variables."""
        email_enabled = NotificationSetting.get("email_enabled")
        if email_enabled is None:
            email_enabled = os.environ.get("EMAIL_NOTIFICATIONS_ENABLED", "true").lower() in ("true", "1", "yes")

        inapp_enabled = NotificationSetting.get("inapp_enabled")
        if inapp_enabled is None:
            inapp_enabled = os.environ.get("INAPP_NOTIFICATIONS_ENABLED", "true").lower() in ("true", "1", "yes")

        admin_email = NotificationSetting.get("admin_email") or os.environ.get("ADMIN_EMAIL", "nk8055444@gmail.com")

        email_sevs = NotificationSetting.get("email_severities")
        if email_sevs is None:
            raw = os.environ.get("EMAIL_SEVERITIES", "high,critical")
            email_sevs = [s.strip().lower() for s in raw.split(",") if s.strip()]

        inapp_sevs = NotificationSetting.get("inapp_severities")
        if inapp_sevs is None:
            raw = os.environ.get("INAPP_SEVERITIES", "low,medium,high,critical")
            inapp_sevs = [s.strip().lower() for s in raw.split(",") if s.strip()]

        return {
            "email_enabled": bool(email_enabled),
            "inapp_enabled": bool(inapp_enabled),
            "admin_email": admin_email.strip(),
            "email_severities": [str(s).lower() for s in email_sevs],
            "inapp_severities": [str(s).lower() for s in inapp_sevs]
        }

    @classmethod
    def dispatch_incident_notification(
        cls,
        incident: Incident,
        is_new: bool = True,
        old_severity: Optional[str] = None
    ) -> List[Notification]:
        """
        Evaluates an incident for qualifying notification generation.
        Applies database-backed deduplication and severity escalation logic.
        """
        if not incident:
            return []

        prefs = cls.get_preferences()
        current_sev = (incident.severity or "medium").lower()
        current_rank = SEVERITY_LEVELS.get(current_sev, 2)

        # Database-backed history check for this incident
        existing_notifs = Notification.query.filter_by(incident_id=incident.id).all()

        is_escalation = False
        if not is_new:
            old_sev = (old_severity or "medium").lower()
            old_rank = SEVERITY_LEVELS.get(old_sev, 2)
            if current_rank > old_rank:
                is_escalation = True
            else:
                # Severity did not escalate; skip duplicate dispatch
                return []

            # Check if an escalation notification for this severity level was already generated
            already_notified_for_this_sev = any(
                n.severity.lower() == current_sev for n in existing_notifs
            )
            if already_notified_for_this_sev:
                return []
        else:
            # For new incidents, ensure we haven't already notified
            if existing_notifs:
                highest_prev_rank = max([SEVERITY_LEVELS.get(n.severity.lower(), 0) for n in existing_notifs], default=0)
                if current_rank <= highest_prev_rank:
                    return []

        generated: List[Notification] = []

        # -------------------------------------------------------------
        # Channel 1: In-App Dashboard Notification
        # -------------------------------------------------------------
        if prefs["inapp_enabled"] and current_sev in prefs["inapp_severities"]:
            if is_escalation:
                inapp_title = f"[ESCALATION: {current_sev.upper()}] {incident.title}"
                inapp_msg = (
                    f"Incident {incident.incident_id} escalated from {(old_severity or 'previous').upper()} "
                    f"to {current_sev.upper()}. Risk score elevated to {incident.risk_score}."
                )
            else:
                inapp_title = f"[{current_sev.upper()}] {incident.title}"
                inapp_msg = (
                    f"New security incident {incident.incident_id} detected for identity '{incident.affected_user}'. "
                    f"Risk score: {incident.risk_score}."
                )

            inapp_notif = Notification(
                incident_id=incident.id,
                recipient=prefs["admin_email"],
                channel="in_app",
                severity=current_sev,
                title=inapp_title,
                message=inapp_msg,
                is_read=False,
                delivery_status="delivered",
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(inapp_notif)
            generated.append(inapp_notif)

        # -------------------------------------------------------------
        # Channel 2: Email Notification (Gmail SMTP)
        # -------------------------------------------------------------
        if prefs["email_enabled"] and current_sev in prefs["email_severities"]:
            if is_escalation:
                email_title = f"[ESCALATION: {current_sev.upper()}] {incident.title}"
                email_msg = (
                    f"Security incident {incident.incident_id} escalated from {(old_severity or 'previous').upper()} "
                    f"to {current_sev.upper()}. Risk score: {incident.risk_score}."
                )
            else:
                email_title = f"[{current_sev.upper()}] {incident.title}"
                email_msg = (
                    f"Security incident {incident.incident_id} detected for user '{incident.affected_user}'. "
                    f"Risk score: {incident.risk_score}."
                )

            email_notif = Notification(
                incident_id=incident.id,
                recipient=prefs["admin_email"],
                channel="email",
                severity=current_sev,
                title=email_title,
                message=email_msg,
                is_read=False,
                delivery_status="pending",
                retry_count=0,
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(email_notif)
            generated.append(email_notif)

        if generated:
            db.session.commit()

            # Enqueue email notifications to background worker
            worker = NotificationWorker.get_instance()
            for notif in generated:
                if notif.channel == "email":
                    worker.enqueue_email(notif.id)

            logger.info(
                f"Dispatched {len(generated)} notification(s) for Incident {incident.incident_id} "
                f"(Severity: {current_sev.upper()}, Escalation: {is_escalation})"
            )

        return generated
