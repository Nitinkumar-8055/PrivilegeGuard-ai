from flask import Blueprint, render_template, request, jsonify, current_app
from datetime import datetime, timezone
import math
import os
import re

from models import db, Notification, NotificationSetting, Incident, AuditLog
from services.email_service import EmailService, is_valid_email
from services.notification_service import NotificationWorker, NotificationDispatcher

notifications_bp = Blueprint("notifications", __name__)


@notifications_bp.route("/notifications")
def history_page():
    """Renders the dedicated persistent Notification History page."""
    return render_template("notifications.html")


@notifications_bp.route("/settings/notifications")
def settings_page():
    """Renders the dedicated Notification & Alert Management Settings page."""
    return render_template("notification_settings.html")


@notifications_bp.route("/api/notifications", methods=["GET"])
def get_notifications():
    """
    Returns paginated notifications with filtering by severity, read status,
    channel, and text search.
    """
    severity = request.args.get("severity", "").strip().lower()
    is_read_raw = request.args.get("is_read", "").strip().lower()
    channel = request.args.get("channel", "").strip().lower()
    search = request.args.get("search", "").strip()

    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 20))))
    except ValueError:
        page = 1
        per_page = 20

    query = Notification.query

    if severity in ("critical", "high", "medium", "low"):
        query = query.filter(Notification.severity == severity)

    if is_read_raw in ("true", "1"):
        query = query.filter(Notification.is_read.is_(True))
    elif is_read_raw in ("false", "0"):
        query = query.filter(Notification.is_read.is_(False))

    if channel in ("in_app", "email"):
        query = query.filter(Notification.channel == channel)

    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            db.or_(
                Notification.title.ilike(search_filter),
                Notification.message.ilike(search_filter),
                Notification.recipient.ilike(search_filter)
            )
        )

    total_count = query.count()
    unread_count = Notification.query.filter_by(is_read=False).count()

    items = query.order_by(Notification.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    total_pages = max(1, math.ceil(total_count / per_page))

    return jsonify({
        "success": True,
        "notifications": [item.to_dict() for item in items],
        "total": total_count,
        "unread_count": unread_count,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages
    })


@notifications_bp.route("/api/notifications/unread-count", methods=["GET"])
def get_unread_count():
    """Lightweight endpoint for polling navbar notification bell badge."""
    count = Notification.query.filter_by(is_read=False).count()
    return jsonify({
        "success": True,
        "unread_count": count
    })


@notifications_bp.route("/api/notifications/recent", methods=["GET"])
def get_recent_notifications():
    """Returns top 6 most recent notifications for the navigation dropdown menu."""
    limit = min(15, max(1, int(request.args.get("limit", 6))))
    recent = Notification.query.order_by(Notification.created_at.desc()).limit(limit).all()
    unread_count = Notification.query.filter_by(is_read=False).count()

    return jsonify({
        "success": True,
        "notifications": [item.to_dict() for item in recent],
        "unread_count": unread_count
    })


@notifications_bp.route("/api/notifications/<int:notif_id>/read", methods=["POST"])
def mark_read(notif_id):
    """Marks a single notification as read."""
    notif = db.session.get(Notification, notif_id)
    if not notif:
        return jsonify({"success": False, "error": "Notification not found."}), 404

    notif.is_read = True
    db.session.commit()
    unread_count = Notification.query.filter_by(is_read=False).count()

    return jsonify({"success": True, "unread_count": unread_count})


@notifications_bp.route("/api/notifications/<int:notif_id>/unread", methods=["POST"])
def mark_unread(notif_id):
    """Marks a single notification as unread."""
    notif = db.session.get(Notification, notif_id)
    if not notif:
        return jsonify({"success": False, "error": "Notification not found."}), 404

    notif.is_read = False
    db.session.commit()
    unread_count = Notification.query.filter_by(is_read=False).count()

    return jsonify({"success": True, "unread_count": unread_count})


@notifications_bp.route("/api/notifications/mark-all-read", methods=["POST"])
def mark_all_read():
    """Marks all notifications as read."""
    updated = Notification.query.filter_by(is_read=False).update({"is_read": True})
    db.session.commit()

    audit = AuditLog(
        action_type="NOTIFICATIONS_MARKED_READ",
        details=f"Marked {updated} notification(s) as read."
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        "success": True,
        "marked_count": updated,
        "unread_count": 0
    })


@notifications_bp.route("/api/notifications/<int:notif_id>", methods=["DELETE"])
def dismiss_notification(notif_id):
    """Dismisses and deletes an individual notification."""
    notif = db.session.get(Notification, notif_id)
    if not notif:
        return jsonify({"success": False, "error": "Notification not found."}), 404

    db.session.delete(notif)
    db.session.commit()
    unread_count = Notification.query.filter_by(is_read=False).count()

    return jsonify({
        "success": True,
        "message": f"Notification #{notif_id} dismissed.",
        "unread_count": unread_count
    })


@notifications_bp.route("/api/notifications/settings", methods=["GET"])
def get_settings():
    """
    Returns active notification settings and SMTP runtime status.
    SECURITY: SMTP_PASSWORD is NEVER returned over APIs or serialized.
    """
    smtp_cfg = EmailService.get_smtp_config()
    prefs = NotificationDispatcher.get_preferences()

    has_password = bool(os.environ.get("SMTP_PASSWORD"))

    last_success = NotificationSetting.get("last_email_success")
    last_failure = NotificationSetting.get("last_email_failure")
    last_error = NotificationSetting.get("last_email_error")

    worker = NotificationWorker.get_instance()
    worker_running = worker.worker_thread.is_alive() if worker and worker.worker_thread else False
    queue_size = worker.queue.qsize() if worker else 0

    return jsonify({
        "success": True,
        "settings": {
            "smtp_host": smtp_cfg["host"],
            "smtp_port": smtp_cfg["port"],
            "smtp_security": smtp_cfg["security"],
            "smtp_sender": smtp_cfg["sender"],
            "admin_email": prefs["admin_email"],
            "email_enabled": prefs["email_enabled"],
            "inapp_enabled": prefs["inapp_enabled"],
            "email_severities": prefs["email_severities"],
            "inapp_severities": prefs["inapp_severities"],
        },
        "status": {
            "smtp_configured": has_password,
            "smtp_password_status": "Configured (via .env)" if has_password else "Missing in .env",
            "last_email_success": last_success,
            "last_email_failure": last_failure,
            "last_email_error": last_error,
            "worker_running": worker_running,
            "queue_pending_count": queue_size
        }
    })


@notifications_bp.route("/api/notifications/settings", methods=["POST"])
def update_settings():
    """
    Updates administrative notification preferences and channel configurations.
    Validates email format and applies input sanitization.
    """
    data = request.get_json() or {}

    admin_email = data.get("admin_email", "").strip()
    if admin_email and not is_valid_email(admin_email):
        return jsonify({"success": False, "error": f"Invalid recipient email format: '{admin_email}'"}), 400

    smtp_sender = data.get("smtp_sender", "").strip()
    if smtp_sender and not is_valid_email(smtp_sender):
        return jsonify({"success": False, "error": f"Invalid sender email format: '{smtp_sender}'"}), 400

    smtp_host = data.get("smtp_host", "").strip()
    if smtp_host:
        NotificationSetting.set("smtp_host", smtp_host)

    if "smtp_port" in data:
        try:
            port_val = int(data["smtp_port"])
            if port_val <= 0 or port_val > 65535:
                raise ValueError()
            NotificationSetting.set("smtp_port", port_val)
        except ValueError:
            return jsonify({"success": False, "error": "SMTP port must be a valid integer between 1 and 65535."}), 400

    if "smtp_security" in data:
        sec = str(data["smtp_security"]).upper().strip()
        if sec in ("SSL", "TLS", "STARTTLS"):
            NotificationSetting.set("smtp_security", sec)

    if admin_email:
        NotificationSetting.set("admin_email", admin_email)

    if smtp_sender:
        NotificationSetting.set("smtp_sender", smtp_sender)

    if "email_enabled" in data:
        NotificationSetting.set("email_enabled", bool(data["email_enabled"]))

    if "inapp_enabled" in data:
        NotificationSetting.set("inapp_enabled", bool(data["inapp_enabled"]))

    if "email_severities" in data and isinstance(data["email_severities"], list):
        valid_sevs = [s.lower().strip() for s in data["email_severities"] if s.lower().strip() in ("low", "medium", "high", "critical")]
        NotificationSetting.set("email_severities", valid_sevs)

    if "inapp_severities" in data and isinstance(data["inapp_severities"], list):
        valid_sevs = [s.lower().strip() for s in data["inapp_severities"] if s.lower().strip() in ("low", "medium", "high", "critical")]
        NotificationSetting.set("inapp_severities", valid_sevs)

    db.session.commit()

    audit = AuditLog(
        action_type="NOTIFICATION_SETTINGS_UPDATED",
        details=f"Updated notification settings: admin_email='{admin_email or NotificationSetting.get('admin_email')}', email_enabled={data.get('email_enabled')}, inapp_enabled={data.get('inapp_enabled')}."
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Notification preferences updated successfully."
    })


@notifications_bp.route("/api/notifications/test-email", methods=["POST"])
def send_test_email():
    """Triggers an immediate test email to verify Gmail SMTP credentials."""
    data = request.get_json() or {}
    custom_recipient = data.get("recipient", "").strip()

    if custom_recipient and not is_valid_email(custom_recipient):
        return jsonify({"success": False, "error": f"Invalid recipient email format: '{custom_recipient}'"}), 400

    res = EmailService.send_test_email(recipient=custom_recipient or None)

    audit = AuditLog(
        action_type="TEST_EMAIL_DISPATCHED",
        details=f"Test email to '{res.get('recipient')}': success={res.get('success')}, error={res.get('error')}."
    )
    db.session.add(audit)
    db.session.commit()

    if res.get("success"):
        return jsonify({
            "success": True,
            "message": f"Test email successfully delivered to {res['recipient']} via Gmail SMTP.",
            "timestamp": res["timestamp"]
        })
    else:
        return jsonify({
            "success": False,
            "error": res.get("error") or "Failed to deliver test email.",
            "timestamp": res.get("timestamp")
        }), 400


@notifications_bp.route("/api/notifications/retry-failed", methods=["POST"])
def retry_failed_notifications():
    """Re-enqueues failed email notifications for background worker delivery."""
    failed = Notification.query.filter_by(channel="email", delivery_status="failed").all()
    worker = NotificationWorker.get_instance()
    retried_count = 0
    for notif in failed:
        notif.delivery_status = "pending"
        notif.retry_count = 0
        worker.enqueue_email(notif.id)
        retried_count += 1

    db.session.commit()
    return jsonify({
        "success": True,
        "retried_count": retried_count,
        "message": f"Re-enqueued {retried_count} failed notification(s) for delivery."
    })
