from flask import Blueprint, jsonify, request, current_app
from services.collector import WindowsSecurityCollector
from models import db, CollectorCheckpoint

collector_bp = Blueprint("collector", __name__)

@collector_bp.route("/api/collector/status", methods=["GET"])
def get_collector_status():
    """Returns live and database-persisted status of the Windows Security collector."""
    collector = WindowsSecurityCollector.get_instance()
    status_data = collector.get_status()

    # Enrich with persisted DB checkpoint if available
    try:
        cp = CollectorCheckpoint.query.filter_by(channel=collector.channel).first()
        if cp:
            status_data["persisted_checkpoint"] = cp.last_record_id
            status_data["total_collected_lifetime"] = cp.total_events_collected
            if not collector.is_running and cp.status != "Running":
                status_data["status"] = cp.status
            if not status_data.get("error_message") and cp.error_message:
                status_data["error_message"] = cp.error_message
    except Exception:
        pass

    return jsonify({"success": True, "collector": status_data})


@collector_bp.route("/api/collector/start", methods=["POST"])
def start_collector():
    """Starts the Windows Security Event background collection worker."""
    collector = WindowsSecurityCollector.get_instance()
    data = request.get_json(silent=True) or {}
    
    channel = data.get("channel", collector.channel or "Security")
    polling_interval = data.get("polling_interval", collector.polling_interval or 5.0)
    batch_size = data.get("batch_size", collector.batch_size or 100)

    try:
        polling_interval = float(polling_interval)
        batch_size = int(batch_size)
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid polling_interval or batch_size format."}), 400

    result = collector.start(
        app=current_app._get_current_object(),
        channel=channel,
        polling_interval=polling_interval,
        batch_size=batch_size
    )

    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


@collector_bp.route("/api/collector/stop", methods=["POST"])
def stop_collector():
    """Stops the Windows Security Event background collection worker."""
    collector = WindowsSecurityCollector.get_instance()
    result = collector.stop()
    return jsonify(result)


@collector_bp.route("/api/collector/config", methods=["POST"])
def update_collector_config():
    """Updates polling interval and batch size settings."""
    collector = WindowsSecurityCollector.get_instance()
    data = request.get_json(silent=True) or {}

    if "polling_interval" in data:
        try:
            val = float(data["polling_interval"])
            if val < 1.0:
                return jsonify({"success": False, "error": "Polling interval must be >= 1.0 second."}), 400
            collector.polling_interval = val
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "Invalid polling interval value."}), 400

    if "batch_size" in data:
        try:
            val = int(data["batch_size"])
            if val < 1 or val > 1000:
                return jsonify({"success": False, "error": "Batch size must be between 1 and 1000."}), 400
            collector.batch_size = val
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "Invalid batch size value."}), 400

    # Save to DB
    collector.save_checkpoint_to_db(current_app._get_current_object())

    return jsonify({
        "success": True,
        "message": "Collector settings updated.",
        "config": {
            "polling_interval": collector.polling_interval,
            "batch_size": collector.batch_size
        }
    })


@collector_bp.route("/api/collector/poll_once", methods=["POST"])
def poll_once():
    """Triggers an immediate single collection poll cycle."""
    collector = WindowsSecurityCollector.get_instance()
    result = collector.poll_once(current_app._get_current_object())
    return jsonify(result)
