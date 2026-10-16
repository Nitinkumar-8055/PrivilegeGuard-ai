from flask import Flask, render_template, jsonify
import os
from sqlalchemy import event
from config import Config
from models import db

def create_app(config_class=Config):
    """Application factory for PrivilegeGuard AI."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)

    # Configure SQLite PRAGMAs (WAL mode, busy timeout) to prevent database locks
    with app.app_context():
        engine = db.engine
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            if type(dbapi_connection).__module__ == "sqlite3":
                cursor = dbapi_connection.cursor()
                try:
                    cursor.execute("PRAGMA journal_mode=WAL;")
                    cursor.execute("PRAGMA busy_timeout=30000;")
                    cursor.execute("PRAGMA synchronous=NORMAL;")
                except Exception:
                    pass
                finally:
                    cursor.close()

    # Register Blueprints
    from routes.dashboard import dashboard_bp
    from routes.events import events_bp
    from routes.incidents import incidents_bp
    from routes.ingestion import ingestion_bp
    from routes.reports import reports_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(ingestion_bp)
    app.register_blueprint(reports_bp)

    # Template utility filters
    @app.template_filter("badge_color")
    def badge_color_filter(severity):
        mapping = {
            "critical": "badge-critical",
            "high": "badge-high",
            "medium": "badge-medium",
            "low": "badge-low"
        }
        return mapping.get(str(severity).lower(), "badge-medium")

    @app.template_filter("status_color")
    def status_color_filter(status):
        mapping = {
            "New": "badge-new",
            "Investigating": "badge-investigating",
            "Contained": "badge-contained",
            "Closed": "badge-closed",
            "False Positive": "badge-fp"
        }
        return mapping.get(str(status), "badge-new")

    # Error Handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("base.html", error_title="404 - Resource Not Found", error_message="The requested endpoint or resource does not exist."), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template("base.html", error_title="500 - Internal Server Error", error_message="An unexpected server error occurred. Please consult application logs."), 500

    @app.errorhandler(413)
    def file_too_large(error):
        return jsonify({"success": False, "error_message": "File exceeds maximum permitted upload limit (16MB)."}), 413

    # Ensure tables exist
    with app.app_context():
        db.create_all()

    return app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] PrivilegeGuard AI starting on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=True)
