from flask import Blueprint, render_template, request, jsonify
from models import SecurityEvent, db

events_bp = Blueprint("events", __name__)

@events_bp.route("/events")
def events_page():
    """Renders the Event Explorer table and search interface."""
    return render_template("events.html")

@events_bp.route("/api/events")
def get_events():
    """
    Search and filter ingested events.
    Supports queries: search, event_type, username, outcome, page, per_page.
    """
    search = request.args.get("search", "").strip()
    event_type = request.args.get("event_type", "").strip()
    username = request.args.get("username", "").strip()
    outcome = request.args.get("outcome", "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 25, type=int)

    query = SecurityEvent.query

    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            db.or_(
                SecurityEvent.event_id.ilike(search_filter),
                SecurityEvent.username.ilike(search_filter),
                SecurityEvent.actor.ilike(search_filter),
                SecurityEvent.resource.ilike(search_filter),
                SecurityEvent.source_ip.ilike(search_filter),
                SecurityEvent.action.ilike(search_filter)
            )
        )

    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)

    if username:
        query = query.filter(SecurityEvent.username.ilike(f"%{username}%"))

    if outcome:
        query = query.filter(SecurityEvent.outcome == outcome.lower())

    # Order by timestamp descending (most recent first)
    query = query.order_by(SecurityEvent.timestamp.desc())

    total = query.count()
    paginated = query.offset((page - 1) * per_page).limit(per_page).all()

    # Get distinct event types and outcomes for filter dropdowns
    distinct_types = [r[0] for r in db.session.query(SecurityEvent.event_type).distinct().all() if r[0]]
    distinct_outcomes = [r[0] for r in db.session.query(SecurityEvent.outcome).distinct().all() if r[0]]

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page if per_page > 0 else 1,
        "events": [e.to_dict() for e in paginated],
        "filter_options": {
            "event_types": sorted(distinct_types),
            "outcomes": sorted(distinct_outcomes)
        }
    })

@events_bp.route("/api/events/<int:event_id>")
def get_event_detail(event_id):
    """Retrieve full detail for a single event."""
    event = db.get_or_404(SecurityEvent, event_id)
    return jsonify(event.to_dict())
