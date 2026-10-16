import json
from datetime import datetime, timezone
from models import Incident
from services.reporting import ReportingService

def test_reporting_generation(app):
    with app.app_context():
        # Create a mock incident
        inc = Incident(
            incident_id="INC-TEST-001",
            title="Unauthorized Root Escalation",
            affected_user="test_hacker",
            severity="critical",
            risk_score=95,
            risk_factors=json.dumps([{"factor": "Critical Rule", "points": 35, "description": "Triggered rule"}]),
            status="New",
            first_observed_at=datetime.now(timezone.utc),
            last_observed_at=datetime.now(timezone.utc),
            summary="Test summary of root escalation.",
            ai_explanation=json.dumps({
                "what_happened": "Root account self-assigned.",
                "why_flagged": "Rule 002 triggered.",
                "benign_explanation": "None.",
                "uncertainties": "Endpoint logs needed.",
                "investigation_playbook": ["Step 1", "Step 2"]
            }),
            recommended_actions=json.dumps(["Isolate host", "Revoke token"])
        )
        
        # Test JSON report
        json_rep = ReportingService.generate_incident_json(inc)
        assert json_rep["incident_details"]["incident_id"] == "INC-TEST-001"
        assert json_rep["incident_details"]["risk_score"] == 95
        assert len(json_rep["soc_recommendations"]) == 2

        # Test HTML report
        html_rep = ReportingService.generate_incident_html(inc)
        assert "<!DOCTYPE html>" in html_rep
        assert "INC-TEST-001" in html_rep
        assert "CRITICAL" in html_rep
        assert "Isolate host" in html_rep


def test_reporting_endpoints(client, app):
    with app.app_context():
        from models import db
        inc = Incident(
            incident_id="INC-ROUTE-001",
            title="Route Test Incident",
            affected_user="route_user",
            severity="high",
            risk_score=75,
            status="New",
            first_observed_at=datetime.now(timezone.utc),
            last_observed_at=datetime.now(timezone.utc)
        )
        db.session.add(inc)
        db.session.commit()
        inc_id = inc.id

    # Test download JSON
    res_json = client.get(f"/reports/incident/{inc_id}/json")
    assert res_json.status_code == 200
    assert res_json.content_type == "application/json"
    assert "INC-ROUTE-001" in res_json.get_data(as_text=True)

    # Test view HTML
    res_html = client.get(f"/reports/incident/{inc_id}/html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.content_type
    assert "INC-ROUTE-001" in res_html.get_data(as_text=True)

    # Test platform summary JSON
    res_platform = client.get("/reports/platform/json")
    assert res_platform.status_code == 200
    assert "PrivilegeGuard AI" in res_platform.get_data(as_text=True)
