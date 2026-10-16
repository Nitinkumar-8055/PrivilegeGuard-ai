from services.risk_scoring import RiskScorer
from config import TestConfig

class DummyEvent:
    def __init__(self, **kwargs):
        self.event_type = kwargs.get("event_type", "login_success")
        self.new_role = kwargs.get("new_role", None)
        self.resource = kwargs.get("resource", None)
        self.actor = kwargs.get("actor", None)
        self.username = kwargs.get("username", "user1")


def test_risk_scoring_empty():
    score, sev, factors = RiskScorer.calculate_incident_risk([], [], TestConfig)
    assert score == 0
    assert sev == "low"
    assert factors == []


def test_risk_scoring_critical_composite():
    alerts = [
        {"rule_id": "RULE-004", "severity": "critical"},
        {"rule_id": "RULE-002", "severity": "high"}
    ]
    events = [
        DummyEvent(event_type="role_change", new_role="root", actor="user1", username="user1"),
        DummyEvent(event_type="resource_access", resource="/api/v1/vault/keys", username="user1")
    ]

    score, sev, factors = RiskScorer.calculate_incident_risk(alerts, events, TestConfig)
    
    assert 0 <= score <= 100
    assert score >= 80
    assert sev == "critical"
    
    factor_names = [f["factor"] for f in factors]
    assert any("Critical Detection Rule" in fn for fn in factor_names)
    assert any("Sensitive Administrative Role" in fn for fn in factor_names)
    assert any("High-Value Sensitive Asset" in fn for fn in factor_names)
    assert any("Self-Elevation" in fn for fn in factor_names)


def test_severity_bands():
    assert RiskScorer.get_severity_from_score(15) == "low"
    assert RiskScorer.get_severity_from_score(45) == "medium"
    assert RiskScorer.get_severity_from_score(65) == "high"
    assert RiskScorer.get_severity_from_score(92) == "critical"
