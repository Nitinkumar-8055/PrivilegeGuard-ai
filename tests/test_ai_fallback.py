import json
from unittest.mock import patch, MagicMock
import io
from services.ai_analysis import AIAnalysisService
from config import TestConfig

def test_deterministic_ai_fallback():
    incident_meta = {
        "title": "Brute Force Penetration",
        "affected_user": "target_admin",
        "severity": "high",
        "risk_score": 75
    }
    alerts = [
        {"rule_id": "RULE-001", "severity": "high", "reason": "Failed logins followed by success"}
    ]
    events = [
        {"event_id": "EVT-FAIL-1", "event_type": "login_failure", "username": "target_admin"},
        {"event_id": "EVT-FAIL-2", "event_type": "login_failure", "username": "target_admin"},
        {"event_id": "EVT-SUCC-1", "event_type": "login_success", "username": "target_admin"}
    ]

    # Test with non-existent Ollama port/url to ensure fallback activates
    class OfflineConfig:
        OLLAMA_API_URL = "http://127.0.0.1:9999/api/generate"
        OLLAMA_MODEL = "test_offline"
        OLLAMA_TIMEOUT_SECONDS = 1

    analysis = AIAnalysisService.analyze_incident(incident_meta, alerts, events, OfflineConfig)

    assert analysis is not None
    assert "what_happened" in analysis
    assert "why_flagged" in analysis
    assert "supporting_events" in analysis
    assert "benign_explanation" in analysis
    assert "uncertainties" in analysis
    assert "investigation_playbook" in analysis

    assert isinstance(analysis["investigation_playbook"], list)
    assert len(analysis["investigation_playbook"]) > 0

    # Ensure supporting events are strictly matching valid event IDs
    assert "EVT-FAIL-1" in analysis["supporting_events"]
    assert "EVT-SUCC-1" in analysis["supporting_events"]
    assert analysis["is_fallback"] is True
    assert "Deterministic" in analysis["provider"]


def test_ollama_mocked_success_and_hallucination_defense():
    """Verify that when Ollama responds, fabricated event IDs are stripped and markdown fences handled."""
    incident_meta = {
        "title": "Privilege Escalation",
        "affected_user": "victim_user",
        "severity": "critical",
        "risk_score": 90
    }
    alerts = [
        {"rule_id": "RULE-002", "severity": "critical", "reason": "Root escalation"}
    ]
    events = [
        {"event_id": "VALID-EVT-1", "event_type": "role_change", "username": "victim_user"}
    ]

    mock_ollama_llm_json = {
        "what_happened": "User escalated to root.",
        "why_flagged": "Policy violation.",
        "supporting_events": ["VALID-EVT-1", "FABRICATED-EVT-999"],  # Notice the hallucinated ID!
        "benign_explanation": "Break-glass maintenance.",
        "uncertainties": "Need endpoint telemetry.",
        "investigation_playbook": ["Verify change ticket", "Rotate root keys"]
    }

    # Wrap in markdown fence as LLMs frequently do
    wrapped_response = f"```json\n{json.dumps(mock_ollama_llm_json)}\n```"

    mock_http_response = MagicMock()
    mock_http_response.status = 200
    mock_http_response.read.return_value = json.dumps({"response": wrapped_response}).encode("utf-8")
    mock_http_response.__enter__.return_value = mock_http_response

    with patch("urllib.request.urlopen", return_value=mock_http_response):
        analysis = AIAnalysisService.analyze_incident(incident_meta, alerts, events, TestConfig)

        assert analysis is not None
        assert analysis["is_fallback"] is False
        assert "Ollama Local LLM" in analysis["provider"]
        assert "VALID-EVT-1" in analysis["supporting_events"]
        # CRITICAL VERIFICATION: The hallucinated ID was filtered out!
        assert "FABRICATED-EVT-999" not in analysis["supporting_events"]
        assert analysis["what_happened"] == "User escalated to root."
