
from services.ai_service import explain_incident

sample_incident = {
    "incident_id": "TEST-001",
    "event_type": "privilege_escalation",
    "severity": "High",
    "risk_score": 82,
    "evidence": [
        "A privilege change was recorded.",
        "Sensitive resource access followed the change."
    ]
}

if __name__ == "__main__":
    try:
        explanation = explain_incident(sample_incident)
        print("\n--- AI Incident Explanation ---\n")
        print(explanation)
    except RuntimeError as error:
        print(f"AI service error: {error}")
