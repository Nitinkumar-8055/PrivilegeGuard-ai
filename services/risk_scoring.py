from typing import List, Dict, Any, Tuple
from config import Config

class RiskScorer:
    """Calculates an explainable 0-100 risk score with clear factor breakdowns."""

    SEVERITY_BANDS = [
        (0, 29, "low"),
        (30, 59, "medium"),
        (60, 79, "high"),
        (80, 100, "critical")
    ]

    @classmethod
    def get_severity_from_score(cls, score: int) -> str:
        """Map numeric score (0-100) to standard severity label."""
        for low, high, label in cls.SEVERITY_BANDS:
            if low <= score <= high:
                return label
        return "critical" if score >= 80 else "low"

    @classmethod
    def calculate_incident_risk(
        cls,
        alerts: List[Dict[str, Any]],
        events: List[Any],
        config: Any = None
    ) -> Tuple[int, str, List[Dict[str, Any]]]:
        """
        Calculates the risk score and returns:
        (total_score, severity_label, factor_breakdowns)
        """
        cfg = config or Config()
        sensitive_roles = set(r.lower() for r in getattr(cfg, "SENSITIVE_ROLES", []))
        sensitive_resources = set(sr.lower() for sr in getattr(cfg, "SENSITIVE_RESOURCES", []))
        authorized_managers = set(am.lower() for am in getattr(cfg, "AUTHORIZED_ROLE_MANAGERS", []))

        factors: List[Dict[str, Any]] = []
        score = 0

        if not alerts and not events:
            return 0, "low", []

        # -------------------------------------------------------------
        # 1. Primary Rule Alert Severity Base Factor
        # -------------------------------------------------------------
        severities = [a.get("severity", "low").lower() for a in alerts]
        if "critical" in severities:
            pts = 45
            factors.append({
                "factor": "Triggered Critical Detection Rule",
                "points": pts,
                "description": "At least one critical detection rule was triggered (e.g. sensitive resource access post-escalation)."
            })
            score += pts
        elif "high" in severities:
            pts = 35
            factors.append({
                "factor": "Triggered High Severity Rule",
                "points": pts,
                "description": "At least one high severity rule was triggered (e.g. unexpected privilege escalation or brute force success)."
            })
            score += pts
        elif "medium" in severities:
            pts = 20
            factors.append({
                "factor": "Triggered Medium Severity Rule",
                "points": pts,
                "description": "At least one medium severity rule was triggered."
            })
            score += pts
        elif "low" in severities:
            pts = 10
            factors.append({
                "factor": "Triggered Low Severity Rule",
                "points": pts,
                "description": "Low severity rule triggered."
            })
            score += pts

        # Multi-alert compound bonus (avoiding linear double counting)
        if len(alerts) > 1:
            multi_pts = min(15, (len(alerts) - 1) * 8)
            factors.append({
                "factor": f"Compound Alert Concurrency ({len(alerts)} alerts)",
                "points": multi_pts,
                "description": f"Incident spans multiple distinct detection rules ({len(alerts)} alerts)."
            })
            score += multi_pts

        # -------------------------------------------------------------
        # 2. Privilege Level Involved Factor
        # -------------------------------------------------------------
        elevated_to_sensitive = any(
            (ev.new_role or "").lower() in sensitive_roles
            for ev in events
        )
        if elevated_to_sensitive:
            pts = 15
            factors.append({
                "factor": "Sensitive Administrative Role Target",
                "points": pts,
                "description": "Event sequence involves escalation into a sensitive role (e.g., admin, root, secops)."
            })
            score += pts

        # -------------------------------------------------------------
        # 3. High-Value / Sensitive Resource Target Factor
        # -------------------------------------------------------------
        sensitive_target_hit = any(
            any(sr in (ev.resource or "").lower() for sr in sensitive_resources)
            for ev in events
            if ev.event_type == "resource_access"
        )
        if sensitive_target_hit:
            pts = 20
            factors.append({
                "factor": "Access to High-Value Sensitive Asset",
                "points": pts,
                "description": "Target resources include critical infrastructure, cryptographic keys, or customer PII databases."
            })
            score += pts

        # -------------------------------------------------------------
        # 4. Unauthorized Actor / Self-Elevation Factor
        # -------------------------------------------------------------
        unauthorized_actor_detected = any(
            ev.event_type in ("role_change", "permission_grant") and
            ev.actor and
            (ev.actor.lower() not in authorized_managers or ev.actor.lower() == ev.username.lower())
            for ev in events
        )
        if unauthorized_actor_detected:
            pts = 15
            factors.append({
                "factor": "Unauthorized Actor / Self-Elevation",
                "points": pts,
                "description": "Privilege assignment initiated by an unauthorized actor or an account elevating itself."
            })
            score += pts

        # -------------------------------------------------------------
        # 5. Brute Force Sequence (Failures followed by Success)
        # -------------------------------------------------------------
        rule_ids = [a.get("rule_id") for a in alerts]
        if "RULE-001" in rule_ids:
            has_success = any(ev.event_type == "login_success" for ev in events)
            has_failures = any(ev.event_type == "login_failure" for ev in events)
            if has_success and has_failures:
                pts = 25
                factors.append({
                    "factor": "Authentication Compromise Indicator",
                    "points": pts,
                    "description": "Successful login followed a cluster of repeated failed login attempts from the same identity/IP."
                })
                score += pts

        # Clamp score between 0 and 100
        final_score = max(0, min(100, score))
        severity = cls.get_severity_from_score(final_score)

        return final_score, severity, factors
