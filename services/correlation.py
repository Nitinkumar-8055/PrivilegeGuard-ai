import json
import time
import random
import re
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set

from sqlalchemy.exc import SQLAlchemyError, OperationalError

from models import (
    db,
    SecurityEvent,
    Incident,
    IncidentEvent,
    DetectionAlert,
)
from services.risk_scoring import RiskScorer
from services.ai_analysis import AIAnalysisService
from config import Config


def _is_sqlite_locked_error(exc: Exception) -> bool:
    """Check if an exception is an SQLite database locked/busy OperationalError."""
    msg = str(exc).lower()
    return "database is locked" in msg or "database table is locked" in msg or "database is busy" in msg


class IncidentCorrelationEngine:
    """
    Correlates security alerts and related events into incidents.
    Calculates risk scores and stores supporting evidence.
    """

    @classmethod
    def generate_incident_id(cls, reserved_ids: Optional[Set[str]] = None) -> str:
        """Generate a unique human-readable incident identifier, preventing collisions."""
        year = datetime.now().year
        prefix = f"INC-{year}-"

        # Query existing IDs for this year from DB
        try:
            existing_rows = (
                db.session.query(Incident.incident_id)
                .filter(Incident.incident_id.like(f"{prefix}%"))
                .all()
            )
            existing_ids = [row[0] for row in existing_rows if row[0]]
        except Exception:
            existing_ids = []

        if reserved_ids:
            existing_ids.extend(list(reserved_ids))

        max_seq = 0
        pattern = re.compile(rf"^INC-{year}-(\d+)$")
        for inc_id in existing_ids:
            match = pattern.match(inc_id)
            if match:
                try:
                    seq = int(match.group(1))
                    if seq > max_seq:
                        max_seq = seq
                except ValueError:
                    pass

        new_id = f"{prefix}{max_seq + 1:04d}"
        if reserved_ids is not None:
            reserved_ids.add(new_id)
        return new_id

    @classmethod
    def correlate_alerts(
        cls,
        alert_dicts: List[Dict[str, Any]],
        config: Any = None,
    ) -> List[Incident]:
        """
        Group alerts by affected user, find related events,
        and create or update incidents.

        Decouples data gathering and AI analysis from database write transactions
        to prevent holding SQLite locks open during slow external calls.
        Uses bounded retries for transient database locking.
        """
        if not alert_dicts:
            return []

        cfg = config or Config()
        user_alerts: Dict[str, List[Dict[str, Any]]] = {}

        for alert in alert_dicts:
            user = alert.get("affected_user", "unknown")
            user_alerts.setdefault(user, []).append(alert)

        # -------------------------------------------------------------
        # Phase 1: Pre-fetch events and prepare analytical data
        # -------------------------------------------------------------
        all_event_ids = {
            eid
            for alert in alert_dicts
            for eid in alert.get("relevant_event_ids", [])
            if eid
        }

        events_by_id: Dict[str, SecurityEvent] = {}
        if all_event_ids:
            fetched_events = (
                SecurityEvent.query
                .filter(SecurityEvent.event_id.in_(list(all_event_ids)))
                .all()
            )
            for ev in fetched_events:
                events_by_id[ev.event_id] = ev

        # -------------------------------------------------------------
        # Phase 2: In-memory risk scoring, titling, and AI analysis
        # (NO write transaction is held during this phase!)
        # -------------------------------------------------------------
        prepared_data = []
        for user, alerts in user_alerts.items():
            user_event_ids = {
                eid
                for alert in alerts
                for eid in alert.get("relevant_event_ids", [])
                if eid
            }
            user_events = [events_by_id[eid] for eid in user_event_ids if eid in events_by_id]
            if not user_events:
                continue

            user_events.sort(key=lambda ev: ev.timestamp)
            first_ts = user_events[0].timestamp
            last_ts = user_events[-1].timestamp

            rule_ids = [alert.get("rule_id") for alert in alerts]

            if "RULE-004" in rule_ids:
                title = f"Sensitive Asset Access Following Privilege Escalation ({user})"
            elif "RULE-001" in rule_ids and any(ev.event_type == "login_success" for ev in user_events):
                title = f"Credential Compromise and Account Penetration ({user})"
            elif "RULE-003" in rule_ids:
                title = f"Unauthorized Privilege Grant and Role Modification ({user})"
            elif "RULE-002" in rule_ids:
                title = f"Unexpected Privilege Escalation to Sensitive Tier ({user})"
            elif "RULE-005" in rule_ids:
                title = f"Access Denied Enumeration & Boundary Testing ({user})"
            else:
                title = f"Suspicious Privilege & Identity Activity ({user})"

            risk_score, severity, risk_factors = RiskScorer.calculate_incident_risk(
                alerts, user_events, cfg
            )

            incident_meta = {
                "title": title,
                "affected_user": user,
                "severity": severity,
                "risk_score": risk_score,
            }

            events_dict_data = [ev.to_dict() for ev in user_events]

            # AI Analysis executed purely in-memory before write transaction
            ai_explanation = AIAnalysisService.analyze_incident(
                incident_meta,
                alerts,
                events_dict_data,
                cfg,
            ) or {}

            recommended_actions = ai_explanation.get(
                "investigation_playbook",
                [
                    "Review user authentication history",
                    "Verify role changes with system owners",
                    "Inspect sessions for suspicious activity",
                ],
            )

            prepared_data.append({
                "user": user,
                "alerts": alerts,
                "events": user_events,
                "first_ts": first_ts,
                "last_ts": last_ts,
                "title": title,
                "risk_score": risk_score,
                "severity": severity,
                "risk_factors": risk_factors,
                "ai_explanation": ai_explanation,
                "recommended_actions": recommended_actions,
            })

        if not prepared_data:
            return []

        # -------------------------------------------------------------
        # Phase 3: Fast Atomic Database Write with Bounded Retries
        # -------------------------------------------------------------
        max_retries = 5
        base_backoff = 0.1  # seconds

        for attempt in range(max_retries):
            try:
                processed_incidents: List[Incident] = []
                reserved_ids: Set[str] = set()

                for item in prepared_data:
                    user = item["user"]
                    alerts = item["alerts"]
                    events = item["events"]
                    first_ts = item["first_ts"]
                    last_ts = item["last_ts"]
                    title = item["title"]
                    risk_score = item["risk_score"]
                    severity = item["severity"]
                    risk_factors = item["risk_factors"]
                    ai_explanation = item["ai_explanation"]
                    recommended_actions = item["recommended_actions"]

                    # Check for existing incident matching user and time window (+/- 2 hours)
                    existing_incident = Incident.query.filter(
                        Incident.affected_user == user,
                        Incident.first_observed_at <= last_ts + timedelta(hours=2),
                        Incident.last_observed_at >= first_ts - timedelta(hours=2),
                    ).order_by(Incident.last_observed_at.desc()).first()

                    if existing_incident:
                        incident = existing_incident
                        incident.title = title
                        incident.last_observed_at = max(incident.last_observed_at, last_ts)
                        incident.risk_score = max(incident.risk_score, risk_score)
                        incident.severity = RiskScorer.get_severity_from_score(incident.risk_score)
                        incident.risk_factors = json.dumps(risk_factors)
                        incident.ai_explanation = json.dumps(ai_explanation)
                        incident.recommended_actions = json.dumps(recommended_actions)
                        incident.summary = ai_explanation.get("what_happened")

                        existing_event_ids = {
                            eid for (eid,) in (
                                db.session.query(IncidentEvent.event_id)
                                .filter(IncidentEvent.incident_id == incident.id)
                                .all()
                            )
                        }

                        for event in events:
                            if event.id not in existing_event_ids:
                                db.session.add(
                                    IncidentEvent(
                                        incident_id=incident.id,
                                        event_id=event.id,
                                        role_in_incident="correlated_evidence",
                                    )
                                )

                        existing_alerts = DetectionAlert.query.filter_by(
                            incident_id=incident.id
                        ).all()

                        existing_alert_signatures = set()
                        for record in existing_alerts:
                            try:
                                eids = (
                                    json.loads(record.relevant_event_ids)
                                    if record.relevant_event_ids
                                    else []
                                )
                            except (json.JSONDecodeError, TypeError):
                                eids = []
                            existing_alert_signatures.add(
                                (
                                    record.rule_id,
                                    tuple(sorted(str(eid) for eid in eids)),
                                )
                            )

                        for alert in alerts:
                            sig = (
                                alert["rule_id"],
                                tuple(sorted(str(eid) for eid in alert.get("relevant_event_ids", []))),
                            )
                            if sig in existing_alert_signatures:
                                continue

                            detected_at = alert.get("detected_at")
                            if not isinstance(detected_at, datetime):
                                detected_at = datetime.now(timezone.utc)

                            db.session.add(
                                DetectionAlert(
                                    incident_id=incident.id,
                                    rule_id=alert["rule_id"],
                                    rule_name=alert["rule_name"],
                                    affected_user=user,
                                    severity=alert["severity"],
                                    reason=alert["reason"],
                                    suggested_investigation_steps=json.dumps(
                                        alert.get("suggested_investigation_steps", [])
                                    ),
                                    relevant_event_ids=json.dumps(
                                        alert.get("relevant_event_ids", [])
                                    ),
                                    detected_at=detected_at,
                                )
                            )
                            existing_alert_signatures.add(sig)

                    else:
                        inc_id = cls.generate_incident_id(reserved_ids=reserved_ids)
                        incident = Incident(
                            incident_id=inc_id,
                            title=title,
                            affected_user=user,
                            severity=severity,
                            risk_score=risk_score,
                            risk_factors=json.dumps(risk_factors),
                            status="New",
                            first_observed_at=first_ts,
                            last_observed_at=last_ts,
                            summary=ai_explanation.get("what_happened"),
                            ai_explanation=json.dumps(ai_explanation),
                            recommended_actions=json.dumps(recommended_actions),
                        )
                        db.session.add(incident)
                        db.session.flush()

                        for event in events:
                            db.session.add(
                                IncidentEvent(
                                    incident_id=incident.id,
                                    event_id=event.id,
                                    role_in_incident="trigger_evidence",
                                )
                            )

                        for alert in alerts:
                            detected_at = alert.get("detected_at")
                            if not isinstance(detected_at, datetime):
                                detected_at = datetime.now(timezone.utc)

                            db.session.add(
                                DetectionAlert(
                                    incident_id=incident.id,
                                    rule_id=alert["rule_id"],
                                    rule_name=alert["rule_name"],
                                    affected_user=user,
                                    severity=alert["severity"],
                                    reason=alert["reason"],
                                    suggested_investigation_steps=json.dumps(
                                        alert.get("suggested_investigation_steps", [])
                                    ),
                                    relevant_event_ids=json.dumps(
                                        alert.get("relevant_event_ids", [])
                                    ),
                                    detected_at=detected_at,
                                )
                            )

                    processed_incidents.append(incident)

                db.session.commit()
                return processed_incidents

            except (OperationalError, SQLAlchemyError) as exc:
                db.session.rollback()
                if _is_sqlite_locked_error(exc) and attempt < max_retries - 1:
                    sleep_time = (base_backoff * (2 ** attempt)) + random.uniform(0.02, 0.08)
                    time.sleep(sleep_time)
                    continue
                raise