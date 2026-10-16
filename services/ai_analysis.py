import json
import re
import urllib.request
import urllib.error
from typing import Dict, Any, List
from datetime import datetime
from config import Config

class AIAnalysisService:
    """
    Generates structured, explainable security incident analyses.
    Uses local Ollama LLM if available; gracefully falls back to deterministic rule-based analysis.
    """

    @classmethod
    def analyze_incident(
        cls,
        incident_data: Dict[str, Any],
        alerts_data: List[Dict[str, Any]],
        events_data: List[Dict[str, Any]],
        config: Any = None
    ) -> Dict[str, Any]:
        """
        Produce a comprehensive incident explanation.
        Tries Ollama first (if reachable); falls back immediately to deterministic analysis.
        """
        cfg = config or Config()
        ollama_url = getattr(cfg, "OLLAMA_API_URL", "http://localhost:11434/api/generate")
        ollama_model = getattr(cfg, "OLLAMA_MODEL", "llama3")
        timeout = getattr(cfg, "OLLAMA_TIMEOUT_SECONDS", 5)

        valid_event_ids = set(e.get("event_id") for e in events_data if e.get("event_id"))

        # Attempt Ollama query if reachable
        ai_result = cls._query_ollama(ollama_url, ollama_model, incident_data, alerts_data, events_data, valid_event_ids, timeout)
        if ai_result:
            ai_result["provider"] = f"Ollama Local LLM ({ollama_model})"
            return ai_result

        # Deterministic Fallback Engine
        return cls._generate_deterministic_explanation(incident_data, alerts_data, events_data, valid_event_ids)

    @classmethod
    def _query_ollama(
        cls,
        url: str,
        model: str,
        incident_data: Dict[str, Any],
        alerts_data: List[Dict[str, Any]],
        events_data: List[Dict[str, Any]],
        valid_event_ids: set,
        timeout: int
    ) -> Dict[str, Any]:
        """Query local Ollama server with safety and structured output validation."""
        # Sanitize untrusted input strings
        safe_events = []
        for ev in events_data:
            safe_events.append({
                "event_id": str(ev.get("event_id"))[:64],
                "timestamp": str(ev.get("timestamp")),
                "type": str(ev.get("event_type")),
                "user": str(ev.get("username"))[:100],
                "actor": str(ev.get("actor") or "")[:100],
                "role_change": f"{ev.get('old_role')} -> {ev.get('new_role')}" if ev.get("new_role") else "N/A",
                "resource": str(ev.get("resource") or "")[:150],
                "outcome": str(ev.get("outcome"))[:50]
            })

        system_instruction = (
            "You are a Senior Cyber Incident Response Analyst. Analyze the provided identity and access security incident. "
            "You MUST output ONLY a valid JSON object with EXACTLY these keys:\n"
            "- what_happened: string summarizing the chain of events\n"
            "- why_flagged: string explaining the policy violations or suspicious signals\n"
            "- supporting_events: list of strings (ONLY use the exact event_id values provided in the prompt)\n"
            "- benign_explanation: string describing any plausible legitimate or operational reason\n"
            "- uncertainties: string describing what cannot be confirmed without further host/network logs\n"
            "- investigation_playbook: list of 3-5 concrete action items for the SOC analyst\n"
            "DO NOT invent event IDs. DO NOT include markdown formatting outside the JSON."
        )

        prompt_payload = {
            "incident": {
                "title": incident_data.get("title"),
                "affected_user": incident_data.get("affected_user"),
                "severity": incident_data.get("severity"),
                "risk_score": incident_data.get("risk_score")
            },
            "alerts": alerts_data,
            "evidence_events": safe_events
        }

        body = {
            "model": model,
            "prompt": f"{system_instruction}\n\nEvidence Data:\n{json.dumps(prompt_payload, indent=2, default=str)}",
            "stream": False,
            "format": "json"
        }

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(body, default=str).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    resp_data = json.loads(response.read().decode("utf-8"))
                    raw_response = resp_data.get("response", "{}").strip()
                    if raw_response.startswith("```"):
                        raw_response = re.sub(r"^```(?:json)?\s*", "", raw_response)
                        raw_response = re.sub(r"\s*```$", "", raw_response)
                    parsed = json.loads(raw_response)

                    # Validate event IDs against actual incident events
                    raw_supp_events = parsed.get("supporting_events", [])
                    validated_events = [str(eid) for eid in raw_supp_events if str(eid) in valid_event_ids]

                    return {
                        "what_happened": str(parsed.get("what_happened", "Analysis generated by local AI.")),
                        "why_flagged": str(parsed.get("why_flagged", "Triggered policy and privilege detection rules.")),
                        "supporting_events": validated_events if validated_events else list(valid_event_ids),
                        "benign_explanation": str(parsed.get("benign_explanation", "No benign explanation identified.")),
                        "uncertainties": str(parsed.get("uncertainties", "Source host telemetry and user confirmation required.")),
                        "investigation_playbook": parsed.get("investigation_playbook", []),
                        "is_fallback": False
                    }
        except Exception:
            # If Ollama is offline or uninstalled, seamlessly fallback
            return None

    @classmethod
    def _generate_deterministic_explanation(
        cls,
        incident_data: Dict[str, Any],
        alerts_data: List[Dict[str, Any]],
        events_data: List[Dict[str, Any]],
        valid_event_ids: set
    ) -> Dict[str, Any]:
        """
        Generates an accurate, explainable, domain-grounded cybersecurity analysis
        without external AI dependencies.
        """
        user = incident_data.get("affected_user", "Unknown Account")
        title = incident_data.get("title", "Privilege and Identity Anomaly")
        risk_score = incident_data.get("risk_score", 0)
        rule_ids = [a.get("rule_id") for a in alerts_data]

        event_types = [e.get("event_type") for e in events_data]
        resources = list(set([e.get("resource") for e in events_data if e.get("resource")]))
        actors = list(set([e.get("actor") for e in events_data if e.get("actor")]))

        what_happened_parts = []
        why_flagged_parts = []
        playbook = []
        benign_parts = []
        uncertainties = []

        if "RULE-001" in rule_ids:
            fail_count = event_types.count("login_failure")
            has_success = "login_success" in event_types
            if has_success:
                what_happened_parts.append(
                    f"A credential assault was observed against account '{user}' consisting of {fail_count} failed login attempts, "
                    f"followed by a successful authentication."
                )
                why_flagged_parts.append(
                    "Rapid failed authentications preceding a successful entry strongly resemble automated dictionary guessing, "
                    "credential stuffing, or brute-force penetration."
                )
                playbook.extend([
                    f"Review authentication source IP geolocation and cross-reference with known company VPN exit nodes.",
                    f"Initiate an out-of-band contact with '{user}' to confirm if they made the login attempt.",
                    f"Revoke all active sessions and enforce an immediate password and MFA token reset."
                ])
                benign_parts.append(
                    f"The user '{user}' may have forgotten their password or had an automated mobile client retrying stale credentials "
                    f"before successfully entering the correct password."
                )
            else:
                what_happened_parts.append(f"Account '{user}' was subjected to {fail_count} consecutive failed login attempts.")
                why_flagged_parts.append("Repeated authentication failures exceed the security threshold.")
                playbook.append("Monitor account for further authentication attempts or lockouts.")
                benign_parts.append("User typo or expired credentials cached in an email client.")

        if "RULE-004" in rule_ids:
            res_str = ", ".join(resources) if resources else "sensitive directories/vaults"
            what_happened_parts.append(
                f"Immediately following an elevated privilege assignment, account '{user}' accessed high-value sensitive resources: [{res_str}]."
            )
            why_flagged_parts.append(
                "Immediate resource access following privilege acquisition matches the MITRE ATT&CK tactic of Privilege Escalation (TA0004) "
                "coupled with Collection (TA0009)."
            )
            playbook.extend([
                f"Verify whether access to sensitive resource(s) [{res_str}] had an approved change ticket or operational justification.",
                "Review data transfer sizes and egress connections from the host to verify if data exfiltration occurred.",
                "Quarantine affected service tokens and rotate encryption keys or database credentials accessed."
            ])
            benign_parts.append(
                "An engineer or database administrator may have been granted emergency just-in-time (JIT) access to resolve a critical production incident."
            )

        if "RULE-002" in rule_ids:
            elevated_roles = [e.get("new_role") for e in events_data if e.get("new_role")]
            role_str = ", ".join(set(elevated_roles)) if elevated_roles else "administrative tier"
            what_happened_parts.append(
                f"Account '{user}' was promoted to a high-privilege administrative role: '{role_str}'."
            )
            why_flagged_parts.append(
                f"Transition from a standard user role to '{role_str}' represents an unexpected leap in authority that violates least-privilege baselines."
            )
            playbook.append(f"Audit the authorization trail for the elevation of '{user}' to '{role_str}'.")
            benign_parts.append("A scheduled promotion or role change executed through an internal provisioning workflow.")

        if "RULE-003" in rule_ids:
            unauth_actors = [a for a in actors if a != user]
            actor_str = ", ".join(unauth_actors) if unauth_actors else "an unauthorized entity"
            what_happened_parts.append(
                f"Privilege modifications were executed by actor '{actor_str}', who lacks identity governance authorization."
            )
            why_flagged_parts.append(
                "Access control policies restrict role assignments exclusively to designated Identity Governance managers."
            )
            playbook.append(f"Isolate actor '{actor_str}' and inspect their access history for potential identity provider compromise.")
            benign_parts.append("An IT helpdesk administrator performing out-of-band manual user assistance without automated workflow integration.")

        # Default fallbacks if no specific rule text matched
        if not what_happened_parts:
            what_happened_parts.append(f"Suspicious identity activities and access patterns detected for account '{user}'.")
        if not why_flagged_parts:
            why_flagged_parts.append(f"The observed activity triggered security detection rules with a risk score of {risk_score}/100.")
        if not benign_parts:
            benign_parts.append("Routine maintenance by authorized personnel during an off-hours operational window.")
        if not playbook:
            playbook = [
                f"Review complete authentication log history for '{user}'.",
                "Contact the user's direct manager to confirm current project assignments.",
                "Check perimeter firewall and VPN logs for contemporaneous connections."
            ]

        uncertainties.append(
            "Telemetry from the local endpoint (process execution, command-line arguments) is required to determine whether user actions were automated or interactive."
        )
        uncertainties.append(
            "Network egress captures and session payloads are not stored in access logs, so data exfiltration volume must be corroborated via NetFlow or proxy logs."
        )

        return {
            "what_happened": " ".join(what_happened_parts),
            "why_flagged": " ".join(why_flagged_parts),
            "supporting_events": list(valid_event_ids),
            "benign_explanation": " ".join(benign_parts),
            "uncertainties": " ".join(uncertainties),
            "investigation_playbook": playbook,
            "provider": "PrivilegeGuard Deterministic Expert Security Engine (Built-in Rule Analysis)",
            "is_fallback": True
        }
