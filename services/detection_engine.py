from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import json

from config import Config


class BaseDetectionRule(ABC):
    """Abstract base class for all deterministic security detection rules."""
    rule_id: str
    rule_name: str
    severity: str
    description: str

    @abstractmethod
    def evaluate(self, events: List[Any], config: Any) -> List[Dict[str, Any]]:
        """
        Evaluates a chronologically sorted list of events.
        Returns a list of alert dictionaries:
        {
            "rule_id": str,
            "rule_name": str,
            "affected_user": str,
            "severity": str,
            "reason": str,
            "suggested_investigation_steps": List[str],
            "relevant_event_ids": List[str],
            "detected_at": datetime
        }
        """
        pass


class RuleRepeatedFailedLogins(BaseDetectionRule):
    """
    Rule 1: Detects repeated failed logins for the same user within a configurable time window.
    If a successful login follows, includes that event and escalates severity.
    """
    rule_id = "RULE-001"
    rule_name = "Repeated Failed Logins / Potential Brute Force"
    severity = "medium"
    description = "Detects multiple failed authentication attempts within a time window, flagging credential abuse."

    def evaluate(self, events: List[Any], config: Any) -> List[Dict[str, Any]]:
        threshold = getattr(config, "FAILED_LOGIN_THRESHOLD", 3)
        window_minutes = getattr(config, "FAILED_LOGIN_WINDOW_MINUTES", 15)
        window_delta = timedelta(minutes=window_minutes)

        # Group events by user
        user_events: Dict[str, List[Any]] = {}
        for ev in events:
            user = ev.username
            if user not in user_events:
                user_events[user] = []
            user_events[user].append(ev)

        alerts = []

        for user, u_evs in user_events.items():
            # Filter login events
            logins = [e for e in u_evs if e.event_type in ("login_failure", "login_success")]
            # Sort chronologically
            logins.sort(key=lambda x: x.timestamp)

            i = 0
            while i < len(logins):
                if logins[i].event_type == "login_failure":
                    # Collect failures within window starting from logins[i]
                    start_time = logins[i].timestamp
                    fail_cluster = []
                    j = i
                    while j < len(logins) and logins[j].timestamp - start_time <= window_delta:
                        if logins[j].event_type == "login_failure":
                            fail_cluster.append(logins[j])
                        j += 1

                    if len(fail_cluster) >= threshold:
                        # Check for subsequent successful login within 30 min of the last failure
                        last_fail_time = fail_cluster[-1].timestamp
                        subsequent_success = None
                        for s_candidate in logins:
                            if (s_candidate.event_type == "login_success" and
                                    s_candidate.timestamp > last_fail_time and
                                    (s_candidate.timestamp - last_fail_time) <= timedelta(minutes=30)):
                                subsequent_success = s_candidate
                                break

                        event_ids = [f.event_id for f in fail_cluster]
                        if subsequent_success:
                            event_ids.append(subsequent_success.event_id)
                            severity = "high"
                            reason = (
                                f"Observed {len(fail_cluster)} consecutive failed logins for user '{user}' "
                                f"within {window_minutes} minutes, followed immediately by a successful login "
                                f"(event {subsequent_success.event_id}) from source IP {subsequent_success.source_ip}. "
                                "High probability of credential stuffing or brute-force penetration."
                            )
                            steps = [
                                f"Verify whether '{user}' authorized the successful login from IP {subsequent_success.source_ip}.",
                                "Force an immediate password reset and invalidate all active session tokens.",
                                "Examine source IP reputation and block if confirmed malicious.",
                                "Inspect post-authentication activity for anomalous API or resource usage."
                            ]
                        else:
                            severity = "medium"
                            reason = (
                                f"Detected {len(fail_cluster)} failed login attempts for user '{user}' "
                                f"within {window_minutes} minutes without subsequent successful login."
                            )
                            steps = [
                                f"Notify user '{user}' of repeated failed authentication attempts.",
                                "Verify if user recently changed passwords on mobile/workstation clients.",
                                "Check source IP addresses for distributed spraying indicators."
                            ]

                        alerts.append({
                            "rule_id": self.rule_id,
                            "rule_name": self.rule_name,
                            "affected_user": user,
                            "severity": severity,
                            "reason": reason,
                            "suggested_investigation_steps": steps,
                            "relevant_event_ids": event_ids,
                            "detected_at": datetime.now(timezone.utc)
                        })

                        # Skip ahead past this cluster
                        i = j - 1
                i += 1

        return alerts


class RuleUnexpectedPrivilegeEscalation(BaseDetectionRule):
    """
    Rule 2: Detects an ordinary account receiving administrator privileges or another sensitive role unexpectedly.
    Considers the configured role policy and actor who initiated the change.
    """
    rule_id = "RULE-002"
    rule_name = "Unexpected Privilege Escalation"
    severity = "high"
    description = "Flags promotion of non-privileged accounts to sensitive administrative tiers."

    def evaluate(self, events: List[Any], config: Any) -> List[Dict[str, Any]]:
        sensitive_roles = set(r.lower() for r in getattr(config, "SENSITIVE_ROLES", []))
        authorized_managers = set(m.lower() for m in getattr(config, "AUTHORIZED_ROLE_MANAGERS", []))

        alerts = []
        for ev in events:
            if ev.event_type in ("role_change", "permission_grant"):
                new_role = (ev.new_role or "").strip().lower()
                old_role = (ev.old_role or "").strip().lower()
                actor = (ev.actor or "").strip().lower()
                user = ev.username

                # Check if elevated to sensitive role from non-sensitive role
                if new_role in sensitive_roles and old_role not in sensitive_roles:
                    is_self_elevation = (actor and actor == user.lower())
                    is_unauthorized_actor = (actor and actor not in authorized_managers)

                    if is_self_elevation:
                        severity = "critical"
                        reason = (
                            f"User '{user}' unexpectedly elevated their own role from '{ev.old_role}' "
                            f"to privileged role '{ev.new_role}' (self-elevation)."
                        )
                    elif is_unauthorized_actor:
                        severity = "high"
                        reason = (
                            f"User '{user}' was promoted from '{ev.old_role}' to sensitive role '{ev.new_role}' "
                            f"by actor '{ev.actor}', who is not an authorized role manager."
                        )
                    else:
                        severity = "medium"
                        reason = (
                            f"User '{user}' received privileged role '{ev.new_role}' (previously '{ev.old_role}'). "
                            "Requires verification against change management tickets."
                        )

                    alerts.append({
                        "rule_id": self.rule_id,
                        "rule_name": self.rule_name,
                        "affected_user": user,
                        "severity": severity,
                        "reason": reason,
                        "suggested_investigation_steps": [
                            f"Cross-reference promotion of '{user}' with ticketing system / change approval.",
                            f"Audit actor '{ev.actor}' for credential compromise or lateral movement.",
                            "Review effective permissions granted under the new role.",
                            "Prepare to roll back role assignment if no formal authorization exists."
                        ],
                        "relevant_event_ids": [ev.event_id],
                        "detected_at": datetime.now(timezone.utc)
                    })

        return alerts


class RuleUnauthorizedPrivilegeGrant(BaseDetectionRule):
    """
    Rule 3: Detects permission grants or role changes initiated by an actor who is not
    authorized to perform that action under the configured policy.
    """
    rule_id = "RULE-003"
    rule_name = "Unauthorized Privilege Grant"
    severity = "high"
    description = "Detects role modifications and permission grants made by unauthorized actors."

    def evaluate(self, events: List[Any], config: Any) -> List[Dict[str, Any]]:
        authorized_managers = set(m.lower() for m in getattr(config, "AUTHORIZED_ROLE_MANAGERS", []))

        alerts = []
        for ev in events:
            if ev.event_type in ("role_change", "permission_grant"):
                actor = (ev.actor or "").strip().lower()
                user = ev.username

                # If actor is not in authorized list
                if actor and actor not in authorized_managers:
                    reason = (
                        f"Actor '{ev.actor}' executed {ev.event_type} on user '{user}' "
                        f"(assigned role/permission '{ev.new_role or ev.action or ev.resource}'). "
                        "The actor is not present in the authorized role management policy."
                    )
                    alerts.append({
                        "rule_id": self.rule_id,
                        "rule_name": self.rule_name,
                        "affected_user": user,
                        "severity": "high",
                        "reason": reason,
                        "suggested_investigation_steps": [
                            f"Immediately verify the identity and current access level of actor '{ev.actor}'.",
                            "Determine how actor bypassed policy controls to issue privilege assignments.",
                            f"Temporarily suspend granted permissions for target user '{user}'.",
                            "Conduct security audit of the identity provider administration portal."
                        ],
                        "relevant_event_ids": [ev.event_id],
                        "detected_at": datetime.now(timezone.utc)
                    })

        return alerts


class RuleSensitiveAccessFollowingPrivilegeChange(BaseDetectionRule):
    """
    Rule 4: Correlates a privilege escalation with subsequent access to a configured sensitive resource
    within a temporal window.
    """
    rule_id = "RULE-004"
    rule_name = "Sensitive Resource Access Following Escalation"
    severity = "critical"
    description = "Flags access to critical databases, vaults, or keys shortly following an escalation."

    def evaluate(self, events: List[Any], config: Any) -> List[Dict[str, Any]]:
        sensitive_roles = set(r.lower() for r in getattr(config, "SENSITIVE_ROLES", []))
        sensitive_resources = set(res.lower() for res in getattr(config, "SENSITIVE_RESOURCES", []))
        window_minutes = getattr(config, "PRIVILEGE_CHANGE_WINDOW_MINUTES", 30)
        window_delta = timedelta(minutes=window_minutes)

        # Group by user
        user_events: Dict[str, List[Any]] = {}
        for ev in events:
            user = ev.username
            if user not in user_events:
                user_events[user] = []
            user_events[user].append(ev)

        alerts = []

        for user, u_evs in user_events.items():
            u_evs.sort(key=lambda x: x.timestamp)

            # Find all privilege change events that granted a sensitive role
            priv_changes = [
                e for e in u_evs
                if e.event_type in ("role_change", "permission_grant") and
                (e.new_role or "").lower() in sensitive_roles
            ]

            for pc in priv_changes:
                # Look for subsequent resource_access to sensitive resources
                sens_accesses = []
                for ev in u_evs:
                    if ev.event_type == "resource_access" and ev.timestamp >= pc.timestamp:
                        if ev.timestamp - pc.timestamp <= window_delta:
                            res = (ev.resource or "").lower()
                            # Check if resource matches any sensitive resource substring or exact match
                            if any(sr in res for sr in sensitive_resources):
                                sens_accesses.append(ev)

                if sens_accesses:
                    event_ids = [pc.event_id] + [sa.event_id for sa in sens_accesses]
                    res_names = ", ".join(set(sa.resource for sa in sens_accesses))
                    reason = (
                        f"User '{user}' accessed highly sensitive resource(s) [{res_names}] "
                        f"shortly after receiving elevated role '{pc.new_role}' "
                        f"(within {(sens_accesses[0].timestamp - pc.timestamp).total_seconds() / 60:.1f} minutes). "
                        "Indicates rapid exploitation of newly acquired privileges."
                    )
                    alerts.append({
                        "rule_id": self.rule_id,
                        "rule_name": self.rule_name,
                        "affected_user": user,
                        "severity": "critical",
                        "reason": reason,
                        "suggested_investigation_steps": [
                            f"Check if user '{user}' has a documented operational need for accessing [{res_names}].",
                            "Inspect network egress and data download logs for evidence of data exfiltration.",
                            "Revoke active session tokens immediately to prevent further unauthorized access.",
                            "Quarantine target sensitive resources and rotate exposed cryptographic keys or passwords."
                        ],
                        "relevant_event_ids": event_ids,
                        "detected_at": datetime.now(timezone.utc)
                    })

        return alerts


class RuleAccessDeniedSpike(BaseDetectionRule):
    """
    Rule 5 (Supplemental): Detects a cluster of access_denied events for an identity,
    indicating permission probing or privilege boundary testing.
    """
    rule_id = "RULE-005"
    rule_name = "Access Denied Probing / Permission Boundary Testing"
    severity = "medium"
    description = "Detects rapid repeated access denied events indicating an identity attempting unauthorized access."

    def evaluate(self, events: List[Any], config: Any) -> List[Dict[str, Any]]:
        threshold = 3
        window_delta = timedelta(minutes=15)

        user_events: Dict[str, List[Any]] = {}
        for ev in events:
            user = ev.username
            if user not in user_events:
                user_events[user] = []
            user_events[user].append(ev)

        alerts = []
        for user, u_evs in user_events.items():
            denials = [e for e in u_evs if e.event_type == "access_denied" or e.outcome == "denied"]
            denials.sort(key=lambda x: x.timestamp)

            i = 0
            while i < len(denials):
                start_time = denials[i].timestamp
                cluster = []
                j = i
                while j < len(denials) and denials[j].timestamp - start_time <= window_delta:
                    cluster.append(denials[j])
                    j += 1

                if len(cluster) >= threshold:
                    event_ids = [d.event_id for d in cluster]
                    resources = list(set(d.resource for d in cluster if d.resource))
                    res_str = ", ".join(resources) if resources else "various endpoints"
                    alerts.append({
                        "rule_id": self.rule_id,
                        "rule_name": self.rule_name,
                        "affected_user": user,
                        "severity": "medium",
                        "reason": (
                            f"User '{user}' incurred {len(cluster)} access denials against [{res_str}] "
                            f"within {window_delta.total_seconds() / 60:.0f} minutes. Potential permission discovery attempt."
                        ),
                        "suggested_investigation_steps": [
                            f"Review denied resource requests for user '{user}' to check for lateral movement attempts.",
                            "Verify if the user's workstation has been compromised with scanning scripts.",
                            "Check if user role permissions were recently reduced causing expected denials."
                        ],
                        "relevant_event_ids": event_ids,
                        "detected_at": datetime.now(timezone.utc)
                    })
                    i = j - 1
                i += 1

        return alerts


class RuleSecurityLogCleared(BaseDetectionRule):
    """
    Rule 6: Detects clearing of the Windows Security audit log (Event 1102 / action security_audit_log_cleared).
    Represents critical anti-forensics or log tampering activity.
    """
    rule_id = "RULE-006"
    rule_name = "Security Audit Log Cleared / Tampering"
    severity = "critical"
    description = "Flags intentional clearing of the Windows Security audit log, indicating defensive evasion or anti-forensics."

    def evaluate(self, events: List[Any], config: Any) -> List[Dict[str, Any]]:
        alerts = []
        for ev in events:
            action = getattr(ev, "action", "") or ""
            resource = getattr(ev, "resource", "") or ""
            raw = getattr(ev, "raw_data", None)
            is_1102 = False
            if raw:
                try:
                    meta = json.loads(raw) if isinstance(raw, str) else raw
                    if meta.get("windows_event_id") == 1102:
                        is_1102 = True
                except Exception:
                    pass

            if is_1102 or "security_audit_log_cleared" in action or "audit_log_cleared" in action or ("Security Event Log" in resource and "cleared" in action.lower()):
                actor = getattr(ev, "actor", None) or getattr(ev, "username", "unknown")
                alerts.append({
                    "rule_id": self.rule_id,
                    "rule_name": self.rule_name,
                    "affected_user": actor,
                    "severity": self.severity,
                    "reason": f"Windows Security audit log was cleared by user/actor '{actor}'. Anti-forensic activity detected.",
                    "suggested_investigation_steps": [
                        f"Immediately isolate host '{getattr(ev, 'resource', 'target')}' from the corporate network.",
                        f"Audit active sessions and recent authentication for account '{actor}'.",
                        "Review secondary SIEM, Sysmon, and NetFlow telemetry for contemporaneous data staging or exfiltration.",
                        "Re-enable Security auditing baseline immediately."
                    ],
                    "relevant_event_ids": [ev.event_id],
                    "detected_at": datetime.now(timezone.utc)
                })
        return alerts


class RulePrivilegedGroupMembershipAdded(BaseDetectionRule):
    """
    Rule 7: Detects addition of user accounts into sensitive administrative groups (Events 4728, 4732).
    """
    rule_id = "RULE-007"
    rule_name = "Privileged Security Group Membership Addition"
    severity = "high"
    description = "Detects additions to privileged security groups such as Administrators or Domain Admins."

    def evaluate(self, events: List[Any], config: Any) -> List[Dict[str, Any]]:
        sensitive_roles = set(r.lower() for r in getattr(config, "SENSITIVE_ROLES", []))
        sensitive_roles.update(["administrators", "domain admins", "enterprise admins", "schema admins", "backup operators", "account operators"])
        authorized_managers = set(m.lower() for m in getattr(config, "AUTHORIZED_ROLE_MANAGERS", []))

        alerts = []
        for ev in events:
            action = getattr(ev, "action", "") or ""
            new_role = (getattr(ev, "new_role", "") or "").lower()
            resource = (getattr(ev, "resource", "") or "").lower()

            if "group_member_added" in action or any(sr in new_role for sr in sensitive_roles) or any(sr in resource for sr in sensitive_roles):
                target_user = getattr(ev, "username", "unknown")
                actor = getattr(ev, "actor", None) or getattr(ev, "username", "unknown")
                
                # Check if group is sensitive
                is_sensitive = any(sr in new_role for sr in sensitive_roles) or any(sr in resource for sr in sensitive_roles)
                if not is_sensitive:
                    continue

                is_unauthorized_actor = actor.lower() not in authorized_managers and actor != "SYSTEM"
                severity = "critical" if is_unauthorized_actor and actor.lower() == target_user.lower() else ("high" if is_unauthorized_actor else "medium")

                alerts.append({
                    "rule_id": self.rule_id,
                    "rule_name": self.rule_name,
                    "affected_user": target_user,
                    "severity": severity,
                    "reason": f"Account '{target_user}' was added to privileged group '{getattr(ev, 'new_role') or getattr(ev, 'resource')}' by actor '{actor}'.",
                    "suggested_investigation_steps": [
                        f"Verify change request authorization for promoting '{target_user}'.",
                        f"Inspect actor account '{actor}' for potential compromise or unauthorized helpdesk delegation.",
                        "Audit target user's active sessions and MFA enrollment status."
                    ],
                    "relevant_event_ids": [ev.event_id],
                    "detected_at": datetime.now(timezone.utc)
                })
        return alerts


class RuleSuspiciousAccountCreation(BaseDetectionRule):
    """
    Rule 8: Detects new local or domain account creation or enablement (Events 4720, 4722).
    """
    rule_id = "RULE-008"
    rule_name = "Suspicious Account Creation / Enablement"
    severity = "medium"
    description = "Detects newly created or enabled user accounts, flagging potential backdoor or persistence establishment."

    def evaluate(self, events: List[Any], config: Any) -> List[Dict[str, Any]]:
        authorized_managers = set(m.lower() for m in getattr(config, "AUTHORIZED_ROLE_MANAGERS", []))
        alerts = []
        for ev in events:
            action = getattr(ev, "action", "") or ""
            if "account_created" in action or "account_enabled" in action:
                target_user = getattr(ev, "username", "unknown")
                actor = getattr(ev, "actor", None) or "SYSTEM"
                is_unauth = actor.lower() not in authorized_managers and actor != "SYSTEM"
                severity = "high" if is_unauth else "medium"

                alerts.append({
                    "rule_id": self.rule_id,
                    "rule_name": self.rule_name,
                    "affected_user": target_user,
                    "severity": severity,
                    "reason": f"Account '{target_user}' was {action.replace('_', ' ')} by actor '{actor}'. Potential persistence or unauthorized identity provisioning.",
                    "suggested_investigation_steps": [
                        f"Verify HR/IAM ticketing authorization for creating account '{target_user}'.",
                        f"Check if account '{target_user}' has been granted elevated group memberships.",
                        f"Review source workstation and IP from which '{actor}' initiated the account change."
                    ],
                    "relevant_event_ids": [ev.event_id],
                    "detected_at": datetime.now(timezone.utc)
                })
        return alerts


class RuleMultiAccountAuthenticationSpraying(BaseDetectionRule):
    """
    Rule 9: Detects authentication failures against multiple distinct accounts from the same source IP / host.
    Indicates password spraying or brute force enumeration.
    """
    rule_id = "RULE-009"
    rule_name = "Multi-Account Password Spraying"
    severity = "high"
    description = "Flags multiple authentication failures originating from a single source across distinct usernames."

    def evaluate(self, events: List[Any], config: Any) -> List[Dict[str, Any]]:
        window_minutes = getattr(config, "FAILED_LOGIN_WINDOW_MINUTES", 15)
        window_delta = timedelta(minutes=window_minutes)

        # Group failed logins by source_ip
        ip_failures: Dict[str, List[Any]] = {}
        for ev in events:
            if getattr(ev, "event_type", "") == "login_failure" and getattr(ev, "source_ip", None):
                ip = ev.source_ip
                if ip not in ("127.0.0.1", "::1", "localhost"):
                    ip_failures.setdefault(ip, []).append(ev)

        alerts = []
        for ip, failures in ip_failures.items():
            failures.sort(key=lambda x: x.timestamp)
            i = 0
            while i < len(failures):
                start_time = failures[i].timestamp
                cluster = []
                distinct_users = set()
                j = i
                while j < len(failures) and failures[j].timestamp - start_time <= window_delta:
                    cluster.append(failures[j])
                    distinct_users.add(failures[j].username)
                    j += 1

                # If >= 3 distinct users targeted from same IP
                if len(distinct_users) >= 3:
                    event_ids = [f.event_id for f in cluster]
                    user_list_str = ", ".join(sorted(list(distinct_users))[:5])
                    alerts.append({
                        "rule_id": self.rule_id,
                        "rule_name": self.rule_name,
                        "affected_user": f"Multiple ({len(distinct_users)} accounts)",
                        "severity": self.severity,
                        "reason": f"Observed password spraying from source IP '{ip}' targeting {len(distinct_users)} distinct accounts ({user_list_str}) within {window_minutes} minutes.",
                        "suggested_investigation_steps": [
                            f"Block or throttle inbound traffic from source IP '{ip}' at perimeter firewall.",
                            f"Check if any targeted accounts ({user_list_str}) experienced a subsequent successful login.",
                            "Enforce MFA challenge on all targeted identities."
                        ],
                        "relevant_event_ids": event_ids,
                        "detected_at": datetime.now(timezone.utc)
                    })
                    i = j - 1
                i += 1
        return alerts


class RuleExplicitCredentialAbuse(BaseDetectionRule):
    """
    Rule 10: Detects logons using explicit credentials (Event 4648) where caller and target differ.
    """
    rule_id = "RULE-010"
    rule_name = "Explicit Credential Logon Abuse"
    severity = "medium"
    description = "Detects processes attempting logons using alternate explicit credentials (e.g. runas / secondary identity)."

    def evaluate(self, events: List[Any], config: Any) -> List[Dict[str, Any]]:
        sensitive_roles = set(r.lower() for r in getattr(config, "SENSITIVE_ROLES", []))
        alerts = []
        for ev in events:
            action = getattr(ev, "action", "") or ""
            if "explicit_credentials" in action:
                actor = getattr(ev, "actor", None)
                target = getattr(ev, "username", None)
                if actor and target and actor.lower() != target.lower():
                    is_admin_target = any(r in target.lower() for r in sensitive_roles) or "admin" in target.lower()
                    sev = "high" if is_admin_target else "medium"
                    alerts.append({
                        "rule_id": self.rule_id,
                        "rule_name": self.rule_name,
                        "affected_user": target,
                        "severity": sev,
                        "reason": f"Actor '{actor}' initiated an authentication attempt using explicit credentials for target account '{target}'. Potential lateral movement or privilege switching.",
                        "suggested_investigation_steps": [
                            f"Confirm if user '{actor}' has legitimate administrative responsibilities over '{target}'.",
                            "Verify endpoint process execution to determine if tools like RunAs, PsExec, or mimikatz were invoked.",
                            "Check target host session duration and commands executed."
                        ],
                        "relevant_event_ids": [ev.event_id],
                        "detected_at": datetime.now(timezone.utc)
                    })
        return alerts


class DetectionEngine:
    """Orchestrates all security detection rules against ingested events."""

    def __init__(self, config: Any = None):
        self.config = config or Config()
        self.rules: List[BaseDetectionRule] = [
            RuleRepeatedFailedLogins(),
            RuleUnexpectedPrivilegeEscalation(),
            RuleUnauthorizedPrivilegeGrant(),
            RuleSensitiveAccessFollowingPrivilegeChange(),
            RuleAccessDeniedSpike(),
            RuleSecurityLogCleared(),
            RulePrivilegedGroupMembershipAdded(),
            RuleSuspiciousAccountCreation(),
            RuleMultiAccountAuthenticationSpraying(),
            RuleExplicitCredentialAbuse()
        ]

    def run_detection(self, events: List[Any]) -> List[Dict[str, Any]]:
        """Run all detection rules against the given events and return collected alerts."""
        if not events:
            return []

        # Sort all events chronologically
        sorted_events = sorted(events, key=lambda x: x.timestamp)

        all_alerts: List[Dict[str, Any]] = []
        for rule in self.rules:
            try:
                rule_alerts = rule.evaluate(sorted_events, self.config)
                all_alerts.extend(rule_alerts)
            except Exception as e:
                # Rules must never crash the detection pipeline
                print(f"Error evaluating rule {rule.rule_id}: {str(e)}")

        return all_alerts

