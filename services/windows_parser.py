import xml.etree.ElementTree as ET
import json
import re
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, Optional

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

def _clean_str(val: Any) -> Optional[str]:
    """Clean and strip strings, treating '-' or blank as None."""
    if val is None:
        return None
    s = str(val).strip()
    return s if s and s != "-" else None

def _clean_ip(raw_ip: Any) -> Optional[str]:
    """Validate and return valid IPv4 or IPv6 address, or None."""
    s = _clean_str(raw_ip)
    if not s:
        return None
    # Remove port or brackets if any (e.g., [::1]:80)
    s = s.strip("[]")
    if "%" in s:
        s = s.split("%")[0]  # strip scope id
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        return None

def _clean_username(raw_user: Any, domain: Any = None) -> str:
    """Normalize username, optionally appending domain or stripping machine accounts."""
    u = _clean_str(raw_user) or "SYSTEM"
    d = _clean_str(domain)
    # If username contains domain already (DOMAIN\user), keep it clean
    if "\\" in u:
        return u
    if d and d not in ("WORKGROUP", "NT AUTHORITY", ".", "LOCAL") and not u.endswith("$"):
        return f"{d}\\{u}"
    return u


class WindowsEventParser:
    """
    Parses and normalizes Windows Event Log XML representations
    into standard PrivilegeGuard AI security event structures.
    """

    @classmethod
    def parse_xml_to_dict(cls, xml_content: str) -> Optional[Dict[str, Any]]:
        """Extract raw attributes and EventData dictionary from rendered Windows XML."""
        if not xml_content or not xml_content.strip():
            return None

        try:
            root = ET.fromstring(xml_content.strip())
        except Exception:
            # Handle potential XML namespace stripping
            try:
                clean_xml = re.sub(r'xmlns="[^"]+"', '', xml_content)
                clean_xml = re.sub(r"xmlns='[^']+'", '', clean_xml)
                root = ET.fromstring(clean_xml.strip())
            except Exception:
                return None

        # Helper for namespace-aware search
        def find_el(parent, tag):
            el = parent.find(f"e:{tag}", NS)
            if el is None:
                el = parent.find(tag)
            return el

        system_el = find_el(root, "System")
        if system_el is None:
            return None

        event_id_el = find_el(system_el, "EventID")
        record_id_el = find_el(system_el, "EventRecordID")
        time_el = find_el(system_el, "TimeCreated")
        channel_el = find_el(system_el, "Channel")
        computer_el = find_el(system_el, "Computer")

        try:
            event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0
        except ValueError:
            event_id = 0

        try:
            record_id = int(record_id_el.text) if record_id_el is not None and record_id_el.text else 0
        except ValueError:
            record_id = 0

        timestamp_str = None
        if time_el is not None:
            timestamp_str = time_el.attrib.get("SystemTime")

        channel = channel_el.text.strip() if channel_el is not None and channel_el.text else "Security"
        computer = computer_el.text.strip() if computer_el is not None and computer_el.text else "localhost"

        # Parse EventData key-value pairs
        event_data: Dict[str, str] = {}
        data_parent = find_el(root, "EventData")
        if data_parent is None:
            data_parent = find_el(root, "UserData")
        if data_parent is not None:

            # Look for <Data Name="...">val</Data>
            for data_node in data_parent:
                name = data_node.attrib.get("Name")
                text = data_node.text or ""
                if name:
                    event_data[name] = text.strip()
                elif text:
                    # Positional fallback
                    event_data[f"Param_{len(event_data)+1}"] = text.strip()

        return {
            "event_id": event_id,
            "record_id": record_id,
            "timestamp": timestamp_str,
            "channel": channel,
            "computer": computer,
            "data": event_data,
            "raw_xml": xml_content
        }

    @classmethod
    def normalize_event(cls, parsed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Map Windows Event (4624, 4625, 4634, 4648, 4672, 4720, 4722, 4728, 4732, 4738, 4740, 1102)
        to PrivilegeGuard AI standard event schema.
        """
        if not parsed:
            return None

        win_id = parsed.get("event_id", 0)
        record_id = parsed.get("record_id", 0)
        channel = parsed.get("channel", "Security")
        computer = parsed.get("computer", "localhost")
        data = parsed.get("data", {})
        raw_ts = parsed.get("timestamp")

        # Parse timestamp to UTC ISO string
        if raw_ts:
            try:
                # E.g. '2026-10-26T18:00:00.1234567Z'
                cleaned_ts = raw_ts.rstrip("Z")
                if "." in cleaned_ts:
                    parts = cleaned_ts.split(".")
                    # Truncate fractional seconds to 6 digits for Python strptime
                    cleaned_ts = f"{parts[0]}.{parts[1][:6]}"
                dt = datetime.fromisoformat(cleaned_ts)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                iso_ts = dt.isoformat()
            except Exception:
                iso_ts = datetime.now(timezone.utc).isoformat()
        else:
            iso_ts = datetime.now(timezone.utc).isoformat()

        # Deterministic unique event ID based on channel and record ID
        unique_event_id = f"WIN-{channel[:3].upper()}-{record_id}" if record_id > 0 else f"WIN-{channel[:3].upper()}-{win_id}-{int(datetime.now().timestamp()*1000)}"

        # Default field extraction
        target_user = _clean_str(data.get("TargetUserName"))
        target_domain = _clean_str(data.get("TargetDomainName"))
        subject_user = _clean_str(data.get("SubjectUserName"))
        subject_domain = _clean_str(data.get("SubjectDomainName"))
        source_ip = _clean_ip(data.get("IpAddress"))
        logon_type = _clean_str(data.get("LogonType"))
        logon_id = _clean_str(data.get("TargetLogonId") or data.get("SubjectLogonId"))

        raw_meta = {
            "windows_event_id": win_id,
            "record_id": record_id,
            "channel": channel,
            "computer": computer,
            "logon_type": logon_type,
            "target_user": target_user,
            "subject_user": subject_user,
            "target_sid": _clean_str(data.get("TargetUserSid")),
            "subject_sid": _clean_str(data.get("SubjectUserSid")),
            "workstation": _clean_str(data.get("WorkstationName")),
            "status_code": _clean_str(data.get("Status") or data.get("SubStatus")),
            "privileges": _clean_str(data.get("PrivilegeList")),
            "member_name": _clean_str(data.get("MemberName")),
            "group_name": _clean_str(data.get("TargetUserName")) if win_id in (4728, 4732) else None
        }

        # -------------------------------------------------------------
        # Event Specific Mappings
        # -------------------------------------------------------------
        if win_id == 4624:
            # Successful Logon
            username = _clean_username(target_user or subject_user or "unknown", target_domain)
            actor = _clean_username(subject_user) if subject_user and subject_user != target_user else None
            return {
                "event_id": unique_event_id,
                "timestamp": iso_ts,
                "username": username,
                "event_type": "login_success",
                "outcome": "success",
                "source_ip": source_ip,
                "actor": actor,
                "resource": computer,
                "action": f"logon_type_{logon_type}" if logon_type else "logon",
                "session_id": logon_id,
                "raw_data": raw_meta
            }

        elif win_id == 4625:
            # Failed Logon
            username = _clean_username(target_user or "unknown", target_domain)
            sub_status = _clean_str(data.get("SubStatus") or data.get("Status"))
            return {
                "event_id": unique_event_id,
                "timestamp": iso_ts,
                "username": username,
                "event_type": "login_failure",
                "outcome": "failure",
                "source_ip": source_ip,
                "actor": _clean_username(subject_user) if subject_user else None,
                "resource": computer,
                "action": f"failed_logon_substatus_{sub_status}" if sub_status else "failed_logon",
                "session_id": logon_id,
                "raw_data": raw_meta
            }

        elif win_id == 4634:
            # Logoff
            username = _clean_username(target_user or "unknown", target_domain)
            return {
                "event_id": unique_event_id,
                "timestamp": iso_ts,
                "username": username,
                "event_type": "resource_access",
                "outcome": "success",
                "source_ip": source_ip,
                "resource": computer,
                "action": "logoff",
                "session_id": logon_id,
                "raw_data": raw_meta
            }

        elif win_id == 4648:
            # Explicit Credentials Logon
            actor = _clean_username(subject_user or "unknown", subject_domain)
            target = _clean_username(target_user or "unknown", target_domain)
            target_server = _clean_str(data.get("TargetServerName")) or computer
            return {
                "event_id": unique_event_id,
                "timestamp": iso_ts,
                "username": target,
                "event_type": "login_success",
                "outcome": "success",
                "source_ip": source_ip,
                "actor": actor,
                "resource": target_server,
                "action": "explicit_credentials_logon",
                "session_id": logon_id,
                "raw_data": raw_meta
            }

        elif win_id == 4672:
            # Special Privileges Assigned to New Logon
            username = _clean_username(subject_user or target_user or "unknown", subject_domain)
            privs = _clean_str(data.get("PrivilegeList")) or "AdminPrivileges"
            return {
                "event_id": unique_event_id,
                "timestamp": iso_ts,
                "username": username,
                "event_type": "permission_grant",
                "outcome": "success",
                "source_ip": source_ip,
                "actor": username,
                "new_role": "special_privileges",
                "resource": computer,
                "action": f"assigned_privileges:{privs[:80]}",
                "session_id": logon_id,
                "raw_data": raw_meta
            }

        elif win_id == 4720:
            # A user account was created
            actor = _clean_username(subject_user or "SYSTEM", subject_domain)
            target = _clean_username(target_user or "unknown", target_domain)
            return {
                "event_id": unique_event_id,
                "timestamp": iso_ts,
                "username": target,
                "event_type": "role_change",
                "outcome": "success",
                "actor": actor,
                "new_role": "user",
                "resource": computer,
                "action": "user_account_created",
                "session_id": logon_id,
                "raw_data": raw_meta
            }

        elif win_id == 4722:
            # A user account was enabled
            actor = _clean_username(subject_user or "SYSTEM", subject_domain)
            target = _clean_username(target_user or "unknown", target_domain)
            return {
                "event_id": unique_event_id,
                "timestamp": iso_ts,
                "username": target,
                "event_type": "role_change",
                "outcome": "success",
                "actor": actor,
                "resource": computer,
                "action": "user_account_enabled",
                "session_id": logon_id,
                "raw_data": raw_meta
            }

        elif win_id in (4728, 4732):
            # Member added to global (4728) or local (4732) security group
            actor = _clean_username(subject_user or "SYSTEM", subject_domain)
            # MemberName is the account added, TargetUserName is the group name
            member = _clean_str(data.get("MemberName")) or _clean_str(data.get("MemberSid")) or "unknown_member"
            # Extract CN=username if member is an LDAP DN string
            if "CN=" in member:
                cn_match = re.search(r"CN=([^,]+)", member, re.IGNORECASE)
                if cn_match:
                    member = cn_match.group(1)
            group = _clean_str(data.get("TargetUserName")) or "PrivilegedGroup"
            return {
                "event_id": unique_event_id,
                "timestamp": iso_ts,
                "username": member,
                "event_type": "role_change",
                "outcome": "success",
                "actor": actor,
                "old_role": "user",
                "new_role": group,
                "resource": group,
                "action": "security_group_member_added",
                "session_id": logon_id,
                "raw_data": raw_meta
            }

        elif win_id == 4738:
            # A user account was changed
            actor = _clean_username(subject_user or "SYSTEM", subject_domain)
            target = _clean_username(target_user or "unknown", target_domain)
            return {
                "event_id": unique_event_id,
                "timestamp": iso_ts,
                "username": target,
                "event_type": "role_change",
                "outcome": "success",
                "actor": actor,
                "resource": computer,
                "action": "user_account_modified",
                "session_id": logon_id,
                "raw_data": raw_meta
            }

        elif win_id == 4740:
            # A user account was locked out
            target = _clean_username(target_user or "unknown", target_domain)
            return {
                "event_id": unique_event_id,
                "timestamp": iso_ts,
                "username": target,
                "event_type": "access_denied",
                "outcome": "failure",
                "actor": _clean_username(subject_user) if subject_user else None,
                "resource": computer,
                "action": "account_locked_out",
                "session_id": logon_id,
                "raw_data": raw_meta
            }

        elif win_id == 1102:
            # The audit log was cleared!
            actor = _clean_username(subject_user or "SYSTEM", subject_domain)
            return {
                "event_id": unique_event_id,
                "timestamp": iso_ts,
                "username": actor,
                "event_type": "access_denied",
                "outcome": "success",
                "actor": actor,
                "resource": "Windows Security Event Log",
                "action": "security_audit_log_cleared",
                "session_id": logon_id,
                "raw_data": raw_meta
            }

        else:
            # Generic Windows Security event fallback
            username = _clean_username(target_user or subject_user or "SYSTEM", target_domain)
            return {
                "event_id": unique_event_id,
                "timestamp": iso_ts,
                "username": username,
                "event_type": "resource_access",
                "outcome": "success",
                "source_ip": source_ip,
                "actor": _clean_username(subject_user) if subject_user else None,
                "resource": computer,
                "action": f"windows_event_{win_id}",
                "session_id": logon_id,
                "raw_data": raw_meta
            }
