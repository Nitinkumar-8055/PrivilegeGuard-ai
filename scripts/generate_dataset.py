import json
import csv
import os
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

def build_synthetic_events(base_time: datetime = None, include_malformed: bool = True) -> List[Dict[str, Any]]:
    """
    Generates a realistic, reproducible suite of identity and access events.
    Includes normal activity, suspicious attacks, authorized administrative actions,
    and deliberate malformed records for validation testing.
    """
    if base_time is None:
        base_time = datetime.now(timezone.utc) - timedelta(hours=2)

    events: List[Dict[str, Any]] = []

    # ---------------------------------------------------------
    # Scenario 1: Normal Routine User Activity (Benign)
    # ---------------------------------------------------------
    t1 = base_time + timedelta(minutes=5)
    events.extend([
        {
            "event_id": "EVT-NORM-1001",
            "timestamp": (t1).isoformat(),
            "username": "emily.watson",
            "event_type": "login_success",
            "source_ip": "10.0.4.15",
            "outcome": "success",
            "actor": "emily.watson",
            "old_role": "software_engineer",
            "new_role": "software_engineer",
            "resource": "portal://internal-tools",
            "action": "user_login",
            "session_id": "sess-emily-01"
        },
        {
            "event_id": "EVT-NORM-1002",
            "timestamp": (t1 + timedelta(minutes=3)).isoformat(),
            "username": "emily.watson",
            "event_type": "resource_access",
            "source_ip": "10.0.4.15",
            "outcome": "success",
            "actor": "emily.watson",
            "old_role": "software_engineer",
            "new_role": "software_engineer",
            "resource": "git://repos/privilegeguard-core",
            "action": "read_repository",
            "session_id": "sess-emily-01"
        },
        {
            "event_id": "EVT-NORM-1003",
            "timestamp": (t1 + timedelta(minutes=7)).isoformat(),
            "username": "emily.watson",
            "event_type": "resource_access",
            "source_ip": "10.0.4.15",
            "outcome": "success",
            "actor": "emily.watson",
            "old_role": "software_engineer",
            "new_role": "software_engineer",
            "resource": "wiki://engineering-guidelines",
            "action": "read_document",
            "session_id": "sess-emily-01"
        }
    ])

    # ---------------------------------------------------------
    # Scenario 2: Repeated Failed Logins Followed by Success (Brute-Force)
    # ---------------------------------------------------------
    t2 = base_time + timedelta(minutes=20)
    for i in range(4):
        events.append({
            "event_id": f"EVT-BRUTE-200{i+1}",
            "timestamp": (t2 + timedelta(minutes=i*2)).isoformat(),
            "username": "alex.hunter",
            "event_type": "login_failure",
            "source_ip": "198.51.100.89",
            "outcome": "failure",
            "actor": "alex.hunter",
            "old_role": "data_analyst",
            "new_role": "data_analyst",
            "resource": "portal://sso-auth",
            "action": "password_verification",
            "session_id": f"sess-failed-{i+1}"
        })
    # Subsequent successful compromise login from same external IP
    events.append({
        "event_id": "EVT-BRUTE-2005",
        "timestamp": (t2 + timedelta(minutes=10)).isoformat(),
        "username": "alex.hunter",
        "event_type": "login_success",
        "source_ip": "198.51.100.89",
        "outcome": "success",
        "actor": "alex.hunter",
        "old_role": "data_analyst",
        "new_role": "data_analyst",
        "resource": "portal://sso-auth",
        "action": "authenticated_session_created",
        "session_id": "sess-compromised-hunter"
    })

    # ---------------------------------------------------------
    # Scenario 3: Unexpected Privilege Escalation (User -> Admin)
    # ---------------------------------------------------------
    t3 = base_time + timedelta(minutes=35)
    events.append({
        "event_id": "EVT-ESCAL-3001",
        "timestamp": t3.isoformat(),
        "username": "clara.oswald",
        "event_type": "role_change",
        "source_ip": "10.0.12.80",
        "outcome": "success",
        "actor": "clara.oswald",  # Self-elevation or suspicious origin
        "old_role": "marketing_coordinator",
        "new_role": "administrator",
        "resource": "iam://roles/global_admin",
        "action": "role_assigned",
        "session_id": "sess-clara-elevate"
    })

    # ---------------------------------------------------------
    # Scenario 4: Unauthorized Privilege Grant by Non-Manager Actor
    # ---------------------------------------------------------
    t4 = base_time + timedelta(minutes=45)
    events.append({
        "event_id": "EVT-UNAUTH-4001",
        "timestamp": t4.isoformat(),
        "username": "dev.jordan",
        "event_type": "permission_grant",
        "source_ip": "192.168.10.45",
        "outcome": "success",
        "actor": "temp_contractor_vikram",  # Unauthorized actor!
        "old_role": "developer",
        "new_role": "secops_admin",
        "resource": "iam://permissions/all_access",
        "action": "grant_policy",
        "session_id": "sess-vikram-grant"
    })

    # ---------------------------------------------------------
    # Scenario 5: Escalation Followed by Sensitive Resource Access
    # ---------------------------------------------------------
    t5 = base_time + timedelta(minutes=55)
    events.extend([
        {
            "event_id": "EVT-SENS-5001",
            "timestamp": t5.isoformat(),
            "username": "marcus.vance",
            "event_type": "role_change",
            "source_ip": "172.16.8.99",
            "outcome": "success",
            "actor": "compromised_service_token",
            "old_role": "operations_user",
            "new_role": "root",
            "resource": "iam://roles/root",
            "action": "assume_role",
            "session_id": "sess-vance-root"
        },
        {
            "event_id": "EVT-SENS-5002",
            "timestamp": (t5 + timedelta(minutes=3)).isoformat(),
            "username": "marcus.vance",
            "event_type": "resource_access",
            "source_ip": "172.16.8.99",
            "outcome": "success",
            "actor": "marcus.vance",
            "old_role": "root",
            "new_role": "root",
            "resource": "/api/v1/vault/keys",
            "action": "read_secret_keys",
            "session_id": "sess-vance-root"
        },
        {
            "event_id": "EVT-SENS-5003",
            "timestamp": (t5 + timedelta(minutes=6)).isoformat(),
            "username": "marcus.vance",
            "event_type": "resource_access",
            "source_ip": "172.16.8.99",
            "outcome": "success",
            "actor": "marcus.vance",
            "old_role": "root",
            "new_role": "root",
            "resource": "database://customer_pii",
            "action": "bulk_export_query",
            "session_id": "sess-vance-root"
        }
    ])

    # ---------------------------------------------------------
    # Scenario 6: Legitimate Administrator Activity (Authorized & Benign)
    # ---------------------------------------------------------
    t6 = base_time + timedelta(minutes=70)
    events.extend([
        {
            "event_id": "EVT-ADMIN-6001",
            "timestamp": t6.isoformat(),
            "username": "backup_service_account",
            "event_type": "role_change",
            "source_ip": "10.0.0.5",
            "outcome": "success",
            "actor": "secops_admin",  # Authorized actor
            "old_role": "service_account",
            "new_role": "backup_operator",
            "resource": "iam://roles/backup_operator",
            "action": "scheduled_role_rotation",
            "session_id": "sess-secops-maint"
        },
        {
            "event_id": "EVT-ADMIN-6002",
            "timestamp": (t6 + timedelta(minutes=4)).isoformat(),
            "username": "secops_admin",
            "event_type": "resource_access",
            "source_ip": "10.0.0.12",
            "outcome": "success",
            "actor": "secops_admin",
            "old_role": "secops_admin",
            "new_role": "secops_admin",
            "resource": "portal://admin/health_check",
            "action": "system_diagnostics",
            "session_id": "sess-secops-diag"
        }
    ])

    # ---------------------------------------------------------
    # Scenario 7: Malformed / Duplicate / Invalid Data (Optional inclusion)
    # ---------------------------------------------------------
    if include_malformed:
        # A duplicate of EVT-NORM-1001
        events.append({
            "event_id": "EVT-NORM-1001",
            "timestamp": (t1).isoformat(),
            "username": "emily.watson",
            "event_type": "login_success",
            "source_ip": "10.0.4.15",
            "outcome": "success",
            "actor": "emily.watson",
            "old_role": "software_engineer",
            "new_role": "software_engineer",
            "resource": "portal://internal-tools",
            "action": "user_login",
            "session_id": "sess-duplicate-01"
        })
        # Missing required field 'username'
        events.append({
            "event_id": "EVT-MALFORMED-7001",
            "timestamp": (base_time + timedelta(minutes=15)).isoformat(),
            "username": "",
            "event_type": "login_failure",
            "source_ip": "192.168.1.50",
            "outcome": "failure",
            "actor": "unknown",
            "resource": "portal://login"
        })
        # Invalid event type
        events.append({
            "event_id": "EVT-MALFORMED-7002",
            "timestamp": (base_time + timedelta(minutes=16)).isoformat(),
            "username": "random.user",
            "event_type": "password_reset_unknown",
            "source_ip": "192.168.1.51",
            "outcome": "success",
            "actor": "random.user",
            "resource": "portal://pwd"
        })
        # Invalid timestamp
        events.append({
            "event_id": "EVT-MALFORMED-7003",
            "timestamp": "NOT_A_VALID_TIMESTAMP",
            "username": "tester.bob",
            "event_type": "login_failure",
            "source_ip": "192.168.1.52",
            "outcome": "failure",
            "actor": "tester.bob"
        })

    return events


def save_dataset_files(output_dir: str = "data"):
    """Generates both JSON and CSV files in the target data directory."""
    os.makedirs(output_dir, exist_ok=True)
    events = build_synthetic_events(include_malformed=True)

    json_path = os.path.join(output_dir, "sample_events.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    csv_path = os.path.join(output_dir, "sample_events.csv")
    fieldnames = [
        "event_id", "timestamp", "username", "event_type", "source_ip",
        "outcome", "actor", "old_role", "new_role", "resource", "action", "session_id"
    ]
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for ev in events:
            writer.writerow(ev)

    print(f"Generated {len(events)} synthetic events.")
    print(f"JSON: {json_path}")
    print(f"CSV:  {csv_path}")

if __name__ == "__main__":
    save_dataset_files()
