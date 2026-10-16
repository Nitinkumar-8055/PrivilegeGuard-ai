import csv
import io
import json
import re
import ipaddress
import time
import random
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any, Optional, Set
from sqlalchemy.exc import SQLAlchemyError, OperationalError
from models import db, SecurityEvent, AuditLog

VALID_EVENT_TYPES = {
    "login_success",
    "login_failure",
    "role_change",
    "permission_grant",
    "permission_revoke",
    "resource_access",
    "access_denied"
}

REQUIRED_FIELDS = ["event_id", "timestamp", "username", "event_type", "outcome"]


def _is_sqlite_locked_error(exc: Exception) -> bool:
    """Check if an exception is an SQLite database locked/busy OperationalError."""
    msg = str(exc).lower()
    return "database is locked" in msg or "database table is locked" in msg or "database is busy" in msg


def parse_iso_datetime(ts_str: Any) -> Optional[datetime]:
    """Parse various ISO and standard date/time string formats into timezone-aware or UTC datetime."""
    if not ts_str:
        return None
    if isinstance(ts_str, datetime):
        return ts_str
    
    ts_str = str(ts_str).strip()
    # Normalize Z to +00:00
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
        
    # Try standard fromisoformat
    try:
        dt = datetime.fromisoformat(ts_str)
        # If naive, treat as UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass

    # Try common formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f"
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return None


class IngestionService:
    """Handles parsing, validation, duplicate detection, and storage of security events."""

    @staticmethod
    def validate_record(
        record: Dict[str, Any],
        seen_in_batch: Set[str],
        existing_in_db: Optional[Set[str]] = None
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Validates an event record dictionary.
        Returns: (is_valid, rejection_reason, normalized_cleaned_dict)
        """
        if not isinstance(record, dict):
            return False, "Record must be a JSON object / key-value dictionary", None

        # Check required fields
        for field in REQUIRED_FIELDS:
            val = record.get(field)
            if val is None or str(val).strip() == "":
                return False, f"Missing or empty required field: '{field}'", None

        event_id = str(record["event_id"]).strip()
        if not event_id:
            return False, "Invalid event_id: cannot be blank", None

        # Check duplicate in current upload batch
        if event_id in seen_in_batch:
            return False, f"Duplicate event_id '{event_id}' found in current batch", None

        # Check duplicate in database
        if existing_in_db is not None:
            if event_id in existing_in_db:
                return False, f"Duplicate event_id '{event_id}' already exists in database", None
        else:
            existing = SecurityEvent.query.filter_by(event_id=event_id).first()
            if existing:
                return False, f"Duplicate event_id '{event_id}' already exists in database", None

        # Validate username
        username = str(record["username"]).strip()
        if not username:
            return False, "Missing or empty required field: 'username'", None

        # Validate event type
        event_type = str(record["event_type"]).strip().lower()
        if event_type not in VALID_EVENT_TYPES:
            return False, f"Invalid event_type '{event_type}'. Must be one of: {sorted(list(VALID_EVENT_TYPES))}", None

        # Validate timestamp
        parsed_dt = parse_iso_datetime(record["timestamp"])
        if not parsed_dt:
            return False, f"Invalid or unparseable timestamp: '{record.get('timestamp')}'", None

        # Validate IP address format (IPv4 or IPv6) if provided
        raw_ip = str(record.get("source_ip", "")).strip()
        source_ip = None
        if raw_ip:
            try:
                ipaddress.ip_address(raw_ip)
                source_ip = raw_ip
            except ValueError:
                return False, f"Invalid IP address format: '{raw_ip}'", None

        # Build normalized dictionary
        normalized = {
            "event_id": event_id,
            "timestamp": parsed_dt,
            "username": username,
            "event_type": event_type,
            "outcome": str(record["outcome"]).strip().lower(),
            "source_ip": source_ip,
            "actor": str(record.get("actor", "")).strip() or None,
            "old_role": str(record.get("old_role", "")).strip() or None,
            "new_role": str(record.get("new_role", "")).strip() or None,
            "resource": str(record.get("resource", "")).strip() or None,
            "action": str(record.get("action", "")).strip() or None,
            "session_id": str(record.get("session_id", "")).strip() or None,
            "raw_data": json.dumps(record, default=str)
        }

        return True, None, normalized

    @classmethod
    def ingest_json(cls, raw_content: str, max_records: int = 10000) -> Dict[str, Any]:
        """Ingest raw JSON string containing a single event or array of events."""
        try:
            data = json.loads(raw_content)
        except Exception as e:
            return {
                "success": False,
                "error_message": f"Malformed JSON: {str(e)}",
                "total_records": 0,
                "accepted_count": 0,
                "rejected_count": 0,
                "duplicate_count": 0,
                "accepted_events": [],
                "rejected_records": []
            }

        if isinstance(data, dict):
            records = [data]
        elif isinstance(data, list):
            records = data
        else:
            return {
                "success": False,
                "error_message": "JSON must be an array of event objects or a single event object",
                "total_records": 0,
                "accepted_count": 0,
                "rejected_count": 0,
                "duplicate_count": 0,
                "accepted_events": [],
                "rejected_records": []
            }

        if len(records) > max_records:
            return {
                "success": False,
                "error_message": f"Record count exceeds maximum allowed of {max_records} (received {len(records)})",
                "total_records": len(records),
                "accepted_count": 0,
                "rejected_count": len(records),
                "duplicate_count": 0,
                "accepted_events": [],
                "rejected_records": [{"index": i, "reason": "Exceeded batch size limit"} for i in range(len(records))]
            }

        return cls._process_records(records)

    @classmethod
    def ingest_csv(cls, raw_content: str, max_records: int = 10000) -> Dict[str, Any]:
        """Ingest raw CSV string with headers matching event fields."""
        try:
            reader = csv.DictReader(io.StringIO(raw_content.strip()))
            records = list(reader)
        except Exception as e:
            return {
                "success": False,
                "error_message": f"Malformed CSV: {str(e)}",
                "total_records": 0,
                "accepted_count": 0,
                "rejected_count": 0,
                "duplicate_count": 0,
                "accepted_events": [],
                "rejected_records": []
            }

        if len(records) > max_records:
            return {
                "success": False,
                "error_message": f"Record count exceeds maximum allowed of {max_records} (received {len(records)})",
                "total_records": len(records),
                "accepted_count": 0,
                "rejected_count": len(records),
                "duplicate_count": 0,
                "accepted_events": [],
                "rejected_records": [{"index": i, "reason": "Exceeded batch size limit"} for i in range(len(records))]
            }

        return cls._process_records(records)

    @classmethod
    def _process_records(cls, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate and commit records within a safe database transaction with bounded retries."""
        seen_in_batch: Set[str] = set()
        accepted_models: List[SecurityEvent] = []
        rejected_records: List[Dict[str, Any]] = []
        duplicate_count = 0

        # Pre-fetch existing event_ids in database for batch performance
        batch_eids = [
            str(r.get("event_id")).strip()
            for r in records
            if isinstance(r, dict) and r.get("event_id")
        ]
        existing_in_db: Set[str] = set()
        if batch_eids:
            try:
                existing_rows = (
                    db.session.query(SecurityEvent.event_id)
                    .filter(SecurityEvent.event_id.in_(batch_eids))
                    .all()
                )
                existing_in_db = {row[0] for row in existing_rows if row[0]}
            except Exception:
                existing_in_db = set()

        for idx, rec in enumerate(records):
            is_valid, reason, normalized = cls.validate_record(rec, seen_in_batch, existing_in_db)
            if is_valid and normalized:
                seen_in_batch.add(normalized["event_id"])
                event = SecurityEvent(
                    event_id=normalized["event_id"],
                    timestamp=normalized["timestamp"],
                    username=normalized["username"],
                    event_type=normalized["event_type"],
                    source_ip=normalized["source_ip"],
                    outcome=normalized["outcome"],
                    actor=normalized["actor"],
                    old_role=normalized["old_role"],
                    new_role=normalized["new_role"],
                    resource=normalized["resource"],
                    action=normalized["action"],
                    session_id=normalized["session_id"],
                    raw_data=normalized["raw_data"]
                )
                accepted_models.append(event)
            else:
                if reason and "duplicate" in reason.lower():
                    duplicate_count += 1
                rejected_records.append({
                    "index": idx + 1,
                    "event_id": rec.get("event_id", "N/A") if isinstance(rec, dict) else "N/A",
                    "reason": reason,
                    "record": rec
                })

        # Save accepted events in database with bounded retries for transient locks
        if accepted_models:
            max_retries = 5
            base_backoff = 0.1
            commit_success = False
            last_err = None

            for attempt in range(max_retries):
                try:
                    db.session.add_all(accepted_models)
                    # Audit log
                    audit = AuditLog(
                        action_type="INGESTION",
                        details=f"Ingested {len(accepted_models)} valid events. Rejected {len(rejected_records)} invalid records (including {duplicate_count} duplicates)."
                    )
                    db.session.add(audit)
                    db.session.commit()
                    commit_success = True
                    break
                except (OperationalError, SQLAlchemyError) as e:
                    db.session.rollback()
                    last_err = e
                    if _is_sqlite_locked_error(e) and attempt < max_retries - 1:
                        sleep_time = (base_backoff * (2 ** attempt)) + random.uniform(0.02, 0.08)
                        time.sleep(sleep_time)
                        continue
                    break

            if not commit_success:
                return {
                    "success": False,
                    "error_message": f"Database commit failed: {str(last_err)}",
                    "total_records": len(records),
                    "accepted_count": 0,
                    "rejected_count": len(records),
                    "duplicate_count": duplicate_count,
                    "accepted_events": [],
                    "rejected_records": [{"index": i + 1, "reason": f"Transaction rolled back: {str(last_err)}"} for i in range(len(records))]
                }

        return {
            "success": True,
            "error_message": None,
            "total_records": len(records),
            "accepted_count": len(accepted_models),
            "rejected_count": len(rejected_records),
            "duplicate_count": duplicate_count,
            "accepted_events": accepted_models,
            "rejected_records": rejected_records
        }
