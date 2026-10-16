import json
import io
from services.ingestion import IngestionService
from models import SecurityEvent

def test_ingest_valid_json(app):
    with app.app_context():
        valid_json = json.dumps([
            {
                "event_id": "TEST-001",
                "timestamp": "2026-10-15T10:00:00Z",
                "username": "alice",
                "event_type": "login_success",
                "outcome": "success",
                "source_ip": "10.0.0.1"
            },
            {
                "event_id": "TEST-002",
                "timestamp": "2026-10-15T10:05:00Z",
                "username": "bob",
                "event_type": "resource_access",
                "outcome": "success",
                "resource": "/docs/plan"
            }
        ])

        result = IngestionService.ingest_json(valid_json)
        assert result["success"] is True
        assert result["accepted_count"] == 2
        assert result["rejected_count"] == 0

        # Verify database record
        ev = SecurityEvent.query.filter_by(event_id="TEST-001").first()
        assert ev is not None
        assert ev.username == "alice"


def test_ingest_valid_csv(app):
    with app.app_context():
        valid_csv = (
            "event_id,timestamp,username,event_type,outcome,source_ip\n"
            "CSV-001,2026-10-15T11:00:00Z,charlie,login_failure,failure,192.168.1.50\n"
            "CSV-002,2026-10-15T11:02:00Z,charlie,login_success,success,192.168.1.50\n"
        )
        result = IngestionService.ingest_csv(valid_csv)
        assert result["success"] is True
        assert result["accepted_count"] == 2
        assert result["rejected_count"] == 0


def test_missing_required_fields(app):
    with app.app_context():
        # Missing username
        bad_json = json.dumps([
            {
                "event_id": "TEST-BAD-01",
                "timestamp": "2026-10-15T12:00:00Z",
                "username": "",
                "event_type": "login_success",
                "outcome": "success"
            }
        ])
        result = IngestionService.ingest_json(bad_json)
        assert result["accepted_count"] == 0
        assert result["rejected_count"] == 1
        assert "username" in result["rejected_records"][0]["reason"]


def test_invalid_event_type(app):
    with app.app_context():
        bad_json = json.dumps([
            {
                "event_id": "TEST-BAD-02",
                "timestamp": "2026-10-15T12:00:00Z",
                "username": "dave",
                "event_type": "unknown_nonexistent_action",
                "outcome": "success"
            }
        ])
        result = IngestionService.ingest_json(bad_json)
        assert result["accepted_count"] == 0
        assert result["rejected_count"] == 1
        assert "Invalid event_type" in result["rejected_records"][0]["reason"]


def test_invalid_timestamp(app):
    with app.app_context():
        bad_json = json.dumps([
            {
                "event_id": "TEST-BAD-03",
                "timestamp": "not-a-timestamp-at-all",
                "username": "eve",
                "event_type": "login_success",
                "outcome": "success"
            }
        ])
        result = IngestionService.ingest_json(bad_json)
        assert result["accepted_count"] == 0
        assert result["rejected_count"] == 1
        assert "timestamp" in result["rejected_records"][0]["reason"]


def test_duplicate_event_handling(app):
    with app.app_context():
        # 1. Ingest initial event
        first_json = json.dumps([
            {
                "event_id": "DUP-001",
                "timestamp": "2026-10-15T13:00:00Z",
                "username": "frank",
                "event_type": "login_success",
                "outcome": "success"
            }
        ])
        res1 = IngestionService.ingest_json(first_json)
        assert res1["accepted_count"] == 1

        # 2. Try ingesting same event_id again (database duplicate)
        res2 = IngestionService.ingest_json(first_json)
        assert res2["accepted_count"] == 0
        assert res2["rejected_count"] == 1
        assert "already exists in database" in res2["rejected_records"][0]["reason"]

        # 3. Test duplicate within the same batch
        batch_with_dup = json.dumps([
            {
                "event_id": "BATCH-DUP-01",
                "timestamp": "2026-10-15T13:10:00Z",
                "username": "grace",
                "event_type": "login_success",
                "outcome": "success"
            },
            {
                "event_id": "BATCH-DUP-01",
                "timestamp": "2026-10-15T13:11:00Z",
                "username": "grace",
                "event_type": "resource_access",
                "outcome": "success"
            }
        ])
        res3 = IngestionService.ingest_json(batch_with_dup)
        assert res3["accepted_count"] == 1
        assert res3["rejected_count"] == 1
        assert "found in current batch" in res3["rejected_records"][0]["reason"]


def test_upload_api_endpoint(client):
    csv_data = (
        "event_id,timestamp,username,event_type,outcome\n"
        "API-001,2026-10-15T14:00:00Z,helen,login_success,success\n"
    )
    response = client.post(
        "/api/ingestion/upload",
        data={"file": (io.BytesIO(csv_data.encode("utf-8")), "events.csv")},
        content_type="multipart/form-data"
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["accepted_count"] == 1
