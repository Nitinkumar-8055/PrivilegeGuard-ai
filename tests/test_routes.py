import json

def test_dashboard_routes(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "PrivilegeGuard" in res.get_data(as_text=True)

    stats_res = client.get("/api/stats")
    assert stats_res.status_code == 200
    stats = stats_res.get_json()
    assert "total_events" in stats
    assert "total_incidents" in stats


def test_events_routes(client):
    res = client.get("/events")
    assert res.status_code == 200
    assert "Event Explorer" in res.get_data(as_text=True)

    api_res = client.get("/api/events")
    assert api_res.status_code == 200
    data = api_res.get_json()
    assert "events" in data
    assert "total" in data


def test_demo_generation_and_incidents_lifecycle(client):
    # 1. Trigger demo generation
    demo_res = client.post("/api/ingestion/generate_demo")
    assert demo_res.status_code == 200
    demo_data = demo_res.get_json()
    assert demo_data["success"] is True
    assert demo_data["accepted_count"] > 0
    assert demo_data["incidents_created"] > 0

    # 2. Check incidents list
    inc_res = client.get("/api/incidents")
    assert inc_res.status_code == 200
    inc_data = inc_res.get_json()
    assert len(inc_data["incidents"]) > 0

    first_inc = inc_data["incidents"][0]
    inc_id = first_inc["id"]

    # 3. View detail page
    detail_res = client.get(f"/incidents/{inc_id}")
    assert detail_res.status_code == 200
    assert first_inc["incident_id"] in detail_res.get_data(as_text=True)

    # 4. Update status
    status_res = client.post(
        f"/api/incidents/{inc_id}/status",
        json={"status": "Investigating"}
    )
    assert status_res.status_code == 200
    assert status_res.get_json()["incident"]["status"] == "Investigating"

    # 5. Simulate containment action
    sim_res = client.post(
        f"/api/incidents/{inc_id}/simulate_containment",
        json={"action": "lock_account"}
    )
    assert sim_res.status_code == 200
    sim_data = sim_res.get_json()
    assert sim_data["success"] is True
    assert sim_data["new_status"] == "Contained"

    # 6. Clear database
    clear_res = client.post("/api/ingestion/clear")
    assert clear_res.status_code == 200
    assert clear_res.get_json()["success"] is True

    # 7. Confirm database is empty
    empty_stats = client.get("/api/stats").get_json()
    assert empty_stats["total_events"] == 0
    assert empty_stats["total_incidents"] == 0
