from datetime import datetime, timezone
from tests.test_parking_routers import setup_user_and_token

def setup_admin(client, db_session):
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "19900000000", "password": "adminviz"})
    u = db_session.query(User).filter(User.phone_number == "19900000000").first()
    u.role = UserRole.ADMIN
    db_session.commit()
    tok = client.post("/api/v1/login", data={"username": "19900000000", "password": "adminviz"}).json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}

def setup_user_and_vehicle(client):
    headers = setup_user_and_token(client)
    v = client.post("/api/v1/vehicles", json={"license_plate": "VIZ001", "is_default": True}, headers=headers).json()
    return headers, v

def test_layout_and_spaces_crud(client, db_session):
    admin = setup_admin(client, db_session)
    lot = client.post("/api/v1/parking-lots", json={"name": "LotVIZ", "address": "AddrVIZ", "total_capacity": 0, "available_spots": 0}, headers=admin).json()
    grid = [
        ["entrance","road","parking"],
        ["wall","road","parking"],
        ["road","road","exit"],
    ]
    resp = client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={
        "rows": 3, "cols": 3, "grid": grid,
        "entrance_position": {"row": 0, "col": 0},
        "exit_position": {"row": 2, "col": 2},
    }, headers=admin)
    assert resp.status_code == 200
    layout = resp.json()
    assert layout["rows"] == 3 and layout["cols"] == 3
    # spaces count should be 2
    spaces = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()
    assert len(spaces) == 2
    # filter by status/type
    s_avail = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces", params={"status_value": "available"}).json()
    assert len(s_avail) == 2
    # invalid status
    bad_status = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces", params={"status_value": "bad"})
    assert bad_status.status_code == 400
    # invalid type
    bad_type = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces", params={"space_type": "bad"})
    assert bad_type.status_code == 400
    # get single space and 404
    sid = spaces[0]["id"]
    one = client.get(f"/api/v1/parking/spaces/{sid}")
    assert one.status_code == 200
    s404 = client.get(f"/api/v1/parking/spaces/999999")
    assert s404.status_code == 404
    # update space
    up = client.put(f"/api/v1/parking/spaces/{sid}", json={"space_type": "disabled", "space_number": "A-01"}, headers=admin)
    assert up.status_code == 200
    up404 = client.put(f"/api/v1/parking/spaces/999999", json={"space_type": "disabled"}, headers=admin)
    assert up404.status_code == 404

def test_reserve_occupy_vacate_flow(client, db_session):
    admin = setup_admin(client, db_session)
    user_headers, vehicle = setup_user_and_vehicle(client)
    lot = client.post("/api/v1/parking-lots", json={"name": "LotFLOW", "address": "AddrFLOW", "total_capacity": 0, "available_spots": 0}, headers=admin).json()
    grid = [
        ["entrance","road","parking"],
        ["road","road","parking"],
        ["road","road","exit"],
    ]
    client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={
        "rows": 3, "cols": 3, "grid": grid,
        "entrance_position": {"row": 0, "col": 0},
        "exit_position": {"row": 2, "col": 2},
    }, headers=admin)
    spaces = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()
    sid = spaces[0]["id"]
    # reserve
    try:
        from auth.models.user import User
    except ImportError:
        from backend.auth.models.user import User
    u = db_session.query(User).filter(User.phone_number == "15100000000").first()
    from datetime import timedelta
    reserved_until = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    rsv = client.post(f"/api/v1/parking/spaces/{sid}/reserve", json={"user_id": u.id, "vehicle_id": vehicle["id"], "reserved_until": reserved_until}, headers=user_headers)
    assert rsv.status_code == 200
    # occupy
    occ = client.post(f"/api/v1/parking/spaces/{sid}/occupy", json={"vehicle_id": vehicle["id"]}, headers=user_headers)
    assert occ.status_code == 200
    # prepare billing rule
    client.post(f"/api/v1/parking-lots/{lot['id']}/billing-rule", json={"rule_name": "FLOW", "free_duration_minutes": 0, "hourly_rate": "1.00", "daily_cap_rate": "10.00"}, headers=admin)
    # vacate
    vac = client.post(f"/api/v1/parking/spaces/{sid}/vacate", json={"exit_time": datetime.now(timezone.utc).isoformat()}, headers=user_headers)
    assert vac.status_code == 200
    # unreserve path
    un = client.post(f"/api/v1/parking/spaces/{sid}/unreserve", headers=user_headers)
    assert un.status_code in (200, 400)  # 可能已经释放为available

def test_nearest_and_navigate_and_stats(client, db_session):
    admin = setup_admin(client, db_session)
    headers, vehicle = setup_user_and_vehicle(client)
    lot = client.post("/api/v1/parking-lots", json={"name": "LotNAV", "address": "AddrNAV", "total_capacity": 0, "available_spots": 0}, headers=admin).json()
    grid = [
        ["entrance","road","road","parking"],
        ["wall","wall","road","parking"],
        ["road","road","road","exit"],
    ]
    client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={
        "rows": 3, "cols": 4, "grid": grid,
        "entrance_position": {"row": 0, "col": 0},
        "exit_position": {"row": 2, "col": 3},
    }, headers=admin)
    near = client.post(f"/api/v1/parking-lots/{lot['id']}/nearest-space", json={"origin": {"row": 0, "col": 0}})
    assert near.status_code == 200 and "space_id" in near.json()
    path = client.post(f"/api/v1/parking-lots/{lot['id']}/navigate", json={"start": {"row": 0, "col": 0}, "end": {"row": 2, "col": 3}})
    assert path.status_code == 200 and isinstance(path.json()["path"], list)
    stats = client.get(f"/api/v1/parking-lots/{lot['id']}/stats")
    assert stats.status_code == 200 and "total_spaces" in stats.json()
    # occupy all spaces to make nearest fail
    spaces = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()
    for sp in spaces:
        client.post(f"/api/v1/parking/spaces/{sp['id']}/occupy", json={"vehicle_id": vehicle["id"]}, headers=headers)
    near_fail = client.post(f"/api/v1/parking-lots/{lot['id']}/nearest-space", json={"origin": {"row": 0, "col": 0}})
    assert near_fail.status_code == 404