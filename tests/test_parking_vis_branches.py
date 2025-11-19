from datetime import datetime, timezone, timedelta
from tests.test_parking_routers import setup_user_and_token
from tests.test_parking_visualization import setup_admin

def setup_admin_and_user(client, db_session):
    admin = setup_admin(client, db_session)
    user = setup_user_and_token(client)
    client.post("/api/v1/vehicles", json={"license_plate": "B001", "is_default": True}, headers=user)
    return admin, user

def build_lot_with_layout(client, admin, name="LotB1", rows=3, cols=3, grid=None):
    lot = client.post("/api/v1/parking-lots", json={"name": name, "address": "AddrB1", "total_capacity": 0, "available_spots": 0}, headers=admin).json()
    if grid is None:
        grid = [["entrance","road","parking"],["road","road","parking"],["road","road","exit"]]
    resp = client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={
        "rows": rows, "cols": cols, "grid": grid,
        "entrance_position": {"row": 0, "col": 0},
        "exit_position": {"row": rows-1, "col": cols-1},
    }, headers=admin)
    assert resp.status_code == 200
    return lot

def test_layout_get_404(client):
    r404 = client.get("/api/v1/parking-lots/99999/layout")
    assert r404.status_code == 404

def test_layout_update_create_and_update_paths(client, db_session):
    admin, user = setup_admin_and_user(client, db_session)
    lot = build_lot_with_layout(client, admin, name="LotB2")
    grid2 = [["entrance","road","parking"],["road","wall","parking"],["road","road","exit"]]
    resp2 = client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={
        "rows": 3, "cols": 3, "grid": grid2,
        "entrance_position": {"row": 0, "col": 0},
        "exit_position": {"row": 2, "col": 2},
    }, headers=admin)
    assert resp2.status_code == 200

def test_spaces_listing_filters_and_errors(client, db_session):
    admin, user = setup_admin_and_user(client, db_session)
    lot = build_lot_with_layout(client, admin, name="LotB3")
    s_all = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces")
    assert s_all.status_code == 200 and len(s_all.json()) >= 1
    bad_status = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces", params={"status_value": "bad"})
    assert bad_status.status_code == 400
    bad_type = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces", params={"space_type": "bad"})
    assert bad_type.status_code == 400

def test_space_detail_update_and_404(client, db_session):
    admin, user = setup_admin_and_user(client, db_session)
    lot = build_lot_with_layout(client, admin, name="LotB4")
    spaces = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()
    sid = spaces[0]["id"]
    one = client.get(f"/api/v1/parking/spaces/{sid}")
    assert one.status_code == 200
    s404 = client.get("/api/v1/parking/spaces/999999")
    assert s404.status_code == 404
    # 已移除车位属性编辑端点，跳过更新测试

def test_occupy_failures_and_success_paths(client, db_session):
    admin, user = setup_admin_and_user(client, db_session)
    lot = build_lot_with_layout(client, admin, name="LotB5")
    spaces = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()
    sid = spaces[0]["id"]
    r_none = client.post("/api/v1/parking/spaces/999999/occupy", json={}, headers=user)
    assert r_none.status_code == 400
    # 维护/可用状态切换已移除，直接验证占用成功路径
    ok = client.post(f"/api/v1/parking/spaces/{sid}/occupy", json={}, headers=user)
    assert ok.status_code == 200

def test_reserve_conflicts_and_unreserve(client, db_session):
    admin, user = setup_admin_and_user(client, db_session)
    lot = build_lot_with_layout(client, admin, name="LotB6")
    try:
        from auth.models.user import User
    except ImportError:
        from backend.auth.models.user import User
    u = db_session.query(User).filter(User.phone_number == "15100000000").first()
    veh = client.get("/api/v1/vehicles/me", headers=user).json()[0]
    spaces = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()
    sid = spaces[0]["id"]
    rsv = client.post(f"/api/v1/parking/spaces/{sid}/reserve", json={"user_id": u.id, "vehicle_id": veh["id"]}, headers=user)
    assert rsv.status_code == 200
    rsv_conf = client.post(f"/api/v1/parking/spaces/{sid}/reserve", json={"user_id": u.id, "vehicle_id": veh["id"]}, headers=user)
    assert rsv_conf.status_code == 400
    un = client.post(f"/api/v1/parking/spaces/{sid}/unreserve", headers=user)
    assert un.status_code == 200
    un2 = client.post(f"/api/v1/parking/spaces/{sid}/unreserve", headers=user)
    assert un2.status_code == 400

def test_vacate_failures_and_billing_rule_missing(client, db_session):
    admin, user = setup_admin_and_user(client, db_session)
    lot = build_lot_with_layout(client, admin, name="LotB7")
    spaces = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()
    sid = spaces[0]["id"]
    r_fail = client.post(f"/api/v1/parking/spaces/{sid}/vacate", json={}, headers=user)
    assert r_fail.status_code == 400
    client.post(f"/api/v1/parking/spaces/{sid}/occupy", json={}, headers=user)
    r_no_rule = client.post(f"/api/v1/parking/spaces/{sid}/vacate", json={}, headers=user)
    assert r_no_rule.status_code == 400
    client.post(f"/api/v1/parking-lots/{lot['id']}/billing-rule", json={"rule_name": "B7", "free_duration_minutes": 0, "hourly_rate": "1.00", "daily_cap_rate": "10.00"}, headers=admin)
    r_ok = client.post(f"/api/v1/parking/spaces/{sid}/vacate", json={"exit_time": datetime.now(timezone.utc).isoformat()}, headers=user)
    assert r_ok.status_code == 200

def test_nearest_and_navigate_edges(client, db_session):
    admin, user = setup_admin_and_user(client, db_session)
    grid = [["entrance","wall"],["wall","exit"]]
    lot = build_lot_with_layout(client, admin, name="LotB8", rows=2, cols=2, grid=grid)
    near = client.post(f"/api/v1/parking-lots/{lot['id']}/nearest-space", json={"origin": {"row": 0, "col": 0}})
    assert near.status_code == 404
    path = client.post(f"/api/v1/parking-lots/{lot['id']}/navigate", json={"start": {"row": 0, "col": 0}, "end": {"row": 1, "col": 1}})
    assert path.status_code == 200 and path.json()["path"] == []

def test_stats(client, db_session):
    admin, user = setup_admin_and_user(client, db_session)
    lot = build_lot_with_layout(client, admin, name="LotB9")
    stats = client.get(f"/api/v1/parking-lots/{lot['id']}/stats")
    assert stats.status_code == 200 and "total_spaces" in stats.json()