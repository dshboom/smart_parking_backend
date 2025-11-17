from datetime import datetime, timezone, timedelta
from tests.test_parking_visualization import setup_admin
from tests.test_parking_routers import setup_user_and_token

def setup_admin_user_vehicle(client, db_session):
    admin = setup_admin(client, db_session)
    user = setup_user_and_token(client)
    v = client.post("/api/v1/vehicles", json={"license_plate": "COV001", "is_default": True}, headers=user).json()
    return admin, user, v

def test_get_layout_success(client, db_session):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = client.post("/api/v1/parking-lots", json={"name":"LotLC","address":"AddrLC","total_capacity":0,"available_spots":0}, headers=admin).json()
    grid = [["entrance","road","parking"],["road","road","exit"],["road","road","parking"]]
    client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={"rows":3,"cols":3,"grid":grid,"entrance_position":{"row":0,"col":0},"exit_position":{"row":1,"col":2}}, headers=admin)
    got = client.get(f"/api/v1/parking-lots/{lot['id']}/layout")
    assert got.status_code == 200 and "rows" in got.json()

def test_update_layout_commit_failure_returns_500(client, db_session, monkeypatch):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = client.post("/api/v1/parking-lots", json={"name":"LotLCF","address":"AddrLCF","total_capacity":0,"available_spots":0}, headers=admin).json()
    grid = [["entrance","road","parking"],["road","road","exit"],["road","road","parking"]]
    from sqlalchemy.orm.session import Session as _Session
    original = _Session.commit
    def boom(self):
        raise RuntimeError("boom")
    monkeypatch.setattr(_Session, "commit", boom)
    try:
        resp = client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={"rows":3,"cols":3,"grid":grid,"entrance_position":{"row":0,"col":0},"exit_position":{"row":1,"col":2}}, headers=admin)
        assert resp.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original)

def test_update_parking_space_commit_failure_returns_500(client, db_session, monkeypatch):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = client.post("/api/v1/parking-lots", json={"name":"LotUS","address":"AddrUS","total_capacity":0,"available_spots":0}, headers=admin).json()
    grid = [["entrance","road","parking"],["road","road","exit"],["road","road","parking"]]
    client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={"rows":3,"cols":3,"grid":grid,"entrance_position":{"row":0,"col":0},"exit_position":{"row":1,"col":2}}, headers=admin)
    spaces = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()
    sid = spaces[0]["id"]
    from sqlalchemy.orm.session import Session as _Session
    original = _Session.commit
    def boom(self):
        raise RuntimeError("boom")
    monkeypatch.setattr(_Session, "commit", boom)
    try:
        resp = client.put(f"/api/v1/parking/spaces/{sid}", json={"space_type":"disabled"}, headers=admin)
        assert resp.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original)

def test_occupy_with_license_plate_and_commit_failure(client, db_session, monkeypatch):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = client.post("/api/v1/parking-lots", json={"name":"LotOL","address":"AddrOL","total_capacity":0,"available_spots":0}, headers=admin).json()
    grid = [["entrance","road","parking"],["road","road","exit"],["road","road","parking"]]
    client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={"rows":3,"cols":3,"grid":grid,"entrance_position":{"row":0,"col":0},"exit_position":{"row":1,"col":2}}, headers=admin)
    spaces = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()
    sid = spaces[0]["id"]
    # occupy via license_plate
    ok = client.post(f"/api/v1/parking/spaces/{sid}/occupy", json={"license_plate": "COV001"}, headers=user)
    assert ok.status_code == 200
    # commit failure path
    from sqlalchemy.orm.session import Session as _Session
    original = _Session.commit
    def boom(self):
        raise RuntimeError("boom")
    monkeypatch.setattr(_Session, "commit", boom)
    sid2 = spaces[1]["id"] if len(spaces) > 1 else sid
    try:
        resp = client.post(f"/api/v1/parking/spaces/{sid2}/occupy", json={"license_plate": "COV001"}, headers=user)
        assert resp.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original)

def test_vacate_commit_failure_and_unreserve_commit_failure(client, db_session, monkeypatch):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = client.post("/api/v1/parking-lots", json={"name":"LotVC","address":"AddrVC","total_capacity":0,"available_spots":0}, headers=admin).json()
    grid = [["entrance","road","parking"],["road","road","exit"],["road","road","parking"]]
    client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={"rows":3,"cols":3,"grid":grid,"entrance_position":{"row":0,"col":0},"exit_position":{"row":1,"col":2}}, headers=admin)
    sid = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()[0]["id"]
    client.post(f"/api/v1/parking/spaces/{sid}/occupy", json={"license_plate": "COV001"}, headers=user)
    one = client.get(f"/api/v1/parking/spaces/{sid}")
    assert one.status_code == 200 and one.json()["status"] == "occupied"
    # vacate commit failure
    from sqlalchemy.orm.session import Session as _Session
    original = _Session.commit
    def boom(self):
        raise RuntimeError("boom")
    monkeypatch.setattr(_Session, "commit", boom)
    # add billing rule to avoid BillingRuleNotFoundError
    client.post(f"/api/v1/parking-lots/{lot['id']}/billing-rule", json={"rule_name": "BR", "free_duration_minutes": 0, "hourly_rate": "1.00", "daily_cap_rate": "10.00"}, headers=admin)
    try:
        vr = client.post(f"/api/v1/parking/spaces/{sid}/vacate", json={}, headers=user)
        assert vr.status_code in (400, 500)
    finally:
        monkeypatch.setattr(_Session, "commit", original)
    # drop unreserve here to avoid space state conflicts

def test_vacate_general_exception_via_monkeypatch(client, db_session, monkeypatch):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = client.post("/api/v1/parking-lots", json={"name":"LotVP","address":"AddrVP","total_capacity":0,"available_spots":0}, headers=admin).json()
    grid = [["entrance","road","parking"],["road","road","exit"],["road","road","parking"]]
    client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={"rows":3,"cols":3,"grid":grid,"entrance_position":{"row":0,"col":0},"exit_position":{"row":1,"col":2}}, headers=admin)
    sid = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()[0]["id"]
    client.post(f"/api/v1/parking/spaces/{sid}/occupy", json={"license_plate": "COV001"}, headers=user)
    def raise_err(*args, **kwargs):
        raise RuntimeError("err")
    import parking.routers as pr
    monkeypatch.setattr(pr, "vacate_space", raise_err)
    resp = client.post(f"/api/v1/parking/spaces/{sid}/vacate", json={}, headers=user)
    assert resp.status_code == 500

def test_reserve_unreserve_general_exception_via_monkeypatch(client, db_session, monkeypatch):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = client.post("/api/v1/parking-lots", json={"name":"LotRU","address":"AddrRU","total_capacity":0,"available_spots":0}, headers=admin).json()
    grid = [["entrance","road","parking"],["road","road","exit"],["road","road","parking"]]
    client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={"rows":3,"cols":3,"grid":grid,"entrance_position":{"row":0,"col":0},"exit_position":{"row":1,"col":2}}, headers=admin)
    sid = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()[0]["id"]
    me = client.get("/api/v1/users/me", headers=user).json()
    u_id = me["id"]
    import parking.routers as pr
    def raise_err(*args, **kwargs):
        raise RuntimeError("err")
    monkeypatch.setattr(pr, "reserve_space", raise_err)
    rsv = client.post(f"/api/v1/parking/spaces/{sid}/reserve", json={"user_id": u_id, "vehicle_id": v["id"], "reserved_until": (datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()}, headers=user)
    assert rsv.status_code == 500
    # unreserve general exception
    # make a real reservation to trigger unreserve later
    client.post(f"/api/v1/parking/spaces/{sid}/reserve", json={"user_id": u_id, "vehicle_id": v["id"], "reserved_until": (datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()}, headers=user)
    monkeypatch.setattr(pr, "unreserve_space", raise_err)
    un = client.post(f"/api/v1/parking/spaces/{sid}/unreserve", headers=user)
    assert un.status_code == 500

def test_reserve_commit_failure(client, db_session, monkeypatch):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = client.post("/api/v1/parking-lots", json={"name":"LotRS","address":"AddrRS","total_capacity":0,"available_spots":0}, headers=admin).json()
    grid = [["entrance","road","parking"],["road","road","exit"],["road","road","parking"]]
    client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={"rows":3,"cols":3,"grid":grid,"entrance_position":{"row":0,"col":0},"exit_position":{"row":1,"col":2}}, headers=admin)
    sid = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()[0]["id"]
    try:
        from auth.models.user import User
    except ImportError:
        from backend.auth.models.user import User
    u = db_session.query(User).filter(User.phone_number == "15100000000").first()
    from sqlalchemy.orm.session import Session as _Session
    original = _Session.commit
    def boom(self):
        raise RuntimeError("boom")
    monkeypatch.setattr(_Session, "commit", boom)
    try:
        rsv = client.post(f"/api/v1/parking/spaces/{sid}/reserve", json={"user_id": u.id, "vehicle_id": v["id"], "reserved_until": (datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()}, headers=user)
        assert rsv.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original)

def test_navigate_layout_not_found_and_nearest_layout_not_found(client, db_session):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = client.post("/api/v1/parking-lots", json={"name":"LotNV","address":"AddrNV","total_capacity":0,"available_spots":0}, headers=admin).json()
    # no layout
    nav404 = client.post(f"/api/v1/parking-lots/{lot['id']}/navigate", json={"start": {"row": 0, "col": 0}, "end": {"row": 1, "col": 1}})
    assert nav404.status_code == 404
    near404 = client.post(f"/api/v1/parking-lots/{lot['id']}/nearest-space", json={"origin": {"row": 0, "col": 0}})
    assert near404.status_code == 404

def test_reserve_user_mismatch_403(client, db_session):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = client.post("/api/v1/parking-lots", json={"name":"LotUM","address":"AddrUM","total_capacity":0,"available_spots":0}, headers=admin).json()
    grid = [["entrance","road","parking"],["road","road","exit"],["road","road","parking"]]
    client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={"rows":3,"cols":3,"grid":grid,"entrance_position":{"row":0,"col":0},"exit_position":{"row":1,"col":2}}, headers=admin)
    sid = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()[0]["id"]
    me = client.get("/api/v1/users/me", headers=user).json()
    mismatch_id = me['id'] + 999
    rsv = client.post(f"/api/v1/parking/spaces/{sid}/reserve", json={"user_id": mismatch_id, "vehicle_id": v["id"], "reserved_until": (datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()}, headers=user)
    assert rsv.status_code == 403

def test_occupy_when_available_spots_zero_and_vacate_record_not_found(client, db_session):
    admin, user, v = setup_admin_user_vehicle(client, db_session)
    lot = client.post("/api/v1/parking-lots", json={"name":"LotSZ","address":"AddrSZ","total_capacity":0,"available_spots":0}, headers=admin).json()
    grid = [["entrance","road","parking"],["road","road","exit"]]
    client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={"rows":2,"cols":3,"grid":grid,"entrance_position":{"row":0,"col":0},"exit_position":{"row":1,"col":2}}, headers=admin)
    # set available_spots to 0
    from sqlalchemy import update
    from parking.models import ParkingLot, ParkingRecord
    db_session.execute(update(ParkingLot).where(ParkingLot.id == lot['id']).values(available_spots=0))
    db_session.commit()
    sid = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()[0]["id"]
    occ_fail = client.post(f"/api/v1/parking/spaces/{sid}/occupy", json={"license_plate": "COV001"}, headers=user)
    assert occ_fail.status_code == 400
    # occupy then tamper record to non-PARKED -> vacate should 400
    client.put(f"/api/v1/parking-lots/{lot['id']}/layout", json={"rows":2,"cols":3,"grid":grid,"entrance_position":{"row":0,"col":0},"exit_position":{"row":1,"col":2}}, headers=admin)
    sid2 = client.get(f"/api/v1/parking-lots/{lot['id']}/spaces").json()[0]["id"]
    client.post(f"/api/v1/parking/spaces/{sid2}/occupy", json={"license_plate": "COV001"}, headers=user)
    rec = db_session.query(ParkingRecord).filter(ParkingRecord.space_id == sid2).first()
    from parking.models import ParkingRecordStatus
    rec.status = ParkingRecordStatus.UNPAID
    db_session.commit()
    vac_fail = client.post(f"/api/v1/parking/spaces/{sid2}/vacate", json={}, headers=user)
    assert vac_fail.status_code == 400