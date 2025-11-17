from datetime import datetime, timedelta, timezone

def setup_user_and_token(client):
    r = client.post("/api/v1/register", json={"phone_number": "15100000000", "password": "password151"})
    assert r.status_code in (200, 201)
    login = client.post("/api/v1/login", data={"username": "15100000000", "password": "password151"})
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}

def test_vehicle_endpoints_and_errors(client):
    headers = setup_user_and_token(client)
    r = client.post("/api/v1/vehicles", json={"license_plate": "PLATE001", "is_default": True}, headers=headers)
    assert r.status_code == 200
    # set default success
    vid = r.json()["id"]
    r_default_ok = client.put(f"/api/v1/vehicles/{vid}/default", headers=headers)
    assert r_default_ok.status_code == 200
    # duplicate plate
    r_dup = client.post("/api/v1/vehicles", json={"license_plate": "PLATE001"}, headers=headers)
    assert r_dup.status_code == 400 and r_dup.json()["detail"] == "车牌号已绑定"
    # list my vehicles
    r_list = client.get("/api/v1/vehicles/me", headers=headers)
    assert r_list.status_code == 200 and isinstance(r_list.json(), list)
    # set default 404
    r_default_404 = client.put("/api/v1/vehicles/99999/default", headers=headers)
    assert r_default_404.status_code == 404 and r_default_404.json()["detail"] == "车辆不存在"
    # delete 404
    r_del_404 = client.delete("/api/v1/vehicles/99999", headers=headers)
    assert r_del_404.status_code == 404
    # delete existing
    r_del_ok = client.delete(f"/api/v1/vehicles/{vid}", headers=headers)
    assert r_del_ok.status_code == 204

def test_parking_lot_and_billing_rules(client, db_session):
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    # create admin
    r_admin = client.post("/api/v1/register", json={"phone_number": "19800000000", "password": "adminpw88"})
    assert r_admin.status_code in (200, 201)
    u = db_session.query(User).filter(User.phone_number == "19800000000").first()
    u.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "19800000000", "password": "adminpw88"}).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    # create parking lot
    r = client.post("/api/v1/parking-lots", json={
        "name": "LotB", "address": "AddrB", "total_capacity": 50, "available_spots": 50,
        "api_key": "device-lotB", "api_secret": "secret-lotB"
    }, headers=admin_headers)
    assert r.status_code == 200
    lot_id = r.json()["id"]
    # duplicate name
    r_dup = client.post("/api/v1/parking-lots", json={
        "name": "LotB", "address": "AddrC", "total_capacity": 100, "available_spots": 90
    }, headers=admin_headers)
    assert r_dup.status_code == 400 and r_dup.json()["detail"] == "停车场名称已存在"
    # list lots
    r_list = client.get("/api/v1/parking-lots")
    assert r_list.status_code == 200 and len(r_list.json()) >= 1
    # update lot not found
    r_up_404 = client.put("/api/v1/parking-lots/99999", json={"address": "X"}, headers=admin_headers)
    assert r_up_404.status_code == 404
    # update lot ok
    r_up = client.put(f"/api/v1/parking-lots/{lot_id}", json={"address": "AddrB2", "total_capacity": 55, "status": "OPEN"}, headers=admin_headers)
    assert r_up.status_code == 200
    # get billing rule: 若不存在则自动创建默认规则，返回200
    r_gr = client.get(f"/api/v1/parking-lots/{lot_id}/billing-rule", headers=admin_headers)
    assert r_gr.status_code == 200
    # 默认规则已存在，再次创建应冲突
    r_rule = client.post(f"/api/v1/parking-lots/{lot_id}/billing-rule", json={
        "rule_name": "StandardB",
        "free_duration_minutes": 10,
        "hourly_rate": "8.00",
        "daily_cap_rate": "30.00"
    }, headers=admin_headers)
    assert r_rule.status_code == 409
    # 再次创建仍应冲突
    r_rule2 = client.post(f"/api/v1/parking-lots/{lot_id}/billing-rule", json={
        "rule_name": "StandardB2",
        "free_duration_minutes": 20,
        "hourly_rate": "9.00",
        "daily_cap_rate": "25.00"
    }, headers=admin_headers)
    assert r_rule2.status_code == 409
    # put update to hit fields
    r_rule_put = client.put(f"/api/v1/parking-lots/{lot_id}/billing-rule", json={
        "rule_name": "StandardB3",
        "free_duration_minutes": 5,
        "hourly_rate": "10.00",
        "daily_cap_rate": "40.00"
    }, headers=admin_headers)
    assert r_rule_put.status_code == 200 and r_rule_put.json()["rule_name"] == "StandardB3"
    # get billing rule
    got = client.get(f"/api/v1/parking-lots/{lot_id}/billing-rule", headers=admin_headers)
    assert got.status_code == 200

def test_parking_records_and_payments_errors_and_lists(client, db_session):
    headers = setup_user_and_token(client)
    # admin setup and create lot with device auth
    # prepare lot and rule
    # admin setup
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "19800000001", "password": "pwadmin2"})
    u2 = db_session.query(User).filter(User.phone_number == "19800000001").first()
    u2.role = UserRole.ADMIN
    db_session.commit()
    admin_token2 = client.post("/api/v1/login", data={"username": "19800000001", "password": "pwadmin2"}).json()["access_token"]
    admin_headers2 = {"Authorization": f"Bearer {admin_token2}"}
    # create lot and rule as admin
    lot_resp = client.post("/api/v1/parking-lots", json={"name": "LotC", "address": "AddrC", "total_capacity": 20, "available_spots": 15, "api_key": "device-lotC", "api_secret": "secret-lotC"}, headers=admin_headers2)
    assert lot_resp.status_code == 200
    lot = lot_resp.json()
    client.post(f"/api/v1/parking-lots/{lot['id']}/billing-rule", json={"rule_name": "C", "free_duration_minutes": 0, "hourly_rate": "5.00", "daily_cap_rate": "10.00"}, headers=admin_headers2)
    # entry 404 for unknown plate with valid device auth
    import hmac, hashlib, time
    ts = str(int(time.time()))
    base_unknown = f"UNKNOWN|{lot['id']}|{ts}"
    sig_unknown = hmac.new("secret-lotC".encode(), base_unknown.encode(), hashlib.sha256).hexdigest()
    r_e404 = client.post("/api/v1/parking-records/entry", json={"license_plate": "UNKNOWN", "parking_lot_id": lot["id"]}, headers={"X-API-KEY": "device-lotC", "X-TIMESTAMP": ts, "X-SIGNATURE": sig_unknown})
    assert r_e404.status_code == 404
    # prepare vehicle
    client.post("/api/v1/vehicles", json={"license_plate": "PLATEC", "is_default": False}, headers=headers)
    # entry ok
    ts_e = str(int(time.time()))
    base_e = f"PLATEC|{lot['id']}|{ts_e}"
    sig_e = hmac.new("secret-lotC".encode(), base_e.encode(), hashlib.sha256).hexdigest()
    entry = client.post("/api/v1/parking-records/entry", json={"license_plate": "PLATEC", "parking_lot_id": lot["id"]}, headers={"X-API-KEY": "device-lotC", "X-TIMESTAMP": ts_e, "X-SIGNATURE": sig_e}).json()
    # exit 404 for bad record id
    ts_x = str(int(time.time()))
    r_x404 = client.post("/api/v1/parking-records/99999/exit", json={}, headers={"X-API-KEY": "device-lotC", "X-TIMESTAMP": ts_x, "X-SIGNATURE": "nosign"})
    assert r_x404.status_code == 404
    # exit ok
    exit_time = datetime.now(timezone.utc) + timedelta(hours=1)
    ts_exit = str(int(time.time()))
    base_exit = f"{entry['id']}|{lot['id']}|{ts_exit}"
    sig_exit = hmac.new("secret-lotC".encode(), base_exit.encode(), hashlib.sha256).hexdigest()
    r_exit = client.post(f"/api/v1/parking-records/{entry['id']}/exit", json={"exit_time": exit_time.isoformat()}, headers={"X-API-KEY": "device-lotC", "X-TIMESTAMP": ts_exit, "X-SIGNATURE": sig_exit})
    assert r_exit.status_code == 200
    # exit without exit_time to hit default path
    ts_e2 = str(int(time.time()))
    base_e2 = f"PLATEC|{lot['id']}|{ts_e2}"
    sig_e2 = hmac.new("secret-lotC".encode(), base_e2.encode(), hashlib.sha256).hexdigest()
    entry2 = client.post("/api/v1/parking-records/entry", json={"license_plate": "PLATEC", "parking_lot_id": lot["id"]}, headers={"X-API-KEY": "device-lotC", "X-TIMESTAMP": ts_e2, "X-SIGNATURE": sig_e2}).json()
    ts_exit2 = str(int(time.time()))
    base_exit2 = f"{entry2['id']}|{lot['id']}|{ts_exit2}"
    sig_exit2 = hmac.new("secret-lotC".encode(), base_exit2.encode(), hashlib.sha256).hexdigest()
    r_exit2 = client.post(f"/api/v1/parking-records/{entry2['id']}/exit", json={}, headers={"X-API-KEY": "device-lotC", "X-TIMESTAMP": ts_exit2, "X-SIGNATURE": sig_exit2})
    assert r_exit2.status_code == 200
    # list my records
    r_my = client.get("/api/v1/parking-records/me", headers=headers)
    assert r_my.status_code == 200 and len(r_my.json()) >= 1
    # entry with invalid lot id to hit lot-not-found branch
    ts_invalid = str(int(time.time()))
    base_invalid = f"PLATEC|{99999}|{ts_invalid}"
    sig_invalid = hmac.new("secret-lotC".encode(), base_invalid.encode(), hashlib.sha256).hexdigest()
    r_invalid_lot = client.post("/api/v1/parking-records/entry", json={"license_plate": "PLATEC", "parking_lot_id": 99999}, headers={"X-API-KEY": "device-lotC", "X-TIMESTAMP": ts_invalid, "X-SIGNATURE": sig_invalid})
    assert r_invalid_lot.status_code == 404
    # payment create 404 for bad record
    r_p404 = client.post("/api/v1/payments", json={"parking_record_id": 99999, "amount": "1.00", "payment_method": "ALIPAY"}, headers=headers)
    assert r_p404.status_code == 404
    # webhook payment 404 for bad payment id
    r_ps404 = client.post("/api/v1/payments/webhook/notify", json={"payment_id": 99999, "amount": "1.00", "status": "SUCCESS", "timestamp": 1, "signature": "x"})
    assert r_ps404.status_code == 401  # 签名失败优先
    # create payment and list payments
    pay = client.post("/api/v1/payments", json={"parking_record_id": entry['id'], "amount": "2.00", "payment_method": "WECHAT_PAY"}, headers=headers).json()
    # webhook success with valid signature
    import hmac, hashlib, time, os
    secret = os.getenv("PAYMENT_WEBHOOK_SECRET", "test_secret")
    ts = int(time.time())
    base = f"{pay['id']}|{pay['amount']}|SUCCESS|{ts}"
    sig = hmac.new(secret.encode(), base.encode(), hashlib.sha256).hexdigest()
    ok = client.post("/api/v1/payments/webhook/notify", json={
        "payment_id": pay['id'],
        "transaction_id": "txC",
        "status": "SUCCESS",
        "amount": pay['amount'],
        "timestamp": ts,
        "signature": sig,
    })
    assert ok.status_code == 200
    # valid signature but unknown payment id -> 404
    base_404 = f"{999999}|{pay['amount']}|SUCCESS|{ts}"
    sig_404 = hmac.new(secret.encode(), base_404.encode(), hashlib.sha256).hexdigest()
    r_ps404b = client.post("/api/v1/payments/webhook/notify", json={
        "payment_id": 999999,
        "transaction_id": "txX",
        "status": "SUCCESS",
        "amount": pay['amount'],
        "timestamp": ts,
        "signature": sig_404,
    })
    assert r_ps404b.status_code == 404
    # invalid status
    base_bad = f"{pay['id']}|{pay['amount']}|FAILED|{ts}"
    sig_bad = hmac.new(secret.encode(), base_bad.encode(), hashlib.sha256).hexdigest()
    bad_status = client.post("/api/v1/payments/webhook/notify", json={
        "payment_id": pay['id'],
        "transaction_id": "txBad",
        "status": "FAILED",
        "amount": pay['amount'],
        "timestamp": ts,
        "signature": sig_bad,
    })
    assert bad_status.status_code == 400
    r_pmy = client.get("/api/v1/payments/me", headers=headers)
    assert r_pmy.status_code == 200 and len(r_pmy.json()) >= 1
    # update billing rule 404
    r_rule_put_404 = client.put("/api/v1/parking-lots/99999/billing-rule", json={"rule_name": "X"}, headers={"Authorization": admin_headers2["Authorization"]})
    assert r_rule_put_404.status_code == 404
def test_admin_required_on_parking_lot_endpoints(client):
    headers = setup_user_and_token(client)
    r = client.post("/api/v1/parking-lots", json={
        "name": "LotX", "address": "AddrX", "total_capacity": 10, "available_spots": 10
    }, headers=headers)
    assert r.status_code == 403

def test_device_auth_entry_missing_and_invalid(client, db_session):
    # admin create lot with device keys
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "19700000000", "password": "adminkey"})
    u = db_session.query(User).filter(User.phone_number == "19700000000").first()
    u.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "19700000000", "password": "adminkey"}).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    lot = client.post("/api/v1/parking-lots", json={"name": "LotK", "address": "AddrK", "total_capacity": 5, "available_spots": 5, "api_key": "device-lotK", "api_secret": "secret-lotK"}, headers={"Authorization": admin_headers["Authorization"]}).json()
    # missing headers -> 401
    r_missing = client.post("/api/v1/parking-records/entry", json={"license_plate": "K001", "parking_lot_id": lot["id"]})
    assert r_missing.status_code == 401
    # wrong api key -> 401
    import hmac, hashlib, time
    ts = str(int(time.time()))
    base = f"K001|{lot['id']}|{ts}"
    sig = hmac.new("secret-lotK".encode(), base.encode(), hashlib.sha256).hexdigest()
    r_bad_key = client.post("/api/v1/parking-records/entry", json={"license_plate": "K001", "parking_lot_id": lot["id"]}, headers={"X-API-KEY": "wrong-key", "X-TIMESTAMP": ts, "X-SIGNATURE": sig})
    assert r_bad_key.status_code == 401
    # bad signature -> 401
    r_bad_sig = client.post("/api/v1/parking-records/entry", json={"license_plate": "K001", "parking_lot_id": lot["id"]}, headers={"X-API-KEY": "device-lotK", "X-TIMESTAMP": ts, "X-SIGNATURE": "bad"})
    assert r_bad_sig.status_code == 401

def test_device_auth_exit_invalid_key_and_signature(client, db_session):
    # prepare admin, lot, rule, vehicle, record
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "19600000000", "password": "adminkey2"})
    u = db_session.query(User).filter(User.phone_number == "19600000000").first()
    u.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "19600000000", "password": "adminkey2"}).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    lot = client.post("/api/v1/parking-lots", json={"name": "LotE", "address": "AddrE", "total_capacity": 5, "available_spots": 5, "api_key": "device-lotE", "api_secret": "secret-lotE"}, headers={"Authorization": admin_headers["Authorization"]}).json()
    client.post(f"/api/v1/parking-lots/{lot['id']}/billing-rule", json={"rule_name": "E", "free_duration_minutes": 0, "hourly_rate": "1.00", "daily_cap_rate": "10.00"}, headers={"Authorization": admin_headers["Authorization"]})
    headers_user = setup_user_and_token(client)
    client.post("/api/v1/vehicles", json={"license_plate": "E001"}, headers=headers_user)
    import hmac, hashlib, time
    ts_e = str(int(time.time()))
    base_e = f"E001|{lot['id']}|{ts_e}"
    sig_e = hmac.new("secret-lotE".encode(), base_e.encode(), hashlib.sha256).hexdigest()
    entry = client.post("/api/v1/parking-records/entry", json={"license_plate": "E001", "parking_lot_id": lot["id"]}, headers={"X-API-KEY": "device-lotE", "X-TIMESTAMP": ts_e, "X-SIGNATURE": sig_e}).json()
    # wrong api key at exit
    ts_x = str(int(time.time()))
    base_x = f"{entry['id']}|{lot['id']}|{ts_x}"
    sig_x = hmac.new("secret-lotE".encode(), base_x.encode(), hashlib.sha256).hexdigest()
    r_bad_key = client.post(f"/api/v1/parking-records/{entry['id']}/exit", json={}, headers={"X-API-KEY": "bad", "X-TIMESTAMP": ts_x, "X-SIGNATURE": sig_x})
    assert r_bad_key.status_code == 401
    # bad signature
    r_bad_sig = client.post(f"/api/v1/parking-records/{entry['id']}/exit", json={}, headers={"X-API-KEY": "device-lotE", "X-TIMESTAMP": ts_x, "X-SIGNATURE": "bad"})
    assert r_bad_sig.status_code == 401

def test_device_auth_exit_missing_and_lot_not_found(client, db_session):
    # setup admin, lot, rule, user, vehicle, record
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "19300000000", "password": "adminkey5"})
    u = db_session.query(User).filter(User.phone_number == "19300000000").first()
    u.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "19300000000", "password": "adminkey5"}).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    lot = client.post("/api/v1/parking-lots", json={"name": "LotM", "address": "AddrM", "total_capacity": 5, "available_spots": 5, "api_key": "device-lotM", "api_secret": "secret-lotM"}, headers=admin_headers).json()
    client.post(f"/api/v1/parking-lots/{lot['id']}/billing-rule", json={"rule_name": "M", "free_duration_minutes": 0, "hourly_rate": "1.00", "daily_cap_rate": "10.00"}, headers=admin_headers)
    headers_user = setup_user_and_token(client)
    client.post("/api/v1/vehicles", json={"license_plate": "M001"}, headers=headers_user)
    import hmac, hashlib, time
    ts_e = str(int(time.time()))
    base_e = f"M001|{lot['id']}|{ts_e}"
    sig_e = hmac.new("secret-lotM".encode(), base_e.encode(), hashlib.sha256).hexdigest()
    entry = client.post("/api/v1/parking-records/entry", json={"license_plate": "M001", "parking_lot_id": lot["id"]}, headers={"X-API-KEY": "device-lotM", "X-TIMESTAMP": ts_e, "X-SIGNATURE": sig_e}).json()
    # missing headers -> 401
    r_missing = client.post(f"/api/v1/parking-records/{entry['id']}/exit", json={})
    assert r_missing.status_code == 401
    # lot not found -> tamper record lot id
    from sqlalchemy import update
    from parking.models import ParkingRecord
    db_session.execute(update(ParkingRecord).where(ParkingRecord.id == entry['id']).values(parking_lot_id=99999))
    db_session.commit()
    ts_x = str(int(time.time()))
    r_lot404 = client.post(f"/api/v1/parking-records/{entry['id']}/exit", json={}, headers={"X-API-KEY": "device-lotM", "X-TIMESTAMP": ts_x, "X-SIGNATURE": "nosign"})
    assert r_lot404.status_code == 404

def test_exit_without_billing_rule_returns_400(client, db_session):
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "19200000000", "password": "adminkey6"})
    u = db_session.query(User).filter(User.phone_number == "19200000000").first()
    u.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "19200000000", "password": "adminkey6"}).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    lot = client.post("/api/v1/parking-lots", json={"name": "LotN", "address": "AddrN", "total_capacity": 5, "available_spots": 5, "api_key": "device-lotN", "api_secret": "secret-lotN"}, headers=admin_headers).json()
    headers_user = setup_user_and_token(client)
    client.post("/api/v1/vehicles", json={"license_plate": "N001"}, headers=headers_user)
    import hmac, hashlib, time
    ts_e = str(int(time.time()))
    base_e = f"N001|{lot['id']}|{ts_e}"
    sig_e = hmac.new("secret-lotN".encode(), base_e.encode(), hashlib.sha256).hexdigest()
    entry = client.post("/api/v1/parking-records/entry", json={"license_plate": "N001", "parking_lot_id": lot["id"]}, headers={"X-API-KEY": "device-lotN", "X-TIMESTAMP": ts_e, "X-SIGNATURE": sig_e}).json()
    ts_x = str(int(time.time()))
    base_x = f"{entry['id']}|{lot['id']}|{ts_x}"
    sig_x = hmac.new("secret-lotN".encode(), base_x.encode(), hashlib.sha256).hexdigest()
    r_no_rule = client.post(f"/api/v1/parking-records/{entry['id']}/exit", json={}, headers={"X-API-KEY": "device-lotN", "X-TIMESTAMP": ts_x, "X-SIGNATURE": sig_x})
    assert r_no_rule.status_code == 400

def test_parking_entry_capacity_full(client, db_session):
    # admin create lot with zero capacity and device keys
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "19500000000", "password": "adminkey3"})
    u = db_session.query(User).filter(User.phone_number == "19500000000").first()
    u.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "19500000000", "password": "adminkey3"}).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    lot = client.post("/api/v1/parking-lots", json={"name": "LotZ", "address": "AddrZ", "total_capacity": 0, "available_spots": 0, "api_key": "device-lotZ", "api_secret": "secret-lotZ"}, headers={"Authorization": admin_headers["Authorization"]}).json()
    headers_user = setup_user_and_token(client)
    client.post("/api/v1/vehicles", json={"license_plate": "Z001"}, headers=headers_user)
    import hmac, hashlib, time
    ts = str(int(time.time()))
    base = f"Z001|{lot['id']}|{ts}"
    sig = hmac.new("secret-lotZ".encode(), base.encode(), hashlib.sha256).hexdigest()
    r_full = client.post("/api/v1/parking-records/entry", json={"license_plate": "Z001", "parking_lot_id": lot["id"]}, headers={"X-API-KEY": "device-lotZ", "X-TIMESTAMP": ts, "X-SIGNATURE": sig})
    assert r_full.status_code == 404

def test_service_transaction_rollbacks(client, db_session, monkeypatch):
    headers = setup_user_and_token(client)
    # monkeypatch Session.commit to throw during vehicle creation
    from sqlalchemy.orm.session import Session as _Session
    original_commit = _Session.commit
    def boom(self):
        raise RuntimeError("boom")
    monkeypatch.setattr(_Session, "commit", boom)
    try:
        r = client.post("/api/v1/vehicles", json={"license_plate": "ROLL001"}, headers=headers)
        assert r.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original_commit)
    # admin update lot with commit failure
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "19400000000", "password": "adminkey4"})
    u = db_session.query(User).filter(User.phone_number == "19400000000").first()
    u.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "19400000000", "password": "adminkey4"}).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    lot_resp = client.post("/api/v1/parking-lots", json={"name": "LotY", "address": "AddrY", "total_capacity": 10, "available_spots": 10}, headers={"Authorization": admin_headers["Authorization"]})
    lot_id = lot_resp.json()["id"]
    monkeypatch.setattr(_Session, "commit", boom)
    try:
        r_up = client.put(f"/api/v1/parking-lots/{lot_id}", json={"address": "AddrY2"}, headers={"Authorization": admin_headers["Authorization"]})
        assert r_up.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original_commit)

def test_commit_failure_set_default_and_delete_vehicle(client, db_session, monkeypatch):
    headers = setup_user_and_token(client)
    created = client.post("/api/v1/vehicles", json={"license_plate": "ROLLSET1"}, headers=headers).json()
    vid = created["id"]
    from sqlalchemy.orm.session import Session as _Session
    original_commit = _Session.commit
    def boom(self):
        raise RuntimeError("boom")
    # set default commit fails -> 500
    monkeypatch.setattr(_Session, "commit", boom)
    try:
        r_def = client.put(f"/api/v1/vehicles/{vid}/default", headers=headers)
        assert r_def.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original_commit)
    # delete commit fails -> 500
    monkeypatch.setattr(_Session, "commit", boom)
    try:
        r_del = client.delete(f"/api/v1/vehicles/{vid}", headers=headers)
        assert r_del.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original_commit)

def test_commit_failure_create_lot_and_rules(client, db_session, monkeypatch):
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "19000000000", "password": "admcommit"})
    u = db_session.query(User).filter(User.phone_number == "19000000000").first()
    u.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "19000000000", "password": "admcommit"}).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    from sqlalchemy.orm.session import Session as _Session
    original_commit = _Session.commit
    def boom(self):
        raise RuntimeError("boom")
    # create lot commit fails -> 500
    monkeypatch.setattr(_Session, "commit", boom)
    try:
        r_lot_fail = client.post("/api/v1/parking-lots", json={
            "name": "LotCF", "address": "AddrCF", "total_capacity": 10, "available_spots": 10
        }, headers=admin_headers)
        assert r_lot_fail.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original_commit)
    # create lot ok
    lot_ok = client.post("/api/v1/parking-lots", json={
        "name": "LotCF2", "address": "AddrCF2", "total_capacity": 20, "available_spots": 20
    }, headers=admin_headers).json()
    # create rule commit fails -> 500
    monkeypatch.setattr(_Session, "commit", boom)
    try:
        r_rule_fail = client.post(f"/api/v1/parking-lots/{lot_ok['id']}/billing-rule", json={
            "rule_name": "RCF", "free_duration_minutes": 0, "hourly_rate": "1.00", "daily_cap_rate": "9.00"
        }, headers=admin_headers)
        assert r_rule_fail.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original_commit)
    # create rule ok then update commit fails -> 500
    client.post(f"/api/v1/parking-lots/{lot_ok['id']}/billing-rule", json={
        "rule_name": "RCF2", "free_duration_minutes": 0, "hourly_rate": "2.00", "daily_cap_rate": "10.00"
    }, headers=admin_headers)
    monkeypatch.setattr(_Session, "commit", boom)
    try:
        r_rule_up_fail = client.put(f"/api/v1/parking-lots/{lot_ok['id']}/billing-rule", json={
            "rule_name": "RCF3"
        }, headers=admin_headers)
        assert r_rule_up_fail.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original_commit)

def test_commit_failure_parking_entry_and_exit(client, db_session, monkeypatch):
    # setup lot with device keys and billing rule directly via DB, user + vehicle
    from parking.models import ParkingLot, BillingRule
    lot_model = ParkingLot(name="LotCFD", address="AddrCFD", total_capacity=5, available_spots=5, api_key="device-cfd", api_secret="secret-cfd")
    db_session.add(lot_model)
    db_session.commit()
    db_session.refresh(lot_model)
    lot_id = lot_model.id
    rule_model = BillingRule(parking_lot_id=lot_id, rule_name="CFD", free_duration_minutes=0, hourly_rate="1.00", daily_cap_rate="10.00")
    db_session.add(rule_model)
    db_session.commit()
    headers_user = setup_user_and_token(client)
    client.post("/api/v1/vehicles", json={"license_plate": "CFD001"}, headers=headers_user)
    import hmac, hashlib, time
    ts = str(int(time.time()))
    base = f"CFD001|{lot_id}|{ts}"
    sig = hmac.new("secret-cfd".encode(), base.encode(), hashlib.sha256).hexdigest()
    from sqlalchemy.orm.session import Session as _Session
    original_commit = _Session.commit
    def boom(self):
        raise RuntimeError("boom")
    # entry commit fails -> 500
    monkeypatch.setattr(_Session, "commit", boom)
    try:
        r_entry_fail = client.post("/api/v1/parking-records/entry", json={"license_plate": "CFD001", "parking_lot_id": lot_id}, headers={"X-API-KEY": "device-cfd", "X-TIMESTAMP": ts, "X-SIGNATURE": sig})
        assert r_entry_fail.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original_commit)
    # create entry ok
    entry_ok = client.post("/api/v1/parking-records/entry", json={"license_plate": "CFD001", "parking_lot_id": lot_id}, headers={"X-API-KEY": "device-cfd", "X-TIMESTAMP": ts, "X-SIGNATURE": sig}).json()
    tsx = str(int(time.time()))
    base_x = f"{entry_ok['id']}|{lot_id}|{tsx}"
    sig_x = hmac.new("secret-cfd".encode(), base_x.encode(), hashlib.sha256).hexdigest()
    # exit commit fails -> 500
    monkeypatch.setattr(_Session, "commit", boom)
    try:
        r_exit_fail = client.post(f"/api/v1/parking-records/{entry_ok['id']}/exit", json={}, headers={"X-API-KEY": "device-cfd", "X-TIMESTAMP": tsx, "X-SIGNATURE": sig_x})
        assert r_exit_fail.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original_commit)

def test_commit_failure_create_payment_and_webhook(client, db_session, monkeypatch):
    # setup user, admin, lot, rule, vehicle, entry
    headers = setup_user_and_token(client)
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "18900000000", "password": "adminpay"})
    u = db_session.query(User).filter(User.phone_number == "18900000000").first()
    u.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "18900000000", "password": "adminpay"}).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    lot = client.post("/api/v1/parking-lots", json={"name": "LotPAY", "address": "AddrPAY", "total_capacity": 5, "available_spots": 5, "api_key": "device-pay", "api_secret": "secret-pay"}, headers=admin_headers).json()
    client.post(f"/api/v1/parking-lots/{lot['id']}/billing-rule", json={"rule_name": "PAY", "free_duration_minutes": 0, "hourly_rate": "1.00", "daily_cap_rate": "10.00"}, headers=admin_headers)
    client.post("/api/v1/vehicles", json={"license_plate": "PAY001"}, headers=headers)
    import hmac, hashlib, time, os
    ts = str(int(time.time()))
    base = f"PAY001|{lot['id']}|{ts}"
    sig = hmac.new("secret-pay".encode(), base.encode(), hashlib.sha256).hexdigest()
    entry = client.post("/api/v1/parking-records/entry", json={"license_plate": "PAY001", "parking_lot_id": lot["id"]}, headers={"X-API-KEY": "device-pay", "X-TIMESTAMP": ts, "X-SIGNATURE": sig}).json()
    # create payment commit fails -> 500
    from sqlalchemy.orm.session import Session as _Session
    original_commit = _Session.commit
    def boom(self):
        raise RuntimeError("boom")
    monkeypatch.setattr(_Session, "commit", boom)
    try:
        r_pay_fail = client.post("/api/v1/payments", json={"parking_record_id": entry["id"], "amount": "2.00", "payment_method": "WECHAT_PAY"}, headers=headers)
        assert r_pay_fail.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original_commit)
    # create payment ok then webhook commit fails -> 500
    pay = client.post("/api/v1/payments", json={"parking_record_id": entry["id"], "amount": "2.00", "payment_method": "WECHAT_PAY"}, headers=headers).json()
    secret = os.getenv("PAYMENT_WEBHOOK_SECRET", "test_secret")
    import time as _t
    ts2 = int(_t.time())
    base2 = f"{pay['id']}|{pay['amount']}|SUCCESS|{ts2}"
    sig2 = hmac.new(secret.encode(), base2.encode(), hashlib.sha256).hexdigest()
    monkeypatch.setattr(_Session, "commit", boom)
    try:
        r_hook_fail = client.post("/api/v1/payments/webhook/notify", json={
            "payment_id": pay['id'],
            "transaction_id": "txPAY",
            "status": "SUCCESS",
            "amount": pay['amount'],
            "timestamp": ts2,
            "signature": sig2,
        })
        assert r_hook_fail.status_code == 500
    finally:
        monkeypatch.setattr(_Session, "commit", original_commit)