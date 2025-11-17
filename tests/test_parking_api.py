from datetime import datetime, timedelta, timezone

def auth_headers(client):
    r = client.post("/api/v1/register", json={"phone_number": "15000000000", "password": "strongpass"})
    assert r.status_code in (200, 201)
    login = client.post("/api/v1/login", data={"username": "15000000000", "password": "strongpass"})
    assert login.status_code == 200
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def admin_headers(client, db_session):
    r = client.post("/api/v1/register", json={"phone_number": "19900000000", "password": "adminpass"})
    assert r.status_code in (200, 201)
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    u = db_session.query(User).filter(User.phone_number == "19900000000").first()
    u.role = UserRole.ADMIN
    db_session.commit()
    login = client.post("/api/v1/login", data={"username": "19900000000", "password": "adminpass"})
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}

def test_parking_flow(client, db_session):
    headers = auth_headers(client)
    admin = admin_headers(client, db_session)
    lot_resp = client.post("/api/v1/parking-lots", json={
        "name": "LotA",
        "address": "Addr",
        "total_capacity": 100,
        "available_spots": 80,
        "api_key": "device-lotA",
        "api_secret": "secret-lotA"
    }, headers=admin)
    assert lot_resp.status_code == 200
    lot_id = lot_resp.json()["id"]
    rule_resp = client.post(f"/api/v1/parking-lots/{lot_id}/billing-rule", json={
        "rule_name": "Standard",
        "free_duration_minutes": 15,
        "hourly_rate": "10.00",
        "daily_cap_rate": "50.00"
    }, headers=admin)
    assert rule_resp.status_code == 200
    v_resp = client.post("/api/v1/vehicles", json={"license_plate": "ABC123", "is_default": True}, headers=headers)
    assert v_resp.status_code == 200
    import hmac, hashlib, time
    ts = str(int(time.time()))
    base_entry = f"ABC123|{lot_id}|{ts}"
    sig_entry = hmac.new("secret-lotA".encode(), base_entry.encode(), hashlib.sha256).hexdigest()
    entry_resp = client.post("/api/v1/parking-records/entry", json={"license_plate": "ABC123", "parking_lot_id": lot_id}, headers={"X-API-KEY": "device-lotA", "X-TIMESTAMP": ts, "X-SIGNATURE": sig_entry})
    assert entry_resp.status_code == 200
    record_id = entry_resp.json()["id"]
    exit_time = datetime.now(timezone.utc) + timedelta(hours=2)
    ts2 = str(int(time.time()))
    base_exit = f"{record_id}|{lot_id}|{ts2}"
    sig_exit = hmac.new("secret-lotA".encode(), base_exit.encode(), hashlib.sha256).hexdigest()
    exit_resp = client.post(f"/api/v1/parking-records/{record_id}/exit", json={"exit_time": exit_time.isoformat()}, headers={"X-API-KEY": "device-lotA", "X-TIMESTAMP": ts2, "X-SIGNATURE": sig_exit})
    assert exit_resp.status_code == 200
    fee = exit_resp.json()["fee"]
    pay_resp = client.post("/api/v1/payments", json={
        "parking_record_id": record_id,
        "amount": fee,
        "payment_method": "WECHAT_PAY"
    }, headers=headers)
    assert pay_resp.status_code == 200
    payment_id = pay_resp.json()["id"]
    import hmac, hashlib, time, os
    secret = os.getenv("PAYMENT_WEBHOOK_SECRET", "test_secret")
    ts = int(time.time())
    base = f"{payment_id}|{fee}|SUCCESS|{ts}"
    sig = hmac.new(secret.encode(), base.encode(), hashlib.sha256).hexdigest()
    ok_resp = client.post("/api/v1/payments/webhook/notify", json={
        "payment_id": payment_id,
        "transaction_id": "tx123",
        "status": "SUCCESS",
        "amount": fee,
        "timestamp": ts,
        "signature": sig,
    })
    assert ok_resp.status_code == 200
    my_records = client.get("/api/v1/parking-records/me", headers=headers)
    assert my_records.status_code == 200
    assert len(my_records.json()) >= 1