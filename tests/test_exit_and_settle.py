from datetime import datetime, timezone, timedelta
from decimal import Decimal

def setup_admin(client, db_session, phone, password):
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    r = client.post("/api/v1/register", json={"phone_number": phone, "password": password})
    assert r.status_code in (200, 201)
    u = db_session.query(User).filter(User.phone_number == phone).first()
    u.role = UserRole.ADMIN
    db_session.commit()
    token = client.post("/api/v1/login", data={"username": phone, "password": password}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def setup_user(client, db_session, phone, password):
    r = client.post("/api/v1/register", json={"phone_number": phone, "password": password})
    assert r.status_code in (200, 201)
    token = client.post("/api/v1/login", data={"username": phone, "password": password}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_exit_and_settle_flow(client, db_session):
    admin = setup_admin(client, db_session, "19981000001", "adminx01")
    lot = client.post("/api/v1/parking-lots", json={"name": "LotX1", "address": "AddrX1", "total_capacity": 3, "available_spots": 3}, headers=admin).json()
    user = setup_user(client, db_session, "15181000001", "passwordx01")
    veh = client.post("/api/v1/vehicles", json={"license_plate": "X1001"}, headers=user).json()
    # 直接创建计费以生成UNPAID记录
    ts = datetime.now(timezone.utc).isoformat()
    client.post(f"/api/v1/parking-lots/{lot['id']}/billing-rule", json={"rule_name": "X1", "free_duration_minutes": 0, "hourly_rate": "1.00", "daily_cap_rate": "5.00"}, headers=admin)
    entry = client.post("/api/v1/parking-records/entry", json={"license_plate": "X1001", "parking_lot_id": lot["id"]}, headers={"X-API-KEY": lot.get("api_key") or "", "X-TIMESTAMP": "1", "X-SIGNATURE": "bad"})
    # 设备签名未通过则不创建，改走占用车位路径（简化：直接占用失败则跳过）
    # 强制创建一条记录以测试结算逻辑
    from parking.models import ParkingRecord
    rec = ParkingRecord(vehicle_id=veh["id"], parking_lot_id=lot["id"], license_plate_snapshot="X1001", entry_time=datetime.now(timezone.utc))
    db_session.add(rec)
    db_session.commit()
    # 完成结算端点
    r = client.post(f"/api/v1/parking-records/{rec.id}/exit-and-settle", headers=user)
    assert r.status_code in (200, 400)
    if r.status_code == 400:
        # 余额不足场景：充值后重试
        client.post("/api/v1/wallet/recharge", json={"amount": "10.00", "payment_method": "BALANCE"}, headers=user)
        r2 = client.post(f"/api/v1/parking-records/{rec.id}/exit-and-settle", headers=user)
        assert r2.status_code == 200

def test_exit_and_settle_idempotent(client, db_session):
    admin = setup_admin(client, db_session, "19981000002", "adminx02")
    lot = client.post("/api/v1/parking-lots", json={"name": "LotX2", "address": "AddrX2", "total_capacity": 3, "available_spots": 3}, headers=admin).json()
    user = setup_user(client, db_session, "15181000002", "passwordx02")
    veh = client.post("/api/v1/vehicles", json={"license_plate": "X2001"}, headers=user).json()
    # 充值余额
    client.post("/api/v1/wallet/recharge", json={"amount": "20.00", "payment_method": "BALANCE"}, headers=user)
    # 创建记录
    from parking.models import ParkingRecord
    rec = ParkingRecord(vehicle_id=veh["id"], parking_lot_id=lot["id"], license_plate_snapshot="X2001", entry_time=datetime.now(timezone.utc))
    db_session.add(rec)
    db_session.commit()
    # 第一次结算
    r1 = client.post(f"/api/v1/parking-records/{rec.id}/exit-and-settle", headers=user)
    assert r1.status_code == 200
    # 第二次结算（幂等）
    r2 = client.post(f"/api/v1/parking-records/{rec.id}/exit-and-settle", headers=user)
    assert r2.status_code == 200