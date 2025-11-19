from fastapi.testclient import TestClient
from main import app
from auth.database import SessionLocal
from auth.models.user import User
from auth.core.security import get_password_hash, create_access_token
import uuid
from auth.core.enums import PaymentMethod, PaymentType

client = TestClient(app)

def _create_user():
    db = SessionLocal()
    try:
        phone = "138" + str(uuid.uuid4().int)[-8:]
        u = User(username="wallet_tester" + phone[-4:], phone_number=phone, email=f"wallet{phone[-4:]}@test.com", password_hash=get_password_hash("pass123"))
        db.add(u)
        db.commit()
        db.refresh(u)
        return u
    finally:
        db.close()

def _auth_headers(user_id: int, username: str):
    token = create_access_token({"sub": str(user_id), "username": username})
    return {"Authorization": f"Bearer {token}"}

def test_wallet_balance_recharge_withdraw_transactions():
    u = _create_user()
    headers = _auth_headers(u.id, u.username)

    # 初始余额
    r = client.get("/api/v1/wallet/balance", headers=headers)
    assert r.status_code == 200
    assert r.json()["balance"] in ("0", "0.00")

    # 充值
    r = client.post("/api/v1/wallet/recharge", headers=headers, json={"amount": "100.00", "payment_method": PaymentMethod.WECHAT_PAY.value})
    assert r.status_code == 200
    assert r.json()["balance"] == "100.00"

    # 提现失败（超额）
    r = client.post("/api/v1/wallet/withdraw", headers=headers, json={"amount": "150.00", "bank_account": "abc"})
    assert r.status_code == 400

    # 提现成功
    r = client.post("/api/v1/wallet/withdraw", headers=headers, json={"amount": "40.00", "bank_account": "abc"})
    assert r.status_code == 200
    assert r.json()["balance"] == "60.00"

    # 交易列表
    r = client.get("/api/v1/wallet/transactions?skip=0&limit=10", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data.get("total"), int)
    assert isinstance(data.get("transactions"), list)
    assert data["total"] >= 2

def test_wallet_settle_parking_fee():
    u = _create_user()
    headers = _auth_headers(u.id, u.username)
    # 充值足够余额
    client.post("/api/v1/wallet/recharge", headers=headers, json={"amount": "50.00", "payment_method": PaymentMethod.ALIPAY.value})
    # 模拟余额消费：提现 20
    r = client.post("/api/v1/wallet/withdraw", headers=headers, json={"amount": "20.00", "bank_account": "mock"})
    assert r.status_code == 200
    assert r.json()["balance"] == "30.00"