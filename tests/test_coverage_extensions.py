import sys
import os
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_register_email_already_exists(client):
    client.post(
        "/api/v1/register",
        json={
            "phone_number": "18000000001",
            "email": "dup@example.com",
            "password": "password123"
        },
    )

    r = client.post(
        "/api/v1/register",
        json={
            "phone_number": "18000000002",
            "email": "dup@example.com",
            "password": "password456"
        },
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "该邮箱已被注册"


def test_account_lock_after_failed_logins(client, db_session):
    phone = "18000000003"
    password = "correct_password"
    client.post("/api/v1/register", json={"phone_number": phone, "password": password})
    for _ in range(5):
        client.post("/api/v1/login", data={"username": phone, "password": "wrong"})
    r = client.post("/api/v1/login", data={"username": phone, "password": password})
    assert r.status_code == 423
    assert r.json()["detail"] == "账户被锁定"


def test_refresh_missing_token(client):
    r = client.post("/api/v1/refresh", json={})
    assert r.status_code == 400
    assert r.json()["detail"] == "缺少刷新令牌"


def test_refresh_bad_format_token(client):
    r = client.post("/api/v1/refresh", json={"refresh_token": "badformat"})
    assert r.status_code == 401
    assert r.json()["detail"] == "刷新令牌格式错误"


def test_refresh_wrong_secret_and_user_unavailable(client, db_session):
    phone = "18000000004"
    password = "pw12345678"
    login = client.post("/api/v1/register", json={"phone_number": phone, "password": password})
    assert login.status_code == 201
    login = client.post("/api/v1/login", data={"username": phone, "password": password})
    assert login.status_code == 200
    rt = login.json()["refresh_token"]
    token_id = rt.split(".")[0]
    bad = f"{token_id}.wrongsecret"
    r_bad = client.post("/api/v1/refresh", json={"refresh_token": bad})
    assert r_bad.status_code == 401
    assert r_bad.json()["detail"] == "刷新令牌验证失败"

    try:
        from auth.models.user import User, UserStatus
    except ImportError:
        from backend.auth.models.user import User, UserStatus
    u = db_session.query(User).filter(User.phone_number == phone).first()
    u.status = UserStatus.SUSPENDED
    db_session.commit()
    r_forbidden = client.post("/api/v1/refresh", json={"refresh_token": rt})
    assert r_forbidden.status_code == 403
    assert r_forbidden.json()["detail"] == "用户不可用"


def test_current_user_suspended_forbidden(client, db_session):
    phone = "18000000005"
    password = "pw987654321"
    client.post("/api/v1/register", json={"phone_number": phone, "password": password})
    login = client.post("/api/v1/login", data={"username": phone, "password": password})
    token = login.json()["access_token"]
    try:
        from auth.models.user import User, UserStatus
    except ImportError:
        from backend.auth.models.user import User, UserStatus
    u = db_session.query(User).filter(User.phone_number == phone).first()
    u.status = UserStatus.SUSPENDED
    db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    r = client.get("/api/v1/users/me", headers=headers)
    assert r.status_code == 403
    assert r.json()["detail"] == "用户已被禁用"


def test_admin_update_nonexistent_user_status_404(client, db_session):
    try:
        from auth.models.user import User, UserStatus, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserStatus, UserRole
    client.post(
        "/api/v1/register",
        json={"phone_number": "18000000006", "password": "pw"}
    )
    admin = client.post(
        "/api/v1/register",
        json={"phone_number": "18000000007", "password": "admin_pw"}
    )
    u_admin = db_session.query(User).filter(User.phone_number == "18000000007").first()
    u_admin.role = UserRole.ADMIN
    db_session.commit()
    token = client.post("/api/v1/login", data={"username": "18000000007", "password": "admin_pw"}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    r = client.put("/api/v1/admin/users/9999/status", params={"status": "suspended"}, headers=headers)
    assert r.status_code == 404
    assert r.json()["detail"] == "用户不存在"


def test_login_logs_date_filtering(client, db_session):
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "18000000008", "password": "password_18000000008"})
    client.post("/api/v1/register", json={"phone_number": "18000000009", "password": "password_18000000009"})
    admin_user = db_session.query(User).filter(User.phone_number == "18000000008").first()
    admin_user.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "18000000008", "password": "password_18000000008"}).json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}
    client.post("/api/v1/login", data={"username": "18000000009", "password": "password_18000000009"})
    client.post("/api/v1/login", data={"username": "18000000009", "password": "wrong"})
    start = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    end = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    r = client.get(
        "/api/v1/admin/users/2/login-logs",
        params={"start_date": start, "end_date": end},
        headers=headers,
    )
    assert r.status_code == 200
    assert len(r.json()["items"]) >= 2


def test_all_login_logs_date_filtering(client, db_session):
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "18000000010", "password": "password_18000000010"})
    client.post("/api/v1/register", json={"phone_number": "18000000011", "password": "password_18000000011"})
    admin_user = db_session.query(User).filter(User.phone_number == "18000000010").first()
    admin_user.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "18000000010", "password": "password_18000000010"}).json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}
    client.post("/api/v1/login", data={"username": "18000000011", "password": "password_18000000011"})
    start = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    end = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    r = client.get(
        "/api/v1/admin/login-logs",
        params={"start_date": start, "end_date": end},
        headers=headers,
    )
    assert r.status_code == 200
    assert len(r.json()["items"]) >= 1


def test_operation_logs_date_filtering(client, db_session):
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "18000000012", "password": "password_18000000012"})
    client.post("/api/v1/register", json={"phone_number": "18000000013", "password": "password_18000000013"})
    admin_user = db_session.query(User).filter(User.phone_number == "18000000012").first()
    admin_user.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "18000000012", "password": "password_18000000012"}).json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}
    client.put("/api/v1/admin/users/2/status", params={"status": "suspended"}, headers=headers)
    start = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    end = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    r = client.get(
        "/api/v1/admin/operation-logs",
        params={"start_date": start, "end_date": end},
        headers=headers,
    )
    assert r.status_code == 200
    assert len(r.json()["items"]) >= 1


def test_create_access_token_expires_delta():
    try:
        from auth.core.security import create_access_token
    except ImportError:
        from backend.auth.core.security import create_access_token
    token = create_access_token({"sub": "1"}, expires_delta=timedelta(minutes=1))
    assert isinstance(token, str) and len(token) > 0


def test_logout_with_invalid_token_ok(client):
    r = client.post("/api/v1/logout", headers={"Authorization": "Bearer invalid"})
    assert r.status_code == 200
    assert r.json()["detail"] == "登出成功"


def test_root_endpoint(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "message" in r.json()


def test_authenticate_user_paths(client, db_session):
    try:
        from auth.services import auth_service as svc
        from auth.models.user import User
    except ImportError:
        from backend.auth.services import auth_service as svc
        from backend.auth.models.user import User
    phone = "18000000020"
    password = "pw123456789"
    client.post("/api/v1/register", json={"phone_number": phone, "password": password})
    u = db_session.query(User).filter(User.phone_number == phone).first()
    assert svc.authenticate_user(db_session, "nonexistent", "any") is None
    u.account_locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
    db_session.commit()
    assert svc.authenticate_user(db_session, phone, password) is None
    u.account_locked_until = None
    db_session.commit()
    assert svc.authenticate_user(db_session, phone, "wrong") is None
    assert svc.authenticate_user(db_session, phone, password) is not None


def test_revoke_refresh_token_all_branch(client, db_session):
    try:
        from auth.services import auth_service as svc
        from auth.models.user import User
    except ImportError:
        from backend.auth.services import auth_service as svc
        from backend.auth.models.user import User
    phone = "18000000021"
    password = "password_18000000021"
    client.post("/api/v1/register", json={"phone_number": phone, "password": password})
    u = db_session.query(User).filter(User.phone_number == phone).first()
    svc.revoke_refresh_token(db_session, u)


def test_get_current_user_invalid_sub(db_session):
    try:
        from auth.core.security import create_access_token
        from auth.services.auth_service import get_current_user
    except ImportError:
        from backend.auth.core.security import create_access_token
        from backend.auth.services.auth_service import get_current_user
    token = create_access_token({"sub": "abc", "role": "user"})
    import pytest
    with pytest.raises(Exception):
        list(get_current_user.__wrapped__(token=token, db=db_session))


def test_database_utc_datetime_behaviors():
    try:
        from auth.database import UTCDateTime
    except ImportError:
        from backend.auth.database import UTCDateTime
    td = UTCDateTime()
    naive = datetime.utcnow().replace(tzinfo=None)
    aware = datetime.now(timezone.utc)
    b1 = td.process_bind_param(naive, None)
    b2 = td.process_bind_param(aware, None)
    assert b1.tzinfo is None and b2.tzinfo is timezone.utc
    r1 = td.process_result_value(naive, None)
    r2 = td.process_result_value(aware, None)
    assert r1.tzinfo == timezone.utc and r2.tzinfo == timezone.utc


def test_get_db_generator(monkeypatch):
    try:
        import auth.database as database
    except ImportError:
        import backend.auth.database as database
    class Stub:
        def __init__(self):
            self.closed = False
        def close(self):
            self.closed = True
    monkeypatch.setattr(database, "SessionLocal", lambda: Stub())
    gen = database.get_db()
    db = next(gen)
    assert isinstance(db, Stub)
    try:
        next(gen)
    except StopIteration:
        pass
    assert db.closed is True


def test_init_db_success(monkeypatch):
    try:
        import auth.database as database
    except ImportError:
        import backend.auth.database as database
    called = {"v": False}
    def fake_create_all(**kwargs):
        called["v"] = True
    monkeypatch.setattr(database.Base.metadata, "create_all", fake_create_all)
    database.init_db()
    assert called["v"] is True


def test_init_db_failure(monkeypatch):
    try:
        import auth.database as database
    except ImportError:
        import backend.auth.database as database
    def boom(**kwargs):
        raise RuntimeError("boom")
    monkeypatch.setattr(database.Base.metadata, "create_all", boom)
    import pytest
    with pytest.raises(Exception):
        database.init_db()


def test_test_connection_success(monkeypatch):
    try:
        import auth.database as database
    except ImportError:
        import backend.auth.database as database
    class Stub:
        def __init__(self):
            self.closed = False
        def execute(self, q):
            return 1
        def close(self):
            self.closed = True
    monkeypatch.setattr(database, "SessionLocal", lambda: Stub())
    assert database.test_connection() is True


def test_test_connection_failure(monkeypatch):
    try:
        import auth.database as database
    except ImportError:
        import backend.auth.database as database
    class Bad:
        def execute(self, q):
            raise RuntimeError("db fail")
        def close(self):
            pass
    monkeypatch.setattr(database, "SessionLocal", lambda: Bad())
    assert database.test_connection() is False


def test_get_current_user_no_sub(db_session):
    try:
        from auth.core.security import create_access_token
        from auth.services.auth_service import get_current_user
    except ImportError:
        from backend.auth.core.security import create_access_token
        from backend.auth.services.auth_service import get_current_user
    token = create_access_token({"role": "user"})
    import pytest
    with pytest.raises(Exception):
        list(get_current_user.__wrapped__(token=token, db=db_session))


def test_get_current_user_user_not_found(db_session):
    try:
        from auth.core.security import create_access_token
        from auth.services.auth_service import get_current_user
    except ImportError:
        from backend.auth.core.security import create_access_token
        from backend.auth.services.auth_service import get_current_user
    token = create_access_token({"sub": "999999", "role": "user"})
    import pytest
    with pytest.raises(Exception):
        list(get_current_user.__wrapped__(token=token, db=db_session))


def test_revoke_refresh_token_value_error_and_success(client, db_session):
    try:
        from auth.services import auth_service as svc
        from auth.models.user import User, RefreshToken
    except ImportError:
        from backend.auth.services import auth_service as svc
        from backend.auth.models.user import User, RefreshToken
    phone = "18000000022"
    password = "password_18000000022"
    client.post("/api/v1/register", json={"phone_number": phone, "password": password})
    u = db_session.query(User).filter(User.phone_number == phone).first()
    svc.revoke_refresh_token(db_session, u, refresh_token="badformat")
    login = client.post("/api/v1/login", data={"username": phone, "password": password})
    rt = login.json()["refresh_token"]
    u = db_session.query(User).filter(User.phone_number == phone).first()
    svc.revoke_refresh_token(db_session, u, refresh_token=rt)
    token_id = rt.split(".")[0]
    rec = db_session.query(RefreshToken).filter(RefreshToken.user_id == u.id, RefreshToken.token_id == token_id).first()
    assert rec is not None and rec.revoked is True


def test_user_login_logs_status_filter(client, db_session):
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "18000000030", "password": "password_18000000030"})
    client.post("/api/v1/register", json={"phone_number": "18000000031", "password": "password_18000000031"})
    admin_user = db_session.query(User).filter(User.phone_number == "18000000030").first()
    admin_user.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "18000000030", "password": "password_18000000030"}).json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}
    client.post("/api/v1/login", data={"username": "18000000031", "password": "password_18000000031"})
    client.post("/api/v1/login", data={"username": "18000000031", "password": "wrong"})
    r = client.get("/api/v1/admin/users/2/login-logs", params={"status": "failed"}, headers=headers)
    assert r.status_code == 200
    assert len(r.json()["items"]) >= 1


def test_all_login_logs_status_filter(client, db_session):
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "18000000032", "password": "password_18000000032"})
    client.post("/api/v1/register", json={"phone_number": "18000000033", "password": "password_18000000033"})
    admin_user = db_session.query(User).filter(User.phone_number == "18000000032").first()
    admin_user.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "18000000032", "password": "password_18000000032"}).json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}
    client.post("/api/v1/login", data={"username": "18000000033", "password": "password_18000000033"})
    client.post("/api/v1/login", data={"username": "18000000033", "password": "wrong"})
    r = client.get("/api/v1/admin/login-logs", params={"status": "failed"}, headers=headers)
    assert r.status_code == 200
    assert len(r.json()["items"]) >= 1


def test_user_login_logs_nonexistent_user(client, db_session):
    try:
        from auth.models.user import User, UserRole
    except ImportError:
        from backend.auth.models.user import User, UserRole
    client.post("/api/v1/register", json={"phone_number": "18000000034", "password": "password_18000000034"})
    admin_user = db_session.query(User).filter(User.phone_number == "18000000034").first()
    admin_user.role = UserRole.ADMIN
    db_session.commit()
    admin_token = client.post("/api/v1/login", data={"username": "18000000034", "password": "password_18000000034"}).json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}
    r = client.get("/api/v1/admin/users/9999/login-logs", headers=headers)
    assert r.status_code == 404
    assert r.json()["detail"] == "用户不存在"


def test_database_env_missing_raises(monkeypatch):
    try:
        import auth.database as database
    except ImportError:
        import backend.auth.database as database
    import importlib, pytest
    monkeypatch.setenv("DATABASE_URL", "")
    with pytest.raises(ValueError):
        importlib.reload(database)


def test_main_create_tables_error(monkeypatch):
    try:
        import backend.main as main_mod
        from backend.auth.database import Base as B
    except ImportError:
        import main as main_mod
        from auth.database import Base as B
    import importlib
    def boom(*args, **kwargs):
        raise RuntimeError("boom")
    monkeypatch.setattr(B.metadata, "create_all", boom)
    importlib.reload(main_mod)


def test_get_current_user_no_sub_via_router(client):
    try:
        from auth.core.security import create_access_token
    except ImportError:
        from backend.auth.core.security import create_access_token
    token = create_access_token({"role": "user"})
    headers = {"Authorization": f"Bearer {token}"}
    r = client.get("/api/v1/users/me", headers=headers)
    assert r.status_code == 401
    assert r.json()["detail"] == "无法验证凭据"


def test_get_current_user_user_not_found_via_router(client):
    try:
        from auth.core.security import create_access_token
    except ImportError:
        from backend.auth.core.security import create_access_token
    token = create_access_token({"sub": "999999", "role": "user"})
    headers = {"Authorization": f"Bearer {token}"}
    r = client.get("/api/v1/users/me", headers=headers)
    assert r.status_code == 401
    assert r.json()["detail"] == "无法验证凭据"