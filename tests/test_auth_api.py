# tests/test_auth_api.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 注意：测试客户端发送的数据是 json，而不是 pydantic 模型

def test_register_user_success(client):
    """测试用户成功注册"""
    response = client.post(
        "/api/v1/register",
        json={
            "phone_number": "13800138000",
            "email": "test@example.com",
            "username": "testuser",
            "password": "a_very_strong_password"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["phone_number"] == "13800138000"
    assert "password_hash" not in data # 确保密码哈希没有被返回
    assert "id" in data


def test_register_user_phone_already_exists(client):
    """测试手机号已存在时注册失败"""
    # 先成功注册一个用户
    client.post(
        "/api/v1/register",
        json={"phone_number": "13800138001", "password": "password123"}
    )
    
    # 再次使用相同的手机号注册
    response = client.post(
        "/api/v1/register",
        json={"phone_number": "13800138001", "password": "anotherpassword"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "该手机号已被注册"


def test_login_for_access_token_success(client):
    """测试用户成功登录并获取 token"""
    # 1. 先注册一个用户
    phone = "13900139000"
    password = "mysecretpassword"
    client.post(
        "/api/v1/register",
        json={"phone_number": phone, "password": password, "username": "loginuser"}
    )
    
    # 2. 使用该用户的凭据登录
    # 注意：OAuth2PasswordRequestForm 需要 form data，而不是 json
    response = client.post(
        "/api/v1/login",
        data={"username": phone, "password": password} # 可以用手机号/用户名/邮箱登录
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_incorrect_password(client):
    """测试密码错误时登录失败"""
    phone = "13700137000"
    password = "correct_password"
    client.post(
        "/api/v1/register",
        json={"phone_number": phone, "password": password}
    )
    
    response = client.post(
        "/api/v1/login",
        data={"username": phone, "password": "wrong_password"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "用户名或密码不正确"
    # 确保返回了正确的 WWW-Authenticate 头
    assert "WWW-Authenticate" in response.headers


def test_login_user_not_found(client):
    """测试用户不存在时登录失败"""
    response = client.post(
        "/api/v1/login",
        data={"username": "nonexistentuser", "password": "anypassword"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "用户名或密码不正确"


def test_get_current_user_success(client):
    """测试使用有效的 token 访问受保护的路由"""
    # 1. 注册并登录以获取 token
    phone = "15800158000"
    password = "password_for_protected_route"
    client.post("/api/v1/register", json={"phone_number": phone, "password": password})
    login_response = client.post("/api/v1/login", data={"username": phone, "password": password})
    token = login_response.json()["access_token"]
    
    # 2. 使用 token 访问 /users/me
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/v1/users/me", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["phone_number"] == phone


def test_get_current_user_no_token(client):
    """测试在没有 token 的情况下访问受保护路由"""
    response = client.get("/api/v1/users/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"


def test_get_current_user_invalid_token(client):
    """测试使用无效的 token 访问受保护路由"""
    headers = {"Authorization": "Bearer an_invalid_token"}
    response = client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "无法验证凭据"

def test_refresh_token_flow(client):
    phone = "16600166000"
    password = "refresh_flow_password"
    r = client.post("/api/v1/register", json={"phone_number": phone, "password": password})
    assert r.status_code == 201
    login_response = client.post("/api/v1/login", data={"username": phone, "password": password})
    assert login_response.status_code == 200
    refresh_token = login_response.json().get("refresh_token")
    assert refresh_token is not None
    refresh_response = client.post("/api/v1/refresh", json={"refresh_token": refresh_token})
    assert refresh_response.status_code == 200
    data = refresh_response.json()
    assert "access_token" in data
    assert data.get("refresh_token") is not None

def test_logout_revokes_refresh_token(client):
    phone = "16600166001"
    password = "logout_password"
    client.post("/api/v1/register", json={"phone_number": phone, "password": password})
    login_response = client.post("/api/v1/login", data={"username": phone, "password": password})
    token = login_response.json()["access_token"]
    refresh_token = login_response.json().get("refresh_token")
    assert refresh_token is not None
    headers = {"Authorization": f"Bearer {token}"}
    logout_response = client.post("/api/v1/logout", json={"refresh_token": refresh_token}, headers=headers)
    assert logout_response.status_code == 200
    failed_refresh = client.post("/api/v1/refresh", json={"refresh_token": refresh_token})
    assert failed_refresh.status_code == 401