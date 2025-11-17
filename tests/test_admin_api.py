# tests/test_admin_api.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from datetime import datetime, timedelta
try:
    from auth.core.enums import UserRole, UserStatus, LoginStatus, OperationType
except ImportError:
    from backend.auth.core.enums import UserRole, UserStatus, LoginStatus, OperationType

def create_admin_user(client, db_session):
    """创建管理员用户用于测试"""
    # 首先注册一个普通用户
    response = client.post(
        "/api/v1/register",
        json={
            "phone_number": "13800138000",
            "email": "admin@example.com",
            "username": "admin",
            "password": "admin_password",
            "nickname": "管理员"
        }
    )
    assert response.status_code == 201
    
    # 修改用户角色为管理员
    try:
        from auth.models.user import User
    except ImportError:
        from backend.auth.models.user import User
    user = db_session.query(User).filter(User.phone_number == "13800138000").first()
    user.role = UserRole.ADMIN
    db_session.commit()
    
    return user

def create_normal_user(client):
    """创建普通用户用于测试"""
    response = client.post(
        "/api/v1/register",
        json={
            "phone_number": "13900139000",
            "email": "user@example.com",
            "username": "normaluser",
            "password": "user_password",
            "nickname": "普通用户"
        }
    )
    assert response.status_code == 201
    return response.json()

def login_as_admin(client):
    """以管理员身份登录"""
    response = client.post(
        "/api/v1/login",
        data={"username": "13800138000", "password": "admin_password"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]

def login_as_normal_user(client):
    """以普通用户身份登录"""
    response = client.post(
        "/api/v1/login",
        data={"username": "13900139000", "password": "user_password"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]

def test_admin_access_requires_admin_role(client, db_session):
    """测试管理员接口需要管理员权限"""
    # 创建普通用户并登录
    create_normal_user(client)
    user_token = login_as_normal_user(client)
    
    # 尝试以普通用户访问管理接口
    headers = {"Authorization": f"Bearer {user_token}"}
    response = client.get("/api/v1/admin/users", headers=headers)
    
    assert response.status_code == 403
    assert response.json()["detail"] == "需要管理员权限"

def test_get_users_list_as_admin(client, db_session):
    """测试管理员获取用户列表"""
    # 创建管理员用户
    create_admin_user(client, db_session)
    # 创建一些普通用户
    create_normal_user(client)
    
    # 管理员登录
    admin_token = login_as_admin(client)
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # 获取用户列表
    response = client.get("/api/v1/admin/users?skip=0&limit=10", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert len(data["items"]) >= 2  # 至少应该有管理员和普通用户
    assert data["skip"] == 0
    assert data["limit"] == 10

def test_get_users_with_search_filter(client, db_session):
    """测试用户列表搜索和筛选功能"""
    create_admin_user(client, db_session)
    create_normal_user(client)
    
    admin_token = login_as_admin(client)
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # 按手机号搜索
    response = client.get("/api/v1/admin/users?search=13800", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 1
    
    # 按状态筛选
    response = client.get("/api/v1/admin/users?status=active", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 1
    
    # 按角色筛选
    response = client.get("/api/v1/admin/users?role=admin", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 1

def test_get_user_detail_as_admin(client, db_session):
    """测试管理员获取用户详情"""
    create_admin_user(client, db_session)
    normal_user = create_normal_user(client)
    
    admin_token = login_as_admin(client)
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # 获取普通用户详情
    user_id = normal_user["id"]
    response = client.get(f"/api/v1/admin/users/{user_id}", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == user_id
    assert data["phone_number"] == "13900139000"
    assert "login_logs" in data

def test_update_user_status_as_admin(client, db_session):
    """测试管理员更新用户状态"""
    create_admin_user(client, db_session)
    normal_user = create_normal_user(client)
    
    admin_token = login_as_admin(client)
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    user_id = normal_user["id"]
    # 更新用户状态
    response = client.put(f"/api/v1/admin/users/{user_id}/status?status=suspended", headers=headers)
    
    assert response.status_code == 200
    assert response.json()["message"] == "用户状态更新成功"
    
    # 验证状态已更新
    response = client.get(f"/api/v1/admin/users/{user_id}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "suspended"

def test_get_user_login_logs_as_admin(client, db_session):
    """测试管理员获取用户登录日志"""
    create_admin_user(client, db_session)
    create_normal_user(client)
    
    # 模拟一些登录操作
    client.post("/api/v1/login", data={"username": "13900139000", "password": "user_password"})
    client.post("/api/v1/login", data={"username": "13900139000", "password": "wrong_password"})
    
    admin_token = login_as_admin(client)
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # 获取用户登录日志
    response = client.get("/api/v1/admin/users/2/login-logs?skip=0&limit=10", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert len(data["items"]) >= 2  # 至少应该有成功和失败的登录记录

def test_get_all_login_logs_as_admin(client, db_session):
    """测试管理员获取所有登录日志"""
    create_admin_user(client, db_session)
    create_normal_user(client)
    
    # 模拟登录操作
    client.post("/api/v1/login", data={"username": "13800138000", "password": "admin_password"})
    client.post("/api/v1/login", data={"username": "13900139000", "password": "user_password"})
    
    admin_token = login_as_admin(client)
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    response = client.get("/api/v1/admin/login-logs?skip=0&limit=10", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert len(data["items"]) >= 2
    # 验证返回的数据包含用户信息
    if len(data["items"]) > 0:
        log = data["items"][0]
        assert "phone_number" in log
        assert "username" in log

def test_get_operation_logs_as_admin(client, db_session):
    """测试管理员获取操作日志"""
    create_admin_user(client, db_session)
    create_normal_user(client)
    
    admin_token = login_as_admin(client)
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # 执行一些管理操作
    client.put("/api/v1/admin/users/2/status?status=suspended", headers=headers)
    
    response = client.get("/api/v1/admin/operation-logs?skip=0&limit=10", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert len(data["items"]) >= 1  # 至少应该有刚才的状态更新操作
    
    # 验证操作日志包含正确信息
    if len(data["items"]) > 0:
        log = data["items"][0]
        assert "operation_type" in log
        assert "operation_module" in log
        assert "operation_desc" in log

def test_get_dashboard_stats_as_admin(client, db_session):
    """测试管理员获取仪表板统计"""
    create_admin_user(client, db_session)
    create_normal_user(client)
    
    # 模拟一些活动
    client.post("/api/v1/login", data={"username": "13900139000", "password": "user_password"})
    client.post("/api/v1/login", data={"username": "13900139000", "password": "wrong_password"})
    
    admin_token = login_as_admin(client)
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    response = client.get("/api/v1/admin/dashboard/stats", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert "total_users" in data
    assert "active_users" in data
    assert "today_login_attempts" in data
    assert "today_failed_logins" in data
    assert "recent_operations" in data
    assert data["total_users"] >= 2  # 至少应该有管理员和普通用户

def test_nonexistent_user_access(client, db_session):
    """测试访问不存在的用户"""
    create_admin_user(client, db_session)
    admin_token = login_as_admin(client)
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # 访问不存在的用户
    response = client.get("/api/v1/admin/users/9999", headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "用户不存在"

def test_operation_logs_filtering(client, db_session):
    """测试操作日志筛选功能"""
    create_admin_user(client, db_session)
    create_normal_user(client)
    
    admin_token = login_as_admin(client)
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # 执行不同类型的操作
    client.put("/api/v1/admin/users/2/status?status=suspended", headers=headers)
    
    # 按操作类型筛选
    response = client.get("/api/v1/admin/operation-logs?operation_type=update", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 1
    
    # 按操作模块筛选
    response = client.get("/api/v1/admin/operation-logs?operation_module=用户管理", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 1
    
    # 按用户ID筛选
    response = client.get("/api/v1/admin/operation-logs?user_id=1", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 1