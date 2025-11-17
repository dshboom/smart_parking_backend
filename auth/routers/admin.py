# routers/admin.py
from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta, timezone
from ..models import user as user_model
from ..services.auth_service import get_current_user
from ..schemas import schemas
from ..database import get_db
from ..core.enums import UserRole, LoginStatus, OperationType, UserStatus
from sqlalchemy import desc, func, and_

router = APIRouter(
    prefix="/admin",
    tags=["Admin"],
    responses={404: {"description": "Not found"}},
)

def require_admin(current_user: user_model.User = Depends(get_current_user)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return current_user

@router.get("/users", response_model=schemas.UserListResponse)
def get_users(
    skip: int = Query(0, ge=0, description="跳过的记录数"),
    limit: int = Query(10, ge=1, le=100, description="每页记录数"),
    search: Optional[str] = Query(None, description="搜索关键词（手机号、邮箱、用户名）"),
    status: Optional[UserStatus] = Query(None, description="用户状态"),
    role: Optional[UserRole] = Query(None, description="用户角色"),
    db: Session = Depends(get_db),
    current_user: user_model.User = Depends(require_admin)
):
    query = db.query(user_model.User)
    
    if search:
        query = query.filter(
            (user_model.User.phone_number.contains(search)) |
            (user_model.User.email.contains(search)) |
            (user_model.User.username.contains(search))
        )
    
    if status:
        query = query.filter(user_model.User.status == status)
    
    if role:
        query = query.filter(user_model.User.role == role)
    
    total = query.count()
    users = query.order_by(desc(user_model.User.created_at)).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "items": users,
        "skip": skip,
        "limit": limit
    }

@router.get("/users/{user_id}", response_model=schemas.UserReadWithLogs)
def get_user_detail(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: user_model.User = Depends(require_admin)
):
    user = db.query(user_model.User).filter(user_model.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    return user

@router.put("/users/{user_id}/status")
def update_user_status(
    user_id: int,
    status: UserStatus,
    db: Session = Depends(get_db),
    current_user: user_model.User = Depends(require_admin)
):
    user = db.query(user_model.User).filter(user_model.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    user.status = status
    db.commit()
    
    operation_log = user_model.UserOperationLog(
        user_id=current_user.id,
        operation_type=OperationType.UPDATE,
        operation_module="用户管理",
        operation_desc=f"修改用户 {user.phone_number} 状态为 {status.value}",
        operation_ip="admin_panel",
    )
    db.add(operation_log)
    db.commit()
    
    return {"message": "用户状态更新成功"}

@router.get("/users/{user_id}/login-logs", response_model=schemas.LoginLogListResponse)
def get_user_login_logs(
    user_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    status: Optional[LoginStatus] = Query(None, description="登录状态"),
    start_date: Optional[datetime] = Query(None, description="开始日期"),
    end_date: Optional[datetime] = Query(None, description="结束日期"),
    db: Session = Depends(get_db),
    current_user: user_model.User = Depends(require_admin)
):
    user = db.query(user_model.User).filter(user_model.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    query = db.query(user_model.UserLoginLog).filter(user_model.UserLoginLog.user_id == user_id)
    
    if status:
        query = query.filter(user_model.UserLoginLog.status == status)
    
    if start_date:
        query = query.filter(user_model.UserLoginLog.login_time >= start_date)
    
    if end_date:
        query = query.filter(user_model.UserLoginLog.login_time <= end_date)
    
    total = query.count()
    logs = query.order_by(desc(user_model.UserLoginLog.login_time)).offset(skip).limit(limit).all()
    
    log_dicts = []
    for log in logs:
        log_dict = {
            "id": log.id,
            "user_id": log.user_id,
            "login_time": log.login_time,
            "login_ip": log.login_ip,
            "status": log.status,
            "user_agent": log.user_agent,
            "failure_reason": log.failure_reason
        }
        log_dicts.append(log_dict)
    
    return {
        "total": total,
        "items": log_dicts,
        "skip": skip,
        "limit": limit
    }

@router.get("/login-logs", response_model=schemas.LoginLogListResponse)
def get_all_login_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    status: Optional[LoginStatus] = Query(None, description="登录状态"),
    start_date: Optional[datetime] = Query(None, description="开始日期"),
    end_date: Optional[datetime] = Query(None, description="结束日期"),
    db: Session = Depends(get_db),
    current_user: user_model.User = Depends(require_admin)
):
    query = db.query(user_model.UserLoginLog, user_model.User.phone_number, user_model.User.username).join(
        user_model.User, user_model.UserLoginLog.user_id == user_model.User.id
    )
    
    if status:
        query = query.filter(user_model.UserLoginLog.status == status)
    
    if start_date:
        query = query.filter(user_model.UserLoginLog.login_time >= start_date)
    
    if end_date:
        query = query.filter(user_model.UserLoginLog.login_time <= end_date)
    
    total = query.count()
    results = query.order_by(desc(user_model.UserLoginLog.login_time)).offset(skip).limit(limit).all()
    
    logs = []
    for log, phone, username in results:
        log_dict = {
            "id": log.id,
            "user_id": log.user_id,
            "login_time": log.login_time,
            "login_ip": log.login_ip,
            "status": log.status,
            "user_agent": log.user_agent,
            "failure_reason": log.failure_reason,
            "phone_number": phone,
            "username": username
        }
        logs.append(log_dict)
    
    return {
        "total": total,
        "items": logs,
        "skip": skip,
        "limit": limit
    }

@router.patch("/users/{user_id}", response_model=schemas.UserRead)
def admin_update_user(
    user_id: int,
    payload: dict = Body(...),
    db: Session = Depends(get_db),
    current_user: user_model.User = Depends(require_admin)
):
    u = db.query(user_model.User).filter(user_model.User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="用户不存在")
    nickname = payload.get("nickname")
    email = payload.get("email")
    username = payload.get("username")
    role = payload.get("role")
    status_value = payload.get("status")
    new_password = payload.get("new_password")
    locked = payload.get("locked")
    if email:
        exists = db.query(user_model.User).filter(user_model.User.email == email, user_model.User.id != u.id).first()
        if exists:
            raise HTTPException(status_code=400, detail="邮箱已被占用")
        u.email = email
    if username:
        exists = db.query(user_model.User).filter(user_model.User.username == username, user_model.User.id != u.id).first()
        if exists:
            raise HTTPException(status_code=400, detail="用户名已被占用")
        u.username = username
    if nickname is not None:
        u.nickname = nickname
    if role:
        try:
            u.role = UserRole(role)
        except Exception:
            raise HTTPException(status_code=400, detail="角色无效")
    if status_value:
        try:
            u.status = UserStatus(status_value)
        except Exception:
            raise HTTPException(status_code=400, detail="状态无效")
    if isinstance(locked, bool):
        if locked:
            u.account_locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
        else:
            u.account_locked_until = None
    if new_password:
        from ..core.security import get_password_hash
        u.password_hash = get_password_hash(new_password)
    db.commit()
    db.refresh(u)
    op = user_model.UserOperationLog(
        user_id=current_user.id,
        operation_type=OperationType.UPDATE,
        operation_module="用户管理",
        operation_desc=f"管理员更新用户 {u.id}",
        operation_ip="admin_panel",
    )
    db.add(op)
    db.commit()
    return u

@router.get("/operation-logs", response_model=schemas.OperationLogListResponse)
def get_operation_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    operation_type: Optional[OperationType] = Query(None, description="操作类型"),
    operation_module: Optional[str] = Query(None, description="操作模块"),
    user_id: Optional[int] = Query(None, description="用户ID"),
    start_date: Optional[datetime] = Query(None, description="开始日期"),
    end_date: Optional[datetime] = Query(None, description="结束日期"),
    db: Session = Depends(get_db),
    current_user: user_model.User = Depends(require_admin)
):
    query = db.query(user_model.UserOperationLog, user_model.User.phone_number, user_model.User.username).join(
        user_model.User, user_model.UserOperationLog.user_id == user_model.User.id
    )
    
    if operation_type:
        query = query.filter(user_model.UserOperationLog.operation_type == operation_type)
    
    if operation_module:
        query = query.filter(user_model.UserOperationLog.operation_module.contains(operation_module))
    
    if user_id:
        query = query.filter(user_model.UserOperationLog.user_id == user_id)
    
    if start_date:
        query = query.filter(user_model.UserOperationLog.operation_time >= start_date)
    
    if end_date:
        query = query.filter(user_model.UserOperationLog.operation_time <= end_date)
    
    total = query.count()
    results = query.order_by(desc(user_model.UserOperationLog.operation_time)).offset(skip).limit(limit).all()
    
    logs = []
    for log, phone, username in results:
        log_dict = {
            "id": log.id,
            "user_id": log.user_id,
            "operation_type": log.operation_type,
            "operation_module": log.operation_module,
            "operation_desc": log.operation_desc,
            "operation_ip": log.operation_ip,
            "operation_time": log.operation_time,
            "execution_time": log.execution_time,
            "phone_number": phone,
            "username": username
        }
        logs.append(log_dict)
    
    return {
        "total": total,
        "items": logs,
        "skip": skip,
        "limit": limit
    }

@router.get("/dashboard/stats", response_model=schemas.DashboardStats)
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: user_model.User = Depends(require_admin)
):
    total_users = db.query(user_model.User).count()
    active_users = db.query(user_model.User).filter(user_model.User.status == UserStatus.ACTIVE).count()
    today_login_attempts = db.query(user_model.UserLoginLog).filter(
        func.date(user_model.UserLoginLog.login_time) == func.current_date()
    ).count()
    today_failed_logins = db.query(user_model.UserLoginLog).filter(
        and_(
            func.date(user_model.UserLoginLog.login_time) == func.current_date(),
            user_model.UserLoginLog.status == LoginStatus.FAILED
        )
    ).count()
    
    recent_operations = db.query(user_model.UserOperationLog).order_by(
        desc(user_model.UserOperationLog.operation_time)
    ).limit(5).all()
    
    return {
        "total_users": total_users,
        "active_users": active_users,
        "today_login_attempts": today_login_attempts,
        "today_failed_logins": today_failed_logins,
        "recent_operations": recent_operations
    }