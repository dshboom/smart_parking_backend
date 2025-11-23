# schemas.py wll
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List
from datetime import datetime
from ..core.enums import UserRole, UserStatus, LoginStatus, OperationType

class UserBase(BaseModel):
    phone_number: str = Field(..., max_length=20, description="手机号")
    email: Optional[EmailStr] = Field(None, max_length=100, description="邮箱")
    username: Optional[str] = Field(None, max_length=50, description="用户名")
    nickname: Optional[str] = Field(None, max_length=50, description="昵称")
    model_config = ConfigDict(from_attributes=True)

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, description="密码 (明文)")

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = Field(None, max_length=100, description="邮箱")
    username: Optional[str] = Field(None, max_length=50, description="用户名")
    nickname: Optional[str] = Field(None, max_length=50, description="昵称")
    phone_verified: Optional[bool] = None
    email_verified: Optional[bool] = None

class UserRead(UserBase):
    id: int
    role: UserRole
    status: UserStatus
    phone_verified: bool
    email_verified: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

class LoginRequest(BaseModel):
    username: str = Field(..., description="手机号/邮箱/用户名")
    password: str = Field(..., description="密码")

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: str | None = None

class TokenData(BaseModel):
    user_id: int
    role: UserRole

class PasswordChange(BaseModel):
    current_password: str = Field(..., description="当前密码")
    new_password: str = Field(..., min_length=8, description="新密码")

class PasswordResetRequest(BaseModel):
    email: EmailStr = Field(..., description="用于接收重置链接的邮箱")

class PasswordReset(BaseModel):
    token: str = Field(..., description="从邮件中获取的密码重置令牌")
    new_password: str = Field(..., min_length=8, description="新密码")


class UserLoginLogRead(BaseModel):
    id: int
    user_id: int
    login_time: datetime
    login_ip: str
    status: LoginStatus
    user_agent: Optional[str] = None
    failure_reason: Optional[str] = None
    phone_number: Optional[str] = None
    username: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class UserOperationLogRead(BaseModel):
    id: int
    user_id: int
    operation_type: OperationType
    operation_module: str
    operation_desc: str
    operation_ip: str
    operation_time: datetime
    execution_time: Optional[float] = None
    phone_number: Optional[str] = None
    username: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
        
class UserReadWithLogs(UserRead):
    login_logs: List[UserLoginLogRead] = []

class PaginatedResponse(BaseModel):
    total: int
    skip: int
    limit: int

class UserListResponse(PaginatedResponse):
    items: List[UserRead]

class LoginLogListResponse(PaginatedResponse):
    items: List[UserLoginLogRead]

class OperationLogListResponse(PaginatedResponse):
    items: List[UserOperationLogRead]

class DashboardStats(BaseModel):
    total_users: int
    active_users: int
    today_login_attempts: int
    today_failed_logins: int
    recent_operations: List[UserOperationLogRead]