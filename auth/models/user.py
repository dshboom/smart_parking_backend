# /models/user.py wll
from sqlalchemy import (Column, Integer, String, Boolean,
                        ForeignKey, Enum, Index)
from sqlalchemy.dialects.mysql import TIMESTAMP
from ..database import UTCDateTime
from sqlalchemy.dialects.mysql import JSON
from ..database import Base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from ..core.enums import UserRole, UserStatus, LoginStatus, OperationType, VerificationCodeType
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    phone_number = Column(String(20), unique=True, index=True, nullable=False, comment="手机号")
    email = Column(String(100), unique=True, index=True, nullable=True, comment="邮箱")
    username = Column(String(50), unique=True, index=True, nullable=True, comment="用户名")
    password_hash = Column(String(255), nullable=False, comment="密码哈希 (盐值已包含在内)")
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False, comment="用户角色 (admin/user)")
    status = Column(Enum(UserStatus), default=UserStatus.ACTIVE, nullable=False, comment="用户状态")
    nickname = Column(String(50), nullable=True, comment="昵称")
    password_reset_token = Column(String(255), nullable=True, comment="密码重置令牌")
    password_reset_expires = Column(UTCDateTime, nullable=True, comment="密码重置过期时间")
    phone_verified = Column(Boolean, default=False, nullable=False, comment="手机号是否验证")
    email_verified = Column(Boolean, default=False, nullable=False, comment="邮箱是否验证")
    login_attempts = Column(Integer, default=0, nullable=False, comment="登录失败次数")
    last_login_at = Column(UTCDateTime, nullable=True, comment="最后登录时间")
    last_login_ip = Column(String(45), nullable=True, comment="最后登录IP")
    account_locked_until = Column(UTCDateTime, nullable=True, comment="账户锁定时间")
    created_at = Column(UTCDateTime, default=func.now(), nullable=False, comment="创建时间")
    updated_at = Column(UTCDateTime, default=func.now(), onupdate=func.now(), nullable=False, comment="更新时间")
    deleted_at = Column(UTCDateTime, nullable=True, comment="删除时间 (用于软删除)")
    login_logs = relationship("UserLoginLog", back_populates="user", cascade="all, delete-orphan")
    operation_logs = relationship("UserOperationLog", back_populates="user", cascade="all, delete-orphan")
    verifications = relationship("VerificationCode", back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    __table_args__ = (
        Index('idx_users_phone_status', 'phone_number', 'status'),
        Index('idx_users_email_status', 'email', 'status'),
        Index('idx_users_created_at', 'created_at'),
        Index('idx_users_status_role', 'status', 'role'),
    )

class VerificationCode(Base):
    __tablename__ = "verification_codes"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    code_type = Column(Enum(VerificationCodeType), nullable=False, comment="验证码类型")
    code_hash = Column(String(255), nullable=False, comment="验证码的哈希值，增强安全性")
    expires_at = Column(UTCDateTime, nullable=False, comment="过期时间")
    created_at = Column(UTCDateTime, default=func.now(), nullable=False)
    user = relationship("User", back_populates="verifications")

class UserLoginLog(Base):
    __tablename__ = "user_login_logs"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, comment="用户ID")
    login_time = Column(UTCDateTime, default=func.now(), nullable=False, comment="登录时间")
    login_ip = Column(String(45), nullable=False, comment="登录IP地址")
    status = Column(Enum(LoginStatus), nullable=False, comment="登录状态")
    user_agent = Column(String(500), nullable=True, comment="用户代理")
    failure_reason = Column(String(200), nullable=True, comment="失败原因")
    user = relationship("User", back_populates="login_logs")
    __table_args__ = (
        Index('idx_login_logs_user_time', 'user_id', 'login_time'),
        Index('idx_login_logs_time', 'login_time'),
    )

class UserOperationLog(Base):
    __tablename__ = "user_operation_logs"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, comment="用户ID")
    operation_type = Column(Enum(OperationType), nullable=False, comment="操作类型")
    operation_module = Column(String(100), nullable=False, comment="操作模块")
    operation_desc = Column(String(500), nullable=False, comment="操作描述")
    operation_ip = Column(String(45), nullable=False, comment="操作IP")
    operation_time = Column(UTCDateTime, default=func.now(), nullable=False, comment="操作时间")
    
    request_data = Column(JSON, nullable=True, comment="请求数据(JSON)")
    response_data = Column(JSON, nullable=True, comment="响应数据(JSON)")
    execution_time = Column(Integer, nullable=True, comment="执行时间(毫秒)")
    user = relationship("User", back_populates="operation_logs")
    __table_args__ = (
        Index('idx_operation_logs_user_time', 'user_id', 'operation_time'),
        Index('idx_operation_logs_type_module', 'operation_type', 'operation_module'),
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_id = Column(String(64), unique=True, index=True, nullable=False)
    secret_hash = Column(String(255), nullable=False)
    user_agent = Column(String(500), nullable=True)
    ip = Column(String(45), nullable=True)
    expires_at = Column(UTCDateTime, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(UTCDateTime, default=func.now(), nullable=False)
    updated_at = Column(UTCDateTime, default=func.now(), onupdate=func.now(), nullable=False)
    user = relationship("User", back_populates="refresh_tokens")
    __table_args__ = (
        Index('idx_refresh_tokens_user_expires', 'user_id', 'expires_at'),
    )