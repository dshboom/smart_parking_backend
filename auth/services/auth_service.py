# services/auth_service.py
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from typing import Optional
from ..models import user as user_model
from ..schemas import schemas
from ..core.security import get_password_hash, verify_password, create_access_token
from ..core.enums import LoginStatus, VerificationCodeType
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status
from jose import JWTError, jwt
from ..core import security
from ..database import get_db
import secrets

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")

def get_user_by_phone(db: Session, phone_number: str) -> Optional[user_model.User]:
    return db.query(user_model.User).filter(user_model.User.phone_number == phone_number).first()

def get_user_by_email(db: Session, email: str) -> Optional[user_model.User]:
    return db.query(user_model.User).filter(user_model.User.email == email).first()

def get_user_by_username(db: Session, username: str) -> Optional[user_model.User]:
    return db.query(user_model.User).filter(
        (user_model.User.username == username) |
        (user_model.User.email == username) |
        (user_model.User.phone_number == username)
    ).first()

def create_user(db: Session, user: schemas.UserCreate) -> user_model.User:
    hashed_password = get_password_hash(user.password)
    db_user = user_model.User(
        phone_number=user.phone_number,
        email=user.email,
        username=user.username,
        nickname=user.nickname,
        password_hash=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, username: str, password: str) -> Optional[user_model.User]:
    user = get_user_by_username(db, username)
    if not user:
        return None
    if user.account_locked_until and datetime.now(timezone.utc) < user.account_locked_until:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user

def handle_successful_login(db: Session, user: user_model.User, client_ip: str):
    user.login_attempts = 0
    user.last_login_at = datetime.now(timezone.utc)
    user.last_login_ip = client_ip
    user.account_locked_until = None
    db.commit()

def handle_failed_login(db: Session, user: user_model.User):
    user.login_attempts += 1
    if user.login_attempts >= 5:
        user.account_locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
    db.commit()

def create_login_log(
    db: Session, user_id: int, ip: str, user_agent: str, status: LoginStatus, reason: Optional[str] = None
):
    log_entry = user_model.UserLoginLog(
        user_id=user_id,
        login_ip=ip,
        user_agent=user_agent,
        status=status,
        failure_reason=reason
    )
    db.add(log_entry)
    db.commit()

def create_refresh_token(db: Session, user: user_model.User, user_agent: str, ip: str) -> str:
    token_id = secrets.token_hex(16)
    token_secret = secrets.token_urlsafe(32)
    secret_hash = security.pwd_context.hash(token_secret)
    expires = datetime.now(timezone.utc) + timedelta(days=7)
    rt = user_model.RefreshToken(
        user_id=user.id,
        token_id=token_id,
        secret_hash=secret_hash,
        user_agent=user_agent,
        ip=ip,
        expires_at=expires,
        revoked=False,
    )
    db.add(rt)
    db.commit()
    db.refresh(rt)
    return f"{token_id}.{token_secret}"

def update_user_profile(db: Session, user: user_model.User, update: schemas.UserUpdate) -> user_model.User:
    if update.email:
        exists = db.query(user_model.User).filter(user_model.User.email == update.email, user_model.User.id != user.id).first()
        if exists:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="邮箱已被占用")
        user.email = update.email
    if update.username:
        exists = db.query(user_model.User).filter(user_model.User.username == update.username, user_model.User.id != user.id).first()
        if exists:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="用户名已被占用")
        user.username = update.username
    if update.nickname is not None:
        user.nickname = update.nickname
    if update.phone_verified is not None:
        user.phone_verified = update.phone_verified
    if update.email_verified is not None:
        user.email_verified = update.email_verified
    db.commit()
    db.refresh(user)
    return user

def change_password(db: Session, user: user_model.User, current_password: str, new_password: str):
    if not verify_password(current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前密码不正确")
    user.password_hash = get_password_hash(new_password)
    user.login_attempts = 0
    db.commit()

def create_verification_code(db: Session, user: user_model.User, code_type: VerificationCodeType, expires_minutes: int = 10) -> str:
    code = str(secrets.randbelow(1000000)).zfill(6)
    db.query(user_model.VerificationCode).filter(
        user_model.VerificationCode.user_id == user.id,
        user_model.VerificationCode.code_type == code_type
    ).delete()
    code_hash = security.pwd_context.hash(code)
    expires = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    vc = user_model.VerificationCode(user_id=user.id, code_type=code_type, code_hash=code_hash, expires_at=expires)
    db.add(vc)
    db.commit()
    return code

def forgot_password(db: Session, identifier: str) -> str:
    user = get_user_by_username(db, identifier)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="用户不存在")
    token = secrets.token_urlsafe(24)
    user.password_reset_token = token
    user.password_reset_expires = datetime.now(timezone.utc) + timedelta(minutes=15)
    db.commit()
    create_verification_code(db, user, VerificationCodeType.PASSWORD_RESET, 10)
    return token

def reset_password(db: Session, token: str, code: str, new_password: str):
    user = db.query(user_model.User).filter(user_model.User.password_reset_token == token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="重置令牌无效")
    if not user.password_reset_expires or user.password_reset_expires <= datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="重置令牌已过期")
    vc = db.query(user_model.VerificationCode).filter(
        user_model.VerificationCode.user_id == user.id,
        user_model.VerificationCode.code_type == VerificationCodeType.PASSWORD_RESET,
        user_model.VerificationCode.expires_at >= datetime.now(timezone.utc)
    ).order_by(user_model.VerificationCode.created_at.desc()).first()
    if not vc or not security.pwd_context.verify(code, vc.code_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="验证码错误")
    user.password_hash = get_password_hash(new_password)
    user.password_reset_token = None
    user.password_reset_expires = None
    db.query(user_model.VerificationCode).filter(
        user_model.VerificationCode.user_id == user.id,
        user_model.VerificationCode.code_type == VerificationCodeType.PASSWORD_RESET
    ).delete()
    db.commit()

def send_verification_code(db: Session, user: user_model.User, channel: str):
    if channel == "email":
        if not user.email:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="邮箱未设置")
        create_verification_code(db, user, VerificationCodeType.EMAIL_VERIFICATION, 10)
    elif channel == "phone":
        create_verification_code(db, user, VerificationCodeType.PHONE_VERIFICATION, 10)
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="无效的验证码类型")

def verify_email(db: Session, user: user_model.User, code: str):
    vc = db.query(user_model.VerificationCode).filter(
        user_model.VerificationCode.user_id == user.id,
        user_model.VerificationCode.code_type == VerificationCodeType.EMAIL_VERIFICATION,
        user_model.VerificationCode.expires_at >= datetime.now(timezone.utc)
    ).order_by(user_model.VerificationCode.created_at.desc()).first()
    if not vc or not security.pwd_context.verify(code, vc.code_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="验证码错误")
    user.email_verified = True
    db.query(user_model.VerificationCode).filter(
        user_model.VerificationCode.user_id == user.id,
        user_model.VerificationCode.code_type == VerificationCodeType.EMAIL_VERIFICATION
    ).delete()
    db.commit()

def refresh_tokens(db: Session, refresh_token: str) -> dict:
    try:
        token_id, token_secret = refresh_token.split('.', 1)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="刷新令牌格式错误")
    rt = db.query(user_model.RefreshToken).filter(user_model.RefreshToken.token_id == token_id).first()
    if not rt or rt.revoked or rt.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="刷新令牌无效或已过期")
    if not security.pwd_context.verify(token_secret, rt.secret_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="刷新令牌验证失败")
    user = db.query(user_model.User).filter(user_model.User.id == rt.user_id).first()
    if not user or user.status != user_model.UserStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="用户不可用")
    token_data = {"sub": str(user.id), "role": user.role.value}
    access_token = create_access_token(data=token_data)
    new_secret = secrets.token_urlsafe(32)
    rt.secret_hash = security.pwd_context.hash(new_secret)
    rt.expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    db.commit()
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": f"{rt.token_id}.{new_secret}"}

def revoke_refresh_token(db: Session, user: user_model.User, refresh_token: Optional[str] = None):
    if refresh_token:
        try:
            token_id, _ = refresh_token.split('.', 1)
        except ValueError:
            return
        rt = db.query(user_model.RefreshToken).filter(
            user_model.RefreshToken.user_id == user.id,
            user_model.RefreshToken.token_id == token_id
        ).first()
        if rt:
            rt.revoked = True
            db.commit()
    else:
        db.query(user_model.RefreshToken).filter(
            user_model.RefreshToken.user_id == user.id
        ).update({user_model.RefreshToken.revoked: True})
        db.commit()
    
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> user_model.User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, security.settings.SECRET_KEY, algorithms=[security.settings.ALGORITHM]
        )
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
        user_id = int(user_id_str)
    except (JWTError, ValueError):
        raise credentials_exception
    user = db.query(user_model.User).filter(user_model.User.id == user_id).first()
    if user is None:
        raise credentials_exception
    if user.status != user_model.UserStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="用户已被禁用")
    return user