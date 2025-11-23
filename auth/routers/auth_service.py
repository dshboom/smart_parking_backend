# /routers/auth_service.py slh
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from ..schemas import schemas
from ..models import user
from ..services import auth_service
from decimal import Decimal
from wallet.services import recharge_balance
from auth.core.enums import PaymentMethod
from ..services.auth_service import get_current_user
from ..database import get_db
from ..core.enums import LoginStatus
from datetime import datetime, timezone
from fastapi import Body
from jose import jwt
from ..core import security

router = APIRouter(tags=["Authentication"])

@router.post("/register", response_model=schemas.UserRead, status_code=status.HTTP_201_CREATED)
def register_user(user_create: schemas.UserCreate, db: Session = Depends(get_db)):
    if auth_service.get_user_by_phone(db, user_create.phone_number):
        raise HTTPException(status_code=400, detail="该手机号已被注册")
    if user_create.email and auth_service.get_user_by_email(db, user_create.email):
        raise HTTPException(status_code=400, detail="该邮箱已被注册")
        
    created_user = auth_service.create_user(db, user_create)
    try:
        recharge_balance(db, created_user.id, Decimal("30.00"), PaymentMethod.BALANCE)
        db.commit()
    except Exception:
        db.rollback()
    return created_user

@router.post("/login", response_model=schemas.Token)
def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    
    db_user = auth_service.get_user_by_username(db, form_data.username)

    if db_user and db_user.account_locked_until and datetime.now(timezone.utc) < db_user.account_locked_until:
        auth_service.create_login_log(db, db_user.id, client_ip, user_agent, LoginStatus.LOCKED, "账户被锁定")
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="账户被锁定",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not db_user or not auth_service.authenticate_user(db, form_data.username, form_data.password):
        if db_user:
            auth_service.handle_failed_login(db, db_user)
            auth_service.create_login_log(db, db_user.id, client_ip, user_agent, LoginStatus.FAILED, "密码错误")
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码不正确",
            headers={"WWW-Authenticate": "Bearer"},
        )
    auth_service.handle_successful_login(db, db_user, client_ip)
    auth_service.create_login_log(db, db_user.id, client_ip, user_agent, LoginStatus.SUCCESS)
    token_data = {"sub": str(db_user.id), "role": db_user.role.value}
    access_token = auth_service.create_access_token(data=token_data)
    refresh_token = auth_service.create_refresh_token(db, db_user, user_agent, client_ip)
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}

@router.post("/refresh", response_model=schemas.Token)
def refresh_access_token(
    payload: dict = Body(...),
    db: Session = Depends(get_db)
):
    refresh_token = payload.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="缺少刷新令牌")
    data = auth_service.refresh_tokens(db, refresh_token)
    return data

@router.post("/logout")
def logout(
    request: Request,
    payload: dict = Body(None),
    db: Session = Depends(get_db)
):
    auth_header = request.headers.get("authorization", "")
    token = auth_header.split(" ")[1] if " " in auth_header.lower() else None
    user_obj = None
    if token:
        try:
            payload = jwt.decode(token, security.settings.SECRET_KEY, algorithms=[security.settings.ALGORITHM])
            user_id_str = payload.get("sub")
            if user_id_str:
                user_id = int(user_id_str)
                user_obj = db.query(user.User).filter(user.User.id == user_id).first()
        except Exception:
            user_obj = None
    refresh_token = payload.get("refresh_token") if isinstance(payload, dict) else None
    if user_obj:
        auth_service.revoke_refresh_token(db, user_obj, refresh_token)
    return {"detail": "登出成功"}

@router.post("/auth/forgot-password")
def forgot_password(payload: dict = Body(...), db: Session = Depends(get_db)):
    identifier = payload.get("username") or payload.get("phone") or payload.get("email")
    if not identifier:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="缺少账号标识")
    token = auth_service.forgot_password(db, identifier)
    return {"detail": "验证码已发送", "password_reset_token": token}

@router.post("/auth/reset-password")
def reset_password(payload: dict = Body(...), db: Session = Depends(get_db)):
    token = payload.get("token")
    code = payload.get("code")
    new_password = payload.get("new_password")
    if not token or not code or not new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="缺少必要参数")
    auth_service.reset_password(db, token, code, new_password)
    return {"detail": "密码重置成功"}

@router.post("/auth/send-verification-code")
def send_verification_code(payload: dict = Body(...), db: Session = Depends(get_db), current_user: user.User = Depends(get_current_user)):
    channel = payload.get("channel")
    if channel not in ("email", "phone"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="无效的发送渠道")
    auth_service.send_verification_code(db, current_user, channel)
    return {"detail": "验证码已发送"}

@router.post("/auth/verify-email")
def verify_email(payload: dict = Body(...), db: Session = Depends(get_db), current_user: user.User = Depends(get_current_user)):
    code = payload.get("code")
    if not code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="缺少验证码")
    auth_service.verify_email(db, current_user, code)
    return {"detail": "邮箱已验证"}