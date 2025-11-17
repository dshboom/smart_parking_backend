# main.py
from fastapi import FastAPI
import os
from fastapi.middleware.cors import CORSMiddleware
from auth.database import engine, Base, SessionLocal
from auth.core.config import settings
from auth.models import user as user_model
from auth.core.enums import UserRole
from auth.core.security import get_password_hash
from auth.routers.auth_service import router as auth_router
from auth.routers.users import router as users_router
from auth.routers.admin import router as admin_router
from parking.routers import router as parking_router
from wallet.routers import router as wallet_router

try:
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully.")
except Exception as e:
    print(f"Error creating database tables: {e}")

def ensure_default_admin():
    if not settings.ADMIN_USERNAME or not settings.ADMIN_PASSWORD:
        return
    db = SessionLocal()
    try:
        u = db.query(user_model.User).filter(
            (user_model.User.username == settings.ADMIN_USERNAME) |
            (user_model.User.phone_number == settings.ADMIN_USERNAME) |
            (user_model.User.email == settings.ADMIN_USERNAME)
        ).first()
        if not u:
            hashed = get_password_hash(settings.ADMIN_PASSWORD)
            u = user_model.User(
                phone_number=settings.ADMIN_USERNAME,
                username=settings.ADMIN_USERNAME,
                nickname="管理员",
                password_hash=hashed,
                role=UserRole.ADMIN
            )
            db.add(u)
            db.commit()
            db.refresh(u)
        else:
            u.role = UserRole.ADMIN
            u.password_hash = get_password_hash(settings.ADMIN_PASSWORD)
            u.login_attempts = 0
            u.account_locked_until = None
            db.commit()
    finally:
        db.close()

ensure_default_admin()

app = FastAPI(
    title="停车管理系统 API",
    description="用于管理用户认证、停车位预定等核心功能的 API。",
    version="1.0.0",
    contact={
        "name": "API Support",
        "email": "support@example.com",
    },
)

origins_env = os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173")
allow_origins = [o.strip() for o in origins_env.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api_prefix = "/api/v1"
app.include_router(auth_router, prefix=api_prefix)
app.include_router(users_router, prefix=api_prefix)
app.include_router(admin_router, prefix=api_prefix)
app.include_router(parking_router, prefix=api_prefix)
app.include_router(wallet_router, prefix=api_prefix)


@app.get("/", tags=["Root"])
def read_root():
    return {"message": "欢迎使用停车管理系统 API"}

# 兼容前端实时连接：提供基本 WebSocket 回声端点
from fastapi import WebSocket, WebSocketDisconnect
from jose import jwt
from auth.core.config import settings
from realtime.ws_manager import manager
from auth.database import SessionLocal
from auth.models.user import User
from auth.core.enums import UserRole

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    token = ws.query_params.get("token")
    if not token:
        await ws.close(code=4401)
        return
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        sub = payload.get("sub")
        user_id = int(sub) if sub is not None else None
    except Exception:
        await ws.close(code=4401)
        return
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            await ws.close(code=4401)
            return
    finally:
        db.close()
    await ws.accept()
    await manager.connect(ws, user_id)
    try:
        while True:
            try:
                data = await ws.receive_json()
            except Exception:
                await ws.send_json({"type": "error", "payload": {"code": "bad_message"}})
                continue
            t = data.get("type")
            if t == "subscribe_lot":
                lot_id = data.get("payload", {}).get("lot_id")
                try:
                    lot_id = int(lot_id) if lot_id is not None else None
                except Exception:
                    lot_id = None
                if user.role != UserRole.ADMIN:
                    await ws.send_json({"type": "error", "payload": {"code": "forbidden"}})
                    continue
                await manager.subscribe_lot(ws, lot_id)
            elif t == "unsubscribe_lot":
                lot_id = data.get("payload", {}).get("lot_id")
                try:
                    lot_id = int(lot_id) if lot_id is not None else None
                except Exception:
                    lot_id = None
                await manager.unsubscribe_lot(ws, lot_id)
            else:
                await ws.send_json({"type": "heartbeat", "payload": {"ts": data.get("ts")}})
    except WebSocketDisconnect:
        await manager.disconnect(ws)

# 运行时兼容性修复：确保缺失列被创建
pass
