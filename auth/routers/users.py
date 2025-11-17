# routers/users.py
from fastapi import APIRouter, Depends, HTTPException, status
from ..schemas import schemas
from ..models import user as user_model
from ..services.auth_service import get_current_user, update_user_profile, change_password
from ..database import get_db
from sqlalchemy.orm import Session
from parking.models import ParkingRecord, Vehicle
from sqlalchemy import func

router = APIRouter(
    prefix="/users",
    tags=["Users"],
    responses={404: {"description": "Not found"}},
)

@router.get("/me", response_model=schemas.UserRead)
def read_users_me(current_user: user_model.User = Depends(get_current_user)):
    return current_user

@router.patch("/me", response_model=schemas.UserRead)
def update_me(update: schemas.UserUpdate, db: Session = Depends(get_db), current_user: user_model.User = Depends(get_current_user)):
    user = update_user_profile(db, current_user, update)
    return user

@router.post("/me/change-password")
def change_my_password(payload: schemas.PasswordChange, db: Session = Depends(get_db), current_user: user_model.User = Depends(get_current_user)):
    change_password(db, current_user, payload.current_password, payload.new_password)
    return {"detail": "密码修改成功"}

@router.get("/me/stats")
def get_my_stats(db: Session = Depends(get_db), current_user: user_model.User = Depends(get_current_user)):
    q = db.query(ParkingRecord).join(Vehicle, Vehicle.id == ParkingRecord.vehicle_id).filter(Vehicle.user_id == current_user.id)
    total_parkings = q.count()
    records = q.all()
    total_hours = 0.0
    total_amount = 0.0
    for r in records:
        if r.entry_time and r.exit_time:
            dt = (r.exit_time - r.entry_time).total_seconds() / 3600.0
            if dt > 0:
                total_hours += dt
        if r.fee is not None:
            try:
                total_amount += float(r.fee)
            except Exception:
                pass
    return {"totalParkings": int(total_parkings), "totalHours": round(total_hours, 2), "totalAmount": round(total_amount, 2)}