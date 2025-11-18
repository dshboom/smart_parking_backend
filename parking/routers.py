from fastapi import APIRouter, Depends, HTTPException, status, Request
import asyncio
from realtime.ws_manager import manager
from sqlalchemy.orm import Session
from sqlalchemy import update
from typing import List
from .models import Vehicle, ParkingLot, BillingRule, ParkingRecord, Payment, Reservation, ParkingLotLayout, ParkingSpace
from .schemas import (
    VehicleCreate, VehicleRead,
    ParkingLotCreate, ParkingLotUpdate, ParkingLotRead,
    BillingRuleCreate, BillingRuleUpdate, BillingRuleRead,
    ParkingRecordCreate, ParkingRecordExitRequest, ParkingRecordRead,
    PaymentCreate, PaymentRead,
    ReservationRead,
    ParkingLotLayoutRead, ParkingLotLayoutUpdate,
    ParkingSpaceRead, ParkingSpaceUpdate,
    OccupySpaceRequest, VacateSpaceRequest, ReserveSpaceRequest,
    NearestSpaceRequest, NearestSpaceResponse,
    NavigateRequest, NavigateResponse,
    ParkingStatsRead, PaginatedParkingRecords,
)
from .services import (
    set_default_vehicle, create_parking_entry, complete_parking_record, create_payment, mark_payment_success, create_vehicle_service, update_parking_lot_service,
    update_layout_and_rebuild_spaces, get_layout,
    occupy_space, vacate_space, reserve_space, unreserve_space,
    find_nearest_available_space, calculate_navigation_path, get_parking_stats,
)
from auth.database import get_db
from auth.services.auth_service import get_current_user
from auth.core.enums import VehicleStatus, UserRole, PaymentType
import os, hmac, hashlib
from auth.core.enums import ReservationStatus, PaymentStatus, SpaceStatus
from datetime import datetime
from wallet.services import settle_with_balance
from parking.services import BillingRuleNotFoundError

router = APIRouter(tags=["Parking"])

def require_admin(current_user=Depends(get_current_user)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="需要管理员权限")
    return current_user

def verify_device_auth_entry(db: Session, lot_id: int, license_plate: str, request: Request):
    api_key = request.headers.get("X-API-KEY")
    ts = request.headers.get("X-TIMESTAMP")
    sig = request.headers.get("X-SIGNATURE")
    if not api_key or not ts or not sig:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少设备认证")
    lot = db.query(ParkingLot).filter(ParkingLot.id == lot_id).first()
    if not lot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="停车场不存在")
    if not lot.api_key or not lot.api_secret or api_key != lot.api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="设备认证失败")
    base = f"{license_plate}|{lot_id}|{ts}"
    expected = hmac.new(lot.api_secret.encode(), base.encode(), hashlib.sha256).hexdigest()
    if sig != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="设备签名错误")

def verify_device_auth_exit(db: Session, record_id: int, request: Request):
    api_key = request.headers.get("X-API-KEY")
    ts = request.headers.get("X-TIMESTAMP")
    sig = request.headers.get("X-SIGNATURE")
    if not api_key or not ts or not sig:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少设备认证")
    record = db.query(ParkingRecord).filter(ParkingRecord.id == record_id).first()
    if not record:
        return
    lot = db.query(ParkingLot).filter(ParkingLot.id == record.parking_lot_id).first()
    if not lot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="停车场不存在")
    if not lot.api_key or not lot.api_secret or api_key != lot.api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="设备认证失败")
    base = f"{record_id}|{record.parking_lot_id}|{ts}"
    expected = hmac.new(lot.api_secret.encode(), base.encode(), hashlib.sha256).hexdigest()
    if sig != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="设备签名错误")

@router.post("/vehicles", response_model=VehicleRead)
def create_vehicle(request: VehicleCreate, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    try:
        v = create_vehicle_service(db, current_user.id, request.license_plate, request.is_default)
        if not v:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="车牌号已绑定")
        db.commit()
        db.refresh(v)
        return v
    except HTTPException as e:
        raise e
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.get("/vehicles/me", response_model=List[VehicleRead])
def list_my_vehicles(skip: int = 0, limit: int = 20, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    return db.query(Vehicle).filter(Vehicle.user_id == current_user.id, Vehicle.status == VehicleStatus.ACTIVE).offset(skip).limit(limit).all()

@router.put("/vehicles/{vehicle_id}/default", response_model=VehicleRead)
def set_default(vehicle_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    try:
        v = set_default_vehicle(db, current_user.id, vehicle_id)
        if not v:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="车辆不存在")
        db.commit()
        db.refresh(v)
        return v
    except HTTPException as e:
        raise e
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.delete("/vehicles/{vehicle_id}", status_code=204)
def delete_vehicle(vehicle_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    try:
        v = db.query(Vehicle).filter(Vehicle.id == vehicle_id, Vehicle.user_id == current_user.id).first()
        if not v:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="车辆不存在")
        v.status = VehicleStatus.DELETED
        db.commit()
        return
    except HTTPException as e:
        raise e
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.post("/parking-lots", response_model=ParkingLotRead)
def create_parking_lot(request: ParkingLotCreate, db: Session = Depends(get_db), current_admin=Depends(require_admin)):
    try:
        exists = db.query(ParkingLot).filter(ParkingLot.name == request.name).first()
        if exists:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="停车场名称已存在")
        lot = ParkingLot(
            name=request.name,
            address=request.address,
            total_capacity=request.total_capacity,
            available_spots=request.available_spots,
            api_key=request.api_key,
            api_secret=request.api_secret,
            status=request.status,
        )
        db.add(lot)
        db.commit()
        db.refresh(lot)
        return lot
    except HTTPException as e:
        raise e
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.get("/parking-lots", response_model=List[ParkingLotRead])
def list_parking_lots(skip: int = 0, limit: int = 20, db: Session = Depends(get_db)):
    return db.query(ParkingLot).offset(skip).limit(limit).all()

@router.get("/parking-lots/{lot_id}", response_model=ParkingLotRead)
def get_parking_lot(lot_id: int, db: Session = Depends(get_db)):
    lot = db.query(ParkingLot).filter(ParkingLot.id == lot_id).first()
    if not lot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="停车场不存在")
    return lot

@router.put("/parking-lots/{lot_id}", response_model=ParkingLotRead)
def update_parking_lot(lot_id: int, request: ParkingLotUpdate, db: Session = Depends(get_db), current_admin=Depends(require_admin)):
    try:
        lot = update_parking_lot_service(db, lot_id, request.address, request.total_capacity, request.status)
        if not lot:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="停车场不存在")
        db.commit()
        db.refresh(lot)
        return lot
    except HTTPException as e:
        raise e
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.delete("/parking-lots/{lot_id}", status_code=204)
def delete_parking_lot(lot_id: int, db: Session = Depends(get_db), current_admin=Depends(require_admin)):
    try:
        lot = db.query(ParkingLot).filter(ParkingLot.id == lot_id).first()
        if not lot:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="停车场不存在")
        db.delete(lot)
        db.commit()
        return
    except HTTPException as e:
        raise e
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.get("/parking-lots/{lot_id}/billing-rule", response_model=BillingRuleRead)
def get_billing_rule(lot_id: int, db: Session = Depends(get_db)):
    rule = db.query(BillingRule).filter(BillingRule.parking_lot_id == lot_id).first()
    if not rule:
        lot = db.query(ParkingLot).filter(ParkingLot.id == lot_id).first()
        if not lot:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="停车场不存在")
        # 创建默认计费规则，避免前端404
        rule = BillingRule(
            parking_lot_id=lot_id,
            rule_name="默认计费",
            free_duration_minutes=30,
            hourly_rate=5.0,
            daily_cap_rate=50.0,
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
    return rule

@router.post("/parking-lots/{lot_id}/billing-rule", response_model=BillingRuleRead)
def create_billing_rule(lot_id: int, request: BillingRuleCreate, db: Session = Depends(get_db), current_admin=Depends(require_admin)):
    try:
        exists = db.query(BillingRule).filter(BillingRule.parking_lot_id == lot_id).first()
        if exists:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="计费规则已存在")
        rule = BillingRule(
            parking_lot_id=lot_id,
            rule_name=request.rule_name,
            free_duration_minutes=request.free_duration_minutes,
            hourly_rate=request.hourly_rate,
            daily_cap_rate=request.daily_cap_rate,
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        return rule
    except HTTPException as e:
        raise e
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")


@router.put("/parking-lots/{lot_id}/billing-rule", response_model=BillingRuleRead)
def update_billing_rule(lot_id: int, request: BillingRuleUpdate, db: Session = Depends(get_db), current_admin=Depends(require_admin)):
    try:
        rule = db.query(BillingRule).filter(BillingRule.parking_lot_id == lot_id).first()
        if not rule:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="计费规则不存在")
        if request.rule_name is not None:
            rule.rule_name = request.rule_name
        if request.free_duration_minutes is not None:
            rule.free_duration_minutes = request.free_duration_minutes
        if request.hourly_rate is not None:
            rule.hourly_rate = request.hourly_rate
        if request.daily_cap_rate is not None:
            rule.daily_cap_rate = request.daily_cap_rate
        db.commit()
        db.refresh(rule)
        return rule
    except HTTPException as e:
        raise e
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.post("/parking-records/entry", response_model=ParkingRecordRead)
def parking_entry(request: ParkingRecordCreate, db: Session = Depends(get_db), req: Request = None):
    try:
        verify_device_auth_entry(db, request.parking_lot_id, request.license_plate, req)
        record = create_parking_entry(db, request.license_plate, request.parking_lot_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="车辆不存在或车位不足")
        db.commit()
        db.refresh(record)
        return record
    except HTTPException as e:
        raise e
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.post("/parking-records/{record_id}/exit", response_model=ParkingRecordRead)
def parking_exit(record_id: int, request: ParkingRecordExitRequest, db: Session = Depends(get_db), req: Request = None):
    try:
        verify_device_auth_exit(db, record_id, req)
        record = complete_parking_record(db, record_id, request.exit_time)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="记录不存在")
        db.commit()
        db.refresh(record)
        return record
    except HTTPException as e:
        raise e
    except Exception as e:
        from parking.services import BillingRuleNotFoundError
        db.rollback()
        if isinstance(e, BillingRuleNotFoundError):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="计费规则不存在")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.get("/parking-records/me", response_model=List[ParkingRecordRead])
def list_my_records(skip: int = 0, limit: int = 20, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    q = db.query(ParkingRecord).join(Vehicle, Vehicle.id == ParkingRecord.vehicle_id).filter(Vehicle.user_id == current_user.id).order_by(ParkingRecord.entry_time.desc()).offset(skip).limit(limit)
    records = q.all()
    result = []
    for r in records:
        sid = None
        s = db.query(ParkingSpace).filter(ParkingSpace.parking_lot_id == r.parking_lot_id, ParkingSpace.vehicle_id == r.vehicle_id).first()
        if s:
            sid = s.id
        result.append({
            "id": r.id,
            "vehicle_id": r.vehicle_id,
            "parking_lot_id": r.parking_lot_id,
            "space_id": sid,
            "license_plate_snapshot": r.license_plate_snapshot,
            "entry_time": r.entry_time,
            "exit_time": r.exit_time,
            "fee": r.fee,
            "status": r.status,
            "created_at": r.created_at,
        })
    return result


@router.post("/payments", response_model=PaymentRead)
def create_payment_api(request: PaymentCreate, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    try:
        if request.payment_type == PaymentType.RESERVATION_FEE:
            rsv = db.query(Reservation).filter(Reservation.id == request.reservation_id, Reservation.user_id == current_user.id).first()
            if not rsv:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="预约不存在")
            amount = rsv.reservation_fee if rsv.reservation_fee is not None else request.amount
            payment = create_payment(db, current_user.id, amount, request.payment_method, PaymentType.RESERVATION_FEE, None, rsv.id)
        else:
            record = db.query(ParkingRecord).filter(ParkingRecord.id == request.parking_record_id).first()
            if not record:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="停车记录不存在")
            amount = record.fee if record.fee is not None else request.amount
            payment = create_payment(db, current_user.id, amount, request.payment_method, PaymentType.PARKING_FEE, record.id, None)
        db.commit()
        db.refresh(payment)
        return payment
    except HTTPException as e:
        raise e
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.post("/payments/webhook/notify", response_model=PaymentRead)
def payment_webhook_notify(payload: dict, request: Request, db: Session = Depends(get_db)):
    secret = os.getenv("PAYMENT_WEBHOOK_SECRET", "test_secret")
    pid = payload.get("payment_id")
    tx = payload.get("transaction_id")
    status_val = payload.get("status")
    amount = payload.get("amount")
    ts = str(payload.get("timestamp"))
    sig = payload.get("signature") or request.headers.get("X-Signature")
    base = f"{pid}|{amount}|{status_val}|{ts}"
    expected = hmac.new(secret.encode(), base.encode(), hashlib.sha256).hexdigest()
    if not sig or sig != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="签名验证失败")
    if status_val != "SUCCESS":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="支付状态无效")
    payment = db.query(Payment).filter(Payment.id == pid).first()
    if not payment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="支付记录不存在")
    try:
        updated = mark_payment_success(db, pid, tx)
        db.commit()
        db.refresh(updated)
        return updated
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.get("/payments/me", response_model=List[PaymentRead])
def list_my_payments(skip: int = 0, limit: int = 20, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    return db.query(Payment).filter(Payment.user_id == current_user.id).offset(skip).limit(limit).all()

    


@router.get("/admin/payments", response_model=List[PaymentRead])
def admin_list_payments(skip: int = 0, limit: int = 20, status_value: PaymentStatus | None = None, payment_type: PaymentType | None = None, user_id: int | None = None, db: Session = Depends(get_db), current_admin=Depends(require_admin)):
    q = db.query(Payment)
    if status_value is not None:
        q = q.filter(Payment.status == status_value)
    if payment_type is not None:
        q = q.filter(Payment.payment_type == payment_type)
    if user_id is not None:
        q = q.filter(Payment.user_id == user_id)
    return q.order_by(Payment.created_at.desc()).offset(skip).limit(limit).all()

# 管理端：车辆停车记录列表（分页 + 过滤）
@router.get("/admin/parking-records", response_model=PaginatedParkingRecords)
def admin_list_parking_records(
    skip: int = 0,
    limit: int = 20,
    license_plate: str | None = None,
    status: str | None = None, # in_parking | completed
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    db: Session = Depends(get_db),
    current_admin=Depends(require_admin),
):
    q = db.query(ParkingRecord)
    if license_plate:
        q = q.join(Vehicle, Vehicle.id == ParkingRecord.vehicle_id).filter(Vehicle.license_plate.like(f"%{license_plate}%"))
    if status == "in_parking":
        q = q.filter(ParkingRecord.exit_time.is_(None))
    elif status == "completed":
        q = q.filter(ParkingRecord.exit_time.is_not(None))
    if start_date is not None:
        q = q.filter(ParkingRecord.entry_time >= start_date)
    if end_date is not None:
        q = q.filter(ParkingRecord.entry_time <= end_date)
    total = q.count()
    items = q.order_by(ParkingRecord.entry_time.desc()).offset(skip).limit(limit).all()
    return {"items": items, "total": total}

# --- 可视化布局与车位 ---
@router.get("/parking-lots/{lot_id}/layout", response_model=ParkingLotLayoutRead)
def get_parking_lot_layout(lot_id: int, db: Session = Depends(get_db)):
    layout = get_layout(db, lot_id)
    if not layout:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="布局不存在")
    return {
        "rows": layout.rows,
        "cols": layout.cols,
        "grid": layout.grid,
        "entrance_position": {"row": layout.entrance_row, "col": layout.entrance_col},
        "exit_position": {"row": layout.exit_row, "col": layout.exit_col},
    }

@router.put("/parking-lots/{lot_id}/layout", response_model=ParkingLotLayoutRead)
def update_parking_lot_layout(lot_id: int, request: ParkingLotLayoutUpdate, db: Session = Depends(get_db), current_admin=Depends(require_admin)):
    try:
        layout = update_layout_and_rebuild_spaces(db, lot_id, request.rows, request.cols, request.grid, request.entrance_position, request.exit_position)
        db.commit()
        db.refresh(layout)
        return {
            "rows": layout.rows,
            "cols": layout.cols,
            "grid": layout.grid,
            "entrance_position": {"row": layout.entrance_row, "col": layout.entrance_col},
            "exit_position": {"row": layout.exit_row, "col": layout.exit_col},
        }
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.get("/parking-lots/{lot_id}/spaces", response_model=List[ParkingSpaceRead])
def list_parking_spaces(lot_id: int, status_value: str | None = None, space_type: str | None = None, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    from datetime import datetime, timezone
    from parking.services import unreserve_space
    from auth.core.enums import SpaceStatus
    now = datetime.now(timezone.utc)
    try:
        expired_spaces = db.query(ParkingSpace).filter(ParkingSpace.parking_lot_id == lot_id, ParkingSpace.status == SpaceStatus.RESERVED, ParkingSpace.reserved_until != None, ParkingSpace.reserved_until < now).all()
        for sp in expired_spaces:
            unreserve_space(db, sp.id)
        if expired_spaces:
            db.commit()
    except Exception:
        db.rollback()
    q = db.query(ParkingSpace).filter(ParkingSpace.parking_lot_id == lot_id)
    if status_value:
        from auth.core.enums import SpaceStatus
        try:
            q = q.filter(ParkingSpace.status == SpaceStatus(status_value))
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="状态值无效")
    if space_type:
        from auth.core.enums import SpaceType
        try:
            q = q.filter(ParkingSpace.space_type == SpaceType(space_type))
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="类型值无效")
    return q.offset(skip).limit(limit).all()

@router.get("/parking/spaces/{space_id}", response_model=ParkingSpaceRead)
def get_parking_space(space_id: int, db: Session = Depends(get_db)):
    sp = db.query(ParkingSpace).filter(ParkingSpace.id == space_id).first()
    if not sp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="车位不存在")
    return sp

@router.put("/parking/spaces/{space_id}", response_model=ParkingSpaceRead)
def update_parking_space(space_id: int, request: ParkingSpaceUpdate, db: Session = Depends(get_db), current_admin=Depends(require_admin)):
    try:
        sp = db.query(ParkingSpace).filter(ParkingSpace.id == space_id).first()
        if not sp:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="车位不存在")
        if request.space_type is not None:
            sp.space_type = request.space_type
        if request.status is not None:
            sp.status = request.status
        if request.space_number is not None:
            sp.space_number = request.space_number
        db.commit()
        db.refresh(sp)
        return sp
    except HTTPException as e:
        raise e
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.post("/parking/spaces/{space_id}/occupy", response_model=ParkingRecordRead)
async def occupy_parking_space(space_id: int, request: OccupySpaceRequest, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    try:
        vehicle_id = request.vehicle_id
        # 如果未提供vehicle_id，尝试默认车辆
        if not vehicle_id and request.license_plate:
            v = db.query(Vehicle).filter(Vehicle.license_plate == request.license_plate).first()
            vehicle_id = v.id if v else None
        if not vehicle_id:
            dv = db.query(Vehicle).filter(Vehicle.user_id == current_user.id, Vehicle.is_default == True).first()
            vehicle_id = dv.id if dv else None
        res = occupy_space(db, space_id, vehicle_id, request.license_plate)
        if not res:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="占用失败")
        space, record = res
        db.commit()
        db.refresh(record)
        await manager.broadcast_to_lot(space.parking_lot_id, {"type": "space_occupied", "payload": {"space_id": space.id, "parking_lot_id": space.parking_lot_id}})
        await manager.send_to_user(current_user.id, {"type": "my_parking_started", "payload": {"license_plate": request.license_plate}})
        return record
    except HTTPException as e:
        raise e
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.post("/parking/spaces/{space_id}/vacate", response_model=ParkingRecordRead)
async def vacate_parking_space(space_id: int, request: VacateSpaceRequest, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    try:
        res = vacate_space(db, space_id, request.exit_time)
        if not res:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="释放失败")
        space, record = res
        db.commit()
        db.refresh(record)
        await manager.broadcast_to_lot(space.parking_lot_id, {"type": "space_vacated", "payload": {"space_id": space.id, "parking_lot_id": space.parking_lot_id}})
        await manager.send_to_user(current_user.id, {"type": "my_parking_ended", "payload": {"license_plate": record.license_plate_snapshot, "final_fee": (str(record.fee) if record.fee is not None else None)}})
        return record
    except HTTPException as e:
        raise e
    except Exception as e:
        from parking.services import BillingRuleNotFoundError
        db.rollback()
        if isinstance(e, BillingRuleNotFoundError):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="计费规则不存在")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.post("/parking/spaces/{space_id}/reserve", response_model=ReservationRead)
async def reserve_parking_space(space_id: int, request: ReserveSpaceRequest, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    try:
        if current_user.id != request.user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="用户不匹配")
        rsv = reserve_space(db, space_id, request.user_id, request.vehicle_id, request.reserved_until)
        if not rsv:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="预留失败")
        db.commit()
        db.refresh(rsv)
        await manager.broadcast_to_lot(rsv.parking_lot_id, {"type": "space_reserved", "payload": {"space_id": rsv.space_id, "parking_lot_id": rsv.parking_lot_id}})
        await manager.broadcast_all({"type": "space_reserved", "payload": {"space_id": rsv.space_id, "parking_lot_id": rsv.parking_lot_id}})
        return rsv
    except HTTPException as e:
        raise e
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.post("/parking/spaces/{space_id}/unreserve", response_model=ParkingSpaceRead)
async def unreserve_parking_space(space_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    try:
        sp = unreserve_space(db, space_id)
        if not sp:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="取消失败")
        db.commit()
        db.refresh(sp)
        await manager.broadcast_to_lot(sp.parking_lot_id, {"type": "space_unreserved", "payload": {"space_id": sp.id, "parking_lot_id": sp.parking_lot_id}})
        await manager.broadcast_all({"type": "space_unreserved", "payload": {"space_id": sp.id, "parking_lot_id": sp.parking_lot_id}})
        return sp
    except HTTPException as e:
        raise e
    except Exception:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.post("/parking-lots/{lot_id}/nearest-space", response_model=NearestSpaceResponse)
def api_nearest_space(lot_id: int, request: NearestSpaceRequest, db: Session = Depends(get_db)):
    res = find_nearest_available_space(db, lot_id, request.origin, request.preferred_type)
    if not res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="无可用车位")
    return res

@router.post("/parking-lots/{lot_id}/navigate", response_model=NavigateResponse)
def api_navigate(lot_id: int, request: NavigateRequest, db: Session = Depends(get_db)):
    path = calculate_navigation_path(db, lot_id, request.start, request.end)
    if path is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="布局不存在")
    return {"path": path}

@router.get("/parking-lots/{lot_id}/stats", response_model=ParkingStatsRead)
def api_stats(lot_id: int, db: Session = Depends(get_db)):
    try:
        from datetime import datetime, timezone
        from parking.services import unreserve_space
        from auth.core.enums import SpaceStatus
        now = datetime.now(timezone.utc)
        expired_spaces = db.query(ParkingSpace).filter(ParkingSpace.parking_lot_id == lot_id, ParkingSpace.status == SpaceStatus.RESERVED, ParkingSpace.reserved_until != None, ParkingSpace.reserved_until < now).all()
        for sp in expired_spaces:
            unreserve_space(db, sp.id)
        if expired_spaces:
            db.commit()
    except Exception:
        db.rollback()
    return get_parking_stats(db, lot_id)
@router.post("/parking-records/{record_id}/vacate", response_model=ParkingRecordRead)
def vacate_by_record(record_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    try:
        rec = db.query(ParkingRecord).filter(ParkingRecord.id == record_id).first()
        if not rec:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="停车记录不存在")
        # 权限：仅记录所属用户或管理员可操作
        if current_user.role != UserRole.ADMIN and hasattr(rec, "user_id"):
            if rec.user_id != current_user.id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="无权操作该记录")
        # 尝试根据车辆在该停车场找到占用的车位
        space = db.query(ParkingSpace).filter(
            ParkingSpace.parking_lot_id == rec.parking_lot_id,
            ParkingSpace.vehicle_id == rec.vehicle_id,
        ).first()
        if not space:
            # 记录缺少停车场信息时无法结算
            if rec.parking_lot_id is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="停车记录缺少停车场信息")
            # 若计费规则不存在，则创建一个默认计费规则以保障结算闭环
            rule = db.query(BillingRule).filter(BillingRule.parking_lot_id == rec.parking_lot_id).first()
            if not rule:
                rule = BillingRule(
                    parking_lot_id=rec.parking_lot_id,
                    rule_name="默认计费",
                    free_duration_minutes=30,
                    hourly_rate=5.0,
                    daily_cap_rate=50.0,
                )
                db.add(rule)
                db.flush()
        updated = complete_parking_record(db, record_id, datetime.utcnow())
        db.commit()
        db.refresh(updated)
        return updated
        result = vacate_space(db, space.id, datetime.utcnow())
        db.commit()
        # 返回更新后的记录
        updated = db.query(ParkingRecord).filter(ParkingRecord.id == record_id).first()
        return updated
    except HTTPException as e:
        raise e
    except Exception as e:
        db.rollback()
        if isinstance(e, BillingRuleNotFoundError):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="计费规则不存在")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")

@router.post("/parking-records/{record_id}/exit-and-settle")
def exit_and_settle(record_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    try:
        rec = db.query(ParkingRecord).filter(ParkingRecord.id == record_id).first()
        if not rec:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="停车记录不存在")
        # 权限校验：仅记录所属用户或管理员
        if current_user.role != UserRole.ADMIN:
            # 通过车辆归属校验
            v = db.query(Vehicle).filter(Vehicle.id == rec.vehicle_id).first()
            if not v or v.user_id != current_user.id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="无权操作该记录")
        # 直接完成计费与结算，不强依赖空间状态释放
        # 完成计费（若尚未完成），确保存在计费规则
        if rec.exit_time is None or rec.status == ParkingRecordStatus.PARKED:
            if rec.parking_lot_id is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="停车记录缺少停车场信息")
            rule = db.query(BillingRule).filter(BillingRule.parking_lot_id == rec.parking_lot_id).first()
            if not rule:
                rule = BillingRule(
                    parking_lot_id=rec.parking_lot_id,
                    rule_name="默认计费",
                    free_duration_minutes=30,
                    hourly_rate=5.0,
                    daily_cap_rate=50.0,
                )
                db.add(rule)
                db.flush()
            try:
                completed = complete_parking_record(db, record_id, datetime.utcnow())
                db.refresh(completed)
                rec = completed
            except Exception:
                rec.exit_time = datetime.utcnow()
                rec.fee = 0
                rec.status = ParkingRecordStatus.UNPAID
                db.execute(
                    update(ParkingLot)
                    .where(ParkingLot.id == rec.parking_lot_id, ParkingLot.available_spots < ParkingLot.total_capacity)
                    .values(available_spots=ParkingLot.available_spots + 1)
                )
        # 幂等：如已有余额成功支付，则直接返回成功
        existing_success = db.query(Payment).filter(Payment.parking_record_id == record_id, Payment.status == PaymentStatus.SUCCESS).first()
        if existing_success:
            db.commit()
            return {"detail": "已结算", "amount": str(existing_success.amount)}
        # 使用余额结算
        amount = rec.fee if rec.fee is not None else None
        if amount is None:
            amount = 0
        from decimal import Decimal
        ok = settle_with_balance(db, current_user.id, Decimal(str(amount)), PaymentType.PARKING_FEE, record_id, None)
        if not ok:
            db.rollback()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="余额不足")
        # 余额结算成功：保证记录状态为 PAID，保留记录以支持幂等
        db.commit()
        return {"detail": "结算成功", "amount": str(amount)}
    except HTTPException as e:
        raise e
    except Exception as e:
        db.rollback()
        from parking.services import BillingRuleNotFoundError
        if isinstance(e, BillingRuleNotFoundError):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="计费规则不存在")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="内部错误")