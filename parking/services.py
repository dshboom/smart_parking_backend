# services.py slh
from decimal import Decimal
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import update
from .models import Vehicle, ParkingLot, BillingRule, ParkingRecord, Payment, Reservation, ParkingLotLayout, ParkingSpace
from auth.core.enums import ParkingRecordStatus, PaymentStatus, ReservationStatus, PaymentType, SpaceStatus, SpaceType
from typing import List, Tuple
import heapq

class BillingRuleNotFoundError(Exception):
    pass

def compute_fee(entry_time: datetime, exit_time: datetime, rule: BillingRule) -> Decimal:
    if exit_time < entry_time:
        exit_time = entry_time
    total_minutes = int((exit_time - entry_time).total_seconds() // 60)
    free = int(rule.free_duration_minutes or 0)
    billable = max(0, total_minutes - free)
    if billable == 0:
        return Decimal("0.00")
    hourly = Decimal(str(rule.hourly_rate))
    cap = Decimal(str(rule.daily_cap_rate)) if rule.daily_cap_rate is not None else None
    if cap is None:
        hours = (billable + 59) // 60
        fee = hourly * Decimal(hours)
    else:
        days = billable // 1440
        rem = billable % 1440
        fee_days = cap * Decimal(days)
        rem_hours = (rem + 59) // 60
        rem_fee = hourly * Decimal(rem_hours)
        if rem_fee > cap:
            rem_fee = cap
        fee = fee_days + rem_fee
    return fee.quantize(Decimal("0.01"))

def set_default_vehicle(db: Session, user_id: int, vehicle_id: int) -> Vehicle:
    db.query(Vehicle).filter(Vehicle.user_id == user_id).update({Vehicle.is_default: False})
    v = db.query(Vehicle).filter(Vehicle.id == vehicle_id, Vehicle.user_id == user_id).first()
    if v:
        v.is_default = True
    return v

def create_parking_entry(db: Session, license_plate: str, parking_lot_id: int) -> ParkingRecord:
    vehicle = db.query(Vehicle).filter(Vehicle.license_plate == license_plate).first()
    if not vehicle:
        return None
    now = datetime.now(timezone.utc)
    rsv = db.query(Reservation).filter(
        Reservation.vehicle_id == vehicle.id,
        Reservation.parking_lot_id == parking_lot_id,
        Reservation.status == ReservationStatus.ACTIVE,
        Reservation.expires_at >= now,
    ).order_by(Reservation.reservation_time.asc()).first()
    if not rsv:
        dec = db.execute(
            update(ParkingLot)
            .where(ParkingLot.id == parking_lot_id, ParkingLot.available_spots > 0)
            .values(available_spots=ParkingLot.available_spots - 1)
        )
        if dec.rowcount == 0:
            return None
    record = ParkingRecord(
        vehicle_id=vehicle.id,
        parking_lot_id=parking_lot_id,
        license_plate_snapshot=license_plate,
        entry_time=datetime.now(timezone.utc),
        status=ParkingRecordStatus.PARKED,
    )
    db.add(record)
    db.flush()
    if rsv:
        rsv.status = ReservationStatus.COMPLETED
        rsv.parking_record_id = record.id
    return record

def complete_parking_record(db: Session, record_id: int, exit_time: datetime | None = None) -> ParkingRecord:
    record = db.query(ParkingRecord).filter(ParkingRecord.id == record_id).first()
    if not record:
        return None
    if not exit_time:
        exit_time = datetime.now(timezone.utc)
    record.exit_time = exit_time
    rule = db.query(BillingRule).filter(BillingRule.parking_lot_id == record.parking_lot_id).first()
    if not rule:
        raise BillingRuleNotFoundError()
    fee = compute_fee(record.entry_time, exit_time, rule)
    record.fee = fee
    record.status = ParkingRecordStatus.UNPAID
    db.execute(
        update(ParkingLot)
        .where(ParkingLot.id == record.parking_lot_id, ParkingLot.available_spots < ParkingLot.total_capacity)
        .values(available_spots=ParkingLot.available_spots + 1)
    )
    return record

def create_vehicle_service(db: Session, user_id: int, license_plate: str, is_default: bool) -> Vehicle | None:
    exists = db.query(Vehicle).filter(Vehicle.license_plate == license_plate).first()
    if exists:
        return None
    v = Vehicle(user_id=user_id, license_plate=license_plate, is_default=is_default)
    db.add(v)
    db.flush()
    if is_default:
        set_default_vehicle(db, user_id, v.id)
    return v

def update_parking_lot_service(db: Session, lot_id: int, address: str | None, total_capacity: int | None, status) -> ParkingLot | None:
    lot = db.query(ParkingLot).filter(ParkingLot.id == lot_id).first()
    if not lot:
        return None
    if address is not None:
        lot.address = address
    if total_capacity is not None:
        lot.total_capacity = total_capacity
    if status is not None:
        lot.status = status
    return lot

def create_payment(db: Session, user_id: int, amount: Decimal, method, payment_type: PaymentType = PaymentType.PARKING_FEE, record_id: int | None = None, reservation_id: int | None = None) -> Payment:
    payment = Payment(
        parking_record_id=record_id,
        reservation_id=reservation_id,
        user_id=user_id,
        amount=amount,
        payment_method=method,
        payment_type=payment_type,
        status=PaymentStatus.PENDING,
    )
    db.add(payment)
    db.flush()
    return payment

def mark_payment_success(db: Session, payment_id: int, transaction_id: str | None = None) -> Payment:
    payment = db.query(Payment).filter(Payment.id == payment_id).first()
    if not payment:
        return None
    payment.status = PaymentStatus.SUCCESS
    payment.transaction_id = transaction_id
    payment.paid_at = datetime.now(timezone.utc)
    if payment.payment_type == PaymentType.PARKING_FEE:
        record = db.query(ParkingRecord).filter(ParkingRecord.id == payment.parking_record_id).first()
        if record:
            record.status = ParkingRecordStatus.PAID
    else:
        rsv = db.query(Reservation).filter(Reservation.id == payment.reservation_id).first()
        if rsv:
            # 记录预约费用，便于前端展示
            rsv.reservation_fee = payment.amount
            if rsv.status == ReservationStatus.PENDING:
                dec = db.execute(
                    update(ParkingLot)
                    .where(ParkingLot.id == rsv.parking_lot_id, ParkingLot.available_spots > 0)
                    .values(available_spots=ParkingLot.available_spots - 1)
                )
                if dec.rowcount == 1:
                    rsv.status = ReservationStatus.ACTIVE
    return payment

def create_reservation(db: Session, user_id: int, vehicle_id: int | None, parking_lot_id: int, reservation_time: datetime, expires_at: datetime, reservation_fee: Decimal | None) -> Reservation | None:
    lot = db.query(ParkingLot).filter(ParkingLot.id == parking_lot_id).first()
    if not lot:
        return None
    rsv = Reservation(
        user_id=user_id,
        vehicle_id=vehicle_id,
        parking_lot_id=parking_lot_id,
        reservation_fee=reservation_fee,
        reservation_time=reservation_time,
        expires_at=expires_at,
        status=ReservationStatus.PENDING,
    )
    db.add(rsv)
    db.flush()
    if reservation_fee is None or Decimal(str(reservation_fee)) == Decimal("0.00"):
        dec = db.execute(
            update(ParkingLot)
            .where(ParkingLot.id == parking_lot_id, ParkingLot.available_spots > 0)
            .values(available_spots=ParkingLot.available_spots - 1)
        )
        if dec.rowcount == 1:
            rsv.status = ReservationStatus.ACTIVE
    return rsv

def cancel_reservation(db: Session, reservation_id: int) -> Reservation | None:
    rsv = db.query(Reservation).filter(Reservation.id == reservation_id).first()
    if not rsv:
        return None
    if rsv.status == ReservationStatus.ACTIVE:
        db.execute(
            update(ParkingLot)
            .where(ParkingLot.id == rsv.parking_lot_id, ParkingLot.available_spots < ParkingLot.total_capacity)
            .values(available_spots=ParkingLot.available_spots + 1)
        )
        if rsv.space_id:
            sp = db.query(ParkingSpace).filter(ParkingSpace.id == rsv.space_id).first()
            if sp and sp.status == SpaceStatus.RESERVED:
                sp.status = SpaceStatus.AVAILABLE
                sp.reserved_until = None
                sp.vehicle_id = None
    rsv.status = ReservationStatus.CANCELLED
    return rsv

def expire_reservation(db: Session, reservation_id: int) -> Reservation | None:
    rsv = db.query(Reservation).filter(Reservation.id == reservation_id).first()
    if not rsv:
        return None
    if rsv.status == ReservationStatus.ACTIVE:
        db.execute(
            update(ParkingLot)
            .where(ParkingLot.id == rsv.parking_lot_id, ParkingLot.available_spots < ParkingLot.total_capacity)
            .values(available_spots=ParkingLot.available_spots + 1)
        )
    rsv.status = ReservationStatus.EXPIRED
    return rsv

def activate_reservation_admin(db: Session, reservation_id: int) -> Reservation | None:
    rsv = db.query(Reservation).filter(Reservation.id == reservation_id).first()
    if not rsv:
        return None
    if rsv.status != ReservationStatus.PENDING:
        return rsv
    dec = db.execute(
        update(ParkingLot)
        .where(ParkingLot.id == rsv.parking_lot_id, ParkingLot.available_spots > 0)
        .values(available_spots=ParkingLot.available_spots - 1)
    )
    if dec.rowcount == 1:
        rsv.status = ReservationStatus.ACTIVE
    return rsv

def update_reservation(db: Session, reservation_id: int, expires_at: datetime | None) -> Reservation | None:
    rsv = db.query(Reservation).filter(Reservation.id == reservation_id).first()
    if not rsv:
        return None
    if expires_at is not None:
        rsv.expires_at = expires_at
    return rsv

# --- 布局与车位 ---
def update_layout_and_rebuild_spaces(db: Session, lot_id: int, rows: int, cols: int, grid: List[List[str]], entrance: dict, exitp: dict) -> ParkingLotLayout:
    layout = db.query(ParkingLotLayout).filter(ParkingLotLayout.parking_lot_id == lot_id).first()
    if not layout:
        layout = ParkingLotLayout(parking_lot_id=lot_id, rows=rows, cols=cols, grid=grid, entrance_row=entrance.get("row"), entrance_col=entrance.get("col"), exit_row=exitp.get("row"), exit_col=exitp.get("col"))
        db.add(layout)
    else:
        layout.rows = rows
        layout.cols = cols
        layout.grid = grid
        layout.entrance_row = entrance.get("row")
        layout.entrance_col = entrance.get("col")
        layout.exit_row = exitp.get("row")
        layout.exit_col = exitp.get("col")
    # 清理并重建车位
    db.query(ParkingSpace).filter(ParkingSpace.parking_lot_id == lot_id).delete()
    total = 0
    for r in range(rows):
        for c in range(cols):
            if grid[r][c] == "parking":
                sp = ParkingSpace(parking_lot_id=lot_id, row=r, col=c, space_type=SpaceType.STANDARD, status=SpaceStatus.AVAILABLE)
                db.add(sp)
                total += 1
    lot = db.query(ParkingLot).filter(ParkingLot.id == lot_id).first()
    if lot:
        lot.total_capacity = total
        # available 按当前车位状态统计（新建全为可用）
        lot.available_spots = total
    db.flush()
    return layout

def get_layout(db: Session, lot_id: int) -> ParkingLotLayout | None:
    return db.query(ParkingLotLayout).filter(ParkingLotLayout.parking_lot_id == lot_id).first()

# --- 车位操作 ---
def occupy_space(db: Session, space_id: int, vehicle_id: int | None, license_plate: str | None, user_id: int | None = None) -> Tuple[ParkingSpace, ParkingRecord] | None:
    space = db.query(ParkingSpace).filter(ParkingSpace.id == space_id).with_for_update().first()
    if not space:
        return None
    if space.status not in (SpaceStatus.AVAILABLE, SpaceStatus.RESERVED):
        return None
    vehicle = None
    if vehicle_id:
        vehicle = db.query(Vehicle).filter(Vehicle.id == vehicle_id).first()
    elif license_plate:
        vehicle = db.query(Vehicle).filter(Vehicle.license_plate == license_plate).first()
    if not vehicle:
        return None
    # 如果是预留状态，确认是否存在绑定该space的ACTIVE预约
    if space.status == SpaceStatus.RESERVED:
        now = datetime.now(timezone.utc)
        q = db.query(Reservation).filter(Reservation.space_id == space.id, Reservation.status == ReservationStatus.ACTIVE, Reservation.expires_at >= now)
        if user_id is not None:
            q = q.filter(Reservation.user_id == user_id)
        else:
            q = q.filter(Reservation.vehicle_id == vehicle.id)
        rsv = q.first()
        if not rsv:
            return None
        rsv.status = ReservationStatus.COMPLETED
    prev_status = space.status
    space.status = SpaceStatus.OCCUPIED
    space.vehicle_id = vehicle.id
    space.occupied_at = datetime.now(timezone.utc)
    lot_id = space.parking_lot_id
    if prev_status == SpaceStatus.AVAILABLE:
        dec = db.execute(
            update(ParkingLot)
            .where(ParkingLot.id == lot_id, ParkingLot.available_spots > 0)
            .values(available_spots=ParkingLot.available_spots - 1)
        )
        if dec.rowcount == 0:
            return None
    record = ParkingRecord(
        vehicle_id=vehicle.id,
        parking_lot_id=lot_id,
        space_id=space.id,
        license_plate_snapshot=vehicle.license_plate,
        entry_time=datetime.now(timezone.utc),
        status=ParkingRecordStatus.PARKED,
    )
    db.add(record)
    db.flush()
    if prev_status == SpaceStatus.RESERVED:
        try:
            if 'rsv' in locals() and rsv:
                rsv.parking_record_id = record.id
        except Exception:
            pass
    return (space, record)

def vacate_space(db: Session, space_id: int, exit_time: datetime | None = None) -> Tuple[ParkingSpace, ParkingRecord] | None:
    space = db.query(ParkingSpace).filter(ParkingSpace.id == space_id).with_for_update().first()
    if not space or space.status != SpaceStatus.OCCUPIED:
        return None
    record = db.query(ParkingRecord).filter(ParkingRecord.space_id == space_id, ParkingRecord.status == ParkingRecordStatus.PARKED).order_by(ParkingRecord.entry_time.desc()).first()
    if not record:
        return None
    completed = complete_parking_record(db, record.id, exit_time)
    space.status = SpaceStatus.AVAILABLE
    space.vehicle_id = None
    space.occupied_at = None
    space.reserved_until = None
    return (space, completed)

def reserve_space(db: Session, space_id: int, user_id: int, vehicle_id: int | None, reserved_until: datetime | None = None) -> Reservation | None:
    space = db.query(ParkingSpace).filter(ParkingSpace.id == space_id).with_for_update().first()
    if not space or space.status != SpaceStatus.AVAILABLE:
        return None
    # 防重：该space存在未结束的预约
    now = datetime.now(timezone.utc)
    existed = db.query(Reservation).filter(Reservation.space_id == space_id, Reservation.status.in_([ReservationStatus.PENDING, ReservationStatus.ACTIVE]), Reservation.expires_at >= now).first()
    if existed:
        return None
    end_time = reserved_until or (now + timedelta(hours=1))
    if end_time <= now:
        return None
    rsv = create_reservation(db, user_id, vehicle_id, space.parking_lot_id, now, end_time, None)
    if rsv.status == ReservationStatus.ACTIVE:
        space.status = SpaceStatus.RESERVED
        space.reserved_until = end_time
        space.vehicle_id = vehicle_id if vehicle_id is not None else None
        rsv.space_id = space.id
    return rsv

def unreserve_space(db: Session, space_id: int) -> ParkingSpace | None:
    space = db.query(ParkingSpace).filter(ParkingSpace.id == space_id).with_for_update().first()
    if not space or space.status != SpaceStatus.RESERVED:
        return None
    # 找到最新的预约并取消
    rsv = db.query(Reservation).filter(Reservation.space_id == space_id, Reservation.status.in_([ReservationStatus.PENDING, ReservationStatus.ACTIVE])).order_by(Reservation.created_at.desc()).first()
    if rsv:
        cancel_reservation(db, rsv.id)
    space.status = SpaceStatus.AVAILABLE
    space.reserved_until = None
    space.vehicle_id = None
    return space

# --- 导航与查找 ---
def _neighbors(rows: int, cols: int, r: int, c: int):
    for dr, dc in [(1,0),(-1,0),(0,1),(0,-1)]:
        nr, nc = r+dr, c+dc
        if 0 <= nr < rows and 0 <= nc < cols:
            yield nr, nc

def find_nearest_available_space(db: Session, lot_id: int, origin: dict | None, preferred: SpaceType | None) -> dict | None:
    layout = get_layout(db, lot_id)
    if not layout:
        return None
    rows, cols = layout.rows, layout.cols
    start_r = origin.get("row") if origin and "row" in origin else layout.entrance_row
    start_c = origin.get("col") if origin and "col" in origin else layout.entrance_col
    blocked = set()
    # 墙体与障碍
    for r in range(rows):
        for c in range(cols):
            if layout.grid[r][c] == "wall":
                blocked.add((r,c))
    # 占用/维护/预留不可选
    spaces = db.query(ParkingSpace).filter(ParkingSpace.parking_lot_id == lot_id).all()
    unavailable = {(s.row, s.col) for s in spaces if s.status in (SpaceStatus.OCCUPIED, SpaceStatus.MAINTENANCE, SpaceStatus.RESERVED)}
    blocked |= unavailable
    from collections import deque
    q = deque()
    q.append((start_r, start_c, 0))
    visited = {(start_r, start_c)}
    target = None
    while q:
        r, c, d = q.popleft()
        if layout.grid[r][c] == "parking" and (r,c) not in unavailable:
            # 过滤类型
            sp = next((s for s in spaces if s.row == r and s.col == c and s.status == SpaceStatus.AVAILABLE), None)
            if sp and (preferred is None or sp.space_type == preferred):
                target = {"space_id": sp.id, "row": r, "col": c, "distance": d}
                break
        for nr, nc in _neighbors(rows, cols, r, c):
            if (nr, nc) in blocked:
                continue
            if layout.grid[nr][nc] in ("road","entrance","exit","parking") and (nr, nc) not in visited:
                visited.add((nr, nc))
                q.append((nr, nc, d+1))
    return target

def calculate_navigation_path(db: Session, lot_id: int, start: dict, end: dict) -> List[dict] | None:
    layout = get_layout(db, lot_id)
    if not layout:
        return None
    rows, cols = layout.rows, layout.cols
    sr = start.get("row", layout.entrance_row)
    sc = start.get("col", layout.entrance_col)
    er = end.get("row", layout.exit_row)
    ec = end.get("col", layout.exit_col)
    blocked = set()
    for r in range(rows):
        for c in range(cols):
            if layout.grid[r][c] == "wall":
                blocked.add((r,c))
    spaces = db.query(ParkingSpace).filter(ParkingSpace.parking_lot_id == lot_id).all()
    unavailable = {(s.row, s.col) for s in spaces if s.status in (SpaceStatus.OCCUPIED, SpaceStatus.MAINTENANCE, SpaceStatus.RESERVED)}
    blocked |= unavailable
    def h(a: Tuple[int,int], b: Tuple[int,int]):
        return abs(a[0]-b[0]) + abs(a[1]-b[1])
    open_set = []
    heapq.heappush(open_set, (0, (sr, sc)))
    came = {}
    g = {(sr, sc): 0}
    target = (er, ec)
    while open_set:
        _, cur = heapq.heappop(open_set)
        if cur == target:
            # 回溯
            path = []
            while cur in came:
                path.append({"row": cur[0], "col": cur[1]})
                cur = came[cur]
            path.append({"row": sr, "col": sc})
            path.reverse()
            return path
        for nr, nc in _neighbors(rows, cols, cur[0], cur[1]):
            if (nr, nc) in blocked:
                continue
            if layout.grid[nr][nc] not in ("road","entrance","exit","parking"):
                continue
            tentative = g[cur] + 1
            if tentative < g.get((nr, nc), 1e9):
                came[(nr, nc)] = cur
                g[(nr, nc)] = tentative
                f = tentative + h((nr, nc), target)
                heapq.heappush(open_set, (f, (nr, nc)))
    return []

# --- 统计 ---
def get_parking_stats(db: Session, lot_id: int) -> dict:
    spaces = db.query(ParkingSpace).filter(ParkingSpace.parking_lot_id == lot_id).all()
    total = len(spaces)
    occupied = sum(1 for s in spaces if s.status == SpaceStatus.OCCUPIED)
    reserved = sum(1 for s in spaces if s.status == SpaceStatus.RESERVED)
    available = sum(1 for s in spaces if s.status == SpaceStatus.AVAILABLE)
    types = {}
    for s in spaces:
        types[str(s.space_type.value)] = types.get(str(s.space_type.value), 0) + 1
    status_dist = {}
    for s in spaces:
        status_dist[str(s.status.value)] = status_dist.get(str(s.status.value), 0) + 1
    # 简化的小时占用（近24小时）：按entry_time计数
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    hours = []
    for i in range(24):
        start = now - timedelta(hours=i+1)
        end = now - timedelta(hours=i)
        cnt = db.query(ParkingRecord).filter(ParkingRecord.parking_lot_id == lot_id, ParkingRecord.entry_time >= start, ParkingRecord.entry_time < end).count()
        hours.append({"time_window": i, "occupied": cnt})
    return {
        "total_spaces": total,
        "occupied_spaces": occupied,
        "available_spaces": available,
        "reserved_spaces": reserved,
        "occupancy_rate": (occupied / total) if total else 0.0,
        "space_types": types,
        "status_distribution": status_dist,
        "hourly_occupancy": list(reversed(hours)),
    }