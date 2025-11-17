from auth.database import SessionLocal
from auth.models.user import User
from auth.core.security import get_password_hash
from parking.services import reserve_space
from parking.models import Vehicle, ParkingSpace
from parking.models import Reservation
from auth.core.enums import SpaceStatus, ReservationStatus
from datetime import datetime, timezone, timedelta
import uuid

def test_reserve_space_existed_path():
    db = SessionLocal()
    try:
        # user and vehicle
        phone = "139" + str(uuid.uuid4().int)[-8:]
        u = User(username="rs_user" + phone[-4:], phone_number=phone, email=f"rs{phone[-4:]}@test.com", password_hash=get_password_hash("pass123"))
        db.add(u)
        db.flush()
        v = Vehicle(user_id=u.id, license_plate="RS-TEST")
        db.add(v)
        db.flush()
        # find any available space from existing data
        sp = db.query(ParkingSpace).filter(ParkingSpace.status == SpaceStatus.AVAILABLE).first()
        assert sp is not None
        # insert an existed active reservation on that space
        now = datetime.now(timezone.utc)
        r_existed = Reservation(user_id=u.id, vehicle_id=v.id, parking_lot_id=sp.parking_lot_id, space_id=sp.id, reservation_fee=None, reservation_time=now, expires_at=now + timedelta(hours=2), status=ReservationStatus.ACTIVE)
        db.add(r_existed)
        db.commit()
        # second reserve should hit existed path and return None
        r2 = reserve_space(db, sp.id, u.id, v.id, now + timedelta(hours=2))
        assert r2 is None
    finally:
        db.close()
