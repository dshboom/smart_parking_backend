from sqlalchemy import Column, Integer, String, Boolean, Enum, ForeignKey, Index, BigInteger, Numeric, JSON
from sqlalchemy.sql import func
from auth.database import Base, UTCDateTime
from auth.core.enums import VehicleStatus, ParkingLotStatus, ParkingRecordStatus, PaymentStatus, PaymentMethod, ReservationStatus, PaymentType, SpaceStatus, SpaceType

class Vehicle(Base):
    __tablename__ = "vehicles"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    license_plate = Column(String(20), unique=True, nullable=False, index=True)
    is_default = Column(Boolean, default=False, nullable=False)
    status = Column(Enum(VehicleStatus), default=VehicleStatus.ACTIVE, nullable=False)
    created_at = Column(UTCDateTime, default=func.now(), nullable=False)
    updated_at = Column(UTCDateTime, default=func.now(), onupdate=func.now(), nullable=False)
    __table_args__ = (
        Index("idx_vehicles_user", "user_id"),
        Index("idx_vehicles_status", "status"),
        Index("idx_vehicles_user_default", "user_id", "is_default"),
    )

class ParkingLot(Base):
    __tablename__ = "parking_lots"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    address = Column(String(255), nullable=False)
    total_capacity = Column(Integer, nullable=False)
    available_spots = Column(Integer, nullable=False)
    api_key = Column(String(100), unique=True, nullable=True, index=True)
    api_secret = Column(String(255), nullable=True)
    status = Column(Enum(ParkingLotStatus), default=ParkingLotStatus.OPEN, nullable=False)
    created_at = Column(UTCDateTime, default=func.now(), nullable=False)
    updated_at = Column(UTCDateTime, default=func.now(), onupdate=func.now(), nullable=False)
    __table_args__ = (
        Index("idx_parking_lots_status", "status"),
        Index("idx_parking_lots_available", "available_spots"),
    )

class BillingRule(Base):
    __tablename__ = "billing_rules"
    id = Column(Integer, primary_key=True, autoincrement=True)
    parking_lot_id = Column(Integer, ForeignKey("parking_lots.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    rule_name = Column(String(100), nullable=False)
    free_duration_minutes = Column(Integer, nullable=False, default=15)
    hourly_rate = Column(Numeric(10, 2), nullable=False)
    daily_cap_rate = Column(Numeric(10, 2), nullable=True)
    created_at = Column(UTCDateTime, default=func.now(), nullable=False)
    updated_at = Column(UTCDateTime, default=func.now(), onupdate=func.now(), nullable=False)

class ParkingRecord(Base):
    __tablename__ = "parking_records"
    id = Column(BigInteger().with_variant(Integer, 'sqlite'), primary_key=True, autoincrement=True)
    vehicle_id = Column(Integer, ForeignKey("vehicles.id", ondelete="SET NULL"), nullable=True, index=True)
    parking_lot_id = Column(Integer, ForeignKey("parking_lots.id", ondelete="SET NULL"), nullable=True, index=True)
    space_id = Column(Integer, ForeignKey("parking_spaces.id", ondelete="SET NULL"), nullable=True, index=True)
    license_plate_snapshot = Column(String(20), nullable=False)
    entry_time = Column(UTCDateTime, nullable=False, index=True)
    exit_time = Column(UTCDateTime, nullable=True)
    fee = Column(Numeric(10, 2), nullable=True)
    status = Column(Enum(ParkingRecordStatus), default=ParkingRecordStatus.PARKED, nullable=False, index=True)
    created_at = Column(UTCDateTime, default=func.now(), nullable=False)
    __table_args__ = (
        Index("idx_parking_records_vehicle_lot", "vehicle_id", "parking_lot_id"),
        Index("idx_parking_records_lot_space", "parking_lot_id", "space_id"),
    )

class Reservation(Base):
    __tablename__ = "reservations"
    id = Column(BigInteger().with_variant(Integer, 'sqlite'), primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    vehicle_id = Column(Integer, ForeignKey("vehicles.id", ondelete="CASCADE"), nullable=True, index=True)
    parking_lot_id = Column(Integer, ForeignKey("parking_lots.id", ondelete="CASCADE"), nullable=False, index=True)
    space_id = Column(Integer, ForeignKey("parking_spaces.id", ondelete="SET NULL"), nullable=True, index=True)
    reservation_fee = Column(Numeric(10, 2), nullable=True)
    reservation_time = Column(UTCDateTime, nullable=False, index=True)
    expires_at = Column(UTCDateTime, nullable=False, index=True)
    status = Column(Enum(ReservationStatus), default=ReservationStatus.PENDING, nullable=False, index=True)
    parking_record_id = Column(BigInteger().with_variant(Integer, 'sqlite'), ForeignKey("parking_records.id", ondelete="SET NULL"), nullable=True, unique=True)
    created_at = Column(UTCDateTime, default=func.now(), nullable=False)
    updated_at = Column(UTCDateTime, default=func.now(), onupdate=func.now(), nullable=False)
    __table_args__ = (
        Index("idx_reservations_lot_status", "parking_lot_id", "status"),
        Index("idx_reservations_lot_space_status", "parking_lot_id", "space_id", "status"),
        Index("idx_reservations_user_vehicle", "user_id", "vehicle_id"),
    )

class ParkingLotLayout(Base):
    __tablename__ = "parking_lot_layouts"
    id = Column(Integer, primary_key=True, autoincrement=True)
    parking_lot_id = Column(Integer, ForeignKey("parking_lots.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    rows = Column(Integer, nullable=False)
    cols = Column(Integer, nullable=False)
    grid = Column(JSON, nullable=False)
    entrance_row = Column(Integer, nullable=False)
    entrance_col = Column(Integer, nullable=False)
    exit_row = Column(Integer, nullable=False)
    exit_col = Column(Integer, nullable=False)
    created_at = Column(UTCDateTime, default=func.now(), nullable=False)
    updated_at = Column(UTCDateTime, default=func.now(), onupdate=func.now(), nullable=False)

class ParkingSpace(Base):
    __tablename__ = "parking_spaces"
    id = Column(Integer, primary_key=True, autoincrement=True)
    parking_lot_id = Column(Integer, ForeignKey("parking_lots.id", ondelete="CASCADE"), nullable=False, index=True)
    space_number = Column(String(50), nullable=True)
    row = Column(Integer, nullable=False)
    col = Column(Integer, nullable=False)
    space_type = Column(Enum(SpaceType), nullable=False, default=SpaceType.STANDARD)
    status = Column(Enum(SpaceStatus), nullable=False, default=SpaceStatus.AVAILABLE, index=True)
    vehicle_id = Column(Integer, ForeignKey("vehicles.id", ondelete="SET NULL"), nullable=True)
    occupied_at = Column(UTCDateTime, nullable=True)
    reserved_until = Column(UTCDateTime, nullable=True)
    created_at = Column(UTCDateTime, default=func.now(), nullable=False)
    updated_at = Column(UTCDateTime, default=func.now(), onupdate=func.now(), nullable=False)
    __table_args__ = (
        Index("idx_spaces_lot_status", "parking_lot_id", "status"),
        Index("idx_spaces_lot_type", "parking_lot_id", "space_type"),
        Index("uq_spaces_lot_row_col", "parking_lot_id", "row", "col", unique=True),
    )

class SpaceEvent(Base):
    __tablename__ = "space_events"
    id = Column(BigInteger().with_variant(Integer, 'sqlite'), primary_key=True, autoincrement=True)
    space_id = Column(Integer, ForeignKey("parking_spaces.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(50), nullable=False)
    payload = Column(JSON, nullable=True)
    created_at = Column(UTCDateTime, default=func.now(), nullable=False)
    __table_args__ = (
        Index("idx_space_events_space_type_time", "space_id", "event_type", "created_at"),
    )

class Payment(Base):
    __tablename__ = "payments"
    id = Column(BigInteger().with_variant(Integer, 'sqlite'), primary_key=True, autoincrement=True)
    parking_record_id = Column(BigInteger().with_variant(Integer, 'sqlite'), ForeignKey("parking_records.id", ondelete="CASCADE"), nullable=True, index=True)
    reservation_id = Column(BigInteger().with_variant(Integer, 'sqlite'), ForeignKey("reservations.id", ondelete="CASCADE"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    amount = Column(Numeric(10, 2), nullable=False)
    payment_method = Column(Enum(PaymentMethod), nullable=False)
    payment_type = Column(Enum(PaymentType), default=PaymentType.PARKING_FEE, nullable=False)
    transaction_id = Column(String(255), unique=True, nullable=True)
    status = Column(Enum(PaymentStatus), default=PaymentStatus.PENDING, nullable=False, index=True)
    paid_at = Column(UTCDateTime, nullable=True)
    created_at = Column(UTCDateTime, default=func.now(), nullable=False)