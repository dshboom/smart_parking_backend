# schemas.py wll
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Literal
from datetime import datetime
from decimal import Decimal
from auth.core.enums import VehicleStatus, ParkingLotStatus, ParkingRecordStatus, PaymentStatus, PaymentMethod, ReservationStatus, PaymentType, SpaceStatus, SpaceType

class VehicleCreate(BaseModel):
    license_plate: str = Field(..., max_length=20)
    is_default: bool = False

class VehicleUpdate(BaseModel):
    is_default: Optional[bool] = None
    status: Optional[VehicleStatus] = None

class VehicleRead(BaseModel):
    id: int
    user_id: int
    license_plate: str
    is_default: bool
    status: VehicleStatus
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class ParkingLotCreate(BaseModel):
    name: str = Field(..., max_length=100)
    address: str = Field(..., max_length=255)
    total_capacity: int
    available_spots: int
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    status: ParkingLotStatus = ParkingLotStatus.OPEN

class ParkingLotUpdate(BaseModel):
    address: Optional[str] = None
    total_capacity: Optional[int] = None
    status: Optional[ParkingLotStatus] = None

class ParkingLotRead(BaseModel):
    id: int
    name: str
    address: str
    total_capacity: int
    available_spots: int
    status: ParkingLotStatus
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class BillingRuleCreate(BaseModel):
    rule_name: str = Field(..., max_length=100)
    free_duration_minutes: int = 15
    hourly_rate: Decimal
    daily_cap_rate: Optional[Decimal] = None

class BillingRuleUpdate(BaseModel):
    rule_name: Optional[str] = None
    free_duration_minutes: Optional[int] = None
    hourly_rate: Optional[Decimal] = None
    daily_cap_rate: Optional[Decimal] = None

class BillingRuleRead(BaseModel):
    id: int
    parking_lot_id: int
    rule_name: str
    free_duration_minutes: int
    hourly_rate: Decimal
    daily_cap_rate: Optional[Decimal] = None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class ParkingRecordCreate(BaseModel):
    license_plate: str = Field(..., max_length=20)
    parking_lot_id: int

class ParkingRecordExitRequest(BaseModel):
    exit_time: Optional[datetime] = None

class ParkingRecordRead(BaseModel):
    id: int
    vehicle_id: int
    parking_lot_id: int
    space_id: Optional[int] = None
    license_plate_snapshot: str
    entry_time: datetime
    exit_time: Optional[datetime]
    fee: Optional[Decimal]
    status: ParkingRecordStatus
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class ReservationRead(BaseModel):
    id: int
    user_id: int
    vehicle_id: int
    parking_lot_id: int
    space_id: Optional[int]
    reservation_fee: Optional[Decimal]
    reservation_time: datetime
    expires_at: datetime
    status: ReservationStatus
    parking_record_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class PaymentCreate(BaseModel):
    parking_record_id: Optional[int] = None
    reservation_id: Optional[int] = None
    amount: Decimal
    payment_method: PaymentMethod
    payment_type: PaymentType = PaymentType.PARKING_FEE
    transaction_id: Optional[str] = None

class PaymentUpdate(BaseModel):
    status: Optional[PaymentStatus] = None
    transaction_id: Optional[str] = None
    paid_at: Optional[datetime] = None

class PaymentRead(BaseModel):
    id: int
    parking_record_id: Optional[int]
    reservation_id: Optional[int]
    user_id: int
    amount: Decimal
    payment_method: PaymentMethod
    payment_type: PaymentType
    transaction_id: Optional[str]
    status: PaymentStatus
    paid_at: Optional[datetime]
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# --- 可视化布局与车位 ---
class GridCell(BaseModel):
    row: int
    col: int
    type: Literal["road","wall","entrance","exit","parking"]

class ParkingLotLayoutRead(BaseModel):
    rows: int
    cols: int
    grid: List[List[Literal["road","wall","entrance","exit","parking"]]]
    entrance_position: dict
    exit_position: dict

class ParkingLotLayoutUpdate(BaseModel):
    rows: int
    cols: int
    grid: List[List[Literal["road","wall","entrance","exit","parking"]]]
    entrance_position: dict
    exit_position: dict

class ParkingSpaceRead(BaseModel):
    id: int
    parking_lot_id: int
    space_number: Optional[str]
    row: int
    col: int
    space_type: SpaceType
    status: SpaceStatus
    vehicle_id: Optional[int]
    occupied_at: Optional[datetime]
    reserved_until: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class OccupySpaceRequest(BaseModel):
    vehicle_id: Optional[int] = None
    license_plate: Optional[str] = None

class VacateSpaceRequest(BaseModel):
    exit_time: Optional[datetime] = None

class ReserveSpaceRequest(BaseModel):
    user_id: int
    vehicle_id: Optional[int] = None
    reserved_until: Optional[datetime] = None

class NearestSpaceRequest(BaseModel):
    origin: Optional[dict] = None # {row, col} 或 {"entrance": true}
    preferred_type: Optional[SpaceType] = None

class NearestSpaceResponse(BaseModel):
    space_id: int
    row: int
    col: int
    distance: int

class NavigateRequest(BaseModel):
    start: dict
    end: dict

class NavigateResponse(BaseModel):
    path: List[dict]

class ParkingStatsRead(BaseModel):
    total_spaces: int
    occupied_spaces: int
    available_spaces: int
    reserved_spaces: int
    occupancy_rate: float
    space_types: dict
    status_distribution: dict
    hourly_occupancy: List[dict]

class PaginatedParkingRecords(BaseModel):
    items: List[ParkingRecordRead]
    total: int