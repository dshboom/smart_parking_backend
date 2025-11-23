# /core/enums.py wll
import enum

class UserStatus(enum.Enum):
    ACTIVE = "active"
    PENDING = "pending"
    SUSPENDED = "suspended"
    DELETED = "deleted"

class UserRole(enum.Enum):
    USER = "user"
    ADMIN = "admin"

class LoginStatus(enum.Enum):
    SUCCESS = "success"
    FAILED = "failed"
    LOCKED = "locked"

class OperationType(enum.Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    VIEW = "view"
    PROFILE_UPDATE = "profile_update"
    PASSWORD_CHANGE = "password_change"

class VerificationCodeType(enum.Enum):
    EMAIL_VERIFICATION = "email_verification"
    PHONE_VERIFICATION = "phone_verification"
    PASSWORD_RESET = "password_reset"

class VehicleStatus(enum.Enum):
    ACTIVE = "ACTIVE"
    DELETED = "DELETED"

class ParkingLotStatus(enum.Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FULL = "FULL"
    MAINTENANCE = "MAINTENANCE"

class ParkingRecordStatus(enum.Enum):
    PARKED = "PARKED"
    COMPLETED = "COMPLETED"
    UNPAID = "UNPAID"
    PAID = "PAID"

class PaymentStatus(enum.Enum):
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"

class PaymentMethod(enum.Enum):
    WECHAT_PAY = "WECHAT_PAY"
    ALIPAY = "ALIPAY"
    BALANCE = "BALANCE"

class WalletTransactionType(enum.Enum):
    RECHARGE = "RECHARGE"
    WITHDRAW = "WITHDRAW"

class ReservationStatus(enum.Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"

class PaymentType(enum.Enum):
    PARKING_FEE = "PARKING_FEE"
    RESERVATION_FEE = "RESERVATION_FEE"

class SpaceStatus(enum.Enum):
    AVAILABLE = "available"
    OCCUPIED = "occupied"
    RESERVED = "reserved"
    MAINTENANCE = "maintenance"

class SpaceType(enum.Enum):
    STANDARD = "standard"
    DISABLED = "disabled"
    ELECTRIC = "electric"
    COMPACT = "compact"
    FAMILY = "family"

class LayoutCellType(enum.Enum):
    ROAD = "road"
    WALL = "wall"
    ENTRANCE = "entrance"
    EXIT = "exit"
    PARKING = "parking"