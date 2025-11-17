from decimal import Decimal
from sqlalchemy.orm import Session
from auth.core.enums import WalletTransactionType, PaymentMethod, PaymentType
from .models import WalletAccount, WalletTransaction
from parking.services import create_payment, mark_payment_success

def get_or_create_wallet(db: Session, user_id: int) -> WalletAccount:
    acc = db.query(WalletAccount).filter(WalletAccount.user_id == user_id).first()
    if not acc:
        acc = WalletAccount(user_id=user_id, balance=Decimal("0.00"))
        db.add(acc)
        db.flush()
    return acc

def recharge_balance(db: Session, user_id: int, amount: Decimal, method: PaymentMethod) -> WalletAccount:
    acc = get_or_create_wallet(db, user_id)
    acc.balance = (Decimal(str(acc.balance)) + Decimal(str(amount))).quantize(Decimal("0.01"))
    tx = WalletTransaction(user_id=user_id, amount=amount, transaction_type=WalletTransactionType.RECHARGE, method=method, status="SUCCESS")
    db.add(tx)
    return acc

def withdraw_balance(db: Session, user_id: int, amount: Decimal, remark: str | None = None) -> WalletAccount | None:
    acc = get_or_create_wallet(db, user_id)
    if Decimal(str(acc.balance)) < Decimal(str(amount)):
        return None
    acc.balance = (Decimal(str(acc.balance)) - Decimal(str(amount))).quantize(Decimal("0.01"))
    tx = WalletTransaction(user_id=user_id, amount=amount, transaction_type=WalletTransactionType.WITHDRAW, method=None, status="SUCCESS", remark=remark)
    db.add(tx)
    return acc

def list_transactions(db: Session, user_id: int, skip: int = 0, limit: int = 20) -> tuple[int, list[WalletTransaction]]:
    q = db.query(WalletTransaction).filter(WalletTransaction.user_id == user_id).order_by(WalletTransaction.created_at.desc())
    total = q.count()
    items = q.offset(skip).limit(limit).all()
    return total, items

def settle_with_balance(db: Session, user_id: int, amount: Decimal, payment_type: PaymentType, record_id: int | None = None, reservation_id: int | None = None) -> bool:
    acc = get_or_create_wallet(db, user_id)
    if Decimal(str(acc.balance)) < Decimal(str(amount)):
        return False
    acc.balance = (Decimal(str(acc.balance)) - Decimal(str(amount))).quantize(Decimal("0.01"))
    tx = WalletTransaction(user_id=user_id, amount=amount, transaction_type=WalletTransactionType.WITHDRAW, method=PaymentMethod.BALANCE, status="SUCCESS", remark=f"settle {payment_type.value}")
    db.add(tx)
    pay = create_payment(db, user_id, amount, PaymentMethod.BALANCE, payment_type, record_id, reservation_id)
    mark_payment_success(db, pay.id, transaction_id=f"WALLET-{pay.id}")
    return True