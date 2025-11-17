from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from decimal import Decimal
from auth.database import get_db
from auth.services.auth_service import get_current_user
from auth.routers.admin import require_admin
from auth.core.enums import PaymentMethod, PaymentType
from .schemas import WalletBalanceRead, WalletRechargeRequest, WalletWithdrawRequest, WalletTransactionList, WalletTransactionRead, WalletMethodRead
from .services import get_or_create_wallet, recharge_balance, withdraw_balance, list_transactions, settle_with_balance

router = APIRouter(tags=["Wallet"])

@router.get("/wallet/balance", response_model=WalletBalanceRead)
def get_balance(db: Session = Depends(get_db), user=Depends(get_current_user)):
    try:
        acc = get_or_create_wallet(db, user.id)
        db.commit()
        db.refresh(acc)
        return {"balance": acc.balance}
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="获取余额失败")

@router.post("/wallet/recharge", response_model=WalletBalanceRead)
def recharge(req: WalletRechargeRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    try:
        acc = recharge_balance(db, user.id, Decimal(str(req.amount)), req.payment_method)
        db.commit()
        db.refresh(acc)
        return {"balance": acc.balance}
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="充值失败")

@router.post("/wallet/withdraw", response_model=WalletBalanceRead)
def withdraw(req: WalletWithdrawRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    try:
        acc = withdraw_balance(db, user.id, Decimal(str(req.amount)), req.bank_account or None)
        if not acc:
            raise HTTPException(status_code=400, detail="余额不足")
        db.commit()
        db.refresh(acc)
        return {"balance": acc.balance}
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="提现失败")

@router.get("/wallet/transactions", response_model=WalletTransactionList)
def transactions(skip: int = 0, limit: int = 20, db: Session = Depends(get_db), user=Depends(get_current_user)):
    try:
        total, items = list_transactions(db, user.id, skip, limit)
        return {"total": total, "transactions": items}
    except Exception:
        raise HTTPException(status_code=500, detail="获取交易失败")

@router.get("/wallet/methods", response_model=list[WalletMethodRead])
def methods():
    return [
        {"method": PaymentMethod.WECHAT_PAY, "name": "微信支付", "provider": "WeChat"},
        {"method": PaymentMethod.ALIPAY, "name": "支付宝", "provider": "Alipay"},
        {"method": PaymentMethod.BALANCE, "name": "账户余额", "provider": "Wallet"},
    ]

@router.post("/wallet/settle", response_model=WalletBalanceRead)
def settle(payment_type: PaymentType, amount: Decimal, parking_record_id: int | None = None, reservation_id: int | None = None, db: Session = Depends(get_db), user=Depends(get_current_user)):
    try:
        ok = settle_with_balance(db, user.id, Decimal(str(amount)), payment_type, parking_record_id, reservation_id)
        if not ok:
            raise HTTPException(status_code=400, detail="余额不足")
        acc = get_or_create_wallet(db, user.id)
        db.commit()
        db.refresh(acc)
        return {"balance": acc.balance}
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="余额结算失败")

@router.get("/admin/wallet/transactions", response_model=WalletTransactionList)
def admin_transactions(skip: int = 0, limit: int = 20, user_id: int | None = None, db: Session = Depends(get_db), admin=Depends(require_admin)):
    qry_user = user_id if user_id is not None else admin.id
    total, items = list_transactions(db, qry_user, skip, limit)
    return {"total": total, "transactions": items}
